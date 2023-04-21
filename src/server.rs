use crate::{identifier::Identifier, keypair::signing::PublicKey, protocol::messaging};

use futures_util::{stream::SplitSink, SinkExt, StreamExt};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
    runtime::Runtime,
    sync::Mutex,
};
use tokio_tungstenite::{accept_async, tungstenite::protocol::Message, WebSocketStream};

use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::sync::Arc;

#[derive(Debug)]
struct GenericError {
    details: String,
}

impl GenericError {
    fn new(msg: &str) -> GenericError {
        GenericError {
            details: msg.to_string(),
        }
    }
}

impl fmt::Display for GenericError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.details)
    }
}

impl Error for GenericError {
    fn description(&self) -> &str {
        &self.details
    }
}

pub struct Server {
    datastore: Arc<Mutex<Datastore>>,
    runtime: Runtime,
}

pub struct Datastore {
    messages: HashMap<Identifier, Vec<Vec<u8>>>,
    prekeys: HashMap<Identifier, Vec<Vec<u8>>>,
    subscribers: HashMap<Identifier, Vec<(Vec<u8>, async_channel::Sender<Message>)>>,
}

impl Datastore {
    pub fn new() -> Datastore {
        Datastore {
            messages: HashMap::new(),
            prekeys: HashMap::new(),
            subscribers: HashMap::new(),
        }
    }
}

impl Default for Datastore {
    fn default() -> Self {
        Datastore::new()
    }
}

impl Server {
    pub fn new() -> Server {
        let datastore = Arc::new(Mutex::new(Datastore::new()));

        Server {
            datastore: datastore.clone(),
            runtime: test_server(datastore),
        }
    }
}

impl Default for Server {
    fn default() -> Self {
        Server::new()
    }
}

fn test_server(datastore: Arc<Mutex<Datastore>>) -> Runtime {
    let (con_tx, con_rx) = crossbeam::channel::bounded(1);

    let f = async move {
        let listener = TcpListener::bind("127.0.0.1:12345").await.unwrap();
        con_tx.send(()).unwrap();
        let (connection, _) = listener.accept().await.expect("No connections to accept");
        let stream = accept_async(connection).await;
        let stream = stream.expect("Failed to handshake with connection");
        run_connection(stream, datastore).await;
    };

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.spawn(f);

    con_rx
        .recv_deadline(std::time::Instant::now() + std::time::Duration::from_secs(1))
        .expect("Server not ready");

    std::thread::sleep(std::time::Duration::from_millis(100));

    rt
}

async fn run_connection<S>(connection: WebSocketStream<S>, datastore: Arc<Mutex<Datastore>>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut socket_tx, mut socket_rx) = connection.split();
    let (write_tx, mut write_rx) = async_channel::unbounded();

    let connection_id = crate::crypto::random_id();
    let mut subscriptions = Vec::new();

    loop {
        tokio::select! {
            message = socket_rx.next() => {
                if let Some(m) = message {
                    let m = m.expect("socket rx event failed");

                    if m.is_binary() {
                        let data = m.into_data().clone();

                        let event = messaging::root_as_event(&data).expect("Event invalid");
                        let content = event.content().expect("Event content missing");

                        match event.type_() {
                            messaging::ContentType::MESSAGE => {
                                match handle_message(&data, content, &datastore).await {
                                    Ok(_) => ack(&mut socket_tx, event.id().unwrap()).await,
                                    Err(ge) => {
                                        err(&mut socket_tx, event.id().unwrap(), ge.details.as_bytes()).await;
                                        break;
                                    },
                                }
                            },
                            messaging::ContentType::SUBSCRIBE => {
                                match handle_subscribe(content, write_tx.clone(), &connection_id, &mut subscriptions, &datastore).await {
                                    Ok(_) => ack(&mut socket_tx, event.id().unwrap()).await,
                                    Err(ge) => {
                                        err(&mut socket_tx, event.id().unwrap(), ge.details.as_bytes()).await;
                                        break;
                                    },
                                }
                            },
                            messaging::ContentType::OPEN => {

                            },
                            messaging::ContentType::CLOSE => {

                            },
                            _ => {

                            },
                        }
                    } else if m.is_ping() {
                        println!("ping");
                    } else if m.is_pong() {
                        println!("pong");
                    }
                }
            },
            message = write_rx.next() => {
                if let Some(message) = message {
                    if socket_tx.send(message).await.is_err() {
                        break
                    }
                }
            }
        }
    }

    // cleanup subscriptions...

    let mut ds = datastore.lock().await;

    for subscriber in subscriptions {
        // Ignore if no such element is found
        if let Some(s) = ds.subscribers.get_mut(&subscriber) {
            if let Some(p) = s.iter().position(|(conn_id, _)| connection_id.eq(conn_id)) {
                s.remove(p);
            }
        };
    }
}

async fn handle_message(
    data: &[u8],
    content: &[u8],
    datastore: &Arc<Mutex<Datastore>>,
) -> Result<(), GenericError> {
    let message = flatbuffers::root::<messaging::Message>(content)
        .expect("Failed to process websocket message content");

    let payload = match message.payload() {
        Some(payload) => flatbuffers::root::<messaging::Payload>(payload)
            .expect("Failed to process websocket message content"),
        None => return Err(GenericError::new("invalid message payload")),
    };

    // TODO validate message authentication and authorization
    if let Some(recipient) = payload.recipient() {
        let mut ds = datastore.lock().await;
        let identifier = Identifier::Referenced(recipient.to_vec());

        // If the inbox exists, push the message
        if let Some(inbox) = ds.messages.get_mut(&identifier) {
            inbox.push(data.to_vec());
        } else {
            return Err(GenericError::new("recipient inbox not found"));
        };

        // if there are subscribers, forward them the messages
        if let Some(subscribers) = ds.subscribers.get_mut(&identifier) {
            for (_, sub) in subscribers {
                sub.send(Message::Binary(data.to_vec()))
                    .await
                    .expect("failed to send message to subscriber");
            }
        };
    }
    Ok(())
}

async fn handle_subscribe(
    content: &[u8],
    write_tx: async_channel::Sender<Message>,
    connection_id: &[u8],
    subscriptions: &mut Vec<Identifier>,
    datastore: &Arc<Mutex<Datastore>>,
) -> Result<(), GenericError> {
    let subscribe =
        flatbuffers::root::<messaging::Subscribe>(content).expect("Subscribe event invalid");

    // setup subscriptions
    for subscription in subscribe
        .subscriptions()
        .expect("Subscribe subscriptions empty")
    {
        let details_buf = subscription.details().expect("Subscription details empty");
        let details_len = details_buf.len();
        let signatures = subscription
            .signatures()
            .expect("Subscription signatures empty");

        let details = flatbuffers::root::<messaging::SubscriptionDetails>(details_buf)
            .expect("Subscription details invalid");
        let inbox = details.inbox().expect("Subscription inbox missing");

        let (mut authenticated, mut authorized) = (false, false);
        let mut subscriber: Option<&[u8]> = None;

        // validate the subscriptions signatures
        for signature in signatures {
            let sig = signature.signature().expect("Subscription signature empty");

            match signature.type_() {
                messaging::SignatureType::PAYLOAD => {
                    // authenticate the subscriber over the subscriptions details
                    let signer = signature.signer().unwrap_or(inbox);

                    let mut details_sig_buf = vec![0; details_len + 1];
                    details_sig_buf[0] = messaging::SignatureType::PAYLOAD.0 as u8;
                    details_sig_buf[1..details_len + 1].copy_from_slice(details_buf);

                    let pk = PublicKey::from_bytes(signer, crate::keypair::Algorithm::Ed25519)
                        .expect("Subscription signer invalid");

                    if !(pk.verify(&details_sig_buf, sig)) {
                        return Err(GenericError::new("bad auth"));
                    };

                    let identifier = Identifier::Referenced(inbox.to_vec());
                    subscriptions.push(identifier);

                    if inbox == signer {
                        (authenticated, authorized) = (true, true);
                        break;
                    }

                    subscriber = Some(signer);
                    authenticated = true;
                }
                messaging::SignatureType::SUBSCRIPTION => {
                    let mut subscription_sig_buf = vec![0; 65];
                    subscription_sig_buf[0] = messaging::SignatureType::SUBSCRIPTION.0 as u8;
                    subscription_sig_buf[1..33].copy_from_slice(inbox);
                    subscription_sig_buf[33..65]
                        .copy_from_slice(subscriber.expect("Subscriber empty"));

                    let pk = PublicKey::from_bytes(inbox, crate::keypair::Algorithm::Ed25519)
                        .expect("Subscription signer invalid");

                    if !pk.verify(&subscription_sig_buf, sig) {
                        return Err(GenericError::new("bad auth"));
                    };

                    authorized = true;
                }
                _ => continue, // skip other signature types for now
            }
        }

        assert!(authenticated && authorized);
    }

    let mut ds = datastore.lock().await;

    for subscription in subscriptions {
        if let Some(inbox) = ds.messages.get(subscription) {
            for msg in inbox {
                write_tx
                    .send(Message::Binary(msg.clone()))
                    .await
                    .expect("failed to replay message");
            }
        }

        if let Some(subscribers) = ds.subscribers.get_mut(subscription) {
            subscribers.push((connection_id.to_vec(), write_tx.clone()));
        } else {
            ds.subscribers.insert(
                subscription.clone(),
                vec![(connection_id.to_vec(), write_tx.clone())],
            );
        }
    }

    Ok(())
}

async fn ack<S>(socket_tx: &mut SplitSink<WebSocketStream<S>, Message>, id: &[u8])
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);
    let id = builder.create_vector(id);

    let event = messaging::Event::create(
        &mut builder,
        &messaging::EventArgs {
            id: Some(id),
            type_: messaging::ContentType::ACKNOWLEDGEMENT,
            content: None,
        },
    );

    builder.finish(event, None);

    (*socket_tx)
        .send(Message::binary(builder.finished_data()))
        .await
        .expect("Failed to send ACK");
}

async fn err<S>(socket_tx: &mut SplitSink<WebSocketStream<S>, Message>, id: &[u8], reason: &[u8])
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);

    let reason = builder.create_vector(reason);

    let error = messaging::Error::create(
        &mut builder,
        &messaging::ErrorArgs {
            code: messaging::StatusCode::BADAUTH,
            error: Some(reason),
        },
    );

    builder.finish(error, None);
    let content = builder.finished_data().to_vec();
    builder.reset();

    let id = builder.create_vector(id);
    let content = builder.create_vector(&content);

    let event = messaging::Event::create(
        &mut builder,
        &messaging::EventArgs {
            id: Some(id),
            type_: messaging::ContentType::ACKNOWLEDGEMENT,
            content: Some(content),
        },
    );

    builder.finish(event, None);

    (*socket_tx)
        .send(Message::binary(builder.finished_data()))
        .await
        .expect("Failed to send ERR");
}

#[cfg(test)]
mod tests {
    use super::*;
}
