use crate::{
    datastore::Datastore, error::GenericError, keypair::signing::PublicKey, protocol::messaging,
    token::Token,
};

use base64::write;
use futures_util::{stream::SplitSink, SinkExt, StreamExt};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    runtime::Runtime,
    sync::Mutex,
};
use tokio_tungstenite::{accept_async, tungstenite::protocol::Message, WebSocketStream};

use std::sync::Arc;

pub fn test_messaging(
    runtime: &mut Runtime,
    messaging_port: u16,
    datastore: Arc<Mutex<Datastore>>,
) {
    let (con_tx, con_rx) = crossbeam::channel::bounded(1);

    let f = async move {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", messaging_port))
            .await
            .unwrap();
        con_tx.send(()).unwrap();

        while let Ok((connection, _)) = listener.accept().await {
            tokio::spawn(accept_connection(connection, datastore.clone()));
        }
    };
    runtime.spawn(f);

    con_rx
        .recv_deadline(std::time::Instant::now() + std::time::Duration::from_secs(1))
        .expect("Server not ready");

    std::thread::sleep(std::time::Duration::from_millis(100));
}

async fn accept_connection(connection: TcpStream, datastore: Arc<Mutex<Datastore>>) {
    let stream = accept_async(connection).await;
    let stream = stream.expect("Failed to handshake with connection");
    run_connection(stream, datastore).await;
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
                            messaging::EventType::MESSAGE => {
                                // println!(">>> received ws message...");

                                match handle_message(&data, content, &datastore).await {
                                    Ok(_) => ack(&mut socket_tx, event.id().unwrap()).await,
                                    Err(ge) => {
                                        err(&mut socket_tx, event.id().unwrap(), ge.details.as_bytes()).await;
                                        break;
                                    },
                                }
                            },
                            messaging::EventType::SUBSCRIBE => {
                                // println!(">>> received ws subscribe...");

                                match handle_subscribe(content, write_tx.clone(), &connection_id, &mut subscriptions, &datastore).await {
                                    Ok(_) => ack(&mut socket_tx, event.id().unwrap()).await,
                                    Err(ge) => {
                                        println!("subscribe failed: {}", ge);
                                        err(&mut socket_tx, event.id().unwrap(), ge.details.as_bytes()).await;
                                        break;
                                    },
                                }
                            },
                            messaging::EventType::OPEN => {
                                // println!(">>> received ws open...");

                                match handle_open(content, &datastore).await {
                                    Ok(_) => ack(&mut socket_tx, event.id().unwrap()).await,
                                    Err(ge) => {
                                        println!("open err: {}", ge);
                                        err(&mut socket_tx, event.id().unwrap(), ge.details.as_bytes()).await;
                                        break;
                                    },
                                }
                            },
                            messaging::EventType::CLOSE => {

                            },
                            _ => {

                            },
                        }
                    } else if m.is_ping() {
                        println!("ping");
                    } else if m.is_pong() {
                        println!("pong");
                    }
                } else {
                    break
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
        // If the inbox exists, push the message
        if let Some(inbox) = ds.messages.get_mut(recipient) {
            inbox.push(data.to_vec());
        } else {
            return Err(GenericError::new("recipient inbox not found"));
        };

        // if there are subscribers, forward them the messages
        if let Some(subscribers) = ds.subscribers.get_mut(recipient) {
            for (_, sub) in subscribers {
                sub.send(Message::Binary(data.to_vec()))
                    .await
                    .expect("failed to send message to subscriber");
            }
        };
    }
    Ok(())
}

async fn handle_open(
    content: &[u8],
    datastore: &Arc<Mutex<Datastore>>,
) -> Result<(), GenericError> {
    let message = flatbuffers::root::<messaging::Open>(content)
        .expect("Failed to process websocket message content");

    let details = match message.details() {
        Some(details) => flatbuffers::root::<messaging::OpenDetails>(details)
            .expect("Failed to process websocket message content"),
        None => return Err(GenericError::new("invalid message payload")),
    };

    // TODO validate open details proof of work and signatures
    if let Some(inbox) = details.inbox() {
        let mut ds = datastore.lock().await;
        // If the inbox exists, push the message
        if ds.messages.contains_key(inbox) {
            return Err(GenericError::new("recipient inbox not found"));
        } else {
            ds.messages.insert(inbox.to_owned(), Vec::new());
        };
    }

    Ok(())
}

async fn handle_subscribe(
    content: &[u8],
    write_tx: async_channel::Sender<Message>,
    connection_id: &[u8],
    subscriptions: &mut Vec<Vec<u8>>,
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

        // TODO re-enable this when tokens have been updated

        /*
        let (mut authenticated_as, mut authorized_by, mut authorized_for) = (None, None, None);

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

                    let pk = PublicKey::from_address(signer)
                        .expect("Subscription signer invalid");

                    if !(pk.verify(&details_sig_buf, sig)) {
                        return Err(GenericError::new("bad authentication signature"));
                    };

                    // if the signer is the inbox that a subscription is being requested for, then we can exit
                    if inbox == signer {
                        (authenticated_as, authorized_by) =
                            (Some(signer.to_vec()), Some(signer.to_vec()));
                        break;
                    }

                    authenticated_as = Some(signer.to_vec());
                }
                messaging::SignatureType::TOKEN => {
                    let token = match Token::decode(sig) {
                        Ok(token) => token,
                        Err(_) => return Err(GenericError::new("bad token encoding")),
                    };

                    match token {
                        Token::Subscription(token) => {
                            // TODO validate token if not handled by decoding step...
                            // token.validate();

                            (authorized_by, authorized_for) =
                                (Some(token.signer().id()), Some(token.bearer().id()));
                        }
                        _ => return Err(GenericError::new("unsupported token type")),
                    }
                }
                _ => continue, // skip other signature types for now
            }
        }

        let authenticated_as = match authenticated_as {
            Some(authenticated_as) => authenticated_as,
            None => return Err(GenericError::new("unauthenticated subscription")),
        };

        let authorized_by = match authorized_by {
            Some(authorized_by) => authorized_by,
            None => return Err(GenericError::new("unauthorized subscription")),
        };

        if inbox != authorized_by {
            return Err(GenericError::new("unauthorized subscription"));
        }

        if authenticated_as != authorized_by {
            // if the authenticated user does not match the authorized user
            // check the authorizing user has authorized the authenticated user
            let authorized_for = match authorized_for {
                Some(authorized_for) => authorized_for,
                None => return Err(GenericError::new("unauthorized subscription")),
            };

            if authenticated_as != authorized_for {
                return Err(GenericError::new("unauthorized subscription"));
            }
        }

        subscriptions.push(authorized_by);
        */

        subscriptions.push(inbox.to_vec());
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
            version: messaging::Version::V1,
            type_: messaging::EventType::ACKNOWLEDGEMENT,
            content: None,
        },
    );

    builder.finish(event, None);

    (*socket_tx)
        .send(Message::binary(builder.finished_data().to_vec()))
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
            version: messaging::Version::V1,
            type_: messaging::EventType::ACKNOWLEDGEMENT,
            content: Some(content),
        },
    );

    builder.finish(event, None);

    (*socket_tx)
        .send(Message::binary(builder.finished_data()))
        .await
        .expect("Failed to send ERR");
}
