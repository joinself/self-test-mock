use crate::crypto::pow::ProofOfWork;
use crate::datastore::Datastore;
use crate::identifier::Identifier;
use crate::models::{KeyRequest, PrekeyResponse};
use crate::siggraph::SignatureGraph;
use crate::token::Token;

use axum::{
    body::{Body, Bytes},
    debug_handler,
    extract::{Path, State},
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use byteorder::{LittleEndian, ReadBytesExt};
use ciborium::cbor;
use tokio::sync::Mutex;
use tower_http::trace::TraceLayer;

use std::{collections::VecDeque, net::SocketAddr, sync::Arc};

pub fn test_api(
    runtime: &mut tokio::runtime::Runtime,
    port: u16,
    datastore: Arc<Mutex<Datastore>>,
) {
    let app = Router::new()
        .route("/v2/identities", post(identity_create))
        .route("/v2/identities/:id", get(identity_get))
        .route("/v2/identities/:id/operations", post(operation_create))
        .route("/v2/keys", post(key_create))
        .route("/v2/keys/:id", get(key_get))
        .route("/v2/prekeys/:id", post(prekey_create))
        .route("/v2/prekeys/:id", get(prekey_get))
        .layer(TraceLayer::new_for_http())
        .with_state(datastore);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    let (con_tx, con_rx) = crossbeam::channel::bounded(1);

    let f = async move {
        let socket = axum::Server::bind(&addr);
        con_tx.send(()).unwrap();
        println!("starting api on port {}...", port);
        socket
            .serve(app.into_make_service())
            .await
            .expect("server shutting down");
    };

    runtime.spawn(f);

    con_rx
        .recv_deadline(std::time::Instant::now() + std::time::Duration::from_secs(1))
        .expect("Server not ready");

    std::thread::sleep(std::time::Duration::from_millis(200));
}

async fn identity_get(
    Path(id): Path<String>,
    State(state): State<Arc<Mutex<Datastore>>>,
) -> Response {
    let identifier = Identifier::Referenced(hex::decode(id).expect("bad hex identifier"));

    let ds = state.lock().await;

    match ds.identities.get(&identifier) {
        Some(identity) => {
            let mut resp = Vec::new();
            ciborium::ser::into_writer(&cbor!(identity).expect("wont fail"), &mut resp)
                .expect("wont fail");
            resp.into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[debug_handler]
async fn identity_create(
    State(state): State<Arc<Mutex<Datastore>>>,
    mut request: Request<Body>,
) -> Response {
    println!("identity create...");
    let headers = request.headers().clone();

    // get pow headers
    let pow_hash = match headers.get("Self-Pow-Hash") {
        Some(pow_hash) => pow_hash,
        None => return StatusCode::BAD_REQUEST.into_response(),
    }
    .as_bytes();

    let pow_nonce = match headers.get("Self-Pow-Nonce") {
        Some(pow_hash) => pow_hash,
        None => return StatusCode::BAD_REQUEST.into_response(),
    }
    .as_bytes()
    .read_u64::<LittleEndian>()
    .unwrap();

    let body = get_body(request.body_mut()).await;

    // validate pow
    if !ProofOfWork::new(8).validate(&body, pow_hash, pow_nonce) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let mut ds = state.lock().await;

    // load and validate the signature graph operation
    let mut sg = SignatureGraph::new();
    if sg.execute(body.to_vec()).is_err() {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    // create the identity
    ds.identities.insert(
        Identifier::Referenced(sg.id().expect("does not have identifier")),
        vec![body.to_vec()],
    );

    for sk in &sg.signing_keys() {
        ds.messages
            .insert(Identifier::Referenced(sk.to_vec()), Vec::new());
        ds.keys.insert(
            Identifier::Referenced(sk.to_vec()),
            Some(Identifier::Referenced(
                sg.id().expect("does not have identifier"),
            )),
        );
    }

    Bytes::new().into_response()
}

#[debug_handler]
async fn operation_create(
    Path(id): Path<String>,
    State(state): State<Arc<Mutex<Datastore>>>,
    mut request: Request<Body>,
) -> Response {
    let headers = request.headers().clone();

    // get pow headers
    let pow_hash = match headers.get("Self-Pow-Hash") {
        Some(pow_hash) => pow_hash,
        None => return StatusCode::BAD_REQUEST.into_response(),
    }
    .as_bytes();

    let pow_nonce = match headers.get("Self-Pow-Nonce") {
        Some(pow_hash) => pow_hash,
        None => return StatusCode::BAD_REQUEST.into_response(),
    }
    .as_bytes()
    .read_u64::<LittleEndian>()
    .unwrap();

    let body = get_body(request.body_mut()).await;

    // validate pow
    if !ProofOfWork::new(8).validate(&body, pow_hash, pow_nonce) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let mut ds = state.lock().await;

    let identifier = Identifier::Referenced(hex::decode(id).expect("identifier is not hex"));

    // load and validate the signature graph operation
    let operations = match ds.identities.get_mut(&identifier) {
        Some(operations) => operations,
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    let mut sg = SignatureGraph::load(operations, false).expect("wont fail");
    if sg.execute(body.to_vec()).is_err() {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    // update the identities operations
    operations.push(body.to_vec());

    // add an inbox for the new keys
    for sk in &sg.signing_keys() {
        ds.messages
            .insert(Identifier::Referenced(sk.to_vec()), Vec::new());
        ds.keys.insert(
            Identifier::Referenced(sk.to_vec()),
            Some(identifier.clone()),
        );
    }

    Bytes::new().into_response()
}

#[debug_handler]
async fn key_create(
    State(state): State<Arc<Mutex<Datastore>>>,
    mut request: Request<Body>,
) -> Response {
    let headers = request.headers().clone();

    // get pow headers
    let pow_hash = match headers.get("Self-Pow-Hash") {
        Some(pow_hash) => pow_hash,
        None => return StatusCode::BAD_REQUEST.into_response(),
    }
    .as_bytes();

    let pow_nonce = match headers.get("Self-Pow-Nonce") {
        Some(pow_hash) => pow_hash,
        None => return StatusCode::BAD_REQUEST.into_response(),
    }
    .as_bytes()
    .read_u64::<LittleEndian>()
    .unwrap();

    let body = get_body(request.body_mut()).await;

    // validate pow
    if !ProofOfWork::new(8).validate(&body, pow_hash, pow_nonce) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let mut ds = state.lock().await;

    let req_body: &[u8] = &body;

    let req: KeyRequest = match ciborium::de::from_reader(req_body) {
        Ok(req) => req,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let identifier = Identifier::Referenced(req.identifier);

    // create an inbox for the key
    if ds.messages.contains_key(&identifier) {
        return StatusCode::CONFLICT.into_response();
    }

    ds.keys.insert(identifier.clone(), None);
    ds.messages.insert(identifier, Vec::new());

    Bytes::new().into_response()
}

#[debug_handler]
async fn key_get(
    Path(id): Path<String>,
    State(state): State<Arc<Mutex<Datastore>>>,
    mut request: Request<Body>,
) -> Response {
    let headers = request.headers().clone();

    // get pow headers
    let pow_hash = match headers.get("Self-Pow-Hash") {
        Some(pow_hash) => pow_hash,
        None => return StatusCode::BAD_REQUEST.into_response(),
    }
    .as_bytes();

    let pow_nonce = match headers.get("Self-Pow-Nonce") {
        Some(pow_hash) => pow_hash,
        None => return StatusCode::BAD_REQUEST.into_response(),
    }
    .as_bytes()
    .read_u64::<LittleEndian>()
    .unwrap();

    let body = get_body(request.body_mut()).await;

    // validate pow
    if !ProofOfWork::new(8).validate(&body, pow_hash, pow_nonce) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let ds = state.lock().await;

    let req_body: &[u8] = &body;

    let req: KeyRequest = match ciborium::de::from_reader(req_body) {
        Ok(req) => req,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let identifier = Identifier::Referenced(req.identifier);

    if !ds.keys.contains_key(&identifier) {
        return StatusCode::NOT_FOUND.into_response();
    }

    Bytes::new().into_response()
}

#[debug_handler]
async fn prekey_create(
    Path(id): Path<String>,
    State(state): State<Arc<Mutex<Datastore>>>,
    mut request: Request<Body>,
) -> Response {
    let headers = request.headers().clone();
    let body = get_body(request.body_mut()).await;

    let mut ds = state.lock().await;

    let req_body: &[u8] = &body;

    let req: Vec<Vec<u8>> = match ciborium::de::from_reader(req_body) {
        Ok(req) => req,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let identifier = Identifier::Referenced(hex::decode(id).expect("bad hex identifier"));

    // build a buffer containing the full request information
    // used for the authentication request and pow (optional)
    let req_scheme = request.uri().scheme_str().unwrap();
    let req_host = request.uri().host().unwrap();
    let req_path = request.uri().path_and_query().unwrap().as_str();

    let mut req_details =
        vec![
            0;
            request.method().as_str().len() + req_scheme.len() + req_host.len() + req_path.len()
        ];
    req_details.copy_from_slice(req_scheme.as_bytes());
    req_details[req_scheme.len()..].copy_from_slice(req_host.as_bytes());
    req_details[req_scheme.len() + req_host.len()..].copy_from_slice(req_path.as_bytes());

    // get authentication signature for the request
    let authentication = match headers.get("Self-Authentication") {
        Some(authentication) => authentication,
        None => return StatusCode::BAD_REQUEST.into_response(),
    };

    let token = match base64::decode_config(authentication.as_bytes(), base64::URL_SAFE_NO_PAD) {
        Ok(token) => token,
        Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let token = match Token::decode(&token).expect("invalid token encoding") {
        Token::Authentication(token) => token,
        _ => return StatusCode::BAD_REQUEST.into_response(),
    };

    token
        .verify(&req_details)
        .expect("authentication token verification failed");

    if token.signer() != identifier {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    if !ds.keys.contains_key(&identifier) {
        return StatusCode::NOT_FOUND.into_response();
    }

    let queue = match ds.prekeys.get_mut(&identifier) {
        Some(queue) => queue,
        None => {
            ds.prekeys.insert(identifier.clone(), VecDeque::new());
            ds.prekeys.get_mut(&identifier).expect("not empty")
        }
    };

    req.into_iter().for_each(|pk| queue.push_back(pk));

    Bytes::new().into_response()
}

#[debug_handler]
async fn prekey_get(
    Path(id): Path<String>,
    State(state): State<Arc<Mutex<Datastore>>>,
    request: Request<Body>,
) -> Response {
    let headers = request.headers().clone();

    let identifier = Identifier::Referenced(hex::decode(id).expect("bad hex identifier"));

    // build a buffer containing the full request information
    // used for the authentication request and pow (optional)
    let req_scheme = request.uri().scheme_str().unwrap();
    let req_host = request.uri().host().unwrap();
    let req_path = request.uri().path_and_query().unwrap().as_str();

    let mut req_details =
        vec![
            0;
            request.method().as_str().len() + req_scheme.len() + req_host.len() + req_path.len()
        ];
    req_details.copy_from_slice(req_scheme.as_bytes());
    req_details[req_scheme.len()..].copy_from_slice(req_host.as_bytes());
    req_details[req_scheme.len() + req_host.len()..].copy_from_slice(req_path.as_bytes());

    // get authentication signature for the request
    let authentication = match headers.get("Self-Authentication") {
        Some(authentication) => authentication,
        None => return StatusCode::BAD_REQUEST.into_response(),
    };

    let token = match base64::decode_config(authentication.as_bytes(), base64::URL_SAFE_NO_PAD) {
        Ok(token) => token,
        Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let token = match Token::decode(&token).expect("invalid token encoding") {
        Token::Authentication(token) => token,
        _ => return StatusCode::BAD_REQUEST.into_response(),
    };

    token
        .verify(&req_details)
        .expect("authentication token verification failed");

    if let Some(authorization) = headers.get("Self-Authorization") {
        // check for an optional authorization token to authorize the request
        let token = match base64::decode_config(authorization.as_bytes(), base64::URL_SAFE_NO_PAD) {
            Ok(token) => token,
            Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
        };

        let token = match Token::decode(&token).expect("invalid token encoding") {
            Token::Authorization(token) => token,
            _ => return StatusCode::BAD_REQUEST.into_response(),
        };

        if token.signer() != identifier {
            // this request has not been authorized by the correct identity
            return StatusCode::BAD_REQUEST.into_response();
        }

        token
            .verify()
            .expect("authorization token verification failed");
    } else {
        // or fallback to proof of work
        let pow_hash = match headers.get("Self-Pow-Hash") {
            Some(pow_hash) => pow_hash.as_bytes(),
            None => return StatusCode::UNAUTHORIZED.into_response(),
        };

        let pow_nonce = match headers.get("Self-Pow-Nonce") {
            Some(pow_nonce) => pow_nonce.as_bytes().read_u64::<LittleEndian>().unwrap(),
            None => return StatusCode::UNAUTHORIZED.into_response(),
        };

        if !ProofOfWork::new(8).validate(&req_details, pow_hash, pow_nonce) {
            return StatusCode::UNAUTHORIZED.into_response();
        }
    }

    let mut ds = state.lock().await;

    match ds.prekeys.get_mut(&identifier) {
        Some(queue) => match queue.pop_front() {
            Some(prekey) => {
                let mut resp = Vec::new();
                ciborium::ser::into_writer(&PrekeyResponse { key: prekey }, &mut resp)
                    .expect("wont fail");
                resp.into_response()
            }
            None => StatusCode::NOT_FOUND.into_response(),
        },
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn get_body<B>(body: B) -> Bytes
where
    B: axum::body::HttpBody<Data = Bytes>,
    B::Error: std::fmt::Display,
{
    match hyper::body::to_bytes(body).await {
        Ok(bytes) => bytes,
        Err(_) => Bytes::new(),
    }
}
