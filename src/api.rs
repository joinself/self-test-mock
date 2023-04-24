use crate::crypto::pow::ProofOfWork;
use crate::datastore::Datastore;
use crate::identifier::Identifier;
use crate::siggraph::SignatureGraph;

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

use std::{net::SocketAddr, sync::Arc};

pub fn test_api(
    runtime: &mut tokio::runtime::Runtime,
    port: u16,
    datastore: Arc<Mutex<Datastore>>,
) {
    let app = Router::new()
        .route("/v2/identities", post(identity_create))
        .route("/v2/identities/:id", get(identity_get))
        .route("/v2/identities/:id/operations", post(operation_create))
        .with_state(datastore);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    let (con_tx, con_rx) = crossbeam::channel::bounded(1);

    let f = async move {
        let socket = axum::Server::bind(&addr);
        con_tx.send(()).unwrap();
        socket
            .serve(app.into_make_service())
            .await
            .expect("server shutting down");
    };

    runtime.spawn(f);

    con_rx
        .recv_deadline(std::time::Instant::now() + std::time::Duration::from_secs(1))
        .expect("Server not ready");
}

async fn identity_get(
    Path(key): Path<String>,
    State(state): State<Arc<Mutex<Datastore>>>,
) -> Response {
    let identifier = Identifier::Referenced(hex::decode(key).expect("bad hex identifier"));

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
    Path(key): Path<String>,
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

    // load and validate the signature graph operation
    let mut sg = SignatureGraph::new();
    if sg.execute(body.to_vec()).is_err() {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    // create the identity if it doesn't exist
    ds.identities.insert(
        Identifier::Referenced(sg.id().expect("does not have identifier")),
        vec![body.to_vec()],
    );

    for sk in &sg.signing_keys() {
        ds.messages
            .insert(Identifier::Referenced(sk.to_vec()), Vec::new());
    }

    Bytes::new().into_response()
}

#[debug_handler]
async fn operation_create(
    Path(key): Path<String>,
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

    let identifier = Identifier::Referenced(hex::decode(key).expect("identifier is not hex"));

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
    }

    Bytes::new().into_response()
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
