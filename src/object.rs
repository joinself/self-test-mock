use std::sync::Arc;

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
use tower_http::trace::TraceLayer;

use hex::ToHex;
use tokio::sync::Mutex;

use crate::{datastore::Datastore, token::Token};

pub fn test_object(
    runtime: &mut tokio::runtime::Runtime,
    port: u16,
    datastore: Arc<Mutex<Datastore>>,
) {
    let (con_tx, con_rx) = crossbeam::channel::bounded(1);

    /*
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();
    */

    let app = Router::new()
        .route("/objects/", post(object_create))
        .route("/objects/:id", get(object_get))
        .layer(TraceLayer::new_for_http())
        .with_state(datastore);

    let f = async move {
        let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port))
            .await
            .unwrap();
        con_tx.send(()).unwrap();
        axum::serve(listener, app)
            .await
            .expect("server shutting down");
    };

    runtime.spawn(f);

    con_rx
        .recv_deadline(std::time::Instant::now() + std::time::Duration::from_secs(1))
        .expect("Server not ready");
}

#[debug_handler]
async fn object_get(
    Path(id): Path<String>,
    State(state): State<Arc<Mutex<Datastore>>>,
) -> Response {
    let ds = state.lock().await;

    match ds.objects.get(&id) {
        Some(object) => object.to_vec().into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[debug_handler]
async fn object_create(
    State(state): State<Arc<Mutex<Datastore>>>,
    request: Request<Body>,
) -> Response {
    let headers = request.headers().clone();

    // get pow headers
    let pow_hash = match headers.get("X-Self-POW-Hash") {
        Some(pow_hash) => match base64::decode_config(pow_hash, base64::URL_SAFE_NO_PAD) {
            Ok(pow_hash) => pow_hash,
            Err(_) => return StatusCode::BAD_REQUEST.into_response(),
        },
        None => return StatusCode::BAD_REQUEST.into_response(),
    };

    let pow_nonce = match headers.get("X-Self-POW-Nonce") {
        Some(pow_nonce) => match pow_nonce.to_str() {
            Ok(pow_nonce) => pow_nonce.parse::<u64>().unwrap_or(0),
            Err(_) => return StatusCode::BAD_REQUEST.into_response(),
        },
        None => return StatusCode::BAD_REQUEST.into_response(),
    };

    // get authentication token
    let authentication_token = match headers.get("Authorization") {
        Some(authentication_token) => {
            match base64::decode_config(authentication_token, base64::URL_SAFE_NO_PAD) {
                Ok(authentication_token) => authentication_token,
                Err(_) => return StatusCode::BAD_REQUEST.into_response(),
            }
        }
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let body = match axum::body::to_bytes(request.into_body(), 1 << 32).await {
        Ok(body) => body.to_vec(),
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let hash = crate::crypto::hash::sha3(&body);

    // validate pow
    if !crate::crypto::pow::ProofOfWork::new(8).validate(&hash, &pow_hash, pow_nonce) {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    // validate authentication token
    match crate::token::Token::decode(&authentication_token) {
        Ok(token) => match token {
            Token::Authentication(authentication) => {
                if !authentication.content_hash().eq(&hash) {
                    return StatusCode::UNAUTHORIZED.into_response();
                }
            }
            _ => return StatusCode::NOT_ACCEPTABLE.into_response(),
        },
        Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    }

    let mut ds = state.lock().await;

    // create the object
    ds.objects.insert(hash.encode_hex(), body);

    Bytes::new().into_response()
}
