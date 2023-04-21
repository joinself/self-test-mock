use crate::datastore::Datastore;

use axum::{
    body::Bytes,
    extract::{Path, State},
    routing::{get, post},
    Router,
};
use tokio::sync::Mutex;
use tungstenite::protocol::frame::coding::Data;

use std::net::SocketAddr;
use std::sync::Arc;

pub fn test_api(runtime: tokio::runtime::Runtime, datastore: Arc<Mutex<Datastore>>) {
    let app = Router::new()
        .route("/v2/identities", post(identity_create))
        .route("/v2/identities/:id", get(identity_get))
        .with_state(datastore);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

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

async fn identity_get(Path(key): Path<String>, State(state): State<Arc<Mutex<Datastore>>>) {}

async fn identity_create(
    Path(key): Path<String>,
    State(state): State<Arc<Mutex<Datastore>>>,
    bytes: Bytes,
) {
    // ...
}
