use crate::{datastore::Datastore, messaging, object, rpc};

use tokio::{runtime::Runtime, sync::Mutex};

use std::sync::Arc;

pub struct Server {
    datastore: Arc<Mutex<Datastore>>,
    runtime: Runtime,
}

impl Server {
    pub fn new(api_port: u16, object_port: u16, messaging_port: u16) -> Server {
        let datastore = Arc::new(Mutex::new(Datastore::new()));
        let mut runtime = tokio::runtime::Runtime::new().expect("failed to start tokio runtime");

        rpc::test_api(&mut runtime, api_port, datastore.clone());
        object::test_object(&mut runtime, object_port, datastore.clone());
        messaging::test_messaging(&mut runtime, messaging_port, datastore.clone());
        Server { datastore, runtime }
    }
}

impl Default for Server {
    fn default() -> Self {
        Server::new(3000, 3500, 4000)
    }
}
