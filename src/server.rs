use crate::{datastore::Datastore, messaging};

use tokio::{runtime::Runtime, sync::Mutex};

use std::sync::Arc;

pub struct Server {
    datastore: Arc<Mutex<Datastore>>,
    runtime: Runtime,
}

impl Server {
    pub fn new() -> Server {
        let datastore = Arc::new(Mutex::new(Datastore::new()));

        Server {
            datastore: datastore.clone(),
            runtime: messaging::test_messaging(datastore),
        }
    }
}

impl Default for Server {
    fn default() -> Self {
        Server::new()
    }
}

#[cfg(test)]
mod tests {}
