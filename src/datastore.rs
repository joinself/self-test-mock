use tungstenite::Message;

use crate::keypair::signing::PublicKey;

use std::collections::{HashMap, VecDeque};

type Subscription = (Vec<u8>, Vec<u8>, async_channel::Sender<Message>);

pub struct Datastore {
    pub identities: HashMap<Vec<u8>, Vec<Vec<u8>>>,
    pub keys: HashMap<Vec<u8>, Option<PublicKey>>,
    pub messages: HashMap<Vec<u8>, Vec<Vec<u8>>>,
    pub one_time_keys: HashMap<Vec<u8>, VecDeque<Vec<u8>>>,
    pub subscribers: HashMap<Vec<u8>, Vec<Subscription>>,
}

impl Datastore {
    pub fn new() -> Datastore {
        Datastore {
            identities: HashMap::new(),
            keys: HashMap::new(),
            messages: HashMap::new(),
            one_time_keys: HashMap::new(),
            subscribers: HashMap::new(),
        }
    }
}

impl Default for Datastore {
    fn default() -> Self {
        Datastore::new()
    }
}
