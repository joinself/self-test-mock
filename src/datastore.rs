use crate::identifier::Identifier;

use tungstenite::Message;

use std::collections::{HashMap, VecDeque};

type Subscription = (Vec<u8>, async_channel::Sender<Message>);

pub struct Datastore {
    pub identities: HashMap<Identifier, Vec<Vec<u8>>>,
    pub keys: HashMap<Identifier, Option<Identifier>>,
    pub messages: HashMap<Identifier, Vec<Vec<u8>>>,
    pub prekeys: HashMap<Identifier, VecDeque<Vec<u8>>>,
    pub subscribers: HashMap<Identifier, Vec<Subscription>>,
}

impl Datastore {
    pub fn new() -> Datastore {
        Datastore {
            identities: HashMap::new(),
            keys: HashMap::new(),
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
