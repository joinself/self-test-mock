use std::cell::RefCell;
use std::rc::Rc;

use crate::keypair::signing::PublicKey;
use crate::protocol::siggraph::KeyRole;

#[derive(Debug)]
pub struct Node {
    pub typ: KeyRole,
    pub seq: u32,
    pub ca: i64,
    pub ra: i64,
    pub pk: PublicKey,
    pub incoming: Vec<Rc<RefCell<Node>>>,
    pub outgoing: Vec<Rc<RefCell<Node>>>,
}

impl Node {
    pub fn collect(&self) -> Vec<Rc<RefCell<Node>>> {
        let mut nodes: Vec<Rc<RefCell<Node>>> = Vec::new();

        for node in &self.outgoing {
            nodes.push(node.clone());
            nodes.append(&mut node.borrow().collect());
        }

        nodes
    }
}
