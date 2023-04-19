pub mod exchange;
pub mod signing;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum Algorithm {
    Ed25519,
    Curve25519,
}

//#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
//pub enum Role {}
