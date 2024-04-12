pub mod exchange;
pub mod signing;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[repr(u8)]
pub enum Algorithm {
    Ed25519,
    Curve25519,
}

#[repr(u64)]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum Roles {
    Verification = 1 << 1,
    Authentication = 1 << 2,
    Assertion = 1 << 3,
    Invocation = 1 << 4,
    Delegation = 1 << 5,
    Exchange = 1 << 6,
}
