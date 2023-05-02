use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyRequest {
    pub identifier: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Authentication {
    pub iss: Vec<u8>,
    pub tkn: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PrekeyResponse {
    pub key: Vec<u8>,
}
