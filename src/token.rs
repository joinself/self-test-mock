use crate::identifier::Identifier;
use crate::{error::SelfError, keypair::signing::PublicKey};

use byteorder::{LittleEndian, ReadBytesExt};
use chrono::{TimeZone, Utc};
use serde::{Deserialize, Serialize};

const FLAG_DELEGATION_PERMIT: u8 = 1 << 1;
const FLAG_BEARER_PROMISCUOUS: u8 = 1 << 2;

const TOKEN_VERSION_1: u8 = 1;

const TOKEN_KIND_AUTHENTICATION: u8 = 1;
const TOKEN_KIND_AUTHORIZATION: u8 = 2;
const TOKEN_KIND_NOTIFICATION: u8 = 3;
const TOKEN_KIND_SUBSCRIPTION: u8 = 4;
const TOKEN_KIND_DELEGATION: u8 = 5;

const SIGNER_ALG_ED25519: u8 = 1;

#[derive(Clone, Serialize, Deserialize)]
pub enum Token {
    Authentication(Authentication),
    Authorization(Authorization),
    Notification(Notification),
    Subscription(Subscription),
    Delegation(Delegation),
}

impl Token {
    pub fn kind(&self) -> u8 {
        match self {
            Token::Authentication(_) => TOKEN_KIND_AUTHENTICATION,
            Token::Authorization(_) => TOKEN_KIND_AUTHORIZATION,
            Token::Notification(_) => TOKEN_KIND_NOTIFICATION,
            Token::Subscription(_) => TOKEN_KIND_SUBSCRIPTION,
            Token::Delegation(_) => TOKEN_KIND_DELEGATION,
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Token, SelfError> {
        if bytes[0] != TOKEN_VERSION_1 {
            return Err(SelfError::TokenVersionInvalid);
        }

        // TODO proper token validation
        Ok(match bytes[1] {
            TOKEN_KIND_AUTHENTICATION => Token::Authentication(Authentication {
                token: bytes.to_vec(),
            }),
            TOKEN_KIND_AUTHORIZATION => Token::Authorization(Authorization {
                token: bytes.to_vec(),
            }),
            TOKEN_KIND_NOTIFICATION => Token::Notification(Notification {
                token: bytes.to_vec(),
            }),
            TOKEN_KIND_SUBSCRIPTION => Token::Subscription(Subscription {
                token: bytes.to_vec(),
            }),
            TOKEN_KIND_DELEGATION => Token::Delegation(Delegation {
                token: bytes.to_vec(),
            }),
            _ => return Err(SelfError::TokenTypeInvalid),
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, SelfError> {
        Ok(match self {
            Token::Authentication(auth) => auth.token.to_vec(),
            Token::Authorization(auth) => auth.token.to_vec(),
            Token::Notification(notif) => notif.token.to_vec(),
            Token::Subscription(sub) => sub.token.to_vec(),
            Token::Delegation(del) => del.token.to_vec(),
        })
    }

    pub fn version(&self) -> u8 {
        match self {
            Token::Authentication(auth) => auth.token[0],
            Token::Authorization(auth) => auth.token[0],
            Token::Notification(notif) => notif.token[0],
            Token::Subscription(sub) => sub.token[0],
            Token::Delegation(del) => del.token[0],
        }
    }

    pub fn id(&self) -> Vec<u8> {
        match self {
            Token::Authentication(auth) => auth.token[6..26].to_vec(),
            Token::Authorization(auth) => auth.token[6..26].to_vec(),
            Token::Notification(notif) => notif.token[6..26].to_vec(),
            Token::Subscription(sub) => sub.token[6..26].to_vec(),
            Token::Delegation(del) => del.token[6..26].to_vec(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Authentication {
    pub token: Vec<u8>,
}

impl Authentication {
    pub fn signer(&self) -> Identifier {
        Identifier::Referenced(self.token[35..67].to_vec())
    }

    pub fn verify(&self, signed_data: &[u8]) -> Result<(), SelfError> {
        // TODO validate token expiry, etc

        let pk = match self.token[34] {
            SIGNER_ALG_ED25519 => {
                PublicKey::from_bytes(&self.signer().id(), crate::keypair::Algorithm::Ed25519)?
            }
            _ => return Err(SelfError::TokenTypeInvalid),
        };

        let token_len = self.token.len();

        let mut signed_data_buf = vec![0; (token_len - 64) + signed_data.len()];
        signed_data_buf[0..token_len - 64].copy_from_slice(&self.token[0..(token_len - 64)]);
        signed_data_buf[(token_len - 64)..].copy_from_slice(signed_data);

        if !pk.verify(&signed_data_buf, &self.token[(token_len - 64)..]) {
            return Err(SelfError::TokenSignatureInvalid);
        }

        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Authorization {
    pub token: Vec<u8>,
}

impl Authorization {
    pub fn signer(&self) -> Identifier {
        Identifier::Referenced(self.token[35..67].to_vec())
    }

    pub fn verify(&self) -> Result<(), SelfError> {
        let pk = match self.token[34] {
            SIGNER_ALG_ED25519 => {
                PublicKey::from_bytes(&self.signer().id(), crate::keypair::Algorithm::Ed25519)?
            }
            _ => return Err(SelfError::TokenTypeInvalid),
        };

        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Notification {
    pub token: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Delegation {
    pub token: Vec<u8>,
}

impl Delegation {
    pub fn signer(&self) -> Identifier {
        Identifier::Referenced(self.token[35..67].to_vec())
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Subscription {
    pub token: Vec<u8>,
}

impl Subscription {
    pub fn signer(&self) -> Identifier {
        Identifier::Referenced(self.token[35..67].to_vec())
    }

    pub fn bearer(&self) -> Identifier {
        Identifier::Referenced(self.token[35..67].to_vec())
    }
}
