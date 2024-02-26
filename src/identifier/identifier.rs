use crate::error::SelfError;
use crate::keypair::{
    signing::{KeyPair, PublicKey},
    Algorithm,
};

use hex::ToHex;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use std::fmt;
use std::io::Read;

#[derive(Clone)]
pub enum Identifier {
    Owned(KeyPair),
    Referenced(Vec<u8>),
}

impl Identifier {
    pub fn from_bytes(id: &[u8]) -> Result<Identifier, SelfError> {
        let pk = PublicKey::from_bytes(id, Algorithm::Ed25519)?;
        Ok(Identifier::Referenced(pk.id()))
    }

    pub fn id(&self) -> Vec<u8> {
        match self {
            Self::Owned(kp) => kp.id(),
            Self::Referenced(pk) => pk.to_owned(),
        }
    }

    pub fn public_key(&self) -> PublicKey {
        match self {
            Self::Owned(kp) => kp.public(),
            Self::Referenced(pk) => PublicKey::from_bytes(pk, Algorithm::Ed25519).expect("keypair"),
        }
    }
}

impl Serialize for Identifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.id())
    }
}

impl<'de> Deserialize<'de> for Identifier {
    fn deserialize<D>(deserializer: D) -> Result<Identifier, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(IdentifierVisitor)
    }
}

impl fmt::Debug for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Identifier::Owned(_) => f
                .debug_struct("Owned")
                .field("id", &self.id().encode_hex::<String>())
                .finish(),
            Identifier::Referenced(_) => f
                .debug_struct("Referenced")
                .field("id", &self.id().encode_hex::<String>())
                .finish(),
        }
    }
}

impl std::hash::Hash for Identifier {
    fn hash<H>(&self, state: &mut H)
    where
        H: std::hash::Hasher,
    {
        state.write(&self.id());
        state.finish();
    }
}

impl PartialEq for Identifier {
    fn eq(&self, other: &Identifier) -> bool {
        self.public_key().matches(&other.id())
    }
}

impl Eq for Identifier {}

struct IdentifierVisitor;

impl<'de> serde::de::Visitor<'de> for IdentifierVisitor {
    type Value = Identifier;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("an identifier 32 bytes long")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Identifier::Referenced(v.to_vec()))
    }
}
