use hex::ToHex;

use crate::error::SelfError;

use std::fmt;

#[derive(Clone)]
pub enum Identifier {
    Referenced(Vec<u8>),
}

impl Identifier {
    pub fn from_bytes(id: &[u8]) -> Result<Identifier, SelfError> {
        Ok(Identifier::Referenced(id.to_vec()))
    }

    pub fn id(&self) -> Vec<u8> {
        match self {
            Self::Referenced(id) => id.clone(),
        }
    }
}

impl fmt::Debug for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
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
        self.id().eq(&other.id())
    }
}

impl Eq for Identifier {}
