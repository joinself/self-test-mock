use hex::ToHex;
use serde::{Deserialize, Serialize};

use crate::error::SelfError;
use crate::keypair::Algorithm;

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyPair {
    public_key: PublicKey,
    secret_key: SecretKey,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PublicKey {
    id: Option<String>,
    algorithm: Algorithm,
    bytes: Vec<u8>,
}

impl PublicKey {
    pub fn import(
        id: &str,
        algorithm: Algorithm,
        public_key: &str,
    ) -> Result<PublicKey, SelfError> {
        let decoded_public_key = match base64::decode_config(public_key, base64::URL_SAFE_NO_PAD) {
            Ok(decoded_public_key) => decoded_public_key,
            Err(_) => return Err(SelfError::KeyPairDecodeInvalidData),
        };

        if decoded_public_key.len() != 32 {
            return Err(SelfError::KeyPairPublicKeyInvalidLength);
        }

        Ok(PublicKey {
            id: Some(String::from(id)),
            algorithm,
            bytes: decoded_public_key,
        })
    }

    pub fn id(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    pub fn encoded_id(&self) -> String {
        self.bytes.encode_hex()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SecretKey {
    bytes: Vec<u8>,
}

impl KeyPair {
    pub fn new() -> KeyPair {
        let mut curve25519_pk =
            vec![0u8; sodium_sys::crypto_box_PUBLICKEYBYTES as usize].into_boxed_slice();
        let mut curve25519_sk =
            vec![0u8; sodium_sys::crypto_box_SECRETKEYBYTES as usize].into_boxed_slice();

        unsafe {
            sodium_sys::crypto_box_keypair(curve25519_pk.as_mut_ptr(), curve25519_sk.as_mut_ptr());
        }

        KeyPair {
            public_key: PublicKey {
                id: None,
                algorithm: Algorithm::Curve25519,
                bytes: curve25519_pk.to_vec(),
            },
            secret_key: SecretKey {
                bytes: curve25519_sk.to_vec(),
            },
        }
    }

    pub fn decode(encoded_keypair: &[u8]) -> Result<KeyPair, SelfError> {
        match ciborium::de::from_reader(encoded_keypair) {
            Ok(keypair) => Ok(keypair),
            Err(_) => Err(SelfError::KeyPairDecodeInvalidData),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(self, &mut encoded).unwrap();
        encoded
    }

    pub fn import(&self, legacy_keypair: &str) -> Result<KeyPair, SelfError> {
        let (key_id, encoded_seed) = match legacy_keypair.split_once(':') {
            Some((first, last)) => (first, last),
            None => return Err(SelfError::KeyPairDecodeInvalidData),
        };

        let seed = match base64::decode(encoded_seed) {
            Ok(seed) => seed,
            Err(_) => return Err(SelfError::KeyPairDecodeInvalidData),
        };

        let mut curve25519_pk =
            vec![0u8; sodium_sys::crypto_box_PUBLICKEYBYTES as usize].into_boxed_slice();
        let mut curve25519_sk =
            vec![0u8; sodium_sys::crypto_box_SECRETKEYBYTES as usize].into_boxed_slice();

        unsafe {
            sodium_sys::crypto_box_seed_keypair(
                curve25519_pk.as_mut_ptr(),
                curve25519_sk.as_mut_ptr(),
                seed.as_ptr(),
            );
        }

        Ok(KeyPair {
            public_key: PublicKey {
                id: Some(String::from(key_id)),
                algorithm: Algorithm::Curve25519,
                bytes: curve25519_pk.to_vec(),
            },
            secret_key: SecretKey {
                bytes: curve25519_sk.to_vec(),
            },
        })
    }

    pub fn id(&self) -> String {
        if self.public_key.id.is_some() {
            return self.public_key.id.as_ref().unwrap().clone();
        }

        base64::encode_config(&self.public_key.bytes, base64::URL_SAFE_NO_PAD)
    }

    pub fn algorithm(&self) -> Algorithm {
        self.public_key.algorithm
    }

    pub fn public(&self) -> PublicKey {
        self.public_key.clone()
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.secret_key.bytes.clone()
    }
}

impl Default for KeyPair {
    fn default() -> Self {
        KeyPair::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new() {
        let skp = KeyPair::new();
        assert_eq!(skp.public().id().len(), 32);
    }

    #[test]
    fn encode_decode() {
        let skp = KeyPair::new();
        assert_eq!(skp.public().id().len(), 32);

        // encode and decode the keypair
        let encoded_skp = skp.encode();
        KeyPair::decode(&encoded_skp).unwrap();
    }
}
