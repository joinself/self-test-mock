use hex::ToHex;
use serde::{Deserialize, Serialize};

use crate::error::SelfError;
use crate::keypair::Algorithm;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyPair {
    public_key: PublicKey,
    secret_key: SecretKey,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PublicKey {
    bytes: Vec<u8>,
}

impl PublicKey {
    pub fn import(_algorithm: Algorithm, public_key: &str) -> Result<PublicKey, SelfError> {
        let decoded_public_key = match base64::decode_config(public_key, base64::URL_SAFE_NO_PAD) {
            Ok(decoded_public_key) => decoded_public_key,
            Err(_) => return Err(SelfError::KeyPairDecodeInvalidData),
        };

        if decoded_public_key.len() != 32 {
            return Err(SelfError::KeyPairPublicKeyInvalidLength);
        }

        Ok(PublicKey {
            bytes: decoded_public_key,
        })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, SelfError> {
        if bytes.len() < 33 {
            return Err(SelfError::KeyPairPublicKeyInvalidLength);
        }

        Ok(PublicKey {
            bytes: bytes.to_vec(),
        })
    }

    pub fn validate(bytes: &[u8]) -> Result<(), SelfError> {
        if bytes.len() < 33 {
            return Err(SelfError::KeyPairPublicKeyInvalidLength);
        }

        if bytes[0] != Algorithm::Ed25519 as u8 {
            return Err(SelfError::KeyPairAlgorithmUnknown);
        }

        Ok(())
    }

    pub fn address(&self) -> &[u8] {
        &self.bytes
    }

    pub fn public_key_bytes(&self) -> &[u8] {
        &self.bytes[1..33]
    }

    pub fn to_did_key(&self) -> String {
        self.bytes.encode_hex()
    }

    pub fn matches(&self, bytes: &[u8]) -> bool {
        self.bytes.eq(bytes)
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        unsafe {
            sodium_sys::crypto_sign_ed25519_verify_detached(
                signature.as_ptr(),
                message.as_ptr(),
                message.len() as u64,
                self.bytes[1..33].as_ptr(),
            ) == 0
        }
    }
}

impl std::hash::Hash for PublicKey {
    fn hash<H>(&self, state: &mut H)
    where
        H: std::hash::Hasher,
    {
        state.write(&self.bytes);
        state.finish();
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        self.bytes.eq(&other.bytes)
    }
}

impl Eq for PublicKey {}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SecretKey {
    bytes: Vec<u8>,
}

impl KeyPair {
    pub fn new() -> KeyPair {
        let mut ed25519_pk =
            vec![0u8; sodium_sys::crypto_sign_PUBLICKEYBYTES as usize + 1].into_boxed_slice();
        let mut ed25519_sk =
            vec![0u8; sodium_sys::crypto_sign_SECRETKEYBYTES as usize].into_boxed_slice();

        ed25519_pk[0] = crate::keypair::Algorithm::Ed25519 as u8;

        unsafe {
            sodium_sys::crypto_sign_keypair(
                ed25519_pk[1..33].as_mut_ptr(),
                ed25519_sk.as_mut_ptr(),
            );
        }

        KeyPair {
            public_key: PublicKey {
                bytes: ed25519_pk.to_vec(),
            },
            secret_key: SecretKey {
                bytes: ed25519_sk.to_vec(),
            },
        }
    }

    pub fn from_parts(public_key: PublicKey, secret_key: SecretKey) -> KeyPair {
        KeyPair {
            public_key,
            secret_key,
        }
    }

    pub fn decode(encoded_keypair: &[u8]) -> Result<KeyPair, SelfError> {
        match postcard::from_bytes(encoded_keypair) {
            Ok(keypair) => Ok(keypair),
            Err(_) => Err(SelfError::KeyPairDecodeInvalidData),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("failed to encode keypair")
    }

    pub fn import(&self, legacy_keypair: &str) -> Result<KeyPair, SelfError> {
        let (_, encoded_seed) = match legacy_keypair.split_once(':') {
            Some((first, last)) => (first, last),
            None => return Err(SelfError::KeyPairDecodeInvalidData),
        };

        let seed = match base64::decode(encoded_seed) {
            Ok(seed) => seed,
            Err(_) => return Err(SelfError::KeyPairDecodeInvalidData),
        };

        let mut ed25519_pk =
            vec![0u8; sodium_sys::crypto_sign_PUBLICKEYBYTES as usize + 1].into_boxed_slice();
        let mut ed25519_sk =
            vec![0u8; sodium_sys::crypto_sign_SECRETKEYBYTES as usize].into_boxed_slice();

        ed25519_pk[0] = crate::keypair::Algorithm::Ed25519 as u8;

        unsafe {
            sodium_sys::crypto_sign_seed_keypair(
                ed25519_pk[1..33].as_mut_ptr(),
                ed25519_sk.as_mut_ptr(),
                seed.as_ptr(),
            );
        }

        Ok(KeyPair {
            public_key: PublicKey {
                bytes: ed25519_pk.to_vec(),
            },
            secret_key: SecretKey {
                bytes: ed25519_sk.to_vec(),
            },
        })
    }

    pub fn address(&self) -> &[u8] {
        self.public_key.address()
    }

    pub fn public(&self) -> &PublicKey {
        &self.public_key
    }

    // this exists for testing only from other packages
    pub fn secret(&self) -> SecretKey {
        self.secret_key.clone()
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let mut signature = vec![0u8; sodium_sys::crypto_sign_BYTES as usize].into_boxed_slice();

        unsafe {
            sodium_sys::crypto_sign_ed25519_detached(
                signature.as_mut_ptr(),
                &mut (signature.len() as u64),
                message.as_ptr(),
                message.len() as u64,
                self.secret_key.bytes.as_ptr(),
            );
        }

        signature.to_vec()
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
