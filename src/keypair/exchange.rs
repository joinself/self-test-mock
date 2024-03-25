use hex::ToHex;

use crate::error::SelfError;
use crate::keypair::Algorithm;

#[derive(Debug)]
pub struct KeyPair {
    public_key: PublicKey,
    secret_key: SecretKey,
}

#[derive(Debug, Clone)]
pub struct PublicKey {
    algorithm: Algorithm,
    bytes: Vec<u8>,
}

impl PublicKey {
    pub fn from_bytes(bytes: &[u8], algorithm: Algorithm) -> Result<PublicKey, SelfError> {
        if bytes.len() < 32 {
            return Err(SelfError::KeyPairPublicKeyInvalidLength);
        }

        Ok(PublicKey {
            algorithm,
            bytes: bytes.to_vec(),
        })
    }

    pub fn id(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    pub fn address(&self) -> Vec<u8> {
        // TODO properly address this later
        let mut address = vec![0; 33];
        address[0] = crate::keypair::Algorithm::Curve25519 as u8;
        address[1..33].copy_from_slice(&self.bytes);
        address
    }

    pub fn encoded_id(&self) -> String {
        self.bytes.encode_hex()
    }
}

#[derive(Debug)]
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
                algorithm: Algorithm::Curve25519,
                bytes: curve25519_pk.to_vec(),
            },
            secret_key: SecretKey {
                bytes: curve25519_sk.to_vec(),
            },
        }
    }

    pub fn from_bytes(public_key: Vec<u8>, secret_key: Vec<u8>) -> Result<KeyPair, SelfError> {
        if public_key.len() != sodium_sys::crypto_box_PUBLICKEYBYTES as usize {
            return Err(SelfError::KeyPairDataIncorrectLength);
        }
        if secret_key.len() != sodium_sys::crypto_box_SECRETKEYBYTES as usize {
            return Err(SelfError::KeyPairDataIncorrectLength);
        }

        Ok(KeyPair {
            public_key: PublicKey {
                algorithm: Algorithm::Curve25519,
                bytes: public_key,
            },
            secret_key: SecretKey { bytes: secret_key },
        })
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
                algorithm: Algorithm::Curve25519,
                bytes: curve25519_pk.to_vec(),
            },
            secret_key: SecretKey {
                bytes: curve25519_sk.to_vec(),
            },
        })
    }

    pub fn id(&self) -> Vec<u8> {
        self.public_key.bytes.clone()
    }

    pub fn address(&self) -> Vec<u8> {
        self.public_key.address()
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
