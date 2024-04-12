use hex::ToHex;
use serde::{Deserialize, Serialize};
use sodium_sys::{
    crypto_box_MACBYTES, crypto_box_NONCEBYTES, crypto_box_SEALBYTES, crypto_box_easy,
    crypto_box_open_easy, crypto_box_seal, crypto_box_seal_open,
};

use crate::crypto::random;
use crate::error::SelfError;
use crate::keypair::Algorithm;

#[derive(Serialize, Deserialize, Debug)]
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

        if bytes[0] != Algorithm::Curve25519 as u8 {
            return Err(SelfError::KeyPairAlgorithmUnknown);
        }

        Ok(())
    }

    pub fn seal_anonymous(&self, message: &[u8]) -> Vec<u8> {
        let mut ciphertext = vec![0u8; message.len() + (crypto_box_SEALBYTES) as usize];

        unsafe {
            let result = crypto_box_seal(
                ciphertext.as_mut_ptr(),
                message.as_ptr(),
                message.len() as libc::c_ulonglong,
                self.public_key_bytes().as_ptr(),
            );

            assert_eq!(result, 0);
        }

        ciphertext
    }

    pub fn matches(&self, bytes: &[u8]) -> bool {
        self.bytes.eq(bytes)
    }

    pub fn address(&self) -> &[u8] {
        &self.bytes
    }

    pub fn public_key_bytes(&self) -> &[u8] {
        &self.bytes[1..33]
    }

    pub fn encoded_id(&self) -> String {
        self.bytes.encode_hex()
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

#[derive(Serialize, Deserialize, Debug)]
pub struct SecretKey {
    bytes: Vec<u8>,
}

impl KeyPair {
    pub fn new() -> KeyPair {
        let mut curve25519_pk =
            vec![0u8; sodium_sys::crypto_box_PUBLICKEYBYTES as usize + 1].into_boxed_slice();
        let mut curve25519_sk =
            vec![0u8; sodium_sys::crypto_box_SECRETKEYBYTES as usize].into_boxed_slice();

        curve25519_pk[0] = Algorithm::Curve25519 as u8;

        unsafe {
            sodium_sys::crypto_box_keypair(
                curve25519_pk[1..33].as_mut_ptr(),
                curve25519_sk.as_mut_ptr(),
            );
        }

        KeyPair {
            public_key: PublicKey {
                bytes: curve25519_pk.to_vec(),
            },
            secret_key: SecretKey {
                bytes: curve25519_sk.to_vec(),
            },
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

        let mut curve25519_pk =
            vec![0u8; sodium_sys::crypto_box_PUBLICKEYBYTES as usize + 1].into_boxed_slice();
        let mut curve25519_sk =
            vec![0u8; sodium_sys::crypto_box_SECRETKEYBYTES as usize].into_boxed_slice();

        curve25519_pk[0] = Algorithm::Curve25519 as u8;

        unsafe {
            sodium_sys::crypto_box_seed_keypair(
                curve25519_pk[1..33].as_mut_ptr(),
                curve25519_sk.as_mut_ptr(),
                seed.as_ptr(),
            );
        }

        Ok(KeyPair {
            public_key: PublicKey {
                bytes: curve25519_pk.to_vec(),
            },
            secret_key: SecretKey {
                bytes: curve25519_sk.to_vec(),
            },
        })
    }

    pub fn address(&self) -> &[u8] {
        self.public_key.address()
    }

    pub fn public(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn seal(&self, recipient: &PublicKey, message: &[u8]) -> Vec<u8> {
        let mut ciphertext =
            vec![0u8; message.len() + (crypto_box_MACBYTES + crypto_box_NONCEBYTES) as usize];
        random::read_bytes(&mut ciphertext[message.len() + (crypto_box_MACBYTES as usize)..]);

        unsafe {
            let result = crypto_box_easy(
                ciphertext.as_mut_ptr(),
                message.as_ptr(),
                message.len() as libc::c_ulonglong,
                ciphertext[message.len() + (crypto_box_MACBYTES as usize)..].as_ptr(),
                recipient.public_key_bytes().as_ptr(),
                self.secret_key.bytes.as_ptr(),
            );

            assert_eq!(result, 0);
        }

        ciphertext
    }

    pub fn open(&self, sender: &PublicKey, message: &[u8]) -> Result<Vec<u8>, SelfError> {
        let mut plaintext =
            vec![0u8; message.len() - (crypto_box_MACBYTES + crypto_box_NONCEBYTES) as usize];

        unsafe {
            let result = crypto_box_open_easy(
                plaintext.as_mut_ptr(),
                message.as_ptr(),
                (message.len() - crypto_box_NONCEBYTES as usize) as libc::c_ulonglong,
                message[message.len() - (crypto_box_NONCEBYTES as usize)..].as_ptr(),
                sender.public_key_bytes().as_ptr(),
                self.secret_key.bytes.as_ptr(),
            );

            if result != 0 {
                return Err(SelfError::CryptoBoxOpenFailed);
            }
        }

        Ok(plaintext)
    }

    pub fn open_anonymous(&self, message: &[u8]) -> Result<Vec<u8>, SelfError> {
        let mut plaintext = vec![0u8; message.len() - (crypto_box_SEALBYTES) as usize];

        unsafe {
            let result = crypto_box_seal_open(
                plaintext.as_mut_ptr(),
                message.as_ptr(),
                message.len() as libc::c_ulonglong,
                self.public_key.public_key_bytes().as_ptr(),
                self.secret_key.bytes.as_ptr(),
            );

            if result != 0 {
                return Err(SelfError::CryptoBoxOpenFailed);
            }
        }

        Ok(plaintext)
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
