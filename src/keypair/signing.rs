use hex::ToHex;

use crate::error::SelfError;
use crate::keypair::Algorithm;

#[derive(Debug, Clone)]
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
    pub fn import(algorithm: Algorithm, public_key: &str) -> Result<PublicKey, SelfError> {
        let decoded_public_key = match base64::decode_config(public_key, base64::URL_SAFE_NO_PAD) {
            Ok(decoded_public_key) => decoded_public_key,
            Err(_) => return Err(SelfError::KeyPairDecodeInvalidData),
        };

        if decoded_public_key.len() != 32 {
            return Err(SelfError::KeyPairPublicKeyInvalidLength);
        }

        Ok(PublicKey {
            algorithm,
            bytes: decoded_public_key,
        })
    }

    pub fn from_bytes(bytes: &[u8], algorithm: Algorithm) -> Result<PublicKey, SelfError> {
        if bytes.len() < 32 {
            return Err(SelfError::KeyPairPublicKeyInvalidLength);
        }

        Ok(PublicKey {
            algorithm,
            bytes: bytes.to_vec(),
        })
    }

    pub fn from_address(address: &[u8]) -> Result<PublicKey, SelfError> {
        if address.len() < 33 {
            return Err(SelfError::KeyPairPublicKeyInvalidLength);
        }

        let algorithm = match address[0] {
            0 => Algorithm::Ed25519,
            _ => return Err(SelfError::KeyPairAlgorithmUnknown),
        };

        Ok(PublicKey {
            algorithm,
            bytes: address[1..33].to_vec(),
        })
    }

    pub fn id(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    pub fn address(&self) -> Vec<u8> {
        // TODO properly address this later
        let mut address = vec![0; 33];
        address[0] = crate::keypair::Algorithm::Ed25519 as u8;
        address[1..33].copy_from_slice(&self.bytes);
        address
    }

    pub fn encoded_id(&self) -> String {
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
                self.bytes.as_ptr(),
            ) == 0
        }
    }

    pub fn to_exchange_key(&self) -> Result<crate::keypair::exchange::PublicKey, SelfError> {
        let mut curve25519_pk =
            vec![0u8; sodium_sys::crypto_box_PUBLICKEYBYTES as usize].into_boxed_slice();

        unsafe {
            if sodium_sys::crypto_sign_ed25519_pk_to_curve25519(
                curve25519_pk.as_mut_ptr(),
                self.bytes.as_ptr(),
            ) != 0
            {
                return Err(SelfError::KeyPairConversionFailed);
            }
        }

        crate::keypair::exchange::PublicKey::from_bytes(&curve25519_pk, Algorithm::Curve25519)
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

#[derive(Debug, Clone)]
pub struct SecretKey {
    bytes: Vec<u8>,
}

impl KeyPair {
    pub fn new() -> KeyPair {
        let mut ed25519_pk =
            vec![0u8; sodium_sys::crypto_sign_PUBLICKEYBYTES as usize].into_boxed_slice();
        let mut ed25519_sk =
            vec![0u8; sodium_sys::crypto_sign_SECRETKEYBYTES as usize].into_boxed_slice();

        unsafe {
            sodium_sys::crypto_sign_keypair(ed25519_pk.as_mut_ptr(), ed25519_sk.as_mut_ptr());
        }

        KeyPair {
            public_key: PublicKey {
                algorithm: Algorithm::Ed25519,
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

    pub fn to_exchange_key(&self) -> Result<crate::keypair::exchange::KeyPair, SelfError> {
        let mut curve25519_pk =
            vec![0u8; sodium_sys::crypto_box_PUBLICKEYBYTES as usize].into_boxed_slice();
        let mut curve25519_sk =
            vec![0u8; sodium_sys::crypto_box_SECRETKEYBYTES as usize].into_boxed_slice();

        unsafe {
            if sodium_sys::crypto_sign_ed25519_sk_to_curve25519(
                curve25519_sk.as_mut_ptr(),
                self.secret_key.bytes.as_ptr(),
            ) != 0
            {
                return Err(SelfError::KeyPairConversionFailed);
            }

            if sodium_sys::crypto_sign_ed25519_pk_to_curve25519(
                curve25519_pk.as_mut_ptr(),
                self.public_key.bytes.as_ptr(),
            ) != 0
            {
                return Err(SelfError::KeyPairConversionFailed);
            }
        }

        crate::keypair::exchange::KeyPair::from_bytes(
            curve25519_pk.to_vec(),
            curve25519_sk.to_vec(),
        )
    }

    pub fn id(&self) -> Vec<u8> {
        self.public_key.id()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new() {
        let skp = KeyPair::new();
        assert_eq!(skp.public().id().len(), 32);
    }

    #[test]
    fn sign_verify() {
        let skp = KeyPair::new();
        assert_eq!(skp.public().id().len(), 32);

        // sign some data
        let message = "hello".as_bytes();
        let signature = skp.sign(message);
        assert!(signature.len() == 64);

        // verify the signature
        assert!(skp.public().verify(message, &signature));

        // verify a bad signature
        let mut bad_signature = signature.clone();
        bad_signature[0] = 100;
        assert!(!skp.public().verify(message, &bad_signature));

        // verify a bad message
        let bad_message = "goodbye".as_bytes();
        assert!(!skp.public().verify(bad_message, &signature));
    }

    #[test]
    fn generate_ed25519_and_curve25519_keypair() {
        let mut ed25519_pk =
            vec![0u8; sodium_sys::crypto_sign_PUBLICKEYBYTES as usize].into_boxed_slice();
        let mut ed25519_sk =
            vec![0u8; sodium_sys::crypto_sign_SECRETKEYBYTES as usize].into_boxed_slice();

        unsafe {
            sodium_sys::crypto_sign_keypair(ed25519_pk.as_mut_ptr(), ed25519_sk.as_mut_ptr());
        }

        let mut curve25519_sk =
            vec![0u8; sodium_sys::crypto_sign_PUBLICKEYBYTES as usize].into_boxed_slice();
        let mut curve25519_pk =
            vec![0u8; sodium_sys::crypto_sign_SECRETKEYBYTES as usize].into_boxed_slice();

        unsafe {
            sodium_sys::crypto_sign_ed25519_sk_to_curve25519(
                curve25519_sk.as_mut_ptr(),
                ed25519_sk.as_ptr(),
            );
            sodium_sys::crypto_sign_ed25519_pk_to_curve25519(
                curve25519_pk.as_mut_ptr(),
                ed25519_pk.as_ptr(),
            );
        }
    }
}
