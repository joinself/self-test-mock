use rand::prelude::*;
use rand::rngs::adapter::ReseedingRng;
use rand::rngs::OsRng;
use rand_chacha::ChaCha20Core;

pub struct ProofOfWork {
    target: Vec<u8>,
}

impl ProofOfWork {
    pub fn new(leading_zero_bits: usize) -> ProofOfWork {
        // allocate a target buffer to compare against
        // garbage, but it works ¯\_(ツ)_/¯
        let mut target = vec![0; 32];

        for offset in leading_zero_bits..256 {
            target[offset >> 3] |= (1 << (offset & 0x7)) as u8
        }

        let mut cap = 0;

        for (i, v) in target.iter().enumerate() {
            if *v == 255 {
                cap = i;
                break;
            }
        }

        ProofOfWork {
            target: target[..cap].to_vec(),
        }
    }

    pub fn calculate(&self, data: &[u8]) -> (Vec<u8>, u64) {
        // find the hash and nonce combination that
        // fulfills the desired leading zeros target

        // generate a new csprng
        let prng = ChaCha20Core::from_entropy();
        let mut reseeding_rng = ReseedingRng::new(prng, 0, OsRng);

        // allocate a buffer to compute the hash over
        let mut hash_buf = vec![0; data.len() + 8];
        hash_buf[..data.len()].copy_from_slice(data);

        let mut nonce = reseeding_rng.gen::<u64>();

        loop {
            hash_buf[data.len()..].copy_from_slice(&nonce.to_le_bytes());

            let hash = crate::crypto::hash::blake2b(&hash_buf);

            if self.matches(&hash) {
                return (hash, nonce);
            }

            nonce += 1;
        }
    }

    pub fn validate(&self, data: &[u8], hash: &[u8], nonce: u64) -> bool {
        if !self.matches(hash) {
            return false;
        }

        let mut hash_buf = vec![0; data.len() + 8];
        hash_buf[..data.len()].copy_from_slice(data);
        hash_buf[data.len()..].copy_from_slice(&nonce.to_le_bytes());

        let computed_hash = crate::crypto::hash::blake2b(&hash_buf);

        computed_hash == hash
    }

    fn matches(&self, hash: &[u8]) -> bool {
        for offset in 0..(self.target.len() * 8) {
            if hash[offset >> 3] > self.target[offset >> 3] {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn proof_of_work() {
        let p = ProofOfWork::new(23);

        let data = vec![8; 128];

        let (hash, nonce) = p.calculate(&data);

        assert!(p.validate(&data, &hash, nonce));
    }
}
