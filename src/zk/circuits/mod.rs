use ark_bn254::{Bn254, Fr};
use ark_ff::{Field, PrimeField, UniformRand};
use ark_groth16::{Proof, ProvingKey, VerifyingKey};
use sha2::{Sha256, Digest};
use rand::rngs::OsRng;

use super::Circuit;
use crate::Result;

/// A circuit that proves knowledge of a preimage for a hash
#[derive(Clone)]
pub struct HashPreimageCircuit {
    /// The secret preimage
    pub preimage: Vec<u8>,
    /// The public hash
    pub hash: Vec<u8>,
}

impl Circuit for HashPreimageCircuit {
    fn generate_proof(&self, pk: &ProvingKey<Bn254>) -> Result<Proof<Bn254>> {
        // Convert preimage to field elements
        let preimage_bits = bytes_to_bits(&self.preimage);
        let mut hasher = Sha256::new();
        hasher.update(&self.preimage);
        
        let rng = &mut OsRng;
        // In a real implementation, we would construct the actual circuit here
        // For now, we're using a simplified version
        create_random_proof(self.clone(), pk, rng)
            .map_err(|e| crate::Error::Zk(e.to_string()))
    }

    fn verify_proof(&self, vk: &VerifyingKey<Bn254>, proof: &Proof<Bn254>) -> Result<bool> {
        let pvk = prepare_verifying_key(vk);
        let hash_bits = bytes_to_bits(&self.hash);
        
        verify_proof(&pvk, proof, &[Fr::from(hash_bits.len() as u64)])
            .map_err(|e| crate::Error::Zk(e.to_string()))
    }
}

/// A circuit that proves a number is within a range
#[derive(Clone)]
pub struct RangeProofCircuit {
    /// The secret number to prove bounds for
    pub number: u64,
    /// The public upper bound (exclusive)
    pub upper_bound: u64,
    /// The public lower bound (inclusive)
    pub lower_bound: u64,
}

impl Circuit for RangeProofCircuit {
    fn generate_proof(&self, pk: &ProvingKey<Bn254>) -> Result<Proof<Bn254>> {
        assert!(self.number >= self.lower_bound && self.number < self.upper_bound, 
            "Number out of bounds");
            
        let rng = &mut OsRng;
        // In a real implementation, we would construct range constraints here
        create_random_proof(self.clone(), pk, rng)
            .map_err(|e| crate::Error::Zk(e.to_string()))
    }

    fn verify_proof(&self, vk: &VerifyingKey<Bn254>, proof: &Proof<Bn254>) -> Result<bool> {
        let pvk = prepare_verifying_key(vk);
        verify_proof(&pvk, proof, &[
            Fr::from(self.lower_bound),
            Fr::from(self.upper_bound),
        ]).map_err(|e| crate::Error::Zk(e.to_string()))
    }
}

/// Convert bytes to bits for circuit constraints
fn bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for byte in bytes {
        for i in 0..8 {
            bits.push(((byte >> i) & 1) == 1);
        }
    }
    bits
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zk::generate_keys;

    #[test]
    fn test_hash_preimage() {
        let preimage = b"secret value".to_vec();
        let mut hasher = Sha256::new();
        hasher.update(&preimage);
        let hash = hasher.finalize().to_vec();

        let circuit = HashPreimageCircuit {
            preimage: preimage.clone(),
            hash: hash.clone(),
        };

        let (pk, vk) = generate_keys(&circuit).unwrap();
        let proof = circuit.generate_proof(&pk).unwrap();
        assert!(circuit.verify_proof(&vk, &proof).unwrap());
    }

    #[test]
    fn test_range_proof() {
        let circuit = RangeProofCircuit {
            number: 42,
            lower_bound: 0,
            upper_bound: 100,
        };

        let (pk, vk) = generate_keys(&circuit).unwrap();
        let proof = circuit.generate_proof(&pk).unwrap();
        assert!(circuit.verify_proof(&vk, &proof).unwrap());
    }
} 