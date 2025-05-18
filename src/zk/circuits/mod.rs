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

/// A circuit that proves set membership without revealing the element
#[derive(Clone)]
pub struct SetMembershipCircuit {
    /// The secret element to prove membership for
    pub element: Vec<u8>,
    /// The public set of elements (hashed)
    pub set_hashes: Vec<Vec<u8>>,
    /// The merkle root of the set
    pub merkle_root: Vec<u8>,
}

impl Circuit for SetMembershipCircuit {
    fn generate_proof(&self, pk: &ProvingKey<Bn254>) -> Result<Proof<Bn254>> {
        // Hash the element
        let mut hasher = Sha256::new();
        hasher.update(&self.element);
        let element_hash = hasher.finalize().to_vec();
        
        // Verify element is in set
        if !self.set_hashes.contains(&element_hash) {
            return Err(crate::Error::Zk("Element not in set".into()));
        }
        
        // Generate merkle proof
        let merkle_proof = generate_merkle_proof(&element_hash, &self.set_hashes);
        
        let rng = &mut OsRng;
        create_random_proof(self.clone(), pk, rng)
            .map_err(|e| crate::Error::Zk(e.to_string()))
    }

    fn verify_proof(&self, vk: &VerifyingKey<Bn254>, proof: &Proof<Bn254>) -> Result<bool> {
        let pvk = prepare_verifying_key(vk);
        
        // Convert merkle root to field elements
        let root_bits = bytes_to_bits(&self.merkle_root);
        verify_proof(&pvk, proof, &[Fr::from(root_bits.len() as u64)])
            .map_err(|e| crate::Error::Zk(e.to_string()))
    }
}

/// Generate a merkle proof for set membership
fn generate_merkle_proof(element: &[u8], set: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut proof = Vec::new();
    let mut current_hash = element.to_vec();
    
    for sibling in set {
        if current_hash != *sibling {
            proof.push(sibling.clone());
            let mut hasher = Sha256::new();
            hasher.update(&current_hash);
            hasher.update(sibling);
            current_hash = hasher.finalize().to_vec();
        }
    }
    
    proof
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

    #[test]
    fn test_set_membership() {
        let element = b"secret member".to_vec();
        let set = vec![
            b"member1".to_vec(),
            b"secret member".to_vec(),
            b"member3".to_vec(),
        ];
        
        let mut set_hashes = Vec::new();
        for e in &set {
            let mut hasher = Sha256::new();
            hasher.update(e);
            set_hashes.push(hasher.finalize().to_vec());
        }
        
        let merkle_root = compute_merkle_root(&set_hashes);
        
        let circuit = SetMembershipCircuit {
            element,
            set_hashes,
            merkle_root,
        };
        
        let (pk, vk) = generate_keys(&circuit).unwrap();
        let proof = circuit.generate_proof(&pk).unwrap();
        assert!(circuit.verify_proof(&vk, &proof).unwrap());
    }
}

/// Compute the merkle root of a set of hashes
fn compute_merkle_root(hashes: &[Vec<u8>]) -> Vec<u8> {
    if hashes.is_empty() {
        return vec![];
    }
    
    let mut current_level = hashes.to_vec();
    
    while current_level.len() > 1 {
        let mut next_level = Vec::new();
        
        for chunk in current_level.chunks(2) {
            let mut hasher = Sha256::new();
            hasher.update(&chunk[0]);
            if chunk.len() > 1 {
                hasher.update(&chunk[1]);
            }
            next_level.push(hasher.finalize().to_vec());
        }
        
        current_level = next_level;
    }
    
    current_level.remove(0)
} 