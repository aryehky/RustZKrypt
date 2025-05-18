use ark_bn254::{Bn254, Fr};
use ark_ff::UniformRand;
use ark_groth16::{
    generate_random_parameters, prepare_verifying_key, create_random_proof,
    verify_proof, Proof, ProvingKey, VerifyingKey,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::rngs::OsRng;

use crate::Result;

/// Configuration for zero-knowledge operations
#[derive(Debug, Clone)]
pub struct Config {
    /// Maximum constraint size
    pub max_constraints: usize,
    /// Enable recursive proofs
    pub enable_recursive: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_constraints: 1_000_000,
            enable_recursive: false,
        }
    }
}

/// Initialize the ZK module
pub fn init(_config: &Config) -> Result<()> {
    Ok(())
}

/// A trait for circuits that can be proven in zero-knowledge
pub trait Circuit: Clone {
    /// Generate a proof for this circuit
    fn generate_proof(&self, pk: &ProvingKey<Bn254>) -> Result<Proof<Bn254>>;
    
    /// Verify a proof for this circuit
    fn verify_proof(
        &self,
        vk: &VerifyingKey<Bn254>,
        proof: &Proof<Bn254>,
    ) -> Result<bool>;
}

/// A basic example circuit for demonstrating ZK proofs
#[derive(Clone)]
pub struct ExampleCircuit {
    /// The secret value
    pub secret: Fr,
    /// The public hash of the secret
    pub hash: Fr,
}

impl Circuit for ExampleCircuit {
    fn generate_proof(&self, pk: &ProvingKey<Bn254>) -> Result<Proof<Bn254>> {
        let rng = &mut OsRng;
        create_random_proof(self.clone(), pk, rng)
            .map_err(|e| crate::Error::Zk(e.to_string()))
    }

    fn verify_proof(
        &self,
        vk: &VerifyingKey<Bn254>,
        proof: &Proof<Bn254>,
    ) -> Result<bool> {
        let pvk = prepare_verifying_key(vk);
        verify_proof(&pvk, proof, &[self.hash])
            .map_err(|e| crate::Error::Zk(e.to_string()))
    }
}

/// Generate proving and verifying keys for a circuit
pub fn generate_keys<C: Circuit>(
    circuit: &C,
) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>)> {
    let rng = &mut OsRng;
    let params = generate_random_parameters(circuit.clone(), rng)
        .map_err(|e| crate::Error::Zk(e.to_string()))?;
    
    Ok((params, params.vk))
}

/// Serialize a proof to bytes
pub fn serialize_proof(proof: &Proof<Bn254>) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    proof
        .serialize(&mut bytes)
        .map_err(|e| crate::Error::Zk(e.to_string()))?;
    Ok(bytes)
}

/// Deserialize a proof from bytes
pub fn deserialize_proof(bytes: &[u8]) -> Result<Proof<Bn254>> {
    Proof::deserialize(bytes)
        .map_err(|e| crate::Error::Zk(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zk_proof() {
        // Create a simple circuit
        let secret = Fr::rand(&mut OsRng);
        let hash = secret; // In reality, this would be a proper hash
        let circuit = ExampleCircuit { secret, hash };

        // Generate keys
        let (pk, vk) = generate_keys(&circuit).unwrap();

        // Generate and verify proof
        let proof = circuit.generate_proof(&pk).unwrap();
        assert!(circuit.verify_proof(&vk, &proof).unwrap());

        // Test serialization
        let proof_bytes = serialize_proof(&proof).unwrap();
        let deserialized_proof = deserialize_proof(&proof_bytes).unwrap();
        assert!(circuit.verify_proof(&vk, &deserialized_proof).unwrap());
    }
} 