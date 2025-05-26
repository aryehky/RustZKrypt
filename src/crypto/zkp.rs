use std::collections::HashMap;
use ed25519_dalek::{PublicKey, Signature};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use thiserror::Error;

/// Error types for zero-knowledge proofs
#[derive(Debug, Error)]
pub enum ZKPError {
    #[error("Invalid proof: {0}")]
    InvalidProof(String),
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    #[error("Invalid commitment: {0}")]
    InvalidCommitment(String),
}

/// Commitment to a value in a zero-knowledge proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commitment {
    /// The commitment value
    pub value: Vec<u8>,
    /// The commitment type
    pub commitment_type: String,
}

/// Challenge for a zero-knowledge proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    /// The challenge value
    pub value: Vec<u8>,
    /// The challenge type
    pub challenge_type: String,
}

/// Response to a challenge in a zero-knowledge proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    /// The response value
    pub value: Vec<u8>,
    /// The response type
    pub response_type: String,
}

/// Zero-knowledge proof of knowledge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZKProof {
    /// The commitments
    pub commitments: Vec<Commitment>,
    /// The challenge
    pub challenge: Challenge,
    /// The responses
    pub responses: Vec<Response>,
    /// The public inputs
    pub public_inputs: HashMap<String, Vec<u8>>,
}

/// Zero-knowledge proof system
#[derive(Debug)]
pub struct ZKP {
    /// The public key
    public_key: PublicKey,
}

impl ZKP {
    /// Create a new zero-knowledge proof system
    pub fn new(public_key: PublicKey) -> Self {
        Self { public_key }
    }

    /// Generate a commitment to a value
    fn generate_commitment<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        value: &[u8],
        commitment_type: &str,
    ) -> Commitment {
        let mut hasher = Sha256::new();
        hasher.update(value);
        hasher.update(commitment_type.as_bytes());
        let mut random_bytes = vec![0u8; 32];
        rng.fill_bytes(&mut random_bytes);
        hasher.update(&random_bytes);
        
        Commitment {
            value: hasher.finalize().to_vec(),
            commitment_type: commitment_type.to_string(),
        }
    }

    /// Generate a challenge
    fn generate_challenge<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        commitments: &[Commitment],
    ) -> Challenge {
        let mut hasher = Sha256::new();
        for commitment in commitments {
            hasher.update(&commitment.value);
        }
        let mut random_bytes = vec![0u8; 32];
        rng.fill_bytes(&mut random_bytes);
        hasher.update(&random_bytes);
        
        Challenge {
            value: hasher.finalize().to_vec(),
            challenge_type: "signature_knowledge".to_string(),
        }
    }

    /// Generate a response to a challenge
    fn generate_response(
        &self,
        challenge: &Challenge,
        secret: &[u8],
        response_type: &str,
    ) -> Response {
        let mut hasher = Sha256::new();
        hasher.update(secret);
        hasher.update(&challenge.value);
        hasher.update(response_type.as_bytes());
        
        Response {
            value: hasher.finalize().to_vec(),
            response_type: response_type.to_string(),
        }
    }

    /// Prove knowledge of a signature
    pub fn prove_signature_knowledge<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        signature: &Signature,
        message: &[u8],
    ) -> Result<ZKProof, ZKPError> {
        // Generate commitments
        let mut commitments = Vec::new();
        commitments.push(self.generate_commitment(rng, &signature.to_bytes(), "signature"));
        commitments.push(self.generate_commitment(rng, message, "message"));

        // Generate challenge
        let challenge = self.generate_challenge(rng, &commitments);

        // Generate responses
        let mut responses = Vec::new();
        responses.push(self.generate_response(&challenge, &signature.to_bytes(), "signature"));
        responses.push(self.generate_response(&challenge, message, "message"));

        // Create public inputs
        let mut public_inputs = HashMap::new();
        public_inputs.insert("public_key".to_string(), self.public_key.to_bytes().to_vec());

        Ok(ZKProof {
            commitments,
            challenge,
            responses,
            public_inputs,
        })
    }

    /// Verify a zero-knowledge proof
    pub fn verify_proof(&self, proof: &ZKProof) -> Result<bool, ZKPError> {
        // Verify commitments
        for (i, commitment) in proof.commitments.iter().enumerate() {
            let response = &proof.responses[i];
            let mut hasher = Sha256::new();
            hasher.update(&response.value);
            hasher.update(&proof.challenge.value);
            hasher.update(response.response_type.as_bytes());
            
            if hasher.finalize().to_vec() != commitment.value {
                return Err(ZKPError::InvalidProof(
                    format!("Invalid commitment for response {}", i),
                ));
            }
        }

        // Verify challenge
        let mut hasher = Sha256::new();
        for commitment in &proof.commitments {
            hasher.update(&commitment.value);
        }
        if hasher.finalize().to_vec() != proof.challenge.value {
            return Err(ZKPError::InvalidProof("Invalid challenge".into()));
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Keypair;
    use rand::thread_rng;

    #[test]
    fn test_signature_knowledge_proof() {
        let mut rng = thread_rng();
        let keypair = Keypair::generate(&mut rng);
        let message = b"test message";
        let signature = keypair.sign(message);

        let zkp = ZKP::new(keypair.public);
        
        // Generate proof
        let proof = zkp.prove_signature_knowledge(&mut rng, &signature, message).unwrap();
        
        // Verify proof
        assert!(zkp.verify_proof(&proof).unwrap());
    }

    #[test]
    fn test_invalid_proof() {
        let mut rng = thread_rng();
        let keypair = Keypair::generate(&mut rng);
        let message = b"test message";
        let signature = keypair.sign(message);

        let zkp = ZKP::new(keypair.public);
        
        // Generate proof
        let mut proof = zkp.prove_signature_knowledge(&mut rng, &signature, message).unwrap();
        
        // Modify proof to make it invalid
        proof.challenge.value[0] ^= 1;
        
        // Verify proof should fail
        assert!(zkp.verify_proof(&proof).is_err());
    }
} 