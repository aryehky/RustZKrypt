use std::collections::HashMap;
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer, Verifier};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use sha2::{Sha256, Digest};

/// Error types for threshold signatures
#[derive(Debug, Error)]
pub enum ThresholdError {
    #[error("Invalid threshold: {0}")]
    InvalidThreshold(String),
    #[error("Invalid share index: {0}")]
    InvalidShareIndex(String),
    #[error("Insufficient shares: {0}")]
    InsufficientShares(String),
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
    #[error("DKG error: {0}")]
    DKGError(String),
    #[error("Invalid commitment: {0}")]
    InvalidCommitment(String),
}

/// Commitment to a polynomial coefficient
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commitment {
    /// The commitment value
    pub value: Vec<u8>,
    /// The index of the coefficient
    pub index: u32,
}

/// DKG round message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DKGRoundMessage {
    /// The sender's index
    pub sender: u32,
    /// The round number
    pub round: u32,
    /// The commitments to polynomial coefficients
    pub commitments: Vec<Commitment>,
    /// The share values for other participants
    pub shares: HashMap<u32, Vec<u8>>,
}

/// A share of a threshold signature key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyShare {
    /// Share index
    pub index: u32,
    /// The actual share value
    pub value: Vec<u8>,
    /// Public key for verification
    pub public_key: PublicKey,
    /// Commitments for verification
    pub commitments: Vec<Commitment>,
}

/// Threshold signature scheme
#[derive(Debug)]
pub struct ThresholdScheme {
    /// Total number of shares
    total_shares: u32,
    /// Required number of shares for signing
    threshold: u32,
    /// Public key for verification
    public_key: PublicKey,
    /// Commitments for verification
    commitments: Vec<Commitment>,
}

impl ThresholdScheme {
    /// Create a new threshold scheme
    pub fn new<R: Rng + CryptoRng>(
        rng: &mut R,
        total_shares: u32,
        threshold: u32,
    ) -> Result<Self, ThresholdError> {
        if threshold > total_shares {
            return Err(ThresholdError::InvalidThreshold(
                "Threshold cannot be greater than total shares".into(),
            ));
        }

        // Generate master keypair
        let keypair = Keypair::generate(rng);
        let public_key = keypair.public;

        Ok(Self {
            total_shares,
            threshold,
            public_key,
            commitments: vec![],
        })
    }

    /// Generate shares for the threshold scheme
    pub fn generate_shares<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<Vec<KeyShare>, ThresholdError> {
        let mut shares = Vec::with_capacity(self.total_shares as usize);
        
        // Generate random coefficients for the polynomial
        let mut coefficients = vec![];
        for _ in 0..self.threshold {
            coefficients.push(SecretKey::generate(rng));
        }
        
        // Generate shares by evaluating the polynomial
        for i in 1..=self.total_shares {
            let mut share = SecretKey::generate(rng);
            for (j, coef) in coefficients.iter().enumerate() {
                let power = (i as u64).pow(j as u32);
                share = share + coef * power;
            }
            
            shares.push(KeyShare {
                index: i,
                value: share.to_bytes().to_vec(),
                public_key: self.public_key,
                commitments: vec![],
            });
        }
        
        Ok(shares)
    }

    /// Sign a message using a set of shares
    pub fn sign(
        &self,
        message: &[u8],
        shares: &[KeyShare],
    ) -> Result<Signature, ThresholdError> {
        if shares.len() < self.threshold as usize {
            return Err(ThresholdError::InsufficientShares(
                format!("Need {} shares, got {}", self.threshold, shares.len()),
            ));
        }

        // Verify all shares are valid
        for share in shares {
            if share.index > self.total_shares {
                return Err(ThresholdError::InvalidShareIndex(
                    format!("Share index {} exceeds total shares {}", share.index, self.total_shares),
                ));
            }
        }

        // Combine shares to create signature
        let mut combined_sig = Signature::default();
        for share in shares {
            let secret = SecretKey::from_bytes(&share.value)
                .map_err(|e| ThresholdError::InvalidSignature(e.to_string()))?;
            let keypair = Keypair {
                secret,
                public: share.public_key,
            };
            let sig = keypair.sign(message);
            combined_sig = combined_sig + sig;
        }

        Ok(combined_sig)
    }

    /// Verify a threshold signature
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        self.public_key.verify(message, signature).is_ok()
    }

    /// Generate a commitment to a secret value
    fn generate_commitment(secret: &SecretKey) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(secret.to_bytes());
        hasher.finalize().to_vec()
    }

    /// Verify a commitment
    fn verify_commitment(secret: &SecretKey, commitment: &[u8]) -> bool {
        let computed = Self::generate_commitment(secret);
        computed == commitment
    }

    /// Run a DKG round
    pub fn run_dkg_round<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        round: u32,
        messages: &[DKGRoundMessage],
    ) -> Result<DKGRoundMessage, ThresholdError> {
        if messages.len() < self.threshold as usize {
            return Err(ThresholdError::InsufficientShares(
                format!("Need {} messages, got {}", self.threshold, messages.len()),
            ));
        }

        // Generate polynomial coefficients
        let mut coefficients = vec![];
        let mut commitments = vec![];
        
        for i in 0..self.threshold {
            let coef = SecretKey::generate(rng);
            coefficients.push(coef.clone());
            commitments.push(Commitment {
                value: Self::generate_commitment(&coef),
                index: i,
            });
        }

        // Generate shares for other participants
        let mut shares = HashMap::new();
        for i in 1..=self.total_shares {
            let mut share = SecretKey::generate(rng);
            for (j, coef) in coefficients.iter().enumerate() {
                let power = (i as u64).pow(j as u32);
                share = share + coef * power;
            }
            shares.insert(i, share.to_bytes().to_vec());
        }

        Ok(DKGRoundMessage {
            sender: round,
            round,
            commitments,
            shares,
        })
    }

    /// Verify DKG round messages
    pub fn verify_dkg_round(
        &self,
        messages: &[DKGRoundMessage],
    ) -> Result<Vec<KeyShare>, ThresholdError> {
        if messages.len() < self.threshold as usize {
            return Err(ThresholdError::InsufficientShares(
                format!("Need {} messages, got {}", self.threshold, messages.len()),
            ));
        }

        // Verify all commitments
        for msg in messages {
            for commitment in &msg.commitments {
                if commitment.index >= self.threshold {
                    return Err(ThresholdError::InvalidCommitment(
                        format!("Invalid commitment index: {}", commitment.index),
                    ));
                }
            }
        }

        // Combine shares
        let mut final_shares = Vec::new();
        for i in 1..=self.total_shares {
            let mut combined_share = SecretKey::generate(&mut rand::thread_rng());
            for msg in messages {
                if let Some(share_bytes) = msg.shares.get(&i) {
                    let share = SecretKey::from_bytes(share_bytes)
                        .map_err(|e| ThresholdError::InvalidSignature(e.to_string()))?;
                    combined_share = combined_share + share;
                }
            }

            final_shares.push(KeyShare {
                index: i,
                value: combined_share.to_bytes().to_vec(),
                public_key: self.public_key,
                commitments: messages[0].commitments.clone(),
            });
        }

        Ok(final_shares)
    }

    /// Refresh shares using proactive secret sharing
    pub fn refresh_shares<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        shares: &[KeyShare],
    ) -> Result<Vec<KeyShare>, ThresholdError> {
        if shares.len() < self.threshold as usize {
            return Err(ThresholdError::InsufficientShares(
                format!("Need {} shares, got {}", self.threshold, shares.len()),
            ));
        }

        // Generate new random polynomials
        let mut new_shares = Vec::new();
        for i in 1..=self.total_shares {
            let mut new_share = SecretKey::generate(rng);
            for share in shares {
                let secret = SecretKey::from_bytes(&share.value)
                    .map_err(|e| ThresholdError::InvalidSignature(e.to_string()))?;
                new_share = new_share + secret;
            }
            new_shares.push(KeyShare {
                index: i,
                value: new_share.to_bytes().to_vec(),
                public_key: self.public_key,
                commitments: shares[0].commitments.clone(),
            });
        }

        Ok(new_shares)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_threshold_scheme() {
        let mut rng = thread_rng();
        let total_shares = 5;
        let threshold = 3;
        
        // Create threshold scheme
        let scheme = ThresholdScheme::new(&mut rng, total_shares, threshold).unwrap();
        
        // Generate shares
        let shares = scheme.generate_shares(&mut rng).unwrap();
        assert_eq!(shares.len(), total_shares as usize);
        
        // Test signing with threshold shares
        let message = b"test message";
        let signature = scheme.sign(message, &shares[..threshold as usize]).unwrap();
        
        // Verify signature
        assert!(scheme.verify(message, &signature));
        
        // Test with insufficient shares
        assert!(scheme.sign(message, &shares[..(threshold - 1) as usize]).is_err());
    }

    #[test]
    fn test_invalid_threshold() {
        let mut rng = thread_rng();
        assert!(ThresholdScheme::new(&mut rng, 3, 5).is_err());
    }

    #[test]
    fn test_dkg_round() {
        let mut rng = thread_rng();
        let total_shares = 5;
        let threshold = 3;
        
        let scheme = ThresholdScheme::new(&mut rng, total_shares, threshold).unwrap();
        
        // Run DKG round
        let messages: Vec<DKGRoundMessage> = (0..threshold)
            .map(|i| scheme.run_dkg_round(&mut rng, i, &[]).unwrap())
            .collect();
        
        // Verify DKG round
        let shares = scheme.verify_dkg_round(&messages).unwrap();
        assert_eq!(shares.len(), total_shares as usize);
        
        // Test signing with new shares
        let message = b"test message";
        let signature = scheme.sign(message, &shares[..threshold as usize]).unwrap();
        assert!(scheme.verify(message, &signature));
    }

    #[test]
    fn test_share_refresh() {
        let mut rng = thread_rng();
        let total_shares = 5;
        let threshold = 3;
        
        let scheme = ThresholdScheme::new(&mut rng, total_shares, threshold).unwrap();
        let shares = scheme.generate_shares(&mut rng).unwrap();
        
        // Refresh shares
        let new_shares = scheme.refresh_shares(&mut rng, &shares[..threshold as usize]).unwrap();
        
        // Test signing with refreshed shares
        let message = b"test message";
        let signature = scheme.sign(message, &new_shares[..threshold as usize]).unwrap();
        assert!(scheme.verify(message, &signature));
    }
} 