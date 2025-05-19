use std::collections::HashMap;
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer, Verifier};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use thiserror::Error;

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
} 