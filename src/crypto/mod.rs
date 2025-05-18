use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use ed25519_dalek::{Keypair, SecretKey, Signer, Verifier};
use rand::rngs::OsRng;
use zeroize::Zeroize;

use crate::Result;

/// Configuration for cryptographic operations
#[derive(Debug, Clone)]
pub struct Config {
    /// Key size in bytes for symmetric encryption
    pub symmetric_key_size: usize,
    /// Enable post-quantum crypto
    pub enable_pq: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            symmetric_key_size: 32,
            enable_pq: false,
        }
    }
}

/// Initialize the crypto module
pub fn init(_config: &Config) -> Result<()> {
    Ok(())
}

/// A secure key that automatically wipes itself from memory when dropped
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SecureKey(Vec<u8>);

impl SecureKey {
    /// Generate a new random key
    pub fn new(size: usize) -> Self {
        let mut key = vec![0u8; size];
        OsRng.fill_bytes(&mut key);
        Self(key)
    }

    /// Get reference to key bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Encrypt data using AES-256-GCM
pub fn encrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, data)
        .map_err(|e| crate::Error::Crypto(e.to_string()))?;

    // Prepend nonce to ciphertext
    let mut output = nonce.to_vec();
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypt data using AES-256-GCM
pub fn decrypt(encrypted_data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if encrypted_data.len() < 12 {
        return Err(crate::Error::Crypto("Invalid ciphertext".into()));
    }

    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);

    let nonce = Nonce::from_slice(&encrypted_data[..12]);
    let ciphertext = &encrypted_data[12..];

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| crate::Error::Crypto(e.to_string()))
}

/// Generate an Ed25519 keypair
pub fn generate_keypair() -> Keypair {
    let mut csprng = OsRng;
    Keypair::generate(&mut csprng)
}

/// Sign data using Ed25519
pub fn sign(data: &[u8], secret_key: &SecretKey) -> Vec<u8> {
    let keypair = Keypair {
        secret: secret_key.clone(),
        public: (&secret_key).into(),
    };
    keypair.sign(data).to_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_roundtrip() {
        let key = SecureKey::new(32);
        let data = b"hello world";
        
        let encrypted = encrypt(data, key.as_bytes()).unwrap();
        let decrypted = decrypt(&encrypted, key.as_bytes()).unwrap();
        
        assert_eq!(data, &decrypted[..]);
    }

    #[test]
    fn test_signing() {
        let keypair = generate_keypair();
        let message = b"test message";
        
        let signature = sign(message, &keypair.secret);
        assert!(keypair.public.verify(message, &signature.as_slice().try_into().unwrap()).is_ok());
    }
} 