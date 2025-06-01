use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use ed25519_dalek::{Keypair, SecretKey, Signer, Verifier};
use rand::rngs::OsRng;
use zeroize::Zeroize;
use argon2::{Argon2, PasswordHasher};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit as ChaChaKeyInit};
use secrecy::{ExposeSecret, Secret};

use crate::Result;

/// Configuration for cryptographic operations
#[derive(Debug, Clone)]
pub struct Config {
    /// Key size in bytes for symmetric encryption
    pub symmetric_key_size: usize,
    /// Enable post-quantum crypto
    pub enable_pq: bool,
    /// Argon2 parameters for key derivation
    pub argon2_params: Argon2Params,
}

#[derive(Debug, Clone)]
pub struct Argon2Params {
    pub memory_cost: u32,
    pub time_cost: u32,
    pub parallelism: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            memory_cost: 65536, // 64 MiB
            time_cost: 3,
            parallelism: 4,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            symmetric_key_size: 32,
            enable_pq: false,
            argon2_params: Argon2Params::default(),
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

/// Derive a key from a password using Argon2
pub fn derive_key(password: &[u8], salt: &[u8], params: &Argon2Params) -> Result<SecureKey> {
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(
            params.memory_cost,
            params.time_cost,
            params.parallelism,
            Some(32), // Output length
        )?,
    );

    let mut output_key_material = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut output_key_material)
        .map_err(|e| crate::Error::Crypto(e.to_string()))?;

    Ok(SecureKey(output_key_material.to_vec()))
}

/// Encrypt data using ChaCha20-Poly1305
pub fn encrypt_chacha(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let key = chacha20poly1305::Key::from_slice(key);
    let cipher = ChaCha20Poly1305::new(key);
    
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, data)
        .map_err(|e| crate::Error::Crypto(e.to_string()))?;

    // Prepend nonce to ciphertext
    let mut output = nonce.to_vec();
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypt data using ChaCha20-Poly1305
pub fn decrypt_chacha(encrypted_data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if encrypted_data.len() < 12 {
        return Err(crate::Error::Crypto("Invalid ciphertext".into()));
    }

    let key = chacha20poly1305::Key::from_slice(key);
    let cipher = ChaCha20Poly1305::new(key);

    let nonce = chacha20poly1305::Nonce::from_slice(&encrypted_data[..12]);
    let ciphertext = &encrypted_data[12..];

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| crate::Error::Crypto(e.to_string()))
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

    #[test]
    fn test_key_derivation() {
        let password = b"test_password";
        let salt = b"test_salt";
        let params = Argon2Params::default();
        
        let key1 = derive_key(password, salt, &params).unwrap();
        let key2 = derive_key(password, salt, &params).unwrap();
        
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_chacha_encryption_roundtrip() {
        let key = SecureKey::new(32);
        let data = b"hello world";
        
        let encrypted = encrypt_chacha(data, key.as_bytes()).unwrap();
        let decrypted = decrypt_chacha(&encrypted, key.as_bytes()).unwrap();
        
        assert_eq!(data, &decrypted[..]);
    }
} 