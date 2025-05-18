use std::{
    collections::HashMap,
    fs::{self, File},
    io::{Read, Write},
    path::Path,
    sync::{Arc, RwLock},
};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::SecureKey;
use crate::Result;

/// A secure keystore for managing cryptographic keys
#[derive(Default)]
pub struct KeyStore {
    keys: Arc<RwLock<HashMap<String, EncryptedKey>>>,
    master_key: Option<Zeroizing<Vec<u8>>>,
}

/// An encrypted key entry in the keystore
#[derive(Serialize, Deserialize)]
struct EncryptedKey {
    /// Encrypted key data
    data: Vec<u8>,
    /// Key metadata
    metadata: KeyMetadata,
}

/// Metadata about a stored key
#[derive(Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Key identifier
    pub id: String,
    /// Key type (e.g., "aes", "ed25519")
    pub key_type: String,
    /// Creation timestamp
    pub created_at: u64,
    /// Optional description
    pub description: Option<String>,
}

impl KeyStore {
    /// Create a new keystore with the given master key
    pub fn new(master_key: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(master_key);
        let master_key = hasher.finalize().to_vec();
        
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
            master_key: Some(Zeroizing::new(master_key)),
        }
    }

    /// Store a key in the keystore
    pub fn store_key(&self, id: &str, key: &SecureKey, metadata: KeyMetadata) -> Result<()> {
        let master_key = self.master_key.as_ref()
            .ok_or_else(|| crate::Error::Crypto("Master key not set".into()))?;
            
        let key_bytes = key.as_bytes();
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(master_key));
        let nonce = Aes256Gcm::generate_nonce(&mut rand::thread_rng());
        
        let mut encrypted = cipher
            .encrypt(&nonce, key_bytes)
            .map_err(|e| crate::Error::Crypto(e.to_string()))?;
            
        // Prepend nonce
        let mut data = nonce.to_vec();
        data.append(&mut encrypted);
        
        let encrypted_key = EncryptedKey { data, metadata };
        self.keys.write().unwrap().insert(id.to_string(), encrypted_key);
        
        Ok(())
    }

    /// Retrieve a key from the keystore
    pub fn get_key(&self, id: &str) -> Result<(SecureKey, KeyMetadata)> {
        let master_key = self.master_key.as_ref()
            .ok_or_else(|| crate::Error::Crypto("Master key not set".into()))?;
            
        let keys = self.keys.read().unwrap();
        let encrypted_key = keys.get(id)
            .ok_or_else(|| crate::Error::Crypto("Key not found".into()))?;
            
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(master_key));
        let (nonce, ciphertext) = encrypted_key.data.split_at(12);
        
        let key_bytes = cipher
            .decrypt(nonce.into(), ciphertext)
            .map_err(|e| crate::Error::Crypto(e.to_string()))?;
            
        Ok((
            SecureKey::from_bytes(&key_bytes),
            encrypted_key.metadata.clone(),
        ))
    }

    /// Save the keystore to a file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let keys = self.keys.read().unwrap();
        let json = serde_json::to_string(&*keys)
            .map_err(|e| crate::Error::Crypto(e.to_string()))?;
            
        let mut file = File::create(path)
            .map_err(|e| crate::Error::Io(e))?;
        file.write_all(json.as_bytes())
            .map_err(|e| crate::Error::Io(e))?;
            
        Ok(())
    }

    /// Load the keystore from a file
    pub fn load_from_file<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let mut file = File::open(path)
            .map_err(|e| crate::Error::Io(e))?;
            
        let mut json = String::new();
        file.read_to_string(&mut json)
            .map_err(|e| crate::Error::Io(e))?;
            
        let keys: HashMap<String, EncryptedKey> = serde_json::from_str(&json)
            .map_err(|e| crate::Error::Crypto(e.to_string()))?;
            
        *self.keys.write().unwrap() = keys;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_keystore() {
        let master_key = b"master password";
        let store = KeyStore::new(master_key);
        
        let key = SecureKey::new(32);
        let metadata = KeyMetadata {
            id: "test-key".into(),
            key_type: "aes".into(),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            description: Some("Test key".into()),
        };
        
        // Store and retrieve key
        store.store_key("test-key", &key, metadata.clone()).unwrap();
        let (retrieved_key, retrieved_metadata) = store.get_key("test-key").unwrap();
        
        assert_eq!(key.as_bytes(), retrieved_key.as_bytes());
        assert_eq!(metadata.id, retrieved_metadata.id);
        
        // Test file persistence
        let temp_path = "test_keystore.json";
        store.save_to_file(temp_path).unwrap();
        
        let mut new_store = KeyStore::new(master_key);
        new_store.load_from_file(temp_path).unwrap();
        
        let (retrieved_key2, _) = new_store.get_key("test-key").unwrap();
        assert_eq!(key.as_bytes(), retrieved_key2.as_bytes());
        
        fs::remove_file(temp_path).unwrap();
    }
} 