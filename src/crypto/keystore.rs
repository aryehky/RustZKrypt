use std::{
    collections::HashMap,
    fs::{self, File},
    io::{Read, Write},
    path::Path,
    sync::{Arc, RwLock},
    time::{SystemTime, UNIX_EPOCH},
};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
use rusqlite::{Connection, params};
use secrecy::{ExposeSecret, Secret};
use zeroize::Zeroize;
use crate::Result;

use super::{SecureKey, derive_key, Argon2Params};

/// A secure keystore for managing cryptographic keys
pub struct Keystore {
    conn: Connection,
    master_key: Secret<SecureKey>,
}

impl Keystore {
    /// Create a new keystore at the specified path
    pub fn new(path: &Path, master_password: &[u8], salt: &[u8], params: &Argon2Params) -> Result<Self> {
        let conn = Connection::open(path)?;
        
        // Initialize the database schema
        conn.execute(
            "CREATE TABLE IF NOT EXISTS keys (
                id TEXT PRIMARY KEY,
                key_data BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                last_used INTEGER NOT NULL
            )",
            [],
        )?;

        // Derive master key from password
        let master_key = derive_key(master_password, salt, params)?;
        
        Ok(Self {
            conn,
            master_key: Secret::new(master_key),
        })
    }

    /// Store a key in the keystore
    pub fn store_key(&self, id: &str, key: &SecureKey) -> Result<()> {
        let now = chrono::Utc::now().timestamp();
        
        // Encrypt the key with the master key
        let encrypted_key = super::encrypt(key.as_bytes(), self.master_key.expose_secret().as_bytes())?;
        
        self.conn.execute(
            "INSERT OR REPLACE INTO keys (id, key_data, created_at, last_used) 
             VALUES (?1, ?2, ?3, ?3)",
            params![id, encrypted_key, now],
        )?;
        
        Ok(())
    }

    /// Retrieve a key from the keystore
    pub fn get_key(&self, id: &str) -> Result<SecureKey> {
        let encrypted_key: Vec<u8> = self.conn.query_row(
            "SELECT key_data FROM keys WHERE id = ?1",
            params![id],
            |row| row.get(0),
        )?;

        // Update last used timestamp
        self.conn.execute(
            "UPDATE keys SET last_used = ?1 WHERE id = ?2",
            params![chrono::Utc::now().timestamp(), id],
        )?;

        // Decrypt the key
        let key_bytes = super::decrypt(&encrypted_key, self.master_key.expose_secret().as_bytes())?;
        Ok(SecureKey(key_bytes))
    }

    /// Delete a key from the keystore
    pub fn delete_key(&self, id: &str) -> Result<()> {
        self.conn.execute("DELETE FROM keys WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// List all key IDs in the keystore
    pub fn list_keys(&self) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare("SELECT id FROM keys")?;
        let keys = stmt.query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<String>>>()?;
        Ok(keys)
    }
}

impl Drop for Keystore {
    fn drop(&mut self) {
        // Ensure master key is zeroized
        self.master_key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_keystore_operations() {
        let temp_file = NamedTempFile::new().unwrap();
        let params = Argon2Params::default();
        
        let keystore = Keystore::new(
            temp_file.path(),
            b"test_password",
            b"test_salt",
            &params,
        ).unwrap();

        // Store a key
        let key = SecureKey::new(32);
        keystore.store_key("test_key", &key).unwrap();

        // Retrieve the key
        let retrieved_key = keystore.get_key("test_key").unwrap();
        assert_eq!(key.as_bytes(), retrieved_key.as_bytes());

        // List keys
        let keys = keystore.list_keys().unwrap();
        assert_eq!(keys, vec!["test_key"]);

        // Delete the key
        keystore.delete_key("test_key").unwrap();
        assert!(keystore.get_key("test_key").is_err());
    }
} 