#![no_main]
use libfuzzer_sys::fuzz_target;
use rustzkrypt::crypto::{SecureKey, KeyStore, KeyMetadata};

fuzz_target!(|data: &[u8]| {
    // Fuzz key generation with random lengths
    if !data.is_empty() {
        let key_len = data[0] as usize % 64; // Max 64 bytes
        if key_len > 0 {
            let key = SecureKey::new(key_len);
            let _ = key.as_bytes();
        }
    }
    
    // Fuzz keystore operations
    if data.len() > 32 {
        let store = KeyStore::new(&data[..32]);
        let key = SecureKey::new(32);
        
        // Create metadata from fuzzer data
        let metadata = KeyMetadata {
            id: String::from_utf8_lossy(&data[32..]).to_string(),
            key_type: "fuzz".into(),
            created_at: 0,
            description: None,
        };
        
        // Try storing and retrieving the key
        if let Ok(()) = store.store_key(&metadata.id, &key, metadata.clone()) {
            let _ = store.get_key(&metadata.id);
        }
    }
}); 