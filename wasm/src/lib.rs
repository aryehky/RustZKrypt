use wasm_bindgen::prelude::*;
use rustzkrypt::{
    crypto::{self, SecureKey},
    zk::{self, ExampleCircuit},
    Config,
};

#[wasm_bindgen]
pub struct RustZkrypt {
    config: Config,
}

#[wasm_bindgen]
impl RustZkrypt {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<RustZkrypt, JsValue> {
        // Initialize panic hook for better error messages
        console_error_panic_hook::set_once();
        
        let config = Config::default();
        rustzkrypt::init(config.clone())
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
            
        Ok(RustZkrypt { config })
    }

    /// Encrypt a message using AES-256-GCM
    #[wasm_bindgen]
    pub fn encrypt(&self, message: &[u8]) -> Result<Vec<u8>, JsValue> {
        let key = SecureKey::new(32);
        crypto::encrypt(message, key.as_bytes())
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Decrypt a message using AES-256-GCM
    #[wasm_bindgen]
    pub fn decrypt(&self, encrypted: &[u8], key: &[u8]) -> Result<Vec<u8>, JsValue> {
        crypto::decrypt(encrypted, key)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Generate a zero-knowledge proof
    #[wasm_bindgen]
    pub fn generate_proof(&self, secret: &[u8]) -> Result<String, JsValue> {
        use ark_bn254::Fr;
        use ark_ff::UniformRand;
        use rand::rngs::OsRng;

        // Create circuit (simplified for demo)
        let secret_fr = Fr::rand(&mut OsRng);
        let hash = secret_fr;
        let circuit = ExampleCircuit { secret: secret_fr, hash };

        // Generate and serialize proof
        let (pk, _) = zk::generate_keys(&circuit)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        
        let proof = circuit.generate_proof(&pk)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
            
        let proof_bytes = zk::serialize_proof(&proof)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
            
        Ok(base64::encode(&proof_bytes))
    }
}

#[wasm_bindgen(start)]
pub fn main() {
    // Initialize logging for better debugging
    console_log::init_with_level(log::Level::Debug)
        .expect("Failed to initialize logging");
} 