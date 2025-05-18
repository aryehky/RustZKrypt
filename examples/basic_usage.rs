use rustzkrypt::{
    crypto::{self, SecureKey},
    zk::{self, ExampleCircuit},
    Config,
};

#[tokio::main]
async fn main() -> rustzkrypt::Result<()> {
    // Initialize RustZkrypt
    let config = Config::default();
    rustzkrypt::init(config)?;

    println!("🛡️ RustZkrypt Example\n");

    // Encryption example
    println!("📝 Encryption Example:");
    let message = b"Hello, RustZkrypt!";
    let key = SecureKey::new(32);
    
    let encrypted = crypto::encrypt(message, key.as_bytes())?;
    println!("Original: {}", String::from_utf8_lossy(message));
    println!("Encrypted (base64): {}\n", base64::encode(&encrypted));

    let decrypted = crypto::decrypt(&encrypted, key.as_bytes())?;
    println!("Decrypted: {}\n", String::from_utf8_lossy(&decrypted));

    // Zero-knowledge proof example
    println!("🔐 Zero-Knowledge Proof Example:");
    use ark_bn254::Fr;
    use ark_ff::UniformRand;
    use rand::rngs::OsRng;

    // Create a simple circuit
    let secret = Fr::rand(&mut OsRng);
    let hash = secret; // In reality, this would be a proper hash
    let circuit = ExampleCircuit { secret, hash };

    // Generate keys and proof
    println!("Generating keys...");
    let (pk, vk) = zk::generate_keys(&circuit)?;

    println!("Generating proof...");
    let proof = circuit.generate_proof(&pk)?;
    
    println!("Verifying proof...");
    let valid = circuit.verify_proof(&vk, &proof)?;
    
    println!("Proof verified: {}\n", valid);

    // Serialize proof for transmission
    let proof_bytes = zk::serialize_proof(&proof)?;
    println!("Proof (base64): {}", base64::encode(&proof_bytes));

    Ok(())
} 