use clap::{Parser, Subcommand};
use rustzkrypt::{
    crypto::{self, SecureKey},
    zk::{self, ExampleCircuit},
    Config,
};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt a message
    Encrypt {
        /// Message to encrypt
        #[arg(short, long)]
        message: String,
    },
    /// Decrypt a message
    Decrypt {
        /// Base64 encoded encrypted message
        #[arg(short, long)]
        ciphertext: String,
    },
    /// Generate a zero-knowledge proof
    Prove {
        /// Secret value to prove knowledge of
        #[arg(short, long)]
        secret: String,
    },
}

#[tokio::main]
async fn main() -> rustzkrypt::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Parse command line arguments
    let cli = Cli::parse();

    // Initialize RustZkrypt
    let config = Config::default();
    rustzkrypt::init(config)?;

    // Handle commands
    match cli.command {
        Commands::Encrypt { message } => {
            let key = SecureKey::new(32);
            let encrypted = crypto::encrypt(message.as_bytes(), key.as_bytes())?;
            println!("Encrypted (base64): {}", base64::encode(&encrypted));
        }
        Commands::Decrypt { ciphertext } => {
            let key = SecureKey::new(32); // In reality, this would be loaded from secure storage
            let encrypted = base64::decode(&ciphertext)
                .map_err(|e| rustzkrypt::Error::Crypto(e.to_string()))?;
            let decrypted = crypto::decrypt(&encrypted, key.as_bytes())?;
            println!(
                "Decrypted: {}",
                String::from_utf8_lossy(&decrypted)
            );
        }
        Commands::Prove { secret } => {
            use ark_bn254::Fr;
            use ark_ff::UniformRand;
            use rand::rngs::OsRng;

            // Create a simple circuit
            let secret_fr = Fr::rand(&mut OsRng); // In reality, would convert from input
            let hash = secret_fr; // In reality, would be proper hash
            let circuit = ExampleCircuit {
                secret: secret_fr,
                hash,
            };

            // Generate keys and proof
            let (pk, vk) = zk::generate_keys(&circuit)?;
            let proof = circuit.generate_proof(&pk)?;
            
            // Verify the proof
            let valid = circuit.verify_proof(&vk, &proof)?;
            
            println!("Proof generated and verified: {}", valid);
            println!("Proof (base64): {}", base64::encode(&zk::serialize_proof(&proof)?));
        }
    }

    Ok(())
} 