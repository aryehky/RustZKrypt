use serde::{Deserialize, Serialize};
use std::{fs, path::Path};
use tracing::Level;

/// Global configuration for RustZkrypt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Cryptographic settings
    pub crypto: CryptoConfig,
    /// Zero-knowledge proof settings
    pub zk: ZkConfig,
    /// Networking settings
    pub network: NetworkConfig,
    /// Logging configuration
    pub logging: LoggingConfig,
}

/// Cryptographic configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoConfig {
    /// Default key length for new keys
    pub default_key_length: usize,
    /// Key rotation interval in seconds
    pub key_rotation_interval: u64,
    /// Path to keystore file
    pub keystore_path: String,
    /// Enable secure memory wiping
    pub enable_memory_protection: bool,
}

/// Zero-knowledge proof configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkConfig {
    /// Maximum circuit size
    pub max_constraints: usize,
    /// Proof generation timeout in seconds
    pub proof_timeout: u64,
    /// Enable parallel proof generation
    pub parallel_proof_gen: bool,
}

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Listen address for P2P node
    pub listen_addr: String,
    /// Bootstrap peers
    pub bootstrap_peers: Vec<String>,
    /// Message retry attempts
    pub max_retry_attempts: u32,
    /// Retry delay in milliseconds
    pub retry_delay_ms: u64,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level
    pub level: String,
    /// Log file path
    pub file_path: Option<String>,
    /// Enable JSON formatting
    pub json_format: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            crypto: CryptoConfig {
                default_key_length: 32,
                key_rotation_interval: 86400, // 24 hours
                keystore_path: "keystore.json".into(),
                enable_memory_protection: true,
            },
            zk: ZkConfig {
                max_constraints: 1_000_000,
                proof_timeout: 300,
                parallel_proof_gen: true,
            },
            network: NetworkConfig {
                listen_addr: "/ip4/0.0.0.0/tcp/0".into(),
                bootstrap_peers: vec![],
                max_retry_attempts: 3,
                retry_delay_ms: 1000,
            },
            logging: LoggingConfig {
                level: "info".into(),
                file_path: None,
                json_format: false,
            },
        }
    }
}

impl Config {
    /// Load configuration from file
    pub fn load<P: AsRef<Path>>(path: P) -> crate::Result<Self> {
        let contents = fs::read_to_string(path)
            .map_err(|e| crate::Error::Config(format!("Failed to read config: {}", e)))?;
            
        serde_json::from_str(&contents)
            .map_err(|e| crate::Error::Config(format!("Failed to parse config: {}", e)))
    }
    
    /// Save configuration to file
    pub fn save<P: AsRef<Path>>(&self, path: P) -> crate::Result<()> {
        let contents = serde_json::to_string_pretty(self)
            .map_err(|e| crate::Error::Config(format!("Failed to serialize config: {}", e)))?;
            
        fs::write(path, contents)
            .map_err(|e| crate::Error::Config(format!("Failed to write config: {}", e)))
    }
    
    /// Get log level from config
    pub fn log_level(&self) -> Level {
        match self.logging.level.to_lowercase().as_str() {
            "trace" => Level::TRACE,
            "debug" => Level::DEBUG,
            "info" => Level::INFO,
            "warn" => Level::WARN,
            "error" => Level::ERROR,
            _ => Level::INFO,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_config_serialization() {
        let config = Config::default();
        let temp_file = NamedTempFile::new().unwrap();
        
        // Test saving
        config.save(temp_file.path()).unwrap();
        
        // Test loading
        let loaded = Config::load(temp_file.path()).unwrap();
        
        assert_eq!(
            serde_json::to_string(&config).unwrap(),
            serde_json::to_string(&loaded).unwrap()
        );
    }
    
    #[test]
    fn test_log_level() {
        let mut config = Config::default();
        
        config.logging.level = "debug".into();
        assert_eq!(config.log_level(), Level::DEBUG);
        
        config.logging.level = "ERROR".into();
        assert_eq!(config.log_level(), Level::ERROR);
        
        config.logging.level = "invalid".into();
        assert_eq!(config.log_level(), Level::INFO);
    }
} 