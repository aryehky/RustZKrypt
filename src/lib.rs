//! RustZkrypt: A blazing-fast, privacy-first cryptographic toolkit
//! and zero-knowledge infrastructure layer.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod crypto;
pub mod zk;
pub mod net;

use thiserror::Error;

/// Core error type for RustZkrypt operations
#[derive(Error, Debug)]
pub enum Error {
    /// Cryptographic operation failed
    #[error("crypto error: {0}")]
    Crypto(String),
    
    /// Zero-knowledge proof error
    #[error("zk error: {0}")]
    Zk(String),
    
    /// Networking error
    #[error("network error: {0}")]
    Network(String),
    
    /// Input/output error
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type for RustZkrypt operations
pub type Result<T> = std::result::Result<T, Error>;

/// Core configuration for RustZkrypt
#[derive(Debug, Clone)]
pub struct Config {
    /// Network configuration
    pub network: net::Config,
    /// Cryptographic configuration
    pub crypto: crypto::Config,
    /// Zero-knowledge configuration
    pub zk: zk::Config,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            network: net::Config::default(),
            crypto: crypto::Config::default(),
            zk: zk::Config::default(),
        }
    }
}

/// Initialize the RustZkrypt library with the given configuration
pub fn init(config: Config) -> Result<()> {
    crypto::init(&config.crypto)?;
    zk::init(&config.zk)?;
    net::init(&config.network)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init() {
        let config = Config::default();
        assert!(init(config).is_ok());
    }
} 