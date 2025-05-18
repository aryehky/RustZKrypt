use std::time::Duration;

use libp2p::{
    core::muxing::StreamMuxerBox,
    identity,
    noise::{NoiseConfig, X25519Spec},
    tcp::TokioTcpConfig,
    yamux::YamuxConfig,
    PeerId, Transport,
};
use tokio::sync::mpsc;

use crate::Result;

/// Configuration for networking operations
#[derive(Debug, Clone)]
pub struct Config {
    /// Listen address for the p2p node
    pub listen_addr: String,
    /// Bootstrap peers to connect to
    pub bootstrap_peers: Vec<String>,
    /// Connection timeout in seconds
    pub timeout: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_addr: "/ip4/0.0.0.0/tcp/0".into(),
            bootstrap_peers: vec![],
            timeout: 60,
        }
    }
}

/// Initialize the networking module
pub fn init(_config: &Config) -> Result<()> {
    Ok(())
}

/// A peer-to-peer node for secure communication
pub struct Node {
    peer_id: PeerId,
    transport: libp2p::core::transport::Boxed<(PeerId, StreamMuxerBox)>,
    message_tx: mpsc::Sender<Vec<u8>>,
    message_rx: mpsc::Receiver<Vec<u8>>,
}

impl Node {
    /// Create a new p2p node
    pub async fn new(config: &Config) -> Result<Self> {
        // Generate key pair for node identity
        let local_key = identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());

        // Create noise protocol for encryption
        let noise_keys = NoiseConfig::xx(local_key).into_authenticated();

        // Create transport with TCP + Noise + Yamux
        let transport = TokioTcpConfig::new()
            .nodelay(true)
            .upgrade(libp2p::core::upgrade::Version::V1)
            .authenticate(noise_keys)
            .multiplex(YamuxConfig::default())
            .timeout(Duration::from_secs(config.timeout))
            .boxed();

        // Create message channels
        let (tx, rx) = mpsc::channel(100);

        Ok(Self {
            peer_id: local_peer_id,
            transport,
            message_tx: tx,
            message_rx: rx,
        })
    }

    /// Get the node's peer ID
    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    /// Send a message to a peer
    pub async fn send_message(&self, data: Vec<u8>) -> Result<()> {
        self.message_tx
            .send(data)
            .await
            .map_err(|e| crate::Error::Network(e.to_string()))
    }

    /// Receive a message from any peer
    pub async fn receive_message(&mut self) -> Result<Vec<u8>> {
        self.message_rx
            .recv()
            .await
            .ok_or_else(|| crate::Error::Network("Channel closed".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_node_creation() {
        let config = Config::default();
        let node = Node::new(&config).await.unwrap();
        assert!(!node.peer_id().to_string().is_empty());
    }

    #[tokio::test]
    async fn test_message_channel() {
        let config = Config::default();
        let mut node = Node::new(&config).await.unwrap();
        
        let message = b"test message".to_vec();
        node.send_message(message.clone()).await.unwrap();
        
        let received = node.receive_message().await.unwrap();
        assert_eq!(message, received);
    }
} 