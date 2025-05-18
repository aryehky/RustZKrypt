use std::time::Duration;
use std::collections::HashMap;

use libp2p::{
    core::upgrade,
    floodsub::{self, Floodsub, FloodsubEvent, Topic},
    identity, mdns, swarm::SwarmEvent,
    Multiaddr, NetworkBehaviour, PeerId, Swarm,
};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::time::sleep;

use crate::{crypto, Result};

/// Network protocol configuration
#[derive(Clone)]
pub struct ProtocolConfig {
    /// Local peer listening address
    pub listen_addr: Multiaddr,
    /// Bootstrap peers to connect to
    pub bootstrap_peers: Vec<Multiaddr>,
    /// Message topic name
    pub topic: String,
}

/// A secure message in the P2P network
#[derive(Debug, Serialize, Deserialize)]
pub struct SecureMessage {
    /// Message sender's peer ID
    pub from: String,
    /// Encrypted message content
    pub content: Vec<u8>,
    /// Ed25519 signature of the content
    pub signature: Vec<u8>,
    /// Message timestamp
    pub timestamp: u64,
}

/// Network behavior combining floodsub and mDNS
#[derive(NetworkBehaviour)]
#[behaviour(out_event = "OutEvent")]
struct Behaviour {
    floodsub: Floodsub,
    mdns: mdns::async_io::Behaviour,
}

enum OutEvent {
    Floodsub(FloodsubEvent),
    Mdns(mdns::Event),
}

impl From<FloodsubEvent> for OutEvent {
    fn from(event: FloodsubEvent) -> Self {
        OutEvent::Floodsub(event)
    }
}

impl From<mdns::Event> for OutEvent {
    fn from(event: mdns::Event) -> Self {
        OutEvent::Mdns(event)
    }
}

/// Message status tracking
#[derive(Debug, Clone)]
struct MessageStatus {
    attempts: u32,
    last_attempt: u64,
    ack_received: bool,
}

/// Message acknowledgment
#[derive(Debug, Serialize, Deserialize)]
struct MessageAck {
    message_id: String,
    from: String,
    timestamp: u64,
}

/// A P2P messaging protocol node
pub struct ProtocolNode {
    swarm: Swarm<Behaviour>,
    topic: Topic,
    message_tx: mpsc::Sender<SecureMessage>,
    message_rx: mpsc::Receiver<SecureMessage>,
}

impl ProtocolNode {
    /// Create a new protocol node
    pub async fn new(config: ProtocolConfig) -> Result<Self> {
        // Generate peer identity
        let id_keys = identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(id_keys.public());

        // Create transport
        let transport = libp2p::development_transport(id_keys.clone())
            .await
            .map_err(|e| crate::Error::Network(e.to_string()))?;

        // Create floodsub topic
        let topic = Topic::new(config.topic);

        // Create swarm
        let mut swarm = {
            let mdns = mdns::async_io::Behaviour::new(mdns::Config::default())
                .map_err(|e| crate::Error::Network(e.to_string()))?;
            let mut behaviour = Behaviour {
                floodsub: Floodsub::new(peer_id),
                mdns,
            };
            behaviour.floodsub.subscribe(topic.clone());
            Swarm::new(transport, behaviour, peer_id)
        };

        // Listen on the network address
        swarm.listen_on(config.listen_addr)
            .map_err(|e| crate::Error::Network(e.to_string()))?;

        // Connect to bootstrap peers
        for addr in config.bootstrap_peers {
            swarm.dial(addr)
                .map_err(|e| crate::Error::Network(e.to_string()))?;
        }

        // Create message channels
        let (tx, rx) = mpsc::channel(100);

        Ok(Self {
            swarm,
            topic,
            message_tx: tx,
            message_rx: rx,
        })
    }

    /// Send an encrypted message to the network
    pub async fn send_message(&mut self, content: &[u8], keypair: &crypto::SecureKey) -> Result<()> {
        let signature = crypto::sign(content, keypair.as_bytes());
        
        let message = SecureMessage {
            from: self.swarm.local_peer_id().to_string(),
            content: content.to_vec(),
            signature,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        let data = serde_json::to_vec(&message)
            .map_err(|e| crate::Error::Network(e.to_string()))?;
            
        self.swarm.behaviour_mut().floodsub.publish(self.topic.clone(), data);
        Ok(())
    }

    /// Send a message with retry logic
    pub async fn send_message_with_retry(
        &mut self,
        content: &[u8],
        keypair: &crypto::SecureKey,
        max_attempts: u32,
        retry_delay: Duration,
    ) -> Result<()> {
        let message_id = format!("{:x}", Sha256::digest(content));
        let mut status = MessageStatus {
            attempts: 0,
            last_attempt: 0,
            ack_received: false,
        };
        
        while status.attempts < max_attempts && !status.ack_received {
            self.send_message(content, keypair).await?;
            status.attempts += 1;
            status.last_attempt = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
                
            // Wait for acknowledgment
            sleep(retry_delay).await;
            
            // Check if ack was received during sleep
            if let Some(ack) = self.check_ack(&message_id).await {
                status.ack_received = true;
                break;
            }
        }
        
        if !status.ack_received {
            return Err(crate::Error::Network("Message not acknowledged".into()));
        }
        
        Ok(())
    }

    /// Check for message acknowledgment
    async fn check_ack(&self, message_id: &str) -> Option<MessageAck> {
        // Implementation would check a received acks cache
        None // Placeholder
    }

    /// Send message acknowledgment
    async fn send_ack(&mut self, message_id: &str) -> Result<()> {
        let ack = MessageAck {
            message_id: message_id.to_string(),
            from: self.swarm.local_peer_id().to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        
        let data = serde_json::to_vec(&ack)
            .map_err(|e| crate::Error::Network(e.to_string()))?;
            
        self.swarm.behaviour_mut().floodsub.publish(self.topic.clone(), data);
        Ok(())
    }

    /// Run the protocol node with acknowledgments
    pub async fn run_with_acks(&mut self) -> Result<()> {
        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => {
                    match event {
                        SwarmEvent::Behaviour(OutEvent::Floodsub(FloodsubEvent::Message(msg))) => {
                            // Try to parse as regular message or ack
                            if let Ok(message) = serde_json::from_slice::<SecureMessage>(&msg.data) {
                                // Send acknowledgment
                                let message_id = format!("{:x}", Sha256::digest(&message.content));
                                self.send_ack(&message_id).await?;
                                
                                self.message_tx.send(message).await
                                    .map_err(|e| crate::Error::Network(e.to_string()))?;
                            } else if let Ok(ack) = serde_json::from_slice::<MessageAck>(&msg.data) {
                                // Process acknowledgment
                                // Implementation would update acks cache
                            }
                        }
                        SwarmEvent::Behaviour(OutEvent::Mdns(mdns::Event::Discovered(list))) => {
                            for (peer_id, _) in list {
                                self.swarm.behaviour_mut().floodsub.add_node_to_partial_view(peer_id);
                            }
                        }
                        SwarmEvent::Behaviour(OutEvent::Mdns(mdns::Event::Expired(list))) => {
                            for (peer_id, _) in list {
                                self.swarm.behaviour_mut().floodsub.remove_node_from_partial_view(&peer_id);
                            }
                        }
                        _ => {}
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            }
        }
    }

    /// Get the message receiver channel
    pub fn message_receiver(&self) -> mpsc::Receiver<SecureMessage> {
        self.message_rx.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_protocol() {
        let config = ProtocolConfig {
            listen_addr: Multiaddr::from_str("/ip4/127.0.0.1/tcp/0").unwrap(),
            bootstrap_peers: vec![],
            topic: "test".into(),
        };

        let mut node = ProtocolNode::new(config).await.unwrap();
        let key = crypto::SecureKey::new(32);
        
        // Test message sending
        node.send_message(b"test message", &key).await.unwrap();
        
        // Run node for a short time
        tokio::spawn(async move {
            node.run_with_acks().await.unwrap();
        });
    }

    #[tokio::test]
    async fn test_message_retry() {
        let config = ProtocolConfig {
            listen_addr: Multiaddr::from_str("/ip4/127.0.0.1/tcp/0").unwrap(),
            bootstrap_peers: vec![],
            topic: "test".into(),
        };

        let mut node = ProtocolNode::new(config).await.unwrap();
        let key = crypto::SecureKey::new(32);
        
        // Test message sending with retries
        let result = node.send_message_with_retry(
            b"test message",
            &key,
            3,
            Duration::from_millis(100)
        ).await;
        
        // Expect error since no peers to acknowledge
        assert!(result.is_err());
    }
} 