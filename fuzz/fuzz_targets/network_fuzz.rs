#![no_main]
use libfuzzer_sys::fuzz_target;
use rustzkrypt::net::{SecureMessage, MessageAck};
use serde_json;

fuzz_target!(|data: &[u8]| {
    // Try to parse data as SecureMessage
    if let Ok(str_data) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<SecureMessage>(str_data);
    }
    
    // Create and serialize message with fuzzer data
    if data.len() > 16 {
        let message = SecureMessage {
            from: String::from_utf8_lossy(&data[..8]).to_string(),
            content: data[8..12].to_vec(),
            signature: data[12..16].to_vec(),
            timestamp: 12345,
        };
        
        let _ = serde_json::to_string(&message);
    }
    
    // Fuzz message acknowledgments
    if data.len() > 8 {
        let ack = MessageAck {
            message_id: hex::encode(&data[..4]),
            from: String::from_utf8_lossy(&data[4..8]).to_string(),
            timestamp: 12345,
        };
        
        let _ = serde_json::to_string(&ack);
    }
}); 