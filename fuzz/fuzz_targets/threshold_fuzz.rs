#![no_main]
use libfuzzer_sys::fuzz_target;
use rustzkrypt::crypto::threshold::{ThresholdScheme, KeyShare};
use rand::thread_rng;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    let mut rng = thread_rng();
    
    // Use first byte for total shares (1-255)
    let total_shares = (data[0] as u32).max(1);
    // Use second byte for threshold (1-total_shares)
    let threshold = (data[1] as u32).max(1).min(total_shares);
    
    // Create threshold scheme
    if let Ok(scheme) = ThresholdScheme::new(&mut rng, total_shares, threshold) {
        // Generate shares
        if let Ok(shares) = scheme.generate_shares(&mut rng) {
            // Try signing with random subset of shares
            let num_shares = (data.len() - 2) as u32 % total_shares;
            if num_shares >= threshold {
                let selected_shares: Vec<&KeyShare> = shares
                    .iter()
                    .take(num_shares as usize)
                    .collect();
                
                // Try to sign the remaining data
                let message = &data[2..];
                let _ = scheme.sign(message, &selected_shares);
            }
        }
    }
}); 