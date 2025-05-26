#![no_main]
use libfuzzer_sys::fuzz_target;
use rustzkrypt::crypto::threshold::{ThresholdScheme, KeyShare, DKGRoundMessage};
use rand::thread_rng;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    let mut rng = thread_rng();
    
    // Use first byte for total shares (1-255)
    let total_shares = (data[0] as u32).max(1);
    // Use second byte for threshold (1-total_shares)
    let threshold = (data[1] as u32).max(1).min(total_shares);
    
    // Create threshold scheme
    if let Ok(scheme) = ThresholdScheme::new(&mut rng, total_shares, threshold) {
        // Test basic share generation and signing
        if let Ok(shares) = scheme.generate_shares(&mut rng) {
            let num_shares = (data[2] as u32) % total_shares;
            if num_shares >= threshold {
                let selected_shares: Vec<&KeyShare> = shares
                    .iter()
                    .take(num_shares as usize)
                    .collect();
                
                // Try to sign the remaining data
                let message = &data[3..];
                let _ = scheme.sign(message, &selected_shares);
            }
        }

        // Test DKG round
        let round = data[2] as u32;
        let messages: Vec<DKGRoundMessage> = (0..threshold)
            .filter_map(|i| scheme.run_dkg_round(&mut rng, i, &[]).ok())
            .collect();

        if !messages.is_empty() {
            // Verify DKG round
            if let Ok(dkg_shares) = scheme.verify_dkg_round(&messages) {
                // Test signing with DKG shares
                let num_shares = (data[3] as u32) % total_shares;
                if num_shares >= threshold {
                    let selected_shares: Vec<&KeyShare> = dkg_shares
                        .iter()
                        .take(num_shares as usize)
                        .collect();
                    
                    let message = &data[4..];
                    let _ = scheme.sign(message, &selected_shares);
                }
            }
        }

        // Test share refresh
        if let Ok(shares) = scheme.generate_shares(&mut rng) {
            let num_shares = (data[2] as u32) % total_shares;
            if num_shares >= threshold {
                let selected_shares: Vec<&KeyShare> = shares
                    .iter()
                    .take(num_shares as usize)
                    .collect();
                
                // Try to refresh shares
                if let Ok(new_shares) = scheme.refresh_shares(&mut rng, &selected_shares) {
                    // Test signing with refreshed shares
                    let message = &data[3..];
                    let _ = scheme.sign(message, &new_shares[..threshold as usize]);
                }
            }
        }
    }
}); 