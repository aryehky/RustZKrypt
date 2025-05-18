use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rustzkrypt::{
    crypto::{SecureKey, KeyStore},
    zk::{Circuit, HashPreimageCircuit, RangeProofCircuit, SetMembershipCircuit},
    net::ProtocolNode,
};
use sha2::{Sha256, Digest};

fn bench_crypto(c: &mut Criterion) {
    let mut group = c.benchmark_group("Crypto Operations");
    
    // Benchmark key generation
    group.bench_function("key_generation", |b| {
        b.iter(|| {
            let key = SecureKey::new(black_box(32));
            black_box(key);
        });
    });
    
    // Benchmark keystore operations
    group.bench_function("keystore_operations", |b| {
        b.iter(|| {
            let store = KeyStore::new(black_box(b"master password"));
            let key = SecureKey::new(32);
            store.store_key(
                "test-key",
                &key,
                rustzkrypt::crypto::KeyMetadata {
                    id: "test-key".into(),
                    key_type: "aes".into(),
                    created_at: 0,
                    description: None,
                },
            ).unwrap();
        });
    });
    
    group.finish();
}

fn bench_zk_proofs(c: &mut Criterion) {
    let mut group = c.benchmark_group("Zero-Knowledge Proofs");
    
    // Benchmark hash preimage proof
    group.bench_function("hash_preimage_proof", |b| {
        let preimage = b"secret value".to_vec();
        let mut hasher = Sha256::new();
        hasher.update(&preimage);
        let hash = hasher.finalize().to_vec();
        
        let circuit = HashPreimageCircuit {
            preimage: preimage.clone(),
            hash: hash.clone(),
        };
        
        b.iter(|| {
            let (pk, vk) = rustzkrypt::zk::generate_keys(&circuit).unwrap();
            let proof = circuit.generate_proof(&pk).unwrap();
            assert!(circuit.verify_proof(&vk, &proof).unwrap());
        });
    });
    
    // Benchmark range proof
    group.bench_function("range_proof", |b| {
        let circuit = RangeProofCircuit {
            number: 42,
            lower_bound: 0,
            upper_bound: 100,
        };
        
        b.iter(|| {
            let (pk, vk) = rustzkrypt::zk::generate_keys(&circuit).unwrap();
            let proof = circuit.generate_proof(&pk).unwrap();
            assert!(circuit.verify_proof(&vk, &proof).unwrap());
        });
    });
    
    // Benchmark set membership proof
    group.bench_function("set_membership_proof", |b| {
        let element = b"secret member".to_vec();
        let set = vec![
            b"member1".to_vec(),
            b"secret member".to_vec(),
            b"member3".to_vec(),
        ];
        
        let mut set_hashes = Vec::new();
        for e in &set {
            let mut hasher = Sha256::new();
            hasher.update(e);
            set_hashes.push(hasher.finalize().to_vec());
        }
        
        let merkle_root = rustzkrypt::zk::compute_merkle_root(&set_hashes);
        
        let circuit = SetMembershipCircuit {
            element,
            set_hashes,
            merkle_root,
        };
        
        b.iter(|| {
            let (pk, vk) = rustzkrypt::zk::generate_keys(&circuit).unwrap();
            let proof = circuit.generate_proof(&pk).unwrap();
            assert!(circuit.verify_proof(&vk, &proof).unwrap());
        });
    });
    
    group.finish();
}

fn bench_networking(c: &mut Criterion) {
    let mut group = c.benchmark_group("Networking");
    
    // Benchmark message serialization
    group.bench_function("message_serialization", |b| {
        let message = rustzkrypt::net::SecureMessage {
            from: "peer1".into(),
            content: vec![1, 2, 3, 4],
            signature: vec![5, 6, 7, 8],
            timestamp: 12345,
        };
        
        b.iter(|| {
            let serialized = serde_json::to_vec(&message).unwrap();
            black_box(serialized);
        });
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_crypto,
    bench_zk_proofs,
    bench_networking
);
criterion_main!(benches); 