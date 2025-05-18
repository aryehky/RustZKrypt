# 🛡️ RustZkrypt

**RustZkrypt** is a blazing-fast, privacy-first cryptographic toolkit and zero-knowledge infrastructure layer built in Rust. It enables developers to build zk-powered apps, encrypted messaging, and private smart contract interactions — all with clean abstractions, modular cryptography, and Makefile-powered workflows.

> ⚙️ *Zero-knowledge made simple. Encryption made fast. Rust made usable.*

## ✨ Features

- ✅ Built in **Rust** with modular, zero-cost abstractions
- 🔐 Pluggable **zk-SNARK** / **zk-STARK** circuit integrations  
- 📡 Decentralized encrypted **messaging layer**
- 🧠 Easy proof generation with embedded circuit runners
- 🌐 WebAssembly support for browser & embedded targets
- 🛠️ Fully automated with a `Makefile` CLI

## 📦 Installation

### 🔧 Requirements

- [Rust](https://rustup.rs) `>=1.76`
- `make`
- `wasm-pack` (if using WASM)
- (Optional) `zkutil`, `circom`, `snarkjs` for native circuit workflows

### 🚀 Quickstart

```bash
git clone https://github.com/your-username/rustzkrypt.git
cd rustzkrypt
make setup
make build
make test
```

## 🧪 Makefile Commands

| Command | Description |
|---------|-------------|
| `make setup` | Installs dependencies and initializes environment |
| `make build` | Builds the Rust project (native + optional WASM target) |
| `make test` | Runs unit tests |
| `make bench` | Runs performance benchmarks |
| `make clean` | Cleans all build artifacts |
| `make zk` | Generates sample zero-knowledge proofs |
| `make wasm` | Builds the project for WebAssembly |
| `make run` | Runs the CLI demo application |
| `make docs` | Generates Rust documentation (cargo doc) |
| `make lint` | Lints the codebase with clippy |

## 🧩 Structure

```bash
rustzkrypt/
├── circuits/           # Optional: zk circuits in Circom or Noir
├── src/                # Core Rust source code
│   ├── lib.rs          # Main library entry
│   ├── zk/             # zk-proof generation & verification
│   ├── crypto/         # Encryption logic (AES, Ed25519, etc.)
│   ├── net/            # libp2p or networking layer
├── cli/                # Command line interface
├── wasm/               # WASM bindings
├── tests/              # Integration tests
├── Makefile           # Dev automation
├── Cargo.toml         # Rust project manifest
```

## 🧠 Example Use Case

```rust
use rustzkrypt::crypto::encrypt;
use rustzkrypt::zk::generate_proof;

fn main() {
    let message = "Top secret";
    let key = b"an example very very secret key.";

    let ciphertext = encrypt(message, key);
    let proof = generate_proof(&ciphertext);

    println!("Encrypted: {:?}", ciphertext);
    println!("Proof: {:?}", proof);
}
```

## 🔐 Security

RustZkrypt is designed with security-first principles:

- All sensitive data uses `zeroize` for memory wiping
- Ed25519, AES-GCM, and SHA-256 support by default
- Optional post-quantum keys via Kyber integration
- ZK circuits are modular and verifiable with formal tooling

## 🛠 Roadmap

- [ ] Basic zk + encryption modules
- [ ] Circuit support for identity / auth
- [ ] Cross-chain zk bridge PoC
- [ ] Encrypted messaging layer over libp2p
- [ ] WASM SDK + NPM release

## 📜 License

MIT © 2024 RustZkrypt Contributors

## 🌐 Learn More

- [Zero-Knowledge Proofs](https://z.cash/technology/zksnarks/)
- [RustCrypto Project](https://github.com/RustCrypto)
- [zk-SNARK Learning Resources](https://zkp.science)
