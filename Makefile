.PHONY: setup build test bench clean zk wasm run docs lint

# Default target
all: build test

# Setup development environment
setup:
	@echo "Setting up development environment..."
	rustup update
	rustup target add wasm32-unknown-unknown
	cargo install wasm-pack
	cargo install cargo-audit
	@echo "Setup complete!"

# Build the project
build:
	@echo "Building project..."
	cargo build --release
	@echo "Build complete!"

# Run tests
test:
	@echo "Running tests..."
	cargo test --all-features
	@echo "Tests complete!"

# Run benchmarks
bench:
	@echo "Running benchmarks..."
	cargo bench
	@echo "Benchmarks complete!"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	cargo clean
	rm -rf target/
	rm -rf wasm/pkg/
	@echo "Clean complete!"

# Generate and verify a sample ZK proof
zk:
	@echo "Generating sample ZK proof..."
	cargo run --release -- prove -s "test secret"
	@echo "ZK proof complete!"

# Build WebAssembly package
wasm:
	@echo "Building WebAssembly package..."
	wasm-pack build wasm --target web
	@echo "WASM build complete!"

# Run the CLI demo
run:
	@echo "Running CLI demo..."
	cargo run --release -- encrypt -m "Hello, RustZkrypt!"
	@echo "Demo complete!"

# Generate documentation
docs:
	@echo "Generating documentation..."
	cargo doc --no-deps --open
	@echo "Documentation complete!"

# Run linter
lint:
	@echo "Running linter..."
	cargo clippy --all-targets --all-features -- -D warnings
	cargo fmt -- --check
	cargo audit
	@echo "Lint complete!"

# Help target
help:
	@echo "Available targets:"
	@echo "  setup  - Set up development environment"
	@echo "  build  - Build the project"
	@echo "  test   - Run tests"
	@echo "  bench  - Run benchmarks"
	@echo "  clean  - Clean build artifacts"
	@echo "  zk     - Generate sample ZK proof"
	@echo "  wasm   - Build WebAssembly package"
	@echo "  run    - Run CLI demo"
	@echo "  docs   - Generate documentation"
	@echo "  lint   - Run linter"
	@echo "  help   - Show this help message" 