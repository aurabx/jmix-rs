# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Common Commands

### Build & Run
```bash
# Build the library and CLI
cargo build

# Build optimized release version
cargo build --release

# Run the CLI (validate JMIX packages)
cargo run --bin jmix -- validate ./tmp/<ENVELOPE_ID>.jmix

# Run with specific options
cargo run --bin jmix -- validate ./tmp/<id>.jmix --validate-schema --schema-dir ../jmix/schemas --key ./tmp/recipient_secret.key --json

# Decrypt an encrypted JMIX payload
cargo run --bin jmix -- decrypt ./tmp/<id>.jmix --key ./tmp/recipient_secret.key --out ./tmp/decrypted
```

### Examples
```bash
# Run example programs
cargo run --example build_jmix          # Basic envelope creation
cargo run --example jws_signing         # Digital signatures
cargo run --example envelope_encryption # End-to-end encryption
cargo run --example sender_assertions   # Identity verification
cargo run --example performance_optimization  # Performance flags
```

### Testing
```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test module
cargo test encryption
cargo test jws
cargo test assertion

# Run integration tests only
cargo test --test integration_tests
cargo test --test sample_validation_tests

# Run schema validation tests (requires ../jmix/schemas)
JMIX_SCHEMA_DIR=../jmix/schemas cargo test -- --ignored
```

### Code Quality
```bash
# Format code
cargo fmt

# Lint with clippy
cargo clippy

# Generate documentation
cargo doc --open
```

## High-Level Architecture

### Core Components
This crate provides a **Rust library (jmix-rs)** and **CLI tool (jmix)** for the JMIX (JSON Medical Interchange) format. The architecture centers around secure medical data exchange with cryptographic features.

**Key Modules:**
- `builder::JmixBuilder` - High-level API for creating JMIX envelopes with various security configurations
- `types` - Core JMIX data structures (Envelope, Manifest, Metadata, Audit)
- `encryption` - AES-256-GCM encryption with ECDH (Curve25519) key exchange
- `jws` - Ed25519 digital signatures following JWS standard
- `assertion` - Ed25519 cryptographic assertions for entity identity verification
- `dicom` - DICOM file processing and metadata extraction
- `validation` - JSON Schema validation with configurable schema directory
- `package_validation` - Complete package validation API

### Data Flow
1. **Input**: DICOM files + configuration → DICOM processor extracts metadata
2. **Build**: JmixBuilder creates envelope structure (manifest, metadata, audit)
3. **Security**: Optional encryption (AES-256-GCM), signing (JWS), and assertions (Ed25519)
4. **Output**: JMIX package directory with payload/ subdirectory or encrypted payload.enc
5. **Validation**: Schema validation, payload hash verification, assertion checking, decryption

### Encryption Pipeline
- **Key Exchange**: Ephemeral Curve25519 ECDH with recipient's public key
- **Encryption**: AES-256-GCM with IV, authenticated encryption
- **Format**: Base64-encoded ephemeral public key, IV, and auth tag in manifest.json
- **Payload**: TAR archive of payload/ directory → encrypted as payload.enc

### Schema Resolution
Schema validation uses configurable directory path with precedence:
1. CLI flag `--schema-dir <PATH>`
2. Environment variable `JMIX_SCHEMA_DIR`
3. Default `../jmix/schemas`

### Testing Strategy
- **Unit tests**: In-module tests for cryptographic operations, type serialization, DICOM processing
- **Integration tests**: End-to-end envelope creation, encryption/decryption workflows
- **Sample validation**: Uses `/samples` directory with real DICOM data for testing

## Project-Specific Rules & Conventions

### File Output Conventions
- **Temporary files**: Use `./tmp` directory (not `/tmp`) for development outputs
- **JMIX packages**: Created as `<ENVELOPE_ID>.jmix` directories, then ZIP files
- **Encrypted packages**: Use `payload.enc` instead of `payload/` directory

### Cryptographic Standards
- **Encryption algorithm**: AES-256-GCM (as specified in project rules)
- **Key format**: Base64-encoded ephemeral public key, IV, and authentication tag
- **Hash algorithm**: SHA-256 for payload integrity verification

### Sample Data Usage
- **Samples directory**: `/samples` is intended for use in tests (as per project rules)
- **Test DICOM data**: Real CT study with 15 instances across 3 series in `samples/study_1/`
- **JSON samples**: Complete configuration and manifest examples for testing

### Performance Optimization
The builder supports performance flags for large datasets:
- `skip_hashing`: Skips SHA-256 computation, sets hash fields to `None`
- `skip_listing`: Omits DICOM files from files.json manifest
- Use `build_from_dicom_with_options()` and `save_to_files_with_options()` methods

### Schema Directory Configuration
The validation system expects schemas in `../jmix` directory by default (configurable). This path can be set relative to current working directory or as absolute path.

## Environment Variables

- `JMIX_SCHEMA_DIR`: Override default schema directory path for validation
- Used in tests: `JMIX_SCHEMA_DIR=../jmix/schemas cargo test -- --ignored`

## Reference Links

- [README.md](./README.md) - Complete usage documentation and examples
- [Performance Optimization Guide](./docs/performance_optimization.md) - Skip flags for large datasets
- [Test Documentation](./tests/README.md) - Comprehensive testing guide
- [CHANGELOG.md](./CHANGELOG.md) - Release history and changes