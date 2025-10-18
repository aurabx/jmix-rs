# Developer Guide

This document is for contributors and maintainers working on the jmix-rs library and the jmix CLI.

For end-user documentation, see [README.md](../README.md).

## Build and Run

### Basic Build
```bash
# Build library and CLI
cargo build

# Optimized release build
cargo build --release

# Run the CLI (validate JMIX packages)
cargo run --bin jmix -- validate ./tmp/<ENVELOPE_ID>.jmix

# Run with specific options (schema validation, custom schema dir, key, JSON output)
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

## Library Usage

### Basic JMIX Envelope

```rust path=null start=null
use jmix_rs::{builder::JmixBuilder, config::Config};

let builder = JmixBuilder::new();
let config = Config::from_file("config.json")?;
let (envelope, files) = builder.build_from_dicom("path/to/dicom", &config)?;
```

### With Security Features

```rust path=null start=null
// With encryption and signatures
let builder = JmixBuilder::with_complete_security()?;
let (envelope, files) = builder.build_from_dicom("path/to/dicom", &config)?;
let saved_files = builder.save_to_files(&envelope, &files, "output/")?;
```

### DICOM Processing

```rust path=null start=null
use jmix_rs::dicom::DicomProcessor;

let processor = DicomProcessor::new();
let metadata = processor.process_dicom_folder("path/to/dicom", None)?;
println!("Extracted {} instances", metadata.instance_count);
```

### Configuration Example

Create a configuration file:

```json path=null start=null
{
  "version": "1.0",
  "sender": {
    "name": "Healthcare Provider",
    "id": "org:provider.123",
    "contact": "admin@provider.com"
  },
  "patient": {
    "name": "John Doe",
    "id": "PAT12345",
    "dob": "1985-03-15"
  }
}
```

## Technical Details

### DICOM Processing

The library includes a DICOM processor that can:

- Detect DICOM files by magic number, file extension, and parsing validation
- Extract metadata: patient info, study details, series information
- Handle multiple files by merging metadata from multiple instances
- Fallback gracefully using config data when DICOM parsing fails

Example output:

```
Extracted DICOM metadata:
  Patient name: Some("Brown, Jane")
  Patient ID: Some("PID156695") 
  Study description: Some("CT Pulmonary Angiogram")
  Modalities: ["CT"]
  Series count: 1
  Instance count: 15
```

### Cryptographic Features

- **AES-256-GCM**: Authenticated encryption with 256-bit keys
- **Curve25519**: Elliptic curve Diffie-Hellman key exchange
- **Ed25519**: Elliptic curve digital signatures
- **SHA-256**: Cryptographic hashing for fingerprints and integrity
- **JWS**: JSON Web Signature standard (RFC 7515)

### Payload Hashing

JMIX-RS computes and validates a deterministic payload hash stored in `manifest.security.payload_hash` (format: `sha256:<hex>`):

- **Unencrypted packages**: The hash is computed over the contents of `payload/` as follows:
  - Recursively list files under `payload/`
  - Sort by path relative to `payload/` (Unicode codepoint order)
  - For each file: update the SHA-256 hasher with `relative/path` (UTF-8), then a single newline byte (`\n`), then the file's raw bytes
  - The final digest is emitted as `sha256:<hex>`

- **Encrypted packages**: The payload is first assembled as a `payload.tar` and then encrypted to `payload.enc` using AES-256-GCM with ECDH (Curve25519) and HKDF-SHA256. The payload hash is computed as the SHA-256 over the plaintext `payload.tar` bytes prior to encryption and saved in the manifest. This makes the hash independent of IVs/ephemeral keys and stable across encryptions.

During validation:
- **Unencrypted**: the validator recomputes the directory hash and compares it to the manifest value.
- **Encrypted**: when a recipient secret key is provided, the validator decrypts `payload.enc`, hashes the plaintext TAR, and compares.

### Schema Validation

The validation system supports:

- Configurable schema path (default: `../jmix/schemas`)
- Lazy loading of schemas on demand
- Comprehensive validation for manifest, metadata, audit, and files
- Detailed error reporting with schema path and validation failures

To enable schema validation:

1. Ensure schema files exist in `../jmix/schemas/` (or configure a custom directory)
2. Configure schema discovery (precedence):
   - CLI flag `--schema-dir <PATH>`
   - Environment variable `JMIX_SCHEMA_DIR=/absolute/or/relative/path`
   - Default `../jmix/schemas`
3. Run validation tests:
   ```bash
   JMIX_SCHEMA_DIR=../jmix/schemas \
   cargo test test_validate_sample_files_with_schemas -- --ignored
   ```

CLI examples:
```bash
# Use a specific schema directory
cargo run --bin jmix -- validate ./tmp/<id>.jmix --validate-schema --schema-dir ../jmix/schemas

# Or via environment variable (no flag needed)
JMIX_SCHEMA_DIR=../jmix/schemas \
  cargo run --bin jmix -- validate ./tmp/<id>.jmix --validate-schema
```

### Error Handling

```rust path=null start=null
use jmix_rs::error::{JmixError, ValidationError, DicomError, EncryptionError};

match result {
    Ok(envelope) => println!("Success: Secure envelope created"),
    Err(JmixError::Validation(e)) => eprintln!("Schema validation error: {}", e),
    Err(JmixError::Dicom(e)) => eprintln!("DICOM processing error: {}", e),
    Err(JmixError::Encryption(e)) => eprintln!("Encryption error: {}", e),
    Err(JmixError::Jws(e)) => eprintln!("Signing error: {}", e),
    Err(JmixError::Assertion(e)) => eprintln!("Assertion error: {}", e),
    Err(e) => eprintln!("Other error: {}", e),
}
```

## Testing

### Test Coverage
- **Unit tests (32)**: DICOM, encryption, JWS, assertions, builder, types
- **Integration tests (11)**: End-to-end security, DICOM processing, envelope structure
- **Sample validation tests (7)**: JSON sample consistency, config conversion

### Running Tests
```bash
# Run all tests (50+ tests)
cargo test

# Run with output
cargo test -- --nocapture

# Test specific modules
cargo test encryption
cargo test jws
cargo test assertion
```

For detailed test documentation, see [tests/README.md](../tests/README.md).

## Project Structure

```
src/
├── lib.rs                  # Library root
├── config.rs               # Configuration types
├── types.rs                # JMIX core types
├── builder.rs              # High-level builder API
├── validation.rs           # JSON Schema validation
├── dicom.rs                # DICOM file processing
├── encryption.rs           # AES-256-GCM encryption (ECDH+HKDF)
├── jws.rs                  # JWS digital signatures
├── assertion.rs            # Ed25519 identity assertions
├── package_validation.rs   # Package-level validation API (hash, schema, assertions, decrypt)
├── bin/
│   └── jmix.rs             # CLI: jmix validate
└── error.rs                # Error handling

examples/
├── build_jmix.rs       # Basic envelope creation
├── jws_signing.rs      # Digital signature example
├── envelope_encryption.rs    # End-to-end encryption
└── sender_assertions.rs      # Identity verification

samples/
├── study_1/            # Real DICOM files (15 files, 3 series)
├── sample_config.json  # Configuration example
├── sample_manifest.json
├── sample_metadata.json
├── sample_audit.json
└── sample_files.json
```

## Project Rules and Conventions

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

For details, see [Performance Optimization Guide](performance_optimization.md).

### Schema Directory Configuration
The validation system expects schemas in `../jmix` directory by default (configurable). This path can be set relative to current working directory or as absolute path.

## Environment Variables

- `JMIX_SCHEMA_DIR`: Override default schema directory path for validation
- Used in tests: `JMIX_SCHEMA_DIR=../jmix/schemas cargo test -- --ignored`

## Sample Data

The library includes real sample data for testing:

- **DICOM files**: CT study with 15 instances across 3 series
- **JSON samples**: Complete configuration and manifest examples
- **Test data**: Used in integration tests and examples

## References

- [README.md](../README.md) - End-user documentation
- [Performance Optimization Guide](performance_optimization.md) - Skip flags for large datasets
- [Test Documentation](../tests/README.md) - Comprehensive testing guide
- [CHANGELOG.md](../CHANGELOG.md) - Release history and changes
- [WARP.md](../WARP.md) - Development environment guidance

## Documentation

You can find API documentation at [https://docs.rs/jmix-rs/latest/jmix_rs/](https://docs.rs/jmix-rs/latest/jmix_rs/)

## License

This project is licensed under the Apache 2.0 License.