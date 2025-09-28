# JMIX-RS

A Rust implementation of the JMIX (JSON Medical Interchange) format for secure medical data exchange.

## Features

- DICOM file processing and metadata extraction
- JSON Schema validation
- AES-256-GCM encryption with Curve25519 ECDH key exchange
- JWS digital signatures (Ed25519/RS256)
- Cryptographic assertions for sender identity verification
- High-level builder API for envelope creation

## Installation

```toml
[dependencies]
jmix-rs = "0.3.0"
```

## Usage

### Basic JMIX Envelope

```rust
use jmix_rs::{builder::JmixBuilder, config::Config};

let builder = JmixBuilder::new();
let config = Config::from_file("config.json")?;
let (envelope, files) = builder.build_from_dicom("path/to/dicom", &config)?;
```

### With Security Features

```rust
// With encryption and signatures
let builder = JmixBuilder::with_complete_security()?;
let (envelope, files) = builder.build_from_dicom("path/to/dicom", &config)?;
let saved_files = builder.save_to_files(&envelope, &files, "output/")?;
```

### DICOM Processing

```rust
use jmix_rs::dicom::DicomProcessor;

let processor = DicomProcessor::new();
let metadata = processor.process_dicom_folder("path/to/dicom", None)?;
println!("Extracted {} instances", metadata.instance_count);
```

### Configuration Example

Create a configuration file:

```json
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

## Examples

```bash
# Basic envelope creation
cargo run --example build_jmix

# Digital signatures
cargo run --example jws_signing

# End-to-end encryption
cargo run --example envelope_encryption

# Identity verification
cargo run --example sender_assertions
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

### Schema Validation

The validation system supports:

- Configurable schema path (default: `../jmix/schemas`)
- Lazy loading of schemas on demand
- Comprehensive validation for manifest, metadata, audit, and files
- Detailed error reporting with schema path and validation failures

To enable schema validation:

1. Ensure schema files exist in `../jmix/schemas/` (or configured path)
2. Run validation tests:
   ```bash
   cargo test test_validate_sample_files_with_schemas -- --ignored
   ```

### Error Handling

```rust
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

### Test Coverage

- **Unit tests (32)**: DICOM, encryption, JWS, assertions, builder, types
- **Integration tests (11)**: End-to-end security, DICOM processing, envelope structure
- **Sample validation tests (7)**: JSON sample consistency, config conversion

## Project Structure

```
src/
├── lib.rs              # Library root
├── config.rs           # Configuration types
├── types.rs            # JMIX core types
├── builder.rs          # High-level builder API
├── validation.rs       # JSON Schema validation
├── dicom.rs            # DICOM file processing
├── encryption.rs       # AES-256-GCM encryption
├── jws.rs              # JWS digital signatures
├── assertion.rs        # Ed25519 identity assertions
└── error.rs            # Error handling

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

## Sample Data

The library includes real sample data for testing:

- **DICOM files**: CT study with 15 instances across 3 series
- **JSON samples**: Complete configuration and manifest examples
- **Test data**: Used in integration tests and examples

## Development

```bash
# Build and test
cargo build
cargo test

# Run examples
cargo build --examples

# Code quality
cargo clippy
cargo fmt

# Generate documentation
cargo doc --open
```

## License

This project matches the licensing of the original PHP implementation.
