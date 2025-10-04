# JMIX-RS

A Rust implementation of the JMIX (JSON Medical Interchange) format for secure medical data exchange.

## Features

- DICOM file processing and metadata extraction
- JSON Schema validation
- AES-256-GCM encryption with Curve25519 ECDH key exchange
- JWS digital signatures (Ed25519)
- Cryptographic assertions for sender/requester/receiver identity verification
- High-level builder API for envelope creation

## Installation

```toml
[dependencies]
jmix-rs = "0.2.0"
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

## CLI (runbeam)

A small CLI is included to validate JMIX packages.

Build and run:

```bash
cargo run --bin runbeam -- validate ./tmp/<ENVELOPE_ID>.jmix
```

Flags:
- --validate-schema: enable JSON Schema validation (defaults to false)
- --schema-dir PATH: custom schema directory (default ../jmix/schemas)
- --verify-assertions: verify sender/requester/receiver assertions if present
- --key PATH: recipient secret key for decrypting encrypted packages (payload.enc)
- --json: output a machine-readable JSON report

Examples:

```bash
# Unencrypted package, no schema checks
cargo run --bin runbeam -- validate ./tmp/<id>.jmix

# Encrypted package: verify decryption + payload hash using secret key
cargo run --bin runbeam -- validate ./tmp/<id>.jmix --key ./tmp/keys_encrypted_test/recipient_secret.key

# With schema checks (requires schemas available)
cargo run --bin runbeam -- validate ./tmp/<id>.jmix --validate-schema --schema-dir ../jmix/schemas

# JSON output
cargo run --bin runbeam -- validate ./tmp/<id>.jmix --json
```

### Verifying assertions

To verify sender/requester/receiver assertions during validation, add `--verify-assertions`:

```bash
# Build your envelope with assertions (see examples/sender_assertions.rs for generation)
# Then validate with assertion checks enabled
cargo run --bin runbeam -- validate ./tmp/<id>.jmix --verify-assertions
```

### Decrypting an encrypted package

Extract the contents of `payload.enc` using the recipient's secret key:

```bash
cargo run --bin runbeam -- decrypt ./tmp/<id>.jmix \
  --key ./tmp/keys_encrypted_test/recipient_secret.key \
  --out ./tmp/decrypted
```

Tip: Temporary and example outputs are written under ./tmp/ by convention.

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

- Unencrypted packages: The hash is computed over the contents of `payload/` as follows:
  - Recursively list files under `payload/`
  - Sort by path relative to `payload/` (Unicode codepoint order)
  - For each file: update the SHA-256 hasher with `relative/path` (UTF-8), then a single newline byte (`\n`), then the file's raw bytes
  - The final digest is emitted as `sha256:<hex>`

- Encrypted packages: The payload is first assembled as a `payload.tar` and then encrypted to `payload.enc` using AES-256-GCM with ECDH (Curve25519) and HKDF-SHA256. The payload hash is computed as the SHA-256 over the plaintext `payload.tar` bytes prior to encryption and saved in the manifest. This makes the hash independent of IVs/ephemeral keys and stable across encryptions.

During validation:
- Unencrypted: the validator recomputes the directory hash and compares it to the manifest value.
- Encrypted: when a recipient secret key is provided, the validator decrypts `payload.enc`, hashes the plaintext TAR, and compares.

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
cargo run --bin runbeam -- validate ./tmp/<id>.jmix --validate-schema --schema-dir ../jmix/schemas

# Or via environment variable (no flag needed)
JMIX_SCHEMA_DIR=../jmix/schemas \
  cargo run --bin runbeam -- validate ./tmp/<id>.jmix --validate-schema
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
│   └── runbeam.rs          # CLI: runbeam validate
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
