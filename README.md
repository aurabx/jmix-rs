# JMIX-RS

A Rust library for creating, validating, and working with JMIX (JSON Medical Interchange) packages. JMIX enables secure exchange of medical imaging data and metadata with built-in encryption, digital signatures, and integrity verification.

## Features

- 🏗️ **High-level builder API** for creating JMIX envelopes
- 🏥 **DICOM file processing** and metadata extraction  
- 🔐 **End-to-end encryption** using AES-256-GCM with Curve25519 ECDH
- ✍️ **Digital signatures** with Ed25519 (JWS standard)
- 🔍 **JSON Schema validation** with configurable schema directory
- ✅ **Integrity verification** using deterministic SHA-256 payload hashing
- 🛡️ **Cryptographic assertions** for sender/receiver identity verification
- 📦 **Package validation API** with comprehensive error reporting

## Installation

Add to your `Cargo.toml`:

```toml path=null start=null
[dependencies]
jmix-rs = "0.3.2"
```

## Quick Start

### Basic JMIX Envelope

Create a simple JMIX envelope from DICOM files:

```rust path=null start=null
use jmix_rs::{builder::JmixBuilder, config::Config};

let builder = JmixBuilder::new();
let config = Config::from_file("config.json")?;
let (envelope, files) = builder.build_from_dicom("path/to/dicom", &config)?;
```

### With Security Features

Create an envelope with encryption and digital signatures:

```rust path=null start=null
use jmix_rs::builder::JmixBuilder;

// Builder with complete security features
let builder = JmixBuilder::with_complete_security()?;
let (envelope, files) = builder.build_from_dicom("path/to/dicom", &config)?;

// Save to files
let saved_files = builder.save_to_files(&envelope, &files, "./tmp/output")?;
```

### DICOM Processing

Extract metadata from DICOM files:

```rust path=null start=null
use jmix_rs::dicom::DicomProcessor;

let processor = DicomProcessor::new();
let metadata = processor.process_dicom_folder("path/to/dicom", None)?;
println!("Extracted {} instances", metadata.instance_count);
```

### Configuration

Create a configuration file for your JMIX envelope:

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

## API Overview

### Core Types

```rust path=null start=null
use jmix_rs::{
    builder::JmixBuilder,
    config::Config,
    types::{Envelope, Manifest, Metadata, Audit, Files},
    dicom::DicomProcessor,
    validation::ValidationConfig,
    package_validation::{validate_package, ValidationOptions}
};
```

### Builder API

The `JmixBuilder` provides a high-level API for creating JMIX envelopes:

```rust path=null start=null
// Basic builder
let builder = JmixBuilder::new();

// With encryption only
let builder = JmixBuilder::with_encryption(recipient_public_key)?;

// With signatures only  
let builder = JmixBuilder::with_jws_signing()?;

// With complete security (encryption + signatures + assertions)
let builder = JmixBuilder::with_complete_security()?;
```

### Validation API

Validate existing JMIX packages:

```rust path=null start=null
use jmix_rs::package_validation::{validate_package, ValidationOptions};

let options = ValidationOptions {
    validate_schema: true,
    schema_dir: Some("../jmix/schemas".to_string()),
    verify_assertions: true,
    recipient_secret_key_path: Some("./tmp/key.pem".to_string()),
};

let report = validate_package("./tmp/package.jmix", &options)?;
println!("Validation result: {:?}", report);
```

### Error Handling

```rust path=null start=null
use jmix_rs::error::JmixError;

match result {
    Ok(envelope) => println!("Success!"),
    Err(JmixError::Validation(e)) => eprintln!("Schema validation error: {}", e),
    Err(JmixError::Dicom(e)) => eprintln!("DICOM processing error: {}", e),
    Err(JmixError::Encryption(e)) => eprintln!("Encryption error: {}", e),
    Err(JmixError::Jws(e)) => eprintln!("Signing error: {}", e),
    Err(JmixError::Assertion(e)) => eprintln!("Assertion error: {}", e),
    Err(e) => eprintln!("Other error: {}", e),
}
```

## Performance Optimization

For large DICOM datasets, you can use performance flags to optimize processing:

```rust path=null start=null
// Skip SHA-256 hashing for faster processing
let (envelope, files) = builder.build_from_dicom_with_options(
    &dicom_path,
    &config,
    true,  // skip_hashing
    false  // skip_listing
)?;

// Skip both hashing and file listing for maximum speed
let (envelope, files) = builder.build_from_dicom_with_options(
    &dicom_path,
    &config,
    true,  // skip_hashing
    true   // skip_listing
)?;

// Save with same performance flags
builder.save_to_files_with_options(
    &envelope,
    &files,
    &output_dir,
    true,  // skip_hashing
    true   // skip_listing
)?;
```

See [Performance Optimization Guide](docs/performance_optimization.md) for detailed information.

## Schema Validation

Configure JSON Schema validation for JMIX packages:

```rust path=null start=null
use jmix_rs::validation::ValidationConfig;

// Configure schema directory
let validation_config = ValidationConfig::new(
    Some("../jmix/schemas".to_string())
)?;

// Validate envelope components
validation_config.validate_manifest(&envelope.manifest)?;
validation_config.validate_metadata(&envelope.metadata)?;
validation_config.validate_audit(&envelope.audit)?;
```

**Schema resolution order:**
1. `ValidationConfig::new(Some(path))` - Explicit path
2. `JMIX_SCHEMA_DIR` environment variable
3. `../jmix/schemas` (default)

## Technical Details

### Cryptographic Features

- **AES-256-GCM**: Authenticated encryption with 256-bit keys
- **Curve25519**: Elliptic curve Diffie-Hellman key exchange
- **Ed25519**: Elliptic curve digital signatures (JWS standard)
- **SHA-256**: Deterministic payload hashing for integrity verification
- **Ephemeral keys**: Base64-encoded ephemeral public key, IV, and auth tag

### Payload Hashing

JMIX-RS uses deterministic SHA-256 payload hashing:

- **Unencrypted**: Hash computed over `payload/` directory contents
- **Encrypted**: Hash computed over plaintext TAR before encryption
- **Format**: `sha256:<hex>` stored in `manifest.security.payload_hash`

## CLI Tool

The library includes a command-line tool for validating and working with JMIX packages:

### Installation

```bash path=null start=null
# Install from crates.io
cargo install jmix-rs

# Or build from source
cargo build --release
# Binary at: target/release/jmix
```

### Usage

```bash path=null start=null
# Validate a JMIX package
jmix validate ./tmp/package.jmix

# Validate with schema checking
jmix validate ./tmp/package.jmix --validate-schema

# Decrypt an encrypted package
jmix decrypt ./tmp/encrypted.jmix --key ./tmp/key.pem --out ./tmp/output

# JSON output for automation
jmix validate ./tmp/package.jmix --json
```

For detailed CLI documentation, run `jmix --help`.

## Learn More

- 📖 **[Developer Guide](docs/DEVELOPER.md)** - Contributing and development setup
- ⚡ **[Performance Optimization](docs/performance_optimization.md)** - Large dataset handling
- 🧪 **[Testing Guide](tests/README.md)** - Test suite documentation
- 📋 **[Changelog](CHANGELOG.md)** - Release history and changes
- 📚 **[API Documentation](https://docs.rs/jmix-rs/latest/jmix_rs/)** - Rust library docs

## License

This project is licensed under the Apache 2.0 License.
