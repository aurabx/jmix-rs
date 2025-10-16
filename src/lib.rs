//! JMIX-RS: Rust library for JMIX (JSON Medical Interchange) format
//!
//! Secure medical data exchange with cryptographic features including:
//! - AES-256-GCM encryption with ECDH key exchange
//! - Ed25519 digital signatures and JWS support
//! - JSON Schema validation
//! - DICOM metadata extraction
//! - Envelope creation and processing
//! - Performance optimization through skip flags
//!
//! ## Performance Optimization
//!
//! The library supports two performance flags for large datasets:
//!
//! - `skip_hashing`: Skips SHA256 hash computation for files and payload.
//!   When enabled, hash fields are set to `None` and payload hash is set to
//!   `"sha256:skipped"` placeholder.
//!
//! - `skip_listing`: Skips adding DICOM files to the files.json manifest.
//!   Files are still copied to the payload but not indexed. Only metadata.json
//!   and report files (if present) are listed.
//!
//! These flags can significantly improve performance when processing large
//! DICOM datasets where hash verification or file indexing is not required.

pub mod assertion;
pub mod builder;
pub mod config;
pub mod dicom;
pub mod encryption;
pub mod error;
pub mod jws;
pub mod package_validation;
pub mod types;
pub mod validation;

#[cfg(test)]
mod tests;

pub use package_validation::{validate_package, ValidationOptions, ValidationReport};

// Re-export commonly used types
pub use config::Config;
pub use error::{JmixError, JmixResult};
pub use types::{Audit, Envelope, Manifest, Metadata};
