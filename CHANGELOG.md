# Changelog

All notable changes to this project will be documented in this file.

## [0.3.3] - 2026-10-31

Highlights
- Security: bump the `zip` crate from 6.x to the patched 9.x line for GHSA-m665-v7pm-7grj / CVE-2026-115905

Changed
- Dependencies: `zip` is now `9.0.5` (Cargo range `>=9.0.5, <10`), with default features disabled and `deflate` kept for write-only JMIX ZIP creation
- This crate only writes ZIP archives (`ZipWriter` / `SimpleFileOptions`); it does not extract untrusted archives

Notes
- First fixed `zip` version per the GHSA/OSV advisory is **9.0.5** (affected: `<= 9.0.4`). 9.1.3 is a later 9.x release, not the first patch.
- Opt-in read-side hardening `ExtractOptions::enforce_header_consistency(true)` (added in zip 9.1.0) is not used here because jmix-rs does not extract ZIPs. Downstream extractors should enable it when they extract untrusted archives.
- No public API changes. `zip` types are not re-exported.
- `zip` 9.x requires Rust 1.88+.
- aurabx/harmony and aurabx/prime still need a jmix-rs 0.3.3+ release (and their own `zip` pins updated) before the vulnerable transitive 6.x copy can be dropped.

## [0.3.2] - 2025-10-18

Highlights
- RNG migration: replace rand_core/OsRng with getrandom for all randomness
- Zip upgrade: bump zip crate to 6.0 and migrate to write::SimpleFileOptions

Changed
- Encryption: generate ephemeral X25519 keys using getrandom + x25519(secret, ...)
  - Preserves AES-256-GCM format (ephemeral public key, IV, auth tag are base64 in manifest)
- JWS: Ed25519 key generation uses getrandom
- Dependencies: dicom-object and dicom-dictionary-std updated to 0.9
- The incorrectly named binary "runbeam" has been renamed to "jmix"

Notes
- No JMIX manifest schema changes; existing packages remain compatible
- No public API changes expected; if downstreams referenced rand_core types, migrate to internal RNG or pass raw keys

## [0.2.0] - 2025-10-04

Highlights
- Deterministic payload hashing for both unencrypted and encrypted JMIX packages
- Package-level validator API and a CLI to validate packages
- Receiver assertions support in the builder
- Decrypt/extract CLI for encrypted payloads
- JMIX_SCHEMA_DIR environment variable support for schema discovery

Added
- Deterministic payload hashing
  - Unencrypted packages: payload hash is computed over `payload/` deterministically
    - Recursively list files under `payload/`
    - Sort by relative path (Unicode codepoint order)
    - For each file: update the SHA-256 hasher with `relative/path` (UTF-8), then a single newline byte (`\n`), then the file bytes
    - Emit as `sha256:<hex>` and store in `manifest.security.payload_hash`
  - Encrypted packages: compute SHA-256 over plaintext `payload.tar` BEFORE encryption, then store in `manifest.security.payload_hash`.
    - Keeps the hash stable across encryptions (independent of IVs/ephemeral keys)

- Package validation API (src/package_validation.rs)
  - validate_package(dir, &ValidationOptions) -> ValidationReport
  - ValidationOptions: { validate_schema, schema_dir, verify_assertions, recipient_secret_key_path }
  - ValidationReport: { schema_ok, payload_hash_ok, assertions_ok, encryption_ok, errors }
  - Behavior:
    - Unencrypted: recomputes directory-based payload hash and compares
    - Encrypted: decrypts `payload.enc` when a secret key is supplied; hashes plaintext TAR and compares
    - Optional schema validation (manifest, audit, metadata, files)
    - Optional sender/requester/receiver assertion verification

- CLI: runbeam validate
  - Examples:
    - `cargo run --bin runbeam -- validate ./tmp/<id>.jmix`
    - `cargo run --bin runbeam -- validate ./tmp/<id>.jmix --validate-schema`
    - `cargo run --bin runbeam -- validate ./tmp/<id>.jmix --key ./path/to/recipient_secret.key`
    - `cargo run --bin runbeam -- validate ./tmp/<id>.jmix --verify-assertions`
    - `cargo run --bin runbeam -- validate ./tmp/<id>.jmix --json`

- CLI: runbeam decrypt
  - Decrypt and extract `payload.enc` from a JMIX package directory
  - Example:
    - `cargo run --bin runbeam -- decrypt ./tmp/<id>.jmix --key ./path/to/recipient_secret.key --out ./tmp/decrypted`

- Receiver assertions
  - AssertionManager::create_receiver_assertion(entity, manifest, receiver_index, ...)
  - Builder automatically generates receiver assertions when assertions are enabled

- Schema discovery via environment variable
  - JMIX_SCHEMA_DIR is now honored by ValidationConfig (fallback order: CLI flag > JMIX_SCHEMA_DIR > ../jmix/schemas)

Changed
- save_to_files now writes manifest.json after payload hashing so `manifest.security.payload_hash` is correct
- When signing is enabled, manifest.jws is generated from the updated manifest

Testing
- Added package validation tests
  - Unencrypted roundtrip: payload_hash_ok = true
  - Unencrypted tamper: modifying `payload/metadata.json` causes payload_hash_ok = false
  - Encrypted roundtrip [ignored by default]: decryption + hash verification succeed
  - Encrypted wrong key [ignored by default]: decryption fails, payload_hash_ok = false
- Added receiver assertion tests
- Existing encryption/JWS/DICOM tests retained

Documentation
- README updated with:
  - CLI usage for `runbeam validate` and `runbeam decrypt`
  - Deterministic payload hashing details
  - `--verify-assertions` validation example

Upgrade notes
- Pre-0.4.0 envelopes may have `manifest.security.payload_hash` unset or set to a placeholder.
  - The new validator will report a payload hash mismatch for such envelopes.
  - To adopt the new hashing model, rebuild/export envelopes with this version so `payload_hash` is populated deterministically.
- No changes are required for consumers of the unencrypted directory structure or encrypted `payload.enc` layout.

