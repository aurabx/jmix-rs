# Changelog

All notable changes to this project will be documented in this file.

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

