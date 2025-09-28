//! JMIX Envelope Encryption Example
//!
//! This example demonstrates:
//! - Generating encryption keypairs (Curve25519)
//! - Creating encrypted JMIX envelopes with AES-256-GCM
//! - Decrypting and extracting encrypted payload
//! - End-to-end encrypted DICOM data exchange

use jmix_rs::{
    builder::JmixBuilder,
    config::Config,
    encryption::{DecryptionManager, KeyPair},
    error::JmixResult,
};
use std::fs;
use tempfile::TempDir;

fn main() -> JmixResult<()> {
    println!("🔒 JMIX Envelope Encryption Example");
    println!("===================================");

    // Create temporary directory for this example
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let temp_path = temp_dir.path();

    println!("\n1. 📁 Setting up directories...");
    let keys_dir = temp_path.join("keys");
    let envelope_dir = temp_path.join("envelopes");
    fs::create_dir_all(&keys_dir)?;
    fs::create_dir_all(&envelope_dir)?;

    // Step 1: Generate recipient's encryption keypair
    println!("\n2. 🔑 Generating recipient encryption keypair...");
    let recipient_keypair = KeyPair::generate();

    // Save recipient's keys
    let recipient_secret_path = keys_dir.join("recipient_secret.key");
    let recipient_public_path = keys_dir.join("recipient_public.key");
    
    recipient_keypair.save_to_files(&recipient_secret_path, &recipient_public_path)?;
    println!("   ✓ Saved recipient secret key: {}", recipient_secret_path.display());
    println!("   ✓ Saved recipient public key: {}", recipient_public_path.display());
    println!("   ✓ Recipient public key (base64): {}", recipient_keypair.public_key_base64());

    // Step 2: Load sample config
    println!("\n3. 📄 Loading configuration...");
    let config_path = "samples/config.json";
    let config_content = fs::read_to_string(config_path)
        .unwrap_or_else(|_| {
            println!("   ⚠️  Sample config not found, using default");
            r#"{
                "version": "1.0",
                "sender": {
                    "name": "Dr. Alice Smith",
                    "id": "org:example.hospital.radiology",
                    "contact": "alice.smith@hospital.example.org"
                },
                "requester": {
                    "name": "Dr. Bob Johnson", 
                    "id": "org:university.medical.research",
                    "contact": "bob.johnson@university.example.org"
                },
                "receivers": [
                    {
                        "name": "Research Database",
                        "id": "org:research.data.center",
                        "contact": "intake@research.example.org"
                    }
                ],
                "patient": {
                    "id": "PAT-12345",
                    "name": "Test Patient",
                    "dob": "1985-03-15",
                    "sex": "F"
                }
            }"#.to_string()
        });
    
    let config: Config = serde_json::from_str(&config_content)?;
    println!("   ✓ Loaded configuration for sender: {}", config.sender.name);

    // Step 3: Create encrypted JMIX builder
    println!("\n4. 🏗️  Creating JMIX builder with encryption...");
    let recipient_public_key_b64 = recipient_keypair.public_key_base64();
    let builder = JmixBuilder::with_encryption_and_signing(&recipient_public_key_b64)?;
    println!("   ✓ Builder configured with encryption and signing");
    println!("   ✓ Using AES-256-GCM with ECDH key agreement");

    // Step 4: Create some sample "DICOM" files for demonstration
    println!("\n5. 📊 Creating sample data...");
    let dicom_dir = temp_path.join("sample_dicom");
    fs::create_dir_all(&dicom_dir)?;
    
    // Create fake DICOM files (in real usage, these would be actual DICOM files)
    let sample_files = vec![
        ("image_001.dcm", b"DICM\x00\x08\x00\x05\x00CS\x00\x0AXRAY    " as &[u8]),
        ("image_002.dcm", b"DICM\x00\x08\x00\x05\x00CS\x00\x0AMR      "),
        ("series_info.dcm", b"DICM\x00\x08\x00\x05\x00CS\x00\x0ACT      "),
    ];
    
    for (filename, content) in &sample_files {
        let file_path = dicom_dir.join(filename);
        fs::write(&file_path, content)?;
    }
    
    println!("   ✓ Created {} sample DICOM files", sample_files.len());

    // Step 5: Build encrypted envelope from DICOM data
    println!("\n6. 📦 Building encrypted JMIX envelope...");
    let (envelope, dicom_files) = builder.build_from_dicom(&dicom_dir, &config)?;
    
    println!("   ✓ Created envelope with ID: {}", envelope.manifest.id);
    println!("   ✓ Processed {} DICOM files", dicom_files.len());

    // Step 6: Save encrypted envelope
    println!("\n7. 💾 Saving encrypted envelope...");
    let saved_files = builder.save_to_files(&envelope, &dicom_files, &envelope_dir)?;
    
    println!("   ✓ Saved encrypted envelope to: {}", envelope_dir.display());
    println!("   ✓ Generated {} files:", saved_files.len());
    
    for file_path in &saved_files {
        let file_name = file_path.file_name().unwrap().to_string_lossy();
        let file_size = fs::metadata(file_path).map(|m| m.len()).unwrap_or(0);
        println!("     • {} ({} bytes)", file_name, file_size);
    }

    // Step 7: Demonstrate encryption info
    let envelope_path = envelope_dir.join(format!("{}.jmix", envelope.manifest.id));
    let manifest_path = envelope_path.join("manifest.json");
    let manifest_content = fs::read_to_string(&manifest_path)?;
    let manifest: serde_json::Value = serde_json::from_str(&manifest_content)?;
    
    let encryption = manifest.get("security").and_then(|s| s.get("encryption"));
    
    if let Some(encryption) = &encryption {
        println!("\n8. 🔐 Encryption details:");
        println!("   ✓ Algorithm: {}", encryption["algorithm"].as_str().unwrap_or("unknown"));
        println!("   ✓ Ephemeral public key: {}...", 
                &encryption["ephemeral_public_key"].as_str().unwrap_or("")[..16]);
        println!("   ✓ IV length: {} chars", 
                encryption["iv"].as_str().unwrap_or("").len());
        println!("   ✓ Auth tag length: {} chars", 
                encryption["auth_tag"].as_str().unwrap_or("").len());
    }

    // Step 8: Demonstrate decryption
    println!("\n9. 🔓 Demonstrating decryption...");
    
    // Load encrypted payload
    let encrypted_payload_path = envelope_path.join("payload.enc");
    let encrypted_data = fs::read(&encrypted_payload_path)?;
    println!("   ✓ Loaded encrypted payload ({} bytes)", encrypted_data.len());
    
    // Create decryption manager
    let decryption_manager = DecryptionManager::from_secret_key_file(&recipient_secret_path)
        .map_err(|e| jmix_rs::error::JmixError::Other(format!("Failed to create decryption manager: {}", e)))?;
    
    // Parse encryption info from manifest
    let encryption_info: jmix_rs::types::EncryptionInfo = 
        if let Some(enc) = &encryption {
            serde_json::from_value((*enc).clone())
                .map_err(|e| jmix_rs::error::JmixError::Json(e))?
        } else {
            return Err(jmix_rs::error::JmixError::Other("No encryption info found in manifest".to_string()));
        };
    
    // Decrypt the payload
    let decrypted_data = decryption_manager.decrypt(&encrypted_data, &encryption_info)
        .map_err(|e| jmix_rs::error::JmixError::Other(format!("Decryption failed: {}", e)))?;
    
    println!("   ✓ Successfully decrypted payload ({} bytes)", decrypted_data.len());
    
    // Save decrypted TAR for inspection
    let decrypted_tar_path = temp_path.join("decrypted_payload.tar");
    fs::write(&decrypted_tar_path, &decrypted_data)?;
    println!("   ✓ Saved decrypted TAR to: {}", decrypted_tar_path.display());

    // Step 9: Extract and verify decrypted content
    println!("\n10. 📂 Extracting decrypted content...");
    let extract_dir = temp_path.join("decrypted");
    fs::create_dir_all(&extract_dir)?;
    
    // Extract TAR archive
    let tar_file = fs::File::open(&decrypted_tar_path)?;
    let mut archive = tar::Archive::new(tar_file);
    archive.unpack(&extract_dir)?;
    
    println!("   ✓ Extracted decrypted payload to: {}", extract_dir.display());
    
    // List extracted files
    let mut extracted_files = Vec::new();
    for entry in fs::read_dir(&extract_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            extracted_files.push(path);
        } else if path.is_dir() {
            for subentry in fs::read_dir(&path)? {
                let subentry = subentry?;
                let subpath = subentry.path();
                if subpath.is_file() {
                    extracted_files.push(subpath);
                }
            }
        }
    }
    
    println!("   ✓ Extracted files:");
    for file_path in &extracted_files {
        let rel_path = file_path.strip_prefix(&extract_dir).unwrap_or(file_path);
        let file_size = fs::metadata(file_path).map(|m| m.len()).unwrap_or(0);
        println!("     • {} ({} bytes)", rel_path.display(), file_size);
    }

    // Verify metadata was preserved
    let metadata_path = extract_dir.join("metadata.json");
    if metadata_path.exists() {
        let metadata_content = fs::read_to_string(&metadata_path)?;
        let metadata: serde_json::Value = serde_json::from_str(&metadata_content)?;
        if let Some(patient) = metadata.get("patient") {
            println!("   ✓ Verified patient data: ID = {}", 
                    patient.get("id").and_then(|v| v.as_str()).unwrap_or("unknown"));
        }
    }

    // Step 10: Summary
    println!("\n✅ JMIX Encryption Example Complete!");
    println!("====================================");
    println!("✓ Generated Curve25519 keypair for recipient");
    println!("✓ Created encrypted JMIX envelope with AES-256-GCM");
    println!("✓ Used ephemeral keys for forward secrecy"); 
    println!("✓ Successfully encrypted {} DICOM files", dicom_files.len());
    println!("✓ Demonstrated end-to-end decryption and extraction");
    println!("✓ Verified data integrity through authenticated encryption");
    
    println!("\n📁 Files created in: {}", temp_path.display());
    println!("   • Encryption keys: {}", keys_dir.display());
    println!("   • Encrypted envelope: {}", envelope_path.display());
    println!("   • Decrypted content: {}", extract_dir.display());
    
    println!("\n🔐 Security Features Demonstrated:");
    println!("   • AES-256-GCM authenticated encryption");
    println!("   • ECDH key agreement with Curve25519");
    println!("   • HKDF key derivation with SHA-256");
    println!("   • Forward secrecy via ephemeral keys");
    println!("   • Ed25519 digital signatures (manifest.jws)");
    
    Ok(())
}