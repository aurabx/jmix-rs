//! JMIX Sender Assertion Example
//!
//! This example demonstrates:
//! - Creating sender assertions for identity verification
//! - Verifying sender assertions against manifest data
//! - Field-based signature generation and verification
//! - End-to-end assertion workflow for non-repudiation

use jmix_rs::{
    assertion::{AssertionManager, VerificationResult},
    builder::JmixBuilder,
    config::Config,
    error::JmixResult,
};
use std::fs;
use tempfile::TempDir;

fn main() -> JmixResult<()> {
    println!("🔏 JMIX Sender Assertion Example");
    println!("=================================");

    // Create temporary directory for this example
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let temp_path = temp_dir.path();

    println!("\n1. 📁 Setting up directories...");
    let keys_dir = temp_path.join("assertion_keys");
    let envelope_dir = temp_path.join("envelopes");
    fs::create_dir_all(&keys_dir)?;
    fs::create_dir_all(&envelope_dir)?;

    // Step 1: Create assertion manager with generated keys
    println!("\n2. 🔑 Creating assertion manager...");
    let assertion_manager = AssertionManager::with_generated_key()?;
    let public_key_info = assertion_manager.public_key_info()?;
    
    println!("   ✓ Generated Ed25519 keypair for assertions");
    println!("   ✓ Algorithm: {}", public_key_info.alg);
    println!("   ✓ Fingerprint: {}", public_key_info.fingerprint);
    println!("   ✓ Public key: {}...", &public_key_info.public_key[..20]);

    // Step 2: Load sample config
    println!("\n3. 📄 Loading configuration...");
    let config_content = r#"{
        "version": "1.0",
        "sender": {
            "name": "Dr. Alice Smith",
            "id": "org:hospital.radiology.alice",
            "contact": "alice.smith@hospital.example.org"
        },
        "requester": {
            "name": "Dr. Bob Johnson", 
            "id": "org:university.medical.bob",
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
        },
        "security": {
            "classification": "confidential"
        }
    }"#;
    
    let config: Config = serde_json::from_str(&config_content)?;
    println!("   ✓ Loaded configuration for sender: {}", config.sender.name);

    // Step 3: Create JMIX builder with assertions enabled
    println!("\n4. 🏗️  Creating JMIX builder with assertions...");
    let builder = JmixBuilder::with_assertions()?;
    println!("   ✓ Builder configured with assertion generation");

    // Step 4: Create some sample DICOM files
    println!("\n5. 📊 Creating sample data...");
    let dicom_dir = temp_path.join("sample_dicom");
    fs::create_dir_all(&dicom_dir)?;
    
    // Create fake DICOM files
    let sample_files = vec![
        ("patient_scan_1.dcm", b"DICM\x00\x08\x00\x05\x00CS\x00\x0AXRAY    " as &[u8]),
        ("patient_scan_2.dcm", b"DICM\x00\x08\x00\x05\x00CS\x00\x0AMR      "),
    ];
    
    for (filename, content) in &sample_files {
        let file_path = dicom_dir.join(filename);
        fs::write(&file_path, content)?;
    }
    
    println!("   ✓ Created {} sample DICOM files", sample_files.len());

    // Step 5: Build envelope with assertions
    println!("\n6. 📦 Building JMIX envelope with assertions...");
    let (envelope, dicom_files) = builder.build_from_dicom(&dicom_dir, &config)?;
    
    println!("   ✓ Created envelope with ID: {}", envelope.manifest.id);
    println!("   ✓ Processed {} DICOM files", dicom_files.len());

    // Check if sender has assertion
    if let Some(sender_assertion) = &envelope.manifest.sender.assertion {
        println!("   ✓ Generated sender assertion with {} signed fields", sender_assertion.signed_fields.len());
        println!("   ✓ Sender assertion algorithm: {}", sender_assertion.signing_key.alg);
    } else {
        println!("   ⚠️  No sender assertion generated");
    }

    // Check if requester has assertion
    if let Some(requester) = &envelope.manifest.requester {
        if let Some(requester_assertion) = &requester.assertion {
            println!("   ✓ Generated requester assertion with {} signed fields", requester_assertion.signed_fields.len());
        } else {
            println!("   ✓ No requester assertion (optional)");
        }
    }

    // Step 6: Save envelope
    println!("\n7. 💾 Saving envelope with assertions...");
    let saved_files = builder.save_to_files(&envelope, &dicom_files, &envelope_dir)?;
    
    println!("   ✓ Saved envelope to: {}", envelope_dir.display());
    println!("   ✓ Generated {} files", saved_files.len());

    // Step 7: Demonstrate assertion verification
    println!("\n8. 🔍 Verifying sender assertion...");
    
    if let Some(sender_assertion) = &envelope.manifest.sender.assertion {
        // Verify the sender assertion
        let verification_result = AssertionManager::verify_assertion(
            sender_assertion,
            &envelope.manifest.sender,
            &envelope.manifest,
        )?;

        match verification_result {
            VerificationResult::Valid { fingerprint, signed_fields } => {
                println!("   ✅ Sender assertion is VALID");
                println!("   ✓ Fingerprint matches: {}", fingerprint);
                println!("   ✓ Verified {} signed fields:", signed_fields.len());
                
                for (field, value) in &signed_fields {
                    println!("     • {}: {}", field, value);
                }
            },
            VerificationResult::Invalid { reason } => {
                println!("   ❌ Sender assertion is INVALID: {}", reason);
            },
            VerificationResult::Expired { expires_at } => {
                println!("   ⏰ Sender assertion is EXPIRED: {}", expires_at);
            },
        }
    } else {
        println!("   ⚠️  No sender assertion to verify");
    }

    // Step 8: Demonstrate manual assertion creation
    println!("\n9. 🛠️  Manual assertion creation and verification...");
    
    // Create a manual assertion manager
    let manual_manager = AssertionManager::with_generated_key()?;
    
    // Create a custom assertion with specific fields
    let custom_fields = vec![
        "sender.id".to_string(),
        "sender.name".to_string(),
        "manifest.id".to_string(),
        "timestamp".to_string(),
        "security.payload_hash".to_string(),
    ];
    
    let custom_assertion_result = manual_manager.create_custom_assertion(
        &envelope.manifest.sender,
        &envelope.manifest,
        custom_fields,
        Some("2025-12-31T23:59:59Z".to_string()), // Set expiration
        Some("manual://test-key-reference".to_string()), // Key reference
        None, // No directory attestation
    )?;
    
    println!("   ✓ Created custom assertion");
    println!("   ✓ Signed fields: {:?}", custom_assertion_result.assertion.signed_fields);
    println!("   ✓ Key reference: {:?}", custom_assertion_result.assertion.key_reference);
    println!("   ✓ Expires at: {:?}", custom_assertion_result.assertion.expires_at);
    
    // Verify the custom assertion
    let custom_verification = AssertionManager::verify_assertion(
        &custom_assertion_result.assertion,
        &envelope.manifest.sender,
        &envelope.manifest,
    )?;
    
    match custom_verification {
        VerificationResult::Valid { fingerprint: _, signed_fields } => {
            println!("   ✅ Custom assertion verified successfully");
            println!("   ✓ Signed {} fields including payload hash", signed_fields.len());
        },
        VerificationResult::Invalid { reason } => {
            println!("   ❌ Custom assertion failed: {}", reason);
        },
        VerificationResult::Expired { expires_at: _ } => {
            println!("   ⏰ Custom assertion expired");
        },
    }

    // Step 9: Demonstrate tampering detection
    println!("\n10. 🕵️  Demonstrating tampering detection...");
    
    if let Some(sender_assertion) = &envelope.manifest.sender.assertion {
        // Create a modified manifest (simulating tampering)
        let mut tampered_manifest = envelope.manifest.clone();
        tampered_manifest.sender.name = Some("Dr. Evil Hacker".to_string()); // Change sender name
        
        let tampered_verification = AssertionManager::verify_assertion(
            sender_assertion,
            &tampered_manifest.sender,
            &tampered_manifest,
        )?;
        
        match tampered_verification {
            VerificationResult::Valid { .. } => {
                println!("   ❌ Tampering NOT detected (this shouldn't happen!)");
            },
            VerificationResult::Invalid { reason } => {
                println!("   ✅ Tampering DETECTED: {}", reason);
                println!("   ✓ Assertion verification prevents identity spoofing");
            },
            VerificationResult::Expired { .. } => {
                println!("   ⏰ Assertion expired (not tampering)");
            },
        }
    }

    // Step 10: Summary
    println!("\n✅ JMIX Sender Assertion Example Complete!");
    println!("==========================================");
    println!("✓ Generated cryptographic assertions for sender identity");
    println!("✓ Demonstrated field-based signature verification");
    println!("✓ Showed tampering detection capabilities");
    println!("✓ Created both automatic and manual assertions");
    println!("✓ Verified non-repudiation properties");
    
    println!("\n📁 Files created in: {}", temp_path.display());
    println!("   • JMIX envelope: {}", envelope_dir.display());
    
    println!("\n🔐 Security Features Demonstrated:");
    println!("   • Ed25519 digital signatures for assertions");
    println!("   • Field-based signature generation");
    println!("   • Identity verification and non-repudiation");
    println!("   • Tampering detection through signature verification");
    println!("   • Optional expiration and key references");
    
    println!("\n💡 Use Cases:");
    println!("   • Prove who sent a medical data package");
    println!("   • Verify sender identity in peer-to-peer exchange");
    println!("   • Prevent identity spoofing and tampering");
    println!("   • Enable audit trails and forensic verification");
    println!("   • Support compliance with medical data regulations");
    
    Ok(())
}