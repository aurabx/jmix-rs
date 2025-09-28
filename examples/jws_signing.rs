use base64::Engine;
use jmix_rs::{builder::JmixBuilder, config::Config, jws::JwsManager};
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 JMIX-RS: JWS Signing and Verification Demo");
    println!("===========================================");

    // Load configuration from sample file
    println!("\n📋 Loading configuration...");
    let config_content = fs::read_to_string("samples/sample_config.json")
        .expect("Failed to read sample config - make sure samples/sample_config.json exists");
    
    let config: Config = serde_json::from_str(&config_content)
        .expect("Failed to parse configuration JSON");
    
    println!("   ✓ Configuration loaded");

    // Generate keypair for signing
    println!("\n🔑 Generating Ed25519 keypair for signing...");
    let private_key_path = "./tmp/signing_key.pem";
    let public_key_path = "./tmp/verify_key.pem";
    
    let signing_manager = JwsManager::generate_keypair(&private_key_path, &public_key_path)?;
    println!("   ✓ Keypair generated and saved");

    // Create JMIX builder with signing enabled
    println!("\n🏗️ Creating JMIX builder with signing...");
    let builder = JmixBuilder::with_signing_key(&private_key_path)?;
    println!("   ✓ Builder created with signing key loaded");

    // Process DICOM files and build envelope
    println!("\n📊 Processing DICOM files...");
    let dicom_path = "samples/study_1";
    
    if !std::path::Path::new(dicom_path).exists() {
        eprintln!("❌ Error: DICOM directory not found: {}", dicom_path);
        eprintln!("   Make sure samples/study_1/ contains DICOM files");
        std::process::exit(1);
    }

    let (envelope, dicom_files) = builder.build_from_dicom(dicom_path, &config)
        .expect("Failed to build JMIX envelope from DICOM files");
    
    println!("   ✓ DICOM files processed successfully");
    println!("   - Envelope ID: {}", envelope.manifest.id);

    // Save envelope with digital signature
    println!("\n💾 Creating signed JMIX envelope...");
    let output_dir = "./tmp";
    
    let saved_files = builder.save_to_files(&envelope, &dicom_files, output_dir)
        .expect("Failed to save signed JMIX envelope");
    
    println!("   ✓ Signed JMIX envelope created successfully");
    
    let envelope_dir = format!("{}/{}.jmix", output_dir, envelope.manifest.id);
    let manifest_path = format!("{}/manifest.json", envelope_dir);
    let jws_path = format!("{}/manifest.jws", envelope_dir);
    
    // Verify the created files
    println!("   📁 Envelope directory: {}", envelope_dir);
    println!("   📄 Files created:");
    
    let mut jws_found = false;
    for (i, file_path) in saved_files.iter().enumerate() {
        let file_name = file_path.file_name().unwrap().to_string_lossy();
        let file_size = fs::metadata(file_path)
            .map(|m| format!("{} bytes", m.len()))
            .unwrap_or_else(|_| "unknown size".to_string());
        
        if file_name == "manifest.jws" {
            jws_found = true;
        }
        
        if i < 10 {  // Show first 10 files
            println!("     {}. {} ({})", i + 1, file_name, file_size);
        }
    }
    
    if saved_files.len() > 10 {
        println!("     ... and {} more files", saved_files.len() - 10);
    }

    if !jws_found {
        eprintln!("❌ Error: manifest.jws not created!");
        return Ok(());
    }

    // Verify the JWS signature
    println!("\n🔍 Verifying JWS signature...");
    
    // Load the public key for verification
    let public_key = JwsManager::load_public_key(&public_key_path)?;
    
    // Read the manifest.json and manifest.jws
    let manifest_json = fs::read_to_string(&manifest_path)?;
    let jws_content = fs::read_to_string(&jws_path)?;
    
    println!("   📄 Manifest JSON: {} bytes", manifest_json.len());
    println!("   🔏 JWS signature: {} bytes", jws_content.len());
    
    // Verify the signature
    match JwsManager::verify_jws(&jws_content, &public_key) {
        Ok(verified_payload) => {
            println!("   ✅ JWS signature verification: SUCCESS");
            
            // Check if verified payload matches original
            if verified_payload == manifest_json {
                println!("   ✅ Payload integrity: VERIFIED");
                println!("   🎯 The manifest.json content is authentic and unmodified");
            } else {
                println!("   ❌ Payload integrity: FAILED");
                println!("   ⚠️  The verified payload doesn't match the manifest file");
            }
        }
        Err(e) => {
            println!("   ❌ JWS signature verification: FAILED");
            println!("   Error: {}", e);
            return Err(e.into());
        }
    }

    // Show JWS structure
    println!("\n📋 JWS Structure Analysis");
    println!("========================");
    let jws_parts: Vec<&str> = jws_content.trim().split('.').collect();
    if jws_parts.len() == 3 {
        println!("Header (base64url): {} characters", jws_parts[0].len());
        println!("Payload (base64url): {} characters", jws_parts[1].len());  
        println!("Signature (base64url): {} characters", jws_parts[2].len());
        
        // Decode and show header
        if let Ok(header_bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(jws_parts[0]) {
            if let Ok(header_str) = String::from_utf8(header_bytes) {
                println!("Header JSON: {}", header_str);
            }
        }
    }

    // Show key information
    println!("\n🔑 Cryptographic Details");
    println!("=======================");
    println!("Algorithm: EdDSA (Ed25519)");
    println!("Private key: {} (32 bytes)", private_key_path);
    println!("Public key: {} (32 bytes)", public_key_path);
    println!("Signature length: 64 bytes");
    println!("Security level: ~128 bits");

    println!("\n🎉 JWS signing and verification completed successfully!");
    println!("   The JMIX envelope is now digitally signed and can be verified by anyone");
    println!("   with the corresponding public key.");
    println!("\n💡 Key Management Tips:");
    println!("   • Keep private keys secure and never share them");
    println!("   • Public keys can be shared freely for signature verification"); 
    println!("   • Consider using hardware security modules (HSMs) for production keys");

    Ok(())
}