use jmix_rs::{builder::JmixBuilder, config::Config};
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🏥 JMIX-RS: Building medical data envelope from DICOM files");
    println!("==========================================================");

    // Load configuration from sample file
    println!("\n📋 Loading configuration...");
    let config_content = fs::read_to_string("samples/sample_config.json")
        .expect("Failed to read sample config - make sure samples/sample_config.json exists");
    
    let config: Config = serde_json::from_str(&config_content)
        .expect("Failed to parse configuration JSON");
    
    println!("   ✓ Configuration loaded");
    println!("   - Sender: {} ({})", config.sender.name, config.sender.id);
    println!("   - Patient: {:?} ({})", 
             config.patient.name, 
             config.patient.id.as_deref().unwrap_or("Unknown"));

    // Create JMIX builder
    println!("\n🔧 Initializing JMIX builder...");
    let builder = JmixBuilder::new();
    println!("   ✓ Builder created");

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
    println!("   - Timestamp: {}", envelope.manifest.timestamp);
    println!("   - Patient: {:?}", envelope.metadata.patient.name);
    
    if let Some(studies) = &envelope.metadata.studies {
        if let Some(series) = &studies.series {
            println!("   - Series count: {}", series.len());
            for (i, s) in series.iter().enumerate() {
                println!("     • Series {}: {} ({:?} instances)", 
                         i + 1, s.modality, s.instance_count);
            }
        }
    }

    // Save to output directory
    println!("\n💾 Creating JMIX envelope structure...");
    let output_dir = "./tmp";
    
    let saved_files = builder.save_to_files(&envelope, &dicom_files, output_dir)
        .expect("Failed to save JMIX envelope");
    
    println!("   ✓ JMIX envelope created successfully");
    println!("   📁 Envelope directory: {}/{}.jmix", output_dir, envelope.manifest.id);
    println!("   📄 Generated files:");
    
    for (i, file_path) in saved_files.iter().enumerate() {
        let file_name = file_path.file_name().unwrap().to_string_lossy();
        let file_size = fs::metadata(file_path)
            .map(|m| format!("{} bytes", m.len()))
            .unwrap_or_else(|_| "unknown size".to_string());
        
        println!("     {}. {} ({})", i + 1, file_name, file_size);
    }

    // Show summary
    println!("\n📋 JMIX Envelope Summary");
    println!("========================");
    println!("Version: {}", envelope.manifest.version);
    println!("ID: {}", envelope.manifest.id);
    println!("Created: {}", envelope.manifest.timestamp);
    println!("Sender: {}", envelope.manifest.sender.name.as_deref().unwrap_or("Unknown"));
    println!("Patient ID: {}", envelope.metadata.patient.id);
    
    if let Some(study_desc) = envelope.metadata.studies.as_ref()
        .and_then(|s| s.study_description.as_ref()) {
        println!("Study: {}", study_desc);
    }
    
    println!("Audit events: {}", envelope.audit.audit.len());
    
    println!("\n🎉 JMIX envelope creation completed successfully!");
    println!("   Envelope structure created at: ./tmp/{}.jmix/", envelope.manifest.id);
    println!("   📁 Structure follows JMIX specification:");
    println!("     ├── manifest.json    # Envelope metadata (no PII)");
    println!("     ├── audit.json       # Audit trail");
    println!("     ├── payload/");
    println!("     │   ├── metadata.json # Patient and study data");
    println!("     │   ├── files.json   # File manifest");
    println!("     │   ├── dicom/       # DICOM files (empty)");
    println!("     │   └── files/       # Additional files (empty)");
    println!("     └── README.md        # Documentation");

    Ok(())
}