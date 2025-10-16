use jmix_rs::builder::JmixBuilder;
use jmix_rs::config::{Config, ContactInfo, Entity};
use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("JMIX Performance Optimization Example");
    println!("=====================================\n");

    // Create a test configuration
    let config = Config {
        version: Some("1.0".to_string()),
        sender: Entity {
            name: "Performance Test Sender".to_string(),
            id: "test:sender".to_string(),
            contact: ContactInfo::Email("sender@test.com".to_string()),
            assertion: None,
        },
        requester: Entity {
            name: "Performance Test Requester".to_string(),
            id: "test:requester".to_string(),
            contact: ContactInfo::Email("requester@test.com".to_string()),
            assertion: None,
        },
        receivers: vec![Entity {
            name: "Performance Test Receiver".to_string(),
            id: "test:receiver".to_string(),
            contact: ContactInfo::Email("receiver@test.com".to_string()),
            assertion: None,
        }],
        ..Default::default()
    };

    let dicom_path = "./samples/dicom"; // Adjust path as needed
    let output_dir = "./tmp/performance_test";

    // Create output directory
    std::fs::create_dir_all(output_dir)?;

    let builder = JmixBuilder::new();

    // Test 1: Default behavior (with hashing and listing)
    println!("Test 1: Default behavior (hashing + listing)");
    let start = Instant::now();
    match builder.build_from_dicom(&dicom_path, &config) {
        Ok((envelope, files)) => {
            let duration = start.elapsed();
            println!("  ✓ Built envelope in {:?}", duration);
            println!("  ✓ Found {} DICOM files", files.len());
            println!("  ✓ Envelope ID: {}\n", envelope.manifest.id);

            // Save the envelope
            let save_start = Instant::now();
            match builder.save_to_files(&envelope, &files, &output_dir) {
                Ok(_) => println!("  ✓ Saved envelope in {:?}\n", save_start.elapsed()),
                Err(e) => println!("  ✗ Save failed: {}\n", e),
            }
        }
        Err(e) => println!("  ✗ Build failed: {}\n", e),
    }

    // Test 2: Skip hashing only
    println!("Test 2: Skip hashing only");
    let start = Instant::now();
    match builder.build_from_dicom_with_options(&dicom_path, &config, true, false) {
        Ok((envelope, files)) => {
            let duration = start.elapsed();
            println!("  ✓ Built envelope in {:?}", duration);
            println!("  ✓ Found {} DICOM files", files.len());
            println!("  ✓ Envelope ID: {}\n", envelope.manifest.id);

            // Save with skip hashing
            let save_start = Instant::now();
            match builder.save_to_files_with_options(&envelope, &files, &output_dir, true, false) {
                Ok(_) => println!("  ✓ Saved envelope in {:?}\n", save_start.elapsed()),
                Err(e) => println!("  ✗ Save failed: {}\n", e),
            }
        }
        Err(e) => println!("  ✗ Build failed: {}\n", e),
    }

    // Test 3: Skip listing only
    println!("Test 3: Skip listing only");
    let start = Instant::now();
    match builder.build_from_dicom_with_options(&dicom_path, &config, false, true) {
        Ok((envelope, files)) => {
            let duration = start.elapsed();
            println!("  ✓ Built envelope in {:?}", duration);
            println!(
                "  ✓ Found {} DICOM files (still collected for copying)",
                files.len()
            );
            println!("  ✓ Envelope ID: {}\n", envelope.manifest.id);

            // Save with skip listing
            let save_start = Instant::now();
            match builder.save_to_files_with_options(&envelope, &files, &output_dir, false, true) {
                Ok(_) => println!("  ✓ Saved envelope in {:?}\n", save_start.elapsed()),
                Err(e) => println!("  ✗ Save failed: {}\n", e),
            }
        }
        Err(e) => println!("  ✗ Build failed: {}\n", e),
    }

    // Test 4: Skip both hashing and listing
    println!("Test 4: Skip both hashing and listing (maximum performance)");
    let start = Instant::now();
    match builder.build_from_dicom_with_options(&dicom_path, &config, true, true) {
        Ok((envelope, files)) => {
            let duration = start.elapsed();
            println!("  ✓ Built envelope in {:?}", duration);
            println!(
                "  ✓ Found {} DICOM files (collected but not listed)",
                files.len()
            );
            println!("  ✓ Envelope ID: {}\n", envelope.manifest.id);

            // Save with both flags
            let save_start = Instant::now();
            match builder.save_to_files_with_options(&envelope, &files, &output_dir, true, true) {
                Ok(_) => println!("  ✓ Saved envelope in {:?}\n", save_start.elapsed()),
                Err(e) => println!("  ✗ Save failed: {}\n", e),
            }
        }
        Err(e) => println!("  ✗ Build failed: {}\n", e),
    }

    println!("Performance tests completed!");
    println!("\nNote: Performance improvements are most noticeable with larger datasets.");
    println!("For maximum performance in production, consider:");
    println!("- Using skip_hashing=true for initial ingestion");
    println!("- Using skip_listing=true for metadata-only workflows");
    println!("- Running hash verification as a separate background process");

    Ok(())
}
