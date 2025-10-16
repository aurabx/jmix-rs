#[cfg(test)]
mod tests {
    use crate::builder::JmixBuilder;
    use crate::config::{Config, ContactInfo, Entity};
    use std::fs;
    use std::path::Path;
    use tempfile::TempDir;

    fn create_test_config() -> Config {
        Config {
            version: Some("1.0".to_string()),
            sender: Entity {
                name: "Test Sender".to_string(),
                id: "test:sender".to_string(),
                contact: ContactInfo::Email("sender@test.com".to_string()),
                assertion: None,
            },
            requester: Entity {
                name: "Test Requester".to_string(),
                id: "test:requester".to_string(),
                contact: ContactInfo::Email("requester@test.com".to_string()),
                assertion: None,
            },
            receivers: vec![Entity {
                name: "Test Receiver".to_string(),
                id: "test:receiver".to_string(),
                contact: ContactInfo::Email("receiver@test.com".to_string()),
                assertion: None,
            }],
            ..Default::default()
        }
    }

    fn create_test_dicom_files(
        dir: &Path,
    ) -> Result<Vec<std::path::PathBuf>, Box<dyn std::error::Error>> {
        fs::create_dir_all(dir)?;

        // Create fake DICOM files
        let file1 = dir.join("test1.dcm");
        let file2 = dir.join("test2.dcm");

        // Write fake DICOM content with proper DICM header
        let mut fake_content = vec![0; 128]; // 128 bytes of padding
        fake_content.extend_from_slice(b"DICM"); // DICM magic number
        fake_content.extend_from_slice(&[0; 100]); // Some fake data

        fs::write(&file1, &fake_content)?;
        fs::write(&file2, &fake_content)?;

        Ok(vec![file1, file2])
    }

    #[test]
    fn test_build_with_hashing_enabled() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let dicom_dir = temp_dir.path().join("dicom");
        let _dicom_files =
            create_test_dicom_files(&dicom_dir).expect("Failed to create DICOM files");

        let config = create_test_config();
        let builder = JmixBuilder::new();

        // Build with hashing enabled (default behavior)
        let result = builder.build_from_dicom_with_options(&dicom_dir, &config, false, false);
        assert!(result.is_ok());

        let (envelope, files) = result.unwrap();
        assert_eq!(files.len(), 2); // Should find 2 DICOM files
        assert!(!envelope.manifest.id.is_empty());
    }

    #[test]
    fn test_build_with_hashing_disabled() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let dicom_dir = temp_dir.path().join("dicom");
        let _dicom_files =
            create_test_dicom_files(&dicom_dir).expect("Failed to create DICOM files");

        let config = create_test_config();
        let builder = JmixBuilder::new();

        // Build with hashing disabled (skip_hashing = true)
        let result = builder.build_from_dicom_with_options(&dicom_dir, &config, true, false);
        assert!(result.is_ok());

        let (envelope, files) = result.unwrap();
        assert_eq!(files.len(), 2); // Should still find 2 DICOM files
        assert!(!envelope.manifest.id.is_empty());
    }

    #[test]
    fn test_build_with_listing_disabled() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let dicom_dir = temp_dir.path().join("dicom");
        let _dicom_files =
            create_test_dicom_files(&dicom_dir).expect("Failed to create DICOM files");

        let config = create_test_config();
        let builder = JmixBuilder::new();

        // Build with listing disabled (skip_listing = true)
        let result = builder.build_from_dicom_with_options(&dicom_dir, &config, false, true);
        assert!(result.is_ok());

        let (envelope, files) = result.unwrap();
        assert_eq!(files.len(), 2); // Files are still collected for copying
        assert!(!envelope.manifest.id.is_empty());
    }

    #[test]
    fn test_build_with_both_flags_disabled() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let dicom_dir = temp_dir.path().join("dicom");
        let _dicom_files =
            create_test_dicom_files(&dicom_dir).expect("Failed to create DICOM files");

        let config = create_test_config();
        let builder = JmixBuilder::new();

        // Build with both hashing and listing disabled
        let result = builder.build_from_dicom_with_options(&dicom_dir, &config, true, true);
        assert!(result.is_ok());

        let (envelope, files) = result.unwrap();
        assert_eq!(files.len(), 2); // Files are still collected
        assert!(!envelope.manifest.id.is_empty());
    }

    #[test]
    fn test_save_with_options_creates_files() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let dicom_dir = temp_dir.path().join("dicom");
        let output_dir = temp_dir.path().join("output");
        let _dicom_files =
            create_test_dicom_files(&dicom_dir).expect("Failed to create DICOM files");

        let config = create_test_config();
        let builder = JmixBuilder::new();

        // Build envelope
        let (envelope, files) = builder
            .build_from_dicom(&dicom_dir, &config)
            .expect("Failed to build envelope");

        // Save with both flags enabled
        let save_result = builder.save_to_files_with_options_no_zip(
            &envelope,
            &files,
            &output_dir,
            true, // skip_hashing
            true, // skip_listing
        );

        assert!(save_result.is_ok());
        let saved_files = save_result.unwrap();
        assert!(!saved_files.is_empty());

        // Check that the envelope directory was created
        let envelope_dir = output_dir.join(format!("{}.jmix", envelope.manifest.id));
        assert!(envelope_dir.exists());

        // Check for required files
        assert!(envelope_dir.join("manifest.json").exists());
        assert!(envelope_dir.join("audit.json").exists());
        assert!(envelope_dir.join("payload").join("metadata.json").exists());
        assert!(envelope_dir.join("payload").join("files.json").exists());
    }

    #[test]
    fn test_files_manifest_with_hashing_disabled() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let dicom_dir = temp_dir.path().join("dicom");
        let dicom_files =
            create_test_dicom_files(&dicom_dir).expect("Failed to create DICOM files");

        let config = create_test_config();
        let builder = JmixBuilder::new();

        // Build envelope
        let (envelope, _) = builder
            .build_from_dicom(&dicom_dir, &config)
            .expect("Failed to build envelope");

        // Create files manifest with hashing disabled
        let files_manifest = builder
            .create_files_manifest_with_options(&envelope, &dicom_files, true, false)
            .expect("Failed to create files manifest");

        // Should have metadata.json entry plus 2 DICOM files
        assert_eq!(files_manifest.len(), 3);

        // Check that DICOM file entries have no hashes
        for file_entry in &files_manifest {
            if file_entry.file.starts_with("dicom/") {
                assert!(
                    file_entry.hash.is_none(),
                    "Hash should be None when skip_hashing is true"
                );
            }
        }
    }

    #[test]
    fn test_save_with_skip_hashing_sets_placeholder() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let dicom_dir = temp_dir.path().join("dicom");
        let output_dir = temp_dir.path().join("output");
        let _dicom_files =
            create_test_dicom_files(&dicom_dir).expect("Failed to create DICOM files");

        let config = create_test_config();
        let builder = JmixBuilder::new();

        // Build envelope
        let (envelope, files) = builder
            .build_from_dicom(&dicom_dir, &config)
            .expect("Failed to build envelope");

        // Save with hashing disabled
        let _saved_files = builder
            .save_to_files_with_options_no_zip(
                &envelope,
                &files,
                &output_dir,
                true,  // skip_hashing
                false, // skip_listing
            )
            .expect("Failed to save");

        // Read the saved manifest to check payload hash
        let envelope_dir = output_dir.join(format!("{}.jmix", envelope.manifest.id));
        let manifest_path = envelope_dir.join("manifest.json");
        let manifest_content = fs::read_to_string(manifest_path).expect("Failed to read manifest");
        let saved_manifest: serde_json::Value =
            serde_json::from_str(&manifest_content).expect("Failed to parse manifest");

        // Check that payload hash is the placeholder
        let payload_hash = saved_manifest["security"]["payload_hash"]
            .as_str()
            .expect("payload_hash should be a string");
        assert_eq!(
            payload_hash, "sha256:skipped",
            "Payload hash should be placeholder when skip_hashing is true"
        );

        // Read files.json to check that DICOM files have no hashes
        let files_path = envelope_dir.join("payload").join("files.json");
        let files_content = fs::read_to_string(files_path).expect("Failed to read files.json");
        let saved_files: serde_json::Value =
            serde_json::from_str(&files_content).expect("Failed to parse files.json");

        // Check that DICOM files have no hashes
        if let Some(files_array) = saved_files.as_array() {
            for file_entry in files_array {
                let file_name = file_entry["file"]
                    .as_str()
                    .expect("file should be a string");
                if file_name.starts_with("dicom/") {
                    assert!(
                        file_entry["hash"].is_null(),
                        "DICOM file hash should be null when skip_hashing is true"
                    );
                }
            }
        }
    }

    #[test]
    fn test_files_manifest_with_listing_disabled() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let dicom_dir = temp_dir.path().join("dicom");
        let dicom_files =
            create_test_dicom_files(&dicom_dir).expect("Failed to create DICOM files");

        let config = create_test_config();
        let builder = JmixBuilder::new();

        // Build envelope
        let (envelope, _) = builder
            .build_from_dicom(&dicom_dir, &config)
            .expect("Failed to build envelope");

        // Create files manifest with listing disabled
        let files_manifest = builder
            .create_files_manifest_with_options(&envelope, &dicom_files, false, true)
            .expect("Failed to create files manifest");

        // Should only have metadata.json entry (no DICOM files)
        assert_eq!(files_manifest.len(), 1);
        assert_eq!(files_manifest[0].file, "metadata.json");
    }

    #[test]
    fn test_save_with_skip_listing_creates_minimal_files_json() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let dicom_dir = temp_dir.path().join("dicom");
        let output_dir = temp_dir.path().join("output");
        let _dicom_files =
            create_test_dicom_files(&dicom_dir).expect("Failed to create DICOM files");

        let config = create_test_config();
        let builder = JmixBuilder::new();

        // Build envelope
        let (envelope, files) = builder
            .build_from_dicom(&dicom_dir, &config)
            .expect("Failed to build envelope");

        // Save with listing disabled
        let _saved_files = builder
            .save_to_files_with_options_no_zip(
                &envelope,
                &files,
                &output_dir,
                false, // skip_hashing
                true,  // skip_listing
            )
            .expect("Failed to save");

        // Read files.json to check that only metadata.json is listed
        let envelope_dir = output_dir.join(format!("{}.jmix", envelope.manifest.id));
        let files_path = envelope_dir.join("payload").join("files.json");
        let files_content = fs::read_to_string(files_path).expect("Failed to read files.json");
        let saved_files: serde_json::Value =
            serde_json::from_str(&files_content).expect("Failed to parse files.json");

        // Should only have metadata.json entry (no DICOM files)
        if let Some(files_array) = saved_files.as_array() {
            assert_eq!(
                files_array.len(),
                1,
                "files.json should only have metadata.json when skip_listing is true"
            );
            let file_name = files_array[0]["file"]
                .as_str()
                .expect("file should be a string");
            assert_eq!(
                file_name, "metadata.json",
                "Only entry should be metadata.json"
            );
        }

        // But DICOM files should still be physically present in the dicom directory
        let dicom_dir_output = envelope_dir.join("payload").join("dicom");
        assert!(dicom_dir_output.exists(), "DICOM directory should exist");
        let dicom_entries: Vec<_> = fs::read_dir(dicom_dir_output)
            .expect("Failed to read dicom dir")
            .collect();
        assert_eq!(
            dicom_entries.len(),
            2,
            "DICOM files should still be copied even with skip_listing"
        );
    }

    #[test]
    fn test_skip_hashing_flag_acceptance() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let dicom_dir = temp_dir.path().join("dicom");
        let output_dir = temp_dir.path().join("output");
        let _dicom_files =
            create_test_dicom_files(&dicom_dir).expect("Failed to create DICOM files");

        let config = create_test_config();

        // For this test, we'll use unencrypted envelope to test the flag logic

        // Create a test public key by extracting it from the encryption manager
        // For testing, we'll create a simple builder using a generated key
        let builder = JmixBuilder::new();

        // We can't easily access the public key from the encryption manager for this test,
        // so let's skip the encrypted test for now and just test that the build method
        // accepts the flags without error
        let (envelope, files) = builder
            .build_from_dicom(&dicom_dir, &config)
            .expect("Failed to build envelope");

        // Save with hashing disabled (unencrypted to test the flag logic)
        let _saved_files = builder
            .save_to_files_with_options_no_zip(
                &envelope,
                &files,
                &output_dir,
                true,  // skip_hashing
                false, // skip_listing
            )
            .expect("Failed to save");

        // Read the saved manifest to check payload hash
        let envelope_dir = output_dir.join(format!("{}.jmix", envelope.manifest.id));
        let manifest_path = envelope_dir.join("manifest.json");
        let manifest_content = fs::read_to_string(manifest_path).expect("Failed to read manifest");
        let saved_manifest: serde_json::Value =
            serde_json::from_str(&manifest_content).expect("Failed to parse manifest");

        // Check that payload hash is the placeholder
        let payload_hash = saved_manifest["security"]["payload_hash"]
            .as_str()
            .expect("payload_hash should be a string");
        assert_eq!(
            payload_hash, "sha256:skipped",
            "Payload hash should be placeholder when skip_hashing is true"
        );
    }
    #[test]
    fn test_backward_compatibility() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let dicom_dir = temp_dir.path().join("dicom");
        let _dicom_files =
            create_test_dicom_files(&dicom_dir).expect("Failed to create DICOM files");

        let config = create_test_config();
        let builder = JmixBuilder::new();

        // Test that old method still works
        let old_result = builder.build_from_dicom(&dicom_dir, &config);
        let new_result = builder.build_from_dicom_with_options(&dicom_dir, &config, false, false);

        assert!(old_result.is_ok());
        assert!(new_result.is_ok());

        // Results should be equivalent
        let (old_envelope, old_files) = old_result.unwrap();
        let (new_envelope, new_files) = new_result.unwrap();

        assert_eq!(old_files.len(), new_files.len());
        assert_eq!(
            old_envelope.manifest.sender.id,
            new_envelope.manifest.sender.id
        );
    }
}
