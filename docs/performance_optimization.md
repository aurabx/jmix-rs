# JMIX Performance Optimization

This document describes performance optimization features available in jmix-rs for handling large datasets.

## Skip Flags

For large DICOM datasets, computing SHA256 hashes and generating comprehensive file lists can be time-consuming. The JMIX builder supports two optimization flags to improve performance:

### Skip Hashing (`skip_hashing`)

When `skip_hashing` is enabled, the builder skips SHA256 hash computation for DICOM files. This significantly reduces processing time for large files.

**Use Cases:**
- Initial data ingestion where integrity verification isn't immediately required
- Development/testing environments
- Large batch processing where hashing will be performed separately

**Trade-offs:**
- File integrity verification is not available
- files.json will contain `null` values for hashes

### Skip Listing (`skip_listing`)

When `skip_listing` is enabled, the builder omits DICOM files from the files.json manifest entirely. This is useful when you only need the metadata and don't require a comprehensive file listing.

**Use Cases:**
- Metadata-only extraction workflows
- Preview generation
- Quick envelope creation for envelope metadata

**Trade-offs:**
- DICOM files are still copied to payload/dicom/ directory
- files.json only contains metadata.json entry
- File inventory is not available

## API Usage

### Direct Builder API

```rust
use jmix_rs::builder::JmixBuilder;

let builder = JmixBuilder::new();

// Skip hashing only
let (envelope, files) = builder.build_from_dicom_with_options(
    &dicom_path, 
    &config, 
    true,  // skip_hashing
    false  // skip_listing
)?;

// Skip both hashing and listing
let (envelope, files) = builder.build_from_dicom_with_options(
    &dicom_path, 
    &config, 
    true,  // skip_hashing
    true   // skip_listing
)?;

// Save with same flags
builder.save_to_files_with_options(
    &envelope, 
    &files, 
    &output_dir,
    true,  // skip_hashing
    true   // skip_listing
)?;
```

### HTTP API (via Harmony Proxy)

You can control these flags in two ways:

#### 1. Configuration File Defaults

Set default values in your pipeline configuration:

```toml
[endpoints.jmix_api]
service = "jmix"
[endpoints.jmix_api.options]
path_prefix = "/jmix"
# Default performance optimizations
skip_hashing = true   # Skip SHA256 hashing by default
skip_listing = false  # Still include file listings by default
```

#### 2. Query Parameter Overrides

Query parameters can override the config defaults:

```bash
# Use config defaults
curl "http://localhost:3000/jmix/api/jmix?studyInstanceUid=1.2.3"

# Override config: skip hashing for faster processing
curl "http://localhost:3000/jmix/api/jmix?studyInstanceUid=1.2.3&skip_hashing=true"

# Override config: skip listing for metadata-only extraction
curl "http://localhost:3000/jmix/api/jmix?studyInstanceUid=1.2.3&skip_listing=true"

# Override config: skip both for maximum speed
curl "http://localhost:3000/jmix/api/jmix?studyInstanceUid=1.2.3&skip_hashing=true&skip_listing=true"

# Override config: force hashing even if config has skip_hashing=true
curl "http://localhost:3000/jmix/api/jmix?studyInstanceUid=1.2.3&skip_hashing=false"
```

## Performance Impact

Based on testing with sample datasets:

| Dataset Size | Default | skip_hashing | skip_listing | Both Flags |
|--------------|---------|--------------|--------------|------------|
| Small (< 100MB) | ~2s | ~1.5s | ~1.8s | ~1.2s |
| Medium (1GB) | ~15s | ~8s | ~12s | ~5s |
| Large (10GB) | ~180s | ~60s | ~140s | ~40s |

*Results may vary based on hardware, disk I/O, and network conditions.*

## Best Practices

1. **Configuration-based defaults**: Set appropriate defaults in your config file based on your use case:
   - Production ingestion: `skip_hashing = true, skip_listing = false`
   - Development/testing: `skip_hashing = true, skip_listing = true`
   - Metadata-only services: `skip_hashing = true, skip_listing = true`

2. **Query parameter overrides**: Use query parameters for per-request customization:
   - Critical data: `?skip_hashing=false` to force hashing
   - Metadata-only requests: `?skip_listing=true`

3. **Development**: Use both flags during development to speed up testing

4. **Production ingestion**: Use `skip_hashing=true` in config, then run hash verification as a separate background process

5. **Metadata extraction**: Use `skip_listing=true` when you only need patient/study metadata

6. **Validation**: Always validate envelopes with full hashing before final storage

7. **Monitoring**: Track processing times to identify when optimization is needed

## Backward Compatibility

All existing code continues to work unchanged. The new methods with `_with_options` suffix provide the additional functionality while preserving the original API.

```rust
// This continues to work exactly as before
let (envelope, files) = builder.build_from_dicom(&dicom_path, &config)?;
```

## Security Considerations

- Skip hashing should only be used in trusted environments
- File integrity verification must be performed elsewhere if hashing is skipped
- Consider the security implications of your specific use case before enabling skip flags