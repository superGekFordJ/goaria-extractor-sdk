use std::path::Path;
use crate::scaffold::ScaffoldError;

pub fn generate(name: &str, target_dir: &Path) -> Result<(), ScaffoldError> {
    let src_dir = target_dir.join("src");
    std::fs::create_dir_all(&src_dir)?;

    let cargo_toml = format!(
        r#"[package]
name = "{name}"
version = "0.1.0"
edition = "2021"
publish = false

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
goaria-extractor-sdk = "0.1.0"
serde = {{ version = "1.0", default-features = false, features = ["derive", "alloc"] }}
serde_json = {{ version = "1.0", default-features = false, features = ["alloc"] }}
"#
    );
    std::fs::write(target_dir.join("Cargo.toml"), cargo_toml)?;

    let manifest_json = format!(
        r#"{{
  "pack_id": "{name}",
  "pack_version": "0.1.0",
  "abi_version": 1,
  "description": "GoAria extractor pack for {name}",
  "domains": [
    {{
      "host": "fixture.invalid",
      "include_subdomains": true
    }}
  ],
  "capabilities": [
    "cap.parse.wasm",
    "cap.http.fetch"
  ],
  "resource_limits": {{
    "timeout_millis": 5000,
    "max_memory_pages": 32,
    "max_host_calls": 50,
    "max_response_bytes": 1048576,
    "max_output_items": 50,
    "max_output_bytes": 1048576
  }}
}}
"#
    );
    std::fs::write(target_dir.join("manifest.json"), manifest_json)?;

    let lib_rs = r#"use std::collections::BTreeMap;
use goaria_extractor_sdk::prelude::*;

#[goaria_pack]
#[derive(Default)]
pub struct ExtractorImpl;

impl Extractor for ExtractorImpl {
    fn match_url(&self, input: MatchInput) -> Result<MatchOutput, ExtractorError> {
        if input.url.contains("fixture.invalid") {
            Ok(MatchOutput::matched()
                .with_confidence(100)
                .with_reason("matches fixture.invalid domain"))
        } else {
            Ok(MatchOutput::unmatched())
        }
    }

    fn extract(&self, input: ExtractInput) -> Result<ExtractOutput, ExtractorError> {
        if !input.url.contains("fixture.invalid") {
            return Ok(ExtractOutput::default());
        }

        let mut metadata = BTreeMap::new();
        metadata.insert("input_url".to_string(), input.url.clone());

        let item = ExtractedItemRef {
            id: Some("item-001".to_string()),
            url: Some(input.url),
            filename: Some("download.bin".to_string()),
            size_bytes: None,
            mime_type: Some("application/octet-stream".to_string()),
            auth_profile_ref: None,
            header_profile_ref: None,
            metadata: Some(metadata),
        };

        Ok(ExtractOutput::single(item))
    }
}
"#;
    std::fs::write(src_dir.join("lib.rs"), lib_rs)?;

    let gitignore = r#"/target
dist/
*.pack.zip
*.lock.json
"#;
    std::fs::write(target_dir.join(".gitignore"), gitignore)?;

    Ok(())
}
