use crate::scaffold::sdk_assets::{
    EmbeddedFile, EMBEDDED_SDK_VERSION, RUST_MACRO_FILES, RUST_SDK_FILES, SDK_GIT_URL,
    VENDORED_MACRO_CARGO_TOML, VENDORED_SDK_CARGO_TOML,
};
use crate::scaffold::{ScaffoldError, SdkSpec};
use std::path::Path;

fn sdk_dependency_line(sdk: &SdkSpec) -> Result<String, ScaffoldError> {
    match sdk {
        SdkSpec::Vendor => {
            Ok("goaria-extractor-sdk = { path = \"vendor/goaria-extractor-sdk\" }".to_string())
        }
        SdkSpec::Git { git_ref: None } => Ok(format!(
            "goaria-extractor-sdk = {{ git = \"{SDK_GIT_URL}\" }}"
        )),
        SdkSpec::Git {
            git_ref: Some(git_ref),
        } => Ok(format!(
            "goaria-extractor-sdk = {{ git = \"{SDK_GIT_URL}\", rev = \"{git_ref}\" }}"
        )),
        SdkSpec::Crates => Ok(format!("goaria-extractor-sdk = \"{EMBEDDED_SDK_VERSION}\"")),
        SdkSpec::Path(dir) => {
            let path = crate::scaffold::forward_slash_path(dir);
            Ok(format!("goaria-extractor-sdk = {{ path = \"{path}\" }}"))
        }
    }
}

fn write_embedded_tree(root: &Path, files: &[EmbeddedFile]) -> Result<(), ScaffoldError> {
    for file in files {
        let dest = root.join(file.rel_path);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&dest, file.contents)?;
    }
    Ok(())
}

fn write_vendored_sdk(target_dir: &Path) -> Result<(), ScaffoldError> {
    let vendor_dir = target_dir.join("vendor");

    let sdk_dir = vendor_dir.join("goaria-extractor-sdk");
    write_embedded_tree(&sdk_dir, RUST_SDK_FILES)?;
    std::fs::write(
        sdk_dir.join("Cargo.toml"),
        VENDORED_SDK_CARGO_TOML.replace("{version}", EMBEDDED_SDK_VERSION),
    )?;

    let macro_dir = vendor_dir.join("goaria-extractor-macro");
    write_embedded_tree(&macro_dir, RUST_MACRO_FILES)?;
    std::fs::write(
        macro_dir.join("Cargo.toml"),
        VENDORED_MACRO_CARGO_TOML.replace("{version}", EMBEDDED_SDK_VERSION),
    )?;

    let readme = format!(
        "# Vendored GoAria Extractor SDK\n\
         \n\
         These crates were embedded into `cargo-goaria-pack` and written here by\n\
         `cargo goaria-pack new --sdk vendor` (SDK version {EMBEDDED_SDK_VERSION}).\n\
         \n\
         Upstream: {SDK_GIT_URL}\n\
         \n\
         Commit this directory so the pack builds without network access to the SDK repo.\n"
    );
    std::fs::write(vendor_dir.join("README.md"), readme)?;

    Ok(())
}

pub fn generate(name: &str, target_dir: &Path, sdk: &SdkSpec) -> Result<(), ScaffoldError> {
    let src_dir = target_dir.join("src");
    std::fs::create_dir_all(&src_dir)?;

    let sdk_dep = sdk_dependency_line(sdk)?;
    let cargo_toml = format!(
        r#"[package]
name = "{name}"
version = "0.1.0"
edition = "2021"
publish = false

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
{sdk_dep}
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

#[goaria_extractor]
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
            download_auth_ref: None,
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

    if let SdkSpec::Vendor = sdk {
        write_vendored_sdk(target_dir)?;
    }

    Ok(())
}
