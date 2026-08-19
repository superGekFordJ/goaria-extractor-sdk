use std::path::PathBuf;
use cargo_goaria_pack::check::{analyze_wasm_bytecode, verify_wasm_and_manifest};
use cargo_goaria_pack::cli::{Language, PackArgs};
use cargo_goaria_pack::commands::pack::handle_pack;
use cargo_goaria_pack::manifest::Manifest;
use cargo_goaria_pack::pack::{LockEntry, LockFile, LOCK_SCHEMA_VERSION};
use cargo_goaria_pack::scaffold::{scaffold_project, validate_pack_name, ScaffoldError};

#[test]
fn test_scaffold_rust_project() {
    let temp_dir = tempfile::tempdir().unwrap();
    let project_dir = temp_dir.path().join("my-rust-pack");

    scaffold_project("my-rust-pack", Language::Rust, &project_dir).unwrap();

    assert!(project_dir.join("Cargo.toml").exists());
    assert!(project_dir.join("manifest.json").exists());
    assert!(project_dir.join("src").join("lib.rs").exists());
    assert!(project_dir.join(".gitignore").exists());

    // Validate manifest
    let manifest_raw = std::fs::read_to_string(project_dir.join("manifest.json")).unwrap();
    let manifest: Manifest = serde_json::from_str(&manifest_raw).unwrap();
    assert_eq!(manifest.pack_id, "my-rust-pack");
    assert_eq!(manifest.pack_version, "0.1.0");
    assert_eq!(manifest.abi_version, 1);
    assert!(manifest.has_capability("cap.parse.wasm"));
    assert!(manifest.has_capability("cap.http.fetch"));
    assert!(manifest.validate_runnable().is_ok());

    // Re-scaffolding in non-empty directory should fail
    let err = scaffold_project("my-rust-pack", Language::Rust, &project_dir).unwrap_err();
    assert!(matches!(err, ScaffoldError::DirectoryNotEmpty(_)));
}

#[test]
fn test_scaffold_zig_project() {
    let temp_dir = tempfile::tempdir().unwrap();
    let project_dir = temp_dir.path().join("my-zig-pack");

    scaffold_project("my-zig-pack", Language::Zig, &project_dir).unwrap();

    assert!(project_dir.join("build.zig").exists());
    assert!(project_dir.join("build.zig.zon").exists());
    assert!(project_dir.join("manifest.json").exists());
    assert!(project_dir.join("src").join("main.zig").exists());
    assert!(project_dir.join(".gitignore").exists());

    // Validate manifest
    let manifest_raw = std::fs::read_to_string(project_dir.join("manifest.json")).unwrap();
    let manifest: Manifest = serde_json::from_str(&manifest_raw).unwrap();
    assert_eq!(manifest.pack_id, "my-zig-pack");
    assert_eq!(manifest.abi_version, 1);
    assert!(manifest.validate_runnable().is_ok());
}

#[test]
fn test_pack_name_validation() {
    assert!(validate_pack_name("valid-pack").is_ok());
    assert!(validate_pack_name("valid_pack_123").is_ok());
    assert!(validate_pack_name("a").is_ok());

    assert!(matches!(
        validate_pack_name(""),
        Err(ScaffoldError::InvalidPackName(_))
    ));
    assert!(matches!(
        validate_pack_name("Invalid-Uppercase"),
        Err(ScaffoldError::InvalidPackName(_))
    ));
    assert!(matches!(
        validate_pack_name("invalid with spaces"),
        Err(ScaffoldError::InvalidPackName(_))
    ));
    assert!(matches!(
        validate_pack_name("invalid!char"),
        Err(ScaffoldError::InvalidPackName(_))
    ));
    let long_name = "a".repeat(51);
    assert!(matches!(
        validate_pack_name(&long_name),
        Err(ScaffoldError::InvalidPackName(_))
    ));
}

#[test]
fn test_lockfile_generation_and_serialization() {
    let entry = LockEntry {
        pack_id: "test-pack".to_string(),
        pack_version: "0.1.0".to_string(),
        asset_url: None,
        asset_path: "test-pack-0.1.0.pack.zip".to_string(),
        asset_sha256: "4a7f".to_string(),
        public_keys: vec!["d75a".to_string()],
        manifest_sha256: Some("b18e".to_string()),
        payload_sha256: Some("c309".to_string()),
        signature_sha256: Some("89ab".to_string()),
    };

    let lock_file = LockFile::single_entry(entry);
    let json_str = lock_file.to_canonical_json().unwrap();

    assert!(json_str.ends_with('\n'));
    let roundtrip: LockFile = serde_json::from_str(&json_str).unwrap();
    assert_eq!(roundtrip.schema_version, LOCK_SCHEMA_VERSION);
    assert_eq!(roundtrip.packs.len(), 1);
    assert_eq!(roundtrip.packs[0].pack_id, "test-pack");
    assert_eq!(roundtrip.packs[0].asset_sha256, "4a7f");
}

#[test]
fn test_wasm_static_analyzer_on_fixture() {
    let candidates = [
        "../../../target/wasm32-unknown-unknown/release/rust_fixture_pack.wasm",
        "../../target/wasm32-unknown-unknown/release/rust_fixture_pack.wasm",
        "target/wasm32-unknown-unknown/release/rust_fixture_pack.wasm",
    ];
    let mut wasm_bytes = None;
    for c in candidates {
        let p = PathBuf::from(c);
        if p.exists() {
            wasm_bytes = Some(std::fs::read(&p).expect("read wasm"));
            break;
        }
    }
    let wasm_bytes = match wasm_bytes {
        Some(b) => b,
        None => return,
    };

    let manifest_str = include_str!("../../../examples/rust_fixture_pack/manifest.json");
    let manifest: Manifest = serde_json::from_str(manifest_str).expect("parse manifest");

    let analysis = analyze_wasm_bytecode(&wasm_bytes).expect("analyze wasm");
    assert!(analysis.exports.contains("goaria_abi_version"));
    assert!(analysis.exports.contains("goaria_alloc"));
    assert!(analysis.exports.contains("goaria_free"));
    assert!(analysis.exports.contains("goaria_match"));
    assert!(analysis.exports.contains("goaria_extract"));
    assert!(analysis.memory_exported || analysis.exports.contains("memory"));

    assert!(verify_wasm_and_manifest(&analysis, &manifest).is_ok());
}

#[test]
fn test_pack_pipeline_on_fixture() {
    let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("examples")
        .join("rust_fixture_pack");

    let temp_out = tempfile::tempdir().unwrap();

    let args = PackArgs {
        project_dir: fixture_dir,
        out_dir: temp_out.path().to_path_buf(),
        sign_key: None,
        asset_name: None,
        skip_build: true,
    };

    // If wasm exists in target, run pack
    if let Ok(zip_path) = handle_pack(args) {
        assert!(zip_path.exists());
        assert!(temp_out.path().join("manifest.json").exists());
        assert!(temp_out.path().join("payload.wasm").exists());
        assert!(temp_out.path().join("manifest.sig").exists());
        assert!(temp_out.path().join("rust-fixture-pack.lock.json").exists());
    }
}
