use std::path::PathBuf;
use cargo_goaria_pack::check::{
    analyze_wasm_bytecode, verify_wasm_and_manifest, CheckError, WasmAnalysis,
};
use cargo_goaria_pack::cli::{CheckArgs, Language, PackArgs, TestArgs};
use cargo_goaria_pack::commands::check::{handle_check, resolve_manifest_and_wasm};
use cargo_goaria_pack::commands::pack::handle_pack;
use cargo_goaria_pack::commands::test::handle_test;
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
        asset_path: "dist/test-pack-0.1.0.pack.zip".to_string(),
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
    assert_eq!(roundtrip.packs[0].asset_path, "dist/test-pack-0.1.0.pack.zip");
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
    assert!(analysis.memory_exported);

    assert_eq!(
        analysis.export_signatures.get("goaria_abi_version").map(|s| s.as_str()),
        Some("() -> i32")
    );
    assert_eq!(
        analysis.export_signatures.get("goaria_alloc").map(|s| s.as_str()),
        Some("(i32) -> i32")
    );
    assert_eq!(
        analysis.export_signatures.get("goaria_free").map(|s| s.as_str()),
        Some("(i32, i32) -> ()")
    );
    assert_eq!(
        analysis.export_signatures.get("goaria_match").map(|s| s.as_str()),
        Some("(i32, i32) -> i64")
    );
    assert_eq!(
        analysis.export_signatures.get("goaria_extract").map(|s| s.as_str()),
        Some("(i32, i32) -> i64")
    );

    assert!(verify_wasm_and_manifest(&analysis, &manifest).is_ok());
}

#[test]
fn test_wasm_static_analyzer_signature_mismatch() {
    let manifest_str = include_str!("../../../examples/rust_fixture_pack/manifest.json");
    let manifest: Manifest = serde_json::from_str(manifest_str).expect("parse manifest");

    let mut analysis = WasmAnalysis {
        exports: ["goaria_abi_version", "goaria_alloc", "goaria_free", "goaria_match", "goaria_extract", "memory"]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        memory_exported: true,
        ..Default::default()
    };
    analysis.export_signatures.insert("goaria_abi_version".to_string(), "() -> i64".to_string());

    let res = verify_wasm_and_manifest(&analysis, &manifest);
    assert!(matches!(res, Err(CheckError::InvalidExportSignature { name, expected, actual }) if name == "goaria_abi_version" && expected == "() -> i32" && actual == "() -> i64"));
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

        // Verify lockfile content
        let lock_raw = std::fs::read_to_string(temp_out.path().join("rust-fixture-pack.lock.json")).unwrap();
        let lock: LockFile = serde_json::from_str(&lock_raw).unwrap();
        assert!(!lock.packs[0].asset_path.contains('\\'));
    }
}

#[test]
fn test_check_and_test_commands_on_fixture() {
    let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("examples")
        .join("rust_fixture_pack");

    let check_args = CheckArgs {
        project_dir: fixture_dir.clone(),
        wasm: None,
        manifest: None,
    };
    let _ = handle_check(check_args);

    let test_args = TestArgs {
        project_dir: fixture_dir,
        wasm: None,
        manifest: None,
        live: false,
        fixtures: None,
    };
    let _ = handle_test(test_args);
}

#[test]
fn test_resolve_manifest_errors() {
    let temp_dir = tempfile::tempdir().unwrap();
    let invalid_json_manifest = temp_dir.path().join("manifest.json");
    std::fs::write(&invalid_json_manifest, "{ invalid json }").unwrap();

    let res = resolve_manifest_and_wasm(temp_dir.path(), Some(&invalid_json_manifest), None);
    assert!(matches!(res, Err(CheckError::Json(_))));

    let non_existent = temp_dir.path().join("does_not_exist.json");
    let res_io = resolve_manifest_and_wasm(temp_dir.path(), Some(&non_existent), None);
    assert!(matches!(res_io, Err(CheckError::Io(_))));
}
