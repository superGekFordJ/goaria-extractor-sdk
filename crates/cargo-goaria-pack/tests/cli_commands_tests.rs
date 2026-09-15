use std::path::PathBuf;
use std::process::Command;

use cargo_goaria_pack::check::{
    analyze_wasm_bytecode, verify_wasm_and_manifest, CheckError, DisallowedImportInfo, WasmAnalysis,
};
use cargo_goaria_pack::cli::{CheckArgs, Language, PackArgs, TestArgs};
use cargo_goaria_pack::commands::check::{handle_check, resolve_manifest_and_wasm};
use cargo_goaria_pack::commands::pack::handle_pack;
use cargo_goaria_pack::commands::test::{handle_test, TestCommandError};
use cargo_goaria_pack::manifest::Manifest;
use cargo_goaria_pack::pack::lock::{LockEntry, LockFile, LOCK_SCHEMA_VERSION};
use cargo_goaria_pack::scaffold::{scaffold_project, validate_pack_name, ScaffoldError};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn cargo_target_dir() -> PathBuf {
    match std::env::var_os("CARGO_TARGET_DIR") {
        Some(configured) => {
            let configured = PathBuf::from(configured);
            if configured.is_absolute() {
                configured
            } else {
                workspace_root().join(configured)
            }
        }
        None => workspace_root().join("target"),
    }
}

fn rust_fixture_wasm_path() -> PathBuf {
    cargo_target_dir()
        .join("wasm32-unknown-unknown")
        .join("release")
        .join("rust_fixture_pack.wasm")
}

fn rust_fixture_dir() -> PathBuf {
    workspace_root().join("examples").join("rust_fixture_pack")
}

#[test]
fn test_scaffold_rust_project() {
    let temp = tempfile::tempdir().unwrap();
    let project_dir = temp.path().join("my_rust_pack");

    let res = scaffold_project("my_rust_pack", Language::Rust, &project_dir);
    assert!(res.is_ok());

    assert!(project_dir.join("Cargo.toml").exists());
    assert!(project_dir.join("manifest.json").exists());
    assert!(project_dir.join("src/lib.rs").exists());
    assert!(project_dir.join(".gitignore").exists());

    // Validate generated manifest.json
    let manifest_raw = std::fs::read_to_string(project_dir.join("manifest.json")).unwrap();
    let manifest: Manifest = serde_json::from_str(&manifest_raw).unwrap();
    assert_eq!(manifest.pack_id, "my_rust_pack");
    assert_eq!(manifest.abi_version, 1);
    assert!(manifest.validate_runnable().is_ok());
}

#[test]
fn test_scaffold_zig_project() {
    let temp = tempfile::tempdir().unwrap();
    let project_dir = temp.path().join("my_zig_pack");

    let res = scaffold_project("my-zig-pack", Language::Zig, &project_dir);
    assert!(res.is_ok());

    assert!(project_dir.join("build.zig").exists());
    assert!(project_dir.join("build.zig.zon").exists());
    assert!(project_dir.join("manifest.json").exists());
    assert!(project_dir.join("src/main.zig").exists());
    assert!(project_dir.join(".gitignore").exists());

    let manifest_raw = std::fs::read_to_string(project_dir.join("manifest.json")).unwrap();
    let manifest: Manifest = serde_json::from_str(&manifest_raw).unwrap();
    assert_eq!(manifest.pack_id, "my-zig-pack");
    assert_eq!(manifest.abi_version, 1);
    assert!(manifest.validate_runnable().is_ok());
}

#[test]
fn test_new_command_prints_build_before_check() {
    let temp = tempfile::tempdir().unwrap();
    let project_dir = temp.path().join("quickstart-pack");
    let output = Command::new(env!("CARGO_BIN_EXE_cargo-goaria-pack"))
        .args(["new", "quickstart-pack", "--path"])
        .arg(&project_dir)
        .output()
        .unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let build_position = stdout.find("cargo goaria-pack build").unwrap();
    let check_position = stdout.find("cargo goaria-pack check").unwrap();
    assert!(build_position < check_position);
}

#[test]
fn test_pack_name_validation() {
    assert!(validate_pack_name("valid-pack").is_ok());
    assert!(validate_pack_name("valid_pack_123").is_ok());
    assert!(validate_pack_name("abc").is_ok());
    assert!(matches!(
        validate_pack_name("a"),
        Err(ScaffoldError::InvalidPackName(_))
    ));

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
    for invalid_edge in ["---", "-ab", "ab_"] {
        assert!(matches!(
            validate_pack_name(invalid_edge),
            Err(ScaffoldError::InvalidPackName(_))
        ));
    }
    let long_name = "a".repeat(51);
    assert!(matches!(
        validate_pack_name(&long_name),
        Err(ScaffoldError::InvalidPackName(_))
    ));
}

#[test]
fn test_keygen_requires_new_private_output_and_never_prints_seed() {
    let binary = env!("CARGO_BIN_EXE_cargo-goaria-pack");
    let missing_output = Command::new(binary).arg("keygen").output().unwrap();
    assert!(!missing_output.status.success());
    assert!(!String::from_utf8_lossy(&missing_output.stdout).contains("Private Seed"));

    let temp = tempfile::tempdir().unwrap();
    let conflicting_path = temp.path().join("conflicting-key.hex");
    let conflicting_output = Command::new(binary)
        .args(["keygen", "--out-seed"])
        .arg(&conflicting_path)
        .arg("--out-pub")
        .arg(&conflicting_path)
        .output()
        .unwrap();
    assert!(!conflicting_output.status.success());
    assert!(!conflicting_path.exists());

    let seed_path = temp.path().join("signing-seed.hex");
    let output = Command::new(binary)
        .args(["keygen", "--out-seed"])
        .arg(&seed_path)
        .output()
        .unwrap();
    assert!(output.status.success());

    let seed = std::fs::read_to_string(&seed_path).unwrap();
    assert_eq!(seed.len(), 64);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Public Key Hex:"));
    assert!(!stdout.contains(&seed));

    let second_output = Command::new(binary)
        .args(["keygen", "--out-seed"])
        .arg(&seed_path)
        .output()
        .unwrap();
    assert!(!second_output.status.success());
    assert_eq!(std::fs::read_to_string(&seed_path).unwrap(), seed);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&seed_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
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
    assert_eq!(
        roundtrip.packs[0].asset_path,
        "dist/test-pack-0.1.0.pack.zip"
    );
}

#[test]
fn test_manifest_json_schema_matches_host_policy_limits() {
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../docs/manifest_schema.json")).unwrap();
    let limits = &schema["properties"]["resource_limits"]["properties"];

    assert_eq!(limits["timeout_millis"]["maximum"], 10_000);
    assert_eq!(limits["max_memory_pages"]["maximum"], 256);
    assert_eq!(limits["max_host_calls"]["maximum"], 128);
    assert_eq!(limits["max_response_bytes"]["maximum"], 10_485_760);
    assert_eq!(limits["max_output_items"]["maximum"], 1_000);
    assert_eq!(limits["max_output_bytes"]["maximum"], 1_048_576);
    assert_eq!(schema["properties"]["pack_id"]["minLength"], 3);
}

#[test]
fn test_wasm_static_analyzer_on_fixture() {
    let wasm_path = rust_fixture_wasm_path();
    let wasm_bytes = std::fs::read(&wasm_path).unwrap_or_else(|error| {
        panic!(
            "failed to read Rust fixture WASM '{}': {error}; build it before running tests",
            wasm_path.display()
        )
    });

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
        analysis
            .export_signatures
            .get("goaria_abi_version")
            .map(|s| s.as_str()),
        Some("() -> i32")
    );
    assert_eq!(
        analysis
            .export_signatures
            .get("goaria_alloc")
            .map(|s| s.as_str()),
        Some("(i32) -> i32")
    );
    assert_eq!(
        analysis
            .export_signatures
            .get("goaria_free")
            .map(|s| s.as_str()),
        Some("(i32, i32) -> ()")
    );
    assert_eq!(
        analysis
            .export_signatures
            .get("goaria_match")
            .map(|s| s.as_str()),
        Some("(i32, i32) -> i64")
    );
    assert_eq!(
        analysis
            .export_signatures
            .get("goaria_extract")
            .map(|s| s.as_str()),
        Some("(i32, i32) -> i64")
    );

    assert!(verify_wasm_and_manifest(&analysis, &manifest).is_ok());
}

#[test]
fn test_wasm_static_analyzer_signature_mismatch() {
    let manifest_str = include_str!("../../../examples/rust_fixture_pack/manifest.json");
    let manifest: Manifest = serde_json::from_str(manifest_str).expect("parse manifest");

    let mut analysis = WasmAnalysis {
        exports: [
            "goaria_abi_version",
            "goaria_alloc",
            "goaria_free",
            "goaria_match",
            "goaria_extract",
            "memory",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect(),
        memory_exported: true,
        memory_count: 1,
        ..Default::default()
    };
    analysis
        .export_signatures
        .insert("goaria_abi_version".to_string(), "() -> i64".to_string());
    analysis
        .export_signatures
        .insert("goaria_alloc".to_string(), "(i32) -> i32".to_string());
    analysis
        .export_signatures
        .insert("goaria_free".to_string(), "(i32, i32) -> ()".to_string());
    analysis
        .export_signatures
        .insert("goaria_match".to_string(), "(i32, i32) -> i64".to_string());
    analysis.export_signatures.insert(
        "goaria_extract".to_string(),
        "(i32, i32) -> i64".to_string(),
    );

    let res = verify_wasm_and_manifest(&analysis, &manifest);
    assert!(
        matches!(res, Err(CheckError::InvalidExportSignature { name, expected, actual }) if name == "goaria_abi_version" && expected == "() -> i32" && actual == "() -> i64")
    );
}

#[test]
fn test_wasm_static_analyzer_disallowed_imports() {
    let manifest_str = include_str!("../../../examples/rust_fixture_pack/manifest.json");
    let manifest: Manifest = serde_json::from_str(manifest_str).expect("parse manifest");

    let base_analysis = WasmAnalysis {
        exports: [
            "goaria_abi_version",
            "goaria_alloc",
            "goaria_free",
            "goaria_match",
            "goaria_extract",
            "memory",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect(),
        export_signatures: [
            ("goaria_abi_version", "() -> i32"),
            ("goaria_alloc", "(i32) -> i32"),
            ("goaria_free", "(i32, i32) -> ()"),
            ("goaria_match", "(i32, i32) -> i64"),
            ("goaria_extract", "(i32, i32) -> i64"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect(),
        memory_exported: true,
        memory_count: 1,
        ..Default::default()
    };

    // 1. Non-func import (memory)
    let mut bad_import_analysis = base_analysis.clone();
    bad_import_analysis
        .non_func_imports
        .push(DisallowedImportInfo {
            module: "env".to_string(),
            name: "memory".to_string(),
            kind: "memory",
        });
    assert!(matches!(
        verify_wasm_and_manifest(&bad_import_analysis, &manifest),
        Err(CheckError::DisallowedImportType { .. })
    ));

    // 2. Foreign module function import
    let mut bad_mod_analysis = base_analysis.clone();
    bad_mod_analysis.imports.push((
        "env".to_string(),
        "print".to_string(),
        "(i32, i32) -> i64".to_string(),
    ));
    assert!(matches!(
        verify_wasm_and_manifest(&bad_mod_analysis, &manifest),
        Err(CheckError::ForbiddenImportModule { .. })
    ));

    // 3. Forbidden host function
    let mut bad_fn_analysis = base_analysis.clone();
    bad_fn_analysis.imports.push((
        "goaria_host".to_string(),
        "exec_cmd".to_string(),
        "(i32, i32) -> i64".to_string(),
    ));
    assert!(matches!(
        verify_wasm_and_manifest(&bad_fn_analysis, &manifest),
        Err(CheckError::ForbiddenImportFunction { .. })
    ));

    // 4. Missing capability for import
    let mut missing_cap_analysis = base_analysis;
    missing_cap_analysis.imports.push((
        "goaria_host".to_string(),
        "auth_profile_status".to_string(),
        "(i32, i32) -> i64".to_string(),
    ));
    assert!(matches!(
        verify_wasm_and_manifest(&missing_cap_analysis, &manifest),
        Err(CheckError::MissingCapabilityForImport { .. })
    ));
}

#[test]
fn test_wasm_static_analyzer_download_auth_imports() {
    use cargo_goaria_pack::manifest::Capability;

    let manifest_str = include_str!("../../../examples/rust_fixture_pack/manifest.json");
    let mut manifest: Manifest = serde_json::from_str(manifest_str).expect("parse manifest");

    let base_analysis = WasmAnalysis {
        exports: [
            "goaria_abi_version",
            "goaria_alloc",
            "goaria_free",
            "goaria_match",
            "goaria_extract",
            "memory",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect(),
        export_signatures: [
            ("goaria_abi_version", "() -> i32"),
            ("goaria_alloc", "(i32) -> i32"),
            ("goaria_free", "(i32, i32) -> ()"),
            ("goaria_match", "(i32, i32) -> i64"),
            ("goaria_extract", "(i32, i32) -> i64"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect(),
        memory_exported: true,
        memory_count: 1,
        ..Default::default()
    };

    // host_time requires no capability.
    let mut time_only = base_analysis.clone();
    time_only.imports.push((
        "goaria_host".to_string(),
        "host_time".to_string(),
        "(i32, i32) -> i64".to_string(),
    ));
    assert!(verify_wasm_and_manifest(&time_only, &manifest).is_ok());

    // register_download_auth requires cap.download.auth.
    let mut missing_cap = base_analysis.clone();
    missing_cap.imports.push((
        "goaria_host".to_string(),
        "register_download_auth".to_string(),
        "(i32, i32) -> i64".to_string(),
    ));
    assert!(matches!(
        verify_wasm_and_manifest(&missing_cap, &manifest),
        Err(CheckError::MissingCapabilityForImport { .. })
    ));

    // With the capability declared, both imports pass.
    manifest
        .capabilities
        .push(Capability("cap.download.auth".to_string()));
    let mut with_cap = base_analysis;
    with_cap.imports.push((
        "goaria_host".to_string(),
        "register_download_auth".to_string(),
        "(i32, i32) -> i64".to_string(),
    ));
    with_cap.imports.push((
        "goaria_host".to_string(),
        "host_time".to_string(),
        "(i32, i32) -> i64".to_string(),
    ));
    assert!(verify_wasm_and_manifest(&with_cap, &manifest).is_ok());
}

#[test]
fn test_pack_pipeline_on_fixture() {
    let fixture_dir = rust_fixture_dir();

    let temp_out = tempfile::tempdir().unwrap();

    let args = PackArgs {
        project_dir: fixture_dir,
        out_dir: temp_out.path().to_path_buf(),
        sign_key: None,
        asset_name: None,
        skip_build: true,
    };

    let zip_path = handle_pack(args).expect("handle_pack should succeed on fixture");
    assert!(zip_path.exists());
    assert!(temp_out.path().join("manifest.json").exists());
    assert!(temp_out.path().join("payload.wasm").exists());
    assert!(temp_out.path().join("manifest.sig").exists());
    assert!(temp_out.path().join("rust-fixture-pack.lock.json").exists());

    // Verify lockfile content
    let lock_raw =
        std::fs::read_to_string(temp_out.path().join("rust-fixture-pack.lock.json")).unwrap();
    let lock: LockFile = serde_json::from_str(&lock_raw).unwrap();
    assert!(!lock.packs[0].asset_path.contains('\\'));
}

#[test]
fn test_check_and_test_commands_on_fixture() {
    let fixture_dir = rust_fixture_dir();
    let wasm_path = rust_fixture_wasm_path();

    let check_args = CheckArgs {
        project_dir: fixture_dir.clone(),
        wasm: Some(wasm_path.clone()),
        manifest: None,
    };
    handle_check(check_args).expect("handle_check should succeed on fixture");

    let test_args = TestArgs {
        project_dir: fixture_dir,
        wasm: Some(wasm_path),
        manifest: None,
        live: false,
        fixtures: None,
    };
    handle_test(test_args).expect("handle_test should succeed on fixture");
}

#[test]
fn test_fixture_loading_errors_fail_test() {
    let fixture_dir = rust_fixture_dir();
    let wasm_path = rust_fixture_wasm_path();

    let temp_fixtures = tempfile::tempdir().unwrap();
    let corrupt_file = temp_fixtures.path().join("corrupt.json");
    std::fs::write(&corrupt_file, "{ invalid-json }").unwrap();

    let test_args = TestArgs {
        project_dir: fixture_dir.clone(),
        wasm: Some(wasm_path.clone()),
        manifest: None,
        live: false,
        fixtures: Some(temp_fixtures.path().to_path_buf()),
    };
    let res = handle_test(test_args);
    assert!(matches!(res, Err(TestCommandError::Fixture { .. })));

    // Bad base64
    let bad_b64_file = temp_fixtures.path().join("bad_b64.json");
    std::fs::write(
        &bad_b64_file,
        r#"{"url": "https://share.fixture.invalid/test", "body_base64": "!!!not-valid-base64!!!"}"#,
    )
    .unwrap();
    std::fs::remove_file(&corrupt_file).unwrap();

    let test_args_b64 = TestArgs {
        project_dir: fixture_dir.clone(),
        wasm: Some(wasm_path.clone()),
        manifest: None,
        live: false,
        fixtures: Some(temp_fixtures.path().to_path_buf()),
    };
    let res_b64 = handle_test(test_args_b64);
    assert!(matches!(res_b64, Err(TestCommandError::Fixture { .. })));

    for malformed in [
        r#"{"url":"https://share.fixture.invalid/test","status":"200"}"#,
        r#"{"url":"https://share.fixture.invalid/test","headers":{"x-test":["ok",7]}}"#,
        r#"{"url":"https://share.fixture.invalid/test","body_base64":7}"#,
    ] {
        std::fs::write(&bad_b64_file, malformed).unwrap();
        let result = handle_test(TestArgs {
            project_dir: fixture_dir.clone(),
            wasm: Some(wasm_path.clone()),
            manifest: None,
            live: false,
            fixtures: Some(temp_fixtures.path().to_path_buf()),
        });
        assert!(matches!(result, Err(TestCommandError::Fixture { .. })));
    }

    let missing_fixtures = temp_fixtures.path().join("missing");
    let missing_result = handle_test(TestArgs {
        project_dir: fixture_dir,
        wasm: Some(wasm_path),
        manifest: None,
        live: false,
        fixtures: Some(missing_fixtures),
    });
    assert!(matches!(
        missing_result,
        Err(TestCommandError::Fixture { message, .. }) if message.contains("does not exist")
    ));
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
