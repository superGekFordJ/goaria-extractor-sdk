use std::path::{Path, PathBuf};
use std::process::Command;

use cargo_goaria_pack::cli::{Language, NewArgs, SdkSource};
use cargo_goaria_pack::commands::new::handle_new;
use cargo_goaria_pack::scaffold::sdk_assets::{
    zig_package_name, VENDORED_MACRO_CARGO_TOML, VENDORED_SDK_CARGO_TOML,
};
use cargo_goaria_pack::scaffold::{resolve_sdk_spec, scaffold_project, ScaffoldError, SdkSpec};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn assert_no_vendor_line(gitignore: &str) {
    for line in gitignore.lines() {
        assert!(
            !line.trim().contains("vendor"),
            "gitignore must not exclude vendor/: {line}"
        );
    }
}

#[test]
fn test_rust_vendor_scaffolds_flattened_sdk() {
    let temp = tempfile::tempdir().unwrap();
    let project_dir = temp.path().join("my_rust_pack");

    let spec = resolve_sdk_spec(Language::Rust, None, None, None).unwrap();
    assert!(matches!(spec, SdkSpec::Vendor));
    scaffold_project("my_rust_pack", Language::Rust, &project_dir, &spec).unwrap();

    let cargo_toml = read(&project_dir.join("Cargo.toml"));
    assert!(cargo_toml.contains("path = \"vendor/goaria-extractor-sdk\""));

    let sdk_toml = read(&project_dir.join("vendor/goaria-extractor-sdk/Cargo.toml"));
    assert!(!sdk_toml.contains("workspace"));
    assert!(sdk_toml.contains("version = \"0.1.0\""));

    let macro_toml = read(&project_dir.join("vendor/goaria-extractor-macro/Cargo.toml"));
    assert!(macro_toml.contains("proc-macro = true"));
    assert!(!macro_toml.contains("workspace"));

    for file in [
        "abi", "alloc", "broker", "error", "host", "lib", "prelude", "traits", "types",
    ] {
        assert!(
            project_dir
                .join(format!("vendor/goaria-extractor-sdk/src/{file}.rs"))
                .exists(),
            "missing vendored src/{file}.rs"
        );
    }
    assert!(project_dir
        .join("vendor/goaria-extractor-macro/src/lib.rs")
        .exists());
    assert!(project_dir.join("vendor/README.md").exists());
    assert!(!project_dir
        .join("vendor/goaria-extractor-sdk/tests")
        .exists());
    assert!(!project_dir
        .join("vendor/goaria-extractor-macro/tests")
        .exists());

    assert_no_vendor_line(&read(&project_dir.join(".gitignore")));
}

#[test]
fn test_rust_git_and_ref_dependency() {
    let temp = tempfile::tempdir().unwrap();

    let project_dir = temp.path().join("plain_git");
    let spec = resolve_sdk_spec(Language::Rust, Some(SdkSource::Git), None, None).unwrap();
    scaffold_project("plain_git", Language::Rust, &project_dir, &spec).unwrap();
    let cargo_toml = read(&project_dir.join("Cargo.toml"));
    assert!(cargo_toml.contains("git = \"https://github.com/superGekFordJ/goaria-extractor-sdk\""));
    assert!(!project_dir.join("vendor").exists());

    let project_dir = temp.path().join("ref_git");
    let spec = resolve_sdk_spec(
        Language::Rust,
        Some(SdkSource::Git),
        Some("v0.2.0".to_string()),
        None,
    )
    .unwrap();
    scaffold_project("ref_git", Language::Rust, &project_dir, &spec).unwrap();
    let cargo_toml = read(&project_dir.join("Cargo.toml"));
    assert!(cargo_toml.contains("git = \"https://github.com/superGekFordJ/goaria-extractor-sdk\""));
    assert!(cargo_toml.contains("rev = \"v0.2.0\""));
    assert!(!project_dir.join("vendor").exists());
}

#[test]
fn test_rust_crates_dependency() {
    let temp = tempfile::tempdir().unwrap();
    let project_dir = temp.path().join("crates_pack");

    let spec = resolve_sdk_spec(Language::Rust, Some(SdkSource::Crates), None, None).unwrap();
    scaffold_project("crates_pack", Language::Rust, &project_dir, &spec).unwrap();

    let cargo_toml = read(&project_dir.join("Cargo.toml"));
    assert!(cargo_toml.contains("goaria-extractor-sdk = \"0.1.0\""));
    assert!(!project_dir.join("vendor").exists());
}

#[test]
fn test_rust_sdk_path_dependency() {
    let temp = tempfile::tempdir().unwrap();
    let project_dir = temp.path().join("path_pack");
    let sdk_dir = workspace_root().join("crates").join("goaria-extractor-sdk");

    let spec = resolve_sdk_spec(Language::Rust, None, None, Some(sdk_dir.clone())).unwrap();
    scaffold_project("path_pack", Language::Rust, &project_dir, &spec).unwrap();

    let cargo_toml = read(&project_dir.join("Cargo.toml"));
    let canonical = sdk_dir
        .canonicalize()
        .unwrap()
        .display()
        .to_string()
        .replace('\\', "/")
        .replace("//?/", "");
    assert!(cargo_toml.contains(&format!("path = \"{canonical}\"")));
    assert!(!cargo_toml.contains('\\'));
    assert!(!project_dir.join("vendor").exists());
}

#[test]
fn test_zig_vendor_scaffolds_goaria_sdk() {
    let temp = tempfile::tempdir().unwrap();
    let project_dir = temp.path().join("my_zig_pack");

    let spec = resolve_sdk_spec(Language::Zig, None, None, None).unwrap();
    scaffold_project("my-zig-pack", Language::Zig, &project_dir, &spec).unwrap();

    let vendored_zon = read(&project_dir.join("vendor/goaria_sdk/build.zig.zon"));
    assert!(vendored_zon.contains(".name = .goaria_sdk"));
    assert!(vendored_zon.contains(".fingerprint"));
    for file in ["abi", "host", "root", "types"] {
        assert!(project_dir
            .join(format!("vendor/goaria_sdk/src/{file}.zig"))
            .exists());
    }
    assert!(project_dir.join("vendor/goaria_sdk/build.zig").exists());
    assert!(!project_dir.join("vendor/goaria_sdk/.zig-cache").exists());

    let zon = read(&project_dir.join("build.zig.zon"));
    assert!(zon.contains(".name = .my_zig_pack"));
    assert!(zon.contains(".minimum_zig_version = \"0.16.0\""));
    assert!(zon.contains(".goaria_sdk = .{"));
    assert!(zon.contains(".path = \"vendor/goaria_sdk\""));

    let main_zig = read(&project_dir.join("src/main.zig"));
    assert!(main_zig.contains("@import(\"goaria_sdk\")"));
    assert!(main_zig.contains("exportExtractor"));

    let build_zig = read(&project_dir.join("build.zig"));
    assert!(build_zig.contains("b.dependency(\"goaria_sdk\""));
    assert!(build_zig.contains(".name = \"my_zig_pack\""));

    assert_no_vendor_line(&read(&project_dir.join(".gitignore")));
}

#[test]
fn test_zig_fingerprint_matches_zon_name() {
    let temp = tempfile::tempdir().unwrap();
    let project_dir = temp.path().join("fp_pack");

    scaffold_project("fp-pack", Language::Zig, &project_dir, &SdkSpec::Vendor).unwrap();

    let zon = read(&project_dir.join("build.zig.zon"));
    let fp_str = zon
        .split(".fingerprint = 0x")
        .nth(1)
        .and_then(|rest| rest.split(|c: char| !c.is_ascii_hexdigit()).next())
        .expect("fingerprint literal");
    let fp = u64::from_str_radix(fp_str, 16).unwrap();
    assert_eq!(fp >> 32, crc32fast::hash(b"fp_pack") as u64);
    assert_ne!(fp & 0xffff_ffff, 0);
}

#[test]
fn test_zig_package_name_fallbacks() {
    assert_eq!(zig_package_name("my-zig-pack"), "my_zig_pack");
    assert_eq!(zig_package_name("test"), "pack_test");
    assert_eq!(zig_package_name("error"), "pack_error");
    assert_eq!(zig_package_name("3d-pack"), "pack_3d_pack");

    let temp = tempfile::tempdir().unwrap();
    let project_dir = temp.path().join("test_pack_proj");
    scaffold_project("test", Language::Zig, &project_dir, &SdkSpec::Vendor).unwrap();
    let zon = read(&project_dir.join("build.zig.zon"));
    assert!(zon.contains(".name = .pack_test"));
}

#[test]
fn test_zig_git_and_crates_rejected() {
    for source in [SdkSource::Git, SdkSource::Crates] {
        let res = resolve_sdk_spec(Language::Zig, Some(source), None, None);
        assert!(
            matches!(res, Err(ScaffoldError::UnsupportedSdkSource { .. })),
            "expected UnsupportedSdkSource for --sdk {source}"
        );
    }

    let temp = tempfile::tempdir().unwrap();
    let project_dir = temp.path().join("zig_git");
    let output = Command::new(env!("CARGO_BIN_EXE_cargo-goaria-pack"))
        .args(["new", "zig-git", "--lang", "zig", "--sdk", "git", "--path"])
        .arg(&project_dir)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Error:"));
    assert!(!project_dir.exists() || std::fs::read_dir(&project_dir).unwrap().next().is_none());
}

#[test]
fn test_sdk_option_conflicts() {
    let res = resolve_sdk_spec(
        Language::Rust,
        Some(SdkSource::Vendor),
        Some("main".to_string()),
        None,
    );
    assert!(matches!(res, Err(ScaffoldError::ConflictingOptions(_))));

    let res = resolve_sdk_spec(Language::Rust, None, Some("main".to_string()), None);
    assert!(matches!(res, Err(ScaffoldError::ConflictingOptions(_))));

    let dir = PathBuf::from("irrelevant");
    let res = resolve_sdk_spec(
        Language::Rust,
        Some(SdkSource::Vendor),
        None,
        Some(dir.clone()),
    );
    assert!(matches!(res, Err(ScaffoldError::ConflictingOptions(_))));

    let res = resolve_sdk_spec(Language::Rust, None, Some("main".to_string()), Some(dir));
    assert!(matches!(res, Err(ScaffoldError::ConflictingOptions(_))));
}

#[test]
fn test_sdk_path_validation() {
    let temp = tempfile::tempdir().unwrap();
    let empty_dir = temp.path().join("empty");
    std::fs::create_dir_all(&empty_dir).unwrap();

    let res = resolve_sdk_spec(Language::Rust, None, None, Some(empty_dir.clone()));
    assert!(matches!(res, Err(ScaffoldError::InvalidSdkPath(..))));

    let res = resolve_sdk_spec(Language::Zig, None, None, Some(empty_dir));
    assert!(matches!(res, Err(ScaffoldError::InvalidSdkPath(..))));

    // Rust SDK dir without the sibling macro crate must be rejected.
    let fake_root = temp.path().join("fake_repo");
    let fake_sdk = fake_root.join("sdk_only");
    std::fs::create_dir_all(&fake_sdk).unwrap();
    std::fs::write(
        fake_sdk.join("Cargo.toml"),
        "[package]\nname = \"goaria-extractor-sdk\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    let res = resolve_sdk_spec(Language::Rust, None, None, Some(fake_sdk));
    assert!(matches!(res, Err(ScaffoldError::InvalidSdkPath(..))));

    // Zig SDK dir must name the goaria_sdk package.
    let fake_zig = temp.path().join("fake_zig");
    std::fs::create_dir_all(&fake_zig).unwrap();
    std::fs::write(fake_zig.join("build.zig.zon"), ".{ .name = .other }").unwrap();
    let res = resolve_sdk_spec(Language::Zig, None, None, Some(fake_zig));
    assert!(matches!(res, Err(ScaffoldError::InvalidSdkPath(..))));
}

#[test]
fn test_zig_sdk_path_copies_into_vendor() {
    let temp = tempfile::tempdir().unwrap();
    let project_dir = temp.path().join("zig_path_pack");
    let sdk_dir = workspace_root().join("sdk").join("zig");

    let spec = resolve_sdk_spec(Language::Zig, None, None, Some(sdk_dir)).unwrap();
    scaffold_project("zig-path-pack", Language::Zig, &project_dir, &spec).unwrap();

    let vendored_zon = read(&project_dir.join("vendor/goaria_sdk/build.zig.zon"));
    assert!(vendored_zon.contains(".name = .goaria_sdk"));
    assert!(!project_dir.join("vendor/goaria_sdk/.zig-cache").exists());

    let zon = read(&project_dir.join("build.zig.zon"));
    assert!(zon.contains(".path = \"vendor/goaria_sdk\""));
}

#[test]
fn test_vendored_manifest_versions_match_workspace() {
    let root_toml = read(&workspace_root().join("Cargo.toml"));

    let dep_version = |dep: &str| -> String {
        let prefix = format!("{dep} =");
        let line = root_toml
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with(&prefix))
            .unwrap_or_else(|| panic!("{dep} not found in workspace manifest"));
        let start = line.find('"').unwrap();
        let end = line[start + 1..].find('"').unwrap() + start + 1;
        line[start + 1..end].to_string()
    };

    let vendored_dep_line = |toml: &str, dep: &str| -> String {
        let prefix = format!("{dep} =");
        toml.lines()
            .map(str::trim)
            .find(|l| l.starts_with(&prefix))
            .unwrap_or_else(|| panic!("{dep} missing from vendored manifest"))
            .to_string()
    };

    for dep in ["serde", "serde_json", "base64"] {
        let version = dep_version(dep);
        assert!(
            vendored_dep_line(VENDORED_SDK_CARGO_TOML, dep).contains(&format!("\"{version}\"")),
            "vendored SDK manifest {dep} out of sync with workspace version {version}"
        );
    }
    for dep in ["proc-macro2", "quote", "syn"] {
        let version = dep_version(dep);
        assert!(
            vendored_dep_line(VENDORED_MACRO_CARGO_TOML, dep).contains(&format!("\"{version}\"")),
            "vendored macro manifest {dep} out of sync with workspace version {version}"
        );
    }
}

#[test]
fn test_new_command_reports_sdk_source() {
    let temp = tempfile::tempdir().unwrap();
    let project_dir = temp.path().join("demo-pack");
    let output = Command::new(env!("CARGO_BIN_EXE_cargo-goaria-pack"))
        .args(["new", "demo-pack", "--path"])
        .arg(&project_dir)
        .output()
        .unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("SDK source:"));
    assert!(stdout.contains("vendor"));
    assert!(project_dir
        .join("vendor/goaria-extractor-sdk/Cargo.toml")
        .exists());
}

fn make_fake_zig_sdk(root: &Path) -> PathBuf {
    let dir = root.join("fake_zig_sdk");
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::write(dir.join("build.zig"), "pub fn build() {}").unwrap();
    std::fs::write(
        dir.join("build.zig.zon"),
        ".{ .name = .goaria_sdk, .version = \"0.1.0\" }",
    )
    .unwrap();
    std::fs::write(dir.join("src").join("root.zig"), "pub const x = 1;").unwrap();
    dir
}

#[test]
fn test_zig_sdk_path_into_own_subtree_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let sdk_dir = make_fake_zig_sdk(temp.path());
    // Target lives inside the source dir — copying would recurse into itself.
    let project_dir = sdk_dir.join("new_pack");

    let spec = resolve_sdk_spec(Language::Zig, None, None, Some(sdk_dir.clone())).unwrap();
    let res = scaffold_project("new-pack", Language::Zig, &project_dir, &spec);
    assert!(
        matches!(res, Err(ScaffoldError::SdkPathContainsTarget(..))),
        "expected SdkPathContainsTarget, got {res:?}"
    );
    // The scaffolded dir was created by us and must be fully cleaned up.
    assert!(!project_dir.exists());
    assert!(!sdk_dir.join("vendor").exists());
}

#[test]
fn test_sdk_ref_rejects_toml_injection() {
    for bad in ["bad\"ref", "a b", "x\\y", "tab\tref", ""] {
        let res = resolve_sdk_spec(
            Language::Rust,
            Some(SdkSource::Git),
            Some(bad.to_string()),
            None,
        );
        assert!(
            matches!(res, Err(ScaffoldError::InvalidSdkRef(_))),
            "expected InvalidSdkRef for {bad:?}"
        );
    }
    // Commit SHAs, tags, and branch names still pass.
    for good in ["v0.2.0", "main", "abc1234", "feature/foo-bar"] {
        assert!(resolve_sdk_spec(
            Language::Rust,
            Some(SdkSource::Git),
            Some(good.to_string()),
            None,
        )
        .is_ok());
    }
}

#[test]
fn test_sdk_path_requires_real_package_marker() {
    // The workspace root manifest mentions the repo URL but is not the SDK crate.
    let res = resolve_sdk_spec(Language::Rust, None, None, Some(workspace_root()));
    assert!(matches!(res, Err(ScaffoldError::InvalidSdkPath(..))));

    let temp = tempfile::tempdir().unwrap();

    // Rust: right name but missing src/lib.rs.
    let fake_sdk = temp.path().join("fake_rust_sdk");
    std::fs::create_dir_all(&fake_sdk).unwrap();
    std::fs::write(
        fake_sdk.join("Cargo.toml"),
        "[package]
name = \"goaria-extractor-sdk\"
version = \"0.1.0\"
",
    )
    .unwrap();
    let res = resolve_sdk_spec(Language::Rust, None, None, Some(fake_sdk));
    assert!(matches!(res, Err(ScaffoldError::InvalidSdkPath(..))));

    // Zig: a lookalike package name must not pass.
    let fake_zig = temp.path().join("fake_zig");
    std::fs::create_dir_all(fake_zig.join("src")).unwrap();
    std::fs::write(fake_zig.join("build.zig"), "pub fn build() {}").unwrap();
    std::fs::write(fake_zig.join("src").join("root.zig"), "").unwrap();
    std::fs::write(
        fake_zig.join("build.zig.zon"),
        ".{ .name = .goaria_sdk_fork }",
    )
    .unwrap();
    let res = resolve_sdk_spec(Language::Zig, None, None, Some(fake_zig));
    assert!(matches!(res, Err(ScaffoldError::InvalidSdkPath(..))));

    // Zig: right name but missing src/root.zig.
    let fake_zig2 = temp.path().join("fake_zig2");
    std::fs::create_dir_all(&fake_zig2).unwrap();
    std::fs::write(fake_zig2.join("build.zig"), "pub fn build() {}").unwrap();
    std::fs::write(fake_zig2.join("build.zig.zon"), ".{ .name = .goaria_sdk }").unwrap();
    let res = resolve_sdk_spec(Language::Zig, None, None, Some(fake_zig2));
    assert!(matches!(res, Err(ScaffoldError::InvalidSdkPath(..))));
}

#[test]
fn test_new_validates_pack_name_before_sdk_io() {
    let temp = tempfile::tempdir().unwrap();
    let res = handle_new(NewArgs {
        name: "x".to_string(), // too short
        lang: Language::Rust,
        sdk: None,
        sdk_ref: None,
        sdk_path: Some(temp.path().join("nonexistent")),
        path: Some(temp.path().join("out")),
    });
    assert!(matches!(res, Err(ScaffoldError::InvalidPackName(_))));
}

fn collect_files(root: &Path, dir: &Path, out: &mut Vec<String>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        if entry.file_type().unwrap().is_dir() {
            if name == ".zig-cache" || name == "zig-out" || name == ".git" {
                continue;
            }
            collect_files(root, &entry.path(), out);
        } else {
            out.push(
                entry
                    .path()
                    .strip_prefix(root)
                    .unwrap()
                    .display()
                    .to_string()
                    .replace('\\', "/"),
            );
        }
    }
}

#[test]
fn test_embedded_sdk_tables_cover_source_trees() {
    use cargo_goaria_pack::scaffold::sdk_assets::{
        RUST_MACRO_FILES, RUST_SDK_FILES, ZIG_SDK_FILES,
    };

    let check = |dir: PathBuf,
                 files: &[cargo_goaria_pack::scaffold::sdk_assets::EmbeddedFile],
                 required_prefix: Option<&str>| {
        let mut on_disk = Vec::new();
        collect_files(&dir, &dir, &mut on_disk);
        let embedded: std::collections::BTreeSet<_> = files.iter().map(|f| f.rel_path).collect();
        for rel in on_disk {
            if let Some(prefix) = required_prefix {
                if !rel.starts_with(prefix) {
                    continue;
                }
            }
            assert!(
                embedded.contains(rel.as_str()),
                "{rel} exists in {} but is not embedded",
                dir.display()
            );
        }
        for rel in &embedded {
            assert!(dir.join(rel).exists(), "embedded {rel} missing on disk");
        }
    };

    // Rust vendoring covers src/ only; crate manifests are replaced by the
    // flattened VENDORED_*_CARGO_TOML templates and tests/ is excluded by design.
    check(
        workspace_root().join("crates/goaria-extractor-sdk"),
        RUST_SDK_FILES,
        Some("src/"),
    );
    check(
        workspace_root().join("crates/goaria-extractor-macro"),
        RUST_MACRO_FILES,
        Some("src/"),
    );
    check(
        workspace_root().join("sdk").join("zig"),
        ZIG_SDK_FILES,
        None,
    );
}
