pub mod rust;
pub mod sdk_assets;
pub mod zig;

use crate::cli::{Language, SdkSource};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScaffoldError {
    #[error("directory '{0}' already exists and is not empty")]
    DirectoryNotEmpty(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid pack name '{0}': must be 3-50 lowercase letters, digits, hyphens, or underscores, starting and ending with a letter or digit")]
    InvalidPackName(String),
    #[error("--sdk {sdk} is not supported for --lang {lang}: {reason}")]
    UnsupportedSdkSource {
        sdk: String,
        lang: String,
        reason: String,
    },
    #[error("conflicting options: {0}")]
    ConflictingOptions(String),
    #[error("--sdk-path '{0}' is not a valid goaria SDK package directory: {1}")]
    InvalidSdkPath(String, String),
    #[error("--sdk-path '{0}' contains the vendor destination '{1}': refusing to copy a directory into itself")]
    SdkPathContainsTarget(String, String),
    #[error("invalid --sdk-ref '{0}': must be non-empty and free of quotes, backslashes, whitespace, or control characters")]
    InvalidSdkRef(String),
    #[error("pack name '{0}' collides with a vendored SDK crate name; choose a different name")]
    ReservedPackName(String),
    #[error("'{0}' already exists and is not a directory")]
    NotADirectory(String),
}

#[derive(Debug, Clone)]
pub enum SdkSpec {
    Vendor,
    Git { git_ref: Option<String> },
    Crates,
    Path(PathBuf),
}

pub fn validate_pack_name(name: &str) -> Result<(), ScaffoldError> {
    if name.len() < 3 || name.len() > 50 {
        return Err(ScaffoldError::InvalidPackName(name.to_string()));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        return Err(ScaffoldError::InvalidPackName(name.to_string()));
    }
    let bytes = name.as_bytes();
    let valid_edge = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    if !valid_edge(bytes[0]) || !valid_edge(bytes[bytes.len() - 1]) {
        return Err(ScaffoldError::InvalidPackName(name.to_string()));
    }
    Ok(())
}

fn validate_rust_sdk_path(dir: &Path) -> Result<(), ScaffoldError> {
    let display = dir.display().to_string();
    let cargo_toml = dir.join("Cargo.toml");
    let manifest = std::fs::read_to_string(&cargo_toml).map_err(|_| {
        ScaffoldError::InvalidSdkPath(
            display.clone(),
            format!("missing readable Cargo.toml at '{}'", cargo_toml.display()),
        )
    })?;
    let name_re = regex::Regex::new(r#"(?m)^\s*name\s*=\s*"goaria-extractor-sdk""#).unwrap();
    if !name_re.is_match(&manifest) {
        return Err(ScaffoldError::InvalidSdkPath(
            display,
            "Cargo.toml does not declare name = \"goaria-extractor-sdk\"".to_string(),
        ));
    }
    if !dir.join("src").join("lib.rs").is_file() {
        return Err(ScaffoldError::InvalidSdkPath(
            dir.display().to_string(),
            "missing src/lib.rs".to_string(),
        ));
    }
    let macro_toml = dir
        .join("..")
        .join("goaria-extractor-macro")
        .join("Cargo.toml");
    let macro_manifest = std::fs::read_to_string(&macro_toml).map_err(|_| {
        ScaffoldError::InvalidSdkPath(
            dir.display().to_string(),
            format!(
                "sibling goaria-extractor-macro crate not found at '{}'",
                macro_toml.display()
            ),
        )
    })?;
    let macro_re = regex::Regex::new(r#"(?m)^\s*name\s*=\s*"goaria-extractor-macro""#).unwrap();
    if !macro_re.is_match(&macro_manifest) {
        return Err(ScaffoldError::InvalidSdkPath(
            dir.display().to_string(),
            "sibling Cargo.toml does not declare name = \"goaria-extractor-macro\"".to_string(),
        ));
    }
    Ok(())
}

fn validate_zig_sdk_path(dir: &Path) -> Result<(), ScaffoldError> {
    let display = dir.display().to_string();
    let zon = dir.join("build.zig.zon");
    let contents = std::fs::read_to_string(&zon).map_err(|_| {
        ScaffoldError::InvalidSdkPath(
            display.clone(),
            format!("missing readable build.zig.zon at '{}'", zon.display()),
        )
    })?;
    let name_re = regex::Regex::new(r"(?m)(?:^|[{,])\s*\.name\s*=\s*\.goaria_sdk\b").unwrap();
    if !name_re.is_match(&contents) {
        return Err(ScaffoldError::InvalidSdkPath(
            display,
            "build.zig.zon does not declare .name = .goaria_sdk".to_string(),
        ));
    }
    for required in ["build.zig", "src/root.zig"] {
        if !dir.join(required).is_file() {
            return Err(ScaffoldError::InvalidSdkPath(
                dir.display().to_string(),
                format!("missing {required}"),
            ));
        }
    }
    Ok(())
}

pub fn resolve_sdk_spec(
    lang: Language,
    sdk: Option<SdkSource>,
    sdk_ref: Option<String>,
    sdk_path: Option<PathBuf>,
) -> Result<SdkSpec, ScaffoldError> {
    if let Some(dir) = sdk_path {
        if sdk.is_some() {
            return Err(ScaffoldError::ConflictingOptions(
                "--sdk-path cannot be combined with an explicit --sdk".to_string(),
            ));
        }
        if sdk_ref.is_some() {
            return Err(ScaffoldError::ConflictingOptions(
                "--sdk-path cannot be combined with --sdk-ref".to_string(),
            ));
        }
        match lang {
            Language::Rust => validate_rust_sdk_path(&dir)?,
            Language::Zig => validate_zig_sdk_path(&dir)?,
        }
        let canonical = dir.canonicalize().map_err(|e| {
            ScaffoldError::InvalidSdkPath(
                dir.display().to_string(),
                format!("cannot canonicalize directory: {e}"),
            )
        })?;
        return Ok(SdkSpec::Path(canonical));
    }

    let source = sdk.unwrap_or(SdkSource::Vendor);
    if source != SdkSource::Git && sdk_ref.is_some() {
        return Err(ScaffoldError::ConflictingOptions(
            "--sdk-ref only applies to --sdk git".to_string(),
        ));
    }

    match (lang, source) {
        (Language::Zig, SdkSource::Git) => Err(ScaffoldError::UnsupportedSdkSource {
            sdk: source.to_string(),
            lang: lang.to_string(),
            reason: "zig .url dependencies fetch a repository root, but the zig SDK lives in \
                     the sdk/zig subdirectory; use --sdk vendor or --sdk-path instead"
                .to_string(),
        }),
        (Language::Zig, SdkSource::Crates) => Err(ScaffoldError::UnsupportedSdkSource {
            sdk: source.to_string(),
            lang: lang.to_string(),
            reason: "zig has no crates.io registry equivalent; use --sdk vendor or --sdk-path"
                .to_string(),
        }),
        (_, SdkSource::Vendor) => Ok(SdkSpec::Vendor),
        (_, SdkSource::Git) => {
            if let Some(git_ref) = &sdk_ref {
                let invalid = git_ref.is_empty()
                    || git_ref
                        .chars()
                        .any(|c| c == '"' || c == '\\' || c.is_whitespace() || c.is_control());
                if invalid {
                    return Err(ScaffoldError::InvalidSdkRef(git_ref.clone()));
                }
            }
            Ok(SdkSpec::Git { git_ref: sdk_ref })
        }
        (_, SdkSource::Crates) => Ok(SdkSpec::Crates),
    }
}

// Forward-slashed path for generated TOML/zon and console output;
// strips the Windows verbatim prefix produced by canonicalize().
pub(crate) fn forward_slash_path(dir: &Path) -> String {
    let mut s = dir.display().to_string().replace('\\', "/");
    if let Some(stripped) = s.strip_prefix("//?/") {
        s = match stripped.strip_prefix("UNC/") {
            Some(unc) => format!("//{unc}"),
            None => stripped.to_string(),
        };
    }
    s
}

fn canonical_loose(path: &Path) -> PathBuf {
    let mut missing = Vec::new();
    let mut cur = path.to_path_buf();
    loop {
        if let Ok(canonical) = cur.canonicalize() {
            let mut out = canonical;
            for comp in missing.iter().rev() {
                out.push(comp);
            }
            return out;
        }
        match cur.file_name() {
            Some(name) => {
                missing.push(name.to_os_string());
                cur = cur.parent().map(Path::to_path_buf).unwrap_or_default();
            }
            None => return path.to_path_buf(),
        }
    }
}

pub(crate) fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), ScaffoldError> {
    const SKIP_DIRS: &[&str] = &[".zig-cache", "zig-out", ".git", "target"];
    let canon_src = canonical_loose(src);
    let canon_dst = canonical_loose(dst);
    if canon_dst.starts_with(&canon_src) {
        return Err(ScaffoldError::SdkPathContainsTarget(
            forward_slash_path(&canon_src),
            forward_slash_path(dst),
        ));
    }
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let name = entry.file_name();
        let file_type = entry.file_type()?;
        // .git files (worktrees) and symlinks/junctions are skipped, not copied.
        if name == ".git" || file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            if name
                .to_str()
                .map(|n| SKIP_DIRS.contains(&n))
                .unwrap_or(false)
            {
                continue;
            }
            let dst_sub = dst.join(&name);
            std::fs::create_dir_all(&dst_sub)?;
            copy_dir_recursive(&entry.path(), &dst_sub)?;
        } else {
            std::fs::create_dir_all(dst)?;
            std::fs::copy(entry.path(), dst.join(&name))?;
        }
    }
    Ok(())
}

pub fn scaffold_project(
    name: &str,
    lang: Language,
    target_dir: &Path,
    sdk: &SdkSpec,
) -> Result<(), ScaffoldError> {
    validate_pack_name(name)?;

    if lang == Language::Rust && matches!(name, "goaria-extractor-sdk" | "goaria-extractor-macro") {
        return Err(ScaffoldError::ReservedPackName(name.to_string()));
    }

    let created = !target_dir.exists();
    if created {
        std::fs::create_dir_all(target_dir)?;
    } else if !target_dir.is_dir() {
        return Err(ScaffoldError::NotADirectory(
            target_dir.display().to_string(),
        ));
    } else {
        let mut entries = std::fs::read_dir(target_dir)?;
        if entries.next().is_some() {
            return Err(ScaffoldError::DirectoryNotEmpty(
                target_dir.display().to_string(),
            ));
        }
    }

    let result = match lang {
        Language::Rust => rust::generate(name, target_dir, sdk),
        Language::Zig => zig::generate(name, target_dir, sdk),
    };

    if result.is_err() && created {
        let _ = std::fs::remove_dir_all(target_dir);
    }
    result
}
