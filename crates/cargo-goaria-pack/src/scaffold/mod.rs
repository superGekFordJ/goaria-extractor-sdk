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
    if !manifest.contains("goaria-extractor-sdk") {
        return Err(ScaffoldError::InvalidSdkPath(
            display,
            "Cargo.toml does not name the goaria-extractor-sdk package".to_string(),
        ));
    }
    let macro_toml = dir
        .join("..")
        .join("goaria-extractor-macro")
        .join("Cargo.toml");
    if !macro_toml.is_file() {
        return Err(ScaffoldError::InvalidSdkPath(
            dir.display().to_string(),
            format!(
                "sibling goaria-extractor-macro crate not found at '{}'",
                macro_toml.display()
            ),
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
    if !contents.contains("goaria_sdk") {
        return Err(ScaffoldError::InvalidSdkPath(
            display,
            "build.zig.zon does not define the goaria_sdk package".to_string(),
        ));
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
        let canonical = dir.canonicalize().unwrap_or(dir);
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
        (_, SdkSource::Git) => Ok(SdkSpec::Git { git_ref: sdk_ref }),
        (_, SdkSource::Crates) => Ok(SdkSpec::Crates),
    }
}

// Forward-slashed path for generated TOML/zon and console output;
// strips the Windows verbatim prefix produced by canonicalize().
pub(crate) fn forward_slash_path(dir: &Path) -> String {
    let mut s = dir.display().to_string().replace('\\', "/");
    if let Some(stripped) = s.strip_prefix("//?/") {
        s = stripped.to_string();
    }
    s
}

pub(crate) fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), ScaffoldError> {
    const SKIP_DIRS: &[&str] = &[".zig-cache", "zig-out", ".git"];
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let name = entry.file_name();
        let file_type = entry.file_type()?;
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

    let created = !target_dir.exists();
    if created {
        std::fs::create_dir_all(target_dir)?;
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
