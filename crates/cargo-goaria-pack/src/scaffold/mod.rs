pub mod rust;
pub mod zig;

use crate::cli::Language;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScaffoldError {
    #[error("directory '{0}' already exists and is not empty")]
    DirectoryNotEmpty(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid pack name '{0}': must contain only lowercase letters, digits, hyphens, and underscores")]
    InvalidPackName(String),
}

pub fn validate_pack_name(name: &str) -> Result<(), ScaffoldError> {
    if name.is_empty() || name.len() > 50 {
        return Err(ScaffoldError::InvalidPackName(name.to_string()));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        return Err(ScaffoldError::InvalidPackName(name.to_string()));
    }
    Ok(())
}

pub fn scaffold_project(
    name: &str,
    lang: Language,
    target_dir: &Path,
) -> Result<(), ScaffoldError> {
    validate_pack_name(name)?;

    if target_dir.exists() {
        let mut entries = std::fs::read_dir(target_dir)?;
        if entries.next().is_some() {
            return Err(ScaffoldError::DirectoryNotEmpty(
                target_dir.display().to_string(),
            ));
        }
    } else {
        std::fs::create_dir_all(target_dir)?;
    }

    match lang {
        Language::Rust => rust::generate(name, target_dir)?,
        Language::Zig => zig::generate(name, target_dir)?,
    }

    Ok(())
}
