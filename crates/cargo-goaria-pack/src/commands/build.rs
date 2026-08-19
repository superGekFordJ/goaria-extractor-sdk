use std::path::{Path, PathBuf};
use std::process::Command;
use colored::Colorize;
use thiserror::Error;
use crate::cli::BuildArgs;

#[derive(Debug, Error)]
pub enum BuildError {
    #[error("neither Cargo.toml nor build.zig found in '{0}'")]
    NoProjectFound(String),
    #[error("build command failed with status: {0}")]
    CommandFailed(std::process::ExitStatus),
    #[error("I/O error executing compiler: {0}")]
    Io(#[from] std::io::Error),
    #[error("compiled WASM binary not found at expected location: '{0}'")]
    WasmNotFound(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectType {
    Rust,
    Zig,
}

pub fn detect_project_type(project_dir: &Path) -> Result<ProjectType, BuildError> {
    if project_dir.join("Cargo.toml").exists() {
        Ok(ProjectType::Rust)
    } else if project_dir.join("build.zig").exists() {
        Ok(ProjectType::Zig)
    } else {
        Err(BuildError::NoProjectFound(project_dir.display().to_string()))
    }
}

pub fn build_wasm(project_dir: &Path, release: bool) -> Result<PathBuf, BuildError> {
    let proj_type = detect_project_type(project_dir)?;
    match proj_type {
        ProjectType::Rust => build_rust_wasm(project_dir, release),
        ProjectType::Zig => build_zig_wasm(project_dir, release),
    }
}

fn build_rust_wasm(project_dir: &Path, release: bool) -> Result<PathBuf, BuildError> {
    println!(
        "{} compiling Rust WebAssembly module (target: wasm32-unknown-unknown)...",
        "Building:".cyan().bold()
    );
    let mut cmd = Command::new("cargo");
    cmd.arg("build")
        .arg("--target")
        .arg("wasm32-unknown-unknown")
        .current_dir(project_dir);
    if release {
        cmd.arg("--release");
    }

    let status = cmd.status()?;
    if !status.success() {
        return Err(BuildError::CommandFailed(status));
    }

    find_rust_wasm_binary(project_dir, release)
}

fn build_zig_wasm(project_dir: &Path, release: bool) -> Result<PathBuf, BuildError> {
    println!(
        "{} compiling Zig WebAssembly module...",
        "Building:".cyan().bold()
    );
    let mut cmd = Command::new("zig");
    cmd.arg("build").current_dir(project_dir);
    if release {
        cmd.arg("-Doptimize=ReleaseSmall");
    }

    let status = cmd.status()?;
    if !status.success() {
        return Err(BuildError::CommandFailed(status));
    }

    find_zig_wasm_binary(project_dir)
}

fn get_project_candidate_names(project_dir: &Path) -> Vec<String> {
    let mut names = Vec::new();

    // 1. Check manifest.json for pack_id
    if let Ok(content) = std::fs::read_to_string(project_dir.join("manifest.json")) {
        if let Ok(manifest) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(pack_id) = manifest.get("pack_id").and_then(|v| v.as_str()) {
                let pack_id_clean = pack_id.trim();
                if !pack_id_clean.is_empty() {
                    names.push(pack_id_clean.replace('-', "_"));
                    names.push(pack_id_clean.to_string());
                }
            }
        }
    }

    // 2. Check Cargo.toml for package name
    if let Ok(content) = std::fs::read_to_string(project_dir.join("Cargo.toml")) {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("name") && trimmed.contains('=') {
                if let Some(val) = trimmed.split('=').nth(1) {
                    let name = val.trim().trim_matches('"').trim_matches('\'').trim();
                    if !name.is_empty() {
                        names.push(name.replace('-', "_"));
                        names.push(name.to_string());
                    }
                }
                break;
            }
        }
    }

    // 3. Check directory name
    if let Some(dir_name) = project_dir.file_name().and_then(|s| s.to_str()) {
        names.push(dir_name.replace('-', "_"));
        names.push(dir_name.to_string());
    }

    names.dedup();
    names
}

pub fn find_rust_wasm_binary(project_dir: &Path, release: bool) -> Result<PathBuf, BuildError> {
    let mode = if release { "release" } else { "debug" };
    let candidate_names = get_project_candidate_names(project_dir);

    let search_dirs = [
        project_dir
            .join("target")
            .join("wasm32-unknown-unknown")
            .join(mode),
        project_dir
            .join("..")
            .join("target")
            .join("wasm32-unknown-unknown")
            .join(mode),
        project_dir
            .join("..")
            .join("..")
            .join("target")
            .join("wasm32-unknown-unknown")
            .join(mode),
    ];

    for target_dir in &search_dirs {
        if target_dir.exists() {
            // First check specific candidate names
            for name in &candidate_names {
                let candidate_path = target_dir.join(format!("{}.wasm", name));
                if candidate_path.exists() && candidate_path.is_file() {
                    return Ok(candidate_path);
                }
            }
            // Fall back to any .wasm in directory
            if let Some(wasm) = find_wasm_in_dir(target_dir)? {
                return Ok(wasm);
            }
        }
    }

    Err(BuildError::WasmNotFound(search_dirs[0].display().to_string()))
}

pub fn find_zig_wasm_binary(project_dir: &Path) -> Result<PathBuf, BuildError> {
    let candidate_names = get_project_candidate_names(project_dir);

    let search_dirs = [
        project_dir.join("zig-out").join("bin"),
        project_dir.join("..").join("zig-out").join("bin"),
    ];

    for target_dir in &search_dirs {
        if target_dir.exists() {
            for name in &candidate_names {
                let candidate_path = target_dir.join(format!("{}.wasm", name));
                if candidate_path.exists() && candidate_path.is_file() {
                    return Ok(candidate_path);
                }
            }
            if let Some(wasm) = find_wasm_in_dir(target_dir)? {
                return Ok(wasm);
            }
        }
    }

    Err(BuildError::WasmNotFound(search_dirs[0].display().to_string()))
}

fn find_wasm_in_dir(dir: &Path) -> Result<Option<PathBuf>, BuildError> {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("wasm") {
                return Ok(Some(path));
            }
        }
    }
    Ok(None)
}

pub fn handle_build(args: BuildArgs) -> Result<PathBuf, BuildError> {
    let wasm_path = build_wasm(&args.project_dir, args.release)?;
    let size = std::fs::metadata(&wasm_path)?.len();
    println!(
        "{} Built WASM binary: {} ({} bytes)",
        "Success:".green().bold(),
        wasm_path.display(),
        size
    );
    Ok(wasm_path)
}
