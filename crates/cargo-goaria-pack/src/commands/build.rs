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

pub fn find_rust_wasm_binary(project_dir: &Path, release: bool) -> Result<PathBuf, BuildError> {
    let mode = if release { "release" } else { "debug" };
    // Check local target directory
    let local_target = project_dir
        .join("target")
        .join("wasm32-unknown-unknown")
        .join(mode);
    if local_target.exists() {
        if let Some(wasm) = find_wasm_in_dir(&local_target)? {
            return Ok(wasm);
        }
    }
    // Check parent target directory if in workspace
    let parent_target = project_dir
        .join("..")
        .join("target")
        .join("wasm32-unknown-unknown")
        .join(mode);
    if parent_target.exists() {
        if let Some(wasm) = find_wasm_in_dir(&parent_target)? {
            return Ok(wasm);
        }
    }
    // Check workspace root target directory
    let ws_target = project_dir
        .join("..")
        .join("..")
        .join("target")
        .join("wasm32-unknown-unknown")
        .join(mode);
    if ws_target.exists() {
        if let Some(wasm) = find_wasm_in_dir(&ws_target)? {
            return Ok(wasm);
        }
    }

    Err(BuildError::WasmNotFound(local_target.display().to_string()))
}

pub fn find_zig_wasm_binary(project_dir: &Path) -> Result<PathBuf, BuildError> {
    let zig_out = project_dir.join("zig-out").join("bin");
    if zig_out.exists() {
        if let Some(wasm) = find_wasm_in_dir(&zig_out)? {
            return Ok(wasm);
        }
    }
    Err(BuildError::WasmNotFound(zig_out.display().to_string()))
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
