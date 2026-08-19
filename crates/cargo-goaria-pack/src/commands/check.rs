use std::path::{Path, PathBuf};
use colored::Colorize;
use crate::check::{analyze_wasm_bytecode, verify_wasm_and_manifest, CheckError};
use crate::cli::CheckArgs;
use crate::commands::build::{find_rust_wasm_binary, find_zig_wasm_binary};
use crate::manifest::Manifest;

pub fn resolve_manifest_and_wasm(
    project_dir: &Path,
    explicit_manifest: Option<&PathBuf>,
    explicit_wasm: Option<&PathBuf>,
) -> Result<(Manifest, PathBuf, Vec<u8>), CheckError> {
    let manifest_path = explicit_manifest
        .cloned()
        .unwrap_or_else(|| project_dir.join("manifest.json"));

    let manifest_str = std::fs::read_to_string(&manifest_path)?;
    let manifest: Manifest = serde_json::from_str(&manifest_str)?;

    let wasm_path = if let Some(p) = explicit_wasm {
        p.clone()
    } else {
        find_rust_wasm_binary(project_dir, true)
            .or_else(|_| find_zig_wasm_binary(project_dir))?
    };

    let wasm_bytes = std::fs::read(&wasm_path)?;

    Ok((manifest, wasm_path, wasm_bytes))
}

pub fn handle_check(args: CheckArgs) -> Result<(), CheckError> {
    let (manifest, wasm_path, wasm_bytes) =
        resolve_manifest_and_wasm(&args.project_dir, args.manifest.as_ref(), args.wasm.as_ref())?;

    println!(
        "{} manifest.json and WASM binary ({})...",
        "Checking:".cyan().bold(),
        wasm_path.display()
    );

    let analysis = analyze_wasm_bytecode(&wasm_bytes)?;
    verify_wasm_and_manifest(&analysis, &manifest)?;

    println!(
        "  {} Manifest syntax and schema valid (pack_id: '{}', version: '{}')",
        "[✓]".green(),
        manifest.pack_id,
        manifest.pack_version
    );
    println!(
        "  {} Required capability 'cap.parse.wasm' present",
        "[✓]".green()
    );
    println!(
        "  {} WASM binary parsed successfully ({} bytes)",
        "[✓]".green(),
        analysis.byte_size
    );
    println!(
        "  {} Exported functions verified: goaria_abi_version, goaria_alloc, goaria_free, goaria_match, goaria_extract",
        "[✓]".green()
    );
    println!(
        "  {} Exported linear memory 'memory' verified",
        "[✓]".green()
    );
    println!(
        "  {} Imported host functions ({}) aligned with capabilities",
        "[✓]".green(),
        analysis.imports.len()
    );

    println!(
        "{} All static analysis and schema checks passed!",
        "Success:".green().bold()
    );
    Ok(())
}
