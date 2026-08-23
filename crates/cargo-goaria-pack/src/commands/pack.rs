use crate::check::{analyze_wasm_bytecode, verify_wasm_and_manifest, CheckError};
use crate::cli::PackArgs;
use crate::commands::build::{
    build_wasm, detect_project_type, find_rust_wasm_binary, find_zig_wasm_binary, BuildError,
    ProjectType,
};
use crate::manifest::Manifest;
use crate::pack::crypto::{
    generate_keypair, parse_signing_key, sha256_hex, sign_manifest, verify_manifest_signature,
    CryptoError,
};
use crate::pack::lock::{LockEntry, LockFile};
use crate::pack::zip::{build_deterministic_pack_zip, ZipPackError};
use colored::Colorize;
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PackCommandError {
    #[error("build error: {0}")]
    Build(#[from] BuildError),
    #[error("check error: {0}")]
    Check(#[from] CheckError),
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("zip packaging error: {0}")]
    Zip(#[from] ZipPackError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid asset filename '{0}': must be a valid single leaf filename ending with .pack.zip and without path traversal")]
    InvalidAssetName(String),
}

fn validate_asset_name(name: &str) -> Result<(), PackCommandError> {
    let mut components = Path::new(name).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(_)), None) if name.ends_with(".pack.zip") => Ok(()),
        _ => Err(PackCommandError::InvalidAssetName(name.to_string())),
    }
}

pub fn handle_pack(args: PackArgs) -> Result<PathBuf, PackCommandError> {
    let project_dir = &args.project_dir;
    let out_dir = &args.out_dir;
    std::fs::create_dir_all(out_dir)?;

    // 1. Build WASM if needed
    let wasm_path = if args.skip_build {
        let proj_type = detect_project_type(project_dir)?;
        match proj_type {
            ProjectType::Rust => find_rust_wasm_binary(project_dir, true)?,
            ProjectType::Zig => find_zig_wasm_binary(project_dir)?,
        }
    } else {
        build_wasm(project_dir, true)?
    };
    let wasm_bytes = std::fs::read(&wasm_path)?;

    // 2. Read and parse manifest.json
    let manifest_path = project_dir.join("manifest.json");
    let manifest_raw = std::fs::read_to_string(&manifest_path)?;
    let mut manifest: Manifest = serde_json::from_str(&manifest_raw)?;

    // 3. Compute payload SHA256 and update manifest
    let payload_sha = sha256_hex(&wasm_bytes);
    manifest.payload_sha256 = Some(payload_sha.clone());

    // 4. Run static analysis check
    let analysis = analyze_wasm_bytecode(&wasm_bytes)?;
    verify_wasm_and_manifest(&analysis, &manifest)?;

    // 5. Serialize canonical manifest.json (2-space indented + newline)
    let canonical_manifest_json = {
        let mut s = serde_json::to_string_pretty(&manifest)?;
        s.push('\n');
        s.into_bytes()
    };
    let manifest_sha = sha256_hex(&canonical_manifest_json);

    // 6. Sign manifest
    let (signing_key, verifying_key) = if let Some(key_str) = &args.sign_key {
        let sk = parse_signing_key(key_str)?;
        let vk = sk.verifying_key();
        (sk, vk)
    } else {
        println!(
            "{} No signing key specified via --sign-key; generating ephemeral developer key...",
            "Warning:".yellow().bold()
        );
        generate_keypair()
    };
    let pub_key_hex = hex::encode(verifying_key.to_bytes());

    let signature = sign_manifest(&signing_key, &canonical_manifest_json);
    let sig_bytes = signature.to_bytes();
    let sig_sha = sha256_hex(&sig_bytes);

    // Self-verify signature
    verify_manifest_signature(&verifying_key, &canonical_manifest_json, &sig_bytes)?;

    // 7. Build deterministic .pack.zip
    let zip_bytes =
        build_deterministic_pack_zip(&canonical_manifest_json, &wasm_bytes, &sig_bytes)?;
    let asset_sha = sha256_hex(&zip_bytes);

    // 8. Determine and validate asset filenames
    let zip_name = args
        .asset_name
        .unwrap_or_else(|| format!("{}-{}.pack.zip", manifest.pack_id, manifest.pack_version));
    validate_asset_name(&zip_name)?;

    let zip_path = out_dir.join(&zip_name);
    let lock_path = out_dir.join(format!("{}.lock.json", manifest.pack_id));

    // 9. Write outputs
    std::fs::write(&zip_path, &zip_bytes)?;
    std::fs::write(out_dir.join("manifest.json"), &canonical_manifest_json)?;
    std::fs::write(out_dir.join("payload.wasm"), &wasm_bytes)?;
    std::fs::write(out_dir.join("manifest.sig"), sig_bytes)?;

    // 10. Generate companion lockfile
    let lock_entry = LockEntry {
        pack_id: manifest.pack_id.clone(),
        pack_version: manifest.pack_version.clone(),
        asset_url: None,
        asset_path: zip_name.replace('\\', "/"),
        asset_sha256: asset_sha.clone(),
        public_keys: vec![pub_key_hex.clone()],
        manifest_sha256: Some(manifest_sha.clone()),
        payload_sha256: Some(payload_sha.clone()),
        signature_sha256: Some(sig_sha.clone()),
    };
    let lock_file = LockFile::single_entry(lock_entry);
    std::fs::write(&lock_path, lock_file.to_canonical_json()?)?;

    // 11. Summary
    println!(
        "{} Successfully built and packaged extractor pack:",
        "Pack Complete:".green().bold()
    );
    println!("  Pack ID:         {}", manifest.pack_id.cyan());
    println!("  Pack Version:    {}", manifest.pack_version);
    println!("  Asset File:      {}", zip_path.display());
    println!("  Asset SHA256:    {}", asset_sha.yellow());
    println!("  Public Key:      {}", pub_key_hex);
    println!("  Manifest SHA256: {}", manifest_sha);
    println!("  Payload SHA256:  {}", payload_sha);
    println!("  Sig SHA256:      {}", sig_sha);
    println!("  Lock File:       {}", lock_path.display());

    Ok(zip_path)
}
