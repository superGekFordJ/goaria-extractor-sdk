use std::path::PathBuf;
use colored::Colorize;
use crate::cli::SignArgs;
use crate::pack::crypto::{parse_signing_key, sha256_hex, sign_manifest, CryptoError};

pub fn handle_sign(args: SignArgs) -> Result<PathBuf, CryptoError> {
    let signing_key = parse_signing_key(&args.key)?;
    let verifying_key = signing_key.verifying_key();
    let pub_hex = hex::encode(verifying_key.to_bytes());

    let manifest_bytes = std::fs::read(&args.manifest)?;
    let signature = sign_manifest(&signing_key, &manifest_bytes);
    let sig_bytes = signature.to_bytes();

    let out_path = args.out.unwrap_or_else(|| {
        args.manifest
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("manifest.sig")
    });

    std::fs::write(&out_path, sig_bytes)?;
    let sig_sha = sha256_hex(&sig_bytes);

    println!(
        "{} Signed manifest: {}",
        "Success:".green().bold(),
        args.manifest.display()
    );
    println!("  Public Key:    {}", pub_hex);
    println!("  Signature SHA: {}", sig_sha);
    println!("  Output File:   {}", out_path.display());

    Ok(out_path)
}
