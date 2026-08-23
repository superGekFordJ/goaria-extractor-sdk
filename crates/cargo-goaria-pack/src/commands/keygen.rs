use crate::cli::KeygenArgs;
use crate::pack::crypto::{generate_keypair, CryptoError};
use colored::Colorize;
use std::io::Write;
use std::path::{Path, PathBuf};

fn resolve_output_path(path: &Path) -> std::io::Result<PathBuf> {
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "key output path must include a file name",
        )
    })?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    let parent = match parent {
        Some(parent) if parent.is_absolute() => parent.to_path_buf(),
        Some(parent) => std::env::current_dir()?.join(parent),
        None => std::env::current_dir()?,
    };
    Ok(parent.canonicalize()?.join(file_name))
}

fn write_secure_file(path: &Path, content: &str) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(path)?;
    file.write_all(content.as_bytes())?;
    file.sync_all()
}

fn write_new_file(path: &Path, content: &str) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)?;
    file.write_all(content.as_bytes())?;
    file.sync_all()
}

pub fn handle_keygen(args: KeygenArgs) -> Result<(), CryptoError> {
    let out_seed = args
        .out_seed
        .as_ref()
        .ok_or(CryptoError::MissingPrivateSeedOutput)?;
    if let Some(out_pub) = &args.out_pub {
        if resolve_output_path(out_seed)? == resolve_output_path(out_pub)? {
            return Err(CryptoError::ConflictingKeyOutputPaths);
        }
    }

    let (signing_key, verifying_key) = generate_keypair();
    let seed_hex = hex::encode(signing_key.to_bytes());
    let pub_hex = hex::encode(verifying_key.to_bytes());

    write_secure_file(out_seed, &seed_hex)?;

    println!(
        "{} Generated new Ed25519 pack signing keypair:",
        "Keygen:".green().bold()
    );
    println!(
        "  {} Created private seed file {} (seed was not printed)",
        "[✓]".green(),
        out_seed.display()
    );
    println!("  {}  {}", "Public Key Hex:".cyan().bold(), pub_hex);

    if let Some(out_pub) = &args.out_pub {
        write_new_file(out_pub, &pub_hex)?;
        println!(
            "  {} Saved public key to {}",
            "[✓]".green(),
            out_pub.display()
        );
    }

    Ok(())
}
