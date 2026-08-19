use crate::cli::KeygenArgs;
use crate::pack::crypto::{generate_keypair, CryptoError};
use colored::Colorize;

pub fn handle_keygen(args: KeygenArgs) -> Result<(), CryptoError> {
    let (signing_key, verifying_key) = generate_keypair();
    let seed_hex = hex::encode(signing_key.to_bytes());
    let pub_hex = hex::encode(verifying_key.to_bytes());

    println!(
        "{} Generated new Ed25519 pack signing keypair:",
        "Keygen:".green().bold()
    );
    println!(
        "  {} {}",
        "Private Seed Hex (Secret):".yellow().bold(),
        seed_hex
    );
    println!("  {}  {}", "Public Key Hex:".cyan().bold(), pub_hex);

    if let Some(out_seed) = args.out_seed {
        std::fs::write(&out_seed, &seed_hex)?;
        println!("  Saved seed to {}", out_seed.display());
    }
    if let Some(out_pub) = args.out_pub {
        std::fs::write(&out_pub, &pub_hex)?;
        println!("  Saved public key to {}", out_pub.display());
    }

    Ok(())
}
