use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid hex string: {0}")]
    HexDecode(#[from] hex::FromHexError),
    #[error("invalid Ed25519 key length: expected 32 bytes (64 hex chars), got {0} bytes")]
    InvalidKeyLength(usize),
    #[error("invalid Ed25519 signature format: {0}")]
    InvalidSignature(String),
    #[error("signature verification failed")]
    SignatureVerificationFailed,
    #[error("I/O error reading key: {0}")]
    Io(#[from] std::io::Error),
}

/// Generate a new cryptographically secure Ed25519 signing keypair.
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// Parse a signing key from a 64-character lowercase hex string or from a file path.
pub fn parse_signing_key(input: &str) -> Result<SigningKey, CryptoError> {
    let trimmed = input.trim();
    let p = Path::new(trimmed);
    let key_str = if p.exists() && p.is_file() {
        std::fs::read_to_string(p)?.trim().to_string()
    } else {
        trimmed.to_string()
    };

    let raw_bytes = hex::decode(&key_str)?;
    if raw_bytes.len() == 32 {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&raw_bytes);
        Ok(SigningKey::from_bytes(&seed))
    } else if raw_bytes.len() == 64 {
        let mut keypair_bytes = [0u8; 64];
        keypair_bytes.copy_from_slice(&raw_bytes);
        SigningKey::from_keypair_bytes(&keypair_bytes)
            .map_err(|e| CryptoError::InvalidSignature(e.to_string()))
    } else {
        Err(CryptoError::InvalidKeyLength(raw_bytes.len()))
    }
}

/// Parse a verifying (public) key from a 64-character lowercase hex string.
pub fn parse_verifying_key(hex_str: &str) -> Result<VerifyingKey, CryptoError> {
    let raw = hex::decode(hex_str.trim())?;
    if raw.len() != 32 {
        return Err(CryptoError::InvalidKeyLength(raw.len()));
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&raw);
    VerifyingKey::from_bytes(&bytes).map_err(|e| CryptoError::InvalidSignature(e.to_string()))
}

/// Sign canonical manifest JSON bytes with Ed25519.
pub fn sign_manifest(signing_key: &SigningKey, manifest_json: &[u8]) -> Signature {
    signing_key.sign(manifest_json)
}

/// Verify an Ed25519 signature over manifest JSON bytes.
pub fn verify_manifest_signature(
    verifying_key: &VerifyingKey,
    manifest_json: &[u8],
    signature_bytes: &[u8],
) -> Result<(), CryptoError> {
    if signature_bytes.len() != 64 {
        return Err(CryptoError::InvalidSignature(format!(
            "expected 64 signature bytes, got {}",
            signature_bytes.len()
        )));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(signature_bytes);
    let signature = Signature::from_bytes(&sig_arr);
    verifying_key
        .verify(manifest_json, &signature)
        .map_err(|_| CryptoError::SignatureVerificationFailed)
}

/// Compute lowercase 64-character SHA256 hex digest.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}
