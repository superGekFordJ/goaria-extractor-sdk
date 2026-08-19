use std::io::{Cursor, Write};
use thiserror::Error;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, DateTime, ZipWriter};

#[derive(Debug, Error)]
pub enum ZipPackError {
    #[error("ZIP error: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("zip entry '{0}' is empty")]
    EmptyEntry(String),
}

/// Constructs a strictly deterministic .pack.zip archive.
///
/// Properties:
/// - Method: Stored (uncompressed)
/// - Fixed Timestamp: 2026-01-01T00:00:00Z
/// - Mode: 0o644
/// - Sequence: manifest.json, payload.wasm, manifest.sig
pub fn build_deterministic_pack_zip(
    manifest_json: &[u8],
    payload_wasm: &[u8],
    manifest_sig: &[u8],
) -> Result<Vec<u8>, ZipPackError> {
    if manifest_json.is_empty() {
        return Err(ZipPackError::EmptyEntry("manifest.json".to_string()));
    }
    if payload_wasm.is_empty() {
        return Err(ZipPackError::EmptyEntry("payload.wasm".to_string()));
    }
    if manifest_sig.is_empty() {
        return Err(ZipPackError::EmptyEntry("manifest.sig".to_string()));
    }

    let buffer = Cursor::new(Vec::new());
    let mut writer = ZipWriter::new(buffer);

    let fixed_time = DateTime::from_date_and_time(2026, 1, 1, 0, 0, 0)
        .map_err(|_| ZipPackError::EmptyEntry("invalid fixed datetime".to_string()))?;

    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .unix_permissions(0o644)
        .last_modified_time(fixed_time);

    // 1. Entry: manifest.json
    writer.start_file("manifest.json", options)?;
    writer.write_all(manifest_json)?;

    // 2. Entry: payload.wasm
    writer.start_file("payload.wasm", options)?;
    writer.write_all(payload_wasm)?;

    // 3. Entry: manifest.sig
    writer.start_file("manifest.sig", options)?;
    writer.write_all(manifest_sig)?;

    let finished = writer.finish()?;
    Ok(finished.into_inner())
}
