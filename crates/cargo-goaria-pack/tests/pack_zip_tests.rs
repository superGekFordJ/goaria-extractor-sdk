use std::io::{Cursor, Read};
use zip::CompressionMethod;
use cargo_goaria_pack::pack::{build_deterministic_pack_zip, sha256_hex, ZipPackError};

#[test]
fn test_deterministic_zip_reproducibility() {
    let manifest_bytes = br#"{
  "pack_id": "test-pack",
  "pack_version": "0.1.0",
  "abi_version": 1,
  "domains": [
    {
      "host": "fixture.invalid",
      "include_subdomains": true
    }
  ],
  "capabilities": [
    "cap.parse.wasm"
  ],
  "resource_limits": {
    "timeout_millis": 5000,
    "max_memory_pages": 32,
    "max_host_calls": 50,
    "max_response_bytes": 1048576,
    "max_output_items": 50,
    "max_output_bytes": 1048576
  }
}
"#;
    let payload_bytes = b"\x00asm\x01\x00\x00\x00fake-wasm-bytecode";
    let sig_bytes = &[42u8; 64];

    let zip1 = build_deterministic_pack_zip(manifest_bytes, payload_bytes, sig_bytes).unwrap();
    let zip2 = build_deterministic_pack_zip(manifest_bytes, payload_bytes, sig_bytes).unwrap();

    assert_eq!(zip1, zip2, "Deterministic zip output must be byte-for-byte identical");
    assert_eq!(sha256_hex(&zip1), sha256_hex(&zip2));
}

#[test]
fn test_deterministic_zip_structure_and_metadata() {
    let manifest_bytes = b"{\"pack_id\":\"test\"}\n";
    let payload_bytes = b"\x00asm\x01\x00\x00\x00";
    let sig_bytes = &[7u8; 64];

    let zip_data = build_deterministic_pack_zip(manifest_bytes, payload_bytes, sig_bytes).unwrap();

    let mut archive = zip::ZipArchive::new(Cursor::new(&zip_data)).unwrap();
    assert_eq!(archive.len(), 3);

    // 1. manifest.json
    {
        let mut file = archive.by_index(0).unwrap();
        assert_eq!(file.name(), "manifest.json");
        assert_eq!(file.compression(), CompressionMethod::Stored);
        let last_mod = file.last_modified().expect("last_modified");
        assert_eq!(last_mod.year(), 2026);
        assert_eq!(last_mod.month(), 1);
        assert_eq!(last_mod.day(), 1);
        assert_eq!(last_mod.hour(), 0);
        assert_eq!(last_mod.minute(), 0);
        assert_eq!(last_mod.second(), 0);
        #[cfg(unix)]
        assert_eq!(file.unix_mode(), Some(0o644));
        let mut content = Vec::new();
        file.read_to_end(&mut content).unwrap();
        assert_eq!(content, manifest_bytes);
    }

    // 2. payload.wasm
    {
        let mut file = archive.by_index(1).unwrap();
        assert_eq!(file.name(), "payload.wasm");
        assert_eq!(file.compression(), CompressionMethod::Stored);
        let mut content = Vec::new();
        file.read_to_end(&mut content).unwrap();
        assert_eq!(content, payload_bytes);
    }

    // 3. manifest.sig
    {
        let mut file = archive.by_index(2).unwrap();
        assert_eq!(file.name(), "manifest.sig");
        assert_eq!(file.compression(), CompressionMethod::Stored);
        let mut content = Vec::new();
        file.read_to_end(&mut content).unwrap();
        assert_eq!(content, sig_bytes);
    }
}

#[test]
fn test_deterministic_zip_empty_entries_error() {
    let dummy = b"test";
    assert!(matches!(
        build_deterministic_pack_zip(b"", dummy, dummy),
        Err(ZipPackError::EmptyEntry(name)) if name == "manifest.json"
    ));
    assert!(matches!(
        build_deterministic_pack_zip(dummy, b"", dummy),
        Err(ZipPackError::EmptyEntry(name)) if name == "payload.wasm"
    ));
    assert!(matches!(
        build_deterministic_pack_zip(dummy, dummy, b""),
        Err(ZipPackError::EmptyEntry(name)) if name == "manifest.sig"
    ));
}
