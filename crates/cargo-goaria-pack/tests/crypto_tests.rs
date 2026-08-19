use cargo_goaria_pack::pack::{
    generate_keypair, parse_signing_key, parse_verifying_key, sha256_hex, sign_manifest,
    verify_manifest_signature, CryptoError,
};

#[test]
fn test_keygen_and_parsing() {
    let (signing_key, verifying_key) = generate_keypair();
    let seed_hex = hex::encode(signing_key.to_bytes());
    let pub_hex = hex::encode(verifying_key.to_bytes());

    assert_eq!(seed_hex.len(), 64);
    assert_eq!(pub_hex.len(), 64);

    let parsed_sign = parse_signing_key(&seed_hex).unwrap();
    assert_eq!(parsed_sign.to_bytes(), signing_key.to_bytes());

    let parsed_pub = parse_verifying_key(&pub_hex).unwrap();
    assert_eq!(parsed_pub.to_bytes(), verifying_key.to_bytes());
}

#[test]
fn test_key_file_parsing() {
    let (signing_key, _) = generate_keypair();
    let seed_hex = hex::encode(signing_key.to_bytes());

    let temp_dir = tempfile::tempdir().unwrap();
    let key_file = temp_dir.path().join("dev.key");
    std::fs::write(&key_file, format!("{}\n", seed_hex)).unwrap();

    let parsed_sign = parse_signing_key(key_file.to_str().unwrap()).unwrap();
    assert_eq!(parsed_sign.to_bytes(), signing_key.to_bytes());
}

#[test]
fn test_signing_and_verification_happy_path() {
    let (signing_key, verifying_key) = generate_keypair();
    let manifest_json = br#"{
  "pack_id": "test-pack",
  "pack_version": "0.1.0"
}
"#;

    let signature = sign_manifest(&signing_key, manifest_json);
    let sig_bytes = signature.to_bytes();
    assert_eq!(sig_bytes.len(), 64);

    let verify_result = verify_manifest_signature(&verifying_key, manifest_json, &sig_bytes);
    assert!(verify_result.is_ok());
}

#[test]
fn test_signing_tamper_detection() {
    let (signing_key, verifying_key) = generate_keypair();
    let manifest_json = b"{\"pack_id\":\"test-pack\"}";

    let signature = sign_manifest(&signing_key, manifest_json);
    let mut sig_bytes = signature.to_bytes();

    // 1. Tamper with manifest content
    let tampered_manifest = b"{\"pack_id\":\"tampered-pack\"}";
    let res1 = verify_manifest_signature(&verifying_key, tampered_manifest, &sig_bytes);
    assert!(matches!(res1, Err(CryptoError::SignatureVerificationFailed)));

    // 2. Tamper with signature bytes
    sig_bytes[0] ^= 0xFF;
    let res2 = verify_manifest_signature(&verifying_key, manifest_json, &sig_bytes);
    assert!(matches!(res2, Err(CryptoError::SignatureVerificationFailed)));

    // 3. Invalid signature length
    let res3 = verify_manifest_signature(&verifying_key, manifest_json, &sig_bytes[..32]);
    assert!(matches!(res3, Err(CryptoError::InvalidSignature(_))));
}

#[test]
fn test_sha256_hex() {
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256_hex(b"hello world"),
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    );
}
