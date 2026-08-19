use std::path::Path;

use cargo_goaria_pack::manifest::{
    Capability, DomainRule, Manifest, ManifestError, ResourceLimits, CAPABILITY_AUTH_PROFILE,
    CAPABILITY_HTTP_FETCH, CAPABILITY_PARSE_WASM,
};
use cargo_goaria_pack::runner::{
    AuthProvider, ExtractorRunner, HostCallBudget, MemoryTracker, MockBroker, UrlPattern,
};
use goaria_extractor_sdk::types::{
    AuthSecretKind, HostAuthProfileStatusRequest, HostHTTPFetchRequest,
};

fn find_fixture_wasm(candidates: &[&str]) -> Option<Vec<u8>> {
    for c in candidates {
        let p = Path::new(c);
        if p.exists() {
            if let Ok(bytes) = std::fs::read(p) {
                return Some(bytes);
            }
        }
    }
    None
}

fn load_rust_fixture() -> (Option<Vec<u8>>, Manifest) {
    let manifest_str = include_str!("../../../examples/rust_fixture_pack/manifest.json");
    let manifest: Manifest = serde_json::from_str(manifest_str).expect("parse rust manifest");

    let candidates = [
        "../../target/wasm32-unknown-unknown/release/rust_fixture_pack.wasm",
        "target/wasm32-unknown-unknown/release/rust_fixture_pack.wasm",
        "../../../target/wasm32-unknown-unknown/release/rust_fixture_pack.wasm",
        "../target/wasm32-unknown-unknown/release/rust_fixture_pack.wasm",
    ];
    let wasm_bytes = find_fixture_wasm(&candidates);
    (wasm_bytes, manifest)
}

fn load_zig_fixture() -> (Option<Vec<u8>>, Manifest) {
    let manifest_str = include_str!("../../../examples/zig_minimal_pack/manifest.json");
    let manifest: Manifest = serde_json::from_str(manifest_str).expect("parse zig manifest");

    let candidates = [
        "../../examples/zig_minimal_pack/zig-out/bin/zig_minimal_pack.wasm",
        "examples/zig_minimal_pack/zig-out/bin/zig_minimal_pack.wasm",
        "../../../examples/zig_minimal_pack/zig-out/bin/zig_minimal_pack.wasm",
        "../examples/zig_minimal_pack/zig-out/bin/zig_minimal_pack.wasm",
    ];
    let wasm_bytes = find_fixture_wasm(&candidates);
    (wasm_bytes, manifest)
}

#[test]
fn test_manifest_validation() {
    let manifest_str = include_str!("../../../examples/rust_fixture_pack/manifest.json");
    let manifest: Manifest = serde_json::from_str(manifest_str).unwrap();
    assert!(manifest.validate_runnable().is_ok());
    assert!(manifest.has_capability(CAPABILITY_PARSE_WASM));
    assert!(manifest.has_capability(CAPABILITY_HTTP_FETCH));
    assert!(manifest
        .allows_url("https://share.fixture.invalid/file/123")
        .unwrap());
    assert!(manifest
        .allows_url("https://sub.fixture.invalid/file/123")
        .unwrap());
    assert!(!manifest
        .allows_url("https://other-domain.invalid/file/123")
        .unwrap());
}

#[test]
fn test_manifest_error_conditions() {
    let mut manifest = Manifest {
        pack_id: "".to_string(),
        pack_version: "0.1.0".to_string(),
        abi_version: 1,
        description: None,
        capabilities: vec![Capability::parse_wasm()],
        domains: vec![DomainRule {
            host: "fixture.invalid".to_string(),
            include_subdomains: true,
        }],
        domain_policy_refs: None,
        broker_policy_refs: None,
        resource_limits: ResourceLimits::default(),
        payload_sha256: None,
    };

    assert_eq!(
        manifest.validate_runnable(),
        Err(ManifestError::EmptyPackId)
    );

    manifest.pack_id = "test-pack".to_string();
    manifest.abi_version = 99;
    assert_eq!(
        manifest.validate_runnable(),
        Err(ManifestError::AbiVersionMismatch {
            expected: 1,
            actual: 99
        })
    );

    manifest.abi_version = 1;
    manifest.capabilities.clear();
    assert_eq!(
        manifest.validate_runnable(),
        Err(ManifestError::MissingParseWasmCapability)
    );

    manifest.capabilities.push(Capability::parse_wasm());
    manifest.resource_limits.max_memory_pages = 70_000;
    assert_eq!(
        manifest.validate_runnable(),
        Err(ManifestError::MemoryPagesExceeded(70_000))
    );
}

#[test]
fn test_mock_broker_matching() {
    let mut broker = MockBroker::new();
    broker.add_mock_json(
        UrlPattern::Exact("https://share.fixture.invalid/api/item/42".to_string()),
        200,
        &serde_json::json!({ "id": 42, "title": "Test Item" }),
    );

    broker.add_mock_response(
        UrlPattern::Prefix("https://share.fixture.invalid/static/".to_string()),
        200,
        Default::default(),
        b"raw-data".to_vec(),
    );

    broker.add_mock_json(
        UrlPattern::EndpointRef {
            policy_ref: "pol-1".to_string(),
            endpoint_ref: "ep-1".to_string(),
        },
        200,
        &serde_json::json!({ "status": "ok" }),
    );

    let req_exact = HostHTTPFetchRequest {
        url: Some("https://share.fixture.invalid/api/item/42".to_string()),
        method: Some("GET".to_string()),
        ..Default::default()
    };
    let resp = broker
        .resolve(&req_exact)
        .expect("should resolve exact match");
    assert!(resp.ok);
    assert_eq!(resp.status_code, Some(200));

    let req_prefix = HostHTTPFetchRequest {
        url: Some("https://share.fixture.invalid/static/image.png".to_string()),
        method: Some("GET".to_string()),
        ..Default::default()
    };
    let resp_prefix = broker
        .resolve(&req_prefix)
        .expect("should resolve prefix match");
    assert!(resp_prefix.ok);

    let req_endpoint = HostHTTPFetchRequest {
        broker_policy_ref: Some("pol-1".to_string()),
        endpoint_ref: Some("ep-1".to_string()),
        ..Default::default()
    };
    let resp_ep = broker
        .resolve(&req_endpoint)
        .expect("should resolve endpoint match");
    assert!(resp_ep.ok);

    let req_unmatched = HostHTTPFetchRequest {
        url: Some("https://share.fixture.invalid/not-found".to_string()),
        ..Default::default()
    };
    assert!(broker.resolve(&req_unmatched).is_none());
}

#[test]
fn test_auth_provider_simulation() {
    let mut auth = AuthProvider::new();
    auth.add_profile(
        "default",
        true,
        AuthSecretKind::Bearer,
        "eyJh...",
        Some("secret_token_123".to_string()),
    );

    let manifest_str = include_str!("../../../examples/rust_fixture_pack/manifest.json");
    let mut manifest: Manifest = serde_json::from_str(manifest_str).unwrap();
    manifest
        .capabilities
        .push(Capability(CAPABILITY_AUTH_PROFILE.to_string()));

    let mut budget = HostCallBudget::new(10);
    let req = HostAuthProfileStatusRequest {
        auth_profile_ref: "default".to_string(),
        url: Some("https://share.fixture.invalid/api".to_string()),
        ..Default::default()
    };

    let resp = auth.handle_status(&manifest, &mut budget, req);
    assert!(resp.ok);
    assert_eq!(resp.available, Some(true));
    assert_eq!(resp.kind, Some(AuthSecretKind::Bearer));
    assert_eq!(resp.redacted_display.as_deref(), Some("eyJh..."));
    assert_eq!(
        auth.get_secret("default"),
        Some("secret_token_123".to_string())
    );

    // Missing profile
    let req_missing = HostAuthProfileStatusRequest {
        auth_profile_ref: "non-existent".to_string(),
        url: Some("https://share.fixture.invalid/api".to_string()),
        ..Default::default()
    };
    let resp_missing = auth.handle_status(&manifest, &mut budget, req_missing);
    assert!(resp_missing.ok);
    assert_eq!(resp_missing.available, Some(false));
}

#[test]
fn test_memory_tracker_leak_detection() {
    let mut tracker = MemoryTracker::new();
    tracker.record_alloc(0x1000, 64, "test_alloc_1");
    tracker.record_alloc(0x2000, 128, "test_alloc_2");
    assert_eq!(tracker.active_allocations_count(), 2);
    assert_eq!(tracker.active_bytes(), 192);

    assert!(tracker.check_leaks().is_err());

    tracker.record_free(0x1000, 64).unwrap();
    assert_eq!(tracker.active_allocations_count(), 1);
    assert_eq!(tracker.active_bytes(), 128);

    tracker.record_free(0x2000, 128).unwrap();
    assert_eq!(tracker.active_allocations_count(), 0);
    assert_eq!(tracker.active_bytes(), 0);
    assert!(tracker.check_leaks().is_ok());

    // Freeing unregistered address
    assert!(tracker.record_free(0x3000, 32).is_err());
}

#[test]
fn test_rust_fixture_wasm_runner() {
    let (wasm_opt, manifest) = load_rust_fixture();
    let wasm_bytes = match wasm_opt {
        Some(b) => b,
        None => {
            println!("Skipping test_rust_fixture_wasm_runner: wasm binary not found");
            return;
        }
    };

    let runner = ExtractorRunner::new(&wasm_bytes, manifest).expect("instantiate rust runner");

    // 1. Check ABI Version
    let abi_ver = runner.check_abi().expect("check_abi");
    assert_eq!(abi_ver, 1);

    // 2. Match valid URL
    let match_result = runner
        .match_url("https://share.fixture.invalid/files/42")
        .expect("match_url");
    assert!(match_result.matched);
    assert_eq!(match_result.confidence, Some(100));

    // 3. Match invalid URL
    let match_unrelated = runner
        .match_url("https://example.com/unrelated")
        .expect("match_url unrelated");
    assert!(!match_unrelated.matched);

    // 4. Extract
    let extract_result = runner
        .extract("https://share.fixture.invalid/files/42")
        .expect("extract");
    assert_eq!(extract_result.items.len(), 1);
    let item = &extract_result.items[0];
    assert_eq!(item.id.as_deref(), Some("fixture-item-001"));
    assert_eq!(
        item.url.as_deref(),
        Some("https://download.fixture.invalid/artifact.bin")
    );
    assert_eq!(item.filename.as_deref(), Some("artifact.bin"));
    assert_eq!(item.size_bytes, Some(1024));
}

#[test]
fn test_zig_fixture_wasm_runner() {
    let (wasm_opt, manifest) = load_zig_fixture();
    let wasm_bytes = match wasm_opt {
        Some(b) => b,
        None => {
            println!("Skipping test_zig_fixture_wasm_runner: wasm binary not found");
            return;
        }
    };

    let runner = ExtractorRunner::new(&wasm_bytes, manifest).expect("instantiate zig runner");

    // 1. Check ABI Version
    let abi_ver = runner.check_abi().expect("check_abi");
    assert_eq!(abi_ver, 1);

    // 2. Match valid URL
    let match_result = runner
        .match_url("https://share.fixture.invalid/files/42")
        .expect("match_url");
    assert!(match_result.matched);
    assert_eq!(match_result.confidence, Some(100));

    // 3. Match invalid URL
    let match_unrelated = runner
        .match_url("https://example.com/unrelated")
        .expect("match_url unrelated");
    assert!(!match_unrelated.matched);

    // 4. Extract
    let extract_result = runner
        .extract("https://share.fixture.invalid/files/42")
        .expect("extract");
    assert_eq!(extract_result.items.len(), 1);
    let item = &extract_result.items[0];
    assert_eq!(item.id.as_deref(), Some("zig-item-001"));
    assert_eq!(
        item.url.as_deref(),
        Some("https://download.fixture.invalid/artifact.bin")
    );
    assert_eq!(item.filename.as_deref(), Some("artifact.bin"));
    assert_eq!(item.size_bytes, Some(2048));
}
