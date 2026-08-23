use std::net::IpAddr;
use std::path::PathBuf;

use cargo_goaria_pack::runner::host_broker::is_restricted_ip;
use cargo_goaria_pack::{
    Capability, DomainRule, Manifest, ManifestError, ResourceLimits, CAPABILITY_AUTH_PROFILE,
};
use goaria_extractor_sdk::types::{
    AuthSecretKind, HostAuthProfileStatusRequest, HostHTTPFetchRequest,
};

use cargo_goaria_pack::runner::{
    AuthProvider, ExtractorRunner, HostCallBudget, MemoryTracker, MockBroker, UrlPattern,
};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn cargo_target_dir() -> PathBuf {
    match std::env::var_os("CARGO_TARGET_DIR") {
        Some(configured) => {
            let configured = PathBuf::from(configured);
            if configured.is_absolute() {
                configured
            } else {
                workspace_root().join(configured)
            }
        }
        None => workspace_root().join("target"),
    }
}

fn rust_fixture_wasm_path() -> PathBuf {
    cargo_target_dir()
        .join("wasm32-unknown-unknown")
        .join("release")
        .join("rust_fixture_pack.wasm")
}

fn load_rust_fixture() -> (Vec<u8>, Manifest) {
    let wasm_path = rust_fixture_wasm_path();
    let wasm_bytes = std::fs::read(&wasm_path).unwrap_or_else(|error| {
        panic!(
            "failed to read Rust fixture WASM '{}': {error}; build it before running tests",
            wasm_path.display()
        )
    });
    let manifest_str = include_str!("../../../examples/rust_fixture_pack/manifest.json");
    let manifest: Manifest = serde_json::from_str(manifest_str).expect("parse rust manifest");

    (wasm_bytes, manifest)
}

fn load_zig_fixture() -> (Vec<u8>, Manifest) {
    let wasm_path = workspace_root()
        .join("examples")
        .join("zig_minimal_pack")
        .join("zig-out")
        .join("bin")
        .join("zig_minimal_pack.wasm");
    let wasm_bytes = std::fs::read(&wasm_path).unwrap_or_else(|error| {
        panic!(
            "failed to read Zig fixture WASM '{}': {error}; build it before running tests",
            wasm_path.display()
        )
    });
    let manifest_str = include_str!("../../../examples/zig_minimal_pack/manifest.json");
    let manifest: Manifest = serde_json::from_str(manifest_str).expect("parse zig manifest");

    (wasm_bytes, manifest)
}

#[test]
fn test_domain_rule_matching() {
    let exact_rule = DomainRule {
        host: "share.fixture.invalid".to_string(),
        include_subdomains: false,
    };
    assert!(exact_rule.matches_host("share.fixture.invalid"));
    assert!(!exact_rule.matches_host("sub.share.fixture.invalid"));
    assert!(!exact_rule.matches_host("other.fixture.invalid"));

    let wildcard_rule = DomainRule {
        host: "fixture.invalid".to_string(),
        include_subdomains: true,
    };
    assert!(wildcard_rule.matches_host("fixture.invalid"));
    assert!(wildcard_rule.matches_host("sub.fixture.invalid"));
    assert!(wildcard_rule.matches_host("deep.nested.sub.fixture.invalid"));
    assert!(!wildcard_rule.matches_host("other-fixture.invalid"));
}

#[test]
fn test_manifest_validation_logic() {
    let mut manifest = Manifest {
        pack_id: "".to_string(),
        pack_version: "0.1.0".to_string(),
        abi_version: 1,
        description: None,
        capabilities: vec![Capability::parse_wasm()],
        domains: Some(vec![DomainRule {
            host: "fixture.invalid".to_string(),
            include_subdomains: false,
        }]),
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
        Err(ManifestError::EmptyCapabilities)
    );

    manifest.capabilities.push(Capability::parse_wasm());
    manifest.resource_limits.max_memory_pages = 70_000;
    assert_eq!(
        manifest.validate_runnable(),
        Err(ManifestError::MemoryPagesExceeded(70_000))
    );
}

#[test]
fn test_manifest_deny_unknown_fields() {
    let json = r#"{
        "pack_id": "test-pack",
        "pack_version": "0.1.0",
        "abi_version": 1,
        "domains": [{"host": "fixture.invalid"}],
        "capabilities": ["cap.parse.wasm"],
        "resource_limits": {
            "timeout_millis": 5000,
            "max_memory_pages": 32,
            "max_host_calls": 50,
            "max_response_bytes": 1048576,
            "max_output_items": 50,
            "max_output_bytes": 1048576
        },
        "unknown_extra_field": "disallowed"
    }"#;
    let res: Result<Manifest, _> = serde_json::from_str(json);
    assert!(res.is_err());
}

#[test]
fn test_manifest_missing_required_fields_fails() {
    // Missing capabilities
    let json_missing_caps = r#"{
        "pack_id": "test-pack",
        "pack_version": "0.1.0",
        "abi_version": 1,
        "domains": [{"host": "fixture.invalid"}],
        "resource_limits": {
            "timeout_millis": 5000,
            "max_memory_pages": 32,
            "max_host_calls": 50,
            "max_response_bytes": 1048576,
            "max_output_items": 50,
            "max_output_bytes": 1048576
        }
    }"#;
    assert!(serde_json::from_str::<Manifest>(json_missing_caps).is_err());

    // Missing resource_limits
    let json_missing_limits = r#"{
        "pack_id": "test-pack",
        "pack_version": "0.1.0",
        "abi_version": 1,
        "domains": [{"host": "fixture.invalid"}],
        "capabilities": ["cap.parse.wasm"]
    }"#;
    assert!(serde_json::from_str::<Manifest>(json_missing_limits).is_err());

    // Missing field inside resource_limits
    let json_missing_subfield = r#"{
        "pack_id": "test-pack",
        "pack_version": "0.1.0",
        "abi_version": 1,
        "domains": [{"host": "fixture.invalid"}],
        "capabilities": ["cap.parse.wasm"],
        "resource_limits": {
            "timeout_millis": 5000,
            "max_memory_pages": 32,
            "max_host_calls": 50
        }
    }"#;
    assert!(serde_json::from_str::<Manifest>(json_missing_subfield).is_err());
}

#[test]
fn test_is_restricted_ip() {
    // IPv4 Restricted
    assert!(is_restricted_ip("127.0.0.1".parse::<IpAddr>().unwrap()));
    assert!(is_restricted_ip("10.0.0.1".parse::<IpAddr>().unwrap()));
    assert!(is_restricted_ip("172.16.0.1".parse::<IpAddr>().unwrap()));
    assert!(is_restricted_ip("192.168.1.1".parse::<IpAddr>().unwrap()));
    assert!(is_restricted_ip("169.254.1.1".parse::<IpAddr>().unwrap()));
    assert!(is_restricted_ip("100.64.0.1".parse::<IpAddr>().unwrap()));
    assert!(is_restricted_ip("192.0.2.1".parse::<IpAddr>().unwrap()));
    assert!(is_restricted_ip("0.0.0.0".parse::<IpAddr>().unwrap()));
    assert!(is_restricted_ip("0.1.2.3".parse::<IpAddr>().unwrap()));
    assert!(is_restricted_ip("224.0.0.1".parse::<IpAddr>().unwrap()));

    // IPv6 Restricted
    assert!(is_restricted_ip("::1".parse::<IpAddr>().unwrap()));
    assert!(is_restricted_ip("::".parse::<IpAddr>().unwrap()));
    assert!(is_restricted_ip("fe80::1".parse::<IpAddr>().unwrap()));
    assert!(is_restricted_ip("fc00::1".parse::<IpAddr>().unwrap()));
    assert!(is_restricted_ip("64:ff9b::1".parse::<IpAddr>().unwrap()));
    assert!(is_restricted_ip("64:ff9b:1::1".parse::<IpAddr>().unwrap()));
    assert!(is_restricted_ip("100::1".parse::<IpAddr>().unwrap()));
    assert!(is_restricted_ip("2001::1".parse::<IpAddr>().unwrap()));
    assert!(is_restricted_ip("2001:1ff::1".parse::<IpAddr>().unwrap()));
    assert!(is_restricted_ip("2001:db8::1".parse::<IpAddr>().unwrap()));
    assert!(is_restricted_ip("2002::1".parse::<IpAddr>().unwrap()));
    assert!(is_restricted_ip(
        "::ffff:127.0.0.1".parse::<IpAddr>().unwrap()
    ));

    // Public IPs (not restricted)
    assert!(!is_restricted_ip("8.8.8.8".parse::<IpAddr>().unwrap()));
    assert!(!is_restricted_ip("1.1.1.1".parse::<IpAddr>().unwrap()));
    assert!(!is_restricted_ip(
        "2606:4700:4700::1111".parse::<IpAddr>().unwrap()
    ));
}

#[test]
fn test_mock_broker_matching() {
    let mut broker = MockBroker::new();
    broker.add_rule(cargo_goaria_pack::runner::MockBrokerRule {
        pattern: UrlPattern::Exact("https://share.fixture.invalid/api/item/42".to_string()),
        status_code: 200,
        headers: Default::default(),
        body: serde_json::to_vec(&serde_json::json!({ "id": 42, "title": "Test Item" })).unwrap(),
    });

    broker.add_rule(cargo_goaria_pack::runner::MockBrokerRule {
        pattern: UrlPattern::Prefix("https://share.fixture.invalid/static/".to_string()),
        status_code: 200,
        headers: Default::default(),
        body: b"raw-data".to_vec(),
    });

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

    assert!(tracker.record_free(0x1000, 63).is_err());
    assert_eq!(tracker.active_allocations_count(), 2);
    assert_eq!(tracker.active_bytes(), 192);

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
    let (wasm_bytes, manifest) = load_rust_fixture();
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
    let (wasm_bytes, manifest) = load_zig_fixture();
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
