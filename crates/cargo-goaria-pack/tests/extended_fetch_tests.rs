//! Extended Fetch parity matrix against the host contract.
//! Basic layer B1-B13 runs without `cap.http.fetch.extended`; the extended
//! layer E1-E12 declares it. All assertions key on `error_code` and no test
//! performs real network I/O (Live cases terminate before transport).

use base64::Engine;
use cargo_goaria_pack::runner::HostCallBudget;
use cargo_goaria_pack::{
    AuthProvider, Capability, DomainRule, HostBroker, LiveBroker, Manifest, MockBroker,
    MockBrokerRule, MockRequestExpectation, ResourceLimits, UrlPattern, ValidatedFetchShape,
};
use goaria_extractor_sdk::types::HostHTTPFetchRequest;
use std::collections::BTreeMap;

const TEST_URL: &str = "https://share.fixture.invalid/api/item";

fn manifest(capabilities: &[&str], hosts: &[&str]) -> Manifest {
    Manifest {
        pack_id: "matrix-pack".to_string(),
        pack_version: "0.1.0".to_string(),
        abi_version: 1,
        description: None,
        capabilities: capabilities
            .iter()
            .map(|cap| Capability(cap.to_string()))
            .collect(),
        domains: Some(
            hosts
                .iter()
                .map(|host| DomainRule {
                    host: host.to_string(),
                    include_subdomains: false,
                })
                .collect(),
        ),
        domain_policy_refs: None,
        broker_policy_refs: None,
        resource_limits: ResourceLimits::default(),
        payload_sha256: None,
    }
}

fn basic_manifest() -> Manifest {
    manifest(&["cap.http.fetch"], &["share.fixture.invalid"])
}

fn extended_manifest() -> Manifest {
    manifest(
        &["cap.http.fetch", "cap.http.fetch.extended"],
        &[
            "share.fixture.invalid",
            "example.com",
            "127.0.0.1",
            "10.0.0.1",
            "192.0.2.1",
        ],
    )
}

fn alias_manifest(capabilities: &[&str]) -> Manifest {
    let mut m = manifest(capabilities, &[]);
    m.domains = Some(Vec::new());
    m.domain_policy_refs = Some(vec!["dpr-matrix".to_string()]);
    m.broker_policy_refs = Some(vec!["bpr-matrix".to_string()]);
    m
}

fn request() -> HostHTTPFetchRequest {
    HostHTTPFetchRequest {
        url: Some(TEST_URL.to_string()),
        ..Default::default()
    }
}

fn headers(entries: &[(&str, &str)]) -> Option<BTreeMap<String, String>> {
    Some(
        entries
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect(),
    )
}

fn run(
    broker: &HostBroker,
    manifest: &Manifest,
    req: HostHTTPFetchRequest,
    auth_provider: &AuthProvider,
) -> goaria_extractor_sdk::types::HostHTTPFetchResponse {
    let mut budget = HostCallBudget::new(8);
    broker.handle_fetch(manifest, &mut budget, req, auth_provider)
}

fn mock_with(rule: MockBrokerRule) -> HostBroker {
    let mut broker = MockBroker::new();
    broker.add_rule(rule);
    HostBroker::Mock(broker)
}

fn simple_hit_rule() -> MockBrokerRule {
    MockBrokerRule {
        pattern: UrlPattern::Exact(TEST_URL.to_string()),
        status_code: 200,
        headers: BTreeMap::new(),
        body: b"payload".to_vec(),
        expect: None,
    }
}

fn assert_code(
    resp: &goaria_extractor_sdk::types::HostHTTPFetchResponse,
    code: &str,
    context: &str,
) {
    assert!(
        !resp.ok,
        "{context}: expected failure with {code}, got ok response"
    );
    assert_eq!(
        resp.error_code.as_deref(),
        Some(code),
        "{context}: wrong error_code (message: {:?})",
        resp.message
    );
}

// ---------- Basic layer (no extended capability) ----------

#[test]
fn b1_basic_get_hits_mock_rule() {
    let resp = run(
        &mock_with(simple_hit_rule()),
        &basic_manifest(),
        request(),
        &AuthProvider::new(),
    );
    assert!(resp.ok, "message: {:?}", resp.message);
    assert_eq!(resp.status_code, Some(200));
    assert_eq!(resp.error_code, None);
}

#[test]
fn b2_lowercase_post_counts_as_extended() {
    let req = HostHTTPFetchRequest {
        method: Some("post".to_string()),
        ..request()
    };
    let resp = run(
        &HostBroker::Mock(MockBroker::new()),
        &basic_manifest(),
        req,
        &AuthProvider::new(),
    );
    assert_code(&resp, "policy_denied", "B2");
}

#[test]
fn b3_privileged_headers_require_extended_capability() {
    for name in ["X-User", "Authorization"] {
        let req = HostHTTPFetchRequest {
            headers: headers(&[(name, "v")]),
            ..request()
        };
        let resp = run(
            &HostBroker::Mock(MockBroker::new()),
            &basic_manifest(),
            req,
            &AuthProvider::new(),
        );
        assert_code(&resp, "policy_denied", name);
    }
}

#[test]
fn b4_legal_body_needs_extended_but_bad_base64_is_invalid_request() {
    let legal = HostHTTPFetchRequest {
        method: Some("POST".to_string()),
        headers: headers(&[("Content-Type", "application/json")]),
        body_base64: Some("aGk=".to_string()),
        ..request()
    };
    let resp = run(
        &HostBroker::Mock(MockBroker::new()),
        &basic_manifest(),
        legal,
        &AuthProvider::new(),
    );
    assert_code(&resp, "policy_denied", "B4 legal body");

    let illegal = HostHTTPFetchRequest {
        body_base64: Some("%%%".to_string()),
        ..request()
    };
    let resp = run(
        &HostBroker::Mock(MockBroker::new()),
        &basic_manifest(),
        illegal,
        &AuthProvider::new(),
    );
    assert_code(&resp, "invalid_request", "B4 bad base64");
}

#[test]
fn b5_safe_headers_pass_and_forbidden_names_fail() {
    // Safe five headers still reach the mock.
    let req = HostHTTPFetchRequest {
        headers: headers(&[
            ("Accept", "application/json"),
            ("Accept-Language", "en-US"),
            ("Content-Type", "application/json"),
            ("Referer", "https://share.fixture.invalid/"),
            ("User-Agent", "matrix-test"),
        ]),
        ..request()
    };
    let resp = run(
        &mock_with(simple_hit_rule()),
        &basic_manifest(),
        req,
        &AuthProvider::new(),
    );
    assert!(resp.ok, "B5 safe headers: {:?}", resp.message);

    for name in [
        "Range",
        "Accept-Encoding",
        "Cookie",
        "Content-Length",
        "Set-Cookie",
        "Host",
        "Connection",
        "Transfer-Encoding",
        "Proxy-Authorization",
    ] {
        let req = HostHTTPFetchRequest {
            headers: headers(&[(name, "v")]),
            ..request()
        };
        let resp = run(
            &HostBroker::Mock(MockBroker::new()),
            &basic_manifest(),
            req,
            &AuthProvider::new(),
        );
        assert_code(&resp, "fetch_failed", name);
    }

    // x-* is privileged, so it is gated at the capability step (same as B3).
    let req = HostHTTPFetchRequest {
        headers: headers(&[("x-api-key", "v")]),
        ..request()
    };
    let resp = run(
        &HostBroker::Mock(MockBroker::new()),
        &basic_manifest(),
        req,
        &AuthProvider::new(),
    );
    assert_code(&resp, "policy_denied", "B5 x-api-key");
}

#[test]
fn b6_referer_restored_and_range_rejected() {
    let req = HostHTTPFetchRequest {
        headers: headers(&[("Referer", "https://share.fixture.invalid/")]),
        ..request()
    };
    let resp = run(
        &mock_with(simple_hit_rule()),
        &basic_manifest(),
        req,
        &AuthProvider::new(),
    );
    assert!(resp.ok, "B6 referer: {:?}", resp.message);
}

#[test]
fn b7_error_status_fixtures_still_report_ok() {
    for status in [404, 500] {
        let resp = run(
            &mock_with(MockBrokerRule {
                status_code: status,
                ..simple_hit_rule()
            }),
            &basic_manifest(),
            request(),
            &AuthProvider::new(),
        );
        assert!(resp.ok, "B7 status {status} must report ok:true");
        assert_eq!(resp.status_code, Some(status));
        assert_eq!(resp.error_code, None);
    }
}

#[test]
fn b8_domain_miss_and_bad_url_are_fetch_failed() {
    let req = HostHTTPFetchRequest {
        url: Some("https://other.fixture.invalid/x".to_string()),
        ..Default::default()
    };
    let resp = run(
        &HostBroker::Mock(MockBroker::new()),
        &basic_manifest(),
        req,
        &AuthProvider::new(),
    );
    assert_code(&resp, "fetch_failed", "B8 domain miss");

    let req = HostHTTPFetchRequest {
        url: Some("::::".to_string()),
        ..Default::default()
    };
    let resp = run(
        &HostBroker::Mock(MockBroker::new()),
        &basic_manifest(),
        req,
        &AuthProvider::new(),
    );
    assert_code(&resp, "fetch_failed", "B8 malformed url");
}

#[test]
fn b9_raw_and_ref_mode_combinations() {
    let auth = AuthProvider::new();

    // url mixed with any ref-mode field
    for req in [
        HostHTTPFetchRequest {
            broker_policy_ref: Some("bpr-ok".to_string()),
            ..request()
        },
        HostHTTPFetchRequest {
            endpoint_ref: Some("ep-ok".to_string()),
            ..request()
        },
        HostHTTPFetchRequest {
            params: Some(BTreeMap::from([("k".to_string(), "v".to_string())])),
            ..request()
        },
    ] {
        let resp = run(
            &HostBroker::Mock(MockBroker::new()),
            &basic_manifest(),
            req,
            &auth,
        );
        assert_code(&resp, "invalid_request", "B9 url+ref mix");
    }

    // lone params / partial refs under legacy manifest
    for req in [
        HostHTTPFetchRequest {
            params: Some(BTreeMap::from([("k".to_string(), "v".to_string())])),
            ..Default::default()
        },
        HostHTTPFetchRequest {
            broker_policy_ref: Some("bpr-ok".to_string()),
            ..Default::default()
        },
        HostHTTPFetchRequest {
            endpoint_ref: Some("ep-ok".to_string()),
            ..Default::default()
        },
    ] {
        let resp = run(
            &HostBroker::Mock(MockBroker::new()),
            &basic_manifest(),
            req,
            &auth,
        );
        assert_code(&resp, "invalid_request", "B9 lone/partial refs");
    }

    // refs under a legacy (domains) manifest
    let req = HostHTTPFetchRequest {
        broker_policy_ref: Some("bpr-ok".to_string()),
        endpoint_ref: Some("ep-ok".to_string()),
        ..Default::default()
    };
    let resp = run(
        &HostBroker::Mock(MockBroker::new()),
        &basic_manifest(),
        req,
        &auth,
    );
    assert_code(&resp, "invalid_request", "B9 refs under legacy manifest");

    // url under an alias manifest
    let resp = run(
        &HostBroker::Mock(MockBroker::new()),
        &alias_manifest(&["cap.http.fetch"]),
        request(),
        &auth,
    );
    assert_code(&resp, "invalid_request", "B9 url under alias manifest");

    // empty request (no url, no refs)
    let resp = run(
        &HostBroker::Mock(MockBroker::new()),
        &basic_manifest(),
        HostHTTPFetchRequest::default(),
        &auth,
    );
    assert_code(&resp, "invalid_request", "B9 empty request");
}

#[test]
fn b10_auth_profile_ref_outcomes() {
    let auth = AuthProvider::new();

    // Invalid slug
    let req = HostHTTPFetchRequest {
        auth_profile_ref: Some("Bad_Slug".to_string()),
        ..request()
    };
    let resp = run(
        &HostBroker::Mock(MockBroker::new()),
        &manifest(
            &["cap.http.fetch", "cap.auth.profile"],
            &["share.fixture.invalid"],
        ),
        req,
        &auth,
    );
    assert_code(&resp, "invalid_request", "B10 bad slug");

    // Valid slug, missing cap.auth.profile: the capability gate lives inside
    // the broker's auth path, so the failure is authenticated_fetch_failed.
    let req = HostHTTPFetchRequest {
        auth_profile_ref: Some("my-prof".to_string()),
        ..request()
    };
    let resp = run(
        &HostBroker::Mock(MockBroker::new()),
        &basic_manifest(),
        req,
        &auth,
    );
    assert_code(&resp, "authenticated_fetch_failed", "B10 missing auth cap");

    // Valid slug, capability present, profile unregistered
    let req = HostHTTPFetchRequest {
        auth_profile_ref: Some("my-prof".to_string()),
        ..request()
    };
    let resp = run(
        &HostBroker::Mock(MockBroker::new()),
        &manifest(
            &["cap.http.fetch", "cap.auth.profile"],
            &["share.fixture.invalid"],
        ),
        req,
        &auth,
    );
    assert_code(
        &resp,
        "authenticated_fetch_failed",
        "B10 unregistered profile",
    );
}

#[test]
fn b11_negative_limits_invalid_and_zero_is_unset() {
    for req in [
        HostHTTPFetchRequest {
            timeout_millis: Some(-1),
            ..request()
        },
        HostHTTPFetchRequest {
            max_response_bytes: Some(-1),
            ..request()
        },
    ] {
        let resp = run(
            &HostBroker::Mock(MockBroker::new()),
            &basic_manifest(),
            req,
            &AuthProvider::new(),
        );
        assert_code(&resp, "invalid_request", "B11 negative limit");
    }

    // Zero values are treated as unset and reach the mock.
    let req = HostHTTPFetchRequest {
        timeout_millis: Some(0),
        max_response_bytes: Some(0),
        ..request()
    };
    let resp = run(
        &mock_with(simple_hit_rule()),
        &basic_manifest(),
        req,
        &AuthProvider::new(),
    );
    assert!(resp.ok, "B11 zero-as-unset: {:?}", resp.message);
}

// B12 (basic redirect hop decisions) is covered by the classify_response
// unit tests in host_broker.rs; B13 (decode-failure invalid_request) is
// covered by the engine.rs decode unit tests.

#[test]
fn broker_disabled_and_live_ref_mode_codes() {
    let resp = run(
        &HostBroker::Disabled,
        &basic_manifest(),
        request(),
        &AuthProvider::new(),
    );
    assert_code(&resp, "broker_disabled", "disabled broker");

    let req = HostHTTPFetchRequest {
        broker_policy_ref: Some("bpr-matrix".to_string()),
        endpoint_ref: Some("ep-matrix".to_string()),
        ..Default::default()
    };
    let resp = run(
        &HostBroker::Live(LiveBroker::new()),
        &alias_manifest(&["cap.http.fetch"]),
        req,
        &AuthProvider::new(),
    );
    assert_code(
        &resp,
        "ref_mode_not_supported_in_live_runner",
        "live ref mode",
    );
}

// ---------- Extended layer (cap.http.fetch + cap.http.fetch.extended) ----------

fn post_json_request() -> HostHTTPFetchRequest {
    HostHTTPFetchRequest {
        method: Some("POST".to_string()),
        headers: headers(&[
            ("Content-Type", "application/json"),
            ("Authorization", "Bearer synthetic-token-123"),
            ("X-User", "u1"),
        ]),
        body_base64: Some("aGk=".to_string()),
        ..request()
    }
}

#[test]
fn e1_post_body_and_privileged_headers_match_expect() {
    let rule = MockBrokerRule {
        expect: Some(MockRequestExpectation {
            method: Some("post".to_string()),
            headers: BTreeMap::from([
                ("content-type".to_string(), "application/json".to_string()),
                (
                    "authorization".to_string(),
                    "Bearer synthetic-token-123".to_string(),
                ),
                ("x-user".to_string(), "u1".to_string()),
            ]),
            body_base64: Some("aGk=".to_string()),
            ..Default::default()
        }),
        ..simple_hit_rule()
    };
    let resp = run(
        &mock_with(rule),
        &extended_manifest(),
        post_json_request(),
        &AuthProvider::new(),
    );
    assert!(resp.ok, "E1 full expect match: {:?}", resp.message);
    assert_eq!(resp.status_code, Some(200));
}

#[test]
fn e2_body_base64_shape_failures_are_invalid_request() {
    let oversized = base64::engine::general_purpose::STANDARD.encode(vec![7u8; 16 * 1024 + 1]);
    for encoded in [
        "aG k=",
        "aG\tk=",
        "aG\rk=",
        "aG\nk=",
        "aGk",
        oversized.as_str(),
    ] {
        let req = HostHTTPFetchRequest {
            method: Some("POST".to_string()),
            headers: headers(&[("Content-Type", "application/json")]),
            body_base64: Some(encoded.to_string()),
            ..request()
        };
        let resp = run(
            &HostBroker::Mock(MockBroker::new()),
            &extended_manifest(),
            req,
            &AuthProvider::new(),
        );
        assert_code(&resp, "invalid_request", "E2 body_base64 shape");
    }
}

#[test]
fn e3_body_method_and_content_type_rules() {
    // body on non-POST methods
    for method in ["GET", "HEAD"] {
        let req = HostHTTPFetchRequest {
            method: Some(method.to_string()),
            headers: headers(&[("Content-Type", "application/json")]),
            body_base64: Some("aGk=".to_string()),
            ..request()
        };
        let resp = run(
            &HostBroker::Mock(MockBroker::new()),
            &extended_manifest(),
            req,
            &AuthProvider::new(),
        );
        assert_code(&resp, "invalid_request", method);
    }

    // body without Content-Type
    let req = HostHTTPFetchRequest {
        method: Some("POST".to_string()),
        body_base64: Some("aGk=".to_string()),
        ..request()
    };
    let resp = run(
        &HostBroker::Mock(MockBroker::new()),
        &extended_manifest(),
        req,
        &AuthProvider::new(),
    );
    assert_code(&resp, "invalid_request", "E3 missing content-type");

    // two canonical Content-Type entries (counted on the raw map in shape
    // validation, before header-level duplicate detection)
    let req = HostHTTPFetchRequest {
        method: Some("POST".to_string()),
        headers: headers(&[
            ("content-type", "application/json"),
            ("Content-Type", "application/json"),
        ]),
        body_base64: Some("aGk=".to_string()),
        ..request()
    };
    let resp = run(
        &HostBroker::Mock(MockBroker::new()),
        &extended_manifest(),
        req,
        &AuthProvider::new(),
    );
    assert_code(&resp, "invalid_request", "E3 duplicate content-type");

    // disallowed media type
    let req = HostHTTPFetchRequest {
        method: Some("POST".to_string()),
        headers: headers(&[("Content-Type", "text/plain")]),
        body_base64: Some("aGk=".to_string()),
        ..request()
    };
    let resp = run(
        &HostBroker::Mock(MockBroker::new()),
        &extended_manifest(),
        req,
        &AuthProvider::new(),
    );
    assert_code(&resp, "invalid_request", "E3 bad media type");
}

#[test]
fn e4_malformed_pack_owned_authorization_fails() {
    for value in ["Bearer", " Bearer  x ", "Bearer  x", "Bad(scheme) v"] {
        let req = HostHTTPFetchRequest {
            headers: headers(&[("Authorization", value)]),
            ..request()
        };
        let resp = run(
            &HostBroker::Mock(MockBroker::new()),
            &extended_manifest(),
            req,
            &AuthProvider::new(),
        );
        assert_code(&resp, "fetch_failed", value);
    }
}

#[test]
fn e5_denied_extended_header_names_fail() {
    for name in [
        "x-forwarded-for",
        "x-real-ip",
        "x-client-cert",
        "x-client-cert-cn",
        "x-auth-user",
        "x-ms-client-principal",
        "x-proxy-foo",
        "x-goaria-x",
        "x-amzn-oidc-sub",
        "x-goog-iap-jwt",
    ] {
        let req = HostHTTPFetchRequest {
            headers: headers(&[(name, "v")]),
            ..request()
        };
        let resp = run(
            &HostBroker::Mock(MockBroker::new()),
            &extended_manifest(),
            req,
            &AuthProvider::new(),
        );
        assert_code(&resp, "fetch_failed", name);
    }
}

#[test]
fn e5_allowed_business_headers_pass_the_header_gate() {
    // Passing the header gate is proven by the mock asserting the exact
    // request header values.
    let allowed: &[(&str, &str)] = &[
        ("x-user", "u1"),
        ("x-username", "n1"),
        ("x-uid", "i1"),
        ("x-amzn-mkt-token", "t1"),
    ];
    let mut expect_headers = BTreeMap::new();
    for (name, value) in allowed {
        expect_headers.insert(name.to_string(), value.to_string());
    }
    let rule = MockBrokerRule {
        expect: Some(MockRequestExpectation {
            headers: expect_headers,
            ..Default::default()
        }),
        ..simple_hit_rule()
    };
    let req = HostHTTPFetchRequest {
        headers: headers(allowed),
        ..request()
    };
    let resp = run(
        &mock_with(rule),
        &extended_manifest(),
        req,
        &AuthProvider::new(),
    );
    assert!(resp.ok, "E5 allowed headers: {:?}", resp.message);
}

#[test]
fn e6_header_count_value_and_duplication_limits() {
    // canonical duplicate
    let req = HostHTTPFetchRequest {
        headers: headers(&[("authorization", "Bearer a"), ("Authorization", "Bearer b")]),
        ..request()
    };
    let resp = run(
        &HostBroker::Mock(MockBroker::new()),
        &extended_manifest(),
        req,
        &AuthProvider::new(),
    );
    assert_code(&resp, "fetch_failed", "E6 canonical dup");

    // 17 headers exceeds the count cap
    let many: Vec<(String, String)> = (0..17)
        .map(|i| (format!("x-h{i:02}"), "v".to_string()))
        .collect();
    let req = HostHTTPFetchRequest {
        headers: Some(many.into_iter().collect()),
        ..request()
    };
    let resp = run(
        &HostBroker::Mock(MockBroker::new()),
        &extended_manifest(),
        req,
        &AuthProvider::new(),
    );
    assert_code(&resp, "fetch_failed", "E6 header count");

    // oversized value
    let long = "v".repeat(1025);
    let req = HostHTTPFetchRequest {
        headers: headers(&[("x-big", long.as_str())]),
        ..request()
    };
    let resp = run(
        &HostBroker::Mock(MockBroker::new()),
        &extended_manifest(),
        req,
        &AuthProvider::new(),
    );
    assert_code(&resp, "fetch_failed", "E6 value size");

    // control bytes (privileged branch rejects all control bytes)
    for value in ["a\x01b", "a\x7fb", "a\tb"] {
        let req = HostHTTPFetchRequest {
            headers: headers(&[("x-ctl", value)]),
            ..request()
        };
        let resp = run(
            &HostBroker::Mock(MockBroker::new()),
            &extended_manifest(),
            req,
            &AuthProvider::new(),
        );
        assert_code(&resp, "fetch_failed", value);
    }
}

#[test]
fn e7_extended_with_auth_profile_is_invalid_request() {
    let req = HostHTTPFetchRequest {
        method: Some("POST".to_string()),
        auth_profile_ref: Some("my-prof".to_string()),
        ..request()
    };
    let resp = run(
        &HostBroker::Mock(MockBroker::new()),
        &manifest(
            &[
                "cap.http.fetch",
                "cap.http.fetch.extended",
                "cap.auth.profile",
            ],
            &["share.fixture.invalid"],
        ),
        req,
        &AuthProvider::new(),
    );
    assert_code(&resp, "invalid_request", "E7");
}

#[test]
fn e8_extended_requires_https_and_public_hosts() {
    // Pre-transport rejections through LiveBroker; no network is touched.
    let live = HostBroker::Live(LiveBroker::new());
    let auth = AuthProvider::new();

    let extended_get = HostHTTPFetchRequest {
        headers: headers(&[("X-User", "u1")]),
        ..Default::default()
    };

    // extended over http
    let req = HostHTTPFetchRequest {
        url: Some("http://example.com/x".to_string()),
        ..extended_get.clone()
    };
    let resp = run(&live, &extended_manifest(), req, &auth);
    assert_code(&resp, "fetch_failed", "E8 http scheme");

    // restricted IP literal hosts
    for url in [
        "https://127.0.0.1/x",
        "https://10.0.0.1/x",
        "https://192.0.2.1/x",
    ] {
        let req = HostHTTPFetchRequest {
            url: Some(url.to_string()),
            ..extended_get.clone()
        };
        let resp = run(&live, &extended_manifest(), req, &auth);
        assert_code(&resp, "fetch_failed", url);
    }
}

// E9 redirect decisions and E10 secret-reflection internals are covered by
// the classify_response / contains_secret_reflection unit tests in
// host_broker.rs (pure functions; no network required).

#[test]
fn e11_expect_mismatches_fall_through_to_no_mock_match() {
    // Each divergence — method, header value, body — alone must miss.
    for expect in [
        MockRequestExpectation {
            method: Some("GET".to_string()),
            ..Default::default()
        },
        MockRequestExpectation {
            headers: BTreeMap::from([("x-user".to_string(), "other".to_string())]),
            ..Default::default()
        },
        MockRequestExpectation {
            body_base64: Some("b3RoZXI=".to_string()),
            ..Default::default()
        },
    ] {
        let rule = MockBrokerRule {
            expect: Some(expect),
            ..simple_hit_rule()
        };
        let resp = run(
            &mock_with(rule),
            &extended_manifest(),
            post_json_request(),
            &AuthProvider::new(),
        );
        assert_code(&resp, "no_mock_match", "E11 expect mismatch");
    }
}

#[test]
fn e12_lowercase_content_type_is_canonicalized() {
    let rule = MockBrokerRule {
        expect: Some(MockRequestExpectation {
            method: Some("POST".to_string()),
            headers: BTreeMap::from([("content-type".to_string(), "application/json".to_string())]),
            body_base64: Some("aGk=".to_string()),
            ..Default::default()
        }),
        ..simple_hit_rule()
    };
    let req = HostHTTPFetchRequest {
        method: Some("POST".to_string()),
        headers: headers(&[("content-type", "application/json")]),
        body_base64: Some("aGk=".to_string()),
        ..request()
    };
    let resp = run(
        &mock_with(rule),
        &extended_manifest(),
        req,
        &AuthProvider::new(),
    );
    assert!(resp.ok, "E12 lowercase content-type: {:?}", resp.message);
}

#[test]
fn ref_mode_mock_matching_and_validated_shape_export() {
    // Ref-mode request under an alias manifest matches a rule declaring ref
    // expectations, without resolving refs to URLs.
    let rule = MockBrokerRule {
        expect: Some(MockRequestExpectation {
            broker_policy_ref: Some("bpr-matrix".to_string()),
            endpoint_ref: Some("ep-matrix".to_string()),
            ..Default::default()
        }),
        ..simple_hit_rule()
    };
    let req = HostHTTPFetchRequest {
        broker_policy_ref: Some("bpr-matrix".to_string()),
        endpoint_ref: Some("ep-matrix".to_string()),
        params: Some(BTreeMap::from([("p".to_string(), "1".to_string())])),
        ..Default::default()
    };
    let resp = run(
        &mock_with(rule),
        &alias_manifest(&["cap.http.fetch"]),
        req,
        &AuthProvider::new(),
    );
    assert!(resp.ok, "ref-mode match: {:?}", resp.message);
    assert_eq!(resp.final_url, None);

    // Wrong endpoint ref misses
    let rule = MockBrokerRule {
        expect: Some(MockRequestExpectation {
            endpoint_ref: Some("ep-other".to_string()),
            ..Default::default()
        }),
        ..simple_hit_rule()
    };
    let req = HostHTTPFetchRequest {
        broker_policy_ref: Some("bpr-matrix".to_string()),
        endpoint_ref: Some("ep-matrix".to_string()),
        ..Default::default()
    };
    let resp = run(
        &mock_with(rule),
        &alias_manifest(&["cap.http.fetch"]),
        req,
        &AuthProvider::new(),
    );
    assert_code(&resp, "no_mock_match", "ref-mode wrong endpoint_ref");

    // Invalid ref shape (uppercase) is invalid_request at mode determination
    let req = HostHTTPFetchRequest {
        broker_policy_ref: Some("BPR-BAD".to_string()),
        endpoint_ref: Some("ep-matrix".to_string()),
        ..Default::default()
    };
    let resp = run(
        &HostBroker::Mock(MockBroker::new()),
        &alias_manifest(&["cap.http.fetch"]),
        req,
        &AuthProvider::new(),
    );
    assert_code(&resp, "invalid_request", "ref-mode invalid ref slug");

    // ValidatedFetchShape is constructible for direct resolve() tests.
    let shape = ValidatedFetchShape {
        method: "GET".to_string(),
        ..Default::default()
    };
    let mut broker = MockBroker::new();
    broker.add_rule(simple_hit_rule());
    let req = request();
    assert!(broker.resolve(&req, &shape, None).is_some());
}

// ---------- Boundary and egress-safety regression layer ----------

#[test]
fn boundary_body_headers_and_value_caps_are_inclusive() {
    // Exactly 16 KiB decoded body passes the cap.
    let body_16kib = base64::engine::general_purpose::STANDARD.encode(vec![7u8; 16 * 1024]);
    let req = HostHTTPFetchRequest {
        method: Some("POST".to_string()),
        headers: headers(&[("Content-Type", "application/json")]),
        body_base64: Some(body_16kib),
        ..request()
    };
    let resp = run(
        &mock_with(simple_hit_rule()),
        &extended_manifest(),
        req,
        &AuthProvider::new(),
    );
    assert!(resp.ok, "16 KiB body: {:?}", resp.message);

    // Exactly 16 request headers pass the count cap.
    let many: Vec<(String, String)> = (0..16)
        .map(|i| (format!("x-h{i:02}"), "v".to_string()))
        .collect();
    let req = HostHTTPFetchRequest {
        headers: Some(many.into_iter().collect()),
        ..request()
    };
    let resp = run(
        &mock_with(simple_hit_rule()),
        &extended_manifest(),
        req,
        &AuthProvider::new(),
    );
    assert!(resp.ok, "16 headers: {:?}", resp.message);

    // Exactly 1024-byte header value passes.
    let long = "v".repeat(1024);
    let req = HostHTTPFetchRequest {
        headers: headers(&[("x-big", long.as_str())]),
        ..request()
    };
    let resp = run(
        &mock_with(simple_hit_rule()),
        &extended_manifest(),
        req,
        &AuthProvider::new(),
    );
    assert!(resp.ok, "1024-byte value: {:?}", resp.message);
}

#[test]
fn unsafe_targets_fail_at_the_shared_egress_gate() {
    // These are rejected before any transport in mock mode as well: scheme,
    // userinfo (including the empty `//` form), IP literals, trailing dots.
    for url in [
        "ftp://share.fixture.invalid/x",
        "javascript:alert(1)",
        "data:text/plain,x",
        "https://user@share.fixture.invalid/",
        "https://user:pw@share.fixture.invalid/",
        "https://@share.fixture.invalid/",
        "https://share.fixture.invalid./",
        "https://127.0.0.1/",
        "https://[::1]/",
    ] {
        let req = HostHTTPFetchRequest {
            url: Some(url.to_string()),
            ..Default::default()
        };
        let resp = run(
            &mock_with(simple_hit_rule()),
            &basic_manifest(),
            req,
            &AuthProvider::new(),
        );
        assert_code(&resp, "fetch_failed", url);
    }
}

#[test]
fn auth_profile_over_http_is_denied_before_transport() {
    let mut auth = AuthProvider::new();
    auth.add_profile(
        "my-prof",
        true,
        goaria_extractor_sdk::types::AuthSecretKind::Bearer,
        "eyJ...",
        Some("topsecret-token".to_string()),
    );
    let m = manifest(
        &["cap.http.fetch", "cap.auth.profile"],
        &["share.fixture.invalid"],
    );
    let req = HostHTTPFetchRequest {
        url: Some("http://share.fixture.invalid/x".to_string()),
        auth_profile_ref: Some("my-prof".to_string()),
        ..Default::default()
    };
    let resp = run(&mock_with(simple_hit_rule()), &m, req, &auth);
    assert_code(&resp, "authenticated_fetch_failed", "auth over http");
}

#[test]
fn empty_auth_profile_ref_is_treated_as_unset() {
    let req = HostHTTPFetchRequest {
        auth_profile_ref: Some(String::new()),
        ..request()
    };
    let resp = run(
        &mock_with(simple_hit_rule()),
        &basic_manifest(),
        req,
        &AuthProvider::new(),
    );
    assert!(resp.ok, "empty auth_profile_ref: {:?}", resp.message);
}

#[test]
fn ref_mode_params_and_membership_are_enforced() {
    let auth = AuthProvider::new();
    let alias = alias_manifest(&["cap.http.fetch"]);

    // Sensitive key, reserved URL syntax, and credential-looking values are
    // all invalid_request at mode determination.
    for params in [
        BTreeMap::from([("token".to_string(), "v".to_string())]),
        BTreeMap::from([("k".to_string(), "https://x".to_string())]),
        BTreeMap::from([("k".to_string(), "Bearer abc".to_string())]),
    ] {
        let req = HostHTTPFetchRequest {
            broker_policy_ref: Some("bpr-matrix".to_string()),
            endpoint_ref: Some("ep-matrix".to_string()),
            params: Some(params),
            ..Default::default()
        };
        let resp = run(&HostBroker::Mock(MockBroker::new()), &alias, req, &auth);
        assert_code(&resp, "invalid_request", "ref params");
    }

    // More than 16 params entries.
    let many: BTreeMap<String, String> = (0..17)
        .map(|i| (format!("k{i:02}"), "v".to_string()))
        .collect();
    let req = HostHTTPFetchRequest {
        broker_policy_ref: Some("bpr-matrix".to_string()),
        endpoint_ref: Some("ep-matrix".to_string()),
        params: Some(many),
        ..Default::default()
    };
    let resp = run(&HostBroker::Mock(MockBroker::new()), &alias, req, &auth);
    assert_code(&resp, "invalid_request", "ref params >16");

    // A syntactically valid but undeclared broker_policy_ref is policy_denied.
    let req = HostHTTPFetchRequest {
        broker_policy_ref: Some("bpr-unknown".to_string()),
        endpoint_ref: Some("ep-matrix".to_string()),
        ..Default::default()
    };
    let resp = run(&HostBroker::Mock(MockBroker::new()), &alias, req, &auth);
    assert_code(&resp, "policy_denied", "unknown broker_policy_ref");
}

#[test]
fn mock_response_egress_matches_live_contract() {
    // Fixture headers outside the safe allowlist never reach the guest, and
    // safe names surface under canonical Title-Case keys.
    let mut fixture_headers = BTreeMap::new();
    fixture_headers.insert("content-type".to_string(), vec!["text/plain".to_string()]);
    fixture_headers.insert("x-internal".to_string(), vec!["nope".to_string()]);
    fixture_headers.insert("set-cookie".to_string(), vec!["sid=1".to_string()]);
    let rule = MockBrokerRule {
        headers: fixture_headers,
        ..simple_hit_rule()
    };
    let resp = run(
        &mock_with(rule),
        &basic_manifest(),
        request(),
        &AuthProvider::new(),
    );
    assert!(resp.ok);
    let exposed = resp.headers.expect("safe headers must be exposed");
    assert_eq!(exposed.len(), 1);
    assert_eq!(
        exposed.get("Content-Type").map(|v| v.as_slice()),
        Some(&["text/plain".to_string()][..])
    );

    // Redirect-class fixture statuses still report ok:true.
    let rule = MockBrokerRule {
        status_code: 302,
        ..simple_hit_rule()
    };
    let resp = run(
        &mock_with(rule),
        &basic_manifest(),
        request(),
        &AuthProvider::new(),
    );
    assert!(resp.ok, "mock 3xx must report ok:true");
    assert_eq!(resp.status_code, Some(302));

    // Secrets embedded in safe header values and the final URL are redacted.
    let mut fixture_headers = BTreeMap::new();
    fixture_headers.insert(
        "etag".to_string(),
        vec!["has-supersecretvalue-inside".to_string()],
    );
    let rule = MockBrokerRule {
        headers: fixture_headers,
        ..simple_hit_rule()
    };
    let req = HostHTTPFetchRequest {
        url: Some(format!("{TEST_URL}?token=supersecretvalue")),
        headers: headers(&[("X-User", "supersecretvalue")]),
        ..Default::default()
    };
    let mut rule = rule;
    rule.pattern = UrlPattern::Prefix(TEST_URL.to_string());
    let resp = run(
        &mock_with(rule),
        &extended_manifest(),
        req,
        &AuthProvider::new(),
    );
    assert!(resp.ok, "redaction case: {:?}", resp.message);
    let exposed = resp.headers.unwrap();
    assert_eq!(
        exposed.get("Etag").map(|v| v.as_slice()),
        Some(&["has-[REDACTED]-inside".to_string()][..])
    );
    assert_eq!(
        resp.final_url.as_deref(),
        Some(format!("{TEST_URL}?token=[REDACTED]").as_str())
    );
}
