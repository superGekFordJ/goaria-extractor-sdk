use goaria_extractor_sdk::abi::{
    dispatch_extract, dispatch_match, pack_json_response, pack_result, unpack_result,
    CURRENT_ABI_VERSION,
};
use goaria_extractor_sdk::alloc::{alloc, copy_slice_to_guest, free, ptr_to_raw};
use goaria_extractor_sdk::error::ExtractorError;
use goaria_extractor_sdk::traits::Extractor;
use goaria_extractor_sdk::types::{
    AuthSecretKind, ExtractInput, ExtractOutput, ExtractedItemRef, HostAuthProfileStatusRequest,
    HostAuthProfileStatusResponse, HostHTTPFetchRequest, HostHTTPFetchResponse, MatchInput,
    MatchOutput,
};
use std::collections::BTreeMap;

// -----------------------------------------------------------------------------
// 1. Pack / Unpack ABI Tests
// -----------------------------------------------------------------------------

#[test]
fn test_pack_and_unpack_result() {
    let ptr: u32 = 0x1234_5678;
    let len: u32 = 0x9ABC_DEF0;

    let packed = pack_result(ptr, len);
    let (unpacked_ptr, unpacked_len) = unpack_result(packed);

    assert_eq!(unpacked_ptr, ptr);
    assert_eq!(unpacked_len, len);
}

#[test]
fn test_current_abi_version_is_one() {
    assert_eq!(CURRENT_ABI_VERSION, 1);
}

#[test]
fn test_pack_json_response() {
    let output = MatchOutput::matched();
    let packed = pack_json_response(&output);
    assert_ne!(packed, 0);
    let (ptr, len) = unpack_result(packed as u64);
    assert_ne!(ptr, 0);
    assert_ne!(len, 0);
    let raw = unsafe { ptr_to_raw(ptr as i32) };
    let slice = unsafe { std::slice::from_raw_parts(raw, len as usize) };
    let deserialized: MatchOutput = serde_json::from_slice(slice).unwrap();
    assert_eq!(deserialized, output);
    unsafe { free(ptr as i32, len as i32) };
}

// -----------------------------------------------------------------------------
// 2. Serde Exact JSON DTO & Forward Compatibility Tests
// -----------------------------------------------------------------------------

#[test]
fn test_match_input_serde() {
    let input = MatchInput {
        url: "https://share.fixture.invalid/item/123".to_string(),
    };
    let json_str = serde_json::to_string(&input).unwrap();
    assert_eq!(
        json_str,
        r#"{"url":"https://share.fixture.invalid/item/123"}"#
    );

    let roundtrip: MatchInput = serde_json::from_str(&json_str).unwrap();
    assert_eq!(roundtrip, input);
}

#[test]
fn test_match_output_fluent_builder() {
    let output = MatchOutput::matched()
        .with_confidence(95)
        .with_reason("matches url pattern");

    assert!(output.matched);
    assert_eq!(output.confidence, Some(95));
    assert_eq!(output.reason.as_deref(), Some("matches url pattern"));

    let json_str = serde_json::to_string(&output).unwrap();
    let roundtrip: MatchOutput = serde_json::from_str(&json_str).unwrap();
    assert_eq!(roundtrip, output);
}

#[test]
fn test_match_output_unmatched_default() {
    let output = MatchOutput::unmatched();
    assert!(!output.matched);
    assert_eq!(output.confidence, None);
    assert_eq!(output.reason, None);
}

#[test]
fn test_extract_input_serde() {
    let input = ExtractInput {
        url: "https://share.fixture.invalid/item/456".to_string(),
    };
    let json_str = serde_json::to_string(&input).unwrap();
    assert_eq!(
        json_str,
        r#"{"url":"https://share.fixture.invalid/item/456"}"#
    );
}

#[test]
fn test_extracted_item_ref_and_extract_output() {
    let mut metadata = BTreeMap::new();
    metadata.insert("author".to_string(), "Alice".to_string());

    let item = ExtractedItemRef {
        id: Some("item-101".to_string()),
        url: Some("https://share.fixture.invalid/download/file.zip".to_string()),
        filename: Some("file.zip".to_string()),
        size_bytes: Some(1024 * 1024 * 10),
        mime_type: Some("application/zip".to_string()),
        auth_profile_ref: Some("profile-oauth".to_string()),
        header_profile_ref: None,
        download_auth_ref: None,
        metadata: Some(metadata),
    };

    let output = ExtractOutput::single(item);
    assert_eq!(output.items.len(), 1);
    assert_eq!(output.items[0].id.as_deref(), Some("item-101"));

    let json_str = serde_json::to_string(&output).unwrap();
    let roundtrip: ExtractOutput = serde_json::from_str(&json_str).unwrap();
    assert_eq!(roundtrip, output);
}

#[test]
fn test_host_http_fetch_request_and_response_dto() {
    let mut headers = BTreeMap::new();
    headers.insert("Accept".to_string(), "application/json".to_string());

    let req = HostHTTPFetchRequest {
        url: Some("https://api.fixture.invalid/v1/resource".to_string()),
        method: Some("GET".to_string()),
        headers: Some(headers),
        body_base64: None,
        timeout_millis: Some(3000),
        auth_profile_ref: None,
        broker_policy_ref: None,
        endpoint_ref: None,
        params: None,
        max_response_bytes: None,
        omit_browser_context: None,
    };

    let req_json = serde_json::to_string(&req).unwrap();
    let parsed_req: HostHTTPFetchRequest = serde_json::from_str(&req_json).unwrap();
    assert_eq!(parsed_req.method.as_deref(), Some("GET"));

    let mut resp_headers = BTreeMap::new();
    resp_headers.insert(
        "Content-Type".to_string(),
        vec!["application/json".to_string()],
    );

    let resp = HostHTTPFetchResponse {
        ok: true,
        status_code: Some(200),
        final_url: Some("https://api.fixture.invalid/v1/resource".to_string()),
        headers: Some(resp_headers),
        body_base64: Some("eyJtc2ciOiAiaGVsbG8ifQ==".to_string()),
        error_code: None,
        message: None,
    };

    let resp_json = serde_json::to_string(&resp).unwrap();
    let parsed_resp: HostHTTPFetchResponse = serde_json::from_str(&resp_json).unwrap();
    assert!(parsed_resp.ok);
    assert_eq!(parsed_resp.status_code, Some(200));
}

#[test]
fn test_fetch_request_body_base64_wire_contract() {
    let req = HostHTTPFetchRequest {
        method: Some("POST".to_string()),
        url: Some("https://api.fixture.invalid/v1/submit".to_string()),
        body_base64: Some("aGVsbG8=".to_string()),
        ..Default::default()
    };
    let json_str = serde_json::to_string(&req).unwrap();
    assert!(json_str.contains(r#""body_base64":"aGVsbG8=""#));

    let roundtrip: HostHTTPFetchRequest = serde_json::from_str(&json_str).unwrap();
    assert_eq!(roundtrip, req);

    // omitempty semantics: absent option must not emit the key
    let bare = HostHTTPFetchRequest {
        url: Some("https://api.fixture.invalid/v1".to_string()),
        ..Default::default()
    };
    let bare_json = serde_json::to_string(&bare).unwrap();
    assert!(!bare_json.contains("body_base64"));

    // explicit empty string decodes back to Some("")
    let decoded: HostHTTPFetchRequest =
        serde_json::from_str(r#"{"url":"https://api.fixture.invalid/","body_base64":""}"#).unwrap();
    assert_eq!(decoded.body_base64.as_deref(), Some(""));
}

#[test]
fn test_fetch_request_rejects_unknown_body_field() {
    // deny_unknown_fields must keep rejecting legacy/incorrect body spellings
    let raw = r#"{"url":"https://api.fixture.invalid/","body":"aGVsbG8="}"#;
    assert!(serde_json::from_str::<HostHTTPFetchRequest>(raw).is_err());
}

#[test]
fn test_capability_constants() {
    use goaria_extractor_sdk::types::{
        CAPABILITY_AUTH_PROFILE, CAPABILITY_DOWNLOAD_AUTH, CAPABILITY_HTTP_FETCH,
        CAPABILITY_HTTP_FETCH_EXTENDED, CAPABILITY_PARSE_WASM,
    };
    assert_eq!(CAPABILITY_PARSE_WASM, "cap.parse.wasm");
    assert_eq!(CAPABILITY_HTTP_FETCH, "cap.http.fetch");
    assert_eq!(CAPABILITY_HTTP_FETCH_EXTENDED, "cap.http.fetch.extended");
    assert_eq!(CAPABILITY_AUTH_PROFILE, "cap.auth.profile");
    assert_eq!(CAPABILITY_DOWNLOAD_AUTH, "cap.download.auth");
}

#[test]
fn test_build_post_body_request_shape() {
    use base64::Engine;
    use goaria_extractor_sdk::broker::build_post_body_request;

    let req = build_post_body_request(
        "https://api.fixture.invalid/v1/submit",
        b"hello",
        "application/json",
    );
    assert_eq!(req.method.as_deref(), Some("POST"));
    assert_eq!(
        req.url.as_deref(),
        Some("https://api.fixture.invalid/v1/submit")
    );
    let encoded = req.body_base64.as_deref().unwrap();
    assert_eq!(encoded, "aGVsbG8=");
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap(),
        b"hello"
    );
    let headers = req.headers.as_ref().unwrap();
    assert_eq!(headers.len(), 1);
    assert_eq!(
        headers.get("Content-Type").map(String::as_str),
        Some("application/json")
    );
    // no ref-mode or auth fields leak into a raw POST request
    assert!(req.broker_policy_ref.is_none());
    assert!(req.endpoint_ref.is_none());
    assert!(req.auth_profile_ref.is_none());
}

#[test]
fn test_host_auth_profile_status_dto() {
    let req = HostAuthProfileStatusRequest {
        auth_profile_ref: "token-profile-01".to_string(),
        url: Some("https://api.fixture.invalid/user".to_string()),
        broker_policy_ref: None,
        endpoint_ref: None,
        params: None,
    };
    let req_json = serde_json::to_string(&req).unwrap();
    let parsed_req: HostAuthProfileStatusRequest = serde_json::from_str(&req_json).unwrap();
    assert_eq!(parsed_req.auth_profile_ref, "token-profile-01");

    let resp = HostAuthProfileStatusResponse {
        ok: true,
        available: Some(true),
        kind: Some(AuthSecretKind::Bearer),
        redacted_display: Some("ghp_••••".to_string()),
        error_code: None,
        message: None,
    };
    let resp_json = serde_json::to_string(&resp).unwrap();
    let parsed_resp: HostAuthProfileStatusResponse = serde_json::from_str(&resp_json).unwrap();
    assert!(parsed_resp.ok);
    assert_eq!(parsed_resp.kind, Some(AuthSecretKind::Bearer));
}

#[test]
fn test_register_download_auth_dto_wire_contract() {
    use goaria_extractor_sdk::types::{
        HostRegisterDownloadAuthRequest, HostRegisterDownloadAuthResponse,
    };

    let req = HostRegisterDownloadAuthRequest {
        kind: "bearer".to_string(),
        token: "opaque-token-42".to_string(),
    };
    let req_json = serde_json::to_string(&req).unwrap();
    assert_eq!(req_json, r#"{"kind":"bearer","token":"opaque-token-42"}"#);

    // request DTO is strict: unknown fields are rejected
    assert!(serde_json::from_str::<HostRegisterDownloadAuthRequest>(
        r#"{"kind":"bearer","token":"x","extra":1}"#
    )
    .is_err());

    let resp: HostRegisterDownloadAuthResponse = serde_json::from_str(
        r#"{"ok":true,"download_auth_ref":"dar-0123456789abcdef0123456789abcdef"}"#,
    )
    .unwrap();
    assert!(resp.ok);
    assert_eq!(
        resp.download_auth_ref.as_deref(),
        Some("dar-0123456789abcdef0123456789abcdef")
    );

    // forward compatibility: newer host fields must stay decodable
    let resp_fwd: HostRegisterDownloadAuthResponse =
        serde_json::from_str(r#"{"ok":false,"error_code":"policy_denied","future":1}"#).unwrap();
    assert!(!resp_fwd.ok);
    assert_eq!(resp_fwd.error_code.as_deref(), Some("policy_denied"));
}

#[test]
fn test_host_time_dto_wire_contract() {
    use goaria_extractor_sdk::types::{HostTimeRequest, HostTimeResponse};

    // the request wire shape is intentionally an empty object
    assert_eq!(serde_json::to_string(&HostTimeRequest {}).unwrap(), "{}");
    assert!(serde_json::from_str::<HostTimeRequest>(r#"{"at":1}"#).is_err());

    let resp: HostTimeResponse =
        serde_json::from_str(r#"{"ok":true,"unix_secs":1800000000}"#).unwrap();
    assert!(resp.ok);
    assert_eq!(resp.unix_secs, Some(1_800_000_000));
}

#[test]
fn test_extracted_item_download_auth_ref_and_omit_browser_context() {
    // download_auth_ref serializes as an opaque string on the item
    let item = ExtractedItemRef {
        id: Some("item-1".to_string()),
        download_auth_ref: Some("dar-0123456789abcdef0123456789abcdef".to_string()),
        ..Default::default()
    };
    let json_str = serde_json::to_string(&item).unwrap();
    assert!(json_str.contains(
        r#""download_auth_ref":"dar-0123456789abcdef0123456789abcdef""#
    ));
    let roundtrip: ExtractedItemRef = serde_json::from_str(&json_str).unwrap();
    assert_eq!(roundtrip, item);

    // omit_browser_context is opt-in on the fetch request
    let req = HostHTTPFetchRequest {
        url: Some("https://api.fixture.invalid/v1".to_string()),
        omit_browser_context: Some(true),
        ..Default::default()
    };
    let req_json = serde_json::to_string(&req).unwrap();
    assert!(req_json.contains(r#""omit_browser_context":true"#));
    let roundtrip: HostHTTPFetchRequest = serde_json::from_str(&req_json).unwrap();
    assert_eq!(roundtrip, req);
}

// -----------------------------------------------------------------------------
// 3. Allocator and Pointer Marshalling Tests
// -----------------------------------------------------------------------------

#[test]
fn test_memory_allocation_and_free() {
    unsafe {
        let size = 512;
        let ptr = alloc(size);
        assert_ne!(ptr, 0);

        let raw = ptr_to_raw(ptr);
        assert!(!raw.is_null());

        let slice = std::slice::from_raw_parts_mut(raw, size as usize);
        for (i, byte) in slice.iter_mut().enumerate() {
            *byte = (i % 256) as u8;
        }

        for (i, byte) in slice.iter().enumerate() {
            assert_eq!(*byte, (i % 256) as u8);
        }

        free(ptr, size);
    }
}

#[test]
fn test_copy_slice_to_guest() {
    let test_data = b"Hello GoAria WebAssembly Guest!";
    unsafe {
        let (ptr, len) = copy_slice_to_guest(test_data);
        assert_ne!(ptr, 0);
        assert_eq!(len as usize, test_data.len());
        let raw = ptr_to_raw(ptr);
        assert_eq!(std::slice::from_raw_parts(raw, len as usize), test_data);
        free(ptr, len);
    }
}

// -----------------------------------------------------------------------------
// 4. Panic Barrier & Dispatcher Tests
// -----------------------------------------------------------------------------

#[derive(Default)]
struct PanickingExtractor;

impl Extractor for PanickingExtractor {
    fn match_url(&self, _input: MatchInput) -> Result<MatchOutput, ExtractorError> {
        panic!("deliberate panic inside match_url");
    }

    fn extract(&self, _input: ExtractInput) -> Result<ExtractOutput, ExtractorError> {
        panic!("deliberate panic inside extract");
    }
}

struct PanickingDefaultExtractor;

impl Default for PanickingDefaultExtractor {
    fn default() -> Self {
        panic!("deliberate panic inside Default::default()");
    }
}

impl Extractor for PanickingDefaultExtractor {
    fn match_url(&self, _input: MatchInput) -> Result<MatchOutput, ExtractorError> {
        Ok(MatchOutput::matched())
    }

    fn extract(&self, _input: ExtractInput) -> Result<ExtractOutput, ExtractorError> {
        Ok(ExtractOutput::default())
    }
}

#[derive(Default)]
struct ErroringExtractor;

impl Extractor for ErroringExtractor {
    fn match_url(&self, _input: MatchInput) -> Result<MatchOutput, ExtractorError> {
        Err(ExtractorError::ExecutionFailed(
            "custom failure".to_string(),
        ))
    }

    fn extract(&self, _input: ExtractInput) -> Result<ExtractOutput, ExtractorError> {
        Err(ExtractorError::ExecutionFailed(
            "extract failed".to_string(),
        ))
    }
}

#[derive(Default)]
struct NormalExtractor;

impl Extractor for NormalExtractor {
    fn match_url(&self, input: MatchInput) -> Result<MatchOutput, ExtractorError> {
        if input.url.contains("fixture.invalid") {
            Ok(MatchOutput::matched().with_confidence(95))
        } else {
            Ok(MatchOutput::unmatched())
        }
    }

    fn extract(&self, input: ExtractInput) -> Result<ExtractOutput, ExtractorError> {
        let item = ExtractedItemRef {
            id: Some("id-1".to_string()),
            url: Some(input.url),
            ..Default::default()
        };
        Ok(ExtractOutput::single(item))
    }
}

#[test]
fn test_dispatch_match_normal() {
    let input = MatchInput {
        url: "https://share.fixture.invalid/test".to_string(),
    };
    let input_bytes = serde_json::to_vec(&input).unwrap();
    let (ptr, len) = unsafe { copy_slice_to_guest(&input_bytes) };

    let packed = unsafe { dispatch_match::<NormalExtractor>(ptr, len) };
    assert_ne!(packed, 0);

    let (out_ptr, out_len) = unpack_result(packed as u64);
    let raw = unsafe { ptr_to_raw(out_ptr as i32) };
    let slice = unsafe { std::slice::from_raw_parts(raw, out_len as usize) };
    let output: MatchOutput = serde_json::from_slice(slice).unwrap();
    assert!(output.matched);
    assert_eq!(output.confidence, Some(95));
    unsafe {
        free(out_ptr as i32, out_len as i32);
        free(ptr, len);
    };
}

#[test]
fn test_dispatch_match_panicking_barrier() {
    let input = MatchInput {
        url: "https://share.fixture.invalid/panic".to_string(),
    };
    let input_bytes = serde_json::to_vec(&input).unwrap();
    let (ptr, len) = unsafe { copy_slice_to_guest(&input_bytes) };

    let packed = unsafe { dispatch_match::<PanickingExtractor>(ptr, len) };
    assert_ne!(packed, 0);

    let (out_ptr, out_len) = unpack_result(packed as u64);
    let raw = unsafe { ptr_to_raw(out_ptr as i32) };
    let slice = unsafe { std::slice::from_raw_parts(raw, out_len as usize) };
    let output: MatchOutput = serde_json::from_slice(slice).unwrap();
    assert!(!output.matched);
    assert!(output.reason.unwrap().contains("panicked"));
    unsafe {
        free(out_ptr as i32, out_len as i32);
        free(ptr, len);
    };
}

#[test]
fn test_dispatch_match_panicking_default_barrier() {
    let input = MatchInput {
        url: "https://share.fixture.invalid/panic-default".to_string(),
    };
    let input_bytes = serde_json::to_vec(&input).unwrap();
    let (ptr, len) = unsafe { copy_slice_to_guest(&input_bytes) };

    let packed = unsafe { dispatch_match::<PanickingDefaultExtractor>(ptr, len) };
    assert_ne!(packed, 0);

    let (out_ptr, out_len) = unpack_result(packed as u64);
    let raw = unsafe { ptr_to_raw(out_ptr as i32) };
    let slice = unsafe { std::slice::from_raw_parts(raw, out_len as usize) };
    let output: MatchOutput = serde_json::from_slice(slice).unwrap();
    assert!(!output.matched);
    assert!(output.reason.unwrap().contains("panicked"));
    unsafe {
        free(out_ptr as i32, out_len as i32);
        free(ptr, len);
    };
}

#[test]
fn test_dispatch_match_erroring_barrier() {
    let input = MatchInput {
        url: "https://share.fixture.invalid/err".to_string(),
    };
    let input_bytes = serde_json::to_vec(&input).unwrap();
    let (ptr, len) = unsafe { copy_slice_to_guest(&input_bytes) };

    let packed = unsafe { dispatch_match::<ErroringExtractor>(ptr, len) };
    assert_ne!(packed, 0);

    let (out_ptr, out_len) = unpack_result(packed as u64);
    let raw = unsafe { ptr_to_raw(out_ptr as i32) };
    let slice = unsafe { std::slice::from_raw_parts(raw, out_len as usize) };
    let output: MatchOutput = serde_json::from_slice(slice).unwrap();
    assert!(!output.matched);
    assert!(output.reason.unwrap().contains("custom failure"));
    unsafe {
        free(out_ptr as i32, out_len as i32);
        free(ptr, len);
    };
}

#[test]
fn test_dispatch_match_invalid_pointer() {
    let packed = unsafe { dispatch_match::<NormalExtractor>(0, 0) };
    assert_ne!(packed, 0);

    let (out_ptr, out_len) = unpack_result(packed as u64);
    let raw = unsafe { ptr_to_raw(out_ptr as i32) };
    let slice = unsafe { std::slice::from_raw_parts(raw, out_len as usize) };
    let output: MatchOutput = serde_json::from_slice(slice).unwrap();
    assert!(!output.matched);
    assert!(output.reason.unwrap().contains("invalid input"));
    unsafe { free(out_ptr as i32, out_len as i32) };
}

#[test]
fn test_dispatch_extract_panicking_barrier() {
    let input = ExtractInput {
        url: "https://share.fixture.invalid/panic".to_string(),
    };
    let input_bytes = serde_json::to_vec(&input).unwrap();
    let (ptr, len) = unsafe { copy_slice_to_guest(&input_bytes) };

    let packed = unsafe { dispatch_extract::<PanickingExtractor>(ptr, len) };
    assert_ne!(packed, 0);

    let (out_ptr, out_len) = unpack_result(packed as u64);
    let raw = unsafe { ptr_to_raw(out_ptr as i32) };
    let slice = unsafe { std::slice::from_raw_parts(raw, out_len as usize) };
    let output: ExtractOutput = serde_json::from_slice(slice).unwrap();
    assert!(output.items.is_empty());
    unsafe {
        free(out_ptr as i32, out_len as i32);
        free(ptr, len);
    };
}

#[test]
fn test_dispatch_extract_panicking_default_barrier() {
    let input = ExtractInput {
        url: "https://share.fixture.invalid/panic-default".to_string(),
    };
    let input_bytes = serde_json::to_vec(&input).unwrap();
    let (ptr, len) = unsafe { copy_slice_to_guest(&input_bytes) };

    let packed = unsafe { dispatch_extract::<PanickingDefaultExtractor>(ptr, len) };
    assert_ne!(packed, 0);

    let (out_ptr, out_len) = unpack_result(packed as u64);
    let raw = unsafe { ptr_to_raw(out_ptr as i32) };
    let slice = unsafe { std::slice::from_raw_parts(raw, out_len as usize) };
    let output: ExtractOutput = serde_json::from_slice(slice).unwrap();
    assert!(output.items.is_empty());
    unsafe {
        free(out_ptr as i32, out_len as i32);
        free(ptr, len);
    };
}

#[test]
fn test_dispatch_extract_normal() {
    let input = ExtractInput {
        url: "https://share.fixture.invalid/item/456".to_string(),
    };
    let input_bytes = serde_json::to_vec(&input).unwrap();
    let (ptr, len) = unsafe { copy_slice_to_guest(&input_bytes) };

    let packed = unsafe { dispatch_extract::<NormalExtractor>(ptr, len) };
    assert_ne!(packed, 0);

    let (out_ptr, out_len) = unpack_result(packed as u64);
    let raw = unsafe { ptr_to_raw(out_ptr as i32) };
    let slice = unsafe { std::slice::from_raw_parts(raw, out_len as usize) };
    let output: ExtractOutput = serde_json::from_slice(slice).unwrap();
    assert_eq!(output.items.len(), 1);
    assert_eq!(
        output.items[0].url.as_deref(),
        Some("https://share.fixture.invalid/item/456")
    );
    unsafe {
        free(out_ptr as i32, out_len as i32);
        free(ptr, len);
    };
}
