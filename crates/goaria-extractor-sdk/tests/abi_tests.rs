use std::collections::BTreeMap;
use goaria_extractor_sdk::abi::{
    dispatch_extract, dispatch_match, pack_json_response, pack_result, unpack_result,
    CURRENT_ABI_VERSION,
};
use goaria_extractor_sdk::alloc::{alloc, copy_slice_to_guest, free, GuestBuffer};
use goaria_extractor_sdk::error::ExtractorError;
use goaria_extractor_sdk::prelude::*;

// -----------------------------------------------------------------------------
// 1. Bitshift Packing/Unpacking Tests
// -----------------------------------------------------------------------------

#[test]
fn test_pack_unpack_result() {
    assert_eq!(pack_result(0, 0), 0);
    assert_eq!(pack_result(1024, 256), 0x0000040000000100);
    assert_eq!(unpack_result(pack_result(12345, 6789)), (12345, 6789));
    assert_eq!(
        unpack_result(pack_result(u32::MAX, u32::MAX)),
        (u32::MAX, u32::MAX)
    );
    assert_eq!(
        unpack_result(pack_result(0xDEADBEEF, 0x12345678)),
        (0xDEADBEEF, 0x12345678)
    );
}

#[test]
fn test_abi_version_constant() {
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
    let buf = GuestBuffer::from_raw(ptr as i32, len as i32).unwrap();
    let deserialized: MatchOutput = serde_json::from_slice(buf.as_slice()).unwrap();
    assert_eq!(deserialized, output);
}

// -----------------------------------------------------------------------------
// 2. Serde Exact JSON DTO Tests
// -----------------------------------------------------------------------------

#[test]
fn test_match_input_serde() {
    let input = MatchInput {
        url: "https://share.fixture.invalid/item/123".to_string(),
    };
    let json_str = serde_json::to_string(&input).unwrap();
    assert_eq!(json_str, r#"{"url":"https://share.fixture.invalid/item/123"}"#);

    let parsed: MatchInput = serde_json::from_str(&json_str).unwrap();
    assert_eq!(parsed, input);
}

#[test]
fn test_match_output_serde() {
    let matched = MatchOutput::matched();
    let json_str = serde_json::to_string(&matched).unwrap();
    assert_eq!(json_str, r#"{"matched":true,"confidence":100}"#);

    let unmatched = MatchOutput::unmatched();
    let json_str = serde_json::to_string(&unmatched).unwrap();
    assert_eq!(json_str, r#"{"matched":false}"#);

    let with_reason = MatchOutput::matched().with_reason("domain matched");
    let json_str = serde_json::to_string(&with_reason).unwrap();
    assert_eq!(
        json_str,
        r#"{"matched":true,"confidence":100,"reason":"domain matched"}"#
    );
}

#[test]
fn test_extract_input_serde() {
    let input = ExtractInput {
        url: "https://share.fixture.invalid/item/123".to_string(),
    };
    let json_str = serde_json::to_string(&input).unwrap();
    assert_eq!(json_str, r#"{"url":"https://share.fixture.invalid/item/123"}"#);
}

#[test]
fn test_extract_output_serde() {
    let empty = ExtractOutput::new();
    let json_str = serde_json::to_string(&empty).unwrap();
    assert_eq!(json_str, r#"{"items":[]}"#);

    let mut metadata = BTreeMap::new();
    metadata.insert("category".to_string(), "sample".to_string());

    let item = ExtractedItemRef {
        id: Some("item-1".to_string()),
        url: Some("https://download.fixture.invalid/file.bin".to_string()),
        filename: Some("file.bin".to_string()),
        size_bytes: Some(4096),
        mime_type: Some("application/octet-stream".to_string()),
        auth_profile_ref: Some("profile-alpha".to_string()),
        header_profile_ref: None,
        metadata: Some(metadata),
    };

    let output = ExtractOutput::single(item);
    let json_str = serde_json::to_string(&output).unwrap();
    assert!(json_str.contains(r#""id":"item-1""#));
    assert!(json_str.contains(r#""url":"https://download.fixture.invalid/file.bin""#));
    assert!(json_str.contains(r#""filename":"file.bin""#));
    assert!(json_str.contains(r#""size_bytes":4096"#));
    assert!(json_str.contains(r#""mime_type":"application/octet-stream""#));
    assert!(json_str.contains(r#""auth_profile_ref":"profile-alpha""#));
    assert!(!json_str.contains("header_profile_ref"));
}

#[test]
fn test_auth_secret_kind_serde() {
    let bearer = AuthSecretKind::Bearer;
    assert_eq!(serde_json::to_string(&bearer).unwrap(), r#""bearer""#);

    let cookie = AuthSecretKind::Cookie;
    assert_eq!(serde_json::to_string(&cookie).unwrap(), r#""cookie""#);

    let parsed_unknown: AuthSecretKind = serde_json::from_str(r#""custom_token""#).unwrap();
    assert_eq!(parsed_unknown, AuthSecretKind::Unknown);
}

#[test]
fn test_host_http_fetch_request_and_response_serde() {
    let mut params = BTreeMap::new();
    params.insert("page".to_string(), "1".to_string());
    let mut headers = BTreeMap::new();
    headers.insert("Accept".to_string(), "application/json".to_string());

    let req = HostHTTPFetchRequest {
        method: Some("POST".to_string()),
        url: Some("https://api.fixture.invalid/v1/resource".to_string()),
        broker_policy_ref: Some("policy-1".to_string()),
        endpoint_ref: Some("endpoint-1".to_string()),
        params: Some(params),
        headers: Some(headers),
        auth_profile_ref: Some("auth-1".to_string()),
        timeout_millis: Some(3000),
        max_response_bytes: Some(65536),
    };

    let json_str = serde_json::to_string(&req).unwrap();
    let deserialized: HostHTTPFetchRequest = serde_json::from_str(&json_str).unwrap();
    assert_eq!(deserialized, req);

    let mut resp_headers = BTreeMap::new();
    resp_headers.insert("content-type".to_string(), vec!["application/json".to_string()]);

    let resp = HostHTTPFetchResponse {
        ok: true,
        status_code: Some(200),
        final_url: Some("https://api.fixture.invalid/v1/resource".to_string()),
        headers: Some(resp_headers),
        body_base64: Some("SGVsbG8gV29ybGQ=".to_string()),
        error_code: None,
        message: None,
    };

    let json_resp = serde_json::to_string(&resp).unwrap();
    let deserialized_resp: HostHTTPFetchResponse = serde_json::from_str(&json_resp).unwrap();
    assert_eq!(deserialized_resp, resp);
}

#[test]
fn test_host_auth_profile_status_serde() {
    let req = HostAuthProfileStatusRequest {
        auth_profile_ref: "default".to_string(),
        url: Some("https://share.fixture.invalid".to_string()),
        broker_policy_ref: None,
        endpoint_ref: None,
        params: None,
    };

    let json_str = serde_json::to_string(&req).unwrap();
    let deserialized: HostAuthProfileStatusRequest = serde_json::from_str(&json_str).unwrap();
    assert_eq!(deserialized, req);

    let resp = HostAuthProfileStatusResponse {
        ok: true,
        available: Some(true),
        kind: Some(AuthSecretKind::Bearer),
        redacted_display: Some("token_****_1234".to_string()),
        error_code: None,
        message: None,
    };

    let json_resp = serde_json::to_string(&resp).unwrap();
    let deserialized_resp: HostAuthProfileStatusResponse = serde_json::from_str(&json_resp).unwrap();
    assert_eq!(deserialized_resp, resp);
}

// -----------------------------------------------------------------------------
// 3. Memory Allocator & GuestBuffer Tests
// -----------------------------------------------------------------------------

#[test]
fn test_memory_allocation_and_free() {
    unsafe {
        let size = 512;
        let ptr = alloc(size);
        assert_ne!(ptr, 0);

        let raw = goaria_extractor_sdk::alloc::ptr_to_raw(ptr);
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
fn test_copy_slice_to_guest_and_guest_buffer() {
    let test_data = b"Hello GoAria WebAssembly Guest!";
    unsafe {
        let (ptr, len) = copy_slice_to_guest(test_data);
        assert_ne!(ptr, 0);
        assert_eq!(len as usize, test_data.len());

        let buffer = GuestBuffer::from_raw(ptr, len).expect("valid buffer");
        assert_eq!(buffer.ptr(), ptr);
        assert_eq!(buffer.len(), len);
        assert!(!buffer.is_empty());
        assert_eq!(buffer.as_slice(), test_data);
        assert_eq!(buffer.as_str().unwrap(), "Hello GoAria WebAssembly Guest!");
        // buffer dropped and freed here
    }
}

#[test]
fn test_guest_buffer_invalid_inputs() {
    assert!(GuestBuffer::from_raw(0, 10).is_none());
    assert!(GuestBuffer::from_raw(100, 0).is_none());
    assert!(GuestBuffer::from_raw(100, -1).is_none());
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

#[derive(Default)]
struct ErroringExtractor;

impl Extractor for ErroringExtractor {
    fn match_url(&self, _input: MatchInput) -> Result<MatchOutput, ExtractorError> {
        Err(ExtractorError::ExecutionFailed("custom failure".to_string()))
    }

    fn extract(&self, _input: ExtractInput) -> Result<ExtractOutput, ExtractorError> {
        Err(ExtractorError::ExecutionFailed("extract failed".to_string()))
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
    let buf = GuestBuffer::from_raw(out_ptr as i32, out_len as i32).unwrap();
    let output: MatchOutput = serde_json::from_slice(buf.as_slice()).unwrap();
    assert!(output.matched);
    assert_eq!(output.confidence, Some(95));
    unsafe { free(ptr, len) };
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
    let buf = GuestBuffer::from_raw(out_ptr as i32, out_len as i32).unwrap();
    let output: MatchOutput = serde_json::from_slice(buf.as_slice()).unwrap();
    assert!(!output.matched);
    assert!(output.reason.unwrap().contains("panicked"));
    unsafe { free(ptr, len) };
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
    let buf = GuestBuffer::from_raw(out_ptr as i32, out_len as i32).unwrap();
    let output: MatchOutput = serde_json::from_slice(buf.as_slice()).unwrap();
    assert!(!output.matched);
    assert!(output.reason.unwrap().contains("custom failure"));
    unsafe { free(ptr, len) };
}

#[test]
fn test_dispatch_match_invalid_pointer() {
    let packed = unsafe { dispatch_match::<NormalExtractor>(0, 0) };
    assert_ne!(packed, 0);

    let (out_ptr, out_len) = unpack_result(packed as u64);
    let buf = GuestBuffer::from_raw(out_ptr as i32, out_len as i32).unwrap();
    let output: MatchOutput = serde_json::from_slice(buf.as_slice()).unwrap();
    assert!(!output.matched);
    assert!(output.reason.unwrap().contains("invalid input"));
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
    let buf = GuestBuffer::from_raw(out_ptr as i32, out_len as i32).unwrap();
    let output: ExtractOutput = serde_json::from_slice(buf.as_slice()).unwrap();
    assert!(output.items.is_empty());
    unsafe { free(ptr, len) };
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
    let buf = GuestBuffer::from_raw(out_ptr as i32, out_len as i32).unwrap();
    let output: ExtractOutput = serde_json::from_slice(buf.as_slice()).unwrap();
    assert_eq!(output.items.len(), 1);
    assert_eq!(
        output.items[0].url.as_deref(),
        Some("https://share.fixture.invalid/item/456")
    );
    unsafe { free(ptr, len) };
}
