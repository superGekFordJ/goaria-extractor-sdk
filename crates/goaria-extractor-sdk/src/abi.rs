use crate::traits::Extractor;
use crate::types::{ExtractInput, ExtractOutput, MatchInput, MatchOutput};

pub const CURRENT_ABI_VERSION: u32 = 1;
pub const ABI_EXPORT_VERSION: &str = "goaria_abi_version";
pub const ABI_EXPORT_ALLOC: &str = "goaria_alloc";
pub const ABI_EXPORT_FREE: &str = "goaria_free";
pub const ABI_EXPORT_MATCH: &str = "goaria_match";
pub const ABI_EXPORT_EXTRACT: &str = "goaria_extract";

pub const HOST_IMPORT_MODULE: &str = "goaria_host";
pub const HOST_IMPORT_HTTP_FETCH: &str = "http_fetch";
pub const HOST_IMPORT_AUTH_PROFILE_STATUS: &str = "auth_profile_status";

/// Pack pointer and length into a single 64-bit unsigned integer.
#[inline]
pub const fn pack_result(ptr: u32, len: u32) -> u64 {
    ((ptr as u64) << 32) | (len as u64)
}

/// Unpack 64-bit integer into (pointer, length) tuple.
#[inline]
pub const fn unpack_result(packed: u64) -> (u32, u32) {
    ((packed >> 32) as u32, packed as u32)
}

/// Serialize a value to JSON in guest memory and return the packed 64-bit pointer/length.
pub fn pack_json_response<T: serde::Serialize>(value: &T) -> i64 {
    match serde_json::to_vec(value) {
        Ok(bytes) => {
            let (ptr, len) = unsafe { crate::alloc::copy_slice_to_guest(&bytes) };
            pack_result(ptr as u32, len as u32) as i64
        }
        Err(_) => 0,
    }
}

/// Dispatcher for `goaria_match` called by macro generated stub.
///
/// On `wasm32-unknown-unknown`, the default `panic=abort` strategy produces an
/// `unreachable` trap that the host runtime isolates; it cannot be recovered by `catch_unwind`.
///
/// # Safety
/// The caller must ensure that `ptr` and `len` specify a valid guest memory buffer.
pub unsafe fn dispatch_match<E: Extractor + Default>(ptr: i32, len: i32) -> i64 {
    if ptr == 0 || len <= 0 {
        return pack_json_response(&MatchOutput {
            matched: false,
            confidence: None,
            reason: Some("invalid input buffer pointer or length".to_string()),
        });
    }

    let raw = crate::alloc::ptr_to_raw(ptr);
    if raw.is_null() {
        return pack_json_response(&MatchOutput {
            matched: false,
            confidence: None,
            reason: Some("invalid input buffer pointer".to_string()),
        });
    }

    let input_bytes = std::slice::from_raw_parts(raw, len as usize);
    let input: MatchInput = match serde_json::from_slice(input_bytes) {
        Ok(inp) => inp,
        Err(e) => {
            return pack_json_response(&MatchOutput {
                matched: false,
                confidence: None,
                reason: Some(format!("failed to parse match input JSON: {}", e)),
            });
        }
    };

    #[cfg(target_arch = "wasm32")]
    let output = match E::default().match_url(input) {
        Ok(output) => output,
        Err(err) => MatchOutput {
            matched: false,
            confidence: None,
            reason: Some(err.to_string()),
        },
    };

    #[cfg(not(target_arch = "wasm32"))]
    let output = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        E::default().match_url(input)
    })) {
        Ok(Ok(output)) => output,
        Ok(Err(err)) => MatchOutput {
            matched: false,
            confidence: None,
            reason: Some(err.to_string()),
        },
        Err(_) => MatchOutput {
            matched: false,
            confidence: None,
            reason: Some("guest panicked during match_url".to_string()),
        },
    };

    pack_json_response(&output)
}

/// Dispatcher for `goaria_extract` called by macro generated stub.
///
/// On `wasm32-unknown-unknown`, the default `panic=abort` strategy produces an
/// `unreachable` trap that the host runtime isolates; it cannot be recovered by `catch_unwind`.
///
/// # Safety
/// The caller must ensure that `ptr` and `len` specify a valid guest memory buffer.
pub unsafe fn dispatch_extract<E: Extractor + Default>(ptr: i32, len: i32) -> i64 {
    if ptr == 0 || len <= 0 {
        return pack_json_response(&ExtractOutput::default());
    }

    let raw = crate::alloc::ptr_to_raw(ptr);
    if raw.is_null() {
        return pack_json_response(&ExtractOutput::default());
    }

    let input_bytes = std::slice::from_raw_parts(raw, len as usize);
    let input: ExtractInput = match serde_json::from_slice(input_bytes) {
        Ok(inp) => inp,
        Err(_) => {
            return pack_json_response(&ExtractOutput::default());
        }
    };

    #[cfg(target_arch = "wasm32")]
    let output = E::default().extract(input).unwrap_or_default();

    #[cfg(not(target_arch = "wasm32"))]
    let output =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| E::default().extract(input)))
            .ok()
            .and_then(Result::ok)
            .unwrap_or_default();

    pack_json_response(&output)
}
