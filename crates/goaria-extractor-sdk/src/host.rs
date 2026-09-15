use crate::abi::unpack_result;
use crate::alloc::GuestBuffer;
use crate::error::ExtractorError;

#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "goaria_host")]
extern "C" {
    pub fn http_fetch(req_ptr: i32, req_len: i32) -> i64;
    pub fn auth_profile_status(req_ptr: i32, req_len: i32) -> i64;
    pub fn register_download_auth(req_ptr: i32, req_len: i32) -> i64;
    pub fn host_time(req_ptr: i32, req_len: i32) -> i64;
}

#[cfg(not(target_arch = "wasm32"))]
#[allow(unused_variables)]
unsafe fn http_fetch(req_ptr: i32, req_len: i32) -> i64 {
    0
}

#[cfg(not(target_arch = "wasm32"))]
#[allow(unused_variables)]
unsafe fn auth_profile_status(req_ptr: i32, req_len: i32) -> i64 {
    0
}

#[cfg(not(target_arch = "wasm32"))]
#[allow(unused_variables)]
unsafe fn register_download_auth(req_ptr: i32, req_len: i32) -> i64 {
    0
}

#[cfg(not(target_arch = "wasm32"))]
#[allow(unused_variables)]
unsafe fn host_time(req_ptr: i32, req_len: i32) -> i64 {
    0
}

/// Low-level invocation of goaria_host.http_fetch.
pub fn raw_http_fetch(request_json_bytes: &[u8]) -> Result<GuestBuffer, ExtractorError> {
    let req_len = request_json_bytes.len() as i32;
    let req_ptr = request_json_bytes.as_ptr() as i32;

    let result_packed = unsafe { http_fetch(req_ptr, req_len) };
    if result_packed == 0 {
        return Err(ExtractorError::HostError {
            error_code: "host_call_failed".to_string(),
            message: "host http_fetch returned null or 0".to_string(),
        });
    }

    let (resp_ptr, resp_len) = unpack_result(result_packed as u64);
    unsafe { GuestBuffer::from_host_raw(resp_ptr, resp_len) }.ok_or_else(|| {
        ExtractorError::HostError {
            error_code: "invalid_response_buffer".to_string(),
            message: "host returned invalid response buffer".to_string(),
        }
    })
}

/// Low-level invocation of goaria_host.auth_profile_status.
pub fn raw_auth_profile_status(request_json_bytes: &[u8]) -> Result<GuestBuffer, ExtractorError> {
    let req_len = request_json_bytes.len() as i32;
    let req_ptr = request_json_bytes.as_ptr() as i32;

    let result_packed = unsafe { auth_profile_status(req_ptr, req_len) };
    if result_packed == 0 {
        return Err(ExtractorError::HostError {
            error_code: "host_call_failed".to_string(),
            message: "host auth_profile_status returned null or 0".to_string(),
        });
    }

    let (resp_ptr, resp_len) = unpack_result(result_packed as u64);
    unsafe { GuestBuffer::from_host_raw(resp_ptr, resp_len) }.ok_or_else(|| {
        ExtractorError::HostError {
            error_code: "invalid_response_buffer".to_string(),
            message: "host returned invalid response buffer".to_string(),
        }
    })
}

/// Low-level invocation of goaria_host.register_download_auth.
pub fn raw_register_download_auth(request_json_bytes: &[u8]) -> Result<GuestBuffer, ExtractorError> {
    let req_len = request_json_bytes.len() as i32;
    let req_ptr = request_json_bytes.as_ptr() as i32;

    let result_packed = unsafe { register_download_auth(req_ptr, req_len) };
    if result_packed == 0 {
        return Err(ExtractorError::HostError {
            error_code: "host_call_failed".to_string(),
            message: "host register_download_auth returned null or 0".to_string(),
        });
    }

    let (resp_ptr, resp_len) = unpack_result(result_packed as u64);
    unsafe { GuestBuffer::from_host_raw(resp_ptr, resp_len) }.ok_or_else(|| {
        ExtractorError::HostError {
            error_code: "invalid_response_buffer".to_string(),
            message: "host returned invalid response buffer".to_string(),
        }
    })
}

/// Low-level invocation of goaria_host.host_time.
pub fn raw_host_time(request_json_bytes: &[u8]) -> Result<GuestBuffer, ExtractorError> {
    let req_len = request_json_bytes.len() as i32;
    let req_ptr = request_json_bytes.as_ptr() as i32;

    let result_packed = unsafe { host_time(req_ptr, req_len) };
    if result_packed == 0 {
        return Err(ExtractorError::HostError {
            error_code: "host_call_failed".to_string(),
            message: "host host_time returned null or 0".to_string(),
        });
    }

    let (resp_ptr, resp_len) = unpack_result(result_packed as u64);
    unsafe { GuestBuffer::from_host_raw(resp_ptr, resp_len) }.ok_or_else(|| {
        ExtractorError::HostError {
            error_code: "invalid_response_buffer".to_string(),
            message: "host returned invalid response buffer".to_string(),
        }
    })
}
