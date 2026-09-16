use std::fmt;

/// Standard error type for GoAria extractor operations.
///
/// How a returned `Err` reaches the host depends on the entrypoint: see
/// [`Extractor`](crate::traits::Extractor) for the wire mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractorError {
    /// JSON serialization or deserialization failed while encoding a
    /// host-import request or decoding a host-import response. Produced by
    /// `From<serde_json::Error>`; also available to extractor code that
    /// parses its own payloads.
    Serialization(String),
    /// A `goaria_host` import call failed: either at the transport level
    /// (SDK-minted `host_call_failed` / `invalid_response_buffer` /
    /// `invalid_response` codes) or because the host response payload
    /// reported `ok: false`, in which case `error_code` is the host's wire
    /// code (`invalid_request`, `policy_denied`, `budget_exhausted`, …).
    HostError {
        /// Stable machine-readable error code — the host's wire `error_code`
        /// or an SDK-minted transport code.
        error_code: String,
        /// Human-readable detail from the host response.
        message: String,
    },
    /// The brokered fetch was permitted and executed but the remote server
    /// returned HTTP status >= 400.
    HttpError {
        /// HTTP status code returned by the remote server.
        status_code: i32,
        /// Human-readable detail.
        message: String,
    },
    /// Caller-supplied input failed validation. Not produced by SDK
    /// internals; available for extractor implementations validating their
    /// own inputs.
    InvalidInput(String),
    /// A base64 payload could not be decoded (e.g. a response `body_base64`).
    /// Produced by `From<base64::DecodeError>`.
    Base64Decode(String),
    /// General extractor-logic failure. Produced by `From<&str>` /
    /// `From<String>` and by SDK helpers for failures with no narrower
    /// variant (e.g. a non-UTF-8 response body in `fetch_text`).
    ExecutionFailed(String),
}

impl fmt::Display for ExtractorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Serialization(msg) => write!(f, "serialization error: {}", msg),
            Self::HostError {
                error_code,
                message,
            } => {
                write!(f, "host error [{}]: {}", error_code, message)
            }
            Self::HttpError {
                status_code,
                message,
            } => {
                write!(f, "HTTP error [{}]: {}", status_code, message)
            }
            Self::InvalidInput(msg) => write!(f, "invalid input: {}", msg),
            Self::Base64Decode(msg) => write!(f, "base64 decode error: {}", msg),
            Self::ExecutionFailed(msg) => write!(f, "execution failed: {}", msg),
        }
    }
}

impl std::error::Error for ExtractorError {}

impl From<serde_json::Error> for ExtractorError {
    fn from(err: serde_json::Error) -> Self {
        Self::Serialization(err.to_string())
    }
}

impl From<base64::DecodeError> for ExtractorError {
    fn from(err: base64::DecodeError) -> Self {
        Self::Base64Decode(err.to_string())
    }
}

impl From<&str> for ExtractorError {
    fn from(msg: &str) -> Self {
        Self::ExecutionFailed(msg.to_string())
    }
}

impl From<String> for ExtractorError {
    fn from(msg: String) -> Self {
        Self::ExecutionFailed(msg)
    }
}
