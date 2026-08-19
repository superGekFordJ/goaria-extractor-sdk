use std::fmt;

/// Standard error type for GoAria extractor operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractorError {
    Serialization(String),
    HostError { error_code: String, message: String },
    HttpError { status_code: i32, message: String },
    InvalidInput(String),
    Base64Decode(String),
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
