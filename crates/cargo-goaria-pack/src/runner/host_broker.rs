use base64::Engine;
use regex::Regex;
use std::collections::BTreeMap;
use std::io::Read;
use std::time::Duration;

use goaria_extractor_sdk::types::{HostHTTPFetchRequest, HostHTTPFetchResponse};

use crate::manifest::Manifest;
use crate::runner::auth_provider::AuthProvider;
use crate::runner::limits::{HostCallBudget, MAX_HOST_IMPORT_RESPONSE_BYTES};

const DEFAULT_REDIRECT_LIMIT: usize = 5;

static SAFE_REQUEST_HEADERS: &[&str] = &[
    "accept",
    "accept-language",
    "content-type",
    "referer",
    "user-agent",
];

static SAFE_RESPONSE_HEADERS: &[&str] =
    &["content-length", "content-type", "etag", "last-modified"];

static FORBIDDEN_PACK_HEADERS: &[&str] = &[
    "authorization",
    "cookie",
    "set-cookie",
    "host",
    "connection",
    "proxy-authorization",
    "transfer-encoding",
];

/// Match condition for mock HTTP broker rules.
#[derive(Debug, Clone)]
pub enum UrlPattern {
    Exact(String),
    Prefix(String),
    Regex(Regex),
    EndpointRef {
        policy_ref: String,
        endpoint_ref: String,
    },
}

impl UrlPattern {
    pub fn matches(&self, req: &HostHTTPFetchRequest) -> bool {
        match self {
            Self::Exact(url) => req.url.as_deref() == Some(url.as_str()),
            Self::Prefix(prefix) => req.url.as_deref().is_some_and(|u| u.starts_with(prefix)),
            Self::Regex(re) => req.url.as_deref().is_some_and(|u| re.is_match(u)),
            Self::EndpointRef {
                policy_ref,
                endpoint_ref,
            } => {
                req.broker_policy_ref.as_deref() == Some(policy_ref.as_str())
                    && req.endpoint_ref.as_deref() == Some(endpoint_ref.as_str())
            }
        }
    }
}

/// A configured mock response rule.
#[derive(Debug, Clone)]
pub struct MockBrokerRule {
    pub pattern: UrlPattern,
    pub status_code: i32,
    pub headers: BTreeMap<String, Vec<String>>,
    pub body: Vec<u8>,
}

/// Deterministic mock host broker.
#[derive(Debug, Default, Clone)]
pub struct MockBroker {
    rules: Vec<MockBrokerRule>,
}

impl MockBroker {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn add_rule(&mut self, rule: MockBrokerRule) -> &mut Self {
        self.rules.push(rule);
        self
    }

    pub fn add_mock_response(
        &mut self,
        pattern: UrlPattern,
        status_code: i32,
        headers: BTreeMap<String, Vec<String>>,
        body: Vec<u8>,
    ) -> &mut Self {
        self.add_rule(MockBrokerRule {
            pattern,
            status_code,
            headers,
            body,
        })
    }

    pub fn add_mock_json(
        &mut self,
        pattern: UrlPattern,
        status_code: i32,
        json_val: &serde_json::Value,
    ) -> &mut Self {
        let body = serde_json::to_vec(json_val).unwrap_or_default();
        let mut headers = BTreeMap::new();
        headers.insert(
            "Content-Type".to_string(),
            vec!["application/json".to_string()],
        );
        headers.insert("Content-Length".to_string(), vec![body.len().to_string()]);

        self.add_rule(MockBrokerRule {
            pattern,
            status_code,
            headers,
            body,
        })
    }

    pub fn resolve(&self, req: &HostHTTPFetchRequest) -> Option<HostHTTPFetchResponse> {
        for rule in &self.rules {
            if rule.pattern.matches(req) {
                let body_b64 = base64::engine::general_purpose::STANDARD.encode(&rule.body);
                return Some(HostHTTPFetchResponse {
                    ok: (200..400).contains(&rule.status_code),
                    status_code: Some(rule.status_code),
                    final_url: req.url.clone(),
                    headers: Some(rule.headers.clone()),
                    body_base64: Some(body_b64),
                    error_code: None,
                    message: None,
                });
            }
        }
        None
    }
}

/// Live synchronous HTTP broker powered by `ureq`.
#[derive(Debug, Clone)]
pub struct LiveBroker {
    agent: ureq::Agent,
}

impl Default for LiveBroker {
    fn default() -> Self {
        Self::new()
    }
}

impl LiveBroker {
    pub fn new() -> Self {
        let agent = ureq::builder()
            .timeout_connect(Duration::from_secs(5))
            .timeout_read(Duration::from_secs(10))
            .redirects(DEFAULT_REDIRECT_LIMIT as u32)
            .build();

        Self { agent }
    }

    pub fn fetch(
        &self,
        req: &HostHTTPFetchRequest,
        auth_header: Option<(&str, &str)>,
    ) -> HostHTTPFetchResponse {
        let url_str = match req.url.as_deref() {
            Some(u) => u,
            None => {
                return HostHTTPFetchResponse {
                    ok: false,
                    error_code: Some("invalid_request".to_string()),
                    message: Some("missing request url".to_string()),
                    ..Default::default()
                };
            }
        };

        let method = req.method.as_deref().unwrap_or("GET").to_uppercase();
        let mut request = match method.as_str() {
            "GET" => self.agent.get(url_str),
            "HEAD" => self.agent.head(url_str),
            "POST" => self.agent.post(url_str),
            _ => {
                return HostHTTPFetchResponse {
                    ok: false,
                    error_code: Some("unsupported_method".to_string()),
                    message: Some(format!("HTTP method '{}' is not supported", method)),
                    ..Default::default()
                };
            }
        };

        // Attach safe request headers
        if let Some(headers) = &req.headers {
            for (k, v) in headers {
                let lower = k.trim().to_lowercase();
                if FORBIDDEN_PACK_HEADERS.contains(&lower.as_str()) {
                    continue;
                }
                if SAFE_REQUEST_HEADERS.contains(&lower.as_str()) {
                    request = request.set(k, v);
                }
            }
        }

        // Attach host-injected auth credentials if resolved
        if let Some((name, val)) = auth_header {
            request = request.set(name, val);
        }

        // Set request timeout
        if let Some(millis) = req.timeout_millis {
            if millis > 0 {
                request = request.timeout(Duration::from_millis(millis as u64));
            }
        }

        let max_bytes = req
            .max_response_bytes
            .unwrap_or(MAX_HOST_IMPORT_RESPONSE_BYTES as i64) as usize;

        match request.call() {
            Ok(response) => Self::process_response(response, max_bytes),
            Err(ureq::Error::Status(_, response)) => Self::process_response(response, max_bytes),
            Err(ureq::Error::Transport(transport_err)) => HostHTTPFetchResponse {
                ok: false,
                error_code: Some("transport_error".to_string()),
                message: Some(transport_err.to_string()),
                ..Default::default()
            },
        }
    }

    fn process_response(response: ureq::Response, max_bytes: usize) -> HostHTTPFetchResponse {
        let status = response.status() as i32;
        let final_url = response.get_url().to_string();

        let mut resp_headers = BTreeMap::new();
        for safe_header in SAFE_RESPONSE_HEADERS {
            if let Some(val) = response.header(safe_header) {
                resp_headers.insert(safe_header.to_string(), vec![val.to_string()]);
            }
        }

        let mut reader = response.into_reader();
        let mut body_bytes = Vec::new();
        let mut chunk = [0u8; 8192];

        loop {
            match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    if body_bytes.len() + n > max_bytes {
                        return HostHTTPFetchResponse {
                            ok: false,
                            status_code: Some(status),
                            final_url: Some(final_url),
                            headers: Some(resp_headers),
                            error_code: Some("response_too_large".to_string()),
                            message: Some(format!(
                                "response body exceeds {} bytes limit",
                                max_bytes
                            )),
                            ..Default::default()
                        };
                    }
                    body_bytes.extend_from_slice(&chunk[..n]);
                }
                Err(e) => {
                    return HostHTTPFetchResponse {
                        ok: false,
                        status_code: Some(status),
                        final_url: Some(final_url),
                        headers: Some(resp_headers),
                        error_code: Some("read_error".to_string()),
                        message: Some(format!("failed to read response body: {}", e)),
                        ..Default::default()
                    };
                }
            }
        }

        let body_b64 = base64::engine::general_purpose::STANDARD.encode(&body_bytes);
        let ok = (200..400).contains(&status);
        HostHTTPFetchResponse {
            ok,
            status_code: Some(status),
            final_url: Some(final_url),
            headers: Some(resp_headers),
            body_base64: Some(body_b64),
            error_code: if ok {
                None
            } else {
                Some("http_status_error".to_string())
            },
            message: if ok {
                None
            } else {
                Some(format!("HTTP error status {}", status))
            },
        }
    }
}

/// Top-level broker dispatch enum.
#[derive(Debug, Clone)]
pub enum HostBroker {
    Mock(MockBroker),
    Live(LiveBroker),
    Disabled,
}

impl HostBroker {
    pub fn handle_fetch(
        &self,
        manifest: &Manifest,
        budget: &mut HostCallBudget,
        req: HostHTTPFetchRequest,
        auth_provider: &AuthProvider,
    ) -> HostHTTPFetchResponse {
        // 1. Consume budget
        if let Err(e) = budget.consume() {
            return HostHTTPFetchResponse {
                ok: false,
                error_code: Some("budget_exhausted".to_string()),
                message: Some(e.to_string()),
                ..Default::default()
            };
        }

        // 2. Validate capability
        if !manifest.has_capability("cap.http.fetch") {
            return HostHTTPFetchResponse {
                ok: false,
                error_code: Some("permission_denied".to_string()),
                message: Some("pack does not have capability 'cap.http.fetch'".to_string()),
                ..Default::default()
            };
        }

        // 3. Validate domain rules
        if let Some(url) = &req.url {
            match manifest.allows_url(url) {
                Ok(true) => {}
                Ok(false) => {
                    return HostHTTPFetchResponse {
                        ok: false,
                        error_code: Some("domain_not_allowed".to_string()),
                        message: Some(format!(
                            "URL '{}' not allowed by manifest domain rules",
                            url
                        )),
                        ..Default::default()
                    };
                }
                Err(e) => {
                    return HostHTTPFetchResponse {
                        ok: false,
                        error_code: Some("invalid_url".to_string()),
                        message: Some(e.to_string()),
                        ..Default::default()
                    };
                }
            }
        }

        // 4. Resolve auth secret if profile ref provided
        let secret_holder = if let Some(profile_ref) = &req.auth_profile_ref {
            if !manifest.has_capability("cap.auth.profile") {
                return HostHTTPFetchResponse {
                    ok: false,
                    error_code: Some("permission_denied".to_string()),
                    message: Some("pack does not have capability 'cap.auth.profile'".to_string()),
                    ..Default::default()
                };
            }
            auth_provider.get_secret(profile_ref)
        } else {
            None
        };
        let auth_header = secret_holder.as_deref().map(|s| ("Authorization", s));

        // 5. Dispatch to Mock or Live
        match self {
            Self::Mock(mock) => {
                if let Some(resp) = mock.resolve(&req) {
                    resp
                } else {
                    HostHTTPFetchResponse {
                        ok: false,
                        error_code: Some("no_mock_match".to_string()),
                        message: Some(format!(
                            "no mock rule matched request for URL: {:?}",
                            req.url
                        )),
                        ..Default::default()
                    }
                }
            }
            Self::Live(live) => live.fetch(&req, auth_header),
            Self::Disabled => HostHTTPFetchResponse {
                ok: false,
                error_code: Some("broker_disabled".to_string()),
                message: Some("host network broker is disabled".to_string()),
                ..Default::default()
            },
        }
    }
}
