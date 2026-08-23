use crate::manifest::Manifest;
use crate::runner::auth_provider::AuthProvider;
use crate::runner::limits::{HostCallBudget, MAX_HOST_IMPORT_RESPONSE_BYTES};
use base64::Engine;
use goaria_extractor_sdk::types::{HostHTTPFetchRequest, HostHTTPFetchResponse};
use std::collections::BTreeMap;
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::time::Duration;
use url::Url;

/// Allowed and forbidden header rules
pub const SAFE_REQUEST_HEADERS: &[&str] = &[
    "accept",
    "accept-language",
    "content-type",
    "range",
    "user-agent",
];

pub const FORBIDDEN_PACK_HEADERS: &[&str] =
    &["authorization", "cookie", "proxy-authorization", "host"];

pub const SAFE_RESPONSE_HEADERS: &[&str] = &[
    "content-type",
    "content-length",
    "etag",
    "last-modified",
    "location",
];

/// IP restriction / SSRF prevention checker.
pub fn is_restricted_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => is_restricted_ipv4(ipv4),
        IpAddr::V6(ipv6) => {
            if let Some(ipv4) = ipv6.to_ipv4_mapped() {
                is_restricted_ipv4(ipv4)
            } else {
                is_restricted_ipv6(ipv6)
            }
        }
    }
}

fn is_restricted_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    ip.is_loopback() // 127.0.0.0/8
        || ip.is_private() // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        || ip.is_link_local() // 169.254.0.0/16
        || ip.is_multicast() // 224.0.0.0/4
        || ip.is_broadcast() // 255.255.255.255
        || octets[0] == 0 // Current network (0.0.0.0/8)
        // Carrier-grade NAT (100.64.0.0/10)
        || (octets[0] == 100 && (octets[1] & 0xC0) == 64)
        // IETF protocol assignments (192.0.0.0/24)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        // Documentation TEST-NET-1 (192.0.2.0/24)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        // 6to4 relay anycast (192.88.99.0/24)
        || (octets[0] == 192 && octets[1] == 88 && octets[2] == 99)
        // Benchmark (198.18.0.0/15)
        || (octets[0] == 198 && (octets[1] & 0xFE) == 18)
        // Documentation TEST-NET-2 (198.51.100.0/24)
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        // Documentation TEST-NET-3 (203.0.113.0/24)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
        // Reserved (240.0.0.0/4)
        || (octets[0] >= 240)
}

fn is_restricted_ipv6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    ip.is_loopback() // ::1
        || ip.is_unspecified() // ::
        || ip.is_multicast() // ff00::/8
        // IPv4-IPv6 translation (64:ff9b::/96)
        || (segments[0] == 0x0064
            && segments[1] == 0xff9b
            && segments[2..6].iter().all(|segment| *segment == 0))
        // Local-use IPv4-IPv6 translation (64:ff9b:1::/48)
        || (segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2] == 0x0001)
        // Discard-only prefix (100::/64)
        || (segments[0] == 0x0100 && segments[1..4].iter().all(|segment| *segment == 0))
        // IETF protocol assignments (2001::/23)
        || (segments[0] == 0x2001 && (segments[1] & 0xfe00) == 0)
        // Documentation (2001:db8::/32)
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        // 6to4 (2002::/16)
        || segments[0] == 0x2002
        // Unique Local (fc00::/7)
        || ((segments[0] & 0xfe00) == 0xfc00)
        // Link-Local Unicast (fe80::/10)
        || ((segments[0] & 0xffc0) == 0xfe80)
}

const SSRF_BLOCKED_MARKER: &str = "goaria_ssrf_blocked";

#[derive(Debug, Clone, Copy, Default)]
struct PublicOnlyResolver;

impl ureq::Resolver for PublicOnlyResolver {
    fn resolve(&self, netloc: &str) -> io::Result<Vec<SocketAddr>> {
        let addresses: Vec<_> = netloc.to_socket_addrs()?.collect();
        if addresses.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("host '{netloc}' resolved to no IP addresses"),
            ));
        }
        if let Some(restricted) = addresses
            .iter()
            .find(|address| is_restricted_ip(address.ip()))
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{SSRF_BLOCKED_MARKER}: resolved IP '{}' is not public",
                    restricted.ip()
                ),
            ));
        }

        Ok(addresses)
    }
}

/// Pattern for matching requested URLs against mock rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrlPattern {
    Exact(String),
    Prefix(String),
}

impl UrlPattern {
    pub fn matches(&self, url: &str) -> bool {
        match self {
            Self::Exact(target) => url == target,
            Self::Prefix(prefix) => url.starts_with(prefix),
        }
    }
}

/// Mock rule for simulating broker responses during tests.
#[derive(Debug, Clone)]
pub struct MockBrokerRule {
    pub pattern: UrlPattern,
    pub status_code: i32,
    pub headers: BTreeMap<String, Vec<String>>,
    pub body: Vec<u8>,
}

/// In-memory mock broker for deterministic testing and unit test suites.
#[derive(Debug, Clone, Default)]
pub struct MockBroker {
    rules: Vec<MockBrokerRule>,
}

impl MockBroker {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn add_rule(&mut self, rule: MockBrokerRule) {
        self.rules.push(rule);
    }

    pub fn resolve(&self, req: &HostHTTPFetchRequest) -> Option<HostHTTPFetchResponse> {
        let url = req.url.as_deref()?;

        for rule in &self.rules {
            if rule.pattern.matches(url) {
                let body_b64 = base64::engine::general_purpose::STANDARD.encode(&rule.body);
                let ok = (200..400).contains(&rule.status_code);
                return Some(HostHTTPFetchResponse {
                    ok,
                    status_code: Some(rule.status_code),
                    final_url: Some(url.to_string()),
                    headers: Some(rule.headers.clone()),
                    body_base64: Some(body_b64),
                    error_code: if ok {
                        None
                    } else {
                        Some("http_status_error".to_string())
                    },
                    message: if ok {
                        None
                    } else {
                        Some(format!("mock HTTP error status {}", rule.status_code))
                    },
                });
            }
        }

        None
    }
}

/// Live HTTP network broker using ureq for interactive `run` and live integration testing.
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
        let agent = ureq::AgentBuilder::new()
            .resolver(PublicOnlyResolver)
            .timeout_connect(Duration::from_secs(5))
            .timeout_read(Duration::from_secs(10))
            .redirects(0) // Prevent blind redirection and redirect-based SSRF
            .build();
        Self { agent }
    }

    pub fn fetch(
        &self,
        req: &HostHTTPFetchRequest,
        auth_header: Option<(&str, &str)>,
        manifest_timeout_millis: u64,
        manifest_max_response_bytes: i64,
    ) -> HostHTTPFetchResponse {
        let raw_url = match &req.url {
            Some(u) => u,
            None => {
                return HostHTTPFetchResponse {
                    ok: false,
                    error_code: Some("ref_mode_not_supported_in_live_runner".to_string()),
                    message: Some(
                        "Policy/Endpoint ref mode requires MockBroker in local tests or external broker gateway in production host"
                            .to_string(),
                    ),
                    ..Default::default()
                };
            }
        };

        let parsed_url = match Url::parse(raw_url) {
            Ok(url) => url,
            Err(error) => {
                return HostHTTPFetchResponse {
                    ok: false,
                    error_code: Some("invalid_url".to_string()),
                    message: Some(format!("failed to parse URL: {error}")),
                    ..Default::default()
                };
            }
        };
        if !matches!(parsed_url.scheme(), "http" | "https") {
            return HostHTTPFetchResponse {
                ok: false,
                error_code: Some("invalid_url".to_string()),
                message: Some("URL must use http or https".to_string()),
                ..Default::default()
            };
        }
        let Some(host) = parsed_url.host_str() else {
            return HostHTTPFetchResponse {
                ok: false,
                error_code: Some("invalid_url".to_string()),
                message: Some("URL missing host".to_string()),
                ..Default::default()
            };
        };
        if !parsed_url.username().is_empty() || parsed_url.password().is_some() {
            return HostHTTPFetchResponse {
                ok: false,
                error_code: Some("invalid_url".to_string()),
                message: Some("URL must not contain credentials".to_string()),
                ..Default::default()
            };
        }
        if host.parse::<IpAddr>().is_ok_and(is_restricted_ip) {
            return HostHTTPFetchResponse {
                ok: false,
                error_code: Some("ssrf_blocked".to_string()),
                message: Some("URL host is not a public IP address".to_string()),
                ..Default::default()
            };
        }

        let method = req.method.as_deref().unwrap_or("GET").to_uppercase();
        let mut request = match method.as_str() {
            "GET" => self.agent.get(raw_url),
            "POST" => self.agent.post(raw_url),
            "HEAD" => self.agent.head(raw_url),
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

        let request_timeout_millis = match req.timeout_millis {
            Some(millis) if millis < 0 => {
                return HostHTTPFetchResponse {
                    ok: false,
                    error_code: Some("invalid_timeout_millis".to_string()),
                    message: Some("timeout_millis must not be negative".to_string()),
                    ..Default::default()
                };
            }
            Some(millis) if millis > 0 => (millis as u64).min(manifest_timeout_millis),
            _ => manifest_timeout_millis,
        };
        request = request.timeout(Duration::from_millis(request_timeout_millis));

        // Bound max response bytes strictly against manifest and sanity limits
        let req_max = req
            .max_response_bytes
            .unwrap_or(manifest_max_response_bytes);
        if req_max <= 0 {
            return HostHTTPFetchResponse {
                ok: false,
                error_code: Some("invalid_max_response_bytes".to_string()),
                message: Some("max_response_bytes must be positive".to_string()),
                ..Default::default()
            };
        }
        let max_bytes = (req_max
            .min(manifest_max_response_bytes)
            .min(MAX_HOST_IMPORT_RESPONSE_BYTES as i64)) as usize;

        match request.call() {
            Ok(response) => Self::process_response(response, max_bytes),
            Err(ureq::Error::Status(_, response)) => Self::process_response(response, max_bytes),
            Err(ureq::Error::Transport(transport_err)) => {
                let message = transport_err.to_string();
                HostHTTPFetchResponse {
                    ok: false,
                    error_code: Some(
                        if message.contains(SSRF_BLOCKED_MARKER) {
                            "ssrf_blocked"
                        } else {
                            "transport_error"
                        }
                        .to_string(),
                    ),
                    message: Some(message.replace(SSRF_BLOCKED_MARKER, "SSRF policy blocked")),
                    ..Default::default()
                }
            }
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
            Self::Live(live) => live.fetch(
                &req,
                auth_header,
                manifest.resource_limits.timeout_millis,
                manifest.resource_limits.max_response_bytes,
            ),
            Self::Disabled => HostHTTPFetchResponse {
                ok: false,
                error_code: Some("broker_disabled".to_string()),
                message: Some("host network broker is disabled".to_string()),
                ..Default::default()
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{LiveBroker, PublicOnlyResolver, SSRF_BLOCKED_MARKER};
    use goaria_extractor_sdk::types::HostHTTPFetchRequest;
    use ureq::Resolver;

    #[test]
    fn transport_resolver_returns_only_validated_addresses() {
        let resolver = PublicOnlyResolver;
        let public = resolver.resolve("8.8.8.8:443").unwrap();
        assert_eq!(public.len(), 1);
        assert_eq!(public[0].ip().to_string(), "8.8.8.8");

        let error = resolver.resolve("127.0.0.1:80").unwrap_err();
        assert!(error.to_string().contains(SSRF_BLOCKED_MARKER));
    }

    #[test]
    fn live_agent_blocks_dns_results_at_connection_time() {
        let response = LiveBroker::new().fetch(
            &HostHTTPFetchRequest {
                url: Some("http://localhost/".to_string()),
                ..Default::default()
            },
            None,
            1_000,
            1_024,
        );
        assert!(!response.ok);
        assert_eq!(response.error_code.as_deref(), Some("ssrf_blocked"));
    }
}
