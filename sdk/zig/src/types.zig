const std = @import("std");

/// Manifest capability: compile and instantiate the WebAssembly payload.
pub const CAPABILITY_PARSE_WASM = "cap.parse.wasm";
/// Manifest capability: invoke goaria_host.http_fetch (GET/HEAD, safe headers).
pub const CAPABILITY_HTTP_FETCH = "cap.http.fetch";
/// Manifest capability: extended fetch features (POST, request body,
/// pack-owned Authorization or X-* headers). Requires cap.http.fetch.
pub const CAPABILITY_HTTP_FETCH_EXTENDED = "cap.http.fetch.extended";
/// Manifest capability: use host-custody auth profiles.
pub const CAPABILITY_AUTH_PROFILE = "cap.auth.profile";
/// Manifest capability: register a self-minted bearer credential for the
/// materialized download Authorization header.
pub const CAPABILITY_DOWNLOAD_AUTH = "cap.download.auth";

/// Key-value string map (e.g. metadata, params, request headers).
pub const StringMap = std.json.ArrayHashMap([]const u8);

/// Multi-value header map (e.g. response headers).
pub const HeaderMap = std.json.ArrayHashMap([]const []const u8);

/// Input payload passed to `goaria_match`.
pub const MatchInput = struct {
    /// Candidate URL the host asks the pack to evaluate.
    url: []const u8,
};

/// Output payload returned by `goaria_match`.
pub const MatchOutput = struct {
    /// Whether the pack supports the candidate URL. The host only invokes
    /// `goaria_extract` on a pack that reports `true` here.
    matched: bool,
    /// Match confidence, 0–100; `null` omits the field, which the host
    /// decodes as `0`. Emitting `100` for a confident match is an SDK
    /// convention, not a wire default.
    confidence: ?u8 = null,
    /// Optional human-readable explanation. The host rejects reasons longer
    /// than 512 bytes or containing control characters.
    reason: ?[]const u8 = null,

    /// Confident match result (`matched: true`, `confidence: 100` — an SDK
    /// convention; the ABI assigns no meaning to a particular value).
    pub fn matchedResult() MatchOutput {
        return .{
            .matched = true,
            .confidence = 100,
            .reason = null,
        };
    }

    /// Negative match result (`matched: false`, no confidence or reason).
    pub fn unmatchedResult() MatchOutput {
        return .{
            .matched = false,
            .confidence = null,
            .reason = null,
        };
    }

    /// Return a copy with `confidence` overridden (0–100).
    pub fn withConfidence(self: MatchOutput, conf: u8) MatchOutput {
        var copy = self;
        copy.confidence = conf;
        return copy;
    }

    /// Return a copy with `reason` set (see the field for host limits).
    pub fn withReason(self: MatchOutput, r: []const u8) MatchOutput {
        var copy = self;
        copy.reason = r;
        return copy;
    }
};

/// Input payload passed to `goaria_extract`.
pub const ExtractInput = struct {
    /// URL the host asks the pack to extract downloadable items from.
    url: []const u8,
};

/// Reference to a single extracted resource item.
///
/// The host validates every emitted item: `url` must be a trimmed http(s)
/// URL of at most 2048 bytes without embedded credentials; string fields are
/// limited to 1024 bytes of valid UTF-8 without control characters; and
/// `metadata` accepts at most 16 entries (keys non-empty and at most 64
/// bytes, values at most 512 bytes, no credential-shaped key names such as
/// `authorization`, `cookie`, `token`, or `api_key`).
pub const ExtractedItemRef = struct {
    /// Optional pack-assigned identifier for the item.
    id: ?[]const u8 = null,
    /// Direct downloadable URL (http/https only).
    url: ?[]const u8 = null,
    /// Suggested destination filename.
    filename: ?[]const u8 = null,
    /// Known artifact size in bytes; the host rejects negative values.
    size_bytes: ?i64 = null,
    /// Content MIME type.
    mime_type: ?[]const u8 = null,
    /// Opaque reference to an authentication profile held in host custody;
    /// the host injects the credential when running the download. Mutually
    /// exclusive with `download_auth_ref`.
    auth_profile_ref: ?[]const u8 = null,
    /// Opaque host header profile reference. Mutually exclusive with
    /// `download_auth_ref`.
    header_profile_ref: ?[]const u8 = null,
    /// Opaque host-registered download-auth reference (`dar-` + 32 lowercase
    /// hex) obtained from `register_download_auth` during the same
    /// invocation. A raw token must never cross the ABI in this or any other
    /// field; the host rejects stale, cross-pack, or raw-token-equal values.
    /// Mutually exclusive with `auth_profile_ref` / `header_profile_ref`.
    download_auth_ref: ?[]const u8 = null,
    /// Key-value contextual metadata forwarded to the host (limits above;
    /// credential-shaped keys are rejected).
    metadata: ?StringMap = null,
};

/// Output payload returned by `goaria_extract`.
///
/// An `extract` error or a guest trap surfaces to the host as the empty
/// output (`{"items":[]}`); ABI v1 defines no error channel for extraction.
/// `items` is bounded by the manifest `resource_limits.max_output_items` /
/// `max_output_bytes`.
pub const ExtractOutput = struct {
    items: []const ExtractedItemRef,

    /// Empty extraction result.
    pub fn empty() ExtractOutput {
        return .{ .items = &.{} };
    }

    /// Extraction result containing exactly one item; the returned slice is
    /// allocated from `allocator`.
    pub fn single(allocator: std.mem.Allocator, item: ExtractedItemRef) !ExtractOutput {
        const slice = try allocator.alloc(ExtractedItemRef, 1);
        slice[0] = item;
        return .{ .items = slice };
    }
};

/// Kind of credential secret stored in an auth profile.
pub const AuthSecretKind = enum {
    /// Bearer-token credential materialized as `Authorization: Bearer <token>`.
    bearer,
    /// Cookie-based credential.
    cookie,
};

/// Request payload sent to host import `goaria_host.http_fetch`.
///
/// A request uses exactly one addressing mode: raw mode sets `url`, while
/// ref mode sets `broker_policy_ref` + `endpoint_ref` (plus optional
/// `params`) under an alias manifest. Mixing modes is rejected as
/// `invalid_request`. Requires `cap.http.fetch`; extended features
/// additionally require `cap.http.fetch.extended`, must target HTTPS, and
/// fail closed on any redirect.
pub const HostHTTPFetchRequest = struct {
    /// HTTP method: `GET` (default), `HEAD`, or `POST`.
    method: ?[]const u8 = null,
    /// Raw-mode target URL; mutually exclusive with the ref-mode fields.
    url: ?[]const u8 = null,
    /// Ref-mode broker policy reference; only valid paired with `endpoint_ref`.
    broker_policy_ref: ?[]const u8 = null,
    /// Ref-mode endpoint reference; only valid paired with `broker_policy_ref`.
    endpoint_ref: ?[]const u8 = null,
    /// Ref-mode path/query substitution parameters.
    params: ?StringMap = null,
    /// Request headers. Under `cap.http.fetch` only the safe names `Accept`,
    /// `Accept-Language`, `Content-Type`, `Referer`, and `User-Agent` pass;
    /// pack-owned `Authorization` and business `X-*` names additionally
    /// require `cap.http.fetch.extended`. `Cookie`, `Set-Cookie`, `Host`,
    /// `Content-Length`, `Transfer-Encoding`, `Connection`, and
    /// `Proxy-Authorization` are always rejected. At most 16 headers with
    /// values of at most 1024 bytes each.
    headers: ?StringMap = null,
    /// Strict padded standard base64 request body, decoded cap 16 KiB.
    /// Requires `method = "POST"`, `cap.http.fetch.extended`, and exactly one
    /// `Content-Type` of `application/json` or
    /// `application/x-www-form-urlencoded`.
    body_base64: ?[]const u8 = null,
    /// Host auth profile reference; mutually exclusive with extended-fetch
    /// features and with `omit_browser_context`.
    auth_profile_ref: ?[]const u8 = null,
    /// Per-request timeout in milliseconds; `null`/`0` means unset. The
    /// effective deadline is the smallest positive of request, manifest, and
    /// broker policy maximum.
    timeout_millis: ?i32 = null,
    /// Per-request response byte cap; `null`/`0` means unset. The effective
    /// cap is the smallest positive of request, manifest, and broker policy
    /// maximum.
    max_response_bytes: ?i64 = null,
    /// When `true`, the request is treated as self-authenticated: the host
    /// suppresses all browser-owned context (browser credential grants,
    /// cookies, `User-Agent`, `Accept-Language`, `Referer`) for this request.
    /// Combining it with `auth_profile_ref` is rejected as `invalid_request`.
    omit_browser_context: ?bool = null,
};

/// Response payload received from host import `goaria_host.http_fetch`.
pub const HostHTTPFetchResponse = struct {
    /// Whether the HTTP call succeeded and was permitted by policy.
    ok: bool,
    /// HTTP status code (e.g. `200`, `404`).
    status_code: ?i32 = null,
    /// URL after redirects; secret-shaped values are redacted by the host.
    final_url: ?[]const u8 = null,
    /// Response headers, restricted to the host's safe allowlist
    /// (`Content-Length`, `Content-Type`, `Etag`, `Last-Modified`) under
    /// canonical `Title-Case` names with secret-shaped values redacted.
    headers: ?HeaderMap = null,
    /// Base64-encoded response payload bytes.
    body_base64: ?[]const u8 = null,
    /// Stable machine-readable error code when `ok` is `false`.
    ///
    /// Host categories: `invalid_request`, `policy_denied`, `fetch_failed` /
    /// `authenticated_fetch_failed`, `budget_exhausted`, `not_configured`,
    /// `response_too_large`, `internal_error`. The local CLI additionally
    /// emits `no_mock_match`, `broker_disabled`, and
    /// `ref_mode_not_supported_in_live_runner`.
    error_code: ?[]const u8 = null,
    /// Human-readable error detail when `ok` is `false`.
    message: ?[]const u8 = null,
};

/// Request payload sent to host import `goaria_host.auth_profile_status`.
///
/// Like the fetch request, exactly one addressing mode applies: `url` for
/// raw mode or `broker_policy_ref` + `endpoint_ref` (+ `params`) for ref
/// mode.
pub const HostAuthProfileStatusRequest = struct {
    /// Opaque host authentication profile reference to query.
    auth_profile_ref: []const u8,
    /// Raw-mode URL the profile would be used for.
    url: ?[]const u8 = null,
    /// Ref-mode broker policy reference; only valid paired with `endpoint_ref`.
    broker_policy_ref: ?[]const u8 = null,
    /// Ref-mode endpoint reference; only valid paired with `broker_policy_ref`.
    endpoint_ref: ?[]const u8 = null,
    /// Ref-mode path/query substitution parameters.
    params: ?StringMap = null,
};

/// Response payload received from host import `goaria_host.auth_profile_status`.
pub const HostAuthProfileStatusResponse = struct {
    /// Whether status resolution succeeded.
    ok: bool,
    /// Whether credentials exist in host custody for the profile.
    available: ?bool = null,
    /// Credential kind (`bearer` or `cookie`).
    kind: ?AuthSecretKind = null,
    /// Safe masked representation of the credential for UI display.
    redacted_display: ?[]const u8 = null,
    /// Stable machine-readable error code when `ok` is `false`.
    ///
    /// Host categories: `invalid_request`, `policy_denied`,
    /// `budget_exhausted`, `not_configured`, `auth_unavailable`,
    /// `response_too_large`, `internal_error`.
    error_code: ?[]const u8 = null,
    /// Human-readable error detail when `ok` is `false`.
    message: ?[]const u8 = null,
};

/// Request payload sent to host import `goaria_host.register_download_auth`.
/// Only `kind = "bearer"` exists; the token never leaves the host except as
/// the materialized Authorization header.
pub const HostRegisterDownloadAuthRequest = struct {
    /// Registration kind; only `"bearer"` is defined.
    kind: []const u8,
    /// Raw bearer token: 1–8170 bytes of valid UTF-8 without CR/LF, and it
    /// must not already carry a `Bearer ` scheme prefix (case-insensitive).
    token: []const u8,
};

/// Response payload received from `goaria_host.register_download_auth`.
pub const HostRegisterDownloadAuthResponse = struct {
    /// Whether registration succeeded.
    ok: bool,
    /// Opaque `dar-` + 32 lowercase hex reference bound to the registering
    /// pack identity and the current invocation.
    download_auth_ref: ?[]const u8 = null,
    /// Stable machine-readable error code when `ok` is `false`.
    ///
    /// Host categories: `invalid_request`, `policy_denied`,
    /// `budget_exhausted`, `not_configured` (registry not wired; the local
    /// CLI also emits this when the broker is disabled), `registry_full`,
    /// `response_too_large`, `internal_error`.
    error_code: ?[]const u8 = null,
    /// Human-readable error detail when `ok` is `false`.
    message: ?[]const u8 = null,
};

/// Request payload sent to host import `goaria_host.host_time`. The wire
/// shape is intentionally empty: any field is an invalid_request on the host.
pub const HostTimeRequest = struct {};

/// Response payload received from `goaria_host.host_time`.
pub const HostTimeResponse = struct {
    /// Whether the call succeeded.
    ok: bool,
    /// Unix timestamp (seconds) frozen for the duration of one invocation;
    /// repeated calls inside the same `goaria_extract` return the same value.
    unix_secs: ?i64 = null,
    /// Stable machine-readable error code when `ok` is `false`.
    ///
    /// Host categories: `invalid_request`, `budget_exhausted`,
    /// `response_too_large`, `internal_error`. The local CLI answers
    /// `host_time` even when the broker is disabled — `not_configured` is
    /// never emitted for this import.
    error_code: ?[]const u8 = null,
    /// Human-readable error detail when `ok` is `false`.
    message: ?[]const u8 = null,
};

// Unit Tests
test "MatchInput parsing and MatchOutput serialization" {
    const allocator = std.testing.allocator;
    const json_str = "{\"url\":\"https://share.fixture.invalid/file/123\"}";
    const parsed = try std.json.parseFromSlice(
        MatchInput,
        allocator,
        json_str,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();
    try std.testing.expectEqualStrings("https://share.fixture.invalid/file/123", parsed.value.url);

    const match_out = MatchOutput.matchedResult()
        .withConfidence(95)
        .withReason("matched fixture");
    const out_json = try std.fmt.allocPrint(
        allocator,
        "{f}",
        .{std.json.fmt(match_out, .{ .emit_null_optional_fields = false })},
    );
    defer allocator.free(out_json);
    try std.testing.expectEqualStrings(
        "{\"matched\":true,\"confidence\":95,\"reason\":\"matched fixture\"}",
        out_json,
    );
}

test "ExtractInput parsing and ExtractOutput serialization" {
    const allocator = std.testing.allocator;
    const json_str = "{\"url\":\"https://share.fixture.invalid/file/123\"}";
    const parsed = try std.json.parseFromSlice(
        ExtractInput,
        allocator,
        json_str,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();
    try std.testing.expectEqualStrings("https://share.fixture.invalid/file/123", parsed.value.url);

    const items = [_]ExtractedItemRef{
        .{
            .id = "item-01",
            .url = "https://download.fixture.invalid/file.bin",
            .filename = "file.bin",
            .size_bytes = 2048,
            .mime_type = "application/octet-stream",
        },
    };
    const extract_out = ExtractOutput{ .items = &items };
    const out_json = try std.fmt.allocPrint(
        allocator,
        "{f}",
        .{std.json.fmt(extract_out, .{ .emit_null_optional_fields = false })},
    );
    defer allocator.free(out_json);
    try std.testing.expect(std.mem.indexOf(u8, out_json, "\"id\":\"item-01\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out_json, "\"size_bytes\":2048") != null);
}

test "HostHTTPFetchRequest body_base64 wire contract" {
    const allocator = std.testing.allocator;

    const req = HostHTTPFetchRequest{
        .method = "POST",
        .url = "https://api.fixture.invalid/v1/submit",
        .body_base64 = "aGVsbG8=",
    };
    const req_json = try std.fmt.allocPrint(
        allocator,
        "{f}",
        .{std.json.fmt(req, .{ .emit_null_optional_fields = false })},
    );
    defer allocator.free(req_json);
    try std.testing.expect(std.mem.indexOf(u8, req_json, "\"body_base64\":\"aGVsbG8=\"") != null);

    const parsed = try std.json.parseFromSlice(
        HostHTTPFetchRequest,
        allocator,
        req_json,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();
    try std.testing.expectEqualStrings("aGVsbG8=", parsed.value.body_base64.?);

    // null must not emit the key (omitempty parity)
    const bare = HostHTTPFetchRequest{ .url = "https://api.fixture.invalid/" };
    const bare_json = try std.fmt.allocPrint(
        allocator,
        "{f}",
        .{std.json.fmt(bare, .{ .emit_null_optional_fields = false })},
    );
    defer allocator.free(bare_json);
    try std.testing.expect(std.mem.indexOf(u8, bare_json, "body_base64") == null);

    // explicit null parses back to absent
    const explicit_null = try std.json.parseFromSlice(
        HostHTTPFetchRequest,
        allocator,
        "{\"url\":\"https://api.fixture.invalid/\",\"body_base64\":null}",
        .{ .ignore_unknown_fields = true },
    );
    defer explicit_null.deinit();
    try std.testing.expect(explicit_null.value.body_base64 == null);
}

test "HostHTTPFetchResponse parsing" {
    const allocator = std.testing.allocator;
    const json_str = "{\"ok\":true,\"status_code\":200,\"final_url\":\"https://share.fixture.invalid/res\",\"body_base64\":\"aGVsbG8=\"}";
    const parsed = try std.json.parseFromSlice(
        HostHTTPFetchResponse,
        allocator,
        json_str,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();
    try std.testing.expect(parsed.value.ok);
    try std.testing.expectEqual(@as(?i32, 200), parsed.value.status_code);
    try std.testing.expectEqualStrings("https://share.fixture.invalid/res", parsed.value.final_url.?);
    try std.testing.expectEqualStrings("aGVsbG8=", parsed.value.body_base64.?);
}

test "download_auth_ref and omit_browser_context wire contract" {
    const allocator = std.testing.allocator;

    const item = ExtractedItemRef{
        .id = "item-1",
        .download_auth_ref = "dar-0123456789abcdef0123456789abcdef",
    };
    const item_json = try std.fmt.allocPrint(
        allocator,
        "{f}",
        .{std.json.fmt(item, .{ .emit_null_optional_fields = false })},
    );
    defer allocator.free(item_json);
    try std.testing.expect(std.mem.indexOf(
        u8,
        item_json,
        "\"download_auth_ref\":\"dar-0123456789abcdef0123456789abcdef\"",
    ) != null);

    const req = HostHTTPFetchRequest{
        .url = "https://api.fixture.invalid/v1",
        .omit_browser_context = true,
    };
    const req_json = try std.fmt.allocPrint(
        allocator,
        "{f}",
        .{std.json.fmt(req, .{ .emit_null_optional_fields = false })},
    );
    defer allocator.free(req_json);
    try std.testing.expect(std.mem.indexOf(u8, req_json, "\"omit_browser_context\":true") != null);

    // null must not emit the key (omitempty parity)
    const bare = HostHTTPFetchRequest{ .url = "https://api.fixture.invalid/" };
    const bare_json = try std.fmt.allocPrint(
        allocator,
        "{f}",
        .{std.json.fmt(bare, .{ .emit_null_optional_fields = false })},
    );
    defer allocator.free(bare_json);
    try std.testing.expect(std.mem.indexOf(u8, bare_json, "omit_browser_context") == null);

    const parsed = try std.json.parseFromSlice(
        HostHTTPFetchRequest,
        allocator,
        req_json,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();
    try std.testing.expectEqual(@as(?bool, true), parsed.value.omit_browser_context);
}

test "register_download_auth and host_time DTO wire contract" {
    const allocator = std.testing.allocator;

    const req = HostRegisterDownloadAuthRequest{
        .kind = "bearer",
        .token = "opaque-token-42",
    };
    const req_json = try std.fmt.allocPrint(
        allocator,
        "{f}",
        .{std.json.fmt(req, .{ .emit_null_optional_fields = false })},
    );
    defer allocator.free(req_json);
    try std.testing.expectEqualStrings(
        "{\"kind\":\"bearer\",\"token\":\"opaque-token-42\"}",
        req_json,
    );

    const resp = try std.json.parseFromSlice(
        HostRegisterDownloadAuthResponse,
        allocator,
        "{\"ok\":true,\"download_auth_ref\":\"dar-0123456789abcdef0123456789abcdef\"}",
        .{ .ignore_unknown_fields = true },
    );
    defer resp.deinit();
    try std.testing.expect(resp.value.ok);
    try std.testing.expectEqualStrings(
        "dar-0123456789abcdef0123456789abcdef",
        resp.value.download_auth_ref.?,
    );

    // host_time request serializes to exactly {}
    const time_json = try std.fmt.allocPrint(
        allocator,
        "{f}",
        .{std.json.fmt(HostTimeRequest{}, .{ .emit_null_optional_fields = false })},
    );
    defer allocator.free(time_json);
    try std.testing.expectEqualStrings("{}", time_json);

    const time_resp = try std.json.parseFromSlice(
        HostTimeResponse,
        allocator,
        "{\"ok\":true,\"unix_secs\":1800000000}",
        .{ .ignore_unknown_fields = true },
    );
    defer time_resp.deinit();
    try std.testing.expect(time_resp.value.ok);
    try std.testing.expectEqual(@as(?i64, 1800000000), time_resp.value.unix_secs);
}
