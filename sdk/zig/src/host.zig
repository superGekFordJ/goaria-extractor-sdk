const std = @import("std");
const builtin = @import("builtin");
const types = @import("types.zig");
const abi = @import("abi.zig");

/// Low-level host imports for the "goaria_host" module. On wasm32 these are
/// extern imports; on native targets they are stubs returning `0`.
///
/// Shared convention: the request buffer is guest-owned — the host reads it
/// during the call and does not retain it. The return value is a packed
/// `ptr << 32 | len` handle to a response buffer the host allocated inside
/// the guest via `goaria_alloc`; the guest owns it and must release it with
/// `goaria_free` (`GuestBuffer.deinit`). A `0` return is a transport-level
/// failure — no response was written — while host-reported failures travel
/// inside the response payload (`ok: false` + `error_code`).
pub const raw = if (builtin.target.cpu.arch.isWasm()) struct {
    /// Brokered HTTP fetch (`cap.http.fetch`; extended features additionally
    /// require `cap.http.fetch.extended`).
    pub extern "goaria_host" fn http_fetch(req_ptr: i32, req_len: i32) i64;
    /// Auth-profile availability query (`cap.auth.profile`).
    pub extern "goaria_host" fn auth_profile_status(req_ptr: i32, req_len: i32) i64;
    /// Register a pack-minted bearer token (`cap.download.auth`).
    pub extern "goaria_host" fn register_download_auth(req_ptr: i32, req_len: i32) i64;
    /// Invocation-frozen Unix timestamp (no capability required).
    pub extern "goaria_host" fn host_time(req_ptr: i32, req_len: i32) i64;
} else struct {
    /// Native stub for `http_fetch`; always returns `0`.
    pub fn http_fetch(req_ptr: i32, req_len: i32) i64 {
        _ = req_ptr;
        _ = req_len;
        return 0;
    }
    /// Native stub for `auth_profile_status`; always returns `0`.
    pub fn auth_profile_status(req_ptr: i32, req_len: i32) i64 {
        _ = req_ptr;
        _ = req_len;
        return 0;
    }
    /// Native stub for `register_download_auth`; always returns `0`.
    pub fn register_download_auth(req_ptr: i32, req_len: i32) i64 {
        _ = req_ptr;
        _ = req_len;
        return 0;
    }
    /// Native stub for `host_time`; always returns `0`.
    pub fn host_time(req_ptr: i32, req_len: i32) i64 {
        _ = req_ptr;
        _ = req_len;
        return 0;
    }
};

/// High-level client for GoAria host services. Stateless: each method
/// serializes a request DTO, invokes the matching `goaria_host` import, and
/// decodes the response. Every call consumes one unit of the manifest
/// `resource_limits.max_host_calls` budget; exhaustion surfaces as a
/// `budget_exhausted` wire error.
pub const HostBroker = struct {
    /// Errors surfaced by host-import calls and response decoding.
    ///
    /// Note that host-reported failures mostly travel in-band: a response
    /// with `ok: false` and a wire `error_code` (`invalid_request`,
    /// `policy_denied`, `budget_exhausted`, `not_configured`,
    /// `response_too_large`, `internal_error`, `registry_full`,
    /// `auth_unavailable`, `fetch_failed`, `authenticated_fetch_failed`)
    /// reaches the caller as a parsed response, not as an `Error` — except
    /// where a method documents `HttpError`. The local CLI additionally
    /// emits `no_mock_match`, `broker_disabled`, and
    /// `ref_mode_not_supported_in_live_runner`.
    pub const Error = error{
        /// The host call itself failed (`0` return = transport failure) or
        /// a guest-side allocation failed.
        HostCallFailed,
        /// The host returned a malformed or missing response buffer/field.
        InvalidResponseBuffer,
        /// The response buffer was not valid JSON for the expected type.
        JsonParseError,
        /// The response `body_base64` could not be decoded.
        Base64DecodeError,
        /// The response payload reported `ok: false`; inspect `error_code`
        /// via `fetch` for the wire-level reason.
        HttpError,
    };

    /// Raw low-level invocation of goaria_host.http_fetch.
    ///
    /// Returns a guest-owned `GuestBuffer` (freed via `deinit`).
    /// `HostCallFailed` on a `0` return (transport failure; also the result
    /// on native stub targets), `InvalidResponseBuffer` on a malformed
    /// handle.
    pub fn rawHttpFetch(request_json_bytes: []const u8) Error!abi.GuestBuffer {
        const req_len: i32 = @intCast(request_json_bytes.len);
        const req_ptr: i32 = @intCast(@intFromPtr(request_json_bytes.ptr));

        const result_packed = raw.http_fetch(req_ptr, req_len);
        if (result_packed == 0) return Error.HostCallFailed;

        const unpacked = abi.unpackResult(@bitCast(result_packed));
        return abi.GuestBuffer.fromRaw(@intCast(unpacked.ptr), @intCast(unpacked.len)) orelse Error.InvalidResponseBuffer;
    }

    /// Raw low-level invocation of goaria_host.auth_profile_status. Same
    /// ownership and error mapping as `rawHttpFetch`.
    pub fn rawAuthProfileStatus(request_json_bytes: []const u8) Error!abi.GuestBuffer {
        const req_len: i32 = @intCast(request_json_bytes.len);
        const req_ptr: i32 = @intCast(@intFromPtr(request_json_bytes.ptr));

        const result_packed = raw.auth_profile_status(req_ptr, req_len);
        if (result_packed == 0) return Error.HostCallFailed;

        const unpacked = abi.unpackResult(@bitCast(result_packed));
        return abi.GuestBuffer.fromRaw(@intCast(unpacked.ptr), @intCast(unpacked.len)) orelse Error.InvalidResponseBuffer;
    }

    /// Raw low-level invocation of goaria_host.register_download_auth. Same
    /// ownership and error mapping as `rawHttpFetch`.
    pub fn rawRegisterDownloadAuth(request_json_bytes: []const u8) Error!abi.GuestBuffer {
        const req_len: i32 = @intCast(request_json_bytes.len);
        const req_ptr: i32 = @intCast(@intFromPtr(request_json_bytes.ptr));

        const result_packed = raw.register_download_auth(req_ptr, req_len);
        if (result_packed == 0) return Error.HostCallFailed;

        const unpacked = abi.unpackResult(@bitCast(result_packed));
        return abi.GuestBuffer.fromRaw(@intCast(unpacked.ptr), @intCast(unpacked.len)) orelse Error.InvalidResponseBuffer;
    }

    /// Raw low-level invocation of goaria_host.host_time. Same ownership and
    /// error mapping as `rawHttpFetch`.
    pub fn rawHostTime(request_json_bytes: []const u8) Error!abi.GuestBuffer {
        const req_len: i32 = @intCast(request_json_bytes.len);
        const req_ptr: i32 = @intCast(@intFromPtr(request_json_bytes.ptr));

        const result_packed = raw.host_time(req_ptr, req_len);
        if (result_packed == 0) return Error.HostCallFailed;

        const unpacked = abi.unpackResult(@bitCast(result_packed));
        return abi.GuestBuffer.fromRaw(@intCast(unpacked.ptr), @intCast(unpacked.len)) orelse Error.InvalidResponseBuffer;
    }

    /// Requires `cap.http.fetch`; extended features on the request
    /// additionally require `cap.http.fetch.extended`. This is the raw level:
    /// an `ok: false` payload is *not* an error — inspect `error_code` on the
    /// returned value (see `Error` for the category list). Caller owns the
    /// returned `std.json.Parsed` and must call `deinit`.
    ///
    /// Errors: `HostCallFailed` (transport failure or JSON encode
    /// allocation), `InvalidResponseBuffer`, `JsonParseError`.
    pub fn fetch(
        allocator: std.mem.Allocator,
        req: types.HostHTTPFetchRequest,
    ) Error!std.json.Parsed(types.HostHTTPFetchResponse) {
        const req_json = std.fmt.allocPrint(
            allocator,
            "{f}",
            .{std.json.fmt(req, .{ .emit_null_optional_fields = false })},
        ) catch return Error.HostCallFailed;
        defer allocator.free(req_json);

        var buf = try rawHttpFetch(req_json);
        defer buf.deinit();

        return std.json.parseFromSlice(
            types.HostHTTPFetchResponse,
            allocator,
            buf.slice(),
            .{ .ignore_unknown_fields = true },
        ) catch Error.JsonParseError;
    }

    /// Fetch a direct URL via raw mode (`GET`). Same contract as `fetch`.
    pub fn fetchUrl(
        allocator: std.mem.Allocator,
        url: []const u8,
    ) Error!std.json.Parsed(types.HostHTTPFetchResponse) {
        return fetch(allocator, .{
            .url = url,
            .method = "GET",
        });
    }

    /// POST `body` to `url` with a single `Content-Type` header.
    ///
    /// Requires `cap.http.fetch.extended` alongside `cap.http.fetch`.
    /// Extended requests must use HTTPS and fail closed on any redirect. The
    /// host performs all request validation: `content_type` must be
    /// `application/json` or `application/x-www-form-urlencoded` and the
    /// decoded body is capped at 16 KiB. Same `ok`/`error_code` contract as
    /// `fetch`.
    pub fn fetchUrlWithBody(
        allocator: std.mem.Allocator,
        url: []const u8,
        body: []const u8,
        content_type: []const u8,
    ) Error!std.json.Parsed(types.HostHTTPFetchResponse) {
        var req = try buildPostBodyRequest(allocator, url, body, content_type);
        defer freePostBodyRequest(allocator, &req);
        return fetch(allocator, req);
    }

    /// Fetch an endpoint via ref mode (`broker_policy_ref` + `endpoint_ref`,
    /// optional substitution `params`), valid under an alias (policy-ref)
    /// manifest. The local runner resolves ref mode only against mock
    /// fixtures; a `--live` run fails it in-band with
    /// `ref_mode_not_supported_in_live_runner`. Same `ok`/`error_code`
    /// contract as `fetch`.
    pub fn fetchRef(
        allocator: std.mem.Allocator,
        broker_policy_ref: []const u8,
        endpoint_ref: []const u8,
        params: ?types.StringMap,
    ) Error!std.json.Parsed(types.HostHTTPFetchResponse) {
        return fetch(allocator, buildRefRequest(broker_policy_ref, endpoint_ref, params));
    }

    /// Unlike `fetch`, an `ok: false` payload maps to `HttpError` here.
    /// Caller owns the returned slice; a missing or empty body yields an
    /// empty slice. `Base64DecodeError` when the payload is not valid base64.
    pub fn fetchBytes(
        allocator: std.mem.Allocator,
        req: types.HostHTTPFetchRequest,
    ) Error![]u8 {
        var parsed_resp = try fetch(allocator, req);
        defer parsed_resp.deinit();

        const resp = parsed_resp.value;
        if (!resp.ok) return Error.HttpError;

        const b64 = resp.body_base64 orelse return &.{};
        if (b64.len == 0) return &.{};

        const decoder = std.base64.standard.Decoder;
        const dest_len = decoder.calcSizeForSlice(b64) catch return Error.Base64DecodeError;
        const out_buf = allocator.alloc(u8, dest_len) catch return Error.HostCallFailed;
        errdefer allocator.free(out_buf);

        decoder.decode(out_buf, b64) catch return Error.Base64DecodeError;
        return out_buf;
    }

    /// Alias of `fetchBytes`; no separate UTF-8 validation is performed on
    /// the returned bytes.
    pub fn fetchText(
        allocator: std.mem.Allocator,
        req: types.HostHTTPFetchRequest,
    ) Error![]const u8 {
        return fetchBytes(allocator, req);
    }

    /// Requires `cap.auth.profile`. Like `fetch`, an `ok: false` payload is
    /// *not* an error — a profile lookup miss or host denial arrives in-band
    /// (`error_code`: `invalid_request`, `policy_denied`,
    /// `budget_exhausted`, `not_configured`, `auth_unavailable`,
    /// `response_too_large`, `internal_error`). Caller owns the returned
    /// `std.json.Parsed` and must call `deinit`.
    pub fn authProfileStatus(
        allocator: std.mem.Allocator,
        req: types.HostAuthProfileStatusRequest,
    ) Error!std.json.Parsed(types.HostAuthProfileStatusResponse) {
        const req_json = std.fmt.allocPrint(
            allocator,
            "{f}",
            .{std.json.fmt(req, .{ .emit_null_optional_fields = false })},
        ) catch return Error.HostCallFailed;
        defer allocator.free(req_json);

        var buf = try rawAuthProfileStatus(req_json);
        defer buf.deinit();

        return std.json.parseFromSlice(
            types.HostAuthProfileStatusResponse,
            allocator,
            buf.slice(),
            .{ .ignore_unknown_fields = true },
        ) catch Error.JsonParseError;
    }

    /// Returns `false` both when the profile holds no credentials for the
    /// raw-mode URL and when the status call itself resolved to `ok: false` —
    /// use `authProfileStatus` to distinguish those cases.
    pub fn isAuthAvailable(
        allocator: std.mem.Allocator,
        auth_profile_ref: []const u8,
        url: []const u8,
    ) Error!bool {
        var parsed = try authProfileStatus(allocator, .{
            .auth_profile_ref = auth_profile_ref,
            .url = url,
        });
        defer parsed.deinit();

        return parsed.value.ok and (parsed.value.available orelse false);
    }

    /// Requires `cap.download.auth`.
    ///
    /// `token` is the raw credential: 1–8170 bytes of valid UTF-8 without
    /// CR/LF, and it must not already carry a `Bearer ` scheme prefix. After
    /// the call the token is host-only — on success the response's
    /// `download_auth_ref` (`dar-` + 32 lowercase hex, bound to this pack
    /// identity and invocation) is the only value that may appear on
    /// `ExtractedItemRef.download_auth_ref`. An `ok: false` payload
    /// (`invalid_request`, `policy_denied`, `budget_exhausted`,
    /// `not_configured`, `registry_full`, …) is not an error; inspect
    /// `error_code`. Caller owns the returned `std.json.Parsed`.
    pub fn registerDownloadAuth(
        allocator: std.mem.Allocator,
        token: []const u8,
    ) Error!std.json.Parsed(types.HostRegisterDownloadAuthResponse) {
        const req = types.HostRegisterDownloadAuthRequest{
            .kind = "bearer",
            .token = token,
        };
        const req_json = std.fmt.allocPrint(
            allocator,
            "{f}",
            .{std.json.fmt(req, .{ .emit_null_optional_fields = false })},
        ) catch return Error.HostCallFailed;
        defer allocator.free(req_json);

        var buf = try rawRegisterDownloadAuth(req_json);
        defer buf.deinit();

        return std.json.parseFromSlice(
            types.HostRegisterDownloadAuthResponse,
            allocator,
            buf.slice(),
            .{ .ignore_unknown_fields = true },
        ) catch Error.JsonParseError;
    }

    /// Invocation-scoped Unix timestamp (seconds) snapshot from the host.
    /// Requires no capability. The value is frozen for the duration of one
    /// invocation — repeated calls inside the same `goaria_extract` return
    /// identical timestamps — but each call still consumes one host-call
    /// budget unit.
    ///
    /// Errors: `HttpError` on an `ok: false` payload (`invalid_request`,
    /// `budget_exhausted`, `response_too_large`, `internal_error`),
    /// `InvalidResponseBuffer` when `unix_secs` is missing, plus the
    /// transport/decode errors of `rawHostTime`.
    pub fn hostTime(allocator: std.mem.Allocator) Error!i64 {
        const req_json = "{}";

        var buf = try rawHostTime(req_json);
        defer buf.deinit();

        var parsed = std.json.parseFromSlice(
            types.HostTimeResponse,
            allocator,
            buf.slice(),
            .{ .ignore_unknown_fields = true },
        ) catch return Error.JsonParseError;
        defer parsed.deinit();

        const resp = parsed.value;
        if (!resp.ok) return Error.HttpError;
        return resp.unix_secs orelse Error.InvalidResponseBuffer;
    }
};

fn buildPostBodyRequest(
    allocator: std.mem.Allocator,
    url: []const u8,
    body: []const u8,
    content_type: []const u8,
) HostBroker.Error!types.HostHTTPFetchRequest {
    const encoder = std.base64.standard.Encoder;
    const b64_buf = allocator.alloc(u8, encoder.calcSize(body.len)) catch return HostBroker.Error.HostCallFailed;
    errdefer allocator.free(b64_buf);
    _ = encoder.encode(b64_buf, body);

    var headers: types.StringMap = .{};
    errdefer headers.map.deinit(allocator);
    headers.map.put(allocator, "Content-Type", content_type) catch return HostBroker.Error.HostCallFailed;

    return .{
        .method = "POST",
        .url = url,
        .headers = headers,
        .body_base64 = b64_buf,
    };
}

fn freePostBodyRequest(allocator: std.mem.Allocator, req: *types.HostHTTPFetchRequest) void {
    if (req.body_base64) |b64| allocator.free(b64);
    if (req.headers) |*headers| headers.map.deinit(allocator);
}

fn buildRefRequest(
    broker_policy_ref: []const u8,
    endpoint_ref: []const u8,
    params: ?types.StringMap,
) types.HostHTTPFetchRequest {
    return .{
        .broker_policy_ref = broker_policy_ref,
        .endpoint_ref = endpoint_ref,
        .params = if (params) |p| (if (p.map.count() == 0) null else p) else null,
    };
}

// Unit Tests
test "base64 decoding helper" {
    const encoded = "aGVsbG8gd29ybGQ=";
    const decoder = std.base64.standard.Decoder;
    const dest_len = try decoder.calcSizeForSlice(encoded);
    const buf = try std.testing.allocator.alloc(u8, dest_len);
    defer std.testing.allocator.free(buf);

    try decoder.decode(buf, encoded);
    try std.testing.expectEqualStrings("hello world", buf);
}

test "buildPostBodyRequest produces POST + body_base64 + single Content-Type" {
    const allocator = std.testing.allocator;
    var req = try buildPostBodyRequest(
        allocator,
        "https://api.fixture.invalid/v1/submit",
        "hello",
        "application/json",
    );
    defer freePostBodyRequest(allocator, &req);

    const req_json = try std.fmt.allocPrint(
        allocator,
        "{f}",
        .{std.json.fmt(req, .{ .emit_null_optional_fields = false })},
    );
    defer allocator.free(req_json);

    try std.testing.expect(std.mem.indexOf(u8, req_json, "\"method\":\"POST\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, req_json, "\"url\":\"https://api.fixture.invalid/v1/submit\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, req_json, "\"body_base64\":\"aGVsbG8=\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, req_json, "\"Content-Type\":\"application/json\"") != null);
    // raw mode must not leak ref/auth fields
    try std.testing.expect(std.mem.indexOf(u8, req_json, "broker_policy_ref") == null);
    try std.testing.expect(std.mem.indexOf(u8, req_json, "auth_profile_ref") == null);
}

test "buildRefRequest emits refs only and drops empty params" {
    const allocator = std.testing.allocator;

    const no_params = buildRefRequest("bpr-custom01", "ep-custom01", null);
    const req_json = try std.fmt.allocPrint(
        allocator,
        "{f}",
        .{std.json.fmt(no_params, .{ .emit_null_optional_fields = false })},
    );
    defer allocator.free(req_json);
    try std.testing.expect(std.mem.indexOf(u8, req_json, "\"broker_policy_ref\":\"bpr-custom01\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, req_json, "\"endpoint_ref\":\"ep-custom01\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, req_json, "params") == null);
    try std.testing.expect(std.mem.indexOf(u8, req_json, "url") == null);

    // empty params map collapses to absent (mirror of Rust fetch_ref)
    var empty: types.StringMap = .{};
    defer empty.map.deinit(allocator);
    const with_empty = buildRefRequest("bpr-custom01", "ep-custom01", empty);
    try std.testing.expect(with_empty.params == null);
}
