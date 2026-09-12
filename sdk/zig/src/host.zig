const std = @import("std");
const builtin = @import("builtin");
const types = @import("types.zig");
const abi = @import("abi.zig");

/// Low-level host imports for the "goaria_host" module.
pub const raw = if (builtin.target.cpu.arch.isWasm()) struct {
    pub extern "goaria_host" fn http_fetch(req_ptr: i32, req_len: i32) i64;
    pub extern "goaria_host" fn auth_profile_status(req_ptr: i32, req_len: i32) i64;
} else struct {
    pub fn http_fetch(req_ptr: i32, req_len: i32) i64 {
        _ = req_ptr;
        _ = req_len;
        return 0;
    }
    pub fn auth_profile_status(req_ptr: i32, req_len: i32) i64 {
        _ = req_ptr;
        _ = req_len;
        return 0;
    }
};

/// High-level client for GoAria host services.
pub const HostBroker = struct {
    pub const Error = error{
        HostCallFailed,
        InvalidResponseBuffer,
        JsonParseError,
        Base64DecodeError,
        HttpError,
    };

    /// Raw low-level invocation of goaria_host.http_fetch.
    pub fn rawHttpFetch(request_json_bytes: []const u8) Error!abi.GuestBuffer {
        const req_len: i32 = @intCast(request_json_bytes.len);
        const req_ptr: i32 = @intCast(@intFromPtr(request_json_bytes.ptr));

        const result_packed = raw.http_fetch(req_ptr, req_len);
        if (result_packed == 0) return Error.HostCallFailed;

        const unpacked = abi.unpackResult(@bitCast(result_packed));
        return abi.GuestBuffer.fromRaw(@intCast(unpacked.ptr), @intCast(unpacked.len)) orelse Error.InvalidResponseBuffer;
    }

    /// Raw low-level invocation of goaria_host.auth_profile_status.
    pub fn rawAuthProfileStatus(request_json_bytes: []const u8) Error!abi.GuestBuffer {
        const req_len: i32 = @intCast(request_json_bytes.len);
        const req_ptr: i32 = @intCast(@intFromPtr(request_json_bytes.ptr));

        const result_packed = raw.auth_profile_status(req_ptr, req_len);
        if (result_packed == 0) return Error.HostCallFailed;

        const unpacked = abi.unpackResult(@bitCast(result_packed));
        return abi.GuestBuffer.fromRaw(@intCast(unpacked.ptr), @intCast(unpacked.len)) orelse Error.InvalidResponseBuffer;
    }

    /// Execute an HTTP fetch request via host broker.
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

    /// Fetch a direct URL using standard GET method.
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
    /// Requires the manifest to declare `cap.http.fetch.extended` alongside
    /// `cap.http.fetch`; the host performs all request validation.
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

    /// Fetch an endpoint via alias ref mode (broker_policy_ref + endpoint_ref,
    /// optional substitution params).
    pub fn fetchRef(
        allocator: std.mem.Allocator,
        broker_policy_ref: []const u8,
        endpoint_ref: []const u8,
        params: ?types.StringMap,
    ) Error!std.json.Parsed(types.HostHTTPFetchResponse) {
        return fetch(allocator, buildRefRequest(broker_policy_ref, endpoint_ref, params));
    }

    /// Fetch and decode the response body as raw bytes.
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

    /// Fetch and decode the response body as a UTF-8 string.
    pub fn fetchText(
        allocator: std.mem.Allocator,
        req: types.HostHTTPFetchRequest,
    ) Error![]const u8 {
        return fetchBytes(allocator, req);
    }

    /// Query authentication profile status from the host.
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

    /// Convenience check for whether an auth profile is available for a given URL.
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
