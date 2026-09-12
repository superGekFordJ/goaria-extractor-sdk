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

/// Key-value string map (e.g. metadata, params, request headers).
pub const StringMap = std.json.ArrayHashMap([]const u8);

/// Multi-value header map (e.g. response headers).
pub const HeaderMap = std.json.ArrayHashMap([]const []const u8);

/// Input payload passed to `goaria_match`.
pub const MatchInput = struct {
    url: []const u8,
};

/// Output payload returned by `goaria_match`.
pub const MatchOutput = struct {
    matched: bool,
    confidence: ?u8 = null,
    reason: ?[]const u8 = null,

    pub fn matchedResult() MatchOutput {
        return .{
            .matched = true,
            .confidence = 100,
            .reason = null,
        };
    }

    pub fn unmatchedResult() MatchOutput {
        return .{
            .matched = false,
            .confidence = null,
            .reason = null,
        };
    }

    pub fn withConfidence(self: MatchOutput, conf: u8) MatchOutput {
        var copy = self;
        copy.confidence = conf;
        return copy;
    }

    pub fn withReason(self: MatchOutput, r: []const u8) MatchOutput {
        var copy = self;
        copy.reason = r;
        return copy;
    }
};

/// Input payload passed to `goaria_extract`.
pub const ExtractInput = struct {
    url: []const u8,
};

/// Extracted resource item reference.
pub const ExtractedItemRef = struct {
    id: ?[]const u8 = null,
    url: ?[]const u8 = null,
    filename: ?[]const u8 = null,
    size_bytes: ?i64 = null,
    mime_type: ?[]const u8 = null,
    auth_profile_ref: ?[]const u8 = null,
    header_profile_ref: ?[]const u8 = null,
    metadata: ?StringMap = null,
};

/// Output payload returned by `goaria_extract`.
pub const ExtractOutput = struct {
    items: []const ExtractedItemRef,

    pub fn empty() ExtractOutput {
        return .{ .items = &.{} };
    }

    pub fn single(allocator: std.mem.Allocator, item: ExtractedItemRef) !ExtractOutput {
        const slice = try allocator.alloc(ExtractedItemRef, 1);
        slice[0] = item;
        return .{ .items = slice };
    }
};

/// Kind of authentication secret stored in an auth profile.
pub const AuthSecretKind = enum {
    bearer,
    cookie,
};

/// Request payload sent to host import `goaria_host.http_fetch`.
pub const HostHTTPFetchRequest = struct {
    method: ?[]const u8 = null,
    url: ?[]const u8 = null,
    broker_policy_ref: ?[]const u8 = null,
    endpoint_ref: ?[]const u8 = null,
    params: ?StringMap = null,
    headers: ?StringMap = null,
    body_base64: ?[]const u8 = null,
    auth_profile_ref: ?[]const u8 = null,
    timeout_millis: ?i32 = null,
    max_response_bytes: ?i64 = null,
};

/// Response payload received from host import `goaria_host.http_fetch`.
pub const HostHTTPFetchResponse = struct {
    ok: bool,
    status_code: ?i32 = null,
    final_url: ?[]const u8 = null,
    headers: ?HeaderMap = null,
    body_base64: ?[]const u8 = null,
    error_code: ?[]const u8 = null,
    message: ?[]const u8 = null,
};

/// Request payload sent to host import `goaria_host.auth_profile_status`.
pub const HostAuthProfileStatusRequest = struct {
    auth_profile_ref: []const u8,
    url: ?[]const u8 = null,
    broker_policy_ref: ?[]const u8 = null,
    endpoint_ref: ?[]const u8 = null,
    params: ?StringMap = null,
};

/// Response payload received from host import `goaria_host.auth_profile_status`.
pub const HostAuthProfileStatusResponse = struct {
    ok: bool,
    available: ?bool = null,
    kind: ?AuthSecretKind = null,
    redacted_display: ?[]const u8 = null,
    error_code: ?[]const u8 = null,
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
