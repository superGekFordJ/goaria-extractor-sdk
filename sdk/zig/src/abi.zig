const std = @import("std");
const builtin = @import("builtin");
const types = @import("types.zig");

/// ABI version implemented by this SDK; returned by `goaria_abi_version`.
pub const CURRENT_ABI_VERSION: u32 = 1;
/// Required export: returns `CURRENT_ABI_VERSION` to the host.
pub const ABI_EXPORT_VERSION: []const u8 = "goaria_abi_version";
/// Required export: guest allocator the host calls to reserve guest memory.
pub const ABI_EXPORT_ALLOC: []const u8 = "goaria_alloc";
/// Required export: guest deallocator for host-visible buffers.
pub const ABI_EXPORT_FREE: []const u8 = "goaria_free";
/// Required export: URL-matching entrypoint (`MatchInput` -> `MatchOutput`).
pub const ABI_EXPORT_MATCH: []const u8 = "goaria_match";
/// Required export: extraction entrypoint (`ExtractInput` -> `ExtractOutput`).
pub const ABI_EXPORT_EXTRACT: []const u8 = "goaria_extract";

/// Wasm module namespace under which the host provides its imports.
pub const HOST_IMPORT_MODULE: []const u8 = "goaria_host";
/// Host import: brokered HTTP fetch (`cap.http.fetch`).
pub const HOST_IMPORT_HTTP_FETCH: []const u8 = "http_fetch";
/// Host import: auth-profile availability query (`cap.auth.profile`).
pub const HOST_IMPORT_AUTH_PROFILE_STATUS: []const u8 = "auth_profile_status";

/// Unpacked pointer and length tuple from a 64-bit ABI return value.
pub const Unpacked = struct {
    /// Guest-memory pointer (high 32 bits of the packed value).
    ptr: u32,
    /// Buffer length in bytes (low 32 bits of the packed value).
    len: u32,
};

/// ABI return-value packing: high 32 bits = guest-memory pointer, low 32
/// bits = buffer length. A `0` result signals failure or an empty payload.
pub inline fn packResult(ptr: u32, len: u32) u64 {
    return (@as(u64, ptr) << 32) | @as(u64, len);
}

/// Unpack a 64-bit ABI value into its pointer and length components.
pub inline fn unpackResult(val: u64) Unpacked {
    return .{
        .ptr = @truncate(val >> 32),
        .len = @truncate(val),
    };
}

/// Returns `std.heap.wasm_allocator` on wasm32, `std.heap.page_allocator`
/// on native (test) targets.
pub fn getAllocator() std.mem.Allocator {
    if (builtin.target.cpu.arch.isWasm()) {
        return std.heap.wasm_allocator;
    } else {
        return std.heap.page_allocator;
    }
}

/// Allocate `len` contiguous bytes in guest memory, backing the exported
/// `goaria_alloc`. The host calls it to stage input buffers and host-import
/// response buffers; the guest uses it for output buffers returned across
/// the ABI. Returns `0` when `len <= 0` or allocation fails.
pub fn alloc(len: i32) i32 {
    if (len <= 0) return 0;
    const slice = getAllocator().alloc(u8, @intCast(len)) catch return 0;
    return @intCast(@intFromPtr(slice.ptr));
}

/// Release a buffer previously returned by `alloc`, backing the exported
/// `goaria_free`. `ptr`/`len` must match a single live `alloc` allocation;
/// no-op on non-positive values. Under the ABI the host calls this on input
/// buffers and guest-returned output buffers; the guest calls it on
/// host-import response buffers it owns (see `GuestBuffer`).
pub fn free(ptr: i32, len: i32) void {
    if (ptr <= 0 or len <= 0) return;
    const allocator = getAllocator();
    const u_ptr: usize = @as(usize, @as(u32, @bitCast(ptr)));
    const slice: []u8 = @as([*]u8, @ptrFromInt(u_ptr))[0..@as(usize, @as(u32, @bitCast(len)))];
    allocator.free(slice);
}

/// Serialize `value` to JSON in guest memory and return the packed
/// `ptr << 32 | len` handle. Optional fields that are `null` are omitted
/// from the wire. Returns `0` when serialization or allocation fails.
/// Ownership of the returned buffer passes to the host, which releases it
/// via `goaria_free`.
pub fn packJsonResponse(allocator: std.mem.Allocator, value: anytype) i64 {
    const json_bytes = std.fmt.allocPrint(
        allocator,
        "{f}",
        .{std.json.fmt(value, .{ .emit_null_optional_fields = false })},
    ) catch return 0;

    const ptr: u32 = @truncate(@intFromPtr(json_bytes.ptr));
    const len: u32 = @intCast(json_bytes.len);
    return @bitCast(packResult(ptr, len));
}

/// RAII owner for a buffer living in guest memory — typically a host-import
/// response buffer the host allocated inside the guest via `goaria_alloc`.
/// Call `deinit` to release it through `free`.
pub const GuestBuffer = struct {
    /// Guest-memory pointer to the buffer start.
    ptr: i32,
    len: i32,

    /// Take ownership of a raw pointer/length pair; returns `null` for null
    /// or empty buffers. `ptr`/`len` must designate a live buffer allocated
    /// via `alloc` (on the host's behalf) that is not freed elsewhere.
    pub fn fromRaw(ptr: i32, len: i32) ?GuestBuffer {
        if (ptr == 0 or len <= 0) return null;
        return .{ .ptr = ptr, .len = len };
    }

    pub fn slice(self: GuestBuffer) []const u8 {
        if (self.ptr <= 0 or self.len <= 0) return &.{};
        const u_ptr: usize = @as(usize, @as(u32, @bitCast(self.ptr)));
        const byte_ptr: [*]const u8 = @ptrFromInt(u_ptr);
        return byte_ptr[0..@as(usize, @as(u32, @bitCast(self.len)))];
    }

    /// Release the buffer back to the guest allocator and reset to empty.
    pub fn deinit(self: *GuestBuffer) void {
        if (self.ptr != 0 and self.len > 0) {
            free(self.ptr, self.len);
            self.ptr = 0;
            self.len = 0;
        }
    }
};

/// Comptime helper generating the five mandatory ABI v1 guest exports for an
/// extractor type — call it from a top-level `comptime {}` block:
///
/// ```zig
/// comptime {
///     goaria_sdk.exportExtractor(MyExtractor);
/// }
/// ```
///
/// `Extractor` must provide:
/// - `pub fn matchUrl(allocator: std.mem.Allocator, input: types.MatchInput) !types.MatchOutput`
/// - `pub fn extract(allocator: std.mem.Allocator, input: types.ExtractInput) !types.ExtractOutput`
///
/// Generated exports: `goaria_abi_version`, `goaria_alloc`, `goaria_free`,
/// `goaria_match`, `goaria_extract`. The host invokes `goaria_match` first
/// and only calls `goaria_extract` when the match output reports
/// `matched: true`. Each entrypoint receives a host-owned input buffer
/// (borrowed for the call, freed by the host afterwards) and returns a
/// guest-allocated `ptr << 32 | len` handle the host frees via
/// `goaria_free`.
///
/// Error mapping follows ABI v1, which has no structured error envelope: a
/// `matchUrl` error becomes `matched: false` with `reason` set to
/// `@errorName(err)`; an `extract` error, malformed input, or undecodable
/// JSON becomes an empty `ExtractOutput`. A trap in either function aborts
/// the guest and is isolated by the host runtime.
pub fn exportExtractor(comptime Extractor: type) void {
    _ = struct {
        pub export fn goaria_abi_version() callconv(.c) i32 {
            return CURRENT_ABI_VERSION;
        }

        pub export fn goaria_alloc(len: i32) callconv(.c) i32 {
            return alloc(len);
        }

        pub export fn goaria_free(ptr: i32, len: i32) callconv(.c) void {
            free(ptr, len);
        }

        pub export fn goaria_match(ptr: i32, len: i32) callconv(.c) i64 {
            if (ptr <= 0 or len <= 0) {
                return packJsonResponse(getAllocator(), types.MatchOutput{
                    .matched = false,
                    .confidence = null,
                    .reason = "invalid input buffer pointer or length",
                });
            }

            const allocator = getAllocator();
            const u_ptr: usize = @as(usize, @as(u32, @bitCast(ptr)));
            const byte_ptr: [*]const u8 = @ptrFromInt(u_ptr);
            const input_bytes = byte_ptr[0..@as(usize, @as(u32, @bitCast(len)))];

            var parsed = std.json.parseFromSlice(
                types.MatchInput,
                allocator,
                input_bytes,
                .{ .ignore_unknown_fields = true },
            ) catch {
                return packJsonResponse(allocator, types.MatchOutput{
                    .matched = false,
                    .confidence = null,
                    .reason = "failed to parse match input JSON",
                });
            };
            defer parsed.deinit();

            const output = Extractor.matchUrl(allocator, parsed.value) catch |err| {
                return packJsonResponse(allocator, types.MatchOutput{
                    .matched = false,
                    .confidence = null,
                    .reason = @errorName(err),
                });
            };

            return packJsonResponse(allocator, output);
        }

        pub export fn goaria_extract(ptr: i32, len: i32) callconv(.c) i64 {
            if (ptr <= 0 or len <= 0) {
                return packJsonResponse(getAllocator(), types.ExtractOutput.empty());
            }

            const allocator = getAllocator();
            const u_ptr: usize = @as(usize, @as(u32, @bitCast(ptr)));
            const byte_ptr: [*]const u8 = @ptrFromInt(u_ptr);
            const input_bytes = byte_ptr[0..@as(usize, @as(u32, @bitCast(len)))];

            var parsed = std.json.parseFromSlice(
                types.ExtractInput,
                allocator,
                input_bytes,
                .{ .ignore_unknown_fields = true },
            ) catch {
                return packJsonResponse(allocator, types.ExtractOutput.empty());
            };
            defer parsed.deinit();

            const output = Extractor.extract(allocator, parsed.value) catch {
                return packJsonResponse(allocator, types.ExtractOutput.empty());
            };

            return packJsonResponse(allocator, output);
        }
    };
}

// Unit Tests
test "pack and unpack bitshift arithmetic" {
    const ptr: u32 = 0x12345678;
    const len: u32 = 0x00000042;
    const packed_val = packResult(ptr, len);
    const unpacked = unpackResult(packed_val);
    try std.testing.expectEqual(ptr, unpacked.ptr);
    try std.testing.expectEqual(len, unpacked.len);
}

test "packJsonResponse formatting" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const match_out = types.MatchOutput{
        .matched = true,
        .confidence = 100,
        .reason = "unit test",
    };
    const packed_i64 = packJsonResponse(allocator, match_out);
    try std.testing.expect(packed_i64 != 0);

    const unpacked = unpackResult(@bitCast(packed_i64));
    try std.testing.expect(unpacked.ptr != 0);
    try std.testing.expect(unpacked.len > 0);
}
