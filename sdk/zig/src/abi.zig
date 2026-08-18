const std = @import("std");
const builtin = @import("builtin");
const types = @import("types.zig");

pub const CURRENT_ABI_VERSION: u32 = 1;
pub const ABI_EXPORT_VERSION: []const u8 = "goaria_abi_version";
pub const ABI_EXPORT_ALLOC: []const u8 = "goaria_alloc";
pub const ABI_EXPORT_FREE: []const u8 = "goaria_free";
pub const ABI_EXPORT_MATCH: []const u8 = "goaria_match";
pub const ABI_EXPORT_EXTRACT: []const u8 = "goaria_extract";

pub const HOST_IMPORT_MODULE: []const u8 = "goaria_host";
pub const HOST_IMPORT_HTTP_FETCH: []const u8 = "http_fetch";
pub const HOST_IMPORT_AUTH_PROFILE_STATUS: []const u8 = "auth_profile_status";

/// Unpacked pointer and length tuple from a 64-bit ABI return value.
pub const Unpacked = struct {
    ptr: u32,
    len: u32,
};

/// Pack pointer and length into a single 64-bit unsigned integer.
/// High 32 bits = pointer, Low 32 bits = length.
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

/// Obtain the appropriate allocator for the current execution context.
/// In WASM mode, returns `std.heap.wasm_allocator`.
/// In native test mode, returns `std.heap.page_allocator`.
pub fn getAllocator() std.mem.Allocator {
    if (builtin.target.cpu.arch.isWasm()) {
        return std.heap.wasm_allocator;
    } else {
        return std.heap.page_allocator;
    }
}

/// Allocate contiguous bytes in guest memory.
pub fn alloc(len: i32) i32 {
    if (len <= 0) return 0;
    const slice = getAllocator().alloc(u8, @intCast(len)) catch return 0;
    return @intCast(@intFromPtr(slice.ptr));
}

/// Deallocate contiguous bytes in guest memory.
pub fn free(ptr: i32, len: i32) void {
    if (ptr <= 0 or len <= 0) return;
    const allocator = getAllocator();
    const u_ptr: usize = @as(usize, @as(u32, @bitCast(ptr)));
    const slice: []u8 = @as([*]u8, @ptrFromInt(u_ptr))[0..@as(usize, @as(u32, @bitCast(len)))];
    allocator.free(slice);
}

/// Serialize a value to JSON in guest memory and return the packed 64-bit pointer/length.
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

/// RAII wrapper for a memory buffer allocated in guest memory (e.g. by host import).
pub const GuestBuffer = struct {
    ptr: i32,
    len: i32,

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

    pub fn deinit(self: *GuestBuffer) void {
        if (self.ptr != 0 and self.len > 0) {
            free(self.ptr, self.len);
            self.ptr = 0;
            self.len = 0;
        }
    }
};

/// Declarative comptime helper that exports all 5 mandatory C-ABI functions
/// for an Extractor struct implementing `matchUrl` and `extract`.
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
