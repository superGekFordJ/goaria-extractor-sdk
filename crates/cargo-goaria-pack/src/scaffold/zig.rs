use crate::scaffold::ScaffoldError;
use std::path::Path;

pub fn generate(name: &str, target_dir: &Path) -> Result<(), ScaffoldError> {
    let src_dir = target_dir.join("src");
    std::fs::create_dir_all(&src_dir)?;

    let build_zig = r#"const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.resolveTargetQuery(.{
        .cpu_arch = .wasm32,
        .os_tag = .freestanding,
    });

    const optimize = b.standardOptimizeOption(.{
        .preferred_optimize_mode = .ReleaseSmall,
    });

    const lib = b.addSharedLibrary(.{
        .name = "payload",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    lib.rdynamic = true;
    lib.entry = .disabled;

    b.installArtifact(lib);
}
"#;
    std::fs::write(target_dir.join("build.zig"), build_zig)?;

    let build_zig_zon = format!(
        r#".{{
    .name = "{name}",
    .version = "0.1.0",
    .dependencies = .{{}},
    .paths = .{{
        "build.zig",
        "build.zig.zon",
        "src",
    }},
}}
"#
    );
    std::fs::write(target_dir.join("build.zig.zon"), build_zig_zon)?;

    let manifest_json = format!(
        r#"{{
  "pack_id": "{name}",
  "pack_version": "0.1.0",
  "abi_version": 1,
  "description": "GoAria extractor pack for {name}",
  "domains": [
    {{
      "host": "fixture.invalid",
      "include_subdomains": true
    }}
  ],
  "capabilities": [
    "cap.parse.wasm",
    "cap.http.fetch"
  ],
  "resource_limits": {{
    "timeout_millis": 5000,
    "max_memory_pages": 32,
    "max_host_calls": 50,
    "max_response_bytes": 1048576,
    "max_output_items": 50,
    "max_output_bytes": 1048576
  }}
}}
"#
    );
    std::fs::write(target_dir.join("manifest.json"), manifest_json)?;

    let main_zig = r#"const std = @import("std");

var allocator = std.heap.page_allocator;

inline fn packResult(ptr: u32, len: u32) i64 {
    const val = (@as(u64, ptr) << 32) | @as(u64, len);
    return @bitCast(val);
}

export fn goaria_abi_version() callconv(.c) i32 {
    return 1;
}

export fn goaria_alloc(len: i32) callconv(.c) i32 {
    if (len <= 0) return 0;
    const slice = allocator.alloc(u8, @intCast(len)) catch return 0;
    return @intCast(@intFromPtr(slice.ptr));
}

export fn goaria_free(ptr: i32, len: i32) callconv(.c) void {
    if (ptr <= 0 or len <= 0) return;
    const u_ptr: usize = @as(usize, @as(u32, @bitCast(ptr)));
    const slice: []u8 = @as([*]u8, @ptrFromInt(u_ptr))[0..@as(usize, @as(u32, @bitCast(len)))];
    allocator.free(slice);
}

export fn goaria_match(ptr: i32, len: i32) callconv(.c) i64 {
    _ = ptr;
    _ = len;
    const result = "{\"matched\":true,\"confidence\":100,\"reason\":\"matches fixture domain\"}";
    const out_slice = allocator.alloc(u8, result.len) catch return 0;
    @memcpy(out_slice, result);
    return packResult(@truncate(@intFromPtr(out_slice.ptr)), @intCast(result.len));
}

export fn goaria_extract(ptr: i32, len: i32) callconv(.c) i64 {
    _ = ptr;
    _ = len;
    const result = "{\"items\":[{\"id\":\"item-001\",\"url\":\"https://fixture.invalid/file.bin\",\"filename\":\"file.bin\"}]}";
    const out_slice = allocator.alloc(u8, result.len) catch return 0;
    @memcpy(out_slice, result);
    return packResult(@truncate(@intFromPtr(out_slice.ptr)), @intCast(result.len));
}
"#;
    std::fs::write(src_dir.join("main.zig"), main_zig)?;

    let gitignore = r#".zig-cache/
zig-out/
dist/
*.pack.zip
*.lock.json
"#;
    std::fs::write(target_dir.join(".gitignore"), gitignore)?;

    Ok(())
}
