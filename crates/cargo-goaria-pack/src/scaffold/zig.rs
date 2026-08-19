use std::path::Path;
use crate::scaffold::ScaffoldError;

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
  "name": "{name}",
  "description": "GoAria extractor pack for {name}",
  "authors": [
    "Extractor Developer <developer@example.com>"
  ],
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

export fn goaria_abi_version() u32 {
    return 1;
}

export fn goaria_alloc(size: u32) ?[*]u8 {
    const slice = allocator.alloc(u8, size) catch return null;
    return slice.ptr;
}

export fn goaria_free(ptr: ?[*]u8, size: u32) void {
    if (ptr) |p| {
        allocator.free(p[0..size]);
    }
}

export fn goaria_match(input_ptr: [*]const u8, input_len: u32, out_size: *u32) ?[*]const u8 {
    _ = input_ptr;
    _ = input_len;
    const result = "{\"matched\":true,\"confidence\":100,\"reason\":\"matches fixture domain\"}";
    out_size.* = result.len;
    return result.ptr;
}

export fn goaria_extract(input_ptr: [*]const u8, input_len: u32, out_size: *u32) ?[*]const u8 {
    _ = input_ptr;
    _ = input_len;
    const result = "{\"items\":[{\"id\":\"item-001\",\"url\":\"https://fixture.invalid/file.bin\",\"filename\":\"file.bin\"}]}";
    out_size.* = result.len;
    return result.ptr;
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
