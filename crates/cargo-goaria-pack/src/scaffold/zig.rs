use crate::scaffold::sdk_assets::{
    zig_fingerprint, zig_package_name, zig_struct_name, ZIG_SDK_FILES,
};
use crate::scaffold::{copy_dir_recursive, ScaffoldError, SdkSpec};
use std::path::Path;

fn write_zig_sdk(target_dir: &Path, sdk: &SdkSpec) -> Result<(), ScaffoldError> {
    let vendor_dir = target_dir.join("vendor").join("goaria_sdk");
    match sdk {
        SdkSpec::Vendor => {
            for file in ZIG_SDK_FILES {
                let dest = vendor_dir.join(file.rel_path);
                if let Some(parent) = dest.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&dest, file.contents)?;
            }
            Ok(())
        }
        SdkSpec::Path(dir) => copy_dir_recursive(dir, &vendor_dir),
        other => Err(ScaffoldError::UnsupportedSdkSource {
            sdk: match other {
                SdkSpec::Git { .. } => "git",
                SdkSpec::Crates => "crates",
                _ => "unknown",
            }
            .to_string(),
            lang: "zig".to_string(),
            reason: "zig packs require vendored or local-path SDK sources".to_string(),
        }),
    }
}

pub fn generate(name: &str, target_dir: &Path, sdk: &SdkSpec) -> Result<(), ScaffoldError> {
    // Vendor/copy the SDK first so a rejected source leaves no scaffold residue.
    write_zig_sdk(target_dir, sdk)?;

    let src_dir = target_dir.join("src");
    std::fs::create_dir_all(&src_dir)?;

    let artifact_name = name.replace('-', "_");
    let zon_name = zig_package_name(name);
    let fingerprint = zig_fingerprint(&zon_name);
    let struct_name = format!("{}Extractor", zig_struct_name(name));

    let build_zig = format!(
        r#"const std = @import("std");

pub fn build(b: *std.Build) void {{
    const target = b.resolveTargetQuery(.{{
        .cpu_arch = .wasm32,
        .os_tag = .freestanding,
    }});
    const optimize = b.standardOptimizeOption(.{{
        .preferred_optimize_mode = .ReleaseSmall,
    }});

    const sdk_dep = b.dependency("goaria_sdk", .{{
        .target = target,
        .optimize = optimize,
    }});
    const sdk_mod = sdk_dep.module("goaria_sdk");

    const wasm = b.addExecutable(.{{
        .name = "{artifact_name}",
        .root_module = b.createModule(.{{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .strip = true,
            .imports = &.{{ .{{ .name = "goaria_sdk", .module = sdk_mod }} }},
        }}),
    }});

    wasm.entry = .disabled;
    wasm.rdynamic = true;

    b.installArtifact(wasm);
}}
"#
    );
    std::fs::write(target_dir.join("build.zig"), build_zig)?;

    let build_zig_zon = format!(
        r#".{{
    .name = .{zon_name},
    .version = "0.1.0",
    .fingerprint = 0x{fingerprint:016x},
    .minimum_zig_version = "0.16.0",
    .dependencies = .{{
        .goaria_sdk = .{{
            .path = "vendor/goaria_sdk",
        }},
    }},
    .paths = .{{
        "build.zig",
        "build.zig.zon",
        "manifest.json",
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

    let main_zig = format!(
        r#"const std = @import("std");
const goaria = @import("goaria_sdk");

pub const {struct_name} = struct {{
    pub fn matchUrl(allocator: std.mem.Allocator, input: goaria.MatchInput) !goaria.MatchOutput {{
        _ = allocator;
        if (std.mem.indexOf(u8, input.url, "fixture.invalid") != null) {{
            return goaria.MatchOutput.matchedResult()
                .withConfidence(100)
                .withReason("matches fixture.invalid domain");
        }}
        return goaria.MatchOutput.unmatchedResult();
    }}

    pub fn extract(allocator: std.mem.Allocator, input: goaria.ExtractInput) !goaria.ExtractOutput {{
        if (std.mem.indexOf(u8, input.url, "fixture.invalid") == null) {{
            return goaria.ExtractOutput.empty();
        }}

        const item = goaria.ExtractedItemRef{{
            .id = "item-001",
            .url = input.url,
            .filename = "download.bin",
            .size_bytes = null,
            .mime_type = "application/octet-stream",
        }};

        return try goaria.ExtractOutput.single(allocator, item);
    }}
}};

comptime {{
    goaria.exportExtractor({struct_name});
}}
"#
    );
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
