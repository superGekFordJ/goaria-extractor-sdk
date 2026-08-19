use std::collections::HashSet;
use thiserror::Error;
use wasmparser::{ExternalKind, Parser, Payload};
use crate::manifest::{
    Manifest, ManifestError, CAPABILITY_AUTH_PROFILE, CAPABILITY_HTTP_FETCH,
};

#[derive(Debug, Error)]
pub enum CheckError {
    #[error("manifest validation error: {0}")]
    Manifest(#[from] ManifestError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("build error: {0}")]
    Build(#[from] crate::commands::build::BuildError),
    #[error("WASM parser error: {0}")]
    WasmParser(String),
    #[error("missing required export function: '{0}'")]
    MissingExport(String),
    #[error("missing required linear memory export 'memory'")]
    MissingMemoryExport,
    #[error("forbidden import module '{module}': only 'goaria_host' is permitted")]
    ForbiddenImportModule { module: String },
    #[error("forbidden import function '{module}.{function}'")]
    ForbiddenImportFunction { module: String, function: String },
    #[error("pack imports '{import}' but manifest is missing required capability '{capability}'")]
    MissingCapabilityForImport { import: String, capability: String },
}

#[derive(Debug, Default, Clone)]
pub struct WasmAnalysis {
    pub exports: HashSet<String>,
    pub memory_exported: bool,
    pub imports: Vec<(String, String)>,
    pub byte_size: usize,
}

pub fn analyze_wasm_bytecode(wasm_bytes: &[u8]) -> Result<WasmAnalysis, CheckError> {
    let mut analysis = WasmAnalysis {
        byte_size: wasm_bytes.len(),
        ..Default::default()
    };

    let parser = Parser::new(0);
    for payload in parser.parse_all(wasm_bytes) {
        let payload = payload.map_err(|e| CheckError::WasmParser(e.to_string()))?;
        match payload {
            Payload::ExportSection(reader) => {
                for export in reader {
                    let export = export.map_err(|e| CheckError::WasmParser(e.to_string()))?;
                    if export.kind == ExternalKind::Memory && export.name == "memory" {
                        analysis.memory_exported = true;
                    }
                    analysis.exports.insert(export.name.to_string());
                }
            }
            Payload::ImportSection(reader) => {
                for import in reader {
                    let import = import.map_err(|e| CheckError::WasmParser(e.to_string()))?;
                    analysis
                        .imports
                        .push((import.module.to_string(), import.name.to_string()));
                }
            }
            _ => {}
        }
    }

    Ok(analysis)
}

pub fn verify_wasm_and_manifest(
    analysis: &WasmAnalysis,
    manifest: &Manifest,
) -> Result<(), CheckError> {
    // 1. Validate manifest schema and limits
    manifest.validate_runnable()?;

    // 2. Validate mandatory exports
    let required_exports = [
        "goaria_abi_version",
        "goaria_alloc",
        "goaria_free",
        "goaria_match",
        "goaria_extract",
    ];
    for req in required_exports {
        if !analysis.exports.contains(req) {
            return Err(CheckError::MissingExport(req.to_string()));
        }
    }

    // 3. Validate linear memory export
    if !analysis.memory_exported {
        return Err(CheckError::MissingMemoryExport);
    }

    // 4. Validate imports against 'goaria_host' and capabilities
    for (module, field) in &analysis.imports {
        if module != "goaria_host" {
            return Err(CheckError::ForbiddenImportModule {
                module: module.clone(),
            });
        }

        match field.as_str() {
            "http_fetch" => {
                if !manifest.has_capability(CAPABILITY_HTTP_FETCH) {
                    return Err(CheckError::MissingCapabilityForImport {
                        import: "goaria_host.http_fetch".to_string(),
                        capability: CAPABILITY_HTTP_FETCH.to_string(),
                    });
                }
            }
            "auth_profile_status" => {
                if !manifest.has_capability(CAPABILITY_AUTH_PROFILE) {
                    return Err(CheckError::MissingCapabilityForImport {
                        import: "goaria_host.auth_profile_status".to_string(),
                        capability: CAPABILITY_AUTH_PROFILE.to_string(),
                    });
                }
            }
            other => {
                return Err(CheckError::ForbiddenImportFunction {
                    module: module.clone(),
                    function: other.to_string(),
                });
            }
        }
    }

    Ok(())
}
