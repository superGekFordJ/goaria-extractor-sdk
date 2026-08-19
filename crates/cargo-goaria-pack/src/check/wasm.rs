use std::collections::{HashMap, HashSet};
use thiserror::Error;
use wasmparser::{ExternalKind, Parser, Payload, ValType};
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
    #[error("invalid export signature for '{name}': expected {expected}, found {actual}")]
    InvalidExportSignature {
        name: String,
        expected: String,
        actual: String,
    },
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
    pub export_signatures: HashMap<String, String>,
    pub memory_exported: bool,
    pub imports: Vec<(String, String)>,
    pub byte_size: usize,
}

fn val_type_to_str(vt: &ValType) -> &'static str {
    match vt {
        ValType::I32 => "i32",
        ValType::I64 => "i64",
        ValType::F32 => "f32",
        ValType::F64 => "f64",
        ValType::V128 => "v128",
        ValType::Ref(_) => "ref",
    }
}

fn func_type_to_str(params: &[ValType], results: &[ValType]) -> String {
    let p_str = params
        .iter()
        .map(val_type_to_str)
        .collect::<Vec<_>>()
        .join(", ");
    let r_str = if results.is_empty() {
        "()".to_string()
    } else if results.len() == 1 {
        val_type_to_str(&results[0]).to_string()
    } else {
        format!(
            "({})",
            results
                .iter()
                .map(val_type_to_str)
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    format!("({}) -> {}", p_str, r_str)
}

pub fn analyze_wasm_bytecode(wasm_bytes: &[u8]) -> Result<WasmAnalysis, CheckError> {
    let mut analysis = WasmAnalysis {
        byte_size: wasm_bytes.len(),
        ..Default::default()
    };

    let mut types: Vec<(Vec<ValType>, Vec<ValType>)> = Vec::new();
    let mut import_func_type_indices: Vec<usize> = Vec::new();
    let mut defined_func_type_indices: Vec<usize> = Vec::new();
    let mut exported_funcs: Vec<(String, usize)> = Vec::new();

    let parser = Parser::new(0);
    for payload in parser.parse_all(wasm_bytes) {
        let payload = payload.map_err(|e| CheckError::WasmParser(e.to_string()))?;
        match payload {
            Payload::TypeSection(reader) => {
                for rec_group in reader {
                    let rec_group =
                        rec_group.map_err(|e| CheckError::WasmParser(e.to_string()))?;
                    for sub_type in rec_group.into_types() {
                        match &sub_type.composite_type.inner {
                            wasmparser::CompositeInnerType::Func(func_type) => {
                                types.push((
                                    func_type.params().to_vec(),
                                    func_type.results().to_vec(),
                                ));
                            }
                            _ => {
                                types.push((Vec::new(), Vec::new()));
                            }
                        }
                    }
                }
            }
            Payload::ImportSection(reader) => {
                for import in reader {
                    let import = import.map_err(|e| CheckError::WasmParser(e.to_string()))?;
                    if let wasmparser::TypeRef::Func(type_idx) = import.ty {
                        import_func_type_indices.push(type_idx as usize);
                    }
                    analysis
                        .imports
                        .push((import.module.to_string(), import.name.to_string()));
                }
            }
            Payload::FunctionSection(reader) => {
                for func in reader {
                    let type_idx = func.map_err(|e| CheckError::WasmParser(e.to_string()))?;
                    defined_func_type_indices.push(type_idx as usize);
                }
            }
            Payload::ExportSection(reader) => {
                for export in reader {
                    let export = export.map_err(|e| CheckError::WasmParser(e.to_string()))?;
                    if export.kind == ExternalKind::Memory && export.name == "memory" {
                        analysis.memory_exported = true;
                    }
                    if export.kind == ExternalKind::Func {
                        exported_funcs.push((export.name.to_string(), export.index as usize));
                    }
                    analysis.exports.insert(export.name.to_string());
                }
            }
            _ => {}
        }
    }

    // Resolve exported function signatures
    let num_imported_funcs = import_func_type_indices.len();
    for (name, func_idx) in exported_funcs {
        let type_idx_opt = if func_idx < num_imported_funcs {
            import_func_type_indices.get(func_idx).copied()
        } else {
            defined_func_type_indices
                .get(func_idx - num_imported_funcs)
                .copied()
        };

        if let Some(type_idx) = type_idx_opt {
            if let Some((params, results)) = types.get(type_idx) {
                let sig_str = func_type_to_str(params, results);
                analysis.export_signatures.insert(name, sig_str);
            }
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

    // 2. Validate mandatory exports and ABI v1 type signatures
    let required_exports = [
        ("goaria_abi_version", "() -> i32"),
        ("goaria_alloc", "(i32) -> i32"),
        ("goaria_free", "(i32, i32) -> ()"),
        ("goaria_match", "(i32, i32) -> i64"),
        ("goaria_extract", "(i32, i32) -> i64"),
    ];
    for (req, expected_sig) in required_exports {
        if !analysis.exports.contains(req) {
            return Err(CheckError::MissingExport(req.to_string()));
        }
        if let Some(actual_sig) = analysis.export_signatures.get(req) {
            if actual_sig != expected_sig {
                return Err(CheckError::InvalidExportSignature {
                    name: req.to_string(),
                    expected: expected_sig.to_string(),
                    actual: actual_sig.clone(),
                });
            }
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
