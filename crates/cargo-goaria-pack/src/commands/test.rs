use crate::cli::TestArgs;
use crate::commands::check::resolve_manifest_and_wasm;
use crate::runner::{
    ExtractorRunner, MockBroker, MockBrokerRule, MockRequestExpectation, RunnerError, UrlPattern,
};
use base64::Engine;
use colored::Colorize;
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Instant;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TestCommandError {
    #[error("runner error: {0}")]
    Runner(#[from] RunnerError),
    #[error("check resolution error: {0}")]
    Check(#[from] crate::check::CheckError),
    #[error("fixture error in '{path}': {message}")]
    Fixture { path: String, message: String },
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("test failure: {0}")]
    TestFailed(String),
}

fn load_fixtures_from_dir(dir: &Path, broker: &mut MockBroker) -> Result<(), TestCommandError> {
    if !dir.exists() {
        return Err(TestCommandError::Fixture {
            path: dir.display().to_string(),
            message: "fixtures directory does not exist".to_string(),
        });
    }
    if !dir.is_dir() {
        return Err(TestCommandError::Fixture {
            path: dir.display().to_string(),
            message: "fixtures path is not a directory".to_string(),
        });
    }
    let entries = std::fs::read_dir(dir)?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("json") {
            let content =
                std::fs::read_to_string(&path).map_err(|e| TestCommandError::Fixture {
                    path: path.display().to_string(),
                    message: format!("failed to read fixture file: {}", e),
                })?;
            let val: serde_json::Value =
                serde_json::from_str(&content).map_err(|e| TestCommandError::Fixture {
                    path: path.display().to_string(),
                    message: format!("invalid JSON syntax: {}", e),
                })?;
            parse_and_add_fixture_rules(&path, val, broker)?;
        }
    }
    Ok(())
}

fn parse_and_add_fixture_rules(
    path: &Path,
    val: serde_json::Value,
    broker: &mut MockBroker,
) -> Result<(), TestCommandError> {
    match val {
        serde_json::Value::Array(items) => {
            for item in items {
                add_single_fixture_rule(path, item, broker)?;
            }
        }
        serde_json::Value::Object(_) => {
            add_single_fixture_rule(path, val, broker)?;
        }
        _ => {
            return Err(TestCommandError::Fixture {
                path: path.display().to_string(),
                message: "top-level fixture must be a JSON object or array of objects".to_string(),
            });
        }
    }
    Ok(())
}

fn add_single_fixture_rule(
    path: &Path,
    val: serde_json::Value,
    broker: &mut MockBroker,
) -> Result<(), TestCommandError> {
    let object = val
        .as_object()
        .ok_or_else(|| fixture_error(path, "fixture rule must be an object"))?;
    for field in object.keys() {
        if !matches!(
            field.as_str(),
            "url"
                | "exact"
                | "prefix"
                | "pattern"
                | "status_code"
                | "status"
                | "headers"
                | "json"
                | "body_base64"
                | "body"
                | "expect"
        ) {
            return Err(fixture_error(
                path,
                format!("unknown fixture field '{field}'"),
            ));
        }
    }

    let pattern_fields = ["url", "exact", "prefix", "pattern"];
    let present_patterns: Vec<_> = pattern_fields
        .iter()
        .filter(|field| object.contains_key(**field))
        .collect();
    if present_patterns.len() != 1 {
        return Err(fixture_error(
            path,
            "fixture rule must contain exactly one of 'url', 'exact', 'prefix', or 'pattern'",
        ));
    }
    let pattern_field = *present_patterns[0];
    let pattern_value = required_fixture_string(path, object, pattern_field)?;
    if pattern_value.is_empty() {
        return Err(fixture_error(path, "fixture URL pattern must be non-empty"));
    }
    let pattern = if pattern_field == "prefix" {
        UrlPattern::Prefix(pattern_value.to_string())
    } else {
        UrlPattern::Exact(pattern_value.to_string())
    };

    if object.contains_key("status_code") && object.contains_key("status") {
        return Err(fixture_error(
            path,
            "fixture rule must not contain both 'status_code' and 'status'",
        ));
    }
    let status_code = match object.get("status_code").or_else(|| object.get("status")) {
        Some(value) => {
            let status = value
                .as_i64()
                .and_then(|status| i32::try_from(status).ok())
                .ok_or_else(|| fixture_error(path, "fixture status must be an integer"))?;
            if !(100..=599).contains(&status) {
                return Err(fixture_error(
                    path,
                    "fixture status must be between 100 and 599",
                ));
            }
            status
        }
        None => 200,
    };

    let mut headers = BTreeMap::new();
    if let Some(value) = object.get("headers") {
        let header_object = value
            .as_object()
            .ok_or_else(|| fixture_error(path, "fixture headers must be an object"))?;
        for (name, value) in header_object {
            if !is_valid_header_name(name) {
                return Err(fixture_error(
                    path,
                    format!("invalid fixture header name '{name}'"),
                ));
            }
            let values = if let Some(value) = value.as_str() {
                vec![value.to_string()]
            } else if let Some(array) = value.as_array() {
                let mut values = Vec::with_capacity(array.len());
                for value in array {
                    let value = value.as_str().ok_or_else(|| {
                        fixture_error(
                            path,
                            format!("fixture header '{name}' array must contain only strings"),
                        )
                    })?;
                    values.push(value.to_string());
                }
                values
            } else {
                return Err(fixture_error(
                    path,
                    format!("fixture header '{name}' must be a string or string array"),
                ));
            };
            if values.iter().any(|value| !is_valid_header_value(value)) {
                return Err(fixture_error(
                    path,
                    format!("fixture header '{name}' contains an invalid value"),
                ));
            }
            headers.insert(name.clone(), values);
        }
    }

    let body_fields = ["json", "body_base64", "body"];
    if body_fields
        .iter()
        .filter(|field| object.contains_key(**field))
        .count()
        > 1
    {
        return Err(fixture_error(
            path,
            "fixture rule must contain at most one of 'json', 'body_base64', or 'body'",
        ));
    }
    let body = if let Some(json_value) = object.get("json") {
        if !headers
            .keys()
            .any(|name| name.eq_ignore_ascii_case("content-type"))
        {
            headers.insert(
                "Content-Type".to_string(),
                vec!["application/json".to_string()],
            );
        }
        serde_json::to_vec(json_value).map_err(|error| {
            fixture_error(path, format!("failed to serialize json field: {error}"))
        })?
    } else if object.contains_key("body_base64") {
        let encoded = required_fixture_string(path, object, "body_base64")?;
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|error| {
                fixture_error(path, format!("invalid base64 in body_base64: {error}"))
            })?
    } else if object.contains_key("body") {
        required_fixture_string(path, object, "body")?
            .as_bytes()
            .to_vec()
    } else {
        Vec::new()
    };

    let expect = match object.get("expect") {
        Some(value) => Some(parse_request_expectation(path, value)?),
        None => None,
    };

    broker.add_rule(MockBrokerRule {
        pattern,
        status_code,
        headers,
        body,
        expect,
    });
    Ok(())
}

/// Parse the `expect` sub-object of a fixture rule. Note that `headers` and
/// `body_base64` inside `expect` assert the outgoing request, unlike the
/// same-named top-level keys which shape the mock response.
fn parse_request_expectation(
    path: &Path,
    value: &serde_json::Value,
) -> Result<MockRequestExpectation, TestCommandError> {
    let object = value
        .as_object()
        .ok_or_else(|| fixture_error(path, "fixture 'expect' must be an object"))?;
    for field in object.keys() {
        if !matches!(
            field.as_str(),
            "method" | "headers" | "body_base64" | "broker_policy_ref" | "endpoint_ref"
        ) {
            return Err(fixture_error(
                path,
                format!("unknown expect field '{field}'"),
            ));
        }
    }

    let method = match object.get("method") {
        Some(value) => Some(
            value
                .as_str()
                .ok_or_else(|| fixture_error(path, "expect.method must be a string"))?
                .to_string(),
        ),
        None => None,
    };

    let mut headers = BTreeMap::new();
    if let Some(value) = object.get("headers") {
        let header_object = value
            .as_object()
            .ok_or_else(|| fixture_error(path, "expect.headers must be an object"))?;
        for (name, value) in header_object {
            if !is_valid_header_name(name) {
                return Err(fixture_error(
                    path,
                    format!("invalid expect header name '{name}'"),
                ));
            }
            let value = value.as_str().ok_or_else(|| {
                fixture_error(path, format!("expect header '{name}' must be a string"))
            })?;
            if !is_valid_header_value(value) {
                return Err(fixture_error(
                    path,
                    format!("expect header '{name}' contains an invalid value"),
                ));
            }
            headers.insert(name.trim().to_lowercase(), value.to_string());
        }
    }

    let body_base64 = match object.get("body_base64") {
        Some(value) => {
            let encoded = value
                .as_str()
                .ok_or_else(|| fixture_error(path, "expect.body_base64 must be a string"))?;
            base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|error| {
                    fixture_error(
                        path,
                        format!("invalid base64 in expect.body_base64: {error}"),
                    )
                })?;
            Some(encoded.to_string())
        }
        None => None,
    };

    let broker_policy_ref = match object.get("broker_policy_ref") {
        Some(value) => Some(
            value
                .as_str()
                .ok_or_else(|| fixture_error(path, "expect.broker_policy_ref must be a string"))?
                .to_string(),
        ),
        None => None,
    };
    let endpoint_ref = match object.get("endpoint_ref") {
        Some(value) => Some(
            value
                .as_str()
                .ok_or_else(|| fixture_error(path, "expect.endpoint_ref must be a string"))?
                .to_string(),
        ),
        None => None,
    };

    Ok(MockRequestExpectation {
        method,
        headers,
        body_base64,
        broker_policy_ref,
        endpoint_ref,
    })
}

fn required_fixture_string<'a>(
    path: &Path,
    object: &'a serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<&'a str, TestCommandError> {
    object
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| fixture_error(path, format!("fixture field '{field}' must be a string")))
}

fn fixture_error(path: &Path, message: impl Into<String>) -> TestCommandError {
    TestCommandError::Fixture {
        path: path.display().to_string(),
        message: message.into(),
    }
}

fn is_valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn is_valid_header_value(value: &str) -> bool {
    !value
        .chars()
        .any(|character| (character < ' ' && character != '\t') || character == '\u{7f}')
}

pub fn handle_test(args: TestArgs) -> Result<(), TestCommandError> {
    let (manifest, wasm_path, wasm_bytes) = resolve_manifest_and_wasm(
        &args.project_dir,
        args.manifest.as_ref(),
        args.wasm.as_ref(),
    )?;

    println!(
        "{} running test suite on {} (pack_id: '{}')...\n",
        "Testing:".cyan().bold(),
        wasm_path.display(),
        manifest.pack_id
    );

    let start = Instant::now();
    let runner = ExtractorRunner::new(&wasm_bytes, manifest.clone())?;
    let runner = if args.live {
        runner.with_live_broker()
    } else {
        let mut mock_broker = MockBroker::new();
        let explicit_fixtures = args.fixtures.is_some();
        let fixtures_dir = args.fixtures.clone().unwrap_or_else(|| {
            let manifest_dir = args
                .manifest
                .as_ref()
                .and_then(|m| m.parent())
                .unwrap_or(&args.project_dir);
            let direct_fixtures = manifest_dir.join("fixtures");
            if direct_fixtures.exists() {
                direct_fixtures
            } else {
                manifest_dir.join("tests").join("fixtures")
            }
        });

        if explicit_fixtures || fixtures_dir.exists() {
            println!(
                "  {} Loading mock fixtures from: {}",
                "[✓]".green(),
                fixtures_dir.display()
            );
            load_fixtures_from_dir(&fixtures_dir, &mut mock_broker)?;
        }

        runner.with_mock_broker(mock_broker)
    };

    let mut passed = 0;
    let mut failed = 0;

    // Test 1: ABI Version Check
    print!("  test abi_version negotiation ... ");
    match runner.check_abi() {
        Ok(ver) => {
            println!("{} (ABI v{})", "ok".green(), ver);
            passed += 1;
        }
        Err(e) => {
            println!("{} ({})", "FAILED".red().bold(), e);
            failed += 1;
        }
    }

    // Test 2: Domain matching & extraction tests from manifest domains
    if let Some(domains) = &manifest.domains {
        for domain in domains {
            let test_url = format!("https://{}/test-resource-001", domain.host);
            print!("  test match_url('{}') ... ", test_url);
            match runner.match_url(&test_url) {
                Ok(match_out) => {
                    if match_out.matched {
                        println!(
                            "{} (confidence: {}%)",
                            "ok".green(),
                            match_out.confidence.unwrap_or(0)
                        );
                        passed += 1;

                        // Test extract
                        print!("  test extract('{}') ... ", test_url);
                        match runner.extract(&test_url) {
                            Ok(extract_out) => {
                                println!("{} (items: {})", "ok".green(), extract_out.items.len());
                                passed += 1;
                            }
                            Err(e) => {
                                println!("{} ({})", "FAILED".red().bold(), e);
                                failed += 1;
                            }
                        }
                    } else {
                        println!("{} (declared domain unmatched)", "FAILED".red().bold());
                        failed += 1;
                    }
                }
                Err(e) => {
                    println!("{} ({})", "FAILED".red().bold(), e);
                    failed += 1;
                }
            }
        }
    }

    // Test 3: Negative match URL
    let negative_url = "https://unrelated.example.invalid/path";
    print!("  test negative match_url('{}') ... ", negative_url);
    match runner.match_url(negative_url) {
        Ok(match_out) => {
            if !match_out.matched {
                println!("{}", "ok".green());
                passed += 1;
            } else {
                println!(
                    "{} (unexpected match on foreign domain)",
                    "FAILED".red().bold()
                );
                failed += 1;
            }
        }
        Err(e) => {
            println!("{} ({})", "FAILED".red().bold(), e);
            failed += 1;
        }
    }

    let duration = start.elapsed();
    println!(
        "\nTest result: {}. {} passed; {} failed; finished in {:.2?}",
        if failed == 0 {
            "ok".green().bold()
        } else {
            "FAILED".red().bold()
        },
        passed,
        failed,
        duration
    );

    if failed > 0 {
        Err(TestCommandError::TestFailed(format!(
            "{} test(s) failed",
            failed
        )))
    } else {
        Ok(())
    }
}
