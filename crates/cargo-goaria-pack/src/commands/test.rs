use std::collections::BTreeMap;
use std::path::Path;
use std::time::Instant;
use base64::Engine;
use colored::Colorize;
use thiserror::Error;
use crate::cli::TestArgs;
use crate::commands::check::resolve_manifest_and_wasm;
use crate::runner::{ExtractorRunner, MockBroker, MockBrokerRule, RunnerError, UrlPattern};

#[derive(Debug, Error)]
pub enum TestCommandError {
    #[error("runner error: {0}")]
    Runner(#[from] RunnerError),
    #[error("check resolution error: {0}")]
    Check(#[from] crate::check::CheckError),
    #[error("test failure: {0}")]
    TestFailed(String),
}

fn load_fixtures_from_dir(dir: &Path, broker: &mut MockBroker) {
    if !dir.exists() || !dir.is_dir() {
        return;
    }
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                        parse_and_add_fixture_rules(val, broker);
                    }
                }
            }
        }
    }
}

fn parse_and_add_fixture_rules(val: serde_json::Value, broker: &mut MockBroker) {
    match val {
        serde_json::Value::Array(items) => {
            for item in items {
                add_single_fixture_rule(item, broker);
            }
        }
        serde_json::Value::Object(_) => {
            add_single_fixture_rule(val, broker);
        }
        _ => {}
    }
}

fn add_single_fixture_rule(val: serde_json::Value, broker: &mut MockBroker) {
    let pattern = if let Some(exact) = val
        .get("url")
        .or_else(|| val.get("exact"))
        .and_then(|v| v.as_str())
    {
        UrlPattern::Exact(exact.to_string())
    } else if let Some(prefix) = val.get("prefix").and_then(|v| v.as_str()) {
        UrlPattern::Prefix(prefix.to_string())
    } else if let Some(pattern_str) = val.get("pattern").and_then(|v| v.as_str()) {
        UrlPattern::Exact(pattern_str.to_string())
    } else {
        return;
    };

    let status_code = val
        .get("status_code")
        .or_else(|| val.get("status"))
        .and_then(|v| v.as_i64())
        .unwrap_or(200) as i32;

    let mut headers = BTreeMap::new();
    if let Some(h_obj) = val.get("headers").and_then(|v| v.as_object()) {
        for (k, v) in h_obj {
            if let Some(arr) = v.as_array() {
                let vec_str: Vec<String> = arr
                    .iter()
                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                    .collect();
                headers.insert(k.clone(), vec_str);
            } else if let Some(s) = v.as_str() {
                headers.insert(k.clone(), vec![s.to_string()]);
            }
        }
    }

    let body = if let Some(json_val) = val.get("json") {
        if !headers.contains_key("Content-Type") {
            headers.insert(
                "Content-Type".to_string(),
                vec!["application/json".to_string()],
            );
        }
        serde_json::to_vec(json_val).unwrap_or_default()
    } else if let Some(b64) = val.get("body_base64").and_then(|v| v.as_str()) {
        base64::engine::general_purpose::STANDARD
            .decode(b64)
            .unwrap_or_default()
    } else if let Some(text) = val.get("body").and_then(|v| v.as_str()) {
        text.as_bytes().to_vec()
    } else {
        Vec::new()
    };

    broker.add_rule(MockBrokerRule {
        pattern,
        status_code,
        headers,
        body,
    });
}

pub fn handle_test(args: TestArgs) -> Result<(), TestCommandError> {
    let (manifest, wasm_path, wasm_bytes) =
        resolve_manifest_and_wasm(&args.project_dir, args.manifest.as_ref(), args.wasm.as_ref())?;

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
        let fixtures_dir = args.fixtures.unwrap_or_else(|| {
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

        if fixtures_dir.exists() {
            println!(
                "  {} Loading mock fixtures from: {}",
                "[✓]".green(),
                fixtures_dir.display()
            );
            load_fixtures_from_dir(&fixtures_dir, &mut mock_broker);
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
    for domain in &manifest.domains {
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
                    println!("{} (unmatched)", "ok".yellow());
                    passed += 1;
                }
            }
            Err(e) => {
                println!("{} ({})", "FAILED".red().bold(), e);
                failed += 1;
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
