use std::path::{Path, PathBuf};

use descry_cli::{run_with_io, Cli, Commands, ExpectedVerdict, PolicyAction};
use serde_json::Value;

#[derive(Debug)]
struct FixtureCase {
    path: String,
    expected_decision: String,
    expected_rule: Option<String>,
}

#[test]
fn policy_test_matches_manifest_fixtures() {
    for case in manifest_cases() {
        let cli = policy_test_cli(&case.path, expected_verdict(&case.expected_decision));
        let mut input = [].as_slice();
        let mut output = Vec::new();
        let mut error = Vec::new();

        run_with_io(cli, &mut input, &mut output, &mut error).expect("policy test succeeds");

        assert!(error.is_empty(), "{}", case.path);
        let json: Value = serde_json::from_slice(&output).expect("stdout is json");
        assert_eq!(json["match"], true, "{}", case.path);
        if let Some(rule_id) = case.expected_rule {
            assert_eq!(json["rule"], rule_id, "{}", case.path);
        }
    }
}

#[test]
fn policy_test_reports_mismatch() {
    let cli = policy_test_cli("fixtures/rm-rf-home.json", ExpectedVerdict::Allow);
    let mut input = [].as_slice();
    let mut output = Vec::new();
    let mut error = Vec::new();

    let failure =
        run_with_io(cli, &mut input, &mut output, &mut error).expect_err("mismatch fails");

    assert_eq!(failure.exit_code(), 1);
    assert!(error.is_empty());
    let json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(json["match"], false);
}

#[test]
fn policy_test_routes_project_assets_through_engine() {
    let cli = policy_test_cli(
        "fixtures/infra-file-write.json",
        ExpectedVerdict::RequireApproval,
    );
    let mut input = [].as_slice();
    let mut output = Vec::new();
    let mut error = Vec::new();

    run_with_io(cli, &mut input, &mut output, &mut error).expect("policy test succeeds");

    assert!(error.is_empty());
    let json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(json["verdict"], "require_approval");
    assert_eq!(json["match"], true);
}

#[test]
fn policy_test_hard_block_only_skips_project_assets() {
    let cli = policy_test_cli_with_options(
        "fixtures/infra-file-write.json",
        ExpectedVerdict::Allow,
        true,
    );
    let mut input = [].as_slice();
    let mut output = Vec::new();
    let mut error = Vec::new();

    run_with_io(cli, &mut input, &mut output, &mut error).expect("policy test succeeds");

    assert!(error.is_empty());
    let json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(json["verdict"], "allow");
    assert_eq!(json["match"], true);
}

fn policy_test_cli(fixture: &str, expect: ExpectedVerdict) -> Cli {
    policy_test_cli_with_options(fixture, expect, false)
}

fn policy_test_cli_with_options(
    fixture: &str,
    expect: ExpectedVerdict,
    hard_block_only: bool,
) -> Cli {
    Cli {
        command: Commands::Policy {
            action: PolicyAction::Test {
                fixture: repo_path(fixture),
                expect,
                policy: repo_path("policies/safe-defaults.yml"),
                project: repo_path(".descry/project.yml"),
                approvals: repo_path(".descry/memory/approvals.jsonl"),
                behavior: repo_path(".descry/memory/behavior.json"),
                hard_block_only,
            },
        },
    }
}

fn repo_path(path: impl AsRef<Path>) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

fn manifest_cases() -> Vec<FixtureCase> {
    parse_manifest(include_str!("../../../fixtures/manifest.yml"))
}

fn parse_manifest(body: &str) -> Vec<FixtureCase> {
    let mut cases = Vec::new();
    let mut current = FixtureCase {
        path: String::new(),
        expected_decision: String::new(),
        expected_rule: None,
    };
    for line in body.lines() {
        if let Some(path) = line.strip_prefix("- path: ") {
            if !current.path.is_empty() {
                cases.push(current);
            }
            current = FixtureCase {
                path: path.trim().to_string(),
                expected_decision: String::new(),
                expected_rule: None,
            };
        } else if let Some(value) = line.trim().strip_prefix("expected_decision: ") {
            current.expected_decision = value.trim().to_string();
        } else if let Some(value) = line.trim().strip_prefix("expected_rule: ") {
            current.expected_rule = Some(value.trim().to_string());
        }
    }
    if !current.path.is_empty() {
        cases.push(current);
    }
    cases
}

fn expected_verdict(value: &str) -> ExpectedVerdict {
    match value {
        "allow" => ExpectedVerdict::Allow,
        "require_approval" => ExpectedVerdict::RequireApproval,
        "block" => ExpectedVerdict::Block,
        other => panic!("unsupported manifest decision {other}"),
    }
}
