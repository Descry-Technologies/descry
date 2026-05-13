use std::path::{Path, PathBuf};

use descry_cli::{run_with_io, Cli, Commands, ExpectedVerdict, PolicyAction};
use serde_json::Value;

#[test]
fn policy_test_matches_tier_one_fixtures() {
    let cases = [
        ("fixtures/rm-rf-home.json", ExpectedVerdict::Block),
        ("fixtures/rm-rf-slash.json", ExpectedVerdict::Block),
        ("fixtures/rm-rf-home-var.json", ExpectedVerdict::Block),
        ("fixtures/rm-rf-home-glob.json", ExpectedVerdict::Block),
        ("fixtures/rm-rf-sudo-home.json", ExpectedVerdict::Block),
        ("fixtures/force-push-main.json", ExpectedVerdict::Block),
        ("fixtures/force-push-release.json", ExpectedVerdict::Block),
        ("fixtures/railway-delete.json", ExpectedVerdict::Block),
        ("fixtures/fly-destroy.json", ExpectedVerdict::Block),
        ("fixtures/aws-rds-delete.json", ExpectedVerdict::Block),
        ("fixtures/gcloud-sql-delete.json", ExpectedVerdict::Block),
        ("fixtures/db-drop-database.json", ExpectedVerdict::Block),
        ("fixtures/db-truncate-table.json", ExpectedVerdict::Block),
        (
            "fixtures/mcp-prod-control-plane.json",
            ExpectedVerdict::Block,
        ),
        ("fixtures/mcp-destructive-tool.json", ExpectedVerdict::Block),
        (
            "fixtures/mcp-dangerous-argument.json",
            ExpectedVerdict::Block,
        ),
        ("fixtures/normal-edit.json", ExpectedVerdict::Allow),
        ("fixtures/cargo-test.json", ExpectedVerdict::Allow),
        ("fixtures/mcp-readonly.json", ExpectedVerdict::Allow),
    ];

    for (fixture, expect) in cases {
        let cli = policy_test_cli(fixture, expect);
        let mut input = [].as_slice();
        let mut output = Vec::new();
        let mut error = Vec::new();

        run_with_io(cli, &mut input, &mut output, &mut error).expect("policy test succeeds");

        assert!(error.is_empty(), "{fixture}");
        let json: Value = serde_json::from_slice(&output).expect("stdout is json");
        assert_eq!(json["match"], true, "{fixture}");
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

fn policy_test_cli(fixture: &str, expect: ExpectedVerdict) -> Cli {
    Cli {
        command: Commands::Policy {
            action: PolicyAction::Test {
                fixture: repo_path(fixture),
                expect,
                policy: repo_path("policies/safe-defaults.yml"),
            },
        },
    }
}

fn repo_path(path: impl AsRef<Path>) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}
