use descry_cli::{run_with_io, ApprovalsAction, Cli, Commands};
use serde_json::Value;

#[test]
fn approve_appends_scoped_expiring_approval() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let path = tempdir.path().join(".descry/memory/approvals.jsonl");
    let mut input = [].as_slice();
    let mut output = Vec::new();
    let mut error = Vec::new();

    run_with_io(
        Cli {
            command: Commands::Approve {
                scope: String::from("path:crates/descry-cli/**"),
                ttl: String::from("30m"),
                path: path.clone(),
                approver: String::from("human"),
            },
        },
        &mut input,
        &mut output,
        &mut error,
    )
    .expect("approve succeeds");

    assert!(error.is_empty());
    let output_json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(output_json["scope"], "path:crates/descry-cli/**");
    assert_eq!(output_json["scope_kind"], "path");
    assert_eq!(output_json["scope_pattern"], "crates/descry-cli/**");
    assert_eq!(output_json["approver"], "human");

    let approvals = descry_memory::load_approvals(&path).expect("approvals load");
    assert_eq!(approvals.len(), 1);
    assert_eq!(approvals[0].scope, "path:crates/descry-cli/**");
    assert!(approvals[0].expires_at_epoch_seconds > approvals[0].created_at_epoch_seconds);
}

#[test]
fn approve_rejects_invalid_ttl() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let path = tempdir.path().join(".descry/memory/approvals.jsonl");
    let mut input = [].as_slice();
    let mut output = Vec::new();
    let mut error = Vec::new();

    let failure = run_with_io(
        Cli {
            command: Commands::Approve {
                scope: String::from("path:*"),
                ttl: String::from("soon"),
                path,
                approver: String::from("human"),
            },
        },
        &mut input,
        &mut output,
        &mut error,
    )
    .expect_err("approve fails");

    assert_eq!(failure.exit_code(), 2);
    assert!(output.is_empty());
    assert!(error.is_empty());
}

#[test]
fn approve_rejects_invalid_scope() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let path = tempdir.path().join(".descry/memory/approvals.jsonl");
    let mut input = [].as_slice();
    let mut output = Vec::new();
    let mut error = Vec::new();

    let failure = run_with_io(
        Cli {
            command: Commands::Approve {
                scope: String::from("pat:src/**"),
                ttl: String::from("30m"),
                path,
                approver: String::from("human"),
            },
        },
        &mut input,
        &mut output,
        &mut error,
    )
    .expect_err("approve fails");

    assert_eq!(failure.exit_code(), 2);
    assert!(output.is_empty());
    assert!(error.is_empty());
}

#[test]
fn approve_rejects_ttl_over_24h() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let path = tempdir.path().join(".descry/memory/approvals.jsonl");
    let mut input = [].as_slice();
    let mut output = Vec::new();
    let mut error = Vec::new();

    let failure = run_with_io(
        Cli {
            command: Commands::Approve {
                scope: String::from("path:src/**"),
                ttl: String::from("25h"),
                path,
                approver: String::from("human"),
            },
        },
        &mut input,
        &mut output,
        &mut error,
    )
    .expect_err("approve fails");

    assert_eq!(failure.exit_code(), 2);
    assert!(output.is_empty());
    assert!(error.is_empty());
}

#[test]
fn approvals_list_outputs_live_approvals() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let path = tempdir.path().join(".descry/memory/approvals.jsonl");
    descry_memory::append_approval(
        &path,
        &descry_memory::Approval {
            scope: String::from("action:deploy"),
            created_at_epoch_seconds: 1,
            expires_at_epoch_seconds: u64::MAX,
            approver: String::from("human"),
        },
    )
    .expect("approval appends");
    let mut input = [].as_slice();
    let mut output = Vec::new();
    let mut error = Vec::new();

    run_with_io(
        Cli {
            command: Commands::Approvals {
                action: ApprovalsAction::List { path: path.clone() },
            },
        },
        &mut input,
        &mut output,
        &mut error,
    )
    .expect("approvals list succeeds");

    assert!(error.is_empty());
    let output_json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(
        output_json["path"].as_str().expect("path is string"),
        path.to_string_lossy()
    );
    assert_eq!(output_json["approvals"][0]["scope"], "action:deploy");
    assert_eq!(output_json["approvals"][0]["live"], true);
}

#[test]
fn approvals_revoke_expires_exact_scope() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let path = tempdir.path().join(".descry/memory/approvals.jsonl");
    descry_memory::append_approval(
        &path,
        &descry_memory::Approval {
            scope: String::from("action:deploy"),
            created_at_epoch_seconds: 1,
            expires_at_epoch_seconds: u64::MAX,
            approver: String::from("human"),
        },
    )
    .expect("approval appends");
    let mut input = [].as_slice();
    let mut output = Vec::new();
    let mut error = Vec::new();

    run_with_io(
        Cli {
            command: Commands::Approvals {
                action: ApprovalsAction::Revoke {
                    path: path.clone(),
                    scope: String::from("action:deploy"),
                },
            },
        },
        &mut input,
        &mut output,
        &mut error,
    )
    .expect("approvals revoke succeeds");

    assert!(error.is_empty());
    let output_json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(output_json["revoked"], 1);
    assert!(
        !descry_memory::has_live_approval_for_action(&path, "deploy", u64::MAX - 1)
            .expect("approval reads")
    );
}
