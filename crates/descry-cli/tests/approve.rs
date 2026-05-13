use descry_cli::{run_with_io, Cli, Commands};
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
                scope: String::from("crates/descry-cli/**"),
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
    assert_eq!(output_json["scope"], "crates/descry-cli/**");
    assert_eq!(output_json["approver"], "human");

    let approvals = descry_memory::load_approvals(&path).expect("approvals load");
    assert_eq!(approvals.len(), 1);
    assert_eq!(approvals[0].scope, "crates/descry-cli/**");
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
                scope: String::from("*"),
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
