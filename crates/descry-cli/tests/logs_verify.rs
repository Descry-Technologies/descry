use std::fs;

use descry_audit::AuditChain;
use descry_cli::{run_with_io, Cli, Commands, LogsAction};
use serde_json::Value;

#[test]
fn logs_verify_reports_intact_and_tampered_chain() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let path = tempdir.path().join("audit.log");
    let mut chain = AuditChain::open(&path, "test-repo").expect("chain opens");

    for seq in 1..=3 {
        chain
            .append(
                format!("2026-05-11T20:00:0{seq}Z"),
                "allow",
                format!("acp-{seq}"),
                None,
                Some(format!("reason-{seq}")),
            )
            .expect("append succeeds");
    }

    let (exit_code, output, error) = run_logs_verify(&path, "test-repo");
    assert_eq!(exit_code, 0);
    assert!(error.is_empty());
    let json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(json["ok"], true);
    assert_eq!(json["records"], 3);

    let mut body = fs::read_to_string(&path).expect("audit log reads");
    body = body.replacen("reason-2", "Reason-2", 1);
    fs::write(&path, body).expect("audit log mutates");

    let (exit_code, output, error) = run_logs_verify(&path, "test-repo");
    assert_eq!(exit_code, 1);
    assert!(error.is_empty());
    let json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(json["ok"], false);
    assert_eq!(json["broken_at_seq"], 2);
}

fn run_logs_verify(path: &std::path::Path, repo_id_hash: &str) -> (i32, Vec<u8>, Vec<u8>) {
    let cli = Cli {
        command: Commands::Logs {
            action: LogsAction::Verify {
                path: path.to_path_buf(),
                repo_id_hash: repo_id_hash.to_string(),
            },
        },
    };
    let mut input = [].as_slice();
    let mut output = Vec::new();
    let mut error = Vec::new();
    let exit_code = match run_with_io(cli, &mut input, &mut output, &mut error) {
        Ok(()) => 0,
        Err(error) => error.exit_code(),
    };
    (exit_code, output, error)
}
