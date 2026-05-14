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

#[test]
fn logs_tail_prints_recent_records() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let path = tempdir.path().join("audit.log");
    write_audit_log(&path);

    let cli = Cli {
        command: Commands::Logs {
            action: LogsAction::Tail {
                path: path.clone(),
                lines: 2,
            },
        },
    };
    let (exit_code, output, error) = run_cli(cli);

    assert_eq!(exit_code, 0);
    assert!(error.is_empty());
    let lines: Vec<&str> = std::str::from_utf8(&output)
        .expect("stdout utf8")
        .lines()
        .collect();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].contains("\"seq\":2"));
    assert!(lines[1].contains("\"seq\":3"));
}

#[test]
fn logs_search_filters_by_reason_rule_or_decision() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let path = tempdir.path().join("audit.log");
    write_audit_log(&path);

    let cli = Cli {
        command: Commands::Logs {
            action: LogsAction::Search {
                query: String::from("reason-2"),
                path,
            },
        },
    };
    let (exit_code, output, error) = run_cli(cli);

    assert_eq!(exit_code, 0);
    assert!(error.is_empty());
    let body = std::str::from_utf8(&output).expect("stdout utf8");
    assert!(body.contains("\"seq\":2"));
    assert!(!body.contains("\"seq\":1"));
    assert!(!body.contains("\"seq\":3"));
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
    run_cli(cli)
}

fn write_audit_log(path: &std::path::Path) {
    let mut chain = AuditChain::open(path, "test-repo").expect("chain opens");
    for seq in 1..=3 {
        chain
            .append(
                format!("2026-05-11T20:00:0{seq}Z"),
                if seq == 2 { "block" } else { "allow" },
                format!("acp-{seq}"),
                Some(format!("rule-{seq}")),
                Some(format!("reason-{seq}")),
            )
            .expect("append succeeds");
    }
}

fn run_cli(cli: Cli) -> (i32, Vec<u8>, Vec<u8>) {
    let mut input = [].as_slice();
    let mut output = Vec::new();
    let mut error = Vec::new();
    let exit_code = match run_with_io(cli, &mut input, &mut output, &mut error) {
        Ok(()) => 0,
        Err(error) => error.exit_code(),
    };
    (exit_code, output, error)
}
