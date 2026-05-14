use std::fs;
use std::process::Command;

use descry_cli::{run_with_io, Cli, Commands, ScanAction};
use serde_json::Value;

#[test]
fn scan_secrets_allows_clean_path() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    fs::write(tempdir.path().join("README.md"), "API_KEY=replace_me\n").expect("file writes");

    let json = run_scan(ScanAction::Secrets {
        path: tempdir.path().to_path_buf(),
        staged: false,
    })
    .expect("scan succeeds");

    assert_eq!(json["ok"], true);
    assert_eq!(
        json["findings"]
            .as_array()
            .expect("findings is array")
            .len(),
        0
    );
}

#[test]
fn scan_secrets_blocks_secret_in_path() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    fs::write(
        tempdir.path().join(".env"),
        "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz123456\n",
    )
    .expect("file writes");

    let failure = run_scan(ScanAction::Secrets {
        path: tempdir.path().to_path_buf(),
        staged: false,
    })
    .expect_err("scan fails with finding");

    assert_eq!(failure.exit_code, 1);
    assert_eq!(failure.json["ok"], false);
    assert_eq!(failure.json["findings"][0]["path"], ".env");
    assert_eq!(failure.json["findings"][0]["kind"], "openai_api_key");
    assert_eq!(failure.json["findings"][0]["evidence"], "sk-a...3456");
}

#[test]
fn scan_secrets_blocks_staged_secret() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    git(tempdir.path(), &["init"]);
    fs::write(
        tempdir.path().join(".env"),
        "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz123456\n",
    )
    .expect("file writes");
    git(tempdir.path(), &["add", ".env"]);

    let failure = run_scan(ScanAction::Secrets {
        path: tempdir.path().to_path_buf(),
        staged: true,
    })
    .expect_err("scan fails with finding");

    assert_eq!(failure.exit_code, 1);
    assert_eq!(failure.json["ok"], false);
    assert_eq!(failure.json["mode"], "staged");
    assert_eq!(failure.json["findings"][0]["path"], ".env");
    assert_eq!(failure.json["findings"][0]["kind"], "github_token");
}

#[derive(Debug)]
struct ScanFailure {
    exit_code: i32,
    json: Value,
}

fn run_scan(action: ScanAction) -> Result<Value, ScanFailure> {
    let mut input = [].as_slice();
    let mut output = Vec::new();
    let mut error = Vec::new();
    let result = run_with_io(
        Cli {
            command: Commands::Scan { action },
        },
        &mut input,
        &mut output,
        &mut error,
    );
    assert!(error.is_empty());
    let json: Value = serde_json::from_slice(&output).expect("stdout is json");

    match result {
        Ok(()) => Ok(json),
        Err(error) => Err(ScanFailure {
            exit_code: error.exit_code(),
            json,
        }),
    }
}

fn git(cwd: &std::path::Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("git runs");

    assert!(
        output.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
}
