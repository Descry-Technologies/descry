use std::fs;

use descry_audit::{verify_file, VerifyOutcome};
use descry_cli::{run_with_io, Cli, Commands, CursorHookAction, HookAction};
use descry_memory::Approval;
use serde_json::{json, Value};

#[test]
fn cursor_before_shell_execution_blocks_rm_rf_home_and_writes_audit() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let audit = tempdir.path().join("audit.log");
    let mut input = cursor_shell_payload("rm -rf ~");
    let mut output = Vec::new();
    let mut error = Vec::new();

    let result = run_with_io(shell_cli(&audit), &mut input, &mut output, &mut error);

    result.expect("hook succeeds");
    assert!(!error.is_empty(), "block decision should write to stderr");
    let output_json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(output_json["permission"], "deny");
    assert_eq!(output_json["decision"], "deny");
    assert!(output_json["reason"]
        .as_str()
        .expect("reason is string")
        .contains("rm-root-home"));
    assert_eq!(
        verify_file(&audit, "test-repo"),
        VerifyOutcome::Ok { records: 1 }
    );
    let audit_body = fs::read_to_string(&audit).expect("audit log reads");
    assert!(audit_body.contains(r#""decision":"block""#));
    assert!(!audit_body.contains("rm -rf ~"));
}

#[test]
fn cursor_before_mcp_execution_allows_and_writes_audit() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let audit = tempdir.path().join("audit.log");
    let mut input = cursor_mcp_payload("https://mcp.example.com/mcp", "list_projects");
    let mut output = Vec::new();
    let mut error = Vec::new();

    let result = run_with_io(mcp_cli(&audit), &mut input, &mut output, &mut error);

    result.expect("hook succeeds");
    assert!(error.is_empty());
    let output_json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(output_json["permission"], "allow");
    assert_eq!(output_json["decision"], "allow");
    assert_eq!(
        verify_file(&audit, "test-repo"),
        VerifyOutcome::Ok { records: 1 }
    );
    let audit_body = fs::read_to_string(&audit).expect("audit log reads");
    assert!(audit_body.contains(r#""decision":"allow""#));
    assert!(audit_body.contains(r#""sanitized_target":"https://mcp.example.com/mcp""#));
}

#[test]
fn cursor_before_mcp_execution_blocks_production_control_plane() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let audit = tempdir.path().join("audit.log");
    let mut input = cursor_mcp_payload("https://prod-mcp.example.com/admin", "delete_project");
    let mut output = Vec::new();
    let mut error = Vec::new();

    let result = run_with_io(mcp_cli(&audit), &mut input, &mut output, &mut error);

    result.expect("hook succeeds");
    assert!(!error.is_empty(), "block decision should write to stderr");
    let output_json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(output_json["permission"], "deny");
    assert!(output_json["reason"]
        .as_str()
        .expect("reason is string")
        .contains("mcp-production-control-plane"));
    assert_eq!(
        verify_file(&audit, "test-repo"),
        VerifyOutcome::Ok { records: 1 }
    );
    let audit_body = fs::read_to_string(&audit).expect("audit log reads");
    assert!(audit_body.contains(r#""decision":"block""#));
    assert!(audit_body.contains(r#""sanitized_target":"https://prod-mcp.example.com/admin""#));
}

#[test]
fn cursor_before_mcp_execution_blocks_destructive_tool_name() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let audit = tempdir.path().join("audit.log");
    let mut input = cursor_mcp_payload("https://mcp.example.com/readonly", "delete_project");
    let mut output = Vec::new();
    let mut error = Vec::new();

    let result = run_with_io(mcp_cli(&audit), &mut input, &mut output, &mut error);

    result.expect("hook succeeds");
    assert!(!error.is_empty(), "block decision should write to stderr");
    let output_json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(output_json["permission"], "deny");
    assert!(output_json["reason"]
        .as_str()
        .expect("reason is string")
        .contains("mcp-destructive-tool"));
    assert_eq!(
        verify_file(&audit, "test-repo"),
        VerifyOutcome::Ok { records: 1 }
    );
    let audit_body = fs::read_to_string(&audit).expect("audit log reads");
    assert!(audit_body.contains(r#""decision":"block""#));
    assert!(!audit_body.contains("delete_project"));
}

#[test]
fn cursor_before_mcp_execution_blocks_dangerous_argument_key_without_values() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let audit = tempdir.path().join("audit.log");
    let mut input = cursor_mcp_payload_with_arguments(
        "https://mcp.example.com/readonly",
        "archive_project",
        json!({
            "project_id": "prod-123",
            "confirm_destroy": true
        }),
    );
    let mut output = Vec::new();
    let mut error = Vec::new();

    let result = run_with_io(mcp_cli(&audit), &mut input, &mut output, &mut error);

    result.expect("hook succeeds");
    assert!(!error.is_empty(), "block decision should write to stderr");
    let output_json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(output_json["permission"], "deny");
    assert!(output_json["reason"]
        .as_str()
        .expect("reason is string")
        .contains("mcp-dangerous-argument"));
    assert_eq!(
        verify_file(&audit, "test-repo"),
        VerifyOutcome::Ok { records: 1 }
    );
    let audit_body = fs::read_to_string(&audit).expect("audit log reads");
    assert!(audit_body.contains(r#""decision":"block""#));
    assert!(!audit_body.contains("prod-123"));
}

#[test]
fn cursor_before_mcp_execution_downgrades_block_with_live_approval() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let audit = tempdir.path().join("audit.log");
    let approvals = tempdir.path().join("approvals.jsonl");
    descry_memory::append_approval(
        &approvals,
        &Approval {
            scope: String::from("mcp:https://prod-mcp.example.com/**"),
            created_at_epoch_seconds: 1,
            expires_at_epoch_seconds: u64::MAX,
            approver: String::from("human"),
        },
    )
    .expect("approval appends");
    let mut input = cursor_mcp_payload("https://prod-mcp.example.com/admin", "delete_project");
    let mut output = Vec::new();
    let mut error = Vec::new();

    let result = run_with_io(
        mcp_cli_with_approvals(&audit, &approvals),
        &mut input,
        &mut output,
        &mut error,
    );

    result.expect("hook succeeds");
    assert!(error.is_empty());
    let output_json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(output_json["permission"], "allow");
    assert!(output_json["reason"]
        .as_str()
        .expect("reason is string")
        .contains("scoped approval matched MCP target"));
    let audit_body = fs::read_to_string(&audit).expect("audit log reads");
    assert!(audit_body.contains(r#""decision":"allow_with_log""#));
}

fn shell_cli(audit: &std::path::Path) -> Cli {
    Cli {
        command: Commands::Hook {
            action: HookAction::Cursor {
                action: CursorHookAction::BeforeShellExecution {
                    policy: workspace_root().join("policies/safe-defaults.yml"),
                    project: audit
                        .parent()
                        .expect("audit has parent")
                        .join("project.yml"),
                    audit: audit.to_path_buf(),
                    context: audit.parent().expect("audit has parent").join("context.md"),
                    state: audit.parent().expect("audit has parent").join("state"),
                    approvals: audit
                        .parent()
                        .expect("audit has parent")
                        .join("approvals.jsonl"),
                    asset_policy: audit
                        .parent()
                        .expect("audit has parent")
                        .join("asset-policy.yml"),
                    behavior: audit
                        .parent()
                        .expect("audit has parent")
                        .join("behavior.json"),
                    repo_id_hash: String::from("test-repo"),
                },
            },
        },
    }
}

fn mcp_cli(audit: &std::path::Path) -> Cli {
    mcp_cli_with_approvals(
        audit,
        &audit
            .parent()
            .expect("audit has parent")
            .join("approvals.jsonl"),
    )
}

fn mcp_cli_with_approvals(audit: &std::path::Path, approvals: &std::path::Path) -> Cli {
    Cli {
        command: Commands::Hook {
            action: HookAction::Cursor {
                action: CursorHookAction::BeforeMcpExecution {
                    policy: workspace_root().join("policies/safe-defaults.yml"),
                    project: audit
                        .parent()
                        .expect("audit has parent")
                        .join("project.yml"),
                    audit: audit.to_path_buf(),
                    context: audit.parent().expect("audit has parent").join("context.md"),
                    state: audit.parent().expect("audit has parent").join("state"),
                    approvals: approvals.to_path_buf(),
                    asset_policy: audit
                        .parent()
                        .expect("audit has parent")
                        .join("asset-policy.yml"),
                    behavior: audit
                        .parent()
                        .expect("audit has parent")
                        .join("behavior.json"),
                    repo_id_hash: String::from("test-repo"),
                },
            },
        },
    }
}

fn workspace_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate has workspace parent")
        .parent()
        .expect("crates dir has workspace parent")
        .to_path_buf()
}

fn cursor_shell_payload(command: &str) -> std::io::Cursor<Vec<u8>> {
    let payload = json!({
        "cwd": "/repo",
        "command": command
    });
    std::io::Cursor::new(serde_json::to_vec(&payload).expect("payload encodes"))
}

fn cursor_mcp_payload(url: &str, tool_name: &str) -> std::io::Cursor<Vec<u8>> {
    cursor_mcp_payload_with_arguments(url, tool_name, json!({}))
}

fn cursor_mcp_payload_with_arguments(
    url: &str,
    tool_name: &str,
    arguments: Value,
) -> std::io::Cursor<Vec<u8>> {
    let payload = json!({
        "cwd": "/repo",
        "url": url,
        "tool_name": tool_name,
        "arguments": arguments
    });
    std::io::Cursor::new(serde_json::to_vec(&payload).expect("payload encodes"))
}
