use descry_cli::{
    run_with_io, ClaudeHookAction, Cli, CodexHookAction, Commands, CursorHookAction, HookAction,
};
use serde_json::{json, Value};

#[test]
fn claude_output_schema_matches_contract_fixture() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let audit = tempdir.path().join("audit.log");
    let mut input = claude_write_payload("crates/descry-engine/src/lib.rs");
    let output = run_hook(cli_claude(&audit), &mut input).expect("hook succeeds");
    let actual: Value = serde_json::from_slice(&output).expect("stdout is json");
    let expected = fixture("claude_require_approval.json");

    assert_claude_like_contract(&actual, &expected);
}

#[test]
fn codex_output_schema_denies_require_approval_contract_fixture() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let audit = tempdir.path().join("audit.log");
    let mut input = codex_apply_patch_payload("*** Begin Patch\n*** Update File: crates/descry-engine/src/lib.rs\n-old\n+new\n*** End Patch\n");
    let output = run_hook(cli_codex(&audit), &mut input).expect("hook succeeds");
    let actual: Value = serde_json::from_slice(&output).expect("stdout is json");
    let expected = fixture("codex_require_approval.json");

    assert_claude_like_contract(&actual, &expected);
}

#[test]
fn cursor_shell_output_schema_matches_contract_fixture() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let audit = tempdir.path().join("audit.log");
    let mut input = cursor_shell_payload("npm run deploy");
    let output = run_hook(cli_cursor_shell(&audit), &mut input).expect("hook succeeds");
    let actual: Value = serde_json::from_slice(&output).expect("stdout is json");
    let expected = fixture("cursor_shell_require_approval.json");

    assert_cursor_contract(&actual, &expected);
}

#[test]
fn cursor_mcp_output_schema_matches_contract_fixture() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let audit = tempdir.path().join("audit.log");
    let mut input = cursor_mcp_payload("https://mcp.example.com/mcp", "list_projects");
    let output = run_hook(cli_cursor_mcp(&audit), &mut input).expect("hook succeeds");
    let actual: Value = serde_json::from_slice(&output).expect("stdout is json");
    let expected = fixture("cursor_mcp_allow.json");

    assert_cursor_contract(&actual, &expected);
}

#[test]
fn hook_parse_errors_are_machine_readable() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let audit = tempdir.path().join("audit.log");
    let expected = fixture("parse_error.json");
    let mut input = "{".as_bytes();
    let mut output = Vec::new();
    let mut error = Vec::new();

    let failure = run_with_io(cli_claude(&audit), &mut input, &mut output, &mut error)
        .expect_err("parse fails");

    assert_eq!(failure.exit_code(), expected["exitCode"]);
    assert!(output.is_empty());
    let error_json: Value = serde_json::from_slice(&error).expect("stderr is json");
    assert!(error_json["error"]
        .as_str()
        .expect("error is string")
        .contains(expected["stderr"]["error"].as_str().expect("fixture error")));
}

fn assert_claude_like_contract(actual: &Value, expected: &Value) {
    let actual_output = &actual["hookSpecificOutput"];
    let expected_output = &expected["hookSpecificOutput"];
    assert_eq!(
        actual_output["hookEventName"],
        expected_output["hookEventName"]
    );
    assert_eq!(
        actual_output["permissionDecision"],
        expected_output["permissionDecision"]
    );
    let reason = actual_output["permissionDecisionReason"]
        .as_str()
        .expect("reason is string");
    for fragment in expected_output["permissionDecisionReasonContains"]
        .as_array()
        .expect("reason fragments are array")
    {
        assert!(
            reason.contains(fragment.as_str().expect("fragment is string")),
            "missing reason fragment {fragment:?} in {reason:?}"
        );
    }
}

fn assert_cursor_contract(actual: &Value, expected: &Value) {
    assert_eq!(actual["continue"], expected["continue"]);
    assert_eq!(actual["permission"], expected["permission"]);
    assert_eq!(actual["decision"], expected["decision"]);
    let reason = actual["reason"].as_str().expect("reason is string");
    for fragment in expected["reasonContains"]
        .as_array()
        .expect("reason fragments are array")
    {
        assert!(
            reason.contains(fragment.as_str().expect("fragment is string")),
            "missing reason fragment {fragment:?} in {reason:?}"
        );
    }
    if expected["userMessageSameAsReason"] == true {
        assert_eq!(actual["user_message"], actual["reason"]);
    }
    if expected["agentMessageSameAsReason"] == true {
        assert_eq!(actual["agent_message"], actual["reason"]);
    }
}

fn run_hook(cli: Cli, input: &mut dyn std::io::Read) -> Result<Vec<u8>, descry_cli::CliError> {
    let mut output = Vec::new();
    let mut error = Vec::new();
    run_with_io(cli, input, &mut output, &mut error)?;
    // block/require-approval decisions write a human-readable message to stderr
    let error_str = String::from_utf8_lossy(&error);
    assert!(
        error_str.is_empty() || error_str.contains("Descry:"),
        "unexpected stderr: {error_str}"
    );
    Ok(output)
}

fn fixture(name: &str) -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/hook_contracts")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(path).expect("fixture reads"))
        .expect("fixture is json")
}

fn cli_claude(audit: &std::path::Path) -> Cli {
    Cli {
        command: Commands::Hook {
            action: HookAction::Claude {
                action: ClaudeHookAction::Pretooluse {
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

fn cli_codex(audit: &std::path::Path) -> Cli {
    Cli {
        command: Commands::Hook {
            action: HookAction::Codex {
                action: CodexHookAction::Pretooluse {
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

fn cli_cursor_shell(audit: &std::path::Path) -> Cli {
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

fn cli_cursor_mcp(audit: &std::path::Path) -> Cli {
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

fn workspace_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate has workspace parent")
        .parent()
        .expect("crates dir has workspace parent")
        .to_path_buf()
}

fn claude_write_payload(path: &str) -> std::io::Cursor<Vec<u8>> {
    let payload = json!({
        "session_id": "s1",
        "cwd": "/repo",
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": { "file_path": path, "content": "body omitted" },
        "tool_use_id": "toolu_1"
    });
    std::io::Cursor::new(serde_json::to_vec(&payload).expect("payload encodes"))
}

fn codex_apply_patch_payload(patch: &str) -> std::io::Cursor<Vec<u8>> {
    let payload = json!({
        "session_id": "s1",
        "cwd": "/repo",
        "hook_event_name": "PreToolUse",
        "tool_name": "apply_patch",
        "tool_input": { "cmd": patch },
        "tool_use_id": "toolu_1",
        "model": "gpt-5.5",
        "turn_id": "turn_1"
    });
    std::io::Cursor::new(serde_json::to_vec(&payload).expect("payload encodes"))
}

fn cursor_shell_payload(command: &str) -> std::io::Cursor<Vec<u8>> {
    let payload = json!({
        "cwd": "/repo",
        "command": command
    });
    std::io::Cursor::new(serde_json::to_vec(&payload).expect("payload encodes"))
}

fn cursor_mcp_payload(url: &str, tool_name: &str) -> std::io::Cursor<Vec<u8>> {
    let payload = json!({
        "cwd": "/repo",
        "url": url,
        "tool_name": tool_name,
        "arguments": {}
    });
    std::io::Cursor::new(serde_json::to_vec(&payload).expect("payload encodes"))
}
