use std::fs;

use descry_audit::{verify_file, VerifyOutcome};
use descry_cli::{run_with_io, Cli, CodexHookAction, Commands, HookAction};
use serde_json::{json, Value};

#[test]
fn codex_pretooluse_blocks_rm_rf_home_and_writes_audit() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let audit = tempdir.path().join("audit.log");
    let mut input = codex_bash_payload("rm -rf ~");
    let mut output = Vec::new();
    let mut error = Vec::new();

    let result = run_with_io(cli(&audit), &mut input, &mut output, &mut error);

    result.expect("hook succeeds");
    assert!(!error.is_empty(), "block decision should write to stderr");
    let output_json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(
        output_json["hookSpecificOutput"]["permissionDecision"],
        "deny"
    );
    assert!(
        output_json["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .expect("reason is string")
            .contains("rm-root-home")
    );
    assert_eq!(
        verify_file(&audit, "test-repo"),
        VerifyOutcome::Ok { records: 1 }
    );
    let audit_body = fs::read_to_string(&audit).expect("audit log reads");
    assert!(audit_body.contains(r#""decision":"block""#));
    assert!(!audit_body.contains("rm -rf ~"));
}

#[test]
fn codex_pretooluse_blocks_destructive_mcp_tool() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let audit = tempdir.path().join("audit.log");
    let mut input = codex_mcp_payload("mcp__prod__delete_project");
    let mut output = Vec::new();
    let mut error = Vec::new();

    run_with_io(cli(&audit), &mut input, &mut output, &mut error).expect("hook succeeds");

    assert!(!error.is_empty(), "block decision should write to stderr");
    let output_json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(
        output_json["hookSpecificOutput"]["permissionDecision"],
        "deny"
    );
    assert!(
        output_json["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .expect("reason is string")
            .contains("mcp")
    );
    let audit_body = fs::read_to_string(&audit).expect("audit log reads");
    assert!(!audit_body.contains("prod-123"));
}

#[test]
fn codex_pretooluse_blocks_multi_target_patch_with_secret() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let audit = tempdir.path().join("audit.log");
    let mut input = codex_apply_patch_payload(
        r#"*** Begin Patch
*** Update File: src/lib.rs
@@
*** Update File: .env.production
@@
*** End Patch"#,
        "fix src/lib.rs",
    );
    let mut output = Vec::new();
    let mut error = Vec::new();

    run_with_io(cli(&audit), &mut input, &mut output, &mut error).expect("hook succeeds");

    assert!(!error.is_empty(), "block decision should write to stderr");
    let output_json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(
        output_json["hookSpecificOutput"]["permissionDecision"],
        "deny"
    );
    assert!(
        output_json["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .expect("reason is string")
            .contains(".env.production")
    );
}

fn cli(audit: &std::path::Path) -> Cli {
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

fn workspace_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate has workspace parent")
        .parent()
        .expect("crates dir has workspace parent")
        .to_path_buf()
}

fn codex_bash_payload(command: &str) -> std::io::Cursor<Vec<u8>> {
    let payload = json!({
        "session_id": "s1",
        "cwd": "/repo",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command },
        "tool_use_id": "toolu_1",
        "model": "gpt-5.5",
        "turn_id": "turn_1"
    });
    std::io::Cursor::new(serde_json::to_vec(&payload).expect("payload encodes"))
}

fn codex_mcp_payload(tool_name: &str) -> std::io::Cursor<Vec<u8>> {
    let payload = json!({
        "session_id": "s1",
        "cwd": "/repo",
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": {
            "arguments": {
                "project_id": "prod-123",
                "confirm_destroy": true,
                "password": "redacted"
            }
        },
        "tool_use_id": "toolu_2",
        "model": "gpt-5.5",
        "turn_id": "turn_1"
    });
    std::io::Cursor::new(serde_json::to_vec(&payload).expect("payload encodes"))
}

fn codex_apply_patch_payload(patch: &str, user_prompt: &str) -> std::io::Cursor<Vec<u8>> {
    let payload = json!({
        "session_id": "s1",
        "cwd": "/repo",
        "hook_event_name": "PreToolUse",
        "tool_name": "apply_patch",
        "tool_input": {
            "patch": patch,
            "user_prompt": user_prompt
        },
        "tool_use_id": "toolu_3",
        "model": "gpt-5.5",
        "turn_id": "turn_1"
    });
    std::io::Cursor::new(serde_json::to_vec(&payload).expect("payload encodes"))
}
