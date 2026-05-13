use std::fs;

use descry_audit::{verify_file, VerifyOutcome};
use descry_cli::{run_with_io, ClaudeHookAction, Cli, Commands, HookAction};
use descry_memory::Approval;
use serde_json::{json, Value};

#[test]
fn claude_pretooluse_blocks_rm_rf_home_and_writes_audit() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let audit = tempdir.path().join("audit.log");
    let mut input = claude_bash_payload("rm -rf ~");
    let mut output = Vec::new();
    let mut error = Vec::new();

    let result = run_with_io(cli(&audit), &mut input, &mut output, &mut error);

    result.expect("hook succeeds");
    assert!(error.is_empty());
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
    let state_dir = audit.parent().expect("audit has parent").join("state");
    let recent_events = descry_context::read_recent_events(&state_dir).expect("events read");
    assert_eq!(recent_events.len(), 1);
    assert_eq!(recent_events[0].session_id.as_deref(), Some("s1"));
    assert_eq!(recent_events[0].action_type, "shell.exec");
    assert_eq!(recent_events[0].target, "<shell command omitted>");
    assert_eq!(recent_events[0].decision.as_deref(), Some("block"));
    assert!(state_dir.join("sessions/s1.jsonl").exists());
}

#[test]
fn claude_pretooluse_allows_benign_shell_command() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let audit = tempdir.path().join("audit.log");
    let mut input = claude_bash_payload("cargo test -p descry-core");
    let mut output = Vec::new();
    let mut error = Vec::new();

    run_with_io(cli(&audit), &mut input, &mut output, &mut error).expect("hook succeeds");

    assert!(error.is_empty());
    let output_json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(
        output_json["hookSpecificOutput"]["permissionDecision"],
        "allow"
    );
    assert_eq!(
        verify_file(&audit, "test-repo"),
        VerifyOutcome::Ok { records: 1 }
    );
}

#[test]
fn claude_pretooluse_requires_approval_for_sensitive_off_task_write() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let audit = tempdir.path().join("audit.log");
    let approvals = tempdir.path().join("approvals.jsonl");
    let behavior = tempdir.path().join("behavior.json");
    let mut input = claude_write_payload("crates/descry-engine/src/lib.rs");
    let mut output = Vec::new();
    let mut error = Vec::new();

    run_with_io(
        cli_full(
            &audit,
            &approvals,
            &tempdir.path().join("asset-policy.yml"),
            &behavior,
        ),
        &mut input,
        &mut output,
        &mut error,
    )
    .expect("hook succeeds");

    assert!(error.is_empty());
    let output_json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(
        output_json["hookSpecificOutput"]["permissionDecision"],
        "ask"
    );
    assert!(
        output_json["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .expect("reason is string")
            .contains("requires scoped approval")
    );
    assert_eq!(
        descry_memory::behavior_count(
            &behavior,
            "claude-code",
            "file.write",
            "crates/descry-engine/src/lib.rs"
        )
        .expect("behavior reads"),
        1
    );
}

#[test]
fn claude_pretooluse_downgrades_sensitive_write_with_live_approval() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let audit = tempdir.path().join("audit.log");
    let approvals = tempdir.path().join("approvals.jsonl");
    descry_memory::append_approval(
        &approvals,
        &Approval {
            scope: String::from("crates/descry-engine/**"),
            created_at_epoch_seconds: 1,
            expires_at_epoch_seconds: u64::MAX,
            approver: String::from("human"),
        },
    )
    .expect("approval appends");
    let mut input = claude_write_payload("crates/descry-engine/src/lib.rs");
    let mut output = Vec::new();
    let mut error = Vec::new();

    run_with_io(
        cli_with_approvals(&audit, &approvals),
        &mut input,
        &mut output,
        &mut error,
    )
    .expect("hook succeeds");

    assert!(error.is_empty());
    let output_json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(
        output_json["hookSpecificOutput"]["permissionDecision"],
        "allow"
    );
    let audit_body = fs::read_to_string(&audit).expect("audit log reads");
    assert!(audit_body.contains(r#""decision":"allow_with_log""#));
}

#[test]
fn claude_pretooluse_raises_repeat_sensitive_write_reason() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let audit = tempdir.path().join("audit.log");
    let approvals = tempdir.path().join("approvals.jsonl");
    let behavior = tempdir.path().join("behavior.json");
    let mut second_output = Vec::new();

    for attempt in 1..=2 {
        let mut input = claude_write_payload("crates/descry-engine/src/lib.rs");
        let mut output = Vec::new();
        let mut error = Vec::new();
        run_with_io(
            cli_full(
                &audit,
                &approvals,
                &tempdir.path().join("asset-policy.yml"),
                &behavior,
            ),
            &mut input,
            &mut output,
            &mut error,
        )
        .expect("hook succeeds");
        assert!(error.is_empty());
        if attempt == 2 {
            second_output = output;
        }
    }

    let output_json: Value = serde_json::from_slice(&second_output).expect("stdout is json");
    assert!(
        output_json["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .expect("reason is string")
            .contains("prior attempt")
    );
    assert_eq!(
        descry_memory::behavior_count(
            &behavior,
            "claude-code",
            "file.write",
            "crates/descry-engine/src/lib.rs"
        )
        .expect("behavior reads"),
        2
    );
}

#[test]
fn claude_pretooluse_uses_custom_asset_policy_for_sensitive_write() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let audit = tempdir.path().join("audit.log");
    let approvals = tempdir.path().join("approvals.jsonl");
    let asset_policy = tempdir.path().join("policy.yml");
    fs::write(
        &asset_policy,
        r#"
assets:
  - id: auth-system
    paths:
      - "src/auth/**"
    sensitivity: high
    default_action: require_approval
"#,
    )
    .expect("asset policy writes");
    let mut input = claude_write_payload("src/auth/session.rs");
    let mut output = Vec::new();
    let mut error = Vec::new();

    run_with_io(
        cli_full(
            &audit,
            &approvals,
            &asset_policy,
            &tempdir.path().join("behavior.json"),
        ),
        &mut input,
        &mut output,
        &mut error,
    )
    .expect("hook succeeds");

    assert!(error.is_empty());
    let output_json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(
        output_json["hookSpecificOutput"]["permissionDecision"],
        "ask"
    );
    assert!(
        output_json["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .expect("reason is string")
            .contains("auth-system")
    );
}

#[test]
fn claude_pretooluse_uses_project_defaults_for_secret_write() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let audit = tempdir.path().join("audit.log");
    let approvals = tempdir.path().join("approvals.jsonl");
    let mut input = claude_write_payload(".env.production");
    let mut output = Vec::new();
    let mut error = Vec::new();

    run_with_io(
        cli_full(
            &audit,
            &approvals,
            &tempdir.path().join("missing-legacy-asset-policy.yml"),
            &tempdir.path().join("behavior.json"),
        ),
        &mut input,
        &mut output,
        &mut error,
    )
    .expect("hook succeeds");

    assert!(error.is_empty());
    let output_json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(
        output_json["hookSpecificOutput"]["permissionDecision"],
        "deny"
    );
    assert!(
        output_json["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .expect("reason is string")
            .contains("asset: secrets")
    );
}

#[test]
fn claude_pretooluse_enriches_context_from_project_index() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let audit = tempdir.path().join("audit.log");
    let state = tempdir.path().join("state");
    descry_context::write_project_index(
        &descry_context::ProjectIndex {
            repo_root: tempdir.path().to_path_buf(),
            repo_name: String::from("descry"),
            branch: Some(String::from("fix/session-expiry")),
            languages: vec![String::from("typescript")],
            frameworks: Vec::new(),
            source_paths: vec![String::from("src/**")],
            test_paths: Vec::new(),
            infra_paths: Vec::new(),
            config_paths: Vec::new(),
            secret_paths: Vec::new(),
            deploy_paths: Vec::new(),
        },
        &state.join("project-index.json"),
    )
    .expect("project index writes");
    let mut input = claude_write_payload("src/auth/expiry.ts");
    let mut output = Vec::new();
    let mut error = Vec::new();

    run_with_io(
        cli_full(
            &audit,
            &tempdir.path().join("approvals.jsonl"),
            &tempdir.path().join("missing-legacy-asset-policy.yml"),
            &tempdir.path().join("behavior.json"),
        ),
        &mut input,
        &mut output,
        &mut error,
    )
    .expect("hook succeeds");

    assert!(error.is_empty());
    let output_json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(
        output_json["hookSpecificOutput"]["permissionDecision"],
        "allow"
    );
    assert!(
        output_json["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .expect("reason is string")
            .contains("fix/session-expiry")
    );
}

fn cli(audit: &std::path::Path) -> Cli {
    cli_with_approvals(
        audit,
        &audit
            .parent()
            .expect("audit has parent")
            .join("approvals.jsonl"),
    )
}

fn cli_with_approvals(audit: &std::path::Path, approvals: &std::path::Path) -> Cli {
    cli_full(
        audit,
        approvals,
        &audit
            .parent()
            .expect("audit has parent")
            .join("asset-policy.yml"),
        &audit
            .parent()
            .expect("audit has parent")
            .join("behavior.json"),
    )
}

fn cli_full(
    audit: &std::path::Path,
    approvals: &std::path::Path,
    asset_policy: &std::path::Path,
    behavior: &std::path::Path,
) -> Cli {
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
                    approvals: approvals.to_path_buf(),
                    asset_policy: asset_policy.to_path_buf(),
                    behavior: behavior.to_path_buf(),
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

fn claude_bash_payload(command: &str) -> std::io::Cursor<Vec<u8>> {
    let payload = json!({
        "session_id": "s1",
        "transcript_path": "/tmp/transcript.jsonl",
        "cwd": "/repo",
        "permission_mode": "default",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command },
        "tool_use_id": "toolu_1"
    });
    std::io::Cursor::new(serde_json::to_vec(&payload).expect("payload encodes"))
}

fn claude_write_payload(file_path: &str) -> std::io::Cursor<Vec<u8>> {
    let payload = json!({
        "session_id": "s1",
        "transcript_path": "/tmp/transcript.jsonl",
        "cwd": "/repo",
        "permission_mode": "default",
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {
            "file_path": file_path,
            "content": "content omitted"
        },
        "tool_use_id": "toolu_2"
    });
    std::io::Cursor::new(serde_json::to_vec(&payload).expect("payload encodes"))
}
