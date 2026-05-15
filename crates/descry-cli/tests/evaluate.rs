use descry_cli::{run_with_io, Cli, Commands};
use descry_core::{
    ActionClass, EvidenceRef, EvidenceSource, ScopeContract, ScopePermit, ScopePermitKind,
};
use serde_json::Value;

#[test]
fn evaluate_stdin_outputs_allow_decision() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let cli = Cli {
        command: evaluate_command(tempdir.path()),
    };
    let mut input = include_str!("../../descry-core/tests/fixtures/spec_example.json").as_bytes();
    let mut output = Vec::new();
    let mut error = Vec::new();

    run_with_io(cli, &mut input, &mut output, &mut error).expect("evaluate succeeds");

    assert!(error.is_empty());

    let json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(json["decision"], "allow");
}

#[test]
fn evaluate_stdin_blocks_rm_rf_home_fixture() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let cli = Cli {
        command: evaluate_command(tempdir.path()),
    };
    let mut input = include_str!("../../../fixtures/rm-rf-home.json").as_bytes();
    let mut output = Vec::new();
    let mut error = Vec::new();

    run_with_io(cli, &mut input, &mut output, &mut error).expect("evaluate succeeds");

    assert!(error.is_empty());

    let json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(json["decision"], "block");
}

#[test]
fn evaluate_stdin_blocks_force_push_main_after_branch() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let cli = Cli {
        command: evaluate_command(tempdir.path()),
    };
    let mut fixture: Value =
        serde_json::from_str(include_str!("../../../fixtures/force-push-main.json"))
            .expect("fixture is json");
    fixture["action"]["target"] = Value::String(String::from("git push origin main --force"));
    let body = serde_json::to_vec(&fixture).expect("fixture serializes");
    let mut input = body.as_slice();
    let mut output = Vec::new();
    let mut error = Vec::new();

    run_with_io(cli, &mut input, &mut output, &mut error).expect("evaluate succeeds");

    assert!(error.is_empty());

    let json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(json["decision"], "block");
}

#[test]
fn evaluate_stdin_blocks_secret_write_from_project_defaults() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let cli = Cli {
        command: evaluate_command(tempdir.path()),
    };
    let mut input = include_str!("../../../fixtures/secret-file-write.json").as_bytes();
    let mut output = Vec::new();
    let mut error = Vec::new();

    run_with_io(cli, &mut input, &mut output, &mut error).expect("evaluate succeeds");

    assert!(error.is_empty());

    let json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(json["decision"], "block");
    assert!(json["reason"]
        .as_str()
        .expect("reason is a string")
        .contains("asset: secrets"));
}

#[test]
fn evaluate_stdin_requires_approval_for_infra_write_from_project_defaults() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let cli = Cli {
        command: evaluate_command(tempdir.path()),
    };
    let mut input = include_str!("../../../fixtures/infra-file-write.json").as_bytes();
    let mut output = Vec::new();
    let mut error = Vec::new();

    run_with_io(cli, &mut input, &mut output, &mut error).expect("evaluate succeeds");

    assert!(error.is_empty());

    let json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(json["decision"], "require_approval");
    assert!(json["reason"]
        .as_str()
        .expect("reason is a string")
        .contains("asset: infra"));
}

#[test]
fn evaluate_stdin_allows_source_write_from_inferred_context() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let cli = Cli {
        command: evaluate_command(tempdir.path()),
    };
    let mut input = include_str!("../../../fixtures/inferred-source-file-write.json").as_bytes();
    let mut output = Vec::new();
    let mut error = Vec::new();

    run_with_io(cli, &mut input, &mut output, &mut error).expect("evaluate succeeds");

    assert!(error.is_empty());

    let json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(json["decision"], "allow");
    assert!(json["reason"]
        .as_str()
        .expect("reason is a string")
        .contains("matched task context score="));
}

#[test]
fn evaluate_stdin_uses_scope_contract_for_p1_semantic_firewall_demo() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    append_scope_contract(tempdir.path(), "src/auth/**");

    let mut source_fixture: Value =
        serde_json::from_str(include_str!("../../../fixtures/source-file-write.json"))
            .expect("fixture is json");
    source_fixture["intent"]["active_task"] = Value::Null;
    source_fixture["context"]["branch"] = Value::String(String::from("main"));
    source_fixture["context"]["recent_files"] = Value::Array(Vec::new());
    let source_output = evaluate_json(tempdir.path(), source_fixture);

    assert_eq!(source_output["decision"], "allow");
    assert!(source_output["reason"]
        .as_str()
        .expect("reason is a string")
        .contains("active scope contract"));

    let infra_output = evaluate_json(
        tempdir.path(),
        serde_json::from_str(include_str!("../../../fixtures/infra-file-write.json"))
            .expect("fixture is json"),
    );
    assert_eq!(infra_output["decision"], "require_approval");
    assert!(infra_output["reason"]
        .as_str()
        .expect("reason is a string")
        .contains("asset: infra"));

    let prod_delete_output = evaluate_json(
        tempdir.path(),
        serde_json::from_str(include_str!("../../../fixtures/railway-delete.json"))
            .expect("fixture is json"),
    );
    assert_eq!(prod_delete_output["decision"], "block");
}

#[test]
fn evaluate_stdin_uses_zero_config_asset_graph_for_railway_config() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let cli = Cli {
        command: evaluate_command(tempdir.path()),
    };
    let mut input = include_str!("../../../fixtures/railway-config-write.json").as_bytes();
    let mut output = Vec::new();
    let mut error = Vec::new();

    run_with_io(cli, &mut input, &mut output, &mut error).expect("evaluate succeeds");

    assert!(error.is_empty());
    let json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(json["decision"], "require_approval");
    assert!(json["reason"]
        .as_str()
        .expect("reason is a string")
        .contains("hosted-control-plane:railway"));
}

#[test]
fn evaluate_stdin_blocks_p3_hijack_prod_delete_with_provenance_trail() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let cli = Cli {
        command: evaluate_command(tempdir.path()),
    };
    let mut input = include_str!("../../../fixtures/p3-prod-delete-after-token-read.json").as_bytes();
    let mut output = Vec::new();
    let mut error = Vec::new();

    run_with_io(cli, &mut input, &mut output, &mut error).expect("evaluate succeeds");

    assert!(error.is_empty(), "stderr: {}", String::from_utf8_lossy(&error));
    let json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(
        json["decision"], "block",
        "p3 hijack: prod delete with tool_output provenance must block; got: {json}"
    );
    let reason = json["reason"].as_str().expect("reason is a string");
    assert!(
        reason.contains("drift"),
        "reason must mention drift; got: {reason}"
    );
    assert!(
        reason.contains("external tool output") || reason.contains("tool_output"),
        "reason must cite provenance; got: {reason}"
    );
}

#[test]
fn evaluate_stdin_uses_scanned_project_index_asset_graph_for_p2_demo() {
    let tempdir = tempfile::tempdir().expect("tempdir");

    // Write a real project file so the index scanner picks it up.
    std::fs::create_dir_all(tempdir.path().join("src")).expect("src dir");
    std::fs::write(tempdir.path().join("railway.toml"), "[deploy]\n").expect("railway.toml");
    std::fs::write(tempdir.path().join("src/main.rs"), "fn main() {}").expect("main.rs");

    // Build and write the project index so the engine can load it.
    let index = descry_context::build_project_index(tempdir.path()).expect("index builds");
    let index_path = tempdir.path().join(".descry/state/project-index.json");
    descry_context::write_project_index(&index, &index_path).expect("index writes");

    // Confirm the scanner picked up railway.toml as a hosted-control-plane node.
    assert!(
        index
            .asset_graph
            .iter()
            .any(|node| node.id == "hosted-control-plane:railway"),
        "scanner must detect railway.toml"
    );

    // Evaluate a write to railway.toml — expect require_approval from scanned index.
    let input_json = serde_json::json!({
        "actor": { "type": "agent", "name": "claude-code", "owner": "local", "trust_level": "local_dev_agent" },
        "action": { "type": "file.write", "verb": "modify", "target": "railway.toml", "diff_summary": "update service config" },
        "intent": { "active_task": "fix prod deploy", "source": "claude_pretooluse", "linked_issue": null },
        "asset": { "type": "code_file", "sensitivity": "low", "environment": "local" },
        "context": { "repo": "my-app", "branch": "main", "recent_files": [], "recent_approvals": [] },
        "blast_radius": { "reversible": true, "customer_impact": "none", "financial_impact": "none" }
    });
    let json = evaluate_json(tempdir.path(), input_json);
    assert_eq!(
        json["decision"], "require_approval",
        "scanned project index must drive require_approval for railway.toml write"
    );
    assert!(
        json["reason"]
            .as_str()
            .expect("reason is a string")
            .contains("hosted-control-plane:railway"),
        "reason must reference the scanned asset id"
    );
}

fn evaluate_json(root: &std::path::Path, body: Value) -> Value {
    let cli = Cli {
        command: evaluate_command(root),
    };
    let bytes = serde_json::to_vec(&body).expect("fixture serializes");
    let mut input = bytes.as_slice();
    let mut output = Vec::new();
    let mut error = Vec::new();

    run_with_io(cli, &mut input, &mut output, &mut error).expect("evaluate succeeds");

    assert!(error.is_empty());
    serde_json::from_slice(&output).expect("stdout is json")
}

fn append_scope_contract(root: &std::path::Path, pattern: &str) {
    let contract = ScopeContract::signed(
        "Fix auth session",
        vec![EvidenceRef::new(
            EvidenceSource::ActiveTask,
            "active-task",
            "Fix auth session",
        )],
        vec![ScopePermit::new(
            ScopePermitKind::Path,
            pattern,
            vec![ActionClass::FileWrite],
            "test scope",
        )],
        1,
        u64::MAX,
        0.8,
    )
    .expect("scope contract signs");
    descry_memory::append_scope_contract(
        &root.join(".descry/memory/scope-contracts.jsonl"),
        &contract,
    )
    .expect("scope contract appends");
}

fn evaluate_command(root: &std::path::Path) -> Commands {
    Commands::Evaluate {
        stdin: true,
        policy: workspace_root().join("policies/safe-defaults.yml"),
        project: root.join(".descry/project.yml"),
        project_root: root.to_path_buf(),
        context: root.join(".descry/context.md"),
        state: root.join(".descry/state"),
        project_index: root.join(".descry/state/project-index.json"),
        approvals: root.join(".descry/memory/approvals.jsonl"),
        behavior: root.join(".descry/memory/behavior.json"),
        audit: None,
        no_context: false,
        shadow: false,
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
