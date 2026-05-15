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
