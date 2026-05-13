use descry_cli::{run_with_io, Cli, Commands};
use serde_json::Value;

#[test]
fn evaluate_stdin_outputs_allow_decision() {
    let cli = Cli {
        command: evaluate_command(),
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
    let cli = Cli {
        command: evaluate_command(),
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
    let cli = Cli {
        command: evaluate_command(),
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
    let cli = Cli {
        command: evaluate_command(),
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
    let cli = Cli {
        command: evaluate_command(),
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
    let cli = Cli {
        command: evaluate_command(),
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
        .contains("inferred task context"));
}

fn evaluate_command() -> Commands {
    Commands::Evaluate {
        stdin: true,
        policy: "policies/safe-defaults.yml".into(),
        project: ".descry/project.yml".into(),
        approvals: ".descry/memory/approvals.jsonl".into(),
        behavior: ".descry/memory/behavior.json".into(),
    }
}
