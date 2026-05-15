use std::fs;

use descry_cli::{run_with_io, Cli, Commands, ScopeAction};
use serde_json::Value;

#[test]
fn scope_build_writes_verified_contract_and_show_reads_it() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let project = tempdir.path().join("repo");
    write(project.join("Cargo.toml"), "[workspace]\n");
    write(project.join("src/auth/session.rs"), "");
    write(project.join("tests/auth/session_test.rs"), "");
    write(
        project.join(".github/CODEOWNERS"),
        "src/auth/** @auth-team\n",
    );
    write(project.join(".git/HEAD"), "ref: refs/heads/fix-session\n");
    write(
        project.join(".descry/context.md"),
        "# Descry Context\n\nActive task: Fix src/auth/session.rs\n",
    );
    let cache = project.join(".descry/memory/scope-contracts.jsonl");
    let index = project.join(".descry/state/project-index.json");

    let build_output = run_scope(ScopeAction::Build {
        project: project.clone(),
        context: project.join(".descry/context.md"),
        project_index: index.clone(),
        cache: cache.clone(),
        ttl_seconds: 300,
        created_at_epoch_seconds: Some(100),
    });
    let build_json: Value = serde_json::from_slice(&build_output).expect("stdout is json");

    assert_eq!(build_json["verified"], true);
    assert_eq!(
        build_json["contract"]["task_summary"],
        "Fix src/auth/session.rs"
    );
    assert_eq!(build_json["contract"]["expires_at_epoch_seconds"], 400);
    assert!(build_json["contract"]["permits"]
        .as_array()
        .expect("permits is array")
        .iter()
        .any(|permit| permit["pattern"] == "src/**"));
    assert!(build_json["contract"]["evidence"]
        .as_array()
        .expect("evidence is array")
        .iter()
        .any(|evidence| evidence["source"] == "active_task"));

    let show_output = run_scope(ScopeAction::Show {
        cache: cache.clone(),
        now_epoch_seconds: Some(150),
    });
    let show_json: Value = serde_json::from_slice(&show_output).expect("stdout is json");

    assert_eq!(show_json["count"], 1);
    assert_eq!(
        show_json["contracts"][0]["id"],
        build_json["contract"]["id"]
    );
}

#[test]
fn scope_build_is_deterministic_for_same_inputs() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let project = tempdir.path().join("repo");
    write(project.join("Cargo.toml"), "[workspace]\n");
    write(project.join("src/auth/session.rs"), "");
    write(project.join(".git/HEAD"), "ref: refs/heads/fix-session\n");
    write(
        project.join(".descry/context.md"),
        "# Descry Context\n\nActive task: Fix src/auth/session.rs\n",
    );

    let first = run_scope(ScopeAction::Build {
        project: project.clone(),
        context: project.join(".descry/context.md"),
        project_index: project.join(".descry/state/first-index.json"),
        cache: project.join(".descry/memory/first-scope-contracts.jsonl"),
        ttl_seconds: 300,
        created_at_epoch_seconds: Some(100),
    });
    let second = run_scope(ScopeAction::Build {
        project: project.clone(),
        context: project.join(".descry/context.md"),
        project_index: project.join(".descry/state/second-index.json"),
        cache: project.join(".descry/memory/second-scope-contracts.jsonl"),
        ttl_seconds: 300,
        created_at_epoch_seconds: Some(100),
    });
    let first_json: Value = serde_json::from_slice(&first).expect("first stdout is json");
    let second_json: Value = serde_json::from_slice(&second).expect("second stdout is json");

    assert_eq!(first_json["contract"]["id"], second_json["contract"]["id"]);
    assert_eq!(
        first_json["contract"]["signature"],
        second_json["contract"]["signature"]
    );
}

fn run_scope(action: ScopeAction) -> Vec<u8> {
    let mut input = [].as_slice();
    let mut output = Vec::new();
    let mut error = Vec::new();
    run_with_io(
        Cli {
            command: Commands::Scope { action },
        },
        &mut input,
        &mut output,
        &mut error,
    )
    .expect("scope command succeeds");

    assert!(error.is_empty());
    output
}

fn write(path: std::path::PathBuf, body: &str) {
    fs::create_dir_all(path.parent().expect("path has parent")).expect("parent creates");
    fs::write(path, body).expect("file writes");
}
