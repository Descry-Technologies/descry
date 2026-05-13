use std::fs;

use descry_cli::{run_with_io, Cli, Commands};
use serde_json::Value;

#[test]
fn init_dry_run_reports_paths_without_writing() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    fs::write(tempdir.path().join("Cargo.toml"), "[workspace]\n").expect("cargo toml writes");
    let mut input = [].as_slice();
    let mut output = Vec::new();
    let mut error = Vec::new();

    run_with_io(
        Cli {
            command: Commands::Init {
                project: tempdir.path().to_path_buf(),
                dry_run: true,
            },
        },
        &mut input,
        &mut output,
        &mut error,
    )
    .expect("init dry-run succeeds");

    assert!(error.is_empty());
    assert!(!tempdir.path().join(".descry/project.yml").exists());
    let json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(json["dry_run"], true);
    assert!(json["project_policy"]
        .as_str()
        .expect("path is string")
        .ends_with(".descry/project.yml"));
}

#[test]
fn init_writes_project_config_state_memory_and_index() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    fs::write(tempdir.path().join("Cargo.toml"), "[workspace]\n").expect("cargo toml writes");
    fs::create_dir_all(tempdir.path().join("src")).expect("src dir creates");
    fs::write(tempdir.path().join("src/lib.rs"), "").expect("source writes");
    let mut input = [].as_slice();
    let mut output = Vec::new();
    let mut error = Vec::new();

    run_with_io(
        Cli {
            command: Commands::Init {
                project: tempdir.path().to_path_buf(),
                dry_run: false,
            },
        },
        &mut input,
        &mut output,
        &mut error,
    )
    .expect("init succeeds");

    assert!(error.is_empty());
    let project_policy = tempdir.path().join(".descry/project.yml");
    let index_path = tempdir.path().join(".descry/state/project-index.json");
    assert!(project_policy.exists());
    assert!(tempdir.path().join(".descry/memory").is_dir());
    assert!(index_path.exists());
    let policy = fs::read_to_string(project_policy).expect("policy reads");
    assert!(policy.contains("id: secrets"));
    let index = descry_context::read_project_index(&index_path).expect("index reads");
    assert!(index.languages.contains(&String::from("rust")));
}
