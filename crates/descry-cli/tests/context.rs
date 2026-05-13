use std::fs;

use descry_cli::{run_with_io, Cli, Commands, ContextAction};
use serde_json::Value;

#[test]
fn context_build_writes_project_index_and_show_reads_it() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let project = tempdir.path().join("repo");
    write(project.join("Cargo.toml"), "[workspace]\n");
    write(project.join("crates/app/src/lib.rs"), "");
    write(project.join(".github/workflows/deploy.yml"), "");
    write(project.join(".env.production"), "");
    write(project.join(".git/HEAD"), "ref: refs/heads/context-index\n");
    let index_path = project.join(".descry/state/project-index.json");

    let mut input = [].as_slice();
    let mut build_output = Vec::new();
    let mut build_error = Vec::new();
    run_with_io(
        Cli {
            command: Commands::Context {
                action: ContextAction::Build {
                    project: project.clone(),
                    output_path: index_path.clone(),
                },
            },
        },
        &mut input,
        &mut build_output,
        &mut build_error,
    )
    .expect("context build succeeds");

    assert!(build_error.is_empty());
    assert!(index_path.exists());

    let mut input = [].as_slice();
    let mut show_output = Vec::new();
    let mut show_error = Vec::new();
    run_with_io(
        Cli {
            command: Commands::Context {
                action: ContextAction::Show { path: index_path },
            },
        },
        &mut input,
        &mut show_output,
        &mut show_error,
    )
    .expect("context show succeeds");

    assert!(show_error.is_empty());
    let json: Value = serde_json::from_slice(&show_output).expect("stdout is json");
    assert_eq!(json["branch"], "context-index");
    assert_eq!(json["repo_name"], "repo");
    assert!(json["languages"]
        .as_array()
        .expect("languages is array")
        .contains(&Value::String(String::from("rust"))));
    assert!(json["secret_paths"]
        .as_array()
        .expect("secret paths is array")
        .contains(&Value::String(String::from(".env.production"))));
}

fn write(path: std::path::PathBuf, body: &str) {
    fs::create_dir_all(path.parent().expect("path has parent")).expect("parent creates");
    fs::write(path, body).expect("file writes");
}
