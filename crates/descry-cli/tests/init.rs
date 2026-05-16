use std::fs;
use std::path::Path;
use std::process::Command;

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
                json: true,
                project: tempdir.path().to_path_buf(),
                dry_run: true,
                all: false,
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
                json: true,
                project: tempdir.path().to_path_buf(),
                dry_run: false,
                all: false,
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

#[test]
fn init_all_initializes_project_and_installs_project_hooks() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    git(tempdir.path(), &["init"]);
    fs::write(tempdir.path().join("Cargo.toml"), "[workspace]\n").expect("cargo toml writes");
    fs::create_dir_all(tempdir.path().join("src")).expect("src dir creates");
    fs::write(tempdir.path().join("src/lib.rs"), "").expect("source writes");
    let mut input = [].as_slice();
    let mut output = Vec::new();
    let mut error = Vec::new();

    run_with_io(
        Cli {
            command: Commands::Init {
                json: true,
                project: tempdir.path().to_path_buf(),
                dry_run: false,
                all: true,
            },
        },
        &mut input,
        &mut output,
        &mut error,
    )
    .expect("init --all succeeds");

    assert!(error.is_empty());
    let json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(json["all"], true);
    assert_eq!(json["hooks"].as_array().expect("hooks is array").len(), 4);
    assert!(tempdir.path().join(".descry/project.yml").exists());
    assert!(tempdir
        .path()
        .join(".descry/state/project-index.json")
        .exists());

    let claude_settings = tempdir.path().join(".claude/settings.json");
    let claude_json: Value =
        serde_json::from_str(&fs::read_to_string(&claude_settings).expect("settings read"))
            .expect("settings is json");
    let command = claude_json["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        .as_str()
        .expect("command is string");
    assert_absolute_command(command, "hook claude pretooluse");

    let git_hook = tempdir.path().join(".git/hooks/pre-push");
    let hook_body = fs::read_to_string(git_hook).expect("git hook reads");
    assert!(hook_body.contains("# descry secret scan"));
    assert!(hook_body.contains("scan secrets --staged"));
}

fn assert_absolute_command(command: &str, suffix: &str) {
    let executable = command
        .split_whitespace()
        .next()
        .expect("command has executable");
    assert!(
        Path::new(executable).is_absolute(),
        "command is not absolute: {command}"
    );
    assert!(
        command.ends_with(suffix),
        "command {command:?} did not end with {suffix:?}"
    );
}

fn git(cwd: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("git runs");

    assert!(
        output.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
}
