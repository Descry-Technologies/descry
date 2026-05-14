use std::fs;

use descry_cli::{run_with_io, Cli, Commands};
use serde_json::Value;

#[test]
fn doctor_passes_with_policy_hook_and_missing_audit() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let settings = tempdir.path().join("claude-settings.json");
    let codex_hooks = tempdir.path().join("codex-hooks.json");
    let codex_config = tempdir.path().join("codex-config.toml");
    let cursor_hooks = tempdir.path().join("cursor-hooks.json");
    write_claude_settings_with_hook(&settings);
    write_codex_hooks(&codex_hooks);
    fs::write(&codex_config, "[features]\ncodex_hooks = true\n").expect("config writes");
    write_cursor_hooks(&cursor_hooks);

    let (exit_code, output) = run_doctor(&settings, &codex_hooks, &codex_config, &cursor_hooks);

    assert_eq!(exit_code, 0);
    let json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(json["ok"], true);
    assert!(json["checks"]
        .as_array()
        .expect("checks is array")
        .iter()
        .any(|check| check["id"] == "demo.off_task_edit" && check["ok"] == true));
}

#[test]
fn doctor_fails_when_claude_hook_is_missing() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let settings = tempdir.path().join("claude-settings.json");
    let codex_hooks = tempdir.path().join("codex-hooks.json");
    let codex_config = tempdir.path().join("codex-config.toml");
    let cursor_hooks = tempdir.path().join("cursor-hooks.json");
    fs::write(&settings, r#"{"hooks":{"PreToolUse":[]}}"#).expect("settings writes");
    write_codex_hooks(&codex_hooks);
    fs::write(&codex_config, "[features]\ncodex_hooks = true\n").expect("config writes");
    write_cursor_hooks(&cursor_hooks);

    let (exit_code, output) = run_doctor(&settings, &codex_hooks, &codex_config, &cursor_hooks);

    assert_eq!(exit_code, 1);
    let json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(json["ok"], false);
    assert!(json["checks"]
        .as_array()
        .expect("checks is array")
        .iter()
        .any(|check| check["id"] == "hook.claude.pretooluse" && check["ok"] == false));
}

#[test]
fn doctor_fails_when_codex_or_cursor_hook_is_missing() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let settings = tempdir.path().join("claude-settings.json");
    let codex_hooks = tempdir.path().join("codex-hooks.json");
    let codex_config = tempdir.path().join("codex-config.toml");
    let cursor_hooks = tempdir.path().join("cursor-hooks.json");
    write_claude_settings_with_hook(&settings);
    fs::write(&codex_hooks, r#"{"hooks":{"PreToolUse":[]}}"#).expect("hooks writes");
    fs::write(&codex_config, "[features]\ncodex_hooks = false\n").expect("config writes");
    fs::write(
        &cursor_hooks,
        r#"{"version":1,"hooks":{"beforeShellExecution":[]}}"#,
    )
    .expect("hooks writes");

    let (exit_code, output) = run_doctor(&settings, &codex_hooks, &codex_config, &cursor_hooks);

    assert_eq!(exit_code, 1);
    let json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(json["ok"], false);
    let checks = json["checks"].as_array().expect("checks is array");
    assert!(checks
        .iter()
        .any(|check| check["id"] == "hook.codex.pretooluse" && check["ok"] == false));
    assert!(checks
        .iter()
        .any(|check| check["id"] == "hook.codex.feature_flag" && check["ok"] == false));
    assert!(checks
        .iter()
        .any(|check| check["id"] == "hook.cursor.before_shell_execution" && check["ok"] == false));
    assert!(checks
        .iter()
        .any(|check| check["id"] == "hook.cursor.before_mcp_execution" && check["ok"] == false));
}

#[test]
fn doctor_uses_project_local_paths() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let project = tempdir.path().join("repo");
    fs::create_dir_all(project.join(".claude")).expect("claude dir creates");
    fs::create_dir_all(project.join(".codex")).expect("codex dir creates");
    fs::create_dir_all(project.join(".cursor")).expect("cursor dir creates");
    fs::create_dir_all(project.join(".descry/state")).expect("state dir creates");
    fs::create_dir_all(project.join(".descry/memory")).expect("memory dir creates");
    fs::write(
        project.join(".descry/project.yml"),
        r#"
project:
  name: repo
assets: []
actions: {}
"#,
    )
    .expect("project policy writes");
    descry_context::write_project_index(
        &descry_context::ProjectIndex {
            repo_root: project.clone(),
            repo_name: String::from("repo"),
            branch: Some(String::from("main")),
            languages: vec![String::from("rust")],
            frameworks: vec![String::from("cargo")],
            source_paths: Vec::new(),
            test_paths: Vec::new(),
            infra_paths: Vec::new(),
            config_paths: Vec::new(),
            secret_paths: Vec::new(),
            deploy_paths: Vec::new(),
        },
        &project.join(".descry/state/project-index.json"),
    )
    .expect("project index writes");
    write_claude_settings_with_hook(&project.join(".claude/settings.json"));
    write_codex_hooks(&project.join(".codex/hooks.json"));
    fs::write(
        project.join(".codex/config.toml"),
        "[features]\ncodex_hooks = true\n",
    )
    .expect("config writes");
    write_cursor_hooks(&project.join(".cursor/hooks.json"));

    let (exit_code, output) = run_project_doctor(&project);

    assert_eq!(exit_code, 0);
    let json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(json["ok"], true);
    let checks = json["checks"].as_array().expect("checks is array");
    assert!(checks
        .iter()
        .any(|check| check["id"] == "project.config" && check["ok"] == true));
    assert!(checks
        .iter()
        .any(|check| check["id"] == "project.index" && check["ok"] == true));
}

#[test]
fn doctor_fix_initializes_project_and_installs_hooks() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let project = tempdir.path().join("repo");
    fs::create_dir_all(project.join("src")).expect("project creates");
    fs::write(
        project.join("Cargo.toml"),
        "[package]\nname = \"repo\"\nversion = \"0.1.0\"\n",
    )
    .expect("manifest writes");
    fs::write(project.join("src/lib.rs"), "").expect("source writes");

    let mut input = [].as_slice();
    let mut output = Vec::new();
    let mut error = Vec::new();
    let cli = Cli {
        command: Commands::Doctor {
            project: Some(project.clone()),
            fix: true,
            claude_settings: None,
            codex_hooks: None,
            codex_config: None,
            cursor_hooks: None,
            policy: workspace_root().join("policies/safe-defaults.yml"),
            audit: project.join(".descry/audit.log"),
            repo_id_hash: String::from("test-repo"),
        },
    };

    let exit_code = match run_with_io(cli, &mut input, &mut output, &mut error) {
        Ok(()) => 0,
        Err(error) => error.exit_code(),
    };

    assert_eq!(exit_code, 0);
    assert!(error.is_empty());
    let json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(json["ok"], true);
    assert!(project.join(".descry/project.yml").exists());
    assert!(project.join(".descry/state/project-index.json").exists());
    assert!(fs::read_to_string(project.join(".claude/settings.json"))
        .expect("claude settings reads")
        .contains("descry hook claude pretooluse"));
    assert!(fs::read_to_string(project.join(".codex/hooks.json"))
        .expect("codex hooks reads")
        .contains("descry hook codex pretooluse"));
    assert!(fs::read_to_string(project.join(".cursor/hooks.json"))
        .expect("cursor hooks reads")
        .contains("descry hook cursor before-mcp-execution"));
}

fn run_doctor(
    settings: &std::path::Path,
    codex_hooks: &std::path::Path,
    codex_config: &std::path::Path,
    cursor_hooks: &std::path::Path,
) -> (i32, Vec<u8>) {
    let mut input = [].as_slice();
    let mut output = Vec::new();
    let mut error = Vec::new();
    let cli = Cli {
        command: Commands::Doctor {
            project: None,
            fix: false,
            claude_settings: Some(settings.to_path_buf()),
            codex_hooks: Some(codex_hooks.to_path_buf()),
            codex_config: Some(codex_config.to_path_buf()),
            cursor_hooks: Some(cursor_hooks.to_path_buf()),
            policy: workspace_root().join("policies/safe-defaults.yml"),
            audit: settings
                .parent()
                .expect("settings has parent")
                .join("audit.log"),
            repo_id_hash: String::from("test-repo"),
        },
    };
    let exit_code = match run_with_io(cli, &mut input, &mut output, &mut error) {
        Ok(()) => 0,
        Err(error) => error.exit_code(),
    };
    assert!(error.is_empty());
    (exit_code, output)
}

fn run_project_doctor(project: &std::path::Path) -> (i32, Vec<u8>) {
    let mut input = [].as_slice();
    let mut output = Vec::new();
    let mut error = Vec::new();
    let cli = Cli {
        command: Commands::Doctor {
            project: Some(project.to_path_buf()),
            fix: false,
            claude_settings: None,
            codex_hooks: None,
            codex_config: None,
            cursor_hooks: None,
            policy: workspace_root().join("policies/safe-defaults.yml"),
            audit: project.join(".descry/audit.log"),
            repo_id_hash: String::from("test-repo"),
        },
    };
    let exit_code = match run_with_io(cli, &mut input, &mut output, &mut error) {
        Ok(()) => 0,
        Err(error) => error.exit_code(),
    };
    assert!(error.is_empty());
    (exit_code, output)
}

fn write_claude_settings_with_hook(settings: &std::path::Path) {
    fs::write(
        settings,
        r#"{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "descry hook claude pretooluse"
          }
        ]
      }
    ]
  }
}
"#,
    )
    .expect("settings writes");
}

fn write_codex_hooks(settings: &std::path::Path) {
    fs::write(
        settings,
        r#"{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "descry hook codex pretooluse"
          }
        ]
      }
    ]
  }
}
"#,
    )
    .expect("hooks writes");
}

fn write_cursor_hooks(settings: &std::path::Path) {
    fs::write(
        settings,
        r#"{
  "version": 1,
  "hooks": {
    "beforeShellExecution": [
      {
        "command": "descry hook cursor before-shell-execution"
      }
    ],
    "beforeMCPExecution": [
      {
        "command": "descry hook cursor before-mcp-execution"
      }
    ]
  }
}
"#,
    )
    .expect("hooks writes");
}

fn workspace_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate has workspace parent")
        .parent()
        .expect("crates dir has workspace parent")
        .to_path_buf()
}
