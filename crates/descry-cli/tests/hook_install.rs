use std::fs;

use descry_cli::{run_with_io, Cli, Commands, HookAction, HookInstallAction};
use serde_json::Value;

#[test]
fn hook_install_claude_writes_pretooluse_command_hook() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let settings = tempdir.path().join(".claude/settings.json");
    let mut input = [].as_slice();
    let mut output = Vec::new();
    let mut error = Vec::new();

    run_with_io(cli(&settings), &mut input, &mut output, &mut error).expect("install succeeds");

    assert!(error.is_empty());
    let output_json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(output_json["installed"], true);
    let settings_json: Value =
        serde_json::from_str(&fs::read_to_string(&settings).expect("settings reads"))
            .expect("settings is json");
    assert_eq!(
        settings_json["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
        "descry hook claude pretooluse"
    );
}

#[test]
fn hook_install_claude_is_idempotent() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let settings = tempdir.path().join(".claude/settings.json");

    run_install(&settings).expect("first install succeeds");
    let second = run_install(&settings).expect("second install succeeds");

    let output_json: Value = serde_json::from_slice(&second).expect("stdout is json");
    assert_eq!(output_json["installed"], false);
    let settings_json: Value =
        serde_json::from_str(&fs::read_to_string(&settings).expect("settings reads"))
            .expect("settings is json");
    assert_eq!(
        settings_json["hooks"]["PreToolUse"]
            .as_array()
            .expect("pretooluse is array")
            .len(),
        1
    );
}

#[test]
fn hook_install_claude_preserves_existing_settings() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let settings = tempdir.path().join(".claude/settings.json");
    fs::create_dir_all(settings.parent().expect("settings has parent")).expect("parent creates");
    fs::write(
        &settings,
        r#"{
  "permissions": {
    "deny": ["Bash(rm -rf /)"]
  },
  "hooks": {
    "PostToolUse": []
  }
}
"#,
    )
    .expect("settings writes");

    run_install(&settings).expect("install succeeds");

    let settings_json: Value =
        serde_json::from_str(&fs::read_to_string(&settings).expect("settings reads"))
            .expect("settings is json");
    assert_eq!(settings_json["permissions"]["deny"][0], "Bash(rm -rf /)");
    assert!(settings_json["hooks"]["PostToolUse"].is_array());
    assert_eq!(
        settings_json["hooks"]["PreToolUse"][0]["hooks"][0]["type"],
        "command"
    );
}

#[test]
fn hook_install_codex_writes_pretooluse_hook_and_feature_flag() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let hooks = tempdir.path().join(".codex/hooks.json");
    let config = tempdir.path().join(".codex/config.toml");
    let mut input = [].as_slice();
    let mut output = Vec::new();
    let mut error = Vec::new();

    run_with_io(
        codex_cli(&hooks, &config),
        &mut input,
        &mut output,
        &mut error,
    )
    .expect("install succeeds");

    assert!(error.is_empty());
    let output_json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(output_json["installed"], true);
    assert_eq!(output_json["feature_enabled"], true);
    let hooks_json: Value = serde_json::from_str(&fs::read_to_string(&hooks).expect("hooks read"))
        .expect("hooks is json");
    assert_eq!(
        hooks_json["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
        "descry hook codex pretooluse"
    );
    assert!(fs::read_to_string(&config)
        .expect("config reads")
        .contains("[features]\ncodex_hooks = true"));
}

#[test]
fn hook_install_cursor_writes_before_shell_execution_hook() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let hooks = tempdir.path().join(".cursor/hooks.json");
    let mut input = [].as_slice();
    let mut output = Vec::new();
    let mut error = Vec::new();

    run_with_io(cursor_cli(&hooks), &mut input, &mut output, &mut error).expect("install succeeds");

    assert!(error.is_empty());
    let output_json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(output_json["installed"], true);
    assert_eq!(output_json["installed_shell"], true);
    assert_eq!(output_json["installed_mcp"], true);
    let hooks_json: Value = serde_json::from_str(&fs::read_to_string(&hooks).expect("hooks read"))
        .expect("hooks is json");
    assert_eq!(hooks_json["version"], 1);
    assert_eq!(
        hooks_json["hooks"]["beforeShellExecution"][0]["command"],
        "descry hook cursor before-shell-execution"
    );
    assert_eq!(
        hooks_json["hooks"]["beforeMCPExecution"][0]["command"],
        "descry hook cursor before-mcp-execution"
    );
}

#[test]
fn hook_install_uses_project_local_paths() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let project = tempdir.path().join("repo");
    let mut input = [].as_slice();
    let mut output = Vec::new();
    let mut error = Vec::new();

    run_with_io(
        project_claude_cli(&project),
        &mut input,
        &mut output,
        &mut error,
    )
    .expect("claude install succeeds");
    assert!(error.is_empty());
    let claude_settings = project.join(".claude/settings.json");
    let claude_json: Value =
        serde_json::from_str(&fs::read_to_string(&claude_settings).expect("settings read"))
            .expect("settings is json");
    assert_eq!(
        claude_json["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
        "descry hook claude pretooluse"
    );

    input = [].as_slice();
    output.clear();
    run_with_io(
        project_codex_cli(&project),
        &mut input,
        &mut output,
        &mut error,
    )
    .expect("codex install succeeds");
    assert!(error.is_empty());
    let codex_hooks = project.join(".codex/hooks.json");
    let codex_json: Value =
        serde_json::from_str(&fs::read_to_string(&codex_hooks).expect("hooks read"))
            .expect("hooks is json");
    assert_eq!(
        codex_json["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
        "descry hook codex pretooluse"
    );
    assert!(fs::read_to_string(project.join(".codex/config.toml"))
        .expect("config reads")
        .contains("[features]\ncodex_hooks = true"));

    input = [].as_slice();
    output.clear();
    run_with_io(
        project_cursor_cli(&project),
        &mut input,
        &mut output,
        &mut error,
    )
    .expect("install succeeds");

    assert!(error.is_empty());
    let hooks = project.join(".cursor/hooks.json");
    let hooks_json: Value = serde_json::from_str(&fs::read_to_string(&hooks).expect("hooks read"))
        .expect("hooks is json");
    assert_eq!(
        hooks_json["hooks"]["beforeShellExecution"][0]["command"],
        "descry hook cursor before-shell-execution"
    );
    assert_eq!(
        hooks_json["hooks"]["beforeMCPExecution"][0]["command"],
        "descry hook cursor before-mcp-execution"
    );
}

fn run_install(settings: &std::path::Path) -> Result<Vec<u8>, descry_cli::CliError> {
    let mut input = [].as_slice();
    let mut output = Vec::new();
    let mut error = Vec::new();
    run_with_io(cli(settings), &mut input, &mut output, &mut error)?;
    assert!(error.is_empty());
    Ok(output)
}

fn cli(settings: &std::path::Path) -> Cli {
    Cli {
        command: Commands::Hook {
            action: HookAction::Install {
                action: HookInstallAction::Claude {
                    project: None,
                    settings: Some(settings.to_path_buf()),
                    command: String::from("descry hook claude pretooluse"),
                },
            },
        },
    }
}

fn codex_cli(hooks: &std::path::Path, config: &std::path::Path) -> Cli {
    Cli {
        command: Commands::Hook {
            action: HookAction::Install {
                action: HookInstallAction::Codex {
                    project: None,
                    hooks: Some(hooks.to_path_buf()),
                    config: Some(config.to_path_buf()),
                    command: String::from("descry hook codex pretooluse"),
                },
            },
        },
    }
}

fn cursor_cli(hooks: &std::path::Path) -> Cli {
    Cli {
        command: Commands::Hook {
            action: HookAction::Install {
                action: HookInstallAction::Cursor {
                    project: None,
                    hooks: Some(hooks.to_path_buf()),
                    command: String::from("descry hook cursor before-shell-execution"),
                    mcp_command: String::from("descry hook cursor before-mcp-execution"),
                },
            },
        },
    }
}

fn project_claude_cli(project: &std::path::Path) -> Cli {
    Cli {
        command: Commands::Hook {
            action: HookAction::Install {
                action: HookInstallAction::Claude {
                    project: Some(project.to_path_buf()),
                    settings: None,
                    command: String::from("descry hook claude pretooluse"),
                },
            },
        },
    }
}

fn project_codex_cli(project: &std::path::Path) -> Cli {
    Cli {
        command: Commands::Hook {
            action: HookAction::Install {
                action: HookInstallAction::Codex {
                    project: Some(project.to_path_buf()),
                    hooks: None,
                    config: None,
                    command: String::from("descry hook codex pretooluse"),
                },
            },
        },
    }
}

fn project_cursor_cli(project: &std::path::Path) -> Cli {
    Cli {
        command: Commands::Hook {
            action: HookAction::Install {
                action: HookInstallAction::Cursor {
                    project: Some(project.to_path_buf()),
                    hooks: None,
                    command: String::from("descry hook cursor before-shell-execution"),
                    mcp_command: String::from("descry hook cursor before-mcp-execution"),
                },
            },
        },
    }
}
