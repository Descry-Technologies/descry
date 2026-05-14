use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

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
fn hook_install_claude_uses_absolute_default_command() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let settings = tempdir.path().join(".claude/settings.json");
    let mut input = [].as_slice();
    let mut output = Vec::new();
    let mut error = Vec::new();

    run_with_io(
        Cli {
            command: Commands::Hook {
                action: HookAction::Install {
                    action: HookInstallAction::Claude {
                        project: None,
                        settings: Some(settings.clone()),
                        command: None,
                    },
                },
            },
        },
        &mut input,
        &mut output,
        &mut error,
    )
    .expect("install succeeds");

    assert!(error.is_empty());
    let settings_json: Value =
        serde_json::from_str(&fs::read_to_string(&settings).expect("settings reads"))
            .expect("settings is json");
    let command = settings_json["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        .as_str()
        .expect("command is string");
    assert_absolute_command(command, "hook claude pretooluse");
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
    write_ready_project(&project);
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

#[test]
fn hook_install_project_requires_init() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let project = tempdir.path().join("repo");
    fs::create_dir_all(&project).expect("project creates");
    let mut input = [].as_slice();
    let mut output = Vec::new();
    let mut error = Vec::new();

    let exit_code = match run_with_io(
        project_claude_cli(&project),
        &mut input,
        &mut output,
        &mut error,
    ) {
        Ok(()) => 0,
        Err(error) => error.exit_code(),
    };

    assert_eq!(exit_code, 2);
    assert!(error.is_empty());
    let output_json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(output_json["ok"], false);
    assert!(output_json["next"]
        .as_str()
        .expect("next is string")
        .contains("descry init --project"));
}

#[test]
fn hook_install_git_writes_pre_push_secret_scan() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    git(tempdir.path(), &["init"]);
    let mut input = [].as_slice();
    let mut output = Vec::new();
    let mut error = Vec::new();

    run_with_io(git_cli(tempdir.path()), &mut input, &mut output, &mut error)
        .expect("git hook install succeeds");

    assert!(error.is_empty());
    let output_json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(output_json["host"], "git");
    assert_eq!(output_json["hook"], "pre-push");
    assert_eq!(output_json["installed"], true);

    let hook = tempdir.path().join(".git/hooks/pre-push");
    let body = fs::read_to_string(&hook).expect("hook reads");
    assert!(body.contains("descry scan secrets --staged"));
    #[cfg(unix)]
    assert_ne!(
        fs::metadata(&hook)
            .expect("hook metadata")
            .permissions()
            .mode()
            & 0o111,
        0
    );
}

#[test]
fn hook_install_git_is_idempotent() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    git(tempdir.path(), &["init"]);

    run_git_install(tempdir.path()).expect("first install succeeds");
    let second = run_git_install(tempdir.path()).expect("second install succeeds");

    let output_json: Value = serde_json::from_slice(&second).expect("stdout is json");
    assert_eq!(output_json["installed"], false);

    let hook = fs::read_to_string(tempdir.path().join(".git/hooks/pre-push")).expect("hook reads");
    assert_eq!(hook.matches("descry scan secrets --staged").count(), 1);
}

#[test]
fn hook_install_git_resolves_worktree_git_path() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let main = tempdir.path().join("main");
    let linked = tempdir.path().join("linked");
    fs::create_dir_all(&main).expect("main creates");
    git(&main, &["init"]);
    git(&main, &["config", "user.email", "test@example.com"]);
    git(&main, &["config", "user.name", "Descry Test"]);
    fs::write(main.join("README.md"), "test\n").expect("readme writes");
    git(&main, &["add", "README.md"]);
    git(&main, &["commit", "-m", "initial"]);
    git(
        &main,
        &["worktree", "add", linked.to_str().expect("linked utf8")],
    );

    let output = run_git_install(&linked).expect("git hook install succeeds");
    let output_json: Value = serde_json::from_slice(&output).expect("stdout is json");
    let hook_path = output_json["path"].as_str().expect("path is string");
    assert!(Path::new(hook_path).exists());
    assert!(fs::read_to_string(hook_path)
        .expect("hook reads")
        .contains("descry scan secrets --staged"));
}

fn run_install(settings: &std::path::Path) -> Result<Vec<u8>, descry_cli::CliError> {
    let mut input = [].as_slice();
    let mut output = Vec::new();
    let mut error = Vec::new();
    run_with_io(cli(settings), &mut input, &mut output, &mut error)?;
    assert!(error.is_empty());
    Ok(output)
}

fn run_git_install(project: &std::path::Path) -> Result<Vec<u8>, descry_cli::CliError> {
    let mut input = [].as_slice();
    let mut output = Vec::new();
    let mut error = Vec::new();
    run_with_io(git_cli(project), &mut input, &mut output, &mut error)?;
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
                    command: Some(String::from("descry hook claude pretooluse")),
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
                    command: Some(String::from("descry hook codex pretooluse")),
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
                    command: Some(String::from("descry hook cursor before-shell-execution")),
                    mcp_command: Some(String::from("descry hook cursor before-mcp-execution")),
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
                    command: Some(String::from("descry hook claude pretooluse")),
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
                    command: Some(String::from("descry hook codex pretooluse")),
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
                    command: Some(String::from("descry hook cursor before-shell-execution")),
                    mcp_command: Some(String::from("descry hook cursor before-mcp-execution")),
                },
            },
        },
    }
}

fn git_cli(project: &std::path::Path) -> Cli {
    Cli {
        command: Commands::Hook {
            action: HookAction::Install {
                action: HookInstallAction::Git {
                    project: project.to_path_buf(),
                    hook: String::from("pre-push"),
                    command: Some(String::from("descry scan secrets --staged")),
                },
            },
        },
    }
}

fn write_ready_project(project: &Path) {
    fs::create_dir_all(project.join(".descry/state")).expect("state creates");
    fs::create_dir_all(project.join(".descry/memory")).expect("memory creates");
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
            repo_root: project.to_path_buf(),
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

fn git(cwd: &std::path::Path, args: &[&str]) {
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
