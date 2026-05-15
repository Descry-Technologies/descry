use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use descry_audit::VerifyOutcome;
use serde_json::{json, Value};

use crate::commands::hook::{
    codex_hooks_feature_enabled, contains_command_hook, contains_cursor_command_hook,
    default_claude_settings_path, default_codex_config_path, default_codex_hooks_path,
    default_cursor_hooks_path, git_hook_path, project_claude_settings_path,
    project_codex_config_path, project_codex_hooks_path, project_cursor_hooks_path,
};
use crate::commands::policy_source::load_policy;
use crate::{CliError, DemoAction, DoctorAgent, HookInstallAction, Result};

const CLAUDE_HOOK_COMMAND: &str = "hook claude pretooluse";
const CODEX_HOOK_COMMAND: &str = "hook codex pretooluse";
const CURSOR_SHELL_HOOK_COMMAND: &str = "hook cursor before-shell-execution";
const CURSOR_MCP_HOOK_COMMAND: &str = "hook cursor before-mcp-execution";
const GIT_HOOK_MARKER: &str = "# descry secret scan";

pub struct DoctorConfig {
    pub project: Option<PathBuf>,
    pub fix: bool,
    pub agent: DoctorAgent,
    pub claude_settings: Option<PathBuf>,
    pub codex_hooks: Option<PathBuf>,
    pub codex_config: Option<PathBuf>,
    pub cursor_hooks: Option<PathBuf>,
    pub policy: PathBuf,
    pub audit: PathBuf,
    pub repo_id_hash: String,
}

pub fn run(config: DoctorConfig, output: &mut dyn Write) -> Result<()> {
    let repair_checks = if config.fix {
        apply_fixes(&config)
    } else {
        Vec::new()
    };

    let settings_path = match config.claude_settings {
        Some(path) => path,
        None => match config.project.as_deref() {
            Some(project) => project_claude_settings_path(project),
            None => default_claude_settings_path()?,
        },
    };
    let codex_hooks_path = match config.codex_hooks {
        Some(path) => path,
        None => match config.project.as_deref() {
            Some(project) => project_codex_hooks_path(project),
            None => default_codex_hooks_path()?,
        },
    };
    let codex_config_path = match config.codex_config {
        Some(path) => path,
        None => match config.project.as_deref() {
            Some(project) => project_codex_config_path(project),
            None => default_codex_config_path()?,
        },
    };
    let cursor_hooks_path = match config.cursor_hooks {
        Some(path) => path,
        None => match config.project.as_deref() {
            Some(project) => project_cursor_hooks_path(project),
            None => default_cursor_hooks_path()?,
        },
    };
    let mut checks = Vec::new();
    checks.extend(repair_checks);
    if let Some(project) = config.project.as_deref() {
        if config.agent != DoctorAgent::Git {
            checks.push(check_project_config(&project.join(".descry/project.yml")));
            checks.push(check_project_index(
                &project.join(".descry/state/project-index.json"),
            ));
        }
    }
    if config.agent == DoctorAgent::All {
        checks.push(check_policy(&config.policy));
    }
    if matches!(config.agent, DoctorAgent::Claude | DoctorAgent::All) {
        checks.push(check_claude_hook(&settings_path));
    }
    if matches!(config.agent, DoctorAgent::Codex | DoctorAgent::All) {
        checks.push(check_codex_hook(&codex_hooks_path));
        checks.push(check_codex_feature(&codex_config_path));
    }
    if matches!(config.agent, DoctorAgent::Cursor | DoctorAgent::All) {
        checks.push(check_cursor_shell_hook(&cursor_hooks_path));
        checks.push(check_cursor_mcp_hook(&cursor_hooks_path));
    }
    if matches!(config.agent, DoctorAgent::Git | DoctorAgent::All) {
        if let Some(project) = config.project.as_deref() {
            checks.push(check_git_hook(project));
        } else if config.agent == DoctorAgent::Git {
            checks.push(DoctorCheck {
                id: "hook.git.pre_push",
                ok: false,
                detail: String::from("pass --project to check the git pre-push hook"),
            });
        }
    }
    if config.agent == DoctorAgent::All {
        checks.push(check_audit(&config.audit, &config.repo_id_hash));
        checks.extend(check_launch_demos(&config.policy));
    }
    let ok = checks.iter().all(|check| check.ok);
    let checks_json: Vec<Value> = checks
        .into_iter()
        .map(|check| {
            json!({
                "id": check.id,
                "ok": check.ok,
                "detail": check.detail
            })
        })
        .collect();

    writeln!(
        output,
        "{}",
        json!({
            "ok": ok,
            "checks": checks_json
        })
    )?;

    if ok {
        Ok(())
    } else {
        Err(CliError::new("", 1))
    }
}

fn apply_fixes(config: &DoctorConfig) -> Vec<DoctorCheck> {
    let mut checks = Vec::new();

    if let Some(project) = config.project.as_ref() {
        if config.agent != DoctorAgent::Git {
            let mut sink = Vec::new();
            checks.push(repair_check(
                "repair.init",
                crate::commands::init::run(
                    crate::commands::init::InitConfig {
                        project: project.clone(),
                        dry_run: false,
                        install_hooks: false,
                    },
                    &mut sink,
                ),
                "initialized project policy, state, memory, and index",
            ));
        }
    }

    let settings = config.claude_settings.clone();
    let codex_hooks = config.codex_hooks.clone();
    let codex_config = config.codex_config.clone();
    let cursor_hooks = config.cursor_hooks.clone();
    let project = config.project.clone();

    if matches!(config.agent, DoctorAgent::Claude | DoctorAgent::All) {
        checks.push(repair_check(
            "repair.hook.claude",
            install_with_sink(HookInstallAction::Claude {
                project: project.clone(),
                settings,
                command: None,
            }),
            "installed Claude PreToolUse hook",
        ));
    }
    if matches!(config.agent, DoctorAgent::Codex | DoctorAgent::All) {
        checks.push(repair_check(
            "repair.hook.codex",
            install_with_sink(HookInstallAction::Codex {
                project: project.clone(),
                hooks: codex_hooks,
                config: codex_config,
                command: None,
            }),
            "installed Codex PreToolUse hook and feature flag",
        ));
    }
    if matches!(config.agent, DoctorAgent::Cursor | DoctorAgent::All) {
        checks.push(repair_check(
            "repair.hook.cursor",
            install_with_sink(HookInstallAction::Cursor {
                project: project.clone(),
                hooks: cursor_hooks,
                command: None,
                mcp_command: None,
            }),
            "installed Cursor shell and MCP hooks",
        ));
    }
    if matches!(config.agent, DoctorAgent::Git | DoctorAgent::All) {
        let result = match project {
            Some(project) => install_with_sink(HookInstallAction::Git {
                project,
                hook: String::from("pre-push"),
                command: None,
            }),
            None => Err(CliError::new("pass --project to install the git hook", 2)),
        };
        checks.push(repair_check(
            "repair.hook.git",
            result,
            "installed Git pre-push hook",
        ));
    }

    checks
}

fn install_with_sink(action: HookInstallAction) -> Result<()> {
    let mut sink = Vec::new();
    crate::commands::hook::run_install(action, &mut sink)
}

fn repair_check(id: &'static str, result: Result<()>, success: &str) -> DoctorCheck {
    match result {
        Ok(()) => DoctorCheck {
            id,
            ok: true,
            detail: success.to_string(),
        },
        Err(error) => DoctorCheck {
            id,
            ok: false,
            detail: error.to_string(),
        },
    }
}

fn check_project_config(project_config_path: &Path) -> DoctorCheck {
    match crate::commands::evaluate::load_project_policy(project_config_path) {
        Ok(_) if project_config_path.exists() => DoctorCheck {
            id: "project.config",
            ok: true,
            detail: format!("loaded {}", project_config_path.display()),
        },
        Ok(_) => DoctorCheck {
            id: "project.config",
            ok: false,
            detail: format!("missing {}", project_config_path.display()),
        },
        Err(error) => DoctorCheck {
            id: "project.config",
            ok: false,
            detail: error.to_string(),
        },
    }
}

fn check_project_index(index_path: &Path) -> DoctorCheck {
    match descry_context::read_project_index(index_path) {
        Ok(index) => DoctorCheck {
            id: "project.index",
            ok: true,
            detail: format!("loaded {} for {}", index_path.display(), index.repo_name),
        },
        Err(error) => DoctorCheck {
            id: "project.index",
            ok: false,
            detail: error.to_string(),
        },
    }
}

struct DoctorCheck {
    id: &'static str,
    ok: bool,
    detail: String,
}

fn check_policy(policy_path: &Path) -> DoctorCheck {
    match load_policy(policy_path) {
        Ok(loaded) => DoctorCheck {
            id: "policy.safe_defaults",
            ok: true,
            detail: loaded.source.detail(),
        },
        Err(error) => DoctorCheck {
            id: "policy.safe_defaults",
            ok: false,
            detail: error.to_string(),
        },
    }
}

fn check_claude_hook(settings_path: &Path) -> DoctorCheck {
    match read_json(settings_path) {
        Ok(settings) if settings_has_claude_hook(&settings) => DoctorCheck {
            id: "hook.claude.pretooluse",
            ok: true,
            detail: format!("found {CLAUDE_HOOK_COMMAND} in {}", settings_path.display()),
        },
        Ok(_) => DoctorCheck {
            id: "hook.claude.pretooluse",
            ok: false,
            detail: format!(
                "missing {CLAUDE_HOOK_COMMAND} in {}",
                settings_path.display()
            ),
        },
        Err(error) => DoctorCheck {
            id: "hook.claude.pretooluse",
            ok: false,
            detail: error,
        },
    }
}

fn check_codex_hook(hooks_path: &Path) -> DoctorCheck {
    if !hooks_path.exists() {
        return DoctorCheck {
            id: "hook.codex.pretooluse",
            ok: true,
            detail: String::from("codex not installed, skipping"),
        };
    }
    match read_json(hooks_path) {
        Ok(settings) if settings_has_codex_hook(&settings) => DoctorCheck {
            id: "hook.codex.pretooluse",
            ok: true,
            detail: format!("found {CODEX_HOOK_COMMAND} in {}", hooks_path.display()),
        },
        Ok(_) => DoctorCheck {
            id: "hook.codex.pretooluse",
            ok: false,
            detail: format!("missing {CODEX_HOOK_COMMAND} in {}", hooks_path.display()),
        },
        Err(error) => DoctorCheck {
            id: "hook.codex.pretooluse",
            ok: false,
            detail: error,
        },
    }
}

fn check_codex_feature(config_path: &Path) -> DoctorCheck {
    if !config_path.exists() {
        return DoctorCheck {
            id: "hook.codex.feature_flag",
            ok: true,
            detail: String::from("codex not installed, skipping"),
        };
    }
    match codex_hooks_feature_enabled(config_path) {
        Ok(true) => DoctorCheck {
            id: "hook.codex.feature_flag",
            ok: true,
            detail: format!("codex_hooks enabled in {}", config_path.display()),
        },
        Ok(false) => DoctorCheck {
            id: "hook.codex.feature_flag",
            ok: false,
            detail: format!("missing codex_hooks feature in {}", config_path.display()),
        },
        Err(error) => DoctorCheck {
            id: "hook.codex.feature_flag",
            ok: false,
            detail: error.to_string(),
        },
    }
}

fn check_cursor_shell_hook(hooks_path: &Path) -> DoctorCheck {
    if !hooks_path.exists() {
        return DoctorCheck {
            id: "hook.cursor.before_shell_execution",
            ok: true,
            detail: String::from("cursor not installed, skipping"),
        };
    }
    match read_json(hooks_path) {
        Ok(settings) if settings_has_cursor_shell_hook(&settings) => DoctorCheck {
            id: "hook.cursor.before_shell_execution",
            ok: true,
            detail: format!(
                "found {CURSOR_SHELL_HOOK_COMMAND} in {}",
                hooks_path.display()
            ),
        },
        Ok(_) => DoctorCheck {
            id: "hook.cursor.before_shell_execution",
            ok: false,
            detail: format!(
                "missing {CURSOR_SHELL_HOOK_COMMAND} in {}",
                hooks_path.display()
            ),
        },
        Err(error) => DoctorCheck {
            id: "hook.cursor.before_shell_execution",
            ok: false,
            detail: error,
        },
    }
}

fn check_cursor_mcp_hook(hooks_path: &Path) -> DoctorCheck {
    if !hooks_path.exists() {
        return DoctorCheck {
            id: "hook.cursor.before_mcp_execution",
            ok: true,
            detail: String::from("cursor not installed, skipping"),
        };
    }
    match read_json(hooks_path) {
        Ok(settings) if settings_has_cursor_mcp_hook(&settings) => DoctorCheck {
            id: "hook.cursor.before_mcp_execution",
            ok: true,
            detail: format!(
                "found {CURSOR_MCP_HOOK_COMMAND} in {}",
                hooks_path.display()
            ),
        },
        Ok(_) => DoctorCheck {
            id: "hook.cursor.before_mcp_execution",
            ok: false,
            detail: format!(
                "missing {CURSOR_MCP_HOOK_COMMAND} in {}",
                hooks_path.display()
            ),
        },
        Err(error) => DoctorCheck {
            id: "hook.cursor.before_mcp_execution",
            ok: false,
            detail: error,
        },
    }
}

fn check_git_hook(project: &Path) -> DoctorCheck {
    match git_hook_path(project, "pre-push").and_then(|hook_path| {
        fs::read_to_string(&hook_path)
            .map(|body| (hook_path, body))
            .map_err(CliError::from)
    }) {
        Ok((hook_path, body)) if body.contains(GIT_HOOK_MARKER) => DoctorCheck {
            id: "hook.git.pre_push",
            ok: true,
            detail: format!("found Descry pre-push hook in {}", hook_path.display()),
        },
        Ok((hook_path, _)) => DoctorCheck {
            id: "hook.git.pre_push",
            ok: false,
            detail: format!("missing Descry pre-push hook in {}", hook_path.display()),
        },
        Err(error) => DoctorCheck {
            id: "hook.git.pre_push",
            ok: false,
            detail: error.to_string(),
        },
    }
}

fn read_json(path: &Path) -> std::result::Result<Value, String> {
    fs::read_to_string(path)
        .map_err(|error| error.to_string())
        .and_then(|body| serde_json::from_str::<Value>(&body).map_err(|error| error.to_string()))
}

fn check_audit(audit_path: &Path, repo_id_hash: &str) -> DoctorCheck {
    if !audit_path.exists() {
        return DoctorCheck {
            id: "audit.verify",
            ok: true,
            detail: format!("{} not present yet", audit_path.display()),
        };
    }

    match descry_audit::verify_file(audit_path, repo_id_hash) {
        VerifyOutcome::Ok { records } => DoctorCheck {
            id: "audit.verify",
            ok: true,
            detail: format!("verified {records} records"),
        },
        VerifyOutcome::Broken { at_seq, reason } => DoctorCheck {
            id: "audit.verify",
            ok: false,
            detail: format!("broken at seq {at_seq}: {reason}"),
        },
    }
}

fn check_launch_demos(policy_path: &Path) -> Vec<DoctorCheck> {
    [
        (
            "demo.in_task_edit",
            DemoAction::InTaskEdit {
                policy: policy_path.to_path_buf(),
                json: false,
            },
        ),
        (
            "demo.off_task_edit",
            DemoAction::OffTaskEdit {
                policy: policy_path.to_path_buf(),
                json: false,
            },
        ),
        (
            "demo.secret_access",
            DemoAction::SecretAccess {
                policy: policy_path.to_path_buf(),
                json: false,
            },
        ),
        (
            "demo.rm_rf",
            DemoAction::RmRf {
                policy: policy_path.to_path_buf(),
                json: false,
            },
        ),
        (
            "demo.mcp_poison",
            DemoAction::McpPoison {
                policy: policy_path.to_path_buf(),
                json: false,
            },
        ),
        (
            "demo.prod_delete",
            DemoAction::ProdDelete {
                policy: policy_path.to_path_buf(),
                json: false,
            },
        ),
        (
            "demo.pocketos",
            DemoAction::Pocketos {
                policy: policy_path.to_path_buf(),
                json: false,
            },
        ),
    ]
    .into_iter()
    .map(|(id, action)| check_launch_demo(id, action))
    .collect()
}

fn check_launch_demo(id: &'static str, action: DemoAction) -> DoctorCheck {
    let mut output = Vec::new();
    match crate::commands::demo::run(action, &mut output) {
        Ok(()) => DoctorCheck {
            id,
            ok: true,
            detail: String::from("demo passed"),
        },
        Err(error) => DoctorCheck {
            id,
            ok: false,
            detail: error.to_string(),
        },
    }
}

fn settings_has_claude_hook(settings: &Value) -> bool {
    settings_has_nested_event_command_hook(settings, "PreToolUse", CLAUDE_HOOK_COMMAND)
}

fn settings_has_codex_hook(settings: &Value) -> bool {
    settings_has_nested_event_command_hook(settings, "PreToolUse", CODEX_HOOK_COMMAND)
}

fn settings_has_nested_event_command_hook(
    settings: &Value,
    event_name: &str,
    command: &str,
) -> bool {
    settings
        .get("hooks")
        .and_then(Value::as_object)
        .and_then(|hooks| hooks.get(event_name))
        .and_then(Value::as_array)
        .is_some_and(|hooks| contains_command_hook_suffix(hooks, command))
}

fn settings_has_cursor_shell_hook(settings: &Value) -> bool {
    settings_has_cursor_event_hook(settings, "beforeShellExecution", CURSOR_SHELL_HOOK_COMMAND)
}

fn settings_has_cursor_mcp_hook(settings: &Value) -> bool {
    settings_has_cursor_event_hook(settings, "beforeMCPExecution", CURSOR_MCP_HOOK_COMMAND)
}

fn settings_has_cursor_event_hook(settings: &Value, event_name: &str, command: &str) -> bool {
    settings
        .get("hooks")
        .and_then(Value::as_object)
        .and_then(|hooks| hooks.get(event_name))
        .and_then(Value::as_array)
        .is_some_and(|hooks| contains_cursor_command_hook_suffix(hooks, command))
}

fn command_matches_suffix(command: &str, suffix: &str) -> bool {
    command == suffix
        || command.ends_with(&format!(" {suffix}"))
        || command.ends_with(&format!("descry {suffix}"))
}

fn contains_command_hook_suffix(pretooluse_hooks: &[Value], command_suffix: &str) -> bool {
    contains_command_hook(pretooluse_hooks, command_suffix)
        || pretooluse_hooks.iter().any(|entry| {
            entry
                .get("hooks")
                .and_then(Value::as_array)
                .is_some_and(|hooks| {
                    hooks.iter().any(|hook| {
                        hook.get("type").and_then(Value::as_str) == Some("command")
                            && hook
                                .get("command")
                                .and_then(Value::as_str)
                                .is_some_and(|command| {
                                    command_matches_suffix(command, command_suffix)
                                })
                    })
                })
        })
}

fn contains_cursor_command_hook_suffix(event_hooks: &[Value], command_suffix: &str) -> bool {
    contains_cursor_command_hook(event_hooks, command_suffix)
        || event_hooks.iter().any(|hook| {
            hook.get("command")
                .and_then(Value::as_str)
                .is_some_and(|command| command_matches_suffix(command, command_suffix))
        })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        settings_has_claude_hook, settings_has_codex_hook, settings_has_cursor_mcp_hook,
        settings_has_cursor_shell_hook,
    };

    #[test]
    fn detects_claude_hook_in_settings() {
        let settings = json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "*",
                        "hooks": [
                            { "type": "command", "command": "descry hook claude pretooluse" }
                        ]
                    }
                ]
            }
        });

        assert!(settings_has_claude_hook(&settings));
    }

    #[test]
    fn detects_codex_hook_in_settings() {
        let settings = json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "*",
                        "hooks": [
                            { "type": "command", "command": "descry hook codex pretooluse" }
                        ]
                    }
                ]
            }
        });

        assert!(settings_has_codex_hook(&settings));
    }

    #[test]
    fn detects_cursor_hook_in_settings() {
        let settings = json!({
            "version": 1,
            "hooks": {
                "beforeShellExecution": [
                    { "command": "descry hook cursor before-shell-execution" }
                ]
            }
        });

        assert!(settings_has_cursor_shell_hook(&settings));
    }

    #[test]
    fn detects_cursor_mcp_hook_in_settings() {
        let settings = json!({
            "version": 1,
            "hooks": {
                "beforeMCPExecution": [
                    { "command": "descry hook cursor before-mcp-execution" }
                ]
            }
        });

        assert!(settings_has_cursor_mcp_hook(&settings));
    }
}
