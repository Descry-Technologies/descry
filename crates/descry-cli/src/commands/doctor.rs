use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use descry_audit::VerifyOutcome;
use serde_json::{json, Value};

use crate::commands::hook::{
    codex_hooks_feature_enabled, contains_command_hook, contains_cursor_command_hook,
    default_claude_settings_path, default_codex_config_path, default_codex_hooks_path,
    default_cursor_hooks_path, project_claude_settings_path, project_codex_config_path,
    project_codex_hooks_path, project_cursor_hooks_path,
};
use crate::commands::policy_source::load_policy;
use crate::{CliError, Result};

const CLAUDE_HOOK_COMMAND: &str = "descry hook claude pretooluse";
const CODEX_HOOK_COMMAND: &str = "descry hook codex pretooluse";
const CURSOR_SHELL_HOOK_COMMAND: &str = "descry hook cursor before-shell-execution";
const CURSOR_MCP_HOOK_COMMAND: &str = "descry hook cursor before-mcp-execution";

pub struct DoctorConfig {
    pub project: Option<PathBuf>,
    pub claude_settings: Option<PathBuf>,
    pub codex_hooks: Option<PathBuf>,
    pub codex_config: Option<PathBuf>,
    pub cursor_hooks: Option<PathBuf>,
    pub policy: PathBuf,
    pub audit: PathBuf,
    pub repo_id_hash: String,
}

pub fn run(config: DoctorConfig, output: &mut dyn Write) -> Result<()> {
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
    let checks = vec![
        check_policy(&config.policy),
        check_claude_hook(&settings_path),
        check_codex_hook(&codex_hooks_path),
        check_codex_feature(&codex_config_path),
        check_cursor_shell_hook(&cursor_hooks_path),
        check_cursor_mcp_hook(&cursor_hooks_path),
        check_audit(&config.audit, &config.repo_id_hash),
    ];
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
        .is_some_and(|hooks| contains_command_hook(hooks, command))
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
        .is_some_and(|hooks| contains_cursor_command_hook(hooks, command))
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
