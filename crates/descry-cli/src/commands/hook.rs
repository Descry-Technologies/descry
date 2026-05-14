use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use descry_adapters::claude::{
    claude_output, normalize_pretooluse as normalize_claude_pretooluse, ClaudeHookInput,
};
use descry_adapters::codex::{normalize_pretooluse as normalize_codex_pretooluse, CodexHookInput};
use descry_adapters::cursor::{
    cursor_output, normalize_before_mcp_execution, normalize_before_shell_execution,
    CursorMcpHookInput, CursorShellHookInput,
};
use descry_audit::AuditChain;
use descry_context::SessionEvent;
use descry_core::{ActionContextPacket, Decision, DecisionOutput};
use descry_engine::{build_decision_input_with_legacy_asset_policy, evaluate, EvaluationRuntime};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::{
    ClaudeHookAction, CliError, CodexHookAction, CursorHookAction, HookAction, HookInstallAction,
    Result,
};

pub fn run(
    action: HookAction,
    input: &mut dyn Read,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> Result<()> {
    match action {
        HookAction::Install { action } => run_install(action, output),
        HookAction::Claude { action } => run_claude(action, input, output, error),
        HookAction::Codex { action } => run_codex(action, input, output, error),
        HookAction::Cursor { action } => run_cursor(action, input, output, error),
    }
}

#[derive(Debug)]
struct HookRuntimeConfig {
    policy: PathBuf,
    project: PathBuf,
    audit: PathBuf,
    context: PathBuf,
    state: PathBuf,
    approvals: PathBuf,
    asset_policy: PathBuf,
    behavior: PathBuf,
    repo_id_hash: String,
    session_id: Option<String>,
}

pub(crate) fn run_install(action: HookInstallAction, output: &mut dyn Write) -> Result<()> {
    match action {
        HookInstallAction::Claude {
            project,
            settings,
            command,
        } => {
            if let Some(project) = project.as_deref() {
                ensure_project_ready_for_hook_install(project, output)?;
            }
            let command =
                command.unwrap_or(default_hook_command(&["hook", "claude", "pretooluse"])?);
            let settings_path = match settings {
                Some(path) => path,
                None => match project.as_deref() {
                    Some(project) => project_claude_settings_path(project),
                    None => default_claude_settings_path()?,
                },
            };
            let installed = install_claude_pretooluse_hook(&settings_path, &command)?;
            writeln!(
                output,
                "{}",
                json!({
                    "host": "claude",
                    "event": "PreToolUse",
                    "settings": settings_path,
                    "command": command,
                    "installed": installed
                })
            )?;
            Ok(())
        }
        HookInstallAction::Codex {
            project,
            hooks,
            config,
            command,
        } => {
            if let Some(project) = project.as_deref() {
                ensure_project_ready_for_hook_install(project, output)?;
            }
            let command =
                command.unwrap_or(default_hook_command(&["hook", "codex", "pretooluse"])?);
            let hooks_path = match hooks {
                Some(path) => path,
                None => match project.as_deref() {
                    Some(project) => project_codex_hooks_path(project),
                    None => default_codex_hooks_path()?,
                },
            };
            let config_path = match config {
                Some(path) => path,
                None => match project.as_deref() {
                    Some(project) => project_codex_config_path(project),
                    None => default_codex_config_path()?,
                },
            };
            let installed = install_codex_pretooluse_hook(&hooks_path, &command)?;
            let feature_enabled = ensure_codex_hooks_feature(&config_path)?;
            writeln!(
                output,
                "{}",
                json!({
                    "host": "codex",
                    "event": "PreToolUse",
                    "hooks": hooks_path,
                    "config": config_path,
                    "command": command,
                    "installed": installed,
                    "feature_enabled": feature_enabled
                })
            )?;
            Ok(())
        }
        HookInstallAction::Cursor {
            project,
            hooks,
            command,
            mcp_command,
        } => {
            if let Some(project) = project.as_deref() {
                ensure_project_ready_for_hook_install(project, output)?;
            }
            let command = command.unwrap_or(default_hook_command(&[
                "hook",
                "cursor",
                "before-shell-execution",
            ])?);
            let mcp_command = mcp_command.unwrap_or(default_hook_command(&[
                "hook",
                "cursor",
                "before-mcp-execution",
            ])?);
            let hooks_path = match hooks {
                Some(path) => path,
                None => match project.as_deref() {
                    Some(project) => project_cursor_hooks_path(project),
                    None => default_cursor_hooks_path()?,
                },
            };
            let installed_shell =
                install_cursor_event_command_hook(&hooks_path, "beforeShellExecution", &command)?;
            let installed_mcp =
                install_cursor_event_command_hook(&hooks_path, "beforeMCPExecution", &mcp_command)?;
            writeln!(
                output,
                "{}",
                json!({
                    "host": "cursor",
                    "events": ["beforeShellExecution", "beforeMCPExecution"],
                    "hooks": hooks_path,
                    "command": command,
                    "mcp_command": mcp_command,
                    "installed": installed_shell || installed_mcp,
                    "installed_shell": installed_shell,
                    "installed_mcp": installed_mcp
                })
            )?;
            Ok(())
        }
        HookInstallAction::Git {
            project,
            hook,
            command,
        } => {
            let command =
                command.unwrap_or(default_hook_command(&["scan", "secrets", "--staged"])?);
            let hook_path = git_hook_path(&project, &hook)?;
            let installed = install_git_hook(&hook_path, &command)?;
            writeln!(
                output,
                "{}",
                json!({
                    "host": "git",
                    "hook": hook,
                    "path": hook_path,
                    "command": command,
                    "installed": installed
                })
            )?;
            Ok(())
        }
    }
}

fn default_hook_command(args: &[&str]) -> Result<String> {
    let exe = std::env::current_exe()?;
    let mut command = exe.to_string_lossy().to_string();
    for arg in args {
        command.push(' ');
        command.push_str(arg);
    }
    Ok(command)
}

fn ensure_project_ready_for_hook_install(project: &Path, output: &mut dyn Write) -> Result<()> {
    let project_policy = project.join(".descry/project.yml");
    let project_index = project.join(".descry/state/project-index.json");
    if project_policy.exists() && project_index.exists() {
        return Ok(());
    }

    writeln!(
        output,
        "{}",
        json!({
            "ok": false,
            "project": project,
            "project_policy": project_policy,
            "project_index": project_index,
            "next": format!("descry init --project {}", project.display())
        })
    )?;
    Err(CliError::new("project is not initialized", 2))
}

pub(crate) fn git_hook_path(project: &Path, hook: &str) -> Result<PathBuf> {
    if let Ok(output) = Command::new("git")
        .arg("-C")
        .arg(project)
        .args(["rev-parse", "--git-path"])
        .arg(format!("hooks/{hook}"))
        .output()
    {
        if output.status.success() {
            let raw = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !raw.is_empty() {
                let path = PathBuf::from(raw);
                return Ok(if path.is_absolute() {
                    path
                } else {
                    project.join(path)
                });
            }
        }
    }

    let fallback_hooks_dir = project.join(".git/hooks");
    if fallback_hooks_dir.is_dir() {
        return Ok(fallback_hooks_dir.join(hook));
    }

    Err(CliError::new(
        format!(
            "could not resolve git hook path for {}; run inside a git checkout",
            project.display()
        ),
        2,
    ))
}

fn install_git_hook(hook_path: &Path, command: &str) -> Result<bool> {
    let hooks_dir = hook_path.parent().ok_or_else(|| {
        CliError::new(format!("invalid git hook path {}", hook_path.display()), 2)
    })?;
    fs::create_dir_all(hooks_dir)?;

    let existing = fs::read_to_string(hook_path).unwrap_or_default();
    if existing.contains(command) {
        ensure_executable(hook_path)?;
        return Ok(false);
    }

    let mut body = if existing.trim().is_empty() {
        String::from("#!/usr/bin/env sh\nset -eu\n")
    } else {
        let mut existing = existing;
        if !existing.ends_with('\n') {
            existing.push('\n');
        }
        existing
    };
    body.push_str("\n# descry secret scan\n");
    body.push_str(command);
    body.push('\n');

    fs::write(hook_path, body)?;
    ensure_executable(hook_path)?;
    Ok(true)
}

fn ensure_executable(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(path)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

fn run_claude(
    action: ClaudeHookAction,
    input: &mut dyn Read,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> Result<()> {
    match action {
        ClaudeHookAction::Pretooluse {
            policy,
            project,
            audit,
            context,
            state,
            approvals,
            asset_policy,
            behavior,
            repo_id_hash,
        } => {
            let body = read_hook_body(input)?;
            let hook_input: ClaudeHookInput = serde_json::from_slice(&body)
                .map_err(|parse_error| parse_hook_error(error, parse_error))?;
            let acp = normalize_claude_pretooluse(&hook_input);
            let decision = evaluate_and_record(
                acp,
                HookRuntimeConfig {
                    policy,
                    project,
                    audit,
                    context,
                    state,
                    approvals,
                    asset_policy,
                    behavior,
                    repo_id_hash,
                    session_id: Some(hook_input.session_id.clone()),
                },
            )?;
            let permission_decision = claude_permission_decision(&decision.decision);
            let hook_output = claude_output(permission_decision, host_reason(&decision));
            serde_json::to_writer(output, &hook_output)
                .map_err(|serialize_error| CliError::new(serialize_error.to_string(), 1))?;
            Ok(())
        }
    }
}

fn run_codex(
    action: CodexHookAction,
    input: &mut dyn Read,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> Result<()> {
    match action {
        CodexHookAction::Pretooluse {
            policy,
            project,
            audit,
            context,
            state,
            approvals,
            asset_policy,
            behavior,
            repo_id_hash,
        } => {
            let body = read_hook_body(input)?;
            let hook_input: CodexHookInput = serde_json::from_slice(&body)
                .map_err(|parse_error| parse_hook_error(error, parse_error))?;
            let acp = normalize_codex_pretooluse(&hook_input);
            let decision = evaluate_and_record(
                acp,
                HookRuntimeConfig {
                    policy,
                    project,
                    audit,
                    context,
                    state,
                    approvals,
                    asset_policy,
                    behavior,
                    repo_id_hash,
                    session_id: Some(hook_input.session_id.clone()),
                },
            )?;
            let permission_decision = codex_permission_decision(&decision.decision);
            let hook_output = claude_output(permission_decision, host_reason(&decision));
            serde_json::to_writer(output, &hook_output)
                .map_err(|serialize_error| CliError::new(serialize_error.to_string(), 1))?;
            Ok(())
        }
    }
}

fn run_cursor(
    action: CursorHookAction,
    input: &mut dyn Read,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> Result<()> {
    match action {
        CursorHookAction::BeforeShellExecution {
            policy,
            project,
            audit,
            context,
            state,
            approvals,
            asset_policy,
            behavior,
            repo_id_hash,
        } => {
            let body = read_hook_body(input)?;
            let hook_input: CursorShellHookInput = serde_json::from_slice(&body)
                .map_err(|parse_error| parse_hook_error(error, parse_error))?;
            let acp = normalize_before_shell_execution(&hook_input);
            let decision = evaluate_and_record(
                acp,
                HookRuntimeConfig {
                    policy,
                    project,
                    audit,
                    context,
                    state,
                    approvals,
                    asset_policy,
                    behavior,
                    repo_id_hash,
                    session_id: None,
                },
            )?;
            let cursor_decision = cursor_permission_decision(&decision.decision);
            let hook_output = cursor_output(cursor_decision, host_reason(&decision));
            serde_json::to_writer(output, &hook_output)
                .map_err(|serialize_error| CliError::new(serialize_error.to_string(), 1))?;
            Ok(())
        }
        CursorHookAction::BeforeMcpExecution {
            policy,
            project,
            audit,
            context,
            state,
            approvals,
            asset_policy,
            behavior,
            repo_id_hash,
        } => {
            let body = read_hook_body(input)?;
            let hook_input: CursorMcpHookInput = serde_json::from_slice(&body)
                .map_err(|parse_error| parse_hook_error(error, parse_error))?;
            let acp = normalize_before_mcp_execution(&hook_input);
            let decision = evaluate_and_record(
                acp,
                HookRuntimeConfig {
                    policy,
                    project,
                    audit,
                    context,
                    state,
                    approvals,
                    asset_policy,
                    behavior,
                    repo_id_hash,
                    session_id: None,
                },
            )?;
            let cursor_decision = cursor_permission_decision(&decision.decision);
            let hook_output = cursor_output(cursor_decision, host_reason(&decision));
            serde_json::to_writer(output, &hook_output)
                .map_err(|serialize_error| CliError::new(serialize_error.to_string(), 1))?;
            Ok(())
        }
    }
}

fn read_hook_body(input: &mut dyn Read) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    input.read_to_end(&mut body)?;
    Ok(body)
}

fn parse_hook_error(error: &mut dyn Write, parse_error: serde_json::Error) -> CliError {
    let _ = writeln!(error, "{}", json!({ "error": parse_error.to_string() }));
    CliError::new("", 2)
}

fn host_reason(decision: &DecisionOutput) -> String {
    if decision.conditions.is_empty() {
        decision.reason.clone()
    } else {
        format!("{} {}", decision.reason, decision.conditions.join(" "))
    }
}

fn evaluate_and_record(
    mut acp: ActionContextPacket,
    runtime: HookRuntimeConfig,
) -> Result<DecisionOutput> {
    enrich_acp_context(&mut acp, &runtime.state)?;
    acp.intent.active_task = crate::commands::task::read_active_task(&runtime.context)?;
    let policy = crate::commands::policy_source::load_policy(&runtime.policy)?.policy;
    let project_config = crate::commands::evaluate::load_project_policy(&runtime.project)?;
    let decision_input =
        build_decision_input_with_legacy_asset_policy(acp.clone(), &runtime.asset_policy);
    let decision = evaluate(
        decision_input,
        EvaluationRuntime {
            policy: &policy,
            project_config: &project_config,
            approvals_path: &runtime.approvals,
            behavior_path: &runtime.behavior,
        },
    );
    append_audit(&runtime.audit, &runtime.repo_id_hash, &acp, &decision)?;
    append_context_event(
        &runtime.state,
        runtime.session_id.as_deref(),
        &acp,
        &decision,
    )?;
    record_behavior(&runtime.behavior, &acp)?;
    Ok(decision)
}

fn enrich_acp_context(acp: &mut ActionContextPacket, state_dir: &Path) -> Result<()> {
    if let Ok(index) = descry_context::read_project_index(&state_dir.join("project-index.json")) {
        if acp.context.branch == "unknown" || acp.context.branch.trim().is_empty() {
            if let Some(branch) = index.branch {
                acp.context.branch = branch;
            }
        }
        if acp.context.repo == "unknown" || acp.context.repo.trim().is_empty() {
            acp.context.repo = index.repo_name;
        }
    }

    if acp.context.recent_files.is_empty() {
        let mut recent_files = descry_context::read_recent_events(state_dir)
            .unwrap_or_default()
            .into_iter()
            .rev()
            .filter(|event| event.action_type.starts_with("file."))
            .map(|event| event.target)
            .filter(|target| !target.trim().is_empty())
            .take(20)
            .collect::<Vec<_>>();
        recent_files.reverse();
        recent_files.sort();
        recent_files.dedup();
        acp.context.recent_files = recent_files;
    }

    Ok(())
}

fn record_behavior(behavior_path: &Path, acp: &ActionContextPacket) -> Result<()> {
    let now = current_epoch_seconds()?;
    descry_memory::record_behavior(
        behavior_path,
        &acp.actor.name,
        &acp.action.action_type,
        &acp.action.target,
        now,
    )
    .map_err(|error| CliError::new(error.to_string(), 1))?;
    Ok(())
}

fn append_context_event(
    state_dir: &Path,
    session_id: Option<&str>,
    acp: &ActionContextPacket,
    decision: &DecisionOutput,
) -> Result<()> {
    let event = SessionEvent {
        timestamp_unix: current_epoch_seconds()?,
        session_id: session_id.map(ToString::to_string),
        harness: acp.actor.name.clone(),
        user_prompt: None,
        action_type: acp.action.action_type.clone(),
        target: descry_context::sanitized_event_target(&acp.action.action_type, &acp.action.target),
        decision: Some(decision_name(&decision.decision).to_string()),
    };
    descry_context::append_session_event(state_dir, &event)
        .map_err(|error| CliError::new(error.to_string(), 1))
}

fn current_epoch_seconds() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| CliError::new(error.to_string(), 1))
}

fn append_audit(
    audit_path: &std::path::Path,
    repo_id_hash: &str,
    acp: &ActionContextPacket,
    decision: &descry_core::DecisionOutput,
) -> Result<()> {
    let mut chain = AuditChain::open(audit_path, repo_id_hash)
        .map_err(|audit_error| CliError::new(audit_error.to_string(), 1))?;
    let timestamp = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|time_error| CliError::new(time_error.to_string(), 1))?;
    let acp_hash = hash_acp(acp)?;
    let rule_id = matched_rule_id(&decision.reason);

    chain
        .append(
            timestamp,
            decision_name(&decision.decision),
            acp_hash,
            rule_id,
            Some(decision.reason.clone()),
        )
        .map_err(|audit_error| CliError::new(audit_error.to_string(), 1))?;
    Ok(())
}

fn hash_acp(acp: &ActionContextPacket) -> Result<String> {
    let bytes = serde_json::to_vec(acp)
        .map_err(|serialize_error| CliError::new(serialize_error.to_string(), 1))?;
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    Ok(hex)
}

fn claude_permission_decision(decision: &Decision) -> &'static str {
    match decision {
        Decision::Block => "deny",
        Decision::Ask | Decision::RequireApproval => "ask",
        Decision::Allow | Decision::AllowWithLog => "allow",
    }
}

fn codex_permission_decision(decision: &Decision) -> &'static str {
    match decision {
        Decision::Block | Decision::Ask | Decision::RequireApproval => "deny",
        Decision::Allow | Decision::AllowWithLog => "allow",
    }
}

fn cursor_permission_decision(decision: &Decision) -> &'static str {
    match decision {
        Decision::Block => "deny",
        Decision::Ask | Decision::RequireApproval => "ask",
        Decision::Allow | Decision::AllowWithLog => "allow",
    }
}

fn decision_name(decision: &Decision) -> &'static str {
    match decision {
        Decision::Allow => "allow",
        Decision::AllowWithLog => "allow_with_log",
        Decision::Ask => "ask",
        Decision::RequireApproval => "require_approval",
        Decision::Block => "block",
    }
}

fn matched_rule_id(reason: &str) -> Option<String> {
    reason
        .rsplit_once("(rule: ")
        .and_then(|(_, suffix)| suffix.strip_suffix(')'))
        .map(String::from)
}

pub(crate) fn default_claude_settings_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .ok_or_else(|| CliError::new("HOME is not set; pass --settings", 2))?;
    Ok(PathBuf::from(home).join(".claude").join("settings.json"))
}

pub(crate) fn project_claude_settings_path(project: &Path) -> PathBuf {
    project.join(".claude").join("settings.json")
}

pub(crate) fn default_codex_hooks_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .ok_or_else(|| CliError::new("HOME is not set; pass --hooks", 2))?;
    Ok(PathBuf::from(home).join(".codex").join("hooks.json"))
}

pub(crate) fn project_codex_hooks_path(project: &Path) -> PathBuf {
    project.join(".codex").join("hooks.json")
}

pub(crate) fn default_codex_config_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .ok_or_else(|| CliError::new("HOME is not set; pass --config", 2))?;
    Ok(PathBuf::from(home).join(".codex").join("config.toml"))
}

pub(crate) fn project_codex_config_path(project: &Path) -> PathBuf {
    project.join(".codex").join("config.toml")
}

pub(crate) fn default_cursor_hooks_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .ok_or_else(|| CliError::new("HOME is not set; pass --hooks", 2))?;
    Ok(PathBuf::from(home).join(".cursor").join("hooks.json"))
}

pub(crate) fn project_cursor_hooks_path(project: &Path) -> PathBuf {
    project.join(".cursor").join("hooks.json")
}

fn install_claude_pretooluse_hook(settings_path: &Path, command: &str) -> Result<bool> {
    install_command_hook(settings_path, "PreToolUse", command, "*")
}

fn install_codex_pretooluse_hook(hooks_path: &Path, command: &str) -> Result<bool> {
    install_command_hook(hooks_path, "PreToolUse", command, "*")
}

fn install_command_hook(
    settings_path: &Path,
    event_name: &str,
    command: &str,
    matcher: &str,
) -> Result<bool> {
    let mut settings = read_settings(settings_path)?;
    let root = settings
        .as_object_mut()
        .ok_or_else(|| CliError::new("hook settings root must be a JSON object", 2))?;
    let hooks_value = root
        .entry(String::from("hooks"))
        .or_insert_with(|| json!({}));
    let hooks = hooks_value
        .as_object_mut()
        .ok_or_else(|| CliError::new("hook settings `hooks` must be a JSON object", 2))?;
    let event_value = hooks
        .entry(String::from(event_name))
        .or_insert_with(|| json!([]));
    let event_hooks = event_value
        .as_array_mut()
        .ok_or_else(|| CliError::new("hook event settings must be an array", 2))?;

    if contains_command_hook(event_hooks, command) {
        return Ok(false);
    }

    event_hooks.push(json!({
        "matcher": matcher,
        "hooks": [
            {
                "type": "command",
                "command": command
            }
        ]
    }));
    write_settings(settings_path, &settings)?;
    Ok(true)
}

fn install_cursor_event_command_hook(
    hooks_path: &Path,
    event_name: &str,
    command: &str,
) -> Result<bool> {
    let mut settings = read_settings(hooks_path)?;
    let root = settings
        .as_object_mut()
        .ok_or_else(|| CliError::new("Cursor hooks root must be a JSON object", 2))?;
    root.entry(String::from("version"))
        .or_insert_with(|| json!(1));
    let hooks_value = root
        .entry(String::from("hooks"))
        .or_insert_with(|| json!({}));
    let hooks = hooks_value
        .as_object_mut()
        .ok_or_else(|| CliError::new("Cursor hooks `hooks` must be a JSON object", 2))?;
    let event_value = hooks
        .entry(String::from(event_name))
        .or_insert_with(|| json!([]));
    let event_hooks = event_value
        .as_array_mut()
        .ok_or_else(|| CliError::new("Cursor hook event settings must be an array", 2))?;

    if contains_cursor_command_hook(event_hooks, command) {
        return Ok(false);
    }

    event_hooks.push(json!({ "command": command }));
    write_settings(hooks_path, &settings)?;
    Ok(true)
}

fn ensure_codex_hooks_feature(config_path: &Path) -> Result<bool> {
    let body = if config_path.exists() {
        fs::read_to_string(config_path)?
    } else {
        String::new()
    };
    let (updated, changed) = ensure_codex_hooks_feature_body(&body);
    if changed {
        ensure_parent_dir(config_path)?;
        fs::write(config_path, updated)?;
    }
    Ok(changed)
}

fn ensure_codex_hooks_feature_body(body: &str) -> (String, bool) {
    let mut lines: Vec<String> = body.lines().map(String::from).collect();
    let mut features_index = None;
    let mut feature_key_index = None;
    let mut in_features = false;

    for (index, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_features = trimmed == "[features]";
            if in_features {
                features_index = Some(index);
            }
            continue;
        }
        if in_features && toml_key(trimmed) == Some("codex_hooks") {
            feature_key_index = Some(index);
            break;
        }
    }

    let mut changed = true;
    if let Some(index) = feature_key_index {
        if lines[index].trim() == "codex_hooks = true" {
            changed = false;
        } else {
            lines[index] = String::from("codex_hooks = true");
        }
    } else if let Some(index) = features_index {
        lines.insert(index + 1, String::from("codex_hooks = true"));
    } else {
        if !lines.is_empty() {
            lines.push(String::new());
        }
        lines.push(String::from("[features]"));
        lines.push(String::from("codex_hooks = true"));
    }

    if !changed {
        return (body.to_string(), false);
    }

    (format!("{}\n", lines.join("\n")), true)
}

pub(crate) fn codex_hooks_feature_enabled(config_path: &Path) -> Result<bool> {
    let body = fs::read_to_string(config_path)?;
    let mut in_features = false;
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_features = trimmed == "[features]";
            continue;
        }
        if in_features && toml_key(trimmed) == Some("codex_hooks") {
            return Ok(trimmed == "codex_hooks = true");
        }
    }
    Ok(false)
}

fn toml_key(trimmed_line: &str) -> Option<&str> {
    let (key, _) = trimmed_line.split_once('=')?;
    Some(key.trim())
}

fn read_settings(settings_path: &Path) -> Result<Value> {
    if !settings_path.exists() {
        return Ok(json!({}));
    }

    let body = fs::read_to_string(settings_path)?;
    serde_json::from_str(&body).map_err(|parse_error| {
        CliError::new(
            format!(
                "failed to parse Claude settings {}: {parse_error}",
                settings_path.display()
            ),
            2,
        )
    })
}

fn write_settings(settings_path: &Path, settings: &Value) -> Result<()> {
    ensure_parent_dir(settings_path)?;
    let body = serde_json::to_string_pretty(settings)
        .map_err(|serialize_error| CliError::new(serialize_error.to_string(), 1))?;
    fs::write(settings_path, format!("{body}\n"))?;
    Ok(())
}

fn ensure_parent_dir(path: &Path) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if parent.exists() && !parent.is_dir() {
        return Err(CliError::new(
            format!(
                "cannot write {}; parent path {} exists but is not a directory",
                path.display(),
                parent.display()
            ),
            1,
        ));
    }
    fs::create_dir_all(parent)?;
    Ok(())
}

pub(crate) fn contains_command_hook(pretooluse_hooks: &[Value], command: &str) -> bool {
    pretooluse_hooks.iter().any(|entry| {
        entry
            .get("hooks")
            .and_then(Value::as_array)
            .is_some_and(|hooks| {
                hooks.iter().any(|hook| {
                    hook.get("type").and_then(Value::as_str) == Some("command")
                        && hook.get("command").and_then(Value::as_str) == Some(command)
                })
            })
    })
}

pub(crate) fn contains_cursor_command_hook(event_hooks: &[Value], command: &str) -> bool {
    event_hooks
        .iter()
        .any(|hook| hook.get("command").and_then(Value::as_str) == Some(command))
}

#[cfg(test)]
mod tests {
    use super::{
        claude_permission_decision, codex_permission_decision, contains_command_hook,
        contains_cursor_command_hook, cursor_permission_decision, decision_name,
        ensure_codex_hooks_feature_body,
    };
    use descry_core::Decision;
    use serde_json::json;

    #[test]
    fn maps_descry_decisions_to_claude_permissions() {
        assert_eq!(claude_permission_decision(&Decision::Allow), "allow");
        assert_eq!(claude_permission_decision(&Decision::AllowWithLog), "allow");
        assert_eq!(claude_permission_decision(&Decision::Ask), "ask");
        assert_eq!(
            claude_permission_decision(&Decision::RequireApproval),
            "ask"
        );
        assert_eq!(claude_permission_decision(&Decision::Block), "deny");
    }

    #[test]
    fn emits_stable_decision_names() {
        assert_eq!(decision_name(&Decision::Block), "block");
    }

    #[test]
    fn codex_denies_interactive_decisions() {
        assert_eq!(codex_permission_decision(&Decision::Allow), "allow");
        assert_eq!(codex_permission_decision(&Decision::AllowWithLog), "allow");
        assert_eq!(codex_permission_decision(&Decision::Ask), "deny");
        assert_eq!(
            codex_permission_decision(&Decision::RequireApproval),
            "deny"
        );
        assert_eq!(codex_permission_decision(&Decision::Block), "deny");
    }

    #[test]
    fn cursor_can_ask_for_interactive_decisions() {
        assert_eq!(cursor_permission_decision(&Decision::Allow), "allow");
        assert_eq!(cursor_permission_decision(&Decision::AllowWithLog), "allow");
        assert_eq!(cursor_permission_decision(&Decision::Ask), "ask");
        assert_eq!(
            cursor_permission_decision(&Decision::RequireApproval),
            "ask"
        );
        assert_eq!(cursor_permission_decision(&Decision::Block), "deny");
    }

    #[test]
    fn detects_existing_command_hook() {
        let hooks = vec![json!({
            "matcher": "*",
            "hooks": [
                { "type": "command", "command": "descry hook claude pretooluse" }
            ]
        })];

        assert!(contains_command_hook(
            &hooks,
            "descry hook claude pretooluse"
        ));
        assert!(!contains_command_hook(&hooks, "other command"));
    }

    #[test]
    fn detects_existing_cursor_command_hook() {
        let hooks = vec![json!({ "command": "descry hook cursor before-shell-execution" })];

        assert!(contains_cursor_command_hook(
            &hooks,
            "descry hook cursor before-shell-execution"
        ));
        assert!(!contains_cursor_command_hook(&hooks, "other command"));
    }

    #[test]
    fn enables_codex_hooks_feature_in_existing_toml() {
        let (body, changed) = ensure_codex_hooks_feature_body("[model]\nname = \"gpt-5\"\n");

        assert!(changed);
        assert!(body.contains("[features]\ncodex_hooks = true"));
    }

    #[test]
    fn flips_existing_codex_hooks_feature_to_true() {
        let (body, changed) = ensure_codex_hooks_feature_body("[features]\ncodex_hooks = false\n");

        assert!(changed);
        assert!(body.contains("codex_hooks = true"));
    }
}
