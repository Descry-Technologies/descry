use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
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
use descry_core::{ActionContextPacket, Confidence, Decision, DecisionOutput, RiskScore};
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
    audit: PathBuf,
    context: PathBuf,
    approvals: PathBuf,
    asset_policy: PathBuf,
    behavior: PathBuf,
    repo_id_hash: String,
}

fn run_install(action: HookInstallAction, output: &mut dyn Write) -> Result<()> {
    match action {
        HookInstallAction::Claude {
            project,
            settings,
            command,
        } => {
            let settings_path = match settings {
                Some(path) => path,
                None => match project {
                    Some(project) => project_claude_settings_path(&project),
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
            let hooks_path = match hooks {
                Some(path) => path,
                None => match project {
                    Some(project) => project_cursor_hooks_path(&project),
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
    }
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
            audit,
            context,
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
                    audit,
                    context,
                    approvals,
                    asset_policy,
                    behavior,
                    repo_id_hash,
                },
            )?;
            let permission_decision = claude_permission_decision(&decision.decision);
            let hook_output = claude_output(permission_decision, decision.reason);
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
            audit,
            context,
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
                    audit,
                    context,
                    approvals,
                    asset_policy,
                    behavior,
                    repo_id_hash,
                },
            )?;
            let permission_decision = codex_permission_decision(&decision.decision);
            let hook_output = claude_output(permission_decision, decision.reason);
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
            audit,
            context,
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
                    audit,
                    context,
                    approvals,
                    asset_policy,
                    behavior,
                    repo_id_hash,
                },
            )?;
            let cursor_decision = cursor_permission_decision(&decision.decision);
            let hook_output = cursor_output(cursor_decision, decision.reason);
            serde_json::to_writer(output, &hook_output)
                .map_err(|serialize_error| CliError::new(serialize_error.to_string(), 1))?;
            Ok(())
        }
        CursorHookAction::BeforeMcpExecution {
            policy,
            audit,
            context,
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
                    audit,
                    context,
                    approvals,
                    asset_policy,
                    behavior,
                    repo_id_hash,
                },
            )?;
            let cursor_decision = cursor_permission_decision(&decision.decision);
            let hook_output = cursor_output(cursor_decision, decision.reason);
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

fn evaluate_and_record(
    mut acp: ActionContextPacket,
    runtime: HookRuntimeConfig,
) -> Result<DecisionOutput> {
    acp.intent.active_task = crate::commands::task::read_active_task(&runtime.context)?;
    let policy = crate::commands::policy_source::load_policy(&runtime.policy)?.policy;
    let decision = apply_approval_layer(
        policy.evaluate(&acp),
        &acp,
        &runtime.approvals,
        &runtime.asset_policy,
        &runtime.behavior,
    )?;
    append_audit(&runtime.audit, &runtime.repo_id_hash, &acp, &decision)?;
    record_behavior(&runtime.behavior, &acp)?;
    Ok(decision)
}

fn apply_approval_layer(
    decision: DecisionOutput,
    acp: &ActionContextPacket,
    approvals_path: &Path,
    asset_policy_path: &Path,
    behavior_path: &Path,
) -> Result<DecisionOutput> {
    if decision.decision == Decision::Block && acp.action.action_type == "mcp.call" {
        return apply_mcp_approval_override(decision, acp, approvals_path);
    }
    if decision.decision == Decision::Block || acp.action.action_type != "file.write" {
        return Ok(decision);
    }
    let asset_policy = descry_memory::load_asset_policy(asset_policy_path)
        .map_err(|error| CliError::new(error.to_string(), 1))?;
    let Some(asset) = descry_memory::match_asset(&asset_policy, &acp.action.target) else {
        return Ok(decision);
    };
    if acp.intent.active_task.is_some() {
        return Ok(decision);
    }

    let now = current_epoch_seconds()?;
    let has_approval =
        descry_memory::has_live_approval_for_target(approvals_path, &acp.action.target, now)
            .map_err(|error| CliError::new(error.to_string(), 1))?;

    if has_approval {
        Ok(DecisionOutput {
            decision: Decision::AllowWithLog,
            risk_score: RiskScore::try_from(45).expect("45 is a valid risk score"),
            confidence: Confidence::try_from(0.9).expect("0.9 is a valid confidence"),
            reason: format!(
                "scoped approval matched {} write target {} (asset: {})",
                asset.sensitivity, acp.action.target, asset.id
            ),
            conditions: vec![String::from("Approval applies only until its TTL expires")],
        })
    } else if asset.default_action == "block" {
        Ok(DecisionOutput {
            decision: Decision::Block,
            risk_score: RiskScore::try_from(95).expect("95 is a valid risk score"),
            confidence: Confidence::try_from(0.95).expect("0.95 is a valid confidence"),
            reason: format!(
                "{} write target {} is blocked by asset policy (asset: {})",
                asset.sensitivity, acp.action.target, asset.id
            ),
            conditions: vec![format!(
                "Run: descry approve --scope '{}' --ttl 30m for an explicit override",
                approval_scope_hint(&acp.action.target)
            )],
        })
    } else {
        let previous_attempts = descry_memory::behavior_count(
            behavior_path,
            &acp.actor.name,
            &acp.action.action_type,
            &acp.action.target,
        )
        .map_err(|error| CliError::new(error.to_string(), 1))?;
        let repeat_context = if previous_attempts > 0 {
            format!(" after {previous_attempts} prior attempt(s)")
        } else {
            String::new()
        };
        Ok(DecisionOutput {
            decision: Decision::RequireApproval,
            risk_score: RiskScore::try_from(if previous_attempts > 0 { 90 } else { 80 })
                .expect("risk score is valid"),
            confidence: Confidence::try_from(0.9).expect("0.9 is a valid confidence"),
            reason: format!(
                "{} write target {} requires scoped approval{} (asset: {})",
                asset.sensitivity, acp.action.target, repeat_context, asset.id
            ),
            conditions: vec![format!(
                "Run: descry approve --scope '{}' --ttl 30m",
                approval_scope_hint(&acp.action.target)
            )],
        })
    }
}

fn apply_mcp_approval_override(
    decision: DecisionOutput,
    acp: &ActionContextPacket,
    approvals_path: &Path,
) -> Result<DecisionOutput> {
    let now = current_epoch_seconds()?;
    let has_approval =
        descry_memory::has_live_approval_for_target(approvals_path, &acp.action.target, now)
            .map_err(|error| CliError::new(error.to_string(), 1))?;

    if has_approval {
        Ok(DecisionOutput {
            decision: Decision::AllowWithLog,
            risk_score: RiskScore::try_from(70).expect("70 is a valid risk score"),
            confidence: Confidence::try_from(0.9).expect("0.9 is a valid confidence"),
            reason: format!(
                "scoped approval matched MCP target {} after policy block: {}",
                acp.action.target, decision.reason
            ),
            conditions: vec![String::from(
                "Approval applies only to this MCP target scope until its TTL expires",
            )],
        })
    } else {
        Ok(decision)
    }
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

fn approval_scope_hint(target: &str) -> String {
    if let Some((prefix, _)) = target.rsplit_once('/') {
        format!("{prefix}/**")
    } else {
        target.to_string()
    }
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
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;
        }
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
    if let Some(parent) = settings_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let body = serde_json::to_string_pretty(settings)
        .map_err(|serialize_error| CliError::new(serialize_error.to_string(), 1))?;
    fs::write(settings_path, format!("{body}\n"))?;
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
