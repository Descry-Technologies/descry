use descry_core::acp::{Action, Actor, Asset, BlastRadius, Context, Intent};
use descry_core::{ActionContextPacket, InstructionProvenance};

use crate::provenance;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use serde_json::Value;

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct ClaudeHookInput {
    pub session_id: String,
    pub cwd: Option<String>,
    pub hook_event_name: String,
    pub tool_name: String,
    #[serde(default)]
    pub tool_input: Value,
    pub tool_use_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ClaudeHookOutput {
    #[serde(rename = "hookSpecificOutput")]
    pub hook_specific_output: ClaudeHookSpecificOutput,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ClaudeHookSpecificOutput {
    #[serde(rename = "hookEventName")]
    pub hook_event_name: String,
    #[serde(rename = "permissionDecision")]
    pub permission_decision: String,
    #[serde(rename = "permissionDecisionReason")]
    pub permission_decision_reason: String,
}

pub fn normalize_pretooluse(input: &ClaudeHookInput) -> ActionContextPacket {
    let target = target_for_tool(input);
    let action_type = action_type_for_tool(&input.tool_name);
    let verb = verb_for_action_type(action_type);
    let cwd = input.cwd.as_deref().unwrap_or("unknown");
    let instruction_provenance: Option<InstructionProvenance> = Some(provenance::classify_claude(
        &input.tool_name,
        &input.tool_input,
        input.cwd.as_deref(),
    ));

    ActionContextPacket {
        actor: Actor {
            actor_type: String::from("agent"),
            name: String::from("claude-code"),
            owner: String::from("local"),
            trust_level: String::from("local_dev_agent"),
        },
        action: Action {
            action_type: String::from(action_type),
            verb: String::from(verb),
            target,
            targets: targets_for_tool(input),
            diff_summary: diff_summary_for_tool(input),
            argument_keys: safe_argument_keys(&input.tool_input),
        },
        intent: Intent {
            active_task: None,
            user_prompt: prompt_for_hook(input),
            source: String::from("claude_pretooluse"),
            linked_issue: None,
        },
        asset: Asset {
            asset_type: asset_type_for_action_type(action_type).to_string(),
            sensitivity: String::from("low"),
            environment: String::from("local"),
        },
        context: Context {
            repo: cwd.to_string(),
            branch: String::from("unknown"),
            recent_files: Vec::new(),
            recent_approvals: Vec::new(),
        },
        blast_radius: BlastRadius {
            reversible: action_type != "shell.exec",
            customer_impact: String::from("none"),
            financial_impact: String::from("none"),
        },
        instruction_provenance,
    }
}

pub fn claude_output(permission_decision: &str, reason: impl Into<String>) -> ClaudeHookOutput {
    ClaudeHookOutput {
        hook_specific_output: ClaudeHookSpecificOutput {
            hook_event_name: String::from("PreToolUse"),
            permission_decision: permission_decision.to_string(),
            permission_decision_reason: reason.into(),
        },
    }
}

fn action_type_for_tool(tool_name: &str) -> &'static str {
    match tool_name {
        "Bash" => "shell.exec",
        "Read" => "file.read",
        "Write" | "Edit" | "MultiEdit" => "file.write",
        name if name.starts_with("mcp__") => "mcp.call",
        _ => "sdk.tool.call",
    }
}

fn verb_for_action_type(action_type: &str) -> &'static str {
    match action_type {
        "shell.exec" => "run",
        "file.read" => "read",
        "file.write" => "modify",
        "mcp.call" => "call",
        _ => "call",
    }
}

fn asset_type_for_action_type(action_type: &str) -> &'static str {
    match action_type {
        "shell.exec" => "local_command",
        "file.read" | "file.write" => "code_file",
        "mcp.call" => "mcp_tool",
        _ => "tool_call",
    }
}

fn target_for_tool(input: &ClaudeHookInput) -> String {
    match input.tool_name.as_str() {
        "Bash" => string_field(&input.tool_input, "command").unwrap_or_default(),
        "Read" | "Write" | "Edit" | "MultiEdit" => {
            string_field(&input.tool_input, "file_path").unwrap_or_default()
        }
        name if name.starts_with("mcp__") => mcp_target(name),
        _ => input.tool_name.clone(),
    }
}

fn targets_for_tool(input: &ClaudeHookInput) -> Vec<String> {
    let mut paths = safe_path_list(&input.tool_input);
    if paths.is_empty() {
        paths.push(target_for_tool(input));
    }
    paths
}

fn diff_summary_for_tool(input: &ClaudeHookInput) -> Option<String> {
    match input.tool_name.as_str() {
        "Write" => Some(String::from("Claude Write tool content omitted")),
        "Edit" => Some(String::from("Claude Edit tool string replacement omitted")),
        "MultiEdit" => Some(String::from("Claude MultiEdit tool changes omitted")),
        name if name.starts_with("mcp__") => {
            Some(format!("Claude MCP tool call: {}", mcp_tool_name(name)))
        }
        _ => None,
    }
}

fn string_field(value: &Value, field: &str) -> Option<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

fn prompt_for_hook(input: &ClaudeHookInput) -> Option<String> {
    string_field(&input.tool_input, "user_prompt")
        .or_else(|| string_field(&input.tool_input, "prompt"))
}

fn mcp_target(tool_name: &str) -> String {
    let parts = tool_name.split("__").collect::<Vec<_>>();
    if parts.len() >= 3 {
        format!("{}:{}", parts[1], parts[2..].join("__"))
    } else {
        tool_name.to_string()
    }
}

fn mcp_tool_name(tool_name: &str) -> String {
    tool_name
        .split("__")
        .skip(2)
        .collect::<Vec<_>>()
        .join("__")
        .trim()
        .to_string()
        .if_empty_then(tool_name)
}

trait IfEmptyThen {
    fn if_empty_then(self, fallback: &str) -> String;
}

impl IfEmptyThen for String {
    fn if_empty_then(self, fallback: &str) -> String {
        if self.is_empty() {
            fallback.to_string()
        } else {
            self
        }
    }
}

fn safe_argument_keys(value: &Value) -> Vec<String> {
    let mut keys = BTreeSet::new();
    for field in [
        "arguments",
        "args",
        "parameters",
        "params",
        "input",
        "tool_input",
    ] {
        if let Some(arguments) = value.get(field) {
            collect_argument_keys(arguments, &mut keys);
        }
    }
    collect_argument_keys(value, &mut keys);
    for container in [
        "arguments",
        "args",
        "parameters",
        "params",
        "input",
        "tool_input",
    ] {
        keys.remove(container);
    }
    keys.into_iter().collect()
}

fn collect_argument_keys(value: &Value, keys: &mut BTreeSet<String>) {
    let Some(arguments) = value.as_object() else {
        return;
    };

    for key in arguments.keys() {
        if is_safe_argument_key(key) {
            keys.insert(key.clone());
        }
    }
}

fn safe_path_list(value: &Value) -> Vec<String> {
    let mut paths = Vec::new();
    if let Some(path) = string_field(value, "file_path") {
        paths.push(path);
    }
    if let Some(edits) = value.get("edits").and_then(Value::as_array) {
        for edit in edits {
            if let Some(path) = string_field(edit, "file_path") {
                paths.push(path);
            }
        }
    }
    paths.retain(|path| !path.trim().is_empty());
    paths.sort();
    paths.dedup();
    paths
}

fn is_safe_argument_key(key: &str) -> bool {
    let lowercase = key.to_ascii_lowercase();
    !key.is_empty()
        && key.len() <= 64
        && !lowercase.contains("secret")
        && !lowercase.contains("token")
        && !lowercase.contains("password")
        && !lowercase.contains("passwd")
        && key
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{normalize_pretooluse, ClaudeHookInput};

    #[test]
    fn normalizes_bash_command_to_shell_exec() {
        let input = ClaudeHookInput {
            session_id: String::from("s1"),
            cwd: Some(String::from("/repo")),
            hook_event_name: String::from("PreToolUse"),
            tool_name: String::from("Bash"),
            tool_input: json!({ "command": "rm -rf ~" }),
            tool_use_id: Some(String::from("toolu_1")),
        };

        let acp = normalize_pretooluse(&input);

        assert_eq!(acp.actor.name, "claude-code");
        assert_eq!(acp.action.action_type, "shell.exec");
        assert_eq!(acp.action.target, "rm -rf ~");
        assert_eq!(acp.context.repo, "/repo");
    }

    #[test]
    fn normalizes_write_path_without_content() {
        let input = ClaudeHookInput {
            session_id: String::from("s1"),
            cwd: Some(String::from("/repo")),
            hook_event_name: String::from("PreToolUse"),
            tool_name: String::from("Write"),
            tool_input: json!({ "file_path": "src/lib.rs", "content": "secret body" }),
            tool_use_id: None,
        };

        let acp = normalize_pretooluse(&input);

        assert_eq!(acp.action.action_type, "file.write");
        assert_eq!(acp.action.target, "src/lib.rs");
        assert_eq!(
            acp.action.diff_summary.as_deref(),
            Some("Claude Write tool content omitted")
        );
    }

    #[test]
    fn normalizes_mcp_call_with_safe_argument_keys() {
        let input = ClaudeHookInput {
            session_id: String::from("s1"),
            cwd: Some(String::from("/repo")),
            hook_event_name: String::from("PreToolUse"),
            tool_name: String::from("mcp__prod__delete_project"),
            tool_input: json!({
                "arguments": {
                    "project_id": "prod-123",
                    "confirm_destroy": true,
                    "api_token": "redacted"
                }
            }),
            tool_use_id: None,
        };

        let acp = normalize_pretooluse(&input);

        assert_eq!(acp.action.action_type, "mcp.call");
        assert_eq!(acp.action.target, "prod:delete_project");
        assert_eq!(
            acp.action.diff_summary.as_deref(),
            Some("Claude MCP tool call: delete_project")
        );
        assert_eq!(
            acp.action.argument_keys,
            vec![String::from("confirm_destroy"), String::from("project_id")]
        );
        let serialized = serde_json::to_string(&acp).expect("acp serializes");
        assert!(!serialized.contains("prod-123"));
        assert!(!serialized.contains("redacted"));
    }

    #[test]
    fn normalizes_multiedit_paths_without_edit_content() {
        let input = ClaudeHookInput {
            session_id: String::from("s1"),
            cwd: Some(String::from("/repo")),
            hook_event_name: String::from("PreToolUse"),
            tool_name: String::from("MultiEdit"),
            tool_input: json!({
                "file_path": ".env.production",
                "edits": [
                    { "file_path": "src/lib.rs", "old_string": "secret", "new_string": "safe" }
                ]
            }),
            tool_use_id: None,
        };

        let acp = normalize_pretooluse(&input);

        assert_eq!(acp.action.target, ".env.production");
        assert_eq!(
            acp.action.targets,
            vec![String::from(".env.production"), String::from("src/lib.rs")]
        );
        let serialized = serde_json::to_string(&acp).expect("acp serializes");
        assert!(!serialized.contains("old_string"));
        assert!(!serialized.contains("secret"));
    }
}
