use descry_core::acp::{Action, Actor, Asset, BlastRadius, Context, Intent};
use descry_core::ActionContextPacket;
use serde::{Deserialize, Serialize};
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
            targets: Vec::new(),
            diff_summary: diff_summary_for_tool(input),
            argument_keys: Vec::new(),
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
        _ => input.tool_name.clone(),
    }
}

fn diff_summary_for_tool(input: &ClaudeHookInput) -> Option<String> {
    match input.tool_name.as_str() {
        "Write" => Some(String::from("Claude Write tool content omitted")),
        "Edit" => Some(String::from("Claude Edit tool string replacement omitted")),
        "MultiEdit" => Some(String::from("Claude MultiEdit tool changes omitted")),
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
}
