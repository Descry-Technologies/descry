use descry_core::acp::{Action, Actor, Asset, BlastRadius, Context, Intent};
use descry_core::ActionContextPacket;
use serde::Deserialize;
use serde_json::Value;

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct CodexHookInput {
    pub session_id: String,
    pub cwd: Option<String>,
    pub hook_event_name: String,
    pub tool_name: String,
    #[serde(default)]
    pub tool_input: Value,
    pub tool_use_id: Option<String>,
    pub model: Option<String>,
    pub turn_id: Option<String>,
}

pub fn normalize_pretooluse(input: &CodexHookInput) -> ActionContextPacket {
    let action_type = action_type_for_tool(&input.tool_name);
    let target = target_for_tool(input);
    let cwd = input.cwd.as_deref().unwrap_or("unknown");

    ActionContextPacket {
        actor: Actor {
            actor_type: String::from("agent"),
            name: String::from("codex-cli"),
            owner: String::from("local"),
            trust_level: String::from("local_dev_agent"),
        },
        action: Action {
            action_type: action_type.to_string(),
            verb: verb_for_action_type(action_type).to_string(),
            target,
            diff_summary: diff_summary_for_tool(input),
            argument_keys: Vec::new(),
        },
        intent: Intent {
            active_task: None,
            source: String::from("codex_pretooluse"),
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

fn action_type_for_tool(tool_name: &str) -> &'static str {
    match tool_name {
        "Bash" => "shell.exec",
        "apply_patch" => "file.write",
        name if name.starts_with("mcp__") => "mcp.call",
        _ => "sdk.tool.call",
    }
}

fn verb_for_action_type(action_type: &str) -> &'static str {
    match action_type {
        "shell.exec" => "run",
        "file.write" => "modify",
        "mcp.call" => "call",
        _ => "call",
    }
}

fn asset_type_for_action_type(action_type: &str) -> &'static str {
    match action_type {
        "shell.exec" => "local_command",
        "file.write" => "code_file",
        "mcp.call" => "mcp_tool",
        _ => "tool_call",
    }
}

fn target_for_tool(input: &CodexHookInput) -> String {
    match input.tool_name.as_str() {
        "Bash" => string_field(&input.tool_input, "command").unwrap_or_default(),
        "apply_patch" => String::from("apply_patch"),
        _ => input.tool_name.clone(),
    }
}

fn diff_summary_for_tool(input: &CodexHookInput) -> Option<String> {
    if input.tool_name == "apply_patch" {
        Some(String::from("Codex apply_patch content omitted"))
    } else {
        None
    }
}

fn string_field(value: &Value, field: &str) -> Option<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{normalize_pretooluse, CodexHookInput};

    #[test]
    fn normalizes_bash_command() {
        let input = CodexHookInput {
            session_id: String::from("s1"),
            cwd: Some(String::from("/repo")),
            hook_event_name: String::from("PreToolUse"),
            tool_name: String::from("Bash"),
            tool_input: json!({ "command": "rm -rf ~" }),
            tool_use_id: Some(String::from("toolu_1")),
            model: Some(String::from("gpt-5.5")),
            turn_id: Some(String::from("t1")),
        };

        let acp = normalize_pretooluse(&input);

        assert_eq!(acp.actor.name, "codex-cli");
        assert_eq!(acp.action.action_type, "shell.exec");
        assert_eq!(acp.action.target, "rm -rf ~");
    }
}
