use std::collections::BTreeSet;

use descry_core::acp::{Action, Actor, Asset, BlastRadius, Context, Intent};
use descry_core::{ActionContextPacket, InstructionProvenance, TrustLevel};

use crate::provenance;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct CursorShellHookInput {
    #[serde(default)]
    pub session_id: Option<String>,
    pub cwd: Option<String>,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub tool_input: Value,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct CursorMcpHookInput {
    #[serde(default)]
    pub session_id: Option<String>,
    pub cwd: Option<String>,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub mcp_server_name: Option<String>,
    #[serde(default)]
    pub server_name: Option<String>,
    #[serde(default)]
    pub tool_name: Option<String>,
    #[serde(default)]
    pub tool_input: Value,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CursorHookOutput {
    #[serde(rename = "continue")]
    pub should_continue: bool,
    pub permission: String,
    pub decision: String,
    pub reason: String,
    pub user_message: String,
    pub agent_message: String,
}

pub fn normalize_before_shell_execution(input: &CursorShellHookInput) -> ActionContextPacket {
    let target = input
        .command
        .clone()
        .or_else(|| string_field(&input.tool_input, "command"))
        .unwrap_or_default();
    let cwd = input.cwd.as_deref().unwrap_or("unknown");
    let instruction_provenance: Option<InstructionProvenance> =
        Some(provenance::classify_cursor_shell(Some(&target)));

    ActionContextPacket {
        actor: Actor {
            actor_type: String::from("agent"),
            name: String::from("cursor"),
            owner: String::from("local"),
            trust_level: TrustLevel::LocalDevAgent,
        },
        action: Action {
            action_type: String::from("shell.exec"),
            verb: String::from("run"),
            target,
            targets: Vec::new(),
            diff_summary: None,
            argument_keys: Vec::new(),
        },
        intent: Intent {
            active_task: None,
            user_prompt: prompt_for_tool_input(&input.tool_input),
            source: String::from("cursor_before_shell_execution"),
            linked_issue: None,
        },
        asset: Asset {
            asset_type: String::from("local_command"),
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
            reversible: false,
            customer_impact: String::from("none"),
            financial_impact: String::from("none"),
        },
        instruction_provenance,
    }
}

pub fn normalize_before_mcp_execution(input: &CursorMcpHookInput) -> ActionContextPacket {
    let target = mcp_target(input);
    let cwd = input.cwd.as_deref().unwrap_or("unknown");
    let instruction_provenance: Option<InstructionProvenance> =
        Some(provenance::classify_cursor_mcp(input.url.as_deref()));

    ActionContextPacket {
        actor: Actor {
            actor_type: String::from("agent"),
            name: String::from("cursor"),
            owner: String::from("local"),
            trust_level: TrustLevel::LocalDevAgent,
        },
        action: Action {
            action_type: String::from("mcp.call"),
            verb: String::from("call"),
            target,
            targets: Vec::new(),
            diff_summary: mcp_diff_summary(input),
            argument_keys: mcp_argument_keys(input),
        },
        intent: Intent {
            active_task: None,
            user_prompt: prompt_for_tool_input(&input.tool_input),
            source: String::from("cursor_before_mcp_execution"),
            linked_issue: None,
        },
        asset: Asset {
            asset_type: String::from("mcp_server"),
            sensitivity: String::from("medium"),
            environment: String::from("external"),
        },
        context: Context {
            repo: cwd.to_string(),
            branch: String::from("unknown"),
            recent_files: Vec::new(),
            recent_approvals: Vec::new(),
        },
        blast_radius: BlastRadius {
            reversible: false,
            customer_impact: String::from("unknown"),
            financial_impact: String::from("unknown"),
        },
        instruction_provenance,
    }
}

pub fn cursor_output(decision: &str, reason: impl Into<String>) -> CursorHookOutput {
    let reason = reason.into();
    CursorHookOutput {
        should_continue: true,
        permission: decision.to_string(),
        decision: decision.to_string(),
        reason: reason.clone(),
        user_message: reason.clone(),
        agent_message: reason,
    }
}

fn string_field(value: &Value, field: &str) -> Option<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

fn prompt_for_tool_input(value: &Value) -> Option<String> {
    string_field(value, "user_prompt").or_else(|| string_field(value, "prompt"))
}

fn mcp_target(input: &CursorMcpHookInput) -> String {
    input
        .url
        .clone()
        .or_else(|| string_field(&input.tool_input, "url"))
        .or_else(|| input.command.clone())
        .or_else(|| string_field(&input.tool_input, "command"))
        .or_else(|| input.mcp_server_name.clone())
        .or_else(|| input.server_name.clone())
        .or_else(|| string_field(&input.tool_input, "mcp_server_name"))
        .or_else(|| string_field(&input.tool_input, "server_name"))
        .unwrap_or_else(|| String::from("unknown"))
}

fn mcp_diff_summary(input: &CursorMcpHookInput) -> Option<String> {
    input
        .tool_name
        .clone()
        .or_else(|| string_field(&input.tool_input, "tool_name"))
        .map(|tool_name| format!("Cursor MCP tool call: {tool_name}"))
}

fn mcp_argument_keys(input: &CursorMcpHookInput) -> Vec<String> {
    let mut keys = BTreeSet::new();
    for field in ["arguments", "args", "parameters", "params", "input"] {
        if let Some(value) = input.tool_input.get(field) {
            collect_argument_keys(value, &mut keys);
        }
        if let Some(value) = input.extra.get(field) {
            collect_argument_keys(value, &mut keys);
        }
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

    use super::{
        normalize_before_mcp_execution, normalize_before_shell_execution, CursorMcpHookInput,
        CursorShellHookInput,
    };

    #[test]
    fn normalizes_before_shell_execution() {
        let input = CursorShellHookInput {
            session_id: Some(String::from("s1")),
            cwd: Some(String::from("/repo")),
            command: None,
            tool_input: json!({ "command": "rm -rf ~" }),
        };

        let acp = normalize_before_shell_execution(&input);

        assert_eq!(acp.actor.name, "cursor");
        assert_eq!(acp.action.action_type, "shell.exec");
        assert_eq!(acp.action.target, "rm -rf ~");
    }

    #[test]
    fn normalizes_before_mcp_execution() {
        let input = CursorMcpHookInput {
            session_id: Some(String::from("s1")),
            cwd: Some(String::from("/repo")),
            command: None,
            url: Some(String::from("https://mcp.example.com/mcp")),
            mcp_server_name: None,
            server_name: None,
            tool_name: Some(String::from("list_projects")),
            tool_input: json!({}),
            extra: Default::default(),
        };

        let acp = normalize_before_mcp_execution(&input);

        assert_eq!(acp.actor.name, "cursor");
        assert_eq!(acp.action.action_type, "mcp.call");
        assert_eq!(acp.action.target, "https://mcp.example.com/mcp");
        assert_eq!(
            acp.action.diff_summary.as_deref(),
            Some("Cursor MCP tool call: list_projects")
        );
    }

    #[test]
    fn normalizes_mcp_argument_keys_without_values() {
        let input = CursorMcpHookInput {
            session_id: Some(String::from("s1")),
            cwd: Some(String::from("/repo")),
            command: None,
            url: Some(String::from("https://mcp.example.com/mcp")),
            mcp_server_name: None,
            server_name: None,
            tool_name: Some(String::from("delete_project")),
            tool_input: json!({
                "arguments": {
                    "project_id": "prod-123",
                    "confirm_destroy": true,
                    "api_token": "ignored",
                    "unsafe key": "ignored"
                }
            }),
            extra: Default::default(),
        };

        let acp = normalize_before_mcp_execution(&input);

        assert_eq!(
            acp.action.argument_keys,
            vec![String::from("confirm_destroy"), String::from("project_id")]
        );
        let serialized = serde_json::to_string(&acp).expect("acp serializes");
        assert!(!serialized.contains("prod-123"));
        assert!(!serialized.contains("api_token"));
    }
}
