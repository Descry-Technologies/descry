use std::collections::BTreeSet;

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
    let targets = targets_for_tool(input, &target);
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
            targets,
            diff_summary: diff_summary_for_tool(input),
            argument_keys: safe_argument_keys(&input.tool_input),
        },
        intent: Intent {
            active_task: None,
            user_prompt: prompt_for_hook(input),
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
        "Read" | "read_file" => "file.read",
        "Write" | "Edit" | "write_file" => "file.write",
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
        "file.read" => "code_file",
        "file.write" => "code_file",
        "mcp.call" => "mcp_tool",
        _ => "tool_call",
    }
}

fn target_for_tool(input: &CodexHookInput) -> String {
    match input.tool_name.as_str() {
        "Bash" => string_field(&input.tool_input, "command").unwrap_or_default(),
        "apply_patch" => extract_patch_paths(input)
            .first()
            .cloned()
            .unwrap_or_else(|| String::from("apply_patch")),
        "Read" | "Write" | "Edit" | "read_file" | "write_file" => {
            string_field(&input.tool_input, "file_path")
                .or_else(|| string_field(&input.tool_input, "path"))
                .unwrap_or_default()
        }
        name if name.starts_with("mcp__") => mcp_target(name),
        _ => input.tool_name.clone(),
    }
}

fn targets_for_tool(input: &CodexHookInput, target: &str) -> Vec<String> {
    if input.tool_name == "apply_patch" {
        extract_patch_paths(input)
    } else if matches!(
        input.tool_name.as_str(),
        "Read" | "Write" | "Edit" | "read_file" | "write_file"
    ) {
        vec![target.to_string()]
    } else {
        vec![target.to_string()]
    }
}

fn diff_summary_for_tool(input: &CodexHookInput) -> Option<String> {
    if input.tool_name == "apply_patch" {
        Some(String::from("Codex apply_patch content omitted"))
    } else if input.tool_name.starts_with("mcp__") {
        Some(format!(
            "Codex MCP tool call: {}",
            mcp_tool_name(&input.tool_name)
        ))
    } else if matches!(input.tool_name.as_str(), "Write" | "Edit" | "write_file") {
        Some(String::from("Codex file content omitted"))
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

fn prompt_for_hook(input: &CodexHookInput) -> Option<String> {
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
    let name = tool_name.split("__").skip(2).collect::<Vec<_>>().join("__");
    if name.is_empty() {
        tool_name.to_string()
    } else {
        name
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

fn extract_patch_paths(input: &CodexHookInput) -> Vec<String> {
    let Some(patch) = patch_text(input) else {
        return Vec::new();
    };
    let mut paths = Vec::new();
    for line in patch.lines() {
        if let Some(path) = line.strip_prefix("*** Update File: ") {
            paths.push(path.trim().to_string());
        } else if let Some(path) = line.strip_prefix("*** Add File: ") {
            paths.push(path.trim().to_string());
        } else if let Some(path) = line.strip_prefix("*** Delete File: ") {
            paths.push(path.trim().to_string());
        } else if let Some(path) = line.strip_prefix("*** Move to: ") {
            paths.push(path.trim().to_string());
        }
    }

    paths.retain(|path| !path.is_empty());
    paths.sort();
    paths.dedup();
    paths
}

fn patch_text(input: &CodexHookInput) -> Option<String> {
    if let Some(value) = input.tool_input.as_str() {
        return Some(value.to_string());
    }

    ["patch", "input", "cmd", "command"]
        .into_iter()
        .find_map(|field| string_field(&input.tool_input, field))
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
        assert_eq!(acp.action.targets, vec![String::from("rm -rf ~")]);
    }

    #[test]
    fn normalizes_apply_patch_paths_without_patch_content() {
        let input = CodexHookInput {
            session_id: String::from("s1"),
            cwd: Some(String::from("/repo")),
            hook_event_name: String::from("PreToolUse"),
            tool_name: String::from("apply_patch"),
            tool_input: json!({
                "cmd": "*** Begin Patch\n*** Update File: .env.production\n-secret\n+secret\n*** Add File: src/auth/session.rs\n+pub fn ok() {}\n*** End Patch\n"
            }),
            tool_use_id: Some(String::from("toolu_1")),
            model: Some(String::from("gpt-5.5")),
            turn_id: Some(String::from("t1")),
        };

        let acp = normalize_pretooluse(&input);

        assert_eq!(acp.action.action_type, "file.write");
        assert_eq!(acp.action.target, ".env.production");
        assert_eq!(
            acp.action.targets,
            vec![
                String::from(".env.production"),
                String::from("src/auth/session.rs")
            ]
        );
        assert_eq!(
            acp.action.diff_summary.as_deref(),
            Some("Codex apply_patch content omitted")
        );
    }

    #[test]
    fn normalizes_mcp_call_with_safe_argument_keys() {
        let input = CodexHookInput {
            session_id: String::from("s1"),
            cwd: Some(String::from("/repo")),
            hook_event_name: String::from("PreToolUse"),
            tool_name: String::from("mcp__prod__delete_project"),
            tool_input: json!({
                "arguments": {
                    "project_id": "prod-123",
                    "confirm_destroy": true,
                    "password": "ignored"
                }
            }),
            tool_use_id: Some(String::from("toolu_1")),
            model: Some(String::from("gpt-5.5")),
            turn_id: Some(String::from("t1")),
        };

        let acp = normalize_pretooluse(&input);

        assert_eq!(acp.action.action_type, "mcp.call");
        assert_eq!(acp.action.target, "prod:delete_project");
        assert_eq!(
            acp.action.diff_summary.as_deref(),
            Some("Codex MCP tool call: delete_project")
        );
        assert_eq!(
            acp.action.argument_keys,
            vec![String::from("confirm_destroy"), String::from("project_id")]
        );
        let serialized = serde_json::to_string(&acp).expect("acp serializes");
        assert!(!serialized.contains("prod-123"));
        assert!(!serialized.contains("ignored"));
    }

    #[test]
    fn normalizes_file_read_write_tool_payloads() {
        let input = CodexHookInput {
            session_id: String::from("s1"),
            cwd: Some(String::from("/repo")),
            hook_event_name: String::from("PreToolUse"),
            tool_name: String::from("Read"),
            tool_input: json!({ "path": "src/lib.rs" }),
            tool_use_id: Some(String::from("toolu_1")),
            model: Some(String::from("gpt-5.5")),
            turn_id: Some(String::from("t1")),
        };

        let acp = normalize_pretooluse(&input);

        assert_eq!(acp.action.action_type, "file.read");
        assert_eq!(acp.action.target, "src/lib.rs");
    }
}
