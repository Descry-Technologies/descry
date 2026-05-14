use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::ActionContextPacket;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionClass {
    FileRead,
    FileWrite,
    ShellTest,
    ShellBuild,
    ShellInstall,
    ShellDelete,
    GitRead,
    GitRewrite,
    SecretRead,
    DatabaseDestroy,
    CloudDelete,
    Deploy,
    McpRead,
    McpWrite,
    McpDestroy,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClassifiedAction {
    pub class: ActionClass,
    pub target: String,
    pub reversible: bool,
    pub destructive: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskSource {
    ActiveTask,
    UserPrompt,
    Branch,
    RecentFiles,
    StaticPolicy,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct TaskEnvelope {
    pub summary: String,
    pub confidence: f32,
    pub sources: Vec<TaskSource>,
    pub likely_paths: Vec<String>,
    pub likely_terms: Vec<String>,
    pub matched_context_sources: Vec<TaskSource>,
    pub matched_terms: Vec<String>,
    pub matched_paths: Vec<String>,
    pub matched_asset: Option<String>,
    pub matched_policy: Option<String>,
    pub allowed_action_classes: Vec<ActionClass>,
    pub suspicious_action_classes: Vec<ActionClass>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AssetMatch {
    pub id: String,
    pub sensitivity: String,
    pub default_action: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DecisionInput {
    pub acp: ActionContextPacket,
    pub event: Option<serde_json::Value>,
    pub task: TaskEnvelope,
    pub action: ClassifiedAction,
    pub asset: Option<AssetMatch>,
}

impl TaskEnvelope {
    pub fn from_acp(acp: &ActionContextPacket) -> Self {
        let summary = acp
            .intent
            .active_task
            .clone()
            .unwrap_or_else(|| inferred_summary(acp));
        let sources = task_sources(acp);
        let likely_paths = likely_paths(acp);
        let likely_terms = likely_terms(acp);
        let confidence = if acp.intent.active_task.is_some() {
            0.7
        } else if acp.intent.user_prompt.is_some() {
            0.6
        } else if !likely_paths.is_empty() || !likely_terms.is_empty() {
            0.45
        } else {
            0.2
        };

        Self {
            summary,
            confidence,
            sources: sources.clone(),
            likely_paths: likely_paths.clone(),
            likely_terms: likely_terms.clone(),
            matched_context_sources: sources.clone(),
            matched_terms: likely_terms,
            matched_paths: likely_paths,
            matched_asset: None,
            matched_policy: None,
            allowed_action_classes: vec![ActionClass::FileRead, ActionClass::ShellTest],
            suspicious_action_classes: vec![
                ActionClass::ShellDelete,
                ActionClass::GitRewrite,
                ActionClass::DatabaseDestroy,
                ActionClass::CloudDelete,
                ActionClass::McpDestroy,
            ],
        }
    }
}

fn inferred_summary(acp: &ActionContextPacket) -> String {
    if let Some(prompt) = acp.intent.user_prompt.as_deref() {
        prompt.to_string()
    } else if acp.context.branch != "unknown" && !acp.context.branch.trim().is_empty() {
        acp.context.branch.clone()
    } else if !acp.context.recent_files.is_empty() {
        format!("recent work near {}", acp.context.recent_files.join(", "))
    } else {
        String::from("unknown task")
    }
}

fn task_sources(acp: &ActionContextPacket) -> Vec<TaskSource> {
    let mut sources = Vec::new();
    if acp.intent.active_task.is_some() {
        sources.push(TaskSource::ActiveTask);
    }
    if acp.intent.user_prompt.is_some() {
        sources.push(TaskSource::UserPrompt);
    }
    if acp.context.branch != "unknown" && !acp.context.branch.trim().is_empty() {
        sources.push(TaskSource::Branch);
    }
    if !acp.context.recent_files.is_empty() {
        sources.push(TaskSource::RecentFiles);
    }
    if sources.is_empty() {
        sources.push(TaskSource::Unknown);
    }
    sources
}

fn likely_paths(acp: &ActionContextPacket) -> Vec<String> {
    let mut paths = acp.context.recent_files.clone();
    paths.sort();
    paths.dedup();
    paths
}

fn likely_terms(acp: &ActionContextPacket) -> Vec<String> {
    let mut terms = Vec::new();
    if let Some(task) = acp.intent.active_task.as_deref() {
        terms.extend(split_terms(task));
    }
    if let Some(prompt) = acp.intent.user_prompt.as_deref() {
        terms.extend(split_terms(prompt));
    }
    terms.extend(split_terms(&acp.context.branch));
    for path in &acp.context.recent_files {
        terms.extend(path_terms(path));
    }

    terms.retain(|term| term.len() >= 3 && term != "unknown");
    terms.sort();
    terms.dedup();
    terms
}

fn split_terms(value: &str) -> Vec<String> {
    value
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|term| !term.is_empty())
        .map(|term| term.to_ascii_lowercase())
        .collect()
}

fn path_terms(path: &str) -> Vec<String> {
    split_terms(path)
        .into_iter()
        .filter(|term| !matches!(term.as_str(), "src" | "tests" | "crates" | "app" | "pages"))
        .collect()
}

impl ClassifiedAction {
    pub fn unknown_from_acp(acp: &ActionContextPacket) -> Self {
        Self {
            class: ActionClass::Unknown,
            target: acp.action.target.clone(),
            reversible: acp.blast_radius.reversible,
            destructive: !acp.blast_radius.reversible,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct HarnessEvent {
    pub cwd: PathBuf,
    pub tool_name: String,
}
