use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{ActionContextPacket, DecisionOutput, InstructionProvenance};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftSignal {
    None,
    Suspicious,
    HighConfidence,
}

impl DriftSignal {
    pub fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Suspicious => "suspicious",
            Self::HighConfidence => "high_confidence",
        }
    }
}

/// Classify the drift signal for a decision input.
///
/// Pure function — no I/O, no network, no LLM.
pub fn classify_drift_signal(
    action_class: &ActionClass,
    blast_radius_reversible: bool,
    instruction_provenance: Option<InstructionProvenance>,
    asset_sensitivity: Option<&str>,
    task_confidence: f32,
) -> DriftSignal {
    let provenance = instruction_provenance.unwrap_or(InstructionProvenance::AgentReasoning);

    let external_provenance = matches!(
        provenance,
        InstructionProvenance::ToolOutput
            | InstructionProvenance::RepoContent
            | InstructionProvenance::WebContent
    );

    if !external_provenance {
        return DriftSignal::None;
    }

    let destructive = matches!(
        action_class,
        ActionClass::ShellDelete
            | ActionClass::CloudDelete
            | ActionClass::DatabaseDestroy
            | ActionClass::McpDestroy
            | ActionClass::GitRewrite
    );

    let production_sensitive = asset_sensitivity
        .map(|s| matches!(s, "critical" | "high"))
        .unwrap_or(false);

    if destructive && (!blast_radius_reversible || production_sensitive) {
        return DriftSignal::HighConfidence;
    }

    // Irreversible action with unrecognized class from external provenance — the classifier
    // couldn't name it, but the blast-radius flag makes the intent explicit.
    if !blast_radius_reversible && matches!(action_class, ActionClass::Unknown) {
        return DriftSignal::HighConfidence;
    }

    if task_confidence < 0.5 && destructive {
        return DriftSignal::Suspicious;
    }

    if external_provenance
        && matches!(
            action_class,
            ActionClass::ShellDelete
                | ActionClass::CloudDelete
                | ActionClass::DatabaseDestroy
                | ActionClass::McpDestroy
        )
    {
        return DriftSignal::Suspicious;
    }

    DriftSignal::None
}

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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssetGraphNode {
    pub id: String,
    pub asset_type: String,
    pub sensitivity: String,
    pub environment: String,
    pub default_action: String,
    pub patterns: Vec<String>,
    pub evidence: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DecisionInput {
    pub acp: ActionContextPacket,
    pub event: Option<serde_json::Value>,
    pub task: TaskEnvelope,
    pub action: ClassifiedAction,
    pub asset: Option<AssetMatch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instruction_provenance: Option<crate::InstructionProvenance>,
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

pub struct TaskEnvelopeBuilder<'a> {
    acp: &'a ActionContextPacket,
    matched_asset: Option<String>,
    matched_policy: Option<String>,
}

impl<'a> TaskEnvelopeBuilder<'a> {
    pub fn new(acp: &'a ActionContextPacket) -> Self {
        Self {
            acp,
            matched_asset: None,
            matched_policy: None,
        }
    }

    pub fn matched_asset(mut self, matched_asset: Option<String>) -> Self {
        self.matched_asset = matched_asset;
        self
    }

    pub fn matched_policy(mut self, matched_policy: Option<String>) -> Self {
        self.matched_policy = matched_policy;
        self
    }

    pub fn build(self) -> TaskEnvelope {
        let acp = self.acp;
        let summary = acp
            .intent
            .active_task
            .clone()
            .or_else(|| acp.intent.user_prompt.clone())
            .unwrap_or_else(|| inferred_summary(acp));
        let sources = task_sources(acp);
        let likely_paths = likely_paths(acp);
        let likely_terms = likely_terms(acp);
        let target_text = action_match_text(acp);
        let mut matched_terms = Vec::new();
        let mut matched_paths = Vec::new();
        let mut matched_context_sources = Vec::new();

        collect_term_matches(
            &mut matched_terms,
            &mut matched_context_sources,
            TaskSource::ActiveTask,
            acp.intent.active_task.as_deref(),
            &target_text,
        );
        collect_term_matches(
            &mut matched_terms,
            &mut matched_context_sources,
            TaskSource::UserPrompt,
            acp.intent.user_prompt.as_deref(),
            &target_text,
        );
        collect_term_matches(
            &mut matched_terms,
            &mut matched_context_sources,
            TaskSource::Branch,
            Some(&acp.context.branch),
            &target_text,
        );
        for recent_file in &acp.context.recent_files {
            if path_matches_target(recent_file, &acp.action.target) {
                matched_paths.push(recent_file.clone());
                matched_context_sources.push(TaskSource::RecentFiles);
            }
            collect_term_matches(
                &mut matched_terms,
                &mut matched_context_sources,
                TaskSource::RecentFiles,
                Some(recent_file),
                &target_text,
            );
        }

        matched_terms.sort();
        matched_terms.dedup();
        matched_paths.sort();
        matched_paths.dedup();
        matched_context_sources.sort_by_key(|source| format!("{source:?}"));
        matched_context_sources.dedup();

        let confidence = match (
            acp.intent.active_task.is_some(),
            acp.intent.user_prompt.is_some(),
            matched_paths.is_empty(),
            matched_terms.is_empty(),
        ) {
            (true, _, false, _) => 0.85,
            (true, _, _, false) => 0.75,
            (_, true, false, false) => 0.7,
            (_, true, _, false) => 0.6,
            (_, _, false, _) => 0.5,
            (_, _, _, false) => 0.4,
            _ => 0.2,
        };

        TaskEnvelope {
            summary,
            confidence,
            sources,
            likely_paths,
            likely_terms,
            matched_context_sources,
            matched_terms,
            matched_paths,
            matched_asset: self.matched_asset,
            matched_policy: self.matched_policy,
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

fn action_match_text(acp: &ActionContextPacket) -> String {
    format!(
        "{} {}",
        acp.action.target,
        acp.action.diff_summary.as_deref().unwrap_or_default()
    )
    .to_ascii_lowercase()
}

fn collect_term_matches(
    matched_terms: &mut Vec<String>,
    matched_sources: &mut Vec<TaskSource>,
    source: TaskSource,
    value: Option<&str>,
    target_text: &str,
) {
    let Some(value) = value else {
        return;
    };
    for term in split_terms(value) {
        if term.len() >= 3 && term != "unknown" && target_text.contains(&term) {
            matched_terms.push(term);
            matched_sources.push(source.clone());
        }
    }
}

fn path_matches_target(candidate: &str, target: &str) -> bool {
    if candidate == target {
        return true;
    }

    let candidate_dir = candidate.rsplit_once('/').map(|(dir, _)| dir);
    let target_dir = target.rsplit_once('/').map(|(dir, _)| dir);
    candidate_dir.is_some() && candidate_dir == target_dir
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeContextConfig {
    pub project_root: PathBuf,
    pub context_path: PathBuf,
    pub state_dir: PathBuf,
    pub project_index_path: PathBuf,
    pub project_policy_path: PathBuf,
    pub policy_path: PathBuf,
    pub approvals_path: PathBuf,
    pub behavior_path: PathBuf,
    pub audit_path: Option<PathBuf>,
    pub repo_id_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_asset_policy_path: Option<PathBuf>,
}

pub fn enrich_action_context(
    mut acp: ActionContextPacket,
    config: &RuntimeContextConfig,
) -> std::io::Result<ActionContextPacket> {
    if let Ok(index) = read_project_index_summary(&config.project_index_path) {
        if acp.context.branch == "unknown" || acp.context.branch.trim().is_empty() {
            if let Some(branch) = index.branch {
                acp.context.branch = branch;
            }
        }
        if acp.context.repo == "unknown" || acp.context.repo.trim().is_empty() {
            if let Some(repo_name) = index.repo_name {
                acp.context.repo = repo_name;
            }
        }
    }

    if let Some(active_task) = read_active_task(&config.context_path)? {
        acp.intent.active_task = Some(active_task);
    }

    let mut recent_files = acp.context.recent_files.clone();
    recent_files.extend(read_recent_file_targets(&config.state_dir)?);
    recent_files.retain(|target| !target.trim().is_empty());
    recent_files.sort();
    recent_files.dedup();
    acp.context.recent_files = recent_files;

    Ok(acp)
}

pub fn append_runtime_session_event(
    config: &RuntimeContextConfig,
    session_id: Option<&str>,
    acp: &ActionContextPacket,
    decision: &DecisionOutput,
) -> std::io::Result<()> {
    let event = serde_json::json!({
        "timestamp_unix": current_epoch_seconds()?,
        "session_id": session_id,
        "harness": acp.actor.name,
        "user_prompt": acp.intent.user_prompt.as_deref().map(sanitize_prompt),
        "action_type": acp.action.action_type,
        "target": sanitized_event_target(&acp.action.action_type, &acp.action.target),
        "decision": decision_name(decision),
    });

    append_bounded_jsonl(&config.state_dir.join("recent-actions.jsonl"), &event, 200)?;
    append_bounded_jsonl(
        &config
            .state_dir
            .join("sessions")
            .join(format!("{}.jsonl", session_file_id(session_id))),
        &event,
        200,
    )
}

fn read_active_task(path: &Path) -> std::io::Result<Option<String>> {
    if !path.exists() {
        return Ok(None);
    }
    let body = fs::read_to_string(path)?;
    Ok(body.lines().find_map(|line| {
        line.strip_prefix("Active task:")
            .map(str::trim)
            .filter(|task| !task.is_empty())
            .map(ToString::to_string)
    }))
}

#[derive(Debug)]
struct ProjectIndexSummary {
    repo_name: Option<String>,
    branch: Option<String>,
}

fn read_project_index_summary(path: &Path) -> std::io::Result<ProjectIndexSummary> {
    let body = fs::read_to_string(path)?;
    let value: serde_json::Value = serde_json::from_str(&body)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    Ok(ProjectIndexSummary {
        repo_name: value
            .get("repo_name")
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string),
        branch: value
            .get("branch")
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string),
    })
}

fn read_recent_file_targets(state_dir: &Path) -> std::io::Result<Vec<String>> {
    let path = state_dir.join("recent-actions.jsonl");
    if !path.exists() {
        return Ok(Vec::new());
    }

    let file = OpenOptions::new().read(true).open(path)?;
    let mut targets = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line?;
        // Skip blank lines and null-byte corruption from concurrent writes.
        let trimmed = line.trim_matches('\0').trim();
        if trimmed.is_empty() || !trimmed.starts_with('{') {
            continue;
        }
        let Ok(event) = serde_json::from_str::<serde_json::Value>(trimmed) else {
            continue;
        };
        let action_type = event
            .get("action_type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        if !action_type.starts_with("file.") {
            continue;
        }
        if let Some(target) = event.get("target").and_then(serde_json::Value::as_str) {
            targets.push(target.to_string());
        }
    }
    targets.reverse();
    targets.truncate(20);
    targets.reverse();
    Ok(targets)
}

fn append_bounded_jsonl(
    path: &Path,
    event: &serde_json::Value,
    max_records: usize,
) -> std::io::Result<()> {
    let mut records = read_jsonl_values(path).unwrap_or_default();
    records.push(event.clone());
    if records.len() > max_records {
        records = records.split_off(records.len() - max_records);
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    for record in records {
        serde_json::to_writer(&mut file, &record)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        file.write_all(b"\n")?;
    }
    file.flush()
}

fn read_jsonl_values(path: &Path) -> std::io::Result<Vec<serde_json::Value>> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let file = OpenOptions::new().read(true).open(path)?;
    let mut records = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let event = serde_json::from_str(&line)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        records.push(event);
    }
    Ok(records)
}

fn current_epoch_seconds() -> std::io::Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(std::io::Error::other)
}

fn sanitized_event_target(action_type: &str, target: &str) -> String {
    match action_type {
        "shell.exec" => String::from("<shell command omitted>"),
        "mcp.call" => target.to_string(),
        _ => target.to_string(),
    }
}

fn sanitize_prompt(prompt: &str) -> String {
    prompt
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(512)
        .collect()
}

fn decision_name(decision: &DecisionOutput) -> &'static str {
    match decision.decision {
        crate::Decision::Allow => "allow",
        crate::Decision::AllowWithLog => "allow_with_log",
        crate::Decision::Ask => "ask",
        crate::Decision::RequireApproval => "require_approval",
        crate::Decision::Block => "block",
    }
}

fn session_file_id(session_id: Option<&str>) -> String {
    let raw = session_id.unwrap_or("unknown");
    let sanitized: String = raw
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect();
    if sanitized.is_empty() {
        String::from("unknown")
    } else {
        sanitized
    }
}
