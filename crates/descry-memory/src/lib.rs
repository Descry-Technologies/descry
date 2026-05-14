use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub scope: String,
    pub created_at_epoch_seconds: u64,
    pub expires_at_epoch_seconds: u64,
    pub approver: String,
}

impl Approval {
    pub fn is_live_at(&self, now_epoch_seconds: u64) -> bool {
        self.expires_at_epoch_seconds > now_epoch_seconds
    }

    pub fn matches_target(&self, target: &str, now_epoch_seconds: u64) -> bool {
        self.matches_path_target(target, now_epoch_seconds)
    }

    pub fn matches_path_target(&self, target: &str, now_epoch_seconds: u64) -> bool {
        self.is_live_at(now_epoch_seconds)
            && matches!(self.parsed_scope().kind, ApprovalScopeKind::Path)
            && scope_matches(&self.parsed_scope().pattern, target)
    }

    pub fn matches_mcp_target(&self, target: &str, now_epoch_seconds: u64) -> bool {
        self.is_live_at(now_epoch_seconds)
            && matches!(self.parsed_scope().kind, ApprovalScopeKind::Mcp)
            && scope_matches(&self.parsed_scope().pattern, target)
    }

    pub fn matches_action(&self, action: &str, now_epoch_seconds: u64) -> bool {
        self.is_live_at(now_epoch_seconds)
            && matches!(self.parsed_scope().kind, ApprovalScopeKind::Action)
            && scope_matches(&self.parsed_scope().pattern, action)
    }

    pub fn matches_rule(&self, rule: &str, now_epoch_seconds: u64) -> bool {
        self.is_live_at(now_epoch_seconds)
            && matches!(self.parsed_scope().kind, ApprovalScopeKind::Rule)
            && scope_matches(&self.parsed_scope().pattern, rule)
    }

    pub fn matches_once(&self, acp_hash: &str, now_epoch_seconds: u64) -> bool {
        self.is_live_at(now_epoch_seconds)
            && matches!(self.parsed_scope().kind, ApprovalScopeKind::Once)
            && self.parsed_scope().pattern == acp_hash
    }

    fn parsed_scope(&self) -> ApprovalScope {
        ApprovalScope::parse(&self.scope)
    }
}

pub fn append_approval(path: &Path, approval: &Approval) -> Result<(), MemoryError> {
    if approval.expires_at_epoch_seconds <= approval.created_at_epoch_seconds {
        return Err(MemoryError::InvalidApproval(String::from(
            "approval expiry must be after creation",
        )));
    }
    if approval.scope.trim().is_empty() {
        return Err(MemoryError::InvalidApproval(String::from(
            "approval scope cannot be empty",
        )));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    serde_json::to_writer(&mut file, approval)?;
    file.write_all(b"\n")?;
    file.flush()?;
    file.sync_data()?;
    Ok(())
}

pub fn load_approvals(path: &Path) -> Result<Vec<Approval>, MemoryError> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let file = OpenOptions::new().read(true).open(path)?;
    let mut approvals = Vec::new();
    for (index, line) in BufReader::new(file).lines().enumerate() {
        let line_number = index as u64 + 1;
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let approval =
            serde_json::from_str(&line).map_err(|error| MemoryError::MalformedRecord {
                line: line_number,
                reason: error.to_string(),
            })?;
        approvals.push(approval);
    }
    Ok(approvals)
}

pub fn live_approvals(path: &Path, now_epoch_seconds: u64) -> Result<Vec<Approval>, MemoryError> {
    Ok(load_approvals(path)?
        .into_iter()
        .filter(|approval| approval.is_live_at(now_epoch_seconds))
        .collect())
}

pub fn has_live_approval_for_target(
    path: &Path,
    target: &str,
    now_epoch_seconds: u64,
) -> Result<bool, MemoryError> {
    has_live_approval_for_path(path, target, now_epoch_seconds)
}

pub fn has_live_approval_for_path(
    path: &Path,
    target: &str,
    now_epoch_seconds: u64,
) -> Result<bool, MemoryError> {
    Ok(load_approvals(path)?
        .iter()
        .any(|approval| approval.matches_path_target(target, now_epoch_seconds)))
}

pub fn has_live_approval_for_mcp(
    path: &Path,
    target: &str,
    now_epoch_seconds: u64,
) -> Result<bool, MemoryError> {
    Ok(load_approvals(path)?
        .iter()
        .any(|approval| approval.matches_mcp_target(target, now_epoch_seconds)))
}

pub fn has_live_approval_for_action(
    path: &Path,
    action: &str,
    now_epoch_seconds: u64,
) -> Result<bool, MemoryError> {
    Ok(load_approvals(path)?
        .iter()
        .any(|approval| approval.matches_action(action, now_epoch_seconds)))
}

pub fn has_live_approval_for_rule(
    path: &Path,
    rule: &str,
    now_epoch_seconds: u64,
) -> Result<bool, MemoryError> {
    Ok(load_approvals(path)?
        .iter()
        .any(|approval| approval.matches_rule(rule, now_epoch_seconds)))
}

pub fn has_live_approval_for_once(
    path: &Path,
    acp_hash: &str,
    now_epoch_seconds: u64,
) -> Result<bool, MemoryError> {
    Ok(load_approvals(path)?
        .iter()
        .any(|approval| approval.matches_once(acp_hash, now_epoch_seconds)))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AssetPolicy {
    #[serde(default)]
    pub assets: Vec<AssetRule>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AssetRule {
    pub id: String,
    pub paths: Vec<String>,
    pub sensitivity: String,
    #[serde(default = "default_require_approval")]
    pub default_action: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssetMatch {
    pub id: String,
    pub sensitivity: String,
    pub default_action: String,
}

pub fn load_asset_policy(path: &Path) -> Result<AssetPolicy, MemoryError> {
    if !path.exists() {
        return Ok(default_asset_policy());
    }

    let body = fs::read_to_string(path)?;
    serde_yml::from_str(&body).map_err(MemoryError::Yaml)
}

pub fn match_asset(policy: &AssetPolicy, target: &str) -> Option<AssetMatch> {
    policy.assets.iter().find_map(|asset| {
        if asset.paths.iter().any(|path| scope_matches(path, target)) {
            Some(AssetMatch {
                id: asset.id.clone(),
                sensitivity: asset.sensitivity.clone(),
                default_action: asset.default_action.clone(),
            })
        } else {
            None
        }
    })
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BehaviorStore {
    #[serde(default)]
    pub counters: Vec<BehaviorCounter>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BehaviorCounter {
    pub actor: String,
    pub action_type: String,
    pub target: String,
    pub count: u64,
    pub last_seen_epoch_seconds: u64,
}

pub fn load_behavior_store(path: &Path) -> Result<BehaviorStore, MemoryError> {
    if !path.exists() {
        return Ok(BehaviorStore {
            counters: Vec::new(),
        });
    }

    let body = fs::read_to_string(path)?;
    serde_json::from_str(&body).map_err(MemoryError::Serde)
}

pub fn behavior_count(
    path: &Path,
    actor: &str,
    action_type: &str,
    target: &str,
) -> Result<u64, MemoryError> {
    Ok(load_behavior_store(path)?
        .counters
        .into_iter()
        .find(|counter| {
            counter.actor == actor && counter.action_type == action_type && counter.target == target
        })
        .map_or(0, |counter| counter.count))
}

pub fn record_behavior(
    path: &Path,
    actor: &str,
    action_type: &str,
    target: &str,
    now_epoch_seconds: u64,
) -> Result<BehaviorCounter, MemoryError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut store = load_behavior_store(path)?;
    let updated = if let Some(counter) = store.counters.iter_mut().find(|counter| {
        counter.actor == actor && counter.action_type == action_type && counter.target == target
    }) {
        counter.count += 1;
        counter.last_seen_epoch_seconds = now_epoch_seconds;
        counter.clone()
    } else {
        let counter = BehaviorCounter {
            actor: actor.to_string(),
            action_type: action_type.to_string(),
            target: target.to_string(),
            count: 1,
            last_seen_epoch_seconds: now_epoch_seconds,
        };
        store.counters.push(counter.clone());
        counter
    };

    let body = serde_json::to_string_pretty(&store)?;
    fs::write(path, format!("{body}\n"))?;
    Ok(updated)
}

fn default_asset_policy() -> AssetPolicy {
    AssetPolicy {
        assets: vec![
            AssetRule {
                id: String::from("descry-config"),
                paths: vec![String::from(".descry/**")],
                sensitivity: String::from("critical"),
                default_action: String::from("block"),
            },
            AssetRule {
                id: String::from("descry-engine"),
                paths: vec![String::from("crates/descry-engine/**")],
                sensitivity: String::from("high"),
                default_action: String::from("require_approval"),
            },
            AssetRule {
                id: String::from("descry-policy"),
                paths: vec![String::from("crates/descry-policy/**")],
                sensitivity: String::from("high"),
                default_action: String::from("require_approval"),
            },
            AssetRule {
                id: String::from("descry-memory"),
                paths: vec![String::from("crates/descry-memory/**")],
                sensitivity: String::from("high"),
                default_action: String::from("require_approval"),
            },
        ],
    }
}

fn default_require_approval() -> String {
    String::from("require_approval")
}

fn scope_matches(scope: &str, target: &str) -> bool {
    if scope == "*" || scope == target {
        return true;
    }
    if let Some(prefix) = scope.strip_suffix("/**") {
        return target == prefix || target.starts_with(&format!("{prefix}/"));
    }
    if let Some(prefix) = scope.strip_suffix('*') {
        return target.starts_with(prefix);
    }
    false
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ApprovalScope {
    kind: ApprovalScopeKind,
    pattern: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ApprovalScopeKind {
    Path,
    Action,
    Mcp,
    Rule,
    Once,
}

impl ApprovalScope {
    fn parse(scope: &str) -> Self {
        let trimmed = scope.trim();
        if let Some((prefix, pattern)) = trimmed.split_once(':') {
            let kind = match prefix {
                "path" => Some(ApprovalScopeKind::Path),
                "action" => Some(ApprovalScopeKind::Action),
                "mcp" => Some(ApprovalScopeKind::Mcp),
                "rule" => Some(ApprovalScopeKind::Rule),
                "once" => Some(ApprovalScopeKind::Once),
                _ => None,
            };
            if let Some(kind) = kind {
                return Self {
                    kind,
                    pattern: pattern.trim().to_string(),
                };
            }
        }

        Self {
            kind: if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
                ApprovalScopeKind::Mcp
            } else {
                ApprovalScopeKind::Path
            },
            pattern: trimmed.to_string(),
        }
    }
}

#[derive(Debug)]
pub enum MemoryError {
    Io(std::io::Error),
    Serde(serde_json::Error),
    Yaml(serde_yml::Error),
    MalformedRecord { line: u64, reason: String },
    InvalidApproval(String),
}

impl std::fmt::Display for MemoryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "io error: {error}"),
            Self::Serde(error) => write!(formatter, "json error: {error}"),
            Self::Yaml(error) => write!(formatter, "yaml error: {error}"),
            Self::MalformedRecord { line, reason } => {
                write!(formatter, "malformed record at line {line}: {reason}")
            }
            Self::InvalidApproval(reason) => write!(formatter, "invalid approval: {reason}"),
        }
    }
}

impl std::error::Error for MemoryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Serde(error) => Some(error),
            Self::Yaml(error) => Some(error),
            Self::MalformedRecord { .. } | Self::InvalidApproval(_) => None,
        }
    }
}

impl From<std::io::Error> for MemoryError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for MemoryError {
    fn from(error: serde_json::Error) -> Self {
        Self::Serde(error)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{
        append_approval, behavior_count, has_live_approval_for_action, has_live_approval_for_mcp,
        has_live_approval_for_path, has_live_approval_for_rule, has_live_approval_for_target,
        live_approvals, load_asset_policy, match_asset, record_behavior, Approval,
    };

    #[test]
    fn appends_and_loads_live_approval() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("approvals.jsonl");
        let approval = Approval {
            scope: String::from("crates/descry-cli/**"),
            created_at_epoch_seconds: 100,
            expires_at_epoch_seconds: 200,
            approver: String::from("human"),
        };

        append_approval(&path, &approval).expect("approval appends");

        assert_eq!(
            live_approvals(&path, 150).expect("approvals load"),
            vec![approval]
        );
        assert!(
            has_live_approval_for_target(&path, "crates/descry-cli/src/lib.rs", 150)
                .expect("approval matches")
        );
        assert!(
            !has_live_approval_for_target(&path, "crates/descry-core/src/lib.rs", 150)
                .expect("approval does not match")
        );
    }

    #[test]
    fn typed_approvals_are_narrow() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("approvals.jsonl");
        for scope in [
            "path:src/auth/**",
            "mcp:https://prod-mcp.example.com/**",
            "action:deploy",
            "rule:mcp-destructive-tool",
        ] {
            append_approval(
                &path,
                &Approval {
                    scope: scope.to_string(),
                    created_at_epoch_seconds: 100,
                    expires_at_epoch_seconds: 200,
                    approver: String::from("human"),
                },
            )
            .expect("approval appends");
        }

        assert!(
            has_live_approval_for_path(&path, "src/auth/session.rs", 150)
                .expect("path approval matches")
        );
        assert!(
            !has_live_approval_for_path(&path, "src/billing/invoice.rs", 150)
                .expect("path approval does not match")
        );
        assert!(
            has_live_approval_for_mcp(&path, "https://prod-mcp.example.com/admin", 150)
                .expect("mcp approval matches")
        );
        assert!(
            !has_live_approval_for_mcp(&path, "src/auth/session.rs", 150)
                .expect("path approval does not match mcp")
        );
        assert!(
            has_live_approval_for_action(&path, "deploy", 150).expect("action approval matches")
        );
        assert!(
            has_live_approval_for_rule(&path, "mcp-destructive-tool", 150)
                .expect("rule approval matches")
        );
    }

    #[test]
    fn filters_expired_approval() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("approvals.jsonl");
        append_approval(
            &path,
            &Approval {
                scope: String::from("*"),
                created_at_epoch_seconds: 100,
                expires_at_epoch_seconds: 120,
                approver: String::from("human"),
            },
        )
        .expect("approval appends");

        assert!(live_approvals(&path, 121)
            .expect("approvals load")
            .is_empty());
    }

    #[test]
    fn loads_custom_asset_policy_and_matches_target() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("policy.yml");
        fs::write(
            &path,
            r#"
assets:
  - id: auth-system
    paths:
      - "src/auth/**"
    sensitivity: high
    default_action: require_approval
"#,
        )
        .expect("policy writes");

        let policy = load_asset_policy(&path).expect("policy loads");
        let asset = match_asset(&policy, "src/auth/session.rs").expect("asset matches");

        assert_eq!(asset.id, "auth-system");
        assert_eq!(asset.default_action, "require_approval");
    }

    #[test]
    fn missing_asset_policy_uses_default_sensitive_assets() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let policy = load_asset_policy(&tempdir.path().join("missing.yml")).expect("policy loads");

        assert!(match_asset(&policy, "crates/descry-engine/src/lib.rs").is_some());
    }

    #[test]
    fn records_behavior_counters() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("behavior.json");

        let first = record_behavior(&path, "claude-code", "file.write", "src/auth.rs", 100)
            .expect("behavior records");
        let second = record_behavior(&path, "claude-code", "file.write", "src/auth.rs", 120)
            .expect("behavior records");

        assert_eq!(first.count, 1);
        assert_eq!(second.count, 2);
        assert_eq!(
            behavior_count(&path, "claude-code", "file.write", "src/auth.rs")
                .expect("behavior reads"),
            2
        );
    }
}
