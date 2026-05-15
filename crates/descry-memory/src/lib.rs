use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use descry_core::ScopeContract;
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
        ApprovalScope::parse_lossy(&self.scope)
    }
}

pub fn append_approval(path: &Path, approval: &Approval) -> Result<(), MemoryError> {
    if approval.expires_at_epoch_seconds <= approval.created_at_epoch_seconds {
        return Err(MemoryError::InvalidApproval(String::from(
            "approval expiry must be after creation",
        )));
    }
    validate_approval_scope(&approval.scope)?;
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

pub fn revoke_approval_scope(
    path: &Path,
    scope: &str,
    now_epoch_seconds: u64,
) -> Result<usize, MemoryError> {
    validate_approval_scope(scope)?;
    if !path.exists() {
        return Ok(0);
    }

    let mut approvals = load_approvals(path)?;
    let mut revoked = 0;
    for approval in &mut approvals {
        if approval.scope == scope && approval.expires_at_epoch_seconds > now_epoch_seconds {
            approval.expires_at_epoch_seconds = now_epoch_seconds;
            revoked += 1;
        }
    }

    write_approvals(path, &approvals)?;
    Ok(revoked)
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

fn write_approvals(path: &Path, approvals: &[Approval]) -> Result<(), MemoryError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    for approval in approvals {
        serde_json::to_writer(&mut file, approval)?;
        file.write_all(b"\n")?;
    }
    file.flush()?;
    file.sync_data()?;
    Ok(())
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

pub fn append_scope_contract(path: &Path, contract: &ScopeContract) -> Result<(), MemoryError> {
    if !contract.verify_signature() {
        return Err(MemoryError::InvalidScopeContract(String::from(
            "scope contract signature did not verify",
        )));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    serde_json::to_writer(&mut file, contract)?;
    file.write_all(b"\n")?;
    file.flush()?;
    file.sync_data()?;
    Ok(())
}

pub fn load_scope_contracts(path: &Path) -> Result<Vec<ScopeContract>, MemoryError> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let file = OpenOptions::new().read(true).open(path)?;
    let mut contracts = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(contract) = serde_json::from_str::<ScopeContract>(&line) {
            contracts.push(contract);
        }
    }
    Ok(contracts)
}

pub fn active_scope_contracts(
    path: &Path,
    now_epoch_seconds: u64,
) -> Result<Vec<ScopeContract>, MemoryError> {
    Ok(load_scope_contracts(path)?
        .into_iter()
        .filter(|contract| contract.is_live_at(now_epoch_seconds) && contract.verify_signature())
        .collect())
}

pub fn find_active_scope_contract(
    path: &Path,
    contract_id: &str,
    now_epoch_seconds: u64,
) -> Result<Option<ScopeContract>, MemoryError> {
    Ok(active_scope_contracts(path, now_epoch_seconds)?
        .into_iter()
        .find(|contract| contract.id == contract_id))
}

pub fn expire_scope_contract(
    path: &Path,
    contract_id: &str,
    now_epoch_seconds: u64,
) -> Result<bool, MemoryError> {
    let mut changed = false;
    let mut contracts = load_scope_contracts(path)?;
    for contract in &mut contracts {
        if contract.id == contract_id && contract.expires_at_epoch_seconds > now_epoch_seconds {
            *contract = contract
                .resigned_with_expiry(now_epoch_seconds)
                .map_err(|error| MemoryError::InvalidScopeContract(error.to_string()))?;
            changed = true;
        }
    }

    if changed {
        write_scope_contracts(path, &contracts)?;
    }

    Ok(changed)
}

fn write_scope_contracts(path: &Path, contracts: &[ScopeContract]) -> Result<(), MemoryError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    for contract in contracts {
        if contract.verify_signature() {
            serde_json::to_writer(&mut file, contract)?;
            file.write_all(b"\n")?;
        }
    }
    file.flush()?;
    file.sync_data()?;
    Ok(())
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
pub struct ApprovalScope {
    pub kind: ApprovalScopeKind,
    pub pattern: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApprovalScopeKind {
    Path,
    Action,
    Mcp,
    Rule,
    Once,
}

impl ApprovalScope {
    fn parse_lossy(scope: &str) -> Self {
        validate_approval_scope(scope).unwrap_or_else(|_| Self {
            kind: ApprovalScopeKind::Path,
            pattern: String::new(),
        })
    }
}

impl ApprovalScopeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Path => "path",
            Self::Action => "action",
            Self::Mcp => "mcp",
            Self::Rule => "rule",
            Self::Once => "once",
        }
    }
}

pub fn validate_approval_scope(scope: &str) -> Result<ApprovalScope, MemoryError> {
    let trimmed = scope.trim();
    if trimmed.is_empty() {
        return Err(MemoryError::InvalidApproval(String::from(
            "approval scope cannot be empty",
        )));
    }
    let Some((prefix, pattern)) = trimmed.split_once(':') else {
        return Err(MemoryError::InvalidApproval(String::from(
            "approval scope must start with path:, action:, mcp:, rule:, or once:",
        )));
    };
    let kind = match prefix {
        "path" => ApprovalScopeKind::Path,
        "action" => ApprovalScopeKind::Action,
        "mcp" => ApprovalScopeKind::Mcp,
        "rule" => ApprovalScopeKind::Rule,
        "once" => ApprovalScopeKind::Once,
        _ => {
            return Err(MemoryError::InvalidApproval(format!(
                "unknown approval scope prefix {prefix}"
            )));
        }
    };
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return Err(MemoryError::InvalidApproval(String::from(
            "approval scope pattern cannot be empty",
        )));
    }

    Ok(ApprovalScope {
        kind,
        pattern: pattern.to_string(),
    })
}

#[derive(Debug)]
pub enum MemoryError {
    Io(std::io::Error),
    Serde(serde_json::Error),
    Yaml(serde_yml::Error),
    MalformedRecord { line: u64, reason: String },
    InvalidApproval(String),
    InvalidScopeContract(String),
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
            Self::InvalidScopeContract(reason) => {
                write!(formatter, "invalid scope contract: {reason}")
            }
        }
    }
}

impl std::error::Error for MemoryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Serde(error) => Some(error),
            Self::Yaml(error) => Some(error),
            Self::MalformedRecord { .. }
            | Self::InvalidApproval(_)
            | Self::InvalidScopeContract(_) => None,
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
    use std::io::Write;

    use super::{
        active_scope_contracts, append_approval, append_scope_contract, behavior_count,
        expire_scope_contract, find_active_scope_contract, has_live_approval_for_action,
        has_live_approval_for_mcp, has_live_approval_for_path, has_live_approval_for_rule,
        has_live_approval_for_target, live_approvals, load_asset_policy, load_scope_contracts,
        match_asset, record_behavior, revoke_approval_scope, validate_approval_scope, Approval,
        ApprovalScopeKind,
    };
    use descry_core::{
        ActionClass, EvidenceRef, EvidenceSource, ScopeContract, ScopePermit, ScopePermitKind,
    };

    #[test]
    fn appends_and_loads_live_approval() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("approvals.jsonl");
        let approval = Approval {
            scope: String::from("path:crates/descry-cli/**"),
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
    fn validates_approval_scope_prefixes_and_patterns() {
        let scope = validate_approval_scope("mcp:https://prod-mcp.example.com/**")
            .expect("scope validates");

        assert_eq!(scope.kind, ApprovalScopeKind::Mcp);
        assert_eq!(scope.pattern, "https://prod-mcp.example.com/**");
        validate_approval_scope("pat:src/**").expect_err("unknown prefix fails");
        validate_approval_scope("path:").expect_err("empty pattern fails");
        validate_approval_scope("   ").expect_err("empty scope fails");
        validate_approval_scope("src/**").expect_err("untyped scope fails");
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
                scope: String::from("path:*"),
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
    fn revokes_approval_by_exact_scope() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("approvals.jsonl");
        append_approval(
            &path,
            &Approval {
                scope: String::from("action:deploy"),
                created_at_epoch_seconds: 100,
                expires_at_epoch_seconds: 200,
                approver: String::from("human"),
            },
        )
        .expect("approval appends");

        let revoked = revoke_approval_scope(&path, "action:deploy", 150).expect("scope revokes");

        assert_eq!(revoked, 1);
        assert!(!has_live_approval_for_action(&path, "deploy", 151)
            .expect("approval no longer matches"));
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

    fn scope_contract(created_at: u64, expires_at: u64) -> ScopeContract {
        ScopeContract::signed(
            "Fix auth session",
            vec![EvidenceRef::new(
                EvidenceSource::ActiveTask,
                "task:AUTH-241",
                "Fix auth session",
            )],
            vec![ScopePermit::new(
                ScopePermitKind::Path,
                "src/auth/**",
                vec![ActionClass::FileWrite],
                "active task evidence",
            )],
            created_at,
            expires_at,
            0.8,
        )
        .expect("scope contract signs")
    }

    #[test]
    fn appends_and_loads_active_scope_contract() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("scope-contracts.jsonl");
        let contract = scope_contract(100, 200);

        append_scope_contract(&path, &contract).expect("contract appends");

        assert_eq!(
            active_scope_contracts(&path, 150).expect("contracts load"),
            vec![contract.clone()]
        );
        assert_eq!(
            find_active_scope_contract(&path, &contract.id, 150).expect("contract finds"),
            Some(contract)
        );
    }

    #[test]
    fn active_scope_contracts_ignore_expired_malformed_and_tampered_records() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("scope-contracts.jsonl");
        let active = scope_contract(100, 200);
        let expired = scope_contract(100, 120);
        let mut tampered = scope_contract(100, 200);
        tampered.permits[0].pattern = String::from("infra/**");

        append_scope_contract(&path, &active).expect("active appends");
        append_scope_contract(&path, &expired).expect("expired appends");
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("cache opens")
            .write_all(
                format!(
                    "{}\nnot-json\n",
                    serde_json::to_string(&tampered).expect("tampered serializes")
                )
                .as_bytes(),
            )
            .expect("tampered writes");

        let active_contracts = active_scope_contracts(&path, 150).expect("contracts load");

        assert_eq!(active_contracts, vec![active]);
        assert_eq!(
            load_scope_contracts(&path).expect("contracts load").len(),
            3
        );
    }

    #[test]
    fn rejects_append_of_tampered_scope_contract() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("scope-contracts.jsonl");
        let mut contract = scope_contract(100, 200);
        contract.task_summary = String::from("different task");

        append_scope_contract(&path, &contract).expect_err("tampered contract rejects");
    }

    #[test]
    fn expires_scope_contract_by_id() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("scope-contracts.jsonl");
        let contract = scope_contract(100, 200);
        let contract_id = contract.id.clone();
        append_scope_contract(&path, &contract).expect("contract appends");

        assert!(expire_scope_contract(&path, &contract_id, 150).expect("contract expires"));
        assert!(active_scope_contracts(&path, 151)
            .expect("contracts load")
            .is_empty());
        assert!(load_scope_contracts(&path)
            .expect("contracts load")
            .into_iter()
            .all(|contract| contract.verify_signature()));
    }
}
