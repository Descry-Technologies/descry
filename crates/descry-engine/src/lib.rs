use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use descry_context::ProjectIndex;
use descry_core::{
    classify_drift_signal, ActionClass, ActionContextPacket, AssetMatch, ClassifiedAction,
    Confidence, Decision, DecisionInput, DecisionOutput, DriftSignal, RiskScore,
    RuntimeContextConfig, ScopeContract, ScopePermitKind, TaskEnvelope, TaskEnvelopeBuilder,
    TaskSource,
};
use descry_policy::{Policy, ProjectPolicy};

pub struct EvaluationRuntime<'a> {
    pub policy: &'a Policy,
    pub project_config: &'a ProjectPolicy,
    pub approvals_path: &'a Path,
    pub behavior_path: &'a Path,
    pub project_index: Option<&'a ProjectIndex>,
    pub shadow: bool,
}

#[derive(Clone, Debug)]
pub struct EvaluatedAction {
    pub decision: DecisionOutput,
    pub decision_input: DecisionInput,
}

pub fn evaluate_action(
    acp: ActionContextPacket,
    config: &RuntimeContextConfig,
    session_id: Option<&str>,
    shadow: bool,
) -> Result<EvaluatedAction, String> {
    let acp = descry_core::enrich_action_context(acp, config)
        .map_err(|error| format!("failed to enrich runtime context: {error}"))?;
    let policy = load_policy(&config.policy_path)?;
    let project_config = load_project_policy(&config.project_policy_path)?;
    let project_index = descry_context::read_project_index(&config.project_index_path).ok();
    let decision_input = match config.legacy_asset_policy_path.as_deref() {
        Some(asset_policy_path) => {
            build_decision_input_with_legacy_asset_policy(acp.clone(), asset_policy_path)
        }
        None => build_decision_input(acp.clone()),
    };
    let runtime = EvaluationRuntime {
        policy: &policy,
        project_config: &project_config,
        approvals_path: &config.approvals_path,
        behavior_path: &config.behavior_path,
        project_index: project_index.as_ref(),
        shadow,
    };
    let decision = evaluate_with_legacy_asset_policy(
        decision_input.clone(),
        runtime,
        config.legacy_asset_policy_path.as_deref(),
    );

    record_behavior(&config.behavior_path, &acp)
        .map_err(|error| format!("failed to record behavior: {error}"))?;
    descry_core::append_runtime_session_event(config, session_id, &acp, &decision)
        .map_err(|error| format!("failed to append session event: {error}"))?;

    Ok(EvaluatedAction {
        decision,
        decision_input,
    })
}

const BUILT_IN_SAFE_DEFAULTS: &str =
    include_str!("../../../policies/safe-defaults.yml");
const DEFAULT_POLICY_PATH: &str = "policies/safe-defaults.yml";

fn load_policy(path: &Path) -> Result<Policy, String> {
    match fs::read_to_string(path) {
        Ok(body) => {
            Policy::load_yaml(&body).map_err(|error| format!("failed to load policy: {error}"))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
            && path == Path::new(DEFAULT_POLICY_PATH) =>
        {
            Policy::load_yaml(BUILT_IN_SAFE_DEFAULTS)
                .map_err(|error| format!("failed to load built-in policy: {error}"))
        }
        Err(error) => Err(format!(
            "failed to read policy {}: {error}",
            path.display()
        )),
    }
}

fn load_project_policy(path: &Path) -> Result<ProjectPolicy, String> {
    if !path.exists() {
        return Ok(ProjectPolicy::default());
    }

    let body = fs::read_to_string(path)
        .map_err(|error| format!("failed to read project policy {}: {error}", path.display()))?;
    ProjectPolicy::load_yaml(&body)
        .map_err(|error| format!("failed to load project policy {}: {error}", path.display()))
}

fn record_behavior(behavior_path: &Path, acp: &ActionContextPacket) -> Result<(), String> {
    descry_memory::record_behavior(
        behavior_path,
        &acp.actor.name,
        &acp.action.action_type,
        &acp.action.target,
        current_epoch_seconds(),
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

pub fn evaluate(input: DecisionInput, runtime: EvaluationRuntime<'_>) -> DecisionOutput {
    evaluate_targets(input, runtime, None)
}

fn evaluate_with_legacy_asset_policy(
    input: DecisionInput,
    runtime: EvaluationRuntime<'_>,
    legacy_asset_policy_path: Option<&Path>,
) -> DecisionOutput {
    evaluate_targets(input, runtime, legacy_asset_policy_path)
}

fn evaluate_targets(
    input: DecisionInput,
    runtime: EvaluationRuntime<'_>,
    legacy_asset_policy_path: Option<&Path>,
) -> DecisionOutput {
    let result = expand_target_stage(&input.acp)
        .into_iter()
        .map(|target| evaluate_target_stage(&input, target, &runtime, legacy_asset_policy_path))
        .reduce(strongest_verdict_stage)
        .expect("action targets are never empty");

    if runtime.shadow && result.decision == Decision::Block {
        DecisionOutput {
            decision: Decision::AllowWithLog,
            reason: format!("[shadow] {}", result.reason),
            ..result
        }
    } else {
        result
    }
}

pub fn build_decision_input(acp: ActionContextPacket) -> DecisionInput {
    build_decision_input_with_asset(acp, None)
}

pub fn build_decision_input_with_legacy_asset_policy(
    acp: ActionContextPacket,
    asset_policy_path: &Path,
) -> DecisionInput {
    let target = acp.action.target.clone();
    build_decision_input_with_asset(acp, match_legacy_asset(asset_policy_path, &target))
}

fn build_decision_input_with_asset(
    acp: ActionContextPacket,
    asset: Option<AssetMatch>,
) -> DecisionInput {
    let task = TaskEnvelopeBuilder::new(&acp)
        .matched_asset(asset.as_ref().map(|asset| asset.id.clone()))
        .build();
    let action = classify_action(&acp);
    let instruction_provenance = acp.instruction_provenance;

    DecisionInput {
        acp,
        event: None,
        task,
        action,
        asset,
        instruction_provenance,
    }
}

fn match_runtime_asset(
    target: &str,
    runtime: &EvaluationRuntime<'_>,
    legacy_asset_policy_path: Option<&Path>,
) -> Option<AssetMatch> {
    legacy_asset_policy_path
        .and_then(|asset_policy_path| match_legacy_asset(asset_policy_path, target))
        .or_else(|| runtime.project_config.match_asset(target))
        .or_else(|| match_project_index_asset(target, runtime.project_index))
        .or_else(|| semantic_asset_graph_match(target))
}

fn match_project_index_asset(
    target: &str,
    project_index: Option<&ProjectIndex>,
) -> Option<AssetMatch> {
    let index = project_index?;
    let lowercase_target = target.to_ascii_lowercase();
    for node in &index.asset_graph {
        let matched = node.patterns.iter().any(|pattern| {
            let pat = pattern.to_ascii_lowercase();
            lowercase_target == pat
                || lowercase_target.ends_with(&format!("/{pat}"))
                || lowercase_target.ends_with(&format!("\\{pat}"))
        });
        if matched {
            return Some(AssetMatch {
                id: node.id.clone(),
                sensitivity: node.sensitivity.clone(),
                default_action: node.default_action.clone(),
            });
        }
    }
    None
}

fn expand_target_stage(acp: &ActionContextPacket) -> Vec<String> {
    action_targets(acp)
}

fn evaluate_target_stage(
    input: &DecisionInput,
    target: String,
    runtime: &EvaluationRuntime<'_>,
    legacy_asset_policy_path: Option<&Path>,
) -> DecisionOutput {
    let candidate_input =
        prepare_target_input_stage(input, target, runtime, legacy_asset_policy_path);
    let tier_one_decision = tier_one_policy_stage(&candidate_input, runtime);
    let is_tier_one_block = tier_one_decision.decision == Decision::Block;
    let verdict = verdict_layer_stage(tier_one_decision, &candidate_input, runtime);

    drift_inspection_stage(verdict, &candidate_input, is_tier_one_block)
}

fn drift_inspection_stage(
    upstream: DecisionOutput,
    input: &DecisionInput,
    is_tier_one_block: bool,
) -> DecisionOutput {
    // Skip drift when Tier-1 was authoritative — including when an approval override
    // downgraded that block to allow_with_log. The human approval is the final word.
    if is_tier_one_block {
        return upstream;
    }

    let asset_sensitivity = input.asset.as_ref().map(|a| a.sensitivity.as_str());
    let signal = classify_drift_signal(
        &input.action.class,
        input.action.reversible,
        input.instruction_provenance,
        asset_sensitivity,
        input.task.confidence,
    );

    match signal {
        DriftSignal::None => upstream,
        DriftSignal::Suspicious => {
            let provenance_label = input
                .instruction_provenance
                .map(|p| p.label())
                .unwrap_or("unknown");
            DecisionOutput {
                decision: Decision::RequireApproval,
                risk_score: RiskScore::try_from(78).expect("78 is valid"),
                confidence: Confidence::try_from(0.75).expect("0.75 is valid"),
                reason: format!(
                    "drift: suspicious action {:?} with instruction source: {} (task: {})",
                    input.action.class,
                    provenance_label,
                    input.task.summary.chars().take(120).collect::<String>(),
                ),
                conditions: vec![String::from(
                    "Confirm this action is intentional given the current task",
                )],
            }
        }
        DriftSignal::HighConfidence => {
            let provenance_label = input
                .instruction_provenance
                .map(|p| p.label())
                .unwrap_or("unknown");
            DecisionOutput {
                decision: Decision::Block,
                risk_score: RiskScore::try_from(95).expect("95 is valid"),
                confidence: Confidence::try_from(0.9).expect("0.9 is valid"),
                reason: format!(
                    "drift: blocked {:?} — destructive action with instruction source: {} does not fit task: {}",
                    input.action.class,
                    provenance_label,
                    input.task.summary.chars().take(120).collect::<String>(),
                ),
                conditions: Vec::new(),
            }
        }
    }
}

fn prepare_target_input_stage(
    input: &DecisionInput,
    target: String,
    runtime: &EvaluationRuntime<'_>,
    legacy_asset_policy_path: Option<&Path>,
) -> DecisionInput {
    let mut candidate_input = input.clone();
    candidate_input.acp.action.target = target;
    candidate_input.action = classify_action_stage(&candidate_input.acp);
    candidate_input.asset = asset_match_stage(
        &candidate_input.acp.action.target,
        runtime,
        legacy_asset_policy_path,
    );
    candidate_input.task =
        task_envelope_stage(&candidate_input.acp, candidate_input.asset.as_ref());
    candidate_input
}

fn classify_action_stage(acp: &ActionContextPacket) -> ClassifiedAction {
    classify_action(acp)
}

fn asset_match_stage(
    target: &str,
    runtime: &EvaluationRuntime<'_>,
    legacy_asset_policy_path: Option<&Path>,
) -> Option<AssetMatch> {
    match_runtime_asset(target, runtime, legacy_asset_policy_path)
}

fn task_envelope_stage(acp: &ActionContextPacket, asset: Option<&AssetMatch>) -> TaskEnvelope {
    TaskEnvelopeBuilder::new(acp)
        .matched_asset(asset.map(|asset| asset.id.clone()))
        .build()
}

fn tier_one_policy_stage(input: &DecisionInput, runtime: &EvaluationRuntime<'_>) -> DecisionOutput {
    runtime.policy.evaluate(&input.acp)
}

pub fn classify_action(acp: &ActionContextPacket) -> ClassifiedAction {
    let action_type = acp.action.action_type.as_str();
    let target = acp.action.target.trim();

    let class = if action_type == "file.write" {
        ActionClass::FileWrite
    } else if action_type == "file.read" && looks_like_secret_path(target) {
        ActionClass::SecretRead
    } else if action_type == "file.read" {
        ActionClass::FileRead
    } else if action_type == "mcp.call" {
        classify_mcp(acp)
    } else if action_type == "shell.exec" {
        classify_shell(target)
    } else {
        ActionClass::Unknown
    };

    let destructive = matches!(
        class,
        ActionClass::ShellDelete
            | ActionClass::GitRewrite
            | ActionClass::DatabaseDestroy
            | ActionClass::CloudDelete
            | ActionClass::McpDestroy
    ) || !acp.blast_radius.reversible;

    ClassifiedAction {
        class,
        target: acp.action.target.clone(),
        reversible: acp.blast_radius.reversible,
        destructive,
    }
}

fn classify_shell(target: &str) -> ActionClass {
    let lowercase_target = target.to_ascii_lowercase();
    let tokens = shell_tokens(target).unwrap_or_else(|| {
        lowercase_target
            .split_whitespace()
            .map(ToString::to_string)
            .collect()
    });
    let lowercase_tokens = tokens
        .iter()
        .map(|token| token.to_ascii_lowercase())
        .collect::<Vec<_>>();

    if let Some(class) = classify_git(&lowercase_tokens) {
        return class;
    }
    if classify_database_destroy(&lowercase_target) {
        return ActionClass::DatabaseDestroy;
    }
    if classify_cloud_delete(&lowercase_tokens, &lowercase_target) {
        return ActionClass::CloudDelete;
    }
    if classify_deploy(&lowercase_tokens, &lowercase_target) {
        return ActionClass::Deploy;
    }

    if command_starts_with(&lowercase_tokens, &["git", "status"])
        || command_starts_with(&lowercase_tokens, &["git", "diff"])
        || command_starts_with(&lowercase_tokens, &["git", "log"])
    {
        ActionClass::GitRead
    } else if command_starts_with(&lowercase_tokens, &["cargo", "test"])
        || command_starts_with(&lowercase_tokens, &["npm", "test"])
        || command_starts_with(&lowercase_tokens, &["npm", "run", "test"])
        || command_starts_with(&lowercase_tokens, &["pytest"])
    {
        ActionClass::ShellTest
    } else if command_starts_with(&lowercase_tokens, &["cargo", "build"])
        || command_starts_with(&lowercase_tokens, &["npm", "run", "build"])
        || command_starts_with(&lowercase_tokens, &["go", "build"])
    {
        ActionClass::ShellBuild
    } else if command_starts_with(&lowercase_tokens, &["npm", "install"])
        || command_starts_with(&lowercase_tokens, &["pnpm", "install"])
        || command_starts_with(&lowercase_tokens, &["yarn", "install"])
        || command_starts_with(&lowercase_tokens, &["cargo", "install"])
    {
        ActionClass::ShellInstall
    } else if lowercase_target.contains("rm -rf")
        || lowercase_target.contains("find ") && lowercase_target.contains(" -delete")
    {
        ActionClass::ShellDelete
    } else {
        ActionClass::Unknown
    }
}

fn shell_tokens(command: &str) -> Option<Vec<String>> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut chars = command.chars().peekable();
    let mut quote = None;

    while let Some(character) = chars.next() {
        match (character, quote) {
            ('\\', Some('\'')) => current.push(character),
            ('\\', _) => {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            ('\'' | '"', None) => quote = Some(character),
            (candidate, Some(active_quote)) if candidate == active_quote => quote = None,
            (character, None) if character.is_whitespace() => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            (character, _) => current.push(character),
        }
    }

    if quote.is_some() {
        return None;
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    Some(tokens)
}

fn classify_git(tokens: &[String]) -> Option<ActionClass> {
    if command_starts_with(tokens, &["git", "reset"])
        && tokens.iter().any(|token| token == "--hard")
    {
        return Some(ActionClass::GitRewrite);
    }
    if command_starts_with(tokens, &["git", "clean"])
        && tokens.iter().any(|token| git_clean_forces_delete(token))
    {
        return Some(ActionClass::GitRewrite);
    }
    if command_starts_with(tokens, &["git", "push"])
        && tokens.iter().any(|token| is_git_force_flag(token))
        && tokens.iter().any(|token| is_protected_branch(token))
    {
        return Some(ActionClass::GitRewrite);
    }

    None
}

fn git_clean_forces_delete(token: &str) -> bool {
    token.starts_with('-') && token.contains('f') && token.contains('d')
}

fn is_git_force_flag(token: &str) -> bool {
    token == "-f" || token == "--force" || token == "--force-with-lease"
}

fn is_protected_branch(token: &str) -> bool {
    matches!(token, "main" | "master")
        || token.starts_with("release/")
        || token.starts_with("prod/")
}

fn classify_database_destroy(lowercase_target: &str) -> bool {
    lowercase_target.contains("drop database")
        || lowercase_target.contains("drop table")
        || lowercase_target.contains("truncate table")
        || lowercase_target.contains("db.dropdatabase")
        || lowercase_target.contains(".deletemany({})")
        || delete_from_without_where(lowercase_target)
}

fn delete_from_without_where(text: &str) -> bool {
    text.split(';').any(|statement| {
        let Some(delete_index) = statement.find("delete") else {
            return false;
        };
        let after_delete = statement[delete_index + "delete".len()..].trim_start();
        if !after_delete.starts_with("from") {
            return false;
        }
        let after_from = after_delete["from".len()..].trim();
        !after_from.is_empty() && !contains_word(after_from, "where")
    })
}

fn contains_word(text: &str, word: &str) -> bool {
    text.split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .any(|part| part == word)
}

fn classify_cloud_delete(tokens: &[String], lowercase_target: &str) -> bool {
    command_starts_with(tokens, &["railway", "volume", "delete"])
        || command_starts_with(tokens, &["fly", "apps", "destroy"])
        || command_starts_with(tokens, &["fly", "volumes", "destroy"])
        || command_starts_with(tokens, &["vercel", "project", "remove"])
        || command_starts_with(tokens, &["aws", "ec2", "terminate-instances"])
        || command_starts_with(tokens, &["aws", "rds", "delete-db-instance"])
        || command_starts_with(tokens, &["aws", "rds", "delete-db-cluster"])
        || command_starts_with(tokens, &["gcloud", "compute", "instances", "delete"])
        || command_starts_with(tokens, &["gcloud", "sql", "instances", "delete"])
        || command_starts_with(tokens, &["az", "group", "delete"])
        || lowercase_target.contains("curl")
            && lowercase_target.contains("delete")
            && (lowercase_target.contains("railway.app")
                || lowercase_target.contains("fly.io")
                || lowercase_target.contains("vercel.app/api/internal"))
}

fn classify_deploy(tokens: &[String], lowercase_target: &str) -> bool {
    command_starts_with(tokens, &["fly", "deploy"])
        || command_starts_with(tokens, &["railway", "up"])
        || command_starts_with(tokens, &["npm", "run", "deploy"])
        || tokens.first().is_some_and(|token| token == "deploy")
        || command_starts_with(tokens, &["vercel"]) && tokens.iter().any(|token| token == "--prod")
        || lowercase_target.contains(" deploy")
}

fn command_starts_with(tokens: &[String], expected: &[&str]) -> bool {
    tokens.len() >= expected.len()
        && tokens
            .iter()
            .zip(expected.iter())
            .all(|(actual, expected)| actual == expected)
}

fn classify_mcp(acp: &ActionContextPacket) -> ActionClass {
    let summary = acp.action.diff_summary.as_deref().unwrap_or_default();
    let text = format!(
        "{} {} {}",
        acp.action.target,
        summary,
        acp.action.argument_keys.join(" ")
    )
    .to_ascii_lowercase();

    if acp.action.argument_keys.iter().any(|key| {
        let key = key.to_ascii_lowercase();
        (key.contains("confirm") || key.contains("force") || key.contains("danger"))
            && (key.contains("delete")
                || key.contains("destroy")
                || key.contains("drop")
                || key.contains("purge")
                || key.contains("remove"))
    }) || text.contains("delete")
        || text.contains("destroy")
        || text.contains("drop")
        || text.contains("purge")
        || text.contains("remove")
    {
        ActionClass::McpDestroy
    } else if text.contains("create") || text.contains("update") || text.contains("write") {
        ActionClass::McpWrite
    } else if text.contains("list") || text.contains("get") || text.contains("read") {
        ActionClass::McpRead
    } else {
        ActionClass::Unknown
    }
}

fn verdict_layer_stage(
    tier_one_decision: DecisionOutput,
    input: &DecisionInput,
    runtime: &EvaluationRuntime<'_>,
) -> DecisionOutput {
    let acp = &input.acp;
    if tier_one_decision.decision == Decision::Block && acp.action.action_type == "mcp.call" {
        return mcp_approval_override_stage(tier_one_decision, acp, runtime.approvals_path);
    }
    if tier_one_decision.decision == Decision::Block {
        return tier_one_decision;
    }

    let action_decision = action_policy_stage(input, runtime);
    let asset_decision = asset_policy_stage(input, runtime);

    strongest_verdict_stage(
        strongest_verdict_stage(tier_one_decision, action_decision),
        asset_decision,
    )
}

fn asset_policy_stage(input: &DecisionInput, runtime: &EvaluationRuntime<'_>) -> DecisionOutput {
    asset_policy_decision(input, runtime)
}

fn action_policy_stage(input: &DecisionInput, runtime: &EvaluationRuntime<'_>) -> DecisionOutput {
    action_policy_decision(input, runtime)
}

fn asset_policy_decision(input: &DecisionInput, runtime: &EvaluationRuntime<'_>) -> DecisionOutput {
    let acp = &input.acp;
    let Some(asset) = input.asset.as_ref() else {
        return allow_fallback("no asset policy matched");
    };

    if asset.default_action == "block" && acp.action.action_type != "file.write" {
        return asset_block_decision(acp, asset, action_verb(acp), Vec::new());
    }
    if is_semantic_asset_graph_asset(asset) {
        return asset_graph_asset_decision(input, runtime, asset);
    }
    if acp.action.action_type != "file.write" {
        return allow_fallback("asset policy does not apply to this action type");
    }

    if let Some(scope_decision) = scope_contract_decision(input, runtime, asset) {
        return scope_decision;
    }

    let context_match = task_context_match(input);
    if asset.default_action == "allow_if_context_matches"
        && asset.sensitivity == "normal"
        && context_match.score >= 60
    {
        return DecisionOutput {
            decision: Decision::Allow,
            risk_score: RiskScore::try_from(20).expect("20 is a valid risk score"),
            confidence: Confidence::try_from(0.75).expect("0.75 is a valid confidence"),
            reason: format!(
                "allowed: {} matched task context score={} via {} (asset: {})",
                acp.action.target, context_match.score, context_match.reason, asset.id
            ),
            conditions: Vec::new(),
        };
    }

    let now = current_epoch_seconds();
    let has_approval =
        descry_memory::has_live_approval_for_path(runtime.approvals_path, &acp.action.target, now)
            .unwrap_or(false);

    if has_approval {
        return DecisionOutput {
            decision: Decision::AllowWithLog,
            risk_score: RiskScore::try_from(45).expect("45 is a valid risk score"),
            confidence: Confidence::try_from(0.9).expect("0.9 is a valid confidence"),
            reason: format!(
                "scoped approval matched {} write target {} (asset: {})",
                asset.sensitivity, acp.action.target, asset.id
            ),
            conditions: vec![String::from("Approval applies only until its TTL expires")],
        };
    }

    match asset.default_action.as_str() {
        "block" => asset_block_decision(
            acp,
            asset,
            "write",
            vec![format!(
                "Run: descry approve --scope '{}' --ttl 30m for an explicit override",
                approval_scope_hint(&acp.action.target)
            )],
        ),
        "require_approval" | "allow_if_context_matches" => {
            let reason_suffix = if asset.default_action == "allow_if_context_matches" {
                context_match.approval_reason()
            } else {
                String::from("requires scoped approval")
            };
            asset_require_approval_decision(input, runtime.behavior_path, asset, &reason_suffix)
        }
        "allow" => allow_fallback("asset policy allows this target"),
        _ => allow_fallback("unknown asset default action falls back to allow"),
    }
}

fn asset_graph_asset_decision(
    input: &DecisionInput,
    runtime: &EvaluationRuntime<'_>,
    asset: &AssetMatch,
) -> DecisionOutput {
    if has_live_asset_approval(input, runtime) {
        return DecisionOutput {
            decision: Decision::AllowWithLog,
            risk_score: RiskScore::try_from(60).expect("60 is a valid risk score"),
            confidence: Confidence::try_from(0.9).expect("0.9 is a valid confidence"),
            reason: format!(
                "scoped approval matched {} target {} (asset graph: {})",
                asset.sensitivity, input.acp.action.target, asset.id
            ),
            conditions: vec![String::from("Approval applies only until its TTL expires")],
        };
    }

    match asset.default_action.as_str() {
        "block" => asset_block_decision(&input.acp, asset, action_verb(&input.acp), Vec::new()),
        "require_approval" => DecisionOutput {
            decision: Decision::RequireApproval,
            risk_score: RiskScore::try_from(82).expect("82 is a valid risk score"),
            confidence: Confidence::try_from(0.9).expect("0.9 is a valid confidence"),
            reason: format!(
                "{} target {} requires approval by asset graph (asset: {}, action: {:?})",
                asset.sensitivity, input.acp.action.target, asset.id, input.action.class
            ),
            conditions: vec![approval_condition(&input.acp)],
        },
        "allow" => allow_fallback("asset graph allows this target"),
        _ => allow_fallback("unknown asset graph default action falls back to allow"),
    }
}

fn is_semantic_asset_graph_asset(asset: &AssetMatch) -> bool {
    asset.id.starts_with("hosted-control-plane:") || asset.id == "mcp-production-control-plane"
}

fn has_live_asset_approval(input: &DecisionInput, runtime: &EvaluationRuntime<'_>) -> bool {
    let now = current_epoch_seconds();
    match input.acp.action.action_type.as_str() {
        "mcp.call" => descry_memory::has_live_approval_for_mcp(
            runtime.approvals_path,
            &input.acp.action.target,
            now,
        )
        .unwrap_or(false),
        "file.read" | "file.write" => descry_memory::has_live_approval_for_path(
            runtime.approvals_path,
            &input.acp.action.target,
            now,
        )
        .unwrap_or(false),
        _ => false,
    }
}

fn approval_condition(acp: &ActionContextPacket) -> String {
    let scope = if acp.action.action_type == "mcp.call" {
        format!("mcp:{}", acp.action.target)
    } else {
        approval_scope_hint(&acp.action.target)
    };
    format!("Run: descry approve --scope '{scope}' --ttl 30m")
}

fn action_verb(acp: &ActionContextPacket) -> &'static str {
    match acp.action.action_type.as_str() {
        "file.read" => "read",
        "file.write" => "write",
        "mcp.call" => "MCP",
        "shell.exec" => "shell",
        _ => "action",
    }
}

fn scope_contract_decision(
    input: &DecisionInput,
    runtime: &EvaluationRuntime<'_>,
    asset: &AssetMatch,
) -> Option<DecisionOutput> {
    if asset.default_action != "allow_if_context_matches" || asset.sensitivity != "normal" {
        return None;
    }

    let scope_contracts_path = scope_contracts_path(runtime.approvals_path);
    let contracts =
        descry_memory::active_scope_contracts(&scope_contracts_path, current_epoch_seconds())
            .unwrap_or_default();
    if contracts.is_empty() {
        return None;
    }

    if let Some(scope_match) = matching_scope_permit(input, &contracts) {
        return Some(DecisionOutput {
            decision: Decision::Allow,
            risk_score: RiskScore::try_from(18).expect("18 is a valid risk score"),
            confidence: Confidence::try_from(0.85).expect("0.85 is a valid confidence"),
            reason: format!(
                "allowed: {} matched active scope contract {} permit {} for action {:?} (blast_radius: reversible={}, customer_impact={}, financial_impact={})",
                input.acp.action.target,
                scope_match.contract_id,
                scope_match.permit_pattern,
                input.action.class,
                input.acp.blast_radius.reversible,
                input.acp.blast_radius.customer_impact,
                input.acp.blast_radius.financial_impact
            ),
            conditions: Vec::new(),
        });
    }

    Some(DecisionOutput {
        decision: Decision::RequireApproval,
        risk_score: RiskScore::try_from(70).expect("70 is a valid risk score"),
        confidence: Confidence::try_from(0.85).expect("0.85 is a valid confidence"),
        reason: format!(
            "normal write target {} does not match active scope contract by semantic scope stage (action: {:?}, blast_radius: reversible={}, customer_impact={}, financial_impact={}, asset: {})",
            input.acp.action.target,
            input.action.class,
            input.acp.blast_radius.reversible,
            input.acp.blast_radius.customer_impact,
            input.acp.blast_radius.financial_impact,
            asset.id
        ),
        conditions: vec![format!(
            "Run: descry approve --scope '{}' --ttl 30m",
            approval_scope_hint(&input.acp.action.target)
        )],
    })
}

struct ScopePermitMatch {
    contract_id: String,
    permit_pattern: String,
}

fn matching_scope_permit(
    input: &DecisionInput,
    contracts: &[ScopeContract],
) -> Option<ScopePermitMatch> {
    contracts.iter().find_map(|contract| {
        contract.permits.iter().find_map(|permit| {
            let action_matches = permit.action_classes.contains(&input.action.class);
            let target_matches = match permit.kind {
                ScopePermitKind::Path => pattern_matches(&permit.pattern, &input.acp.action.target),
                ScopePermitKind::Asset => input
                    .asset
                    .as_ref()
                    .is_some_and(|asset| permit.pattern == asset.id),
                ScopePermitKind::Action => project_action_key(&input.action.class)
                    .is_some_and(|action_key| permit.pattern == action_key),
            };

            if action_matches && target_matches {
                Some(ScopePermitMatch {
                    contract_id: contract.id.clone(),
                    permit_pattern: permit.pattern.clone(),
                })
            } else {
                None
            }
        })
    })
}

fn scope_contracts_path(approvals_path: &Path) -> PathBuf {
    if approvals_path
        .file_name()
        .is_some_and(|file_name| file_name == "approvals.jsonl")
    {
        return approvals_path
            .parent()
            .map(|parent| parent.join("scope-contracts.jsonl"))
            .unwrap_or_else(|| PathBuf::from("scope-contracts.jsonl"));
    }

    approvals_path.with_extension("scope-contracts.jsonl")
}

fn pattern_matches(pattern: &str, target: &str) -> bool {
    if pattern == "*" || pattern == target {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("/**") {
        return target == prefix || target.starts_with(&format!("{prefix}/"));
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return target.starts_with(prefix);
    }
    false
}

fn asset_block_decision(
    acp: &ActionContextPacket,
    asset: &AssetMatch,
    verb: &str,
    conditions: Vec<String>,
) -> DecisionOutput {
    DecisionOutput {
        decision: Decision::Block,
        risk_score: RiskScore::try_from(95).expect("95 is a valid risk score"),
        confidence: Confidence::try_from(0.95).expect("0.95 is a valid confidence"),
        reason: format!(
            "{} {} target {} is blocked by asset policy (asset: {})",
            asset.sensitivity, verb, acp.action.target, asset.id
        ),
        conditions,
    }
}

fn asset_require_approval_decision(
    input: &DecisionInput,
    behavior_path: &Path,
    asset: &AssetMatch,
    reason_suffix: &str,
) -> DecisionOutput {
    let acp = &input.acp;
    let previous_attempts = descry_memory::behavior_count(
        behavior_path,
        &acp.actor.name,
        &acp.action.action_type,
        &acp.action.target,
    )
    .unwrap_or(0);
    let repeat_context = if previous_attempts > 0 {
        format!(" after {previous_attempts} prior attempt(s)")
    } else {
        String::new()
    };
    DecisionOutput {
        decision: Decision::RequireApproval,
        risk_score: RiskScore::try_from(if previous_attempts > 0 { 90 } else { 80 })
            .expect("risk score is valid"),
        confidence: Confidence::try_from(0.9).expect("0.9 is a valid confidence"),
        reason: format!(
            "{} write target {} {reason_suffix} by asset policy{repeat_context} (asset: {})",
            asset.sensitivity, acp.action.target, asset.id
        ),
        conditions: vec![format!(
            "Run: descry approve --scope '{}' --ttl 30m",
            approval_scope_hint(&acp.action.target)
        )],
    }
}

fn action_policy_decision(
    input: &DecisionInput,
    runtime: &EvaluationRuntime<'_>,
) -> DecisionOutput {
    let Some(action_key) = project_action_key(&input.action.class) else {
        return allow_fallback("no action policy matched");
    };
    let Some(rule) = runtime.project_config.actions.get(action_key) else {
        return allow_fallback("no action policy matched");
    };
    let has_action_approval = descry_memory::has_live_approval_for_action(
        runtime.approvals_path,
        action_key,
        current_epoch_seconds(),
    )
    .unwrap_or(false);

    if has_action_approval && matches!(rule.default_action.as_str(), "block" | "require_approval") {
        return DecisionOutput {
            decision: Decision::AllowWithLog,
            risk_score: RiskScore::try_from(55).expect("55 is a valid risk score"),
            confidence: Confidence::try_from(0.9).expect("0.9 is a valid confidence"),
            reason: format!(
                "scoped approval matched action {} for target {}",
                action_key, input.acp.action.target
            ),
            conditions: vec![String::from(
                "Approval applies only to this action scope until its TTL expires",
            )],
        };
    }

    match rule.default_action.as_str() {
        "block" => DecisionOutput {
            decision: Decision::Block,
            risk_score: RiskScore::try_from(90).expect("90 is a valid risk score"),
            confidence: Confidence::try_from(0.9).expect("0.9 is a valid confidence"),
            reason: format!(
                "{} target {} is blocked by action policy (action: {})",
                input.acp.action.action_type, input.acp.action.target, action_key
            ),
            conditions: Vec::new(),
        },
        "require_approval" => DecisionOutput {
            decision: Decision::RequireApproval,
            risk_score: RiskScore::try_from(75).expect("75 is a valid risk score"),
            confidence: Confidence::try_from(0.85).expect("0.85 is a valid confidence"),
            reason: format!(
                "{} target {} requires approval by action policy (action: {})",
                input.acp.action.action_type, input.acp.action.target, action_key
            ),
            conditions: vec![format!(
                "Run: descry approve --scope '{}' --ttl 30m",
                action_scope_hint(action_key)
            )],
        },
        "allow" => DecisionOutput {
            decision: Decision::Allow,
            risk_score: RiskScore::try_from(10).expect("10 is a valid risk score"),
            confidence: Confidence::try_from(0.9).expect("0.9 is a valid confidence"),
            reason: format!("allowed by action policy (action: {action_key})"),
            conditions: Vec::new(),
        },
        _ => allow_fallback("unknown action default action falls back to allow"),
    }
}

fn project_action_key(class: &ActionClass) -> Option<&'static str> {
    match class {
        ActionClass::ShellDelete
        | ActionClass::DatabaseDestroy
        | ActionClass::CloudDelete
        | ActionClass::McpDestroy => Some("destructive"),
        ActionClass::Deploy => Some("deploy"),
        ActionClass::ShellTest => Some("test"),
        ActionClass::ShellBuild => Some("build"),
        ActionClass::ShellInstall => Some("install"),
        ActionClass::GitRewrite => Some("git_rewrite"),
        ActionClass::McpWrite => Some("mcp_write"),
        _ => None,
    }
}

fn action_targets(acp: &ActionContextPacket) -> Vec<String> {
    let mut targets = if acp.action.targets.is_empty() {
        vec![acp.action.target.clone()]
    } else {
        acp.action.targets.clone()
    };
    if !acp.action.target.trim().is_empty() {
        targets.push(acp.action.target.clone());
    }
    targets.retain(|target| !target.trim().is_empty());
    targets.sort();
    targets.dedup();
    if targets.is_empty() {
        targets.push(String::from("unknown"));
    }
    targets
}

fn strongest(left: DecisionOutput, right: DecisionOutput) -> DecisionOutput {
    let left_rank = decision_rank(&left.decision);
    let right_rank = decision_rank(&right.decision);
    if right_rank > left_rank {
        right
    } else if left_rank > right_rank {
        left
    } else if right.risk_score.0 > left.risk_score.0 {
        right
    } else {
        left
    }
}

fn strongest_verdict_stage(left: DecisionOutput, right: DecisionOutput) -> DecisionOutput {
    strongest(left, right)
}

fn decision_rank(decision: &Decision) -> u8 {
    match decision {
        Decision::Allow => 0,
        Decision::AllowWithLog => 1,
        Decision::Ask => 2,
        Decision::RequireApproval => 3,
        Decision::Block => 4,
    }
}

fn allow_fallback(reason: &str) -> DecisionOutput {
    DecisionOutput {
        decision: Decision::Allow,
        risk_score: RiskScore::try_from(0).expect("zero is a valid risk score"),
        confidence: Confidence::try_from(1.0).expect("one is a valid confidence"),
        reason: reason.to_string(),
        conditions: Vec::new(),
    }
}

fn apply_mcp_approval_override(
    decision: DecisionOutput,
    acp: &ActionContextPacket,
    approvals_path: &Path,
) -> DecisionOutput {
    let now = current_epoch_seconds();
    let has_approval =
        descry_memory::has_live_approval_for_mcp(approvals_path, &acp.action.target, now)
            .unwrap_or(false);

    if has_approval {
        DecisionOutput {
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
        }
    } else {
        decision
    }
}

fn mcp_approval_override_stage(
    decision: DecisionOutput,
    acp: &ActionContextPacket,
    approvals_path: &Path,
) -> DecisionOutput {
    apply_mcp_approval_override(decision, acp, approvals_path)
}

#[allow(dead_code)]
struct TaskMatch {
    score: u8,
    exact_paths: Vec<String>,
    near_paths: Vec<String>,
    source_test_pairs: Vec<String>,
    matched_terms: Vec<String>,
    sources: Vec<TaskSource>,
    reason: String,
}

impl TaskMatch {
    fn approval_reason(&self) -> String {
        if self.score == 0 {
            String::from("does not match task context score=0 and requires scoped approval")
        } else {
            format!(
                "has weak task context match score={} via {} and requires scoped approval",
                self.score, self.reason
            )
        }
    }
}

fn task_context_match(input: &DecisionInput) -> TaskMatch {
    score_task_context(&input.acp, &input.task)
}

fn score_task_context(acp: &ActionContextPacket, task: &TaskEnvelope) -> TaskMatch {
    let target = normalized_path(&acp.action.target);
    let target_tokens = useful_path_tokens(&target);
    let mut score: u16 = 0;
    let mut exact_paths = Vec::new();
    let mut near_paths = Vec::new();
    let mut source_test_pairs = Vec::new();
    let mut matched_terms = Vec::new();
    let mut sources = Vec::new();

    let candidate_paths = task_candidate_paths(acp, task);
    let mut has_exact_path = false;
    let mut has_near_path = false;
    let mut has_source_test_pair = false;
    let mut has_stem_overlap = false;
    let mut has_recent_proximity = false;

    for candidate in &candidate_paths {
        let candidate = normalized_path(candidate);
        if candidate.is_empty() {
            continue;
        }

        if candidate == target {
            has_exact_path = true;
            exact_paths.push(candidate.clone());
            push_source(&mut sources, TaskSource::RecentFiles);
        }

        if same_directory(&candidate, &target) && candidate != target {
            has_near_path = true;
            near_paths.push(candidate.clone());
            push_source(&mut sources, TaskSource::RecentFiles);
        }

        if source_test_counterpart(&candidate, &target) {
            has_source_test_pair = true;
            source_test_pairs.push(format!("{candidate} <-> {target}"));
            push_source(&mut sources, TaskSource::RecentFiles);
        }

        if filename_stem_overlap(&candidate, &target) {
            has_stem_overlap = true;
            push_source(&mut sources, TaskSource::RecentFiles);
        }

        if recent_file_proximity(acp, &candidate, &target) {
            has_recent_proximity = true;
            push_source(&mut sources, TaskSource::RecentFiles);
        }
    }

    if has_exact_path {
        score += 70;
    }
    if has_near_path {
        score += 35;
    }
    if has_source_test_pair {
        score += 45;
    }
    if has_stem_overlap {
        score += 20;
    }
    if has_recent_proximity {
        score += 20;
    }

    let branch_terms = useful_terms(&acp.context.branch);
    let branch_overlap = matching_terms(branch_terms, &target_tokens, acp)
        .into_iter()
        .take(2)
        .collect::<Vec<_>>();
    if !branch_overlap.is_empty() {
        score += 15 * branch_overlap.len() as u16;
        matched_terms.extend(branch_overlap);
        push_source(&mut sources, TaskSource::Branch);
    }

    let prompt_terms = prompt_task_terms(acp, task);
    let prompt_overlap = matching_terms(prompt_terms, &target_tokens, acp)
        .into_iter()
        .take(3)
        .collect::<Vec<_>>();
    if !prompt_overlap.is_empty() {
        score += 10 * prompt_overlap.len() as u16;
        matched_terms.extend(prompt_overlap);
        if acp.intent.active_task.is_some() {
            push_source(&mut sources, TaskSource::ActiveTask);
        }
        if acp.intent.user_prompt.is_some() {
            push_source(&mut sources, TaskSource::UserPrompt);
        }
    }

    exact_paths.sort();
    exact_paths.dedup();
    near_paths.sort();
    near_paths.dedup();
    source_test_pairs.sort();
    source_test_pairs.dedup();
    matched_terms.sort();
    matched_terms.dedup();
    sources.sort_by_key(|source| format!("{source:?}"));
    sources.dedup();

    let score = score.min(100) as u8;
    let reason = task_match_reason(TaskMatchReasonInput {
        score,
        exact_paths: &exact_paths,
        near_paths: &near_paths,
        source_test_pairs: &source_test_pairs,
        matched_terms: &matched_terms,
        sources: &sources,
        has_stem_overlap,
        has_recent_proximity,
    });

    TaskMatch {
        score,
        exact_paths,
        near_paths,
        source_test_pairs,
        matched_terms,
        sources,
        reason,
    }
}

fn task_candidate_paths(acp: &ActionContextPacket, task: &TaskEnvelope) -> Vec<String> {
    let mut paths = Vec::new();
    paths.extend(task.likely_paths.clone());
    paths.extend(task.matched_paths.clone());
    paths.extend(acp.context.recent_files.clone());
    if let Some(active_task) = acp.intent.active_task.as_deref() {
        paths.extend(path_like_terms(active_task));
    }
    if let Some(prompt) = acp.intent.user_prompt.as_deref() {
        paths.extend(path_like_terms(prompt));
    }
    paths.retain(|path| !path.trim().is_empty());
    paths.sort();
    paths.dedup();
    paths
}

fn normalized_path(path: &str) -> String {
    path.trim().trim_start_matches("./").replace('\\', "/")
}

fn same_directory(left: &str, right: &str) -> bool {
    let left_dir = left.rsplit_once('/').map(|(dir, _)| dir);
    let right_dir = right.rsplit_once('/').map(|(dir, _)| dir);
    left_dir.is_some() && left_dir == right_dir
}

fn source_test_counterpart(left: &str, right: &str) -> bool {
    let left_kind = source_kind(left);
    let right_kind = source_kind(right);
    if !matches!(
        (&left_kind, &right_kind),
        (PathKind::Source, PathKind::Test) | (PathKind::Test, PathKind::Source)
    ) {
        return false;
    }

    let left_tokens = useful_path_tokens(left);
    let right_tokens = useful_path_tokens(right);
    left_tokens
        .iter()
        .filter(|term| right_tokens.contains(term))
        .take(2)
        .count()
        >= 2
}

fn source_kind(path: &str) -> PathKind {
    let path = path.to_ascii_lowercase();
    if path.starts_with("tests/")
        || path.contains("/tests/")
        || path.contains(".test.")
        || path.contains(".spec.")
    {
        PathKind::Test
    } else if path.starts_with("src/") || path.contains("/src/") || path.starts_with("crates/") {
        PathKind::Source
    } else {
        PathKind::Other
    }
}

#[derive(Eq, PartialEq)]
enum PathKind {
    Source,
    Test,
    Other,
}

fn filename_stem_overlap(left: &str, right: &str) -> bool {
    let left_tokens = filename_tokens(left);
    let right_tokens = filename_tokens(right);
    left_tokens.iter().any(|term| right_tokens.contains(term))
}

fn filename_tokens(path: &str) -> Vec<String> {
    let file_name = path.rsplit('/').next().unwrap_or(path);
    useful_terms(file_name)
}

fn useful_path_tokens(path: &str) -> Vec<String> {
    useful_terms(path)
}

fn useful_terms(value: &str) -> Vec<String> {
    let mut terms = value
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|term| term.len() >= 3)
        .map(|term| term.to_ascii_lowercase())
        .filter(|term| is_useful_term(term))
        .collect::<Vec<_>>();
    terms.sort();
    terms.dedup();
    terms
}

fn is_useful_term(term: &str) -> bool {
    !matches!(
        term,
        "app"
            | "fix"
            | "lib"
            | "mod"
            | "src"
            | "test"
            | "tests"
            | "spec"
            | "file"
            | "write"
            | "update"
            | "change"
            | "unknown"
    )
}

fn matching_terms(
    candidate_terms: Vec<String>,
    target_tokens: &[String],
    acp: &ActionContextPacket,
) -> Vec<String> {
    let summary_tokens = useful_terms(acp.action.diff_summary.as_deref().unwrap_or_default());
    let mut terms = candidate_terms
        .into_iter()
        .filter(|term| target_tokens.contains(term) || summary_tokens.contains(term))
        .collect::<Vec<_>>();
    terms.sort();
    terms.dedup();
    terms
}

fn prompt_task_terms(acp: &ActionContextPacket, task: &TaskEnvelope) -> Vec<String> {
    let mut terms = Vec::new();
    if let Some(active_task) = acp.intent.active_task.as_deref() {
        terms.extend(useful_terms(active_task));
    }
    if let Some(prompt) = acp.intent.user_prompt.as_deref() {
        terms.extend(useful_terms(prompt));
    }
    terms.extend(task.likely_terms.clone());
    terms.extend(task.matched_terms.clone());
    terms.extend(useful_terms(&task.summary));
    terms.sort();
    terms.dedup();
    terms
}

fn path_like_terms(value: &str) -> Vec<String> {
    value
        .split_whitespace()
        .map(|term| {
            term.trim_matches(|character: char| {
                !(character.is_ascii_alphanumeric()
                    || matches!(character, '/' | '\\' | '.' | '_' | '-'))
            })
        })
        .filter(|term| term.contains('/'))
        .map(normalized_path)
        .collect()
}

fn recent_file_proximity(acp: &ActionContextPacket, candidate: &str, target: &str) -> bool {
    acp.context.recent_files.iter().any(|recent_file| {
        let recent_file = normalized_path(recent_file);
        recent_file == candidate
            && (recent_file == target
                || same_directory(&recent_file, target)
                || source_test_counterpart(&recent_file, target))
    })
}

fn push_source(sources: &mut Vec<TaskSource>, source: TaskSource) {
    if !sources.contains(&source) {
        sources.push(source);
    }
}

struct TaskMatchReasonInput<'a> {
    score: u8,
    exact_paths: &'a [String],
    near_paths: &'a [String],
    source_test_pairs: &'a [String],
    matched_terms: &'a [String],
    sources: &'a [TaskSource],
    has_stem_overlap: bool,
    has_recent_proximity: bool,
}

fn task_match_reason(input: TaskMatchReasonInput<'_>) -> String {
    if input.score == 0 {
        return String::from("no usable task evidence");
    }

    let mut parts = Vec::new();
    if !input.exact_paths.is_empty() {
        parts.push(format!("exact path {}", input.exact_paths.join(", ")));
    }
    if !input.near_paths.is_empty() {
        parts.push(format!("near path {}", input.near_paths.join(", ")));
    }
    if !input.source_test_pairs.is_empty() {
        parts.push(format!(
            "source/test counterpart {}",
            input.source_test_pairs.join(", ")
        ));
    }
    if input.has_stem_overlap {
        parts.push(String::from("filename stem overlap"));
    }
    if input.has_recent_proximity {
        parts.push(String::from("recent file proximity"));
    }
    if !input.matched_terms.is_empty() {
        parts.push(format!("terms {}", input.matched_terms.join(", ")));
    }
    if !input.sources.is_empty() {
        parts.push(format!(
            "sources {}",
            source_names(input.sources).join(", ")
        ));
    }
    parts.join("; ")
}

fn source_names(sources: &[TaskSource]) -> Vec<&'static str> {
    sources
        .iter()
        .map(|source| match source {
            TaskSource::ActiveTask => "active_task",
            TaskSource::UserPrompt => "user_prompt",
            TaskSource::Branch => "branch",
            TaskSource::RecentFiles => "recent_files",
            TaskSource::StaticPolicy => "static_policy",
            TaskSource::Unknown => "unknown",
        })
        .collect()
}

fn match_legacy_asset(asset_policy_path: &Path, target: &str) -> Option<AssetMatch> {
    let policy = descry_memory::load_asset_policy(asset_policy_path).ok()?;
    descry_memory::match_asset(&policy, target).map(|asset| AssetMatch {
        id: asset.id,
        sensitivity: asset.sensitivity,
        default_action: asset.default_action,
    })
}

fn semantic_asset_graph_match(target: &str) -> Option<AssetMatch> {
    let lowercase = target.to_ascii_lowercase();
    if looks_like_production_mcp_target(&lowercase) {
        return Some(AssetMatch {
            id: String::from("mcp-production-control-plane"),
            sensitivity: String::from("critical"),
            default_action: String::from("require_approval"),
        });
    }
    if let Some(provider) = hosted_control_plane_provider(&lowercase) {
        return Some(AssetMatch {
            id: format!("hosted-control-plane:{provider}"),
            sensitivity: String::from("critical"),
            default_action: String::from("require_approval"),
        });
    }
    None
}

fn looks_like_production_mcp_target(target: &str) -> bool {
    target.contains("prod-mcp")
        || target.contains("production-mcp")
        || target.contains("admin-mcp")
        || target.contains("control-plane-mcp")
        || target.contains("mcp-prod")
        || target.contains("mcp-production")
        || target.contains("mcp-admin")
        || target.contains("mcp-control-plane")
}

fn hosted_control_plane_provider(target: &str) -> Option<&'static str> {
    if target.ends_with("railway.toml")
        || target.contains("api.railway.app")
        || target.contains("api.railway.com")
        || target.contains("railway volume")
        || target.contains("railway up")
    {
        Some("railway")
    } else if target.ends_with("fly.toml")
        || target.contains("api.fly.io")
        || target.contains("fly apps")
        || target.contains("fly volumes")
        || target.contains("fly deploy")
    {
        Some("fly")
    } else if target.ends_with("vercel.json")
        || target.contains(".vercel/project.json")
        || target.contains("vercel.app/api/internal")
        || target.contains("vercel project")
        || target.contains("api.vercel.com")
    {
        Some("vercel")
    } else if target.ends_with("render.yaml")
        || target.ends_with("render.yml")
        || target.contains("api.render.com")
        || target.contains("render.com/deploy")
    {
        Some("render")
    } else if target.ends_with("netlify.toml")
        || target.ends_with("netlify.json")
        || target.contains("api.netlify.com")
        || target.contains(".netlify.app")
    {
        Some("netlify")
    } else if target.ends_with("Procfile")
        || target.ends_with("heroku.yml")
        || target.contains("api.heroku.com")
        || target.contains("heroku.com/deploy")
    {
        Some("heroku")
    } else if target.contains("supabase.com")
        || target.contains("supabase.co")
        || target.contains("supabase/config.toml")
    {
        Some("supabase")
    } else if target.contains("neon.tech") {
        Some("neon")
    } else if target.contains("planetscale.com") {
        Some("planetscale")
    } else if target.contains("turso.tech") || target.contains("turso.io") {
        Some("turso")
    } else if target.contains("aws rds")
        || target.contains("aws ec2 terminate")
        || target.contains("aws s3 rm")
        || target.contains("aws eks")
    {
        Some("aws")
    } else if target.contains("gcloud sql")
        || target.contains("gcloud compute")
        || target.contains("gcloud run")
    {
        Some("gcloud")
    } else if target.contains("az group") || target.contains("az webapp") {
        Some("azure")
    } else {
        production_api_provider_from_url(target)
    }
}

fn production_api_provider_from_url(target: &str) -> Option<&'static str> {
    let url_start = target.find("https://").or_else(|| target.find("http://"))?;
    let after_scheme = target[url_start..]
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let host_end = after_scheme
        .find(['/', ':', ' '])
        .unwrap_or(after_scheme.len());
    let host = &after_scheme[..host_end];
    descry_context::production_api_provider(host)
}

fn looks_like_secret_path(target: &str) -> bool {
    let lowercase_target = target.to_ascii_lowercase();
    lowercase_target.contains(".env")
        || lowercase_target.contains("secret")
        || lowercase_target.contains("token")
        || lowercase_target.contains(".ssh/")
}

fn approval_scope_hint(target: &str) -> String {
    if let Some((prefix, _)) = target.rsplit_once('/') {
        format!("path:{prefix}/**")
    } else {
        format!("path:{target}")
    }
}

fn action_scope_hint(action_key: &str) -> String {
    format!("action:{action_key}")
}

fn current_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use descry_core::acp::{Action, Actor, Asset, BlastRadius, Context, Intent};
    use descry_core::{
        Decision, EvidenceRef, EvidenceSource, ScopeContract, ScopePermit, ScopePermitKind,
    };
    use descry_memory::Approval;
    use descry_policy::Policy;

    use super::*;

    fn acp(action_type: &str, target: &str) -> ActionContextPacket {
        ActionContextPacket {
            actor: Actor {
                actor_type: String::from("agent"),
                name: String::from("codex"),
                owner: String::from("local"),
                trust_level: String::from("local_dev_agent"),
            },
            action: Action {
                action_type: action_type.to_string(),
                verb: String::from("run"),
                target: target.to_string(),
                targets: Vec::new(),
                diff_summary: None,
                argument_keys: Vec::new(),
            },
            intent: Intent {
                active_task: None,
                user_prompt: None,
                source: String::from("unknown"),
                linked_issue: None,
            },
            asset: Asset {
                asset_type: String::from("shell_command"),
                sensitivity: String::from("low"),
                environment: String::from("local"),
            },
            context: Context {
                repo: String::from("descry"),
                branch: String::from("main"),
                recent_files: Vec::new(),
                recent_approvals: Vec::new(),
            },
            blast_radius: BlastRadius {
                reversible: true,
                customer_impact: String::from("none"),
                financial_impact: String::from("none"),
            },
            instruction_provenance: None,
        }
    }

    #[test]
    fn classifies_force_push_as_git_rewrite() {
        let action = classify_action(&acp("shell.exec", "git push origin main --force"));

        assert_eq!(action.class, ActionClass::GitRewrite);
    }

    #[test]
    fn classifies_git_rewrite_variants() {
        let cases = [
            "git push --force origin main",
            "git push -f origin release/2026-05",
            "git reset --hard",
            "git clean -fdx",
        ];

        for target in cases {
            let action = classify_action(&acp("shell.exec", target));

            assert_eq!(action.class, ActionClass::GitRewrite, "{target}");
        }
    }

    #[test]
    fn classifies_rm_rf_as_shell_delete() {
        let action = classify_action(&acp("shell.exec", "rm -rf ~"));

        assert_eq!(action.class, ActionClass::ShellDelete);
    }

    #[test]
    fn classifies_sql_delete_without_where_only_as_database_destroy() {
        let without_where = classify_action(&acp(
            "shell.exec",
            "psql \"$DATABASE_URL\" -c 'DELETE FROM users'",
        ));
        let with_where = classify_action(&acp(
            "shell.exec",
            "mysql -e \"DELETE FROM users WHERE id = 42\"",
        ));

        assert_eq!(without_where.class, ActionClass::DatabaseDestroy);
        assert_ne!(with_where.class, ActionClass::DatabaseDestroy);
    }

    #[test]
    fn classifies_cloud_delete_and_deploy_commands() {
        let cloud_delete_cases = [
            "railway volume delete data",
            "fly apps destroy prod-app",
            "aws ec2 terminate-instances --instance-ids i-123",
            "gcloud compute instances delete prod-vm",
            "az group delete --name prod",
        ];
        for target in cloud_delete_cases {
            let action = classify_action(&acp("shell.exec", target));

            assert_eq!(action.class, ActionClass::CloudDelete, "{target}");
        }

        for target in [
            "vercel --prod",
            "npm run deploy",
            "fly deploy",
            "railway up",
        ] {
            let action = classify_action(&acp("shell.exec", target));

            assert_eq!(action.class, ActionClass::Deploy, "{target}");
        }
    }

    #[test]
    fn classifies_mcp_read_write_and_destroy() {
        let read = classify_action(&acp("mcp.call", "dev:list_projects"));
        let write = classify_action(&acp("mcp.call", "dev:create_project"));
        let destroy = classify_action(&acp("mcp.call", "dev:delete_project"));
        let mut confirm_destroy = acp("mcp.call", "dev:update_project");
        confirm_destroy.action.argument_keys = vec![String::from("confirm_destroy")];

        assert_eq!(read.class, ActionClass::McpRead);
        assert_eq!(write.class, ActionClass::McpWrite);
        assert_eq!(destroy.class, ActionClass::McpDestroy);
        assert_eq!(
            classify_action(&confirm_destroy).class,
            ActionClass::McpDestroy
        );
    }

    fn no_hard_blocks_policy() -> Policy {
        Policy::load_yaml(
            r#"
project:
  name: test
  version: "1"
hard_blocks: []
"#,
        )
        .expect("policy loads")
    }

    fn safe_defaults_policy() -> Policy {
        Policy::load_yaml(include_str!("../../../policies/safe-defaults.yml"))
            .expect("safe defaults policy loads")
    }

    fn temp_path(name: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time is after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "descry-engine-test-{name}-{}-{nanos}",
            std::process::id()
        ))
    }

    fn evaluate_acp(acp: ActionContextPacket, project_config: &ProjectPolicy) -> DecisionOutput {
        let approvals_path = temp_path("approvals.jsonl");
        evaluate_acp_with_approvals(
            acp,
            project_config,
            no_hard_blocks_policy(),
            &approvals_path,
        )
    }

    fn evaluate_acp_with_approvals(
        acp: ActionContextPacket,
        project_config: &ProjectPolicy,
        policy: Policy,
        approvals_path: &Path,
    ) -> DecisionOutput {
        evaluate(
            build_decision_input(acp),
            EvaluationRuntime {
                policy: &policy,
                project_config,
                approvals_path,
                behavior_path: &temp_path("behavior.json"),
                project_index: None,
                shadow: false,
            },
        )
    }

    fn evaluate_acp_with_legacy_asset_policy(
        acp: ActionContextPacket,
        project_config: &ProjectPolicy,
        legacy_asset_policy_path: &Path,
    ) -> DecisionOutput {
        evaluate_with_legacy_asset_policy(
            build_decision_input(acp),
            EvaluationRuntime {
                policy: &no_hard_blocks_policy(),
                project_config,
                approvals_path: &temp_path("approvals.jsonl"),
                behavior_path: &temp_path("behavior.json"),
                project_index: None,
                shadow: false,
            },
            Some(legacy_asset_policy_path),
        )
    }

    fn evaluate_acp_with_memory(
        acp: ActionContextPacket,
        project_config: &ProjectPolicy,
        policy: &Policy,
        approvals_path: &Path,
        behavior_path: &Path,
    ) -> DecisionOutput {
        evaluate(
            build_decision_input(acp),
            EvaluationRuntime {
                policy,
                project_config,
                approvals_path,
                behavior_path,
                project_index: None,
                shadow: false,
            },
        )
    }

    fn append_scope_contract(
        approvals_path: &Path,
        pattern: &str,
        action_classes: Vec<ActionClass>,
    ) {
        let contract = ScopeContract::signed(
            "Fix auth session",
            vec![EvidenceRef::new(
                EvidenceSource::ActiveTask,
                "active-task",
                "Fix auth session",
            )],
            vec![ScopePermit::new(
                ScopePermitKind::Path,
                pattern,
                action_classes,
                "test scope",
            )],
            1,
            u64::MAX,
            0.8,
        )
        .expect("scope contract signs");
        descry_memory::append_scope_contract(&scope_contracts_path(approvals_path), &contract)
            .expect("scope contract appends");
    }

    fn append_malformed_scope_contract(approvals_path: &Path) {
        fs::write(scope_contracts_path(approvals_path), "not-json\n")
            .expect("malformed scope contract writes");
    }

    fn decision_fingerprint(decision: &DecisionOutput) -> String {
        format!(
            "{:?}|{}|{}|{}|{:?}",
            decision.decision,
            decision.risk_score.0,
            decision.confidence.0,
            decision.reason,
            decision.conditions
        )
    }

    fn active_file_write(target: &str, task: &str) -> ActionContextPacket {
        let mut acp = acp("file.write", target);
        acp.intent.active_task = Some(task.to_string());
        acp.action.verb = String::from("modify");
        acp
    }

    #[test]
    fn active_task_does_not_bypass_secret_file_block() {
        let decision = evaluate_acp(
            active_file_write(".env.production", "fix production session expiry"),
            &ProjectPolicy::default(),
        );

        assert_eq!(decision.decision, Decision::Block);
        assert!(decision.reason.contains("asset policy"));
    }

    #[test]
    fn active_scope_contract_allows_matching_source_write_without_task_context() {
        let approvals_path = temp_path("scope-approvals.jsonl");
        let behavior_path = temp_path("scope-behavior.json");
        append_scope_contract(&approvals_path, "src/auth/**", vec![ActionClass::FileWrite]);

        let decision = evaluate_acp_with_memory(
            acp("file.write", "src/auth/session.rs"),
            &ProjectPolicy::default(),
            &no_hard_blocks_policy(),
            &approvals_path,
            &behavior_path,
        );

        assert_eq!(decision.decision, Decision::Allow);
        assert!(decision.reason.contains("active scope contract"));
        assert!(decision.reason.contains("permit src/auth/**"));
    }

    #[test]
    fn active_scope_contract_mismatch_requires_approval() {
        let approvals_path = temp_path("scope-mismatch-approvals.jsonl");
        let behavior_path = temp_path("scope-mismatch-behavior.json");
        append_scope_contract(&approvals_path, "src/auth/**", vec![ActionClass::FileWrite]);

        let decision = evaluate_acp_with_memory(
            acp("file.write", "src/billing/invoice.rs"),
            &ProjectPolicy::default(),
            &no_hard_blocks_policy(),
            &approvals_path,
            &behavior_path,
        );

        assert_eq!(decision.decision, Decision::RequireApproval);
        assert!(decision
            .reason
            .contains("does not match active scope contract"));
        assert!(decision.reason.contains("semantic scope stage"));
    }

    #[test]
    fn active_scope_contract_does_not_bypass_infra_approval() {
        let approvals_path = temp_path("scope-infra-approvals.jsonl");
        let behavior_path = temp_path("scope-infra-behavior.json");
        append_scope_contract(
            &approvals_path,
            ".github/workflows/**",
            vec![ActionClass::FileWrite],
        );

        let decision = evaluate_acp_with_memory(
            acp("file.write", ".github/workflows/deploy.yml"),
            &ProjectPolicy::default(),
            &no_hard_blocks_policy(),
            &approvals_path,
            &behavior_path,
        );

        assert_eq!(decision.decision, Decision::RequireApproval);
        assert!(decision.reason.contains("asset policy"));
        assert!(!decision.reason.contains("active scope contract"));
    }

    #[test]
    fn semantic_asset_graph_requires_approval_for_railway_config_without_project_rule() {
        let project_config = ProjectPolicy::load_yaml(
            r#"
project:
  name: test
assets: []
"#,
        )
        .expect("project policy loads");

        let decision = evaluate_acp(acp("file.write", "railway.toml"), &project_config);

        assert_eq!(decision.decision, Decision::RequireApproval);
        assert!(decision.reason.contains("asset graph"));
        assert!(decision.reason.contains("hosted-control-plane:railway"));
    }

    #[test]
    fn semantic_asset_graph_requires_approval_for_production_mcp_without_hard_block() {
        let decision = evaluate_acp(
            acp("mcp.call", "https://prod-mcp.example.com/admin"),
            &ProjectPolicy::default(),
        );

        assert_eq!(decision.decision, Decision::RequireApproval);
        assert!(decision.reason.contains("asset graph"));
        assert!(decision.reason.contains("mcp-production-control-plane"));
    }

    #[test]
    fn semantic_asset_graph_does_not_weaken_destructive_cloud_block() {
        let decision = evaluate_acp(
            acp(
                "shell.exec",
                "curl -X DELETE https://api.railway.app/v1/volumes/abc",
            ),
            &ProjectPolicy::default(),
        );

        assert_eq!(decision.decision, Decision::Block);
        assert!(decision.reason.contains("action policy"));
    }

    #[test]
    fn invalid_scope_contract_does_not_allow_source_write() {
        let approvals_path = temp_path("scope-invalid-approvals.jsonl");
        let behavior_path = temp_path("scope-invalid-behavior.json");
        append_malformed_scope_contract(&approvals_path);

        let decision = evaluate_acp_with_memory(
            acp("file.write", "src/auth/session.rs"),
            &ProjectPolicy::default(),
            &no_hard_blocks_policy(),
            &approvals_path,
            &behavior_path,
        );

        assert_eq!(decision.decision, Decision::RequireApproval);
        assert!(!decision.reason.contains("active scope contract"));
    }

    #[test]
    fn representative_verdicts_are_deterministic() {
        let project_config = ProjectPolicy::default();
        let safe_defaults = safe_defaults_policy();
        let no_hard_blocks = no_hard_blocks_policy();
        let mut mcp_destroy = acp("mcp.call", "prod-mcp:delete_project");
        mcp_destroy.action.argument_keys = vec![String::from("confirm_destroy")];
        let cases = [
            (
                "tier one hard block",
                acp("shell.exec", "rm -rf ~"),
                &safe_defaults,
            ),
            (
                "matching source write",
                active_file_write("src/auth/session.rs", "fix src/auth/session.rs"),
                &no_hard_blocks,
            ),
            (
                "infra approval",
                active_file_write(".github/workflows/deploy.yml", "fix deployment workflow"),
                &no_hard_blocks,
            ),
            ("mcp destructive", mcp_destroy, &safe_defaults),
        ];

        for (name, acp, policy) in cases {
            let approvals_path = temp_path(&format!("{name}-approvals.jsonl"));
            let behavior_path = temp_path(&format!("{name}-behavior.json"));
            let first = evaluate_acp_with_memory(
                acp.clone(),
                &project_config,
                policy,
                &approvals_path,
                &behavior_path,
            );
            let second = evaluate_acp_with_memory(
                acp,
                &project_config,
                policy,
                &approvals_path,
                &behavior_path,
            );

            assert_eq!(
                decision_fingerprint(&first),
                decision_fingerprint(&second),
                "{name}"
            );
        }
    }

    #[test]
    fn current_critical_verdicts_are_preserved() {
        let safe_defaults = safe_defaults_policy();
        let project_config = ProjectPolicy::default();
        let approvals_path = temp_path("critical-approvals.jsonl");
        let behavior_path = temp_path("critical-behavior.json");

        let rm_home = evaluate_acp_with_memory(
            acp("shell.exec", "rm -rf ~"),
            &project_config,
            &safe_defaults,
            &approvals_path,
            &behavior_path,
        );
        assert_eq!(rm_home.decision, Decision::Block);

        let source_edit = evaluate_acp(
            active_file_write("src/auth/session.rs", "fix src/auth/session.rs"),
            &project_config,
        );
        assert_eq!(source_edit.decision, Decision::Allow);

        let infra_edit = evaluate_acp(
            active_file_write(".github/workflows/deploy.yml", "fix deployment workflow"),
            &project_config,
        );
        assert_eq!(infra_edit.decision, Decision::RequireApproval);

        let mut mcp_destroy = acp("mcp.call", "prod-mcp:delete_project");
        mcp_destroy.action.argument_keys = vec![String::from("confirm_destroy")];
        let mcp_decision = evaluate_acp_with_memory(
            mcp_destroy,
            &project_config,
            &safe_defaults,
            &approvals_path,
            &behavior_path,
        );
        assert!(matches!(
            mcp_decision.decision,
            Decision::Block | Decision::RequireApproval
        ));
    }

    #[test]
    fn active_task_does_not_bypass_workflow_approval() {
        let decision = evaluate_acp(
            active_file_write(".github/workflows/deploy.yml", "fix deployment workflow"),
            &ProjectPolicy::default(),
        );

        assert_eq!(decision.decision, Decision::RequireApproval);
        assert!(decision.reason.contains("asset policy"));
    }

    #[test]
    fn matching_source_task_allows_source_write() {
        let decision = evaluate_acp(
            active_file_write("src/auth/session.rs", "fix src/auth/session.rs"),
            &ProjectPolicy::default(),
        );

        assert_eq!(decision.decision, Decision::Allow);
        assert!(decision.reason.contains("matched task context score="));
        assert!(decision.reason.contains("exact path src/auth/session.rs"));
    }

    #[test]
    fn unrelated_source_task_requires_approval() {
        let mut acp = acp("file.write", "src/billing/invoice.rs");
        acp.context.branch = String::from("fix/session-expiry");
        let decision = evaluate_acp(acp, &ProjectPolicy::default());

        assert_eq!(decision.decision, Decision::RequireApproval);
        assert!(decision.reason.contains("does not match task context"));
    }

    #[test]
    fn branch_and_recent_file_context_allow_matching_source_write() {
        let mut acp = acp("file.write", "src/auth/session.ts");
        acp.context.branch = String::from("fix/session-expiry");
        acp.context.recent_files = vec![String::from("src/auth/session.ts")];

        let decision = evaluate_acp(acp, &ProjectPolicy::default());

        assert_eq!(decision.decision, Decision::Allow);
        assert!(decision.reason.contains("score=100"));
        assert!(decision.reason.contains("exact path src/auth/session.ts"));
    }

    #[test]
    fn branch_and_recent_file_context_do_not_allow_deploy_workflow() {
        let mut acp = acp("file.write", ".github/workflows/deploy.yml");
        acp.context.branch = String::from("fix/session-expiry");
        acp.context.recent_files = vec![String::from("src/auth/session.ts")];

        let decision = evaluate_acp(acp, &ProjectPolicy::default());

        assert_eq!(decision.decision, Decision::RequireApproval);
        assert!(decision.reason.contains("asset policy"));
    }

    #[test]
    fn source_test_counterpart_allows_matching_source_write() {
        let mut acp = acp("file.write", "src/auth/session.ts");
        acp.context.recent_files = vec![String::from("tests/auth/session.test.ts")];

        let decision = evaluate_acp(acp, &ProjectPolicy::default());

        assert_eq!(decision.decision, Decision::Allow);
        assert!(decision.reason.contains("source/test counterpart"));
        assert!(decision.reason.contains("tests/auth/session.test.ts"));
    }

    #[test]
    fn same_directory_plus_branch_allows_source_write() {
        let mut acp = acp("file.write", "src/auth/session.ts");
        acp.context.branch = String::from("fix/session-expiry");
        acp.context.recent_files = vec![String::from("src/auth/token.ts")];

        let decision = evaluate_acp(acp, &ProjectPolicy::default());

        assert_eq!(decision.decision, Decision::Allow);
        assert!(decision.reason.contains("near path src/auth/token.ts"));
        assert!(decision.reason.contains("terms"));
    }

    #[test]
    fn user_prompt_terms_require_approval_without_path_evidence() {
        let mut acp = acp("file.write", "src/auth/session.rs");
        acp.intent.user_prompt = Some(String::from("Fix session expiry handling"));

        let decision = evaluate_acp(acp, &ProjectPolicy::default());

        assert_eq!(decision.decision, Decision::RequireApproval);
        assert!(decision.reason.contains("weak task context match score="));
        assert!(decision.reason.contains("session"));
    }

    #[test]
    fn multi_target_patch_uses_strictest_asset_decision() {
        let mut acp = active_file_write("src/auth/session.rs", "fix session expiry");
        acp.action.targets = vec![
            String::from("src/auth/session.rs"),
            String::from(".env.production"),
        ];

        let decision = evaluate_acp(acp, &ProjectPolicy::default());

        assert_eq!(decision.decision, Decision::Block);
        assert!(decision.reason.contains(".env.production"));
    }

    #[test]
    fn multi_target_patch_uses_strictest_infra_asset_decision() {
        let mut acp = active_file_write("src/auth/session.ts", "fix src/auth/session.ts");
        acp.action.targets = vec![
            String::from("src/auth/session.ts"),
            String::from(".github/workflows/deploy.yml"),
        ];

        let decision = evaluate_acp(acp, &ProjectPolicy::default());

        assert_eq!(decision.decision, Decision::RequireApproval);
        assert!(decision.reason.contains(".github/workflows/deploy.yml"));
        assert!(decision.reason.contains("asset: infra"));
    }

    #[test]
    fn multi_target_patch_allows_two_matching_source_targets() {
        let mut acp = acp("file.write", "src/auth/session.ts");
        acp.context.branch = String::from("fix/session-expiry");
        acp.context.recent_files = vec![String::from("src/auth/session.ts")];
        acp.action.targets = vec![
            String::from("src/auth/session.ts"),
            String::from("tests/auth/session.test.ts"),
        ];

        let decision = evaluate_acp(acp, &ProjectPolicy::default());

        assert_eq!(decision.decision, Decision::Allow);
        assert!(decision.reason.contains("matched task context score="));
    }

    #[test]
    fn multi_target_patch_matches_legacy_asset_policy_per_target() {
        let asset_policy_path = temp_path("legacy-assets.yml");
        fs::write(
            &asset_policy_path,
            r#"
assets:
  - id: secure-source
    paths:
      - "src/secure/**"
    sensitivity: critical
    default_action: block
"#,
        )
        .expect("legacy asset policy writes");
        let mut acp = active_file_write("src/auth/session.ts", "fix src/auth/session.ts");
        acp.action.targets = vec![
            String::from("src/auth/session.ts"),
            String::from("src/secure/keys.ts"),
        ];

        let decision = evaluate_acp_with_legacy_asset_policy(
            acp,
            &ProjectPolicy::default(),
            &asset_policy_path,
        );

        assert_eq!(decision.decision, Decision::Block);
        assert!(decision.reason.contains("src/secure/keys.ts"));
        assert!(decision.reason.contains("asset: secure-source"));
    }

    #[test]
    fn deploy_action_policy_can_block_deploy_commands() {
        let project_config = ProjectPolicy::load_yaml(
            r#"
project:
  name: test
assets: []
actions:
  deploy:
    default_action: block
"#,
        )
        .expect("project policy loads");

        let decision = evaluate_acp(acp("shell.exec", "npm run deploy"), &project_config);

        assert_eq!(decision.decision, Decision::Block);
        assert!(decision.reason.contains("action policy"));
    }

    #[test]
    fn default_action_policy_allows_test_commands() {
        let decision = evaluate_acp(
            acp("shell.exec", "cargo test --workspace"),
            &ProjectPolicy::default(),
        );

        assert_eq!(decision.decision, Decision::Allow);
        assert!(decision.reason.contains("action policy"));
    }

    #[test]
    fn default_action_policy_allows_build_commands() {
        let decision = evaluate_acp(
            acp("shell.exec", "cargo build --workspace"),
            &ProjectPolicy::default(),
        );

        assert_eq!(decision.decision, Decision::Allow);
        assert!(decision.reason.contains("action: build"));
    }

    #[test]
    fn default_action_policy_requires_install_approval() {
        let decision = evaluate_acp(
            acp("shell.exec", "npm install left-pad"),
            &ProjectPolicy::default(),
        );

        assert_eq!(decision.decision, Decision::RequireApproval);
        assert!(decision.reason.contains("action: install"));
    }

    #[test]
    fn default_action_policy_requires_git_rewrite_approval() {
        let decision = evaluate_acp(
            acp("shell.exec", "git reset --hard"),
            &ProjectPolicy::default(),
        );

        assert_eq!(decision.decision, Decision::RequireApproval);
        assert!(decision.reason.contains("action: git_rewrite"));
    }

    #[test]
    fn default_action_policy_requires_mcp_write_approval() {
        let decision = evaluate_acp(
            acp("mcp.call", "dev:create_project"),
            &ProjectPolicy::default(),
        );

        assert_eq!(decision.decision, Decision::RequireApproval);
        assert!(decision.reason.contains("action: mcp_write"));
    }

    #[test]
    fn asset_and_action_policy_conflict_uses_stricter_decision() {
        let project_config = ProjectPolicy::load_yaml(
            r#"
project:
  name: test
assets:
  - id: deploy-scripts
    patterns:
      - "deploy scripts/deploy/**"
    sensitivity: high
    default_action: require_approval
actions:
  deploy:
    default_action: block
"#,
        )
        .expect("project policy loads");
        let acp = acp("shell.exec", "deploy scripts/deploy/prod.sh");

        let decision = evaluate_acp(acp, &project_config);

        assert_eq!(decision.decision, Decision::Block);
    }

    #[test]
    fn path_approval_only_affects_file_targets() {
        let approvals_path = temp_path("typed-path-approvals.jsonl");
        descry_memory::append_approval(
            &approvals_path,
            &Approval {
                scope: String::from("path:crates/descry-engine/**"),
                created_at_epoch_seconds: 1,
                expires_at_epoch_seconds: u64::MAX,
                approver: String::from("human"),
            },
        )
        .expect("approval appends");

        let decision = evaluate_acp_with_approvals(
            acp("file.write", "crates/descry-engine/src/lib.rs"),
            &ProjectPolicy::default(),
            no_hard_blocks_policy(),
            &approvals_path,
        );

        assert_eq!(decision.decision, Decision::AllowWithLog);
        assert!(decision.reason.contains("scoped approval matched"));
    }

    #[test]
    fn mcp_approval_only_affects_mcp_targets() {
        let approvals_path = temp_path("typed-mcp-approvals.jsonl");
        descry_memory::append_approval(
            &approvals_path,
            &Approval {
                scope: String::from("path:https://prod-mcp.example.com/**"),
                created_at_epoch_seconds: 1,
                expires_at_epoch_seconds: u64::MAX,
                approver: String::from("human"),
            },
        )
        .expect("path approval appends");
        let policy = Policy::load_yaml(
            r#"
project:
  name: test
  version: "1"
hard_blocks:
  - id: mcp-production-control-plane
    action: mcp.call
    target_matches:
      - "prod-mcp"
    reason: production MCP control-plane access
"#,
        )
        .expect("policy loads");

        let decision = evaluate_acp_with_approvals(
            acp("mcp.call", "https://prod-mcp.example.com/admin"),
            &ProjectPolicy::default(),
            policy,
            &approvals_path,
        );

        assert_eq!(decision.decision, Decision::Block);
    }

    #[test]
    fn typed_mcp_approval_can_override_mcp_block() {
        let approvals_path = temp_path("typed-mcp-approvals.jsonl");
        descry_memory::append_approval(
            &approvals_path,
            &Approval {
                scope: String::from("mcp:https://prod-mcp.example.com/**"),
                created_at_epoch_seconds: 1,
                expires_at_epoch_seconds: u64::MAX,
                approver: String::from("human"),
            },
        )
        .expect("mcp approval appends");
        let policy = Policy::load_yaml(
            r#"
project:
  name: test
  version: "1"
hard_blocks:
  - id: mcp-production-control-plane
    action: mcp.call
    target_matches:
      - "prod-mcp"
    reason: production MCP control-plane access
"#,
        )
        .expect("policy loads");

        let decision = evaluate_acp_with_approvals(
            acp("mcp.call", "https://prod-mcp.example.com/admin"),
            &ProjectPolicy::default(),
            policy,
            &approvals_path,
        );

        assert_eq!(decision.decision, Decision::AllowWithLog);
    }

    #[test]
    fn path_approval_does_not_override_shell_hard_block() {
        let approvals_path = temp_path("typed-shell-approvals.jsonl");
        descry_memory::append_approval(
            &approvals_path,
            &Approval {
                scope: String::from("path:*"),
                created_at_epoch_seconds: 1,
                expires_at_epoch_seconds: u64::MAX,
                approver: String::from("human"),
            },
        )
        .expect("path approval appends");
        let policy = Policy::load_yaml(
            r#"
project:
  name: test
  version: "1"
hard_blocks:
  - id: rm-home
    action: shell.exec
    command_matches:
      - "rm -rf ~"
    reason: destructive home deletion
"#,
        )
        .expect("policy loads");

        let decision = evaluate_acp_with_approvals(
            acp("shell.exec", "rm -rf ~"),
            &ProjectPolicy::default(),
            policy,
            &approvals_path,
        );

        assert_eq!(decision.decision, Decision::Block);
    }

    #[test]
    fn action_approval_allows_action_policy_checkpoint() {
        let approvals_path = temp_path("typed-action-approvals.jsonl");
        descry_memory::append_approval(
            &approvals_path,
            &Approval {
                scope: String::from("action:deploy"),
                created_at_epoch_seconds: 1,
                expires_at_epoch_seconds: u64::MAX,
                approver: String::from("human"),
            },
        )
        .expect("action approval appends");
        let project_config = ProjectPolicy::load_yaml(
            r#"
project:
  name: test
assets: []
actions:
  deploy:
    default_action: require_approval
"#,
        )
        .expect("project policy loads");

        let decision = evaluate_acp_with_approvals(
            acp("shell.exec", "npm run deploy"),
            &project_config,
            no_hard_blocks_policy(),
            &approvals_path,
        );

        assert_eq!(decision.decision, Decision::AllowWithLog);
    }

    #[test]
    fn evaluate_latency_is_under_50ms_p95() {
        let project_config = ProjectPolicy::default();
        let approvals_path = temp_path("latency-approvals.jsonl");

        // Three representative actions: source edit (allow), infra edit (require_approval), rm-rf (block)
        let actions: Vec<(&str, ActionContextPacket)> = vec![
            (
                "source_edit_allow",
                active_file_write("src/auth/session.rs", "fix src/auth/session.rs"),
            ),
            (
                "infra_edit_require_approval",
                active_file_write(".github/workflows/deploy.yml", "fix deployment workflow"),
            ),
            ("rm_rf_block", acp("shell.exec", "rm -rf ~")),
        ];

        let mut durations: Vec<std::time::Duration> = Vec::with_capacity(300);

        for _ in 0..100 {
            for (_, action) in &actions {
                let start = std::time::Instant::now();
                let _ = evaluate_acp_with_approvals(
                    action.clone(),
                    &project_config,
                    no_hard_blocks_policy(),
                    &approvals_path,
                );
                durations.push(start.elapsed());
            }
        }

        durations.sort_unstable();

        let p50_idx = (durations.len() as f64 * 0.50) as usize;
        let p95_idx = (durations.len() as f64 * 0.95) as usize;
        let p50 = durations[p50_idx.min(durations.len() - 1)];
        let p95 = durations[p95_idx.min(durations.len() - 1)];

        let limit_p95 = std::time::Duration::from_millis(50);
        // Debug builds are ~3–5× slower; 25ms still catches 5× regressions in release.
        #[cfg(debug_assertions)]
        let limit_p50 = std::time::Duration::from_millis(25);
        #[cfg(not(debug_assertions))]
        let limit_p50 = std::time::Duration::from_millis(10);

        assert!(
            p95 < limit_p95,
            "p95 latency {p95:?} exceeds 50ms threshold (p50={p50:?})"
        );
        assert!(
            p50 < limit_p50,
            "p50 latency {p50:?} exceeds 10ms threshold (p95={p95:?})"
        );
    }
}
