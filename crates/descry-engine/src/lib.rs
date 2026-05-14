use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use descry_core::{
    ActionClass, ActionContextPacket, AssetMatch, ClassifiedAction, Confidence, Decision,
    DecisionInput, DecisionOutput, RiskScore, TaskEnvelope,
};
use descry_policy::{Policy, ProjectPolicy};

pub struct EvaluationRuntime<'a> {
    pub policy: &'a Policy,
    pub project_config: &'a ProjectPolicy,
    pub approvals_path: &'a Path,
    pub behavior_path: &'a Path,
}

pub fn evaluate(input: DecisionInput, runtime: EvaluationRuntime<'_>) -> DecisionOutput {
    let targets = action_targets(&input.acp);
    let mut strongest_decision = None;
    let legacy_asset = input.asset.clone();

    for target in targets {
        let mut candidate_input = input.clone();
        candidate_input.acp.action.target = target;
        candidate_input.action = classify_action(&candidate_input.acp);
        candidate_input.asset = legacy_asset.clone().or_else(|| {
            runtime
                .project_config
                .match_asset(&candidate_input.acp.action.target)
        });

        let policy_decision = runtime.policy.evaluate(&candidate_input.acp);
        let decision = apply_decision_layers(policy_decision, &candidate_input, &runtime);
        strongest_decision = Some(match strongest_decision {
            Some(current) => strongest(current, decision),
            None => decision,
        });
    }

    strongest_decision.expect("action targets are never empty")
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
    let task = TaskEnvelope::from_acp(&acp);
    let action = classify_action(&acp);

    DecisionInput {
        acp,
        event: None,
        task,
        action,
        asset,
    }
}

pub fn classify_action(acp: &ActionContextPacket) -> ClassifiedAction {
    let action_type = acp.action.action_type.as_str();
    let target = acp.action.target.trim();
    let lowercase_target = target.to_ascii_lowercase();

    let class = if action_type == "file.write" {
        ActionClass::FileWrite
    } else if action_type == "file.read" && looks_like_secret_path(target) {
        ActionClass::SecretRead
    } else if action_type == "file.read" {
        ActionClass::FileRead
    } else if action_type == "mcp.call" {
        classify_mcp(acp)
    } else if action_type == "shell.exec" {
        classify_shell(&lowercase_target)
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

fn classify_shell(lowercase_target: &str) -> ActionClass {
    if lowercase_target.starts_with("git status")
        || lowercase_target.starts_with("git diff")
        || lowercase_target.starts_with("git log")
    {
        ActionClass::GitRead
    } else if lowercase_target.starts_with("git push")
        && (lowercase_target.contains(" --force")
            || lowercase_target.contains(" -f ")
            || lowercase_target.contains(" --force-with-lease"))
    {
        ActionClass::GitRewrite
    } else if lowercase_target.starts_with("cargo test")
        || lowercase_target.starts_with("npm test")
        || lowercase_target.starts_with("npm run test")
        || lowercase_target.starts_with("pytest")
    {
        ActionClass::ShellTest
    } else if lowercase_target.starts_with("cargo build")
        || lowercase_target.starts_with("npm run build")
        || lowercase_target.starts_with("go build")
    {
        ActionClass::ShellBuild
    } else if lowercase_target.starts_with("npm install")
        || lowercase_target.starts_with("pnpm install")
        || lowercase_target.starts_with("yarn install")
        || lowercase_target.starts_with("cargo install")
    {
        ActionClass::ShellInstall
    } else if lowercase_target.contains("rm -rf")
        || lowercase_target.contains("find ") && lowercase_target.contains(" -delete")
    {
        ActionClass::ShellDelete
    } else if lowercase_target.contains("drop database")
        || lowercase_target.contains("drop table")
        || lowercase_target.contains("truncate table")
        || lowercase_target.contains("db.dropdatabase")
    {
        ActionClass::DatabaseDestroy
    } else if lowercase_target.contains("railway volume delete")
        || lowercase_target.contains("fly apps destroy")
        || lowercase_target.contains("fly volumes destroy")
        || lowercase_target.contains("aws rds delete-db-")
        || lowercase_target.contains("gcloud sql instances delete")
        || lowercase_target.contains("az group delete")
    {
        ActionClass::CloudDelete
    } else if lowercase_target.contains(" deploy")
        || lowercase_target.starts_with("deploy")
        || lowercase_target.contains("vercel --prod")
    {
        ActionClass::Deploy
    } else {
        ActionClass::Unknown
    }
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

    if text.contains("delete")
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

fn apply_decision_layers(
    decision: DecisionOutput,
    input: &DecisionInput,
    runtime: &EvaluationRuntime<'_>,
) -> DecisionOutput {
    let acp = &input.acp;
    if decision.decision == Decision::Block && acp.action.action_type == "mcp.call" {
        return apply_mcp_approval_override(decision, acp, runtime.approvals_path);
    }
    if decision.decision == Decision::Block {
        return decision;
    }

    let asset_decision = asset_policy_decision(input, runtime);
    let action_decision = action_policy_decision(input, runtime);

    strongest(strongest(decision, action_decision), asset_decision)
}

fn asset_policy_decision(input: &DecisionInput, runtime: &EvaluationRuntime<'_>) -> DecisionOutput {
    let acp = &input.acp;
    let Some(asset) = input.asset.as_ref() else {
        return allow_fallback("no asset policy matched");
    };

    if asset.default_action == "block" && acp.action.action_type == "file.read" {
        return asset_block_decision(acp, asset, "read", Vec::new());
    }
    if acp.action.action_type != "file.write" {
        return allow_fallback("asset policy does not apply to this action type");
    }

    let context_match = task_context_match(input);
    if asset.default_action == "allow_if_context_matches" && context_match.matches() {
        return DecisionOutput {
            decision: Decision::Allow,
            risk_score: RiskScore::try_from(20).expect("20 is a valid risk score"),
            confidence: Confidence::try_from(0.75).expect("0.75 is a valid confidence"),
            reason: format!(
                "allowed: {} matches inferred task context \"{}\" via {} (asset: {})",
                acp.action.target,
                input.task.summary,
                context_match.reason(),
                asset.id
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
        "require_approval" | "allow_if_context_matches" => asset_require_approval_decision(
            input,
            runtime.behavior_path,
            asset,
            if asset.default_action == "allow_if_context_matches" {
                "does not match inferred task context and requires scoped approval"
            } else {
                "requires scoped approval"
            },
        ),
        "allow" => allow_fallback("asset policy allows this target"),
        _ => allow_fallback("unknown asset default action falls back to allow"),
    }
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

struct TaskContextMatch {
    paths: Vec<String>,
    terms: Vec<String>,
}

impl TaskContextMatch {
    fn matches(&self) -> bool {
        !self.paths.is_empty() || !self.terms.is_empty()
    }

    fn reason(&self) -> String {
        let mut parts = Vec::new();
        if !self.paths.is_empty() {
            parts.push(format!("paths {}", self.paths.join(", ")));
        }
        if !self.terms.is_empty() {
            parts.push(format!("terms {}", self.terms.join(", ")));
        }
        parts.join("; ")
    }
}

fn task_context_match(input: &DecisionInput) -> TaskContextMatch {
    let target = input.acp.action.target.to_ascii_lowercase();
    let paths = input
        .task
        .likely_paths
        .iter()
        .filter(|path| target == path.to_ascii_lowercase())
        .cloned()
        .collect();
    let terms = input
        .task
        .likely_terms
        .iter()
        .filter(|term| target.contains(term.as_str()))
        .cloned()
        .collect();

    TaskContextMatch { paths, terms }
}

fn match_legacy_asset(asset_policy_path: &Path, target: &str) -> Option<AssetMatch> {
    let policy = descry_memory::load_asset_policy(asset_policy_path).ok()?;
    descry_memory::match_asset(&policy, target).map(|asset| AssetMatch {
        id: asset.id,
        sensitivity: asset.sensitivity,
        default_action: asset.default_action,
    })
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
    use descry_core::Decision;
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
        }
    }

    #[test]
    fn classifies_force_push_as_git_rewrite() {
        let action = classify_action(&acp("shell.exec", "git push origin main --force"));

        assert_eq!(action.class, ActionClass::GitRewrite);
    }

    #[test]
    fn classifies_rm_rf_as_shell_delete() {
        let action = classify_action(&acp("shell.exec", "rm -rf ~"));

        assert_eq!(action.class, ActionClass::ShellDelete);
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
            },
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
            active_file_write("src/auth/session.rs", "fix session expiry"),
            &ProjectPolicy::default(),
        );

        assert_eq!(decision.decision, Decision::Allow);
        assert!(decision.reason.contains("matches inferred task context"));
    }

    #[test]
    fn unrelated_source_task_requires_approval() {
        let decision = evaluate_acp(
            active_file_write("src/billing/invoice.rs", "fix session expiry"),
            &ProjectPolicy::default(),
        );

        assert_eq!(decision.decision, Decision::RequireApproval);
        assert!(decision
            .reason
            .contains("does not match inferred task context"));
    }

    #[test]
    fn branch_and_recent_file_context_allow_matching_source_write() {
        let mut acp = acp("file.write", "src/auth/session.ts");
        acp.context.branch = String::from("fix/session-expiry");
        acp.context.recent_files = vec![String::from("src/auth/session.ts")];

        let decision = evaluate_acp(acp, &ProjectPolicy::default());

        assert_eq!(decision.decision, Decision::Allow);
        assert!(decision.reason.contains("paths src/auth/session.ts"));
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
    fn user_prompt_contributes_task_terms() {
        let mut acp = acp("file.write", "src/auth/session.rs");
        acp.intent.user_prompt = Some(String::from("Fix session expiry handling"));

        let decision = evaluate_acp(acp, &ProjectPolicy::default());

        assert_eq!(decision.decision, Decision::Allow);
        assert!(decision.reason.contains("terms"));
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
}
