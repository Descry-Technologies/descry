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

pub fn evaluate(mut input: DecisionInput, runtime: EvaluationRuntime<'_>) -> DecisionOutput {
    if input.asset.is_none() {
        input.asset = runtime.project_config.match_asset(&input.acp.action.target);
    }
    let policy_decision = runtime.policy.evaluate(&input.acp);
    apply_approval_layer(policy_decision, &input, &runtime)
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

fn apply_approval_layer(
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
    let Some(asset) = input.asset.as_ref() else {
        return decision;
    };
    if asset.default_action == "block" && acp.action.action_type == "file.read" {
        return DecisionOutput {
            decision: Decision::Block,
            risk_score: RiskScore::try_from(95).expect("95 is a valid risk score"),
            confidence: Confidence::try_from(0.95).expect("0.95 is a valid confidence"),
            reason: format!(
                "{} read target {} is blocked by asset policy (asset: {})",
                asset.sensitivity, acp.action.target, asset.id
            ),
            conditions: Vec::new(),
        };
    }
    if acp.action.action_type != "file.write" {
        return decision;
    }
    if acp.intent.active_task.is_some() {
        return decision;
    }
    if asset.default_action == "allow_if_context_matches" && task_matches_target(input) {
        return DecisionOutput {
            decision: Decision::Allow,
            risk_score: RiskScore::try_from(20).expect("20 is a valid risk score"),
            confidence: Confidence::try_from(0.75).expect("0.75 is a valid confidence"),
            reason: format!(
                "allowed: {} matches inferred task context \"{}\" (asset: {})",
                acp.action.target, input.task.summary, asset.id
            ),
            conditions: Vec::new(),
        };
    }

    let now = current_epoch_seconds();
    let has_approval = descry_memory::has_live_approval_for_target(
        runtime.approvals_path,
        &acp.action.target,
        now,
    )
    .unwrap_or(false);

    if has_approval {
        DecisionOutput {
            decision: Decision::AllowWithLog,
            risk_score: RiskScore::try_from(45).expect("45 is a valid risk score"),
            confidence: Confidence::try_from(0.9).expect("0.9 is a valid confidence"),
            reason: format!(
                "scoped approval matched {} write target {} (asset: {})",
                asset.sensitivity, acp.action.target, asset.id
            ),
            conditions: vec![String::from("Approval applies only until its TTL expires")],
        }
    } else if asset.default_action == "block" {
        DecisionOutput {
            decision: Decision::Block,
            risk_score: RiskScore::try_from(95).expect("95 is a valid risk score"),
            confidence: Confidence::try_from(0.95).expect("0.95 is a valid confidence"),
            reason: format!(
                "{} write target {} is blocked by asset policy (asset: {})",
                asset.sensitivity, acp.action.target, asset.id
            ),
            conditions: vec![format!(
                "Run: descry approve --scope '{}' --ttl 30m for an explicit override",
                approval_scope_hint(&acp.action.target)
            )],
        }
    } else {
        let previous_attempts = descry_memory::behavior_count(
            runtime.behavior_path,
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
                "{} write target {} requires scoped approval{} (asset: {})",
                asset.sensitivity, acp.action.target, repeat_context, asset.id
            ),
            conditions: vec![format!(
                "Run: descry approve --scope '{}' --ttl 30m",
                approval_scope_hint(&acp.action.target)
            )],
        }
    }
}

fn apply_mcp_approval_override(
    decision: DecisionOutput,
    acp: &ActionContextPacket,
    approvals_path: &Path,
) -> DecisionOutput {
    let now = current_epoch_seconds();
    let has_approval =
        descry_memory::has_live_approval_for_target(approvals_path, &acp.action.target, now)
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

fn task_matches_target(input: &DecisionInput) -> bool {
    let target = input.acp.action.target.to_ascii_lowercase();
    input
        .task
        .likely_paths
        .iter()
        .any(|path| target == path.to_ascii_lowercase())
        || input
            .task
            .likely_terms
            .iter()
            .any(|term| target.contains(term))
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
        format!("{prefix}/**")
    } else {
        target.to_string()
    }
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
                diff_summary: None,
                argument_keys: Vec::new(),
            },
            intent: Intent {
                active_task: None,
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
}
