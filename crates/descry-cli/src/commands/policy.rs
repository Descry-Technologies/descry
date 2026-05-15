use std::io::Write;
use std::path::Path;

use descry_core::{ActionContextPacket, Decision};
use descry_engine::{build_decision_input, evaluate, EvaluationRuntime};
use serde::Deserialize;
use serde_json::json;

use crate::commands::evaluate::load_project_policy;
use crate::commands::policy_source::load_policy;
use crate::{CliError, ExpectedVerdict, PolicyAction, Result};

pub fn run(action: PolicyAction, output: &mut dyn Write) -> Result<()> {
    match action {
        PolicyAction::Test {
            fixture,
            expect,
            policy,
            project,
            approvals,
            behavior,
            hard_block_only,
        } => {
            let loaded_policy = load_policy(&policy)?;

            let fixture_body = std::fs::read_to_string(&fixture)?;
            let acp: ActionContextPacket =
                serde_json::from_str(&fixture_body).map_err(|error| {
                    CliError::new(
                        format!("failed to parse fixture {}: {error}", fixture.display()),
                        2,
                    )
                })?;

            let decision = if hard_block_only {
                loaded_policy.policy.evaluate(&acp)
            } else {
                let project_config = load_project_policy(&project)?;
                evaluate(
                    build_decision_input(acp),
                    EvaluationRuntime {
                        policy: &loaded_policy.policy,
                        project_config: &project_config,
                        approvals_path: &approvals,
                        behavior_path: &behavior,
                        project_index: None,
                        shadow: false,
                    },
                )
            };
            let verdict = verdict_name(&decision.decision);
            let expected = expect.as_str();
            let matches = verdict == expected;
            let rule = matched_rule_id(&decision.reason);

            writeln!(
                output,
                "{}",
                json!({
                    "rule": rule,
                    "verdict": verdict,
                    "expected": expected,
                    "match": matches
                })
            )?;

            if matches {
                Ok(())
            } else {
                Err(CliError::new("", 1))
            }
        }
        PolicyAction::Precision {
            manifest,
            policy,
            project,
            approvals,
            behavior,
            min_precision,
        } => run_precision(
            &manifest,
            &policy,
            &project,
            &approvals,
            &behavior,
            min_precision,
            output,
        ),
    }
}

#[derive(Debug, Deserialize)]
struct ManifestEntry {
    path: String,
    expected_decision: String,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    notes: Option<String>,
}

fn run_precision(
    manifest_path: &Path,
    policy_path: &Path,
    project_path: &Path,
    approvals_path: &Path,
    behavior_path: &Path,
    min_precision: f64,
    output: &mut dyn Write,
) -> Result<()> {
    let manifest_body = std::fs::read_to_string(manifest_path).map_err(|e| {
        CliError::new(
            format!("failed to read manifest {}: {e}", manifest_path.display()),
            2,
        )
    })?;
    let entries: Vec<ManifestEntry> = serde_yml::from_str(&manifest_body).map_err(|e| {
        CliError::new(format!("failed to parse manifest: {e}"), 2)
    })?;

    let loaded_policy = load_policy(policy_path)?;
    let project_config = load_project_policy(project_path)?;

    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("."));

    let mut total = 0u32;
    let mut correct = 0u32;
    let mut true_positive = 0u32;
    let mut false_positive = 0u32;
    let mut false_negative = 0u32;
    let mut mismatches: Vec<serde_json::Value> = Vec::new();

    for entry in &entries {
        let fixture_path = workspace_root.join(&entry.path);
        let fixture_body = match std::fs::read_to_string(&fixture_path) {
            Ok(body) => body,
            Err(e) => {
                writeln!(
                    output,
                    "{}",
                    json!({"warning": format!("skipping {}: {e}", entry.path)})
                )?;
                continue;
            }
        };
        let acp: ActionContextPacket = match serde_json::from_str(&fixture_body) {
            Ok(acp) => acp,
            Err(e) => {
                writeln!(
                    output,
                    "{}",
                    json!({"warning": format!("invalid fixture {}: {e}", entry.path)})
                )?;
                continue;
            }
        };

        let decision = evaluate(
            build_decision_input(acp),
            EvaluationRuntime {
                policy: &loaded_policy.policy,
                project_config: &project_config,
                approvals_path,
                behavior_path,
                project_index: None,
                shadow: false,
            },
        );
        let actual = verdict_name(&decision.decision);
        let expected = entry.expected_decision.as_str();
        let matches = actual == expected;

        total += 1;
        if matches {
            correct += 1;
        } else {
            mismatches.push(json!({
                "path": entry.path,
                "expected": expected,
                "actual": actual,
                "category": entry.category,
                "reason": decision.reason,
            }));
        }

        let expected_is_block = expected == "block";
        let actual_is_block = actual == "block";

        match (expected_is_block, actual_is_block) {
            (true, true) => true_positive += 1,
            (false, true) => false_positive += 1,
            (true, false) => false_negative += 1,
            (false, false) => {}
        }
    }

    let total_block_predictions = true_positive + false_positive;
    let precision = if total_block_predictions == 0 {
        1.0f64
    } else {
        f64::from(true_positive) / f64::from(total_block_predictions)
    };
    let total_actual_blocks = true_positive + false_negative;
    let recall = if total_actual_blocks == 0 {
        1.0f64
    } else {
        f64::from(true_positive) / f64::from(total_actual_blocks)
    };
    let false_positive_rate = if total == 0 {
        0.0f64
    } else {
        f64::from(false_positive) / f64::from(total)
    };

    let passes = precision >= min_precision;

    writeln!(
        output,
        "{}",
        json!({
            "total": total,
            "correct": correct,
            "true_positive": true_positive,
            "false_positive": false_positive,
            "false_negative": false_negative,
            "precision": precision,
            "recall": recall,
            "false_positive_rate": false_positive_rate,
            "min_precision": min_precision,
            "passes": passes,
            "mismatches": mismatches,
        })
    )?;

    if passes {
        Ok(())
    } else {
        Err(CliError::new(
            format!(
                "block precision {precision:.3} is below minimum {min_precision:.3} ({false_positive} false positive(s) among {total_block_predictions} block decisions)"
            ),
            1,
        ))
    }
}

impl ExpectedVerdict {
    fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::AllowWithLog => "allow_with_log",
            Self::Ask => "ask",
            Self::RequireApproval => "require_approval",
            Self::Block => "block",
        }
    }
}

fn verdict_name(decision: &Decision) -> &'static str {
    match decision {
        Decision::Allow => "allow",
        Decision::AllowWithLog => "allow_with_log",
        Decision::Ask => "ask",
        Decision::RequireApproval => "require_approval",
        Decision::Block => "block",
    }
}

fn matched_rule_id(reason: &str) -> Option<String> {
    reason
        .rsplit_once("(rule: ")
        .and_then(|(_, suffix)| suffix.strip_suffix(')'))
        .map(String::from)
}
