use std::io::Write;

use descry_core::{ActionContextPacket, Decision};
use descry_engine::{build_decision_input, evaluate, EvaluationRuntime};
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
