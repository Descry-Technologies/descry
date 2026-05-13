use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use descry_core::ActionContextPacket;
use descry_engine::{build_decision_input, evaluate, EvaluationRuntime};
use descry_policy::ProjectPolicy;
use serde_json::json;

use crate::{CliError, Result};

pub struct EvaluateConfig {
    pub policy: PathBuf,
    pub project: PathBuf,
    pub approvals: PathBuf,
    pub behavior: PathBuf,
}

pub fn run(
    stdin: bool,
    config: EvaluateConfig,
    input: &mut dyn Read,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> Result<()> {
    if !stdin {
        writeln!(error, "{}", json!({ "error": "evaluate requires --stdin" }))?;
        return Err(CliError::new("", 2));
    }

    let mut body = Vec::new();
    input.read_to_end(&mut body)?;

    match serde_json::from_slice::<ActionContextPacket>(&body) {
        Ok(acp) => {
            let loaded_policy = crate::commands::policy_source::load_policy(&config.policy)?;
            let project_config = load_project_policy(&config.project)?;
            let decision_input = build_decision_input(acp);
            let decision = evaluate(
                decision_input,
                EvaluationRuntime {
                    policy: &loaded_policy.policy,
                    project_config: &project_config,
                    approvals_path: &config.approvals,
                    behavior_path: &config.behavior,
                },
            );
            serde_json::to_writer(output, &decision)
                .map_err(|error| CliError::new(error.to_string(), 1))?;
            Ok(())
        }
        Err(parse_error) => {
            writeln!(error, "{}", json!({ "error": parse_error.to_string() }))?;
            Err(CliError::new("", 2))
        }
    }
}

pub(crate) fn load_project_policy(path: &Path) -> Result<ProjectPolicy> {
    if !path.exists() {
        return Ok(ProjectPolicy::default());
    }

    let body = fs::read_to_string(path)?;
    ProjectPolicy::load_yaml(&body).map_err(|error| CliError::new(error.to_string(), 2))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{run, EvaluateConfig};

    fn config() -> EvaluateConfig {
        EvaluateConfig {
            policy: PathBuf::from("policies/safe-defaults.yml"),
            project: PathBuf::from(".descry/project.yml"),
            approvals: PathBuf::from(".descry/memory/approvals.jsonl"),
            behavior: PathBuf::from(".descry/memory/behavior.json"),
        }
    }

    #[test]
    fn evaluate_stdin_writes_allow_decision() {
        let mut input =
            include_bytes!("../../../descry-core/tests/fixtures/spec_example.json").as_slice();
        let mut output = Vec::new();
        let mut error = Vec::new();

        run(true, config(), &mut input, &mut output, &mut error).expect("evaluate succeeds");

        let output = String::from_utf8(output).expect("stdout is utf8");
        assert!(output.contains(r#""decision":"allow""#));
        assert!(error.is_empty());
    }

    #[test]
    fn evaluate_stdin_rejects_malformed_json() {
        let mut input = "{not json".as_bytes();
        let mut output = Vec::new();
        let mut error = Vec::new();

        let failure =
            run(true, config(), &mut input, &mut output, &mut error).expect_err("parse fails");

        assert_eq!(failure.exit_code(), 2);
        assert!(output.is_empty());
        assert!(String::from_utf8(error)
            .expect("stderr is utf8")
            .contains(r#""error":"#));
    }
}
