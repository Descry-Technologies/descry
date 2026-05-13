use std::io::{Read, Write};

use descry_core::{ActionContextPacket, Confidence, Decision, DecisionOutput, RiskScore};
use serde_json::json;

use crate::{CliError, Result};

pub fn run(
    stdin: bool,
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
        Ok(_acp) => {
            serde_json::to_writer(output, &shim_decision())
                .map_err(|error| CliError::new(error.to_string(), 1))?;
            Ok(())
        }
        Err(parse_error) => {
            writeln!(error, "{}", json!({ "error": parse_error.to_string() }))?;
            Err(CliError::new("", 2))
        }
    }
}

fn shim_decision() -> DecisionOutput {
    DecisionOutput {
        decision: Decision::Allow,
        risk_score: RiskScore::try_from(0).expect("zero is a valid risk score"),
        confidence: Confidence::try_from(1.0).expect("one is a valid confidence"),
        reason: String::from("shim: no policy yet"),
        conditions: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::run;

    #[test]
    fn evaluate_stdin_writes_allow_decision() {
        let mut input =
            include_bytes!("../../../descry-core/tests/fixtures/spec_example.json").as_slice();
        let mut output = Vec::new();
        let mut error = Vec::new();

        run(true, &mut input, &mut output, &mut error).expect("evaluate succeeds");

        let output = String::from_utf8(output).expect("stdout is utf8");
        assert!(output.contains(r#""decision":"allow""#));
        assert!(error.is_empty());
    }

    #[test]
    fn evaluate_stdin_rejects_malformed_json() {
        let mut input = "{not json".as_bytes();
        let mut output = Vec::new();
        let mut error = Vec::new();

        let failure = run(true, &mut input, &mut output, &mut error).expect_err("parse fails");

        assert_eq!(failure.exit_code(), 2);
        assert!(output.is_empty());
        assert!(String::from_utf8(error)
            .expect("stderr is utf8")
            .contains(r#""error":"#));
    }
}
