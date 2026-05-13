use descry_cli::{run_with_io, Cli, Commands};
use serde_json::Value;

#[test]
fn evaluate_stdin_outputs_allow_decision() {
    let cli = Cli {
        command: Commands::Evaluate { stdin: true },
    };
    let mut input = include_str!("../../descry-core/tests/fixtures/spec_example.json").as_bytes();
    let mut output = Vec::new();
    let mut error = Vec::new();

    run_with_io(cli, &mut input, &mut output, &mut error).expect("evaluate succeeds");

    assert!(error.is_empty());

    let json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(json["decision"], "allow");
}
