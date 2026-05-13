use descry_cli::{run_with_io, Cli, Commands, TaskAction};
use serde_json::Value;

#[test]
fn task_set_get_and_clear_round_trip_context_file() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let path = tempdir.path().join(".descry/context.md");

    let (exit_code, output) = run_task(TaskAction::Set {
        task: String::from("  Implement\nClaude hook installer  "),
        path: path.clone(),
    });
    assert_eq!(exit_code, 0);
    let json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(json["active_task"], "Implement Claude hook installer");

    let (exit_code, output) = run_task(TaskAction::Get { path: path.clone() });
    assert_eq!(exit_code, 0);
    let json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert_eq!(json["active_task"], "Implement Claude hook installer");

    let (exit_code, output) = run_task(TaskAction::Clear { path: path.clone() });
    assert_eq!(exit_code, 0);
    let json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert!(json["active_task"].is_null());

    let (exit_code, output) = run_task(TaskAction::Get { path });
    assert_eq!(exit_code, 0);
    let json: Value = serde_json::from_slice(&output).expect("stdout is json");
    assert!(json["active_task"].is_null());
}

#[test]
fn task_set_rejects_empty_task() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let path = tempdir.path().join(".descry/context.md");

    let (exit_code, output) = run_task(TaskAction::Set {
        task: String::from("  \n\t  "),
        path,
    });

    assert_eq!(exit_code, 2);
    assert!(output.is_empty());
}

fn run_task(action: TaskAction) -> (i32, Vec<u8>) {
    let cli = Cli {
        command: Commands::Task { action },
    };
    let mut input = [].as_slice();
    let mut output = Vec::new();
    let mut error = Vec::new();
    let exit_code = match run_with_io(cli, &mut input, &mut output, &mut error) {
        Ok(()) => 0,
        Err(error) => error.exit_code(),
    };
    assert!(error.is_empty());
    (exit_code, output)
}
