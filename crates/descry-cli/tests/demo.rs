use descry_cli::{run_with_io, Cli, Commands, DemoAction};

#[test]
fn demo_pocketos_prints_two_column_block_trace() {
    let cli = Cli {
        command: Commands::Demo {
            action: DemoAction::Pocketos {
                policy: workspace_root().join("policies/safe-defaults.yml"),
            },
        },
    };
    let mut input = [].as_slice();
    let mut output = Vec::new();
    let mut error = Vec::new();

    run_with_io(cli, &mut input, &mut output, &mut error).expect("demo succeeds");

    assert!(error.is_empty());
    let output = String::from_utf8(output).expect("stdout is utf8");
    assert!(output.contains("WITH DESCRY"));
    assert!(output.contains("WITHOUT DESCRY"));
    assert!(output.contains("BLOCKED before execution"));
    assert!(output.contains("production volume deleted"));
    assert!(output.contains("decision: block"));
    assert!(output.contains("control-plane-delete"));
}

fn workspace_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate has workspace parent")
        .parent()
        .expect("crates dir has workspace parent")
        .to_path_buf()
}
