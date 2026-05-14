use clap::CommandFactory;
use descry_cli::Cli;

#[test]
fn version_contains_package_version() {
    let command = Cli::command();
    let version = command.render_version().to_string();

    assert!(
        version.contains("descry 0.1.0"),
        "unexpected version output: {version}"
    );
}
