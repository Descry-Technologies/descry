use descry_cli::{run_with_io, Cli, Commands, DemoAction};

#[test]
fn launch_demos_print_required_trace_fields() {
    let cases = [
        (demo_in_task_edit(), "in-task-edit", "allow"),
        (demo_pocketos(), "pocketos", "block"),
        (demo_rm_rf(), "rm-rf", "block"),
        (demo_secret_access(), "secret-access", "block"),
        (demo_off_task_edit(), "off-task-edit", "require_approval"),
        (demo_mcp_poison(), "mcp-poison", "block"),
        (demo_prod_delete(), "prod-delete", "block"),
    ];

    for (action, name, expected_decision) in cases {
        let cli = Cli {
            command: Commands::Demo { action },
        };
        let mut input = [].as_slice();
        let mut output = Vec::new();
        let mut error = Vec::new();

        run_with_io(cli, &mut input, &mut output, &mut error).expect("demo succeeds");

        assert!(error.is_empty(), "{name}");
        let output = String::from_utf8(output).expect("stdout is utf8");
        assert!(output.contains(&format!("descry demo {name}")), "{name}");
        assert!(output.contains("prompt/context:"), "{name}");
        assert!(output.contains("inferred task:"), "{name}");
        assert!(output.contains("proposed action:"), "{name}");
        assert!(output.contains("classified action:"), "{name}");
        assert!(output.contains("asset match:"), "{name}");
        assert!(
            output.contains(&format!("decision: {expected_decision}")),
            "{name}"
        );
        assert!(output.contains("reason:"), "{name}");
        assert!(output.contains("without Descry:"), "{name}");
    }
}

#[test]
fn demo_in_task_edit_allows_matching_source_change() {
    let output = run_demo(demo_in_task_edit());

    assert!(output.contains("asset match: source"));
    assert!(output.contains("allowed: src/auth/session.ts matches inferred task context"));
}

#[test]
fn demo_secret_access_uses_asset_policy_block() {
    let output = run_demo(demo_secret_access());

    assert!(output.contains("asset match: secrets"));
    assert!(output.contains("critical read target .env.production is blocked"));
}

#[test]
fn demo_off_task_edit_requires_approval() {
    let output = run_demo(demo_off_task_edit());

    assert!(output.contains("asset match: infra"));
    assert!(output.contains("requires scoped approval"));
}

fn run_demo(action: DemoAction) -> String {
    let cli = Cli {
        command: Commands::Demo { action },
    };
    let mut input = [].as_slice();
    let mut output = Vec::new();
    let mut error = Vec::new();

    run_with_io(cli, &mut input, &mut output, &mut error).expect("demo succeeds");

    assert!(error.is_empty());
    String::from_utf8(output).expect("stdout is utf8")
}

fn demo_in_task_edit() -> DemoAction {
    DemoAction::InTaskEdit {
        policy: policy_path(),
    }
}

fn demo_pocketos() -> DemoAction {
    DemoAction::Pocketos {
        policy: policy_path(),
    }
}

fn demo_rm_rf() -> DemoAction {
    DemoAction::RmRf {
        policy: policy_path(),
    }
}

fn demo_secret_access() -> DemoAction {
    DemoAction::SecretAccess {
        policy: policy_path(),
    }
}

fn demo_off_task_edit() -> DemoAction {
    DemoAction::OffTaskEdit {
        policy: policy_path(),
    }
}

fn demo_mcp_poison() -> DemoAction {
    DemoAction::McpPoison {
        policy: policy_path(),
    }
}

fn demo_prod_delete() -> DemoAction {
    DemoAction::ProdDelete {
        policy: policy_path(),
    }
}

fn policy_path() -> std::path::PathBuf {
    workspace_root().join("policies/safe-defaults.yml")
}

fn workspace_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate has workspace parent")
        .parent()
        .expect("crates dir has workspace parent")
        .to_path_buf()
}
