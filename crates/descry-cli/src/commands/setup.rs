use std::io::Write;
use std::path::PathBuf;

use crate::commands::doctor::{DoctorCheck, DoctorConfig};
use crate::{DoctorAgent, Result};

pub fn run(project: PathBuf, output: &mut dyn Write) -> Result<()> {
    writeln!(output, "Descry setup")?;
    writeln!(output)?;

    // Step 1: Initialize the project
    writeln!(output, "  Initializing project...")?;

    let mut init_output = Vec::new();
    let init_result = crate::commands::init::run(
        crate::commands::init::InitConfig {
            project: project.clone(),
            dry_run: false,
            install_hooks: false,
            json: true,
        },
        &mut init_output,
    );

    let dirs_ok = init_result.is_ok();
    let dirs_icon = if dirs_ok { '✓' } else { '✗' };
    writeln!(output, "  {dirs_icon}  Created .descry/ directories")?;
    writeln!(output, "  {dirs_icon}  Wrote project policy")?;
    writeln!(output, "  {dirs_icon}  Built project index")?;
    writeln!(output)?;

    // Step 2: Install hooks
    writeln!(output, "  Installing hooks...")?;

    let claude_result = install_hook(crate::HookInstallAction::Claude {
        project: Some(project.clone()),
        settings: None,
        command: None,
    });
    let claude_icon = if claude_result.is_ok() { '✓' } else { '✗' };
    writeln!(output, "  {claude_icon}  Claude Code")?;

    let git_result = install_hook(crate::HookInstallAction::Git {
        project: project.clone(),
        hook: String::from("pre-push"),
        command: None,
    });
    let git_icon = if git_result.is_ok() { '✓' } else { '✗' };
    writeln!(output, "  {git_icon}  Git pre-push")?;

    writeln!(output)?;

    // Step 3: Run a quick doctor check (hooks + policy only) to show status
    let project_canon = std::fs::canonicalize(&project).unwrap_or(project.clone());
    let doctor_config = DoctorConfig {
        project: Some(project_canon),
        fix: false,
        agent: DoctorAgent::Claude,
        claude_settings: None,
        codex_hooks: None,
        codex_config: None,
        cursor_hooks: None,
        policy: PathBuf::from("policies/safe-defaults.yml"),
        audit: PathBuf::from(".descry/audit.log"),
        repo_id_hash: String::from("descry-default-repo"),
        json: false,
    };

    // Run doctor silently to determine overall health
    let mut doctor_sink = Vec::new();
    let all_ok = crate::commands::doctor::run(doctor_config, &mut doctor_sink).is_ok();

    if all_ok || (dirs_ok && claude_result.is_ok()) {
        writeln!(output, "Protection active. Your AI agents are now guarded.")?;
    } else {
        writeln!(
            output,
            "Setup complete with warnings. Run  descry doctor  for details."
        )?;
    }

    writeln!(output)?;
    writeln!(output, "Next steps:")?;
    writeln!(output, "  descry doctor    — full health check")?;
    writeln!(
        output,
        "  descry demo      — see Descry block a real attack"
    )?;
    writeln!(
        output,
        "  descry task set \"fix login bug\"  — set current task for better accuracy"
    )?;

    Ok(())
}

fn install_hook(action: crate::HookInstallAction) -> Result<()> {
    let mut sink = Vec::new();
    crate::commands::hook::run_install(action, &mut sink)
}

// Make DoctorCheck accessible for setup
#[allow(dead_code)]
fn _use_doctor_check(_: DoctorCheck) {}
