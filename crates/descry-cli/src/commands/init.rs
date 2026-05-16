use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::{HookInstallAction, Result};

pub struct InitConfig {
    pub project: PathBuf,
    pub dry_run: bool,
    pub install_hooks: bool,
    pub json: bool,
}

pub fn run(config: InitConfig, output: &mut dyn Write) -> Result<()> {
    let project_root = fs::canonicalize(&config.project)?;
    let descry_dir = project_root.join(".descry");
    let project_policy_path = descry_dir.join("project.yml");
    let state_dir = descry_dir.join("state");
    let memory_dir = descry_dir.join("memory");
    let index_path = state_dir.join("project-index.json");

    if config.dry_run {
        if config.json {
            writeln!(
                output,
                "{}",
                json!({
                    "dry_run": true,
                    "all": config.install_hooks,
                    "project": project_root,
                    "project_policy": project_policy_path,
                    "state": state_dir,
                    "memory": memory_dir,
                    "project_index": index_path,
                    "hooks": [],
                    "next": "descry doctor"
                })
            )?;
        } else {
            writeln!(output)?;
            writeln!(output, "[dry run] Would create:")?;
            writeln!(output, "  .descry/")?;
            writeln!(output, "  .descry/project.yml")?;
            writeln!(output, "  .descry/state/")?;
            writeln!(output, "  .descry/memory/")?;
        }
        return Ok(());
    }

    // Track outcomes for human-readable mode
    let dirs_ok = fs::create_dir_all(&state_dir)
        .and_then(|_| fs::create_dir_all(&memory_dir))
        .is_ok();

    let policy_ok = if !project_policy_path.exists() {
        let name = project_name(&project_root);
        fs::write(&project_policy_path, default_project_policy_yaml(name)).is_ok()
    } else {
        true
    };

    let index_ok = descry_context::build_project_index(&project_root)
        .and_then(|index| descry_context::write_project_index(&index, &index_path))
        .is_ok();

    let hooks: Vec<Value> = if config.install_hooks {
        install_all_hooks(&project_root).unwrap_or_default()
    } else {
        Vec::new()
    };

    if config.json {
        writeln!(
            output,
            "{}",
            json!({
                "dry_run": config.dry_run,
                "all": config.install_hooks,
                "project": project_root,
                "project_policy": project_policy_path,
                "state": state_dir,
                "memory": memory_dir,
                "project_index": index_path,
                "hooks": hooks,
                "next": "descry doctor"
            })
        )?;
    } else {
        let proj_name = project_name(&project_root);
        writeln!(output)?;
        writeln!(output, "Setting up Descry for {proj_name}/")?;

        let dirs_icon = if dirs_ok { '✓' } else { '✗' };
        writeln!(output, "  {dirs_icon}  Created .descry/ directories")?;

        let policy_icon = if policy_ok { '✓' } else { '✗' };
        writeln!(
            output,
            "  {policy_icon}  Wrote project policy  (.descry/project.yml)"
        )?;

        let index_icon = if index_ok { '✓' } else { '✗' };
        writeln!(output, "  {index_icon}  Built project index")?;

        if config.install_hooks {
            let hooks_ok = !hooks.is_empty();
            let hooks_icon = if hooks_ok { '✓' } else { '✗' };
            writeln!(output, "  {hooks_icon}  Installed hooks      (claude)")?;
        }

        writeln!(output)?;
        writeln!(output, "Done. Run  descry doctor  to verify.")?;
    }

    Ok(())
}

fn install_all_hooks(project_root: &Path) -> Result<Vec<Value>> {
    [
        HookInstallAction::Claude {
            project: Some(project_root.to_path_buf()),
            settings: None,
            command: None,
        },
        HookInstallAction::Codex {
            project: Some(project_root.to_path_buf()),
            hooks: None,
            config: None,
            command: None,
        },
        HookInstallAction::Cursor {
            project: Some(project_root.to_path_buf()),
            hooks: None,
            command: None,
            mcp_command: None,
        },
        HookInstallAction::Git {
            project: project_root.to_path_buf(),
            hook: String::from("pre-push"),
            command: None,
        },
    ]
    .into_iter()
    .map(|action| {
        let mut hook_output = Vec::new();
        crate::commands::hook::run_install(action, &mut hook_output)?;
        serde_json::from_slice(&hook_output)
            .map_err(|error| crate::CliError::new(error.to_string(), 1))
    })
    .collect()
}

fn project_name(project_root: &Path) -> String {
    project_root
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| String::from("descry"))
}

fn default_project_policy_yaml(project_name: String) -> String {
    format!(
        r#"project:
  name: {project_name}

assets:
  - id: secrets
    patterns: [".env*", "**/*secret*", "**/*token*", "~/.ssh/**"]
    sensitivity: critical
    default_action: block

  - id: infra
    patterns: ["infra/**", "terraform/**", ".github/workflows/**", "scripts/deploy/**"]
    sensitivity: high
    default_action: require_approval

  - id: source
    patterns: ["src/**", "tests/**", "crates/**"]
    sensitivity: normal
    default_action: allow_if_context_matches

actions:
  destructive:
    default_action: block
  deploy:
    default_action: require_approval
  test:
    default_action: allow
"#
    )
}
