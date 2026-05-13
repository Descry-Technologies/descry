use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde_json::json;

use crate::Result;

pub struct InitConfig {
    pub project: PathBuf,
    pub dry_run: bool,
}

pub fn run(config: InitConfig, output: &mut dyn Write) -> Result<()> {
    let project_root = fs::canonicalize(&config.project)?;
    let descry_dir = project_root.join(".descry");
    let project_policy_path = descry_dir.join("project.yml");
    let state_dir = descry_dir.join("state");
    let memory_dir = descry_dir.join("memory");
    let index_path = state_dir.join("project-index.json");

    if !config.dry_run {
        fs::create_dir_all(&state_dir)?;
        fs::create_dir_all(&memory_dir)?;
        if !project_policy_path.exists() {
            fs::write(
                &project_policy_path,
                default_project_policy_yaml(project_name(&project_root)),
            )?;
        }
        let index = descry_context::build_project_index(&project_root)?;
        descry_context::write_project_index(&index, &index_path)?;
    }

    writeln!(
        output,
        "{}",
        json!({
            "dry_run": config.dry_run,
            "project": project_root,
            "project_policy": project_policy_path,
            "state": state_dir,
            "memory": memory_dir,
            "project_index": index_path,
            "next": "descry doctor"
        })
    )?;
    Ok(())
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
