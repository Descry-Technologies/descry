use std::io::Write;

use serde_json::json;

use crate::{ContextAction, Result};

pub fn run(action: ContextAction, output: &mut dyn Write) -> Result<()> {
    match action {
        ContextAction::Build {
            project,
            output_path,
        } => {
            let index = descry_context::build_project_index(&project)?;
            descry_context::write_project_index(&index, &output_path)?;
            writeln!(
                output,
                "{}",
                json!({
                    "project": project,
                    "index": output_path,
                    "repo_name": index.repo_name,
                    "branch": index.branch,
                    "languages": index.languages,
                    "frameworks": index.frameworks
                })
            )?;
            Ok(())
        }
        ContextAction::Show { path } => {
            let index = descry_context::read_project_index(&path)?;
            serde_json::to_writer_pretty(&mut *output, &index)
                .map_err(|error| crate::CliError::new(error.to_string(), 1))?;
            writeln!(output)?;
            Ok(())
        }
    }
}
