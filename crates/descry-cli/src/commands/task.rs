use std::fs;
use std::io::Write;
use std::path::Path;

use serde_json::json;

use crate::{CliError, Result, TaskAction};

pub fn run(action: TaskAction, output: &mut dyn Write) -> Result<()> {
    match action {
        TaskAction::Set { task, path } => {
            let task = normalize_task(&task)?;
            write_active_task(&path, &task)?;
            writeln!(
                output,
                "{}",
                json!({
                    "active_task": task,
                    "path": path
                })
            )?;
            Ok(())
        }
        TaskAction::Get { path } => {
            let active_task = read_active_task(&path)?;
            writeln!(
                output,
                "{}",
                json!({
                    "active_task": active_task,
                    "path": path
                })
            )?;
            Ok(())
        }
        TaskAction::Clear { path } => {
            if path.exists() {
                fs::remove_file(&path)?;
            }
            writeln!(
                output,
                "{}",
                json!({
                    "active_task": null,
                    "path": path
                })
            )?;
            Ok(())
        }
    }
}

pub(crate) fn read_active_task(path: &Path) -> Result<Option<String>> {
    if !path.exists() {
        return Ok(None);
    }

    let body = fs::read_to_string(path)?;
    Ok(body.lines().find_map(parse_active_task_line))
}

fn write_active_task(path: &Path, task: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, format!("# Descry Context\n\nActive task: {task}\n"))?;
    Ok(())
}

fn parse_active_task_line(line: &str) -> Option<String> {
    line.strip_prefix("Active task:")
        .map(str::trim)
        .filter(|task| !task.is_empty())
        .map(ToString::to_string)
}

fn normalize_task(task: &str) -> Result<String> {
    let normalized = task.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty() {
        Err(CliError::new("task cannot be empty", 2))
    } else {
        Ok(normalized)
    }
}

#[cfg(test)]
mod tests {
    use super::{normalize_task, parse_active_task_line};

    #[test]
    fn parses_active_task_line() {
        assert_eq!(
            parse_active_task_line("Active task: Implement hook installer").as_deref(),
            Some("Implement hook installer")
        );
    }

    #[test]
    fn normalizes_task_whitespace() {
        assert_eq!(
            normalize_task("  Implement\nClaude hook\tinstaller  ")
                .expect("task normalizes")
                .as_str(),
            "Implement Claude hook installer"
        );
        normalize_task("   ").expect_err("empty task fails");
    }
}
