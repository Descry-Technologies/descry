use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::json;

use crate::{CliError, Result, ScanAction};

const SKIP_DIRS: &[&str] = &[".git", ".descry", "target", "node_modules", "dist"];

#[derive(Debug, PartialEq, Eq)]
struct Finding {
    path: String,
    line: usize,
    kind: &'static str,
    evidence: String,
}

pub fn run(action: ScanAction, output: &mut dyn Write) -> Result<()> {
    match action {
        ScanAction::Secrets { path, staged } => run_secret_scan(path, staged, output),
    }
}

fn run_secret_scan(path: PathBuf, staged: bool, output: &mut dyn Write) -> Result<()> {
    let findings = if staged {
        scan_staged(&path)?
    } else {
        scan_path(&path)?
    };
    let ok = findings.is_empty();
    let findings_json: Vec<_> = findings
        .iter()
        .map(|finding| {
            json!({
                "path": finding.path,
                "line": finding.line,
                "kind": finding.kind,
                "evidence": finding.evidence
            })
        })
        .collect();

    writeln!(
        output,
        "{}",
        json!({
            "ok": ok,
            "mode": if staged { "staged" } else { "path" },
            "findings": findings_json
        })
    )?;

    if ok {
        Ok(())
    } else {
        Err(CliError::new("", 1))
    }
}

fn scan_path(path: &Path) -> Result<Vec<Finding>> {
    let root = fs::canonicalize(path)?;
    let mut findings = Vec::new();
    scan_dir(&root, &root, &mut findings)?;
    Ok(findings)
}

fn scan_dir(root: &Path, dir: &Path, findings: &mut Vec<Finding>) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        let name = entry.file_name().to_string_lossy().to_string();

        if file_type.is_dir() {
            if !SKIP_DIRS.contains(&name.as_str()) {
                scan_dir(root, &path, findings)?;
            }
        } else if file_type.is_file() {
            let relative = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .to_string();
            if let Ok(content) = fs::read_to_string(&path) {
                findings.extend(scan_content(&relative, &content));
            }
        }
    }

    Ok(())
}

fn scan_staged(repo: &Path) -> Result<Vec<Finding>> {
    let output = Command::new("git")
        .args(["diff", "--cached", "--name-only", "--diff-filter=ACMRT"])
        .current_dir(repo)
        .output()
        .map_err(|error| CliError::new(format!("failed to run git: {error}"), 1))?;
    if !output.status.success() {
        return Err(CliError::new(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
            1,
        ));
    }

    let mut findings = Vec::new();
    for path in String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
    {
        if let Some(content) = read_staged_file(repo, path)? {
            findings.extend(scan_content(path, &content));
        }
    }
    Ok(findings)
}

fn read_staged_file(repo: &Path, path: &str) -> Result<Option<String>> {
    let spec = format!(":{path}");
    let output = Command::new("git")
        .args(["show", &spec])
        .current_dir(repo)
        .output()
        .map_err(|error| CliError::new(format!("failed to run git: {error}"), 1))?;
    if !output.status.success() {
        return Ok(None);
    }

    Ok(String::from_utf8(output.stdout).ok())
}

fn scan_content(path: &str, content: &str) -> Vec<Finding> {
    content
        .lines()
        .enumerate()
        .filter_map(|(index, line)| {
            detect_secret(line).map(|(kind, evidence)| Finding {
                path: path.to_string(),
                line: index + 1,
                kind,
                evidence,
            })
        })
        .collect()
}

fn detect_secret(line: &str) -> Option<(&'static str, String)> {
    let trimmed = line.trim();
    if trimmed.starts_with('#') || trimmed.starts_with("//") {
        return None;
    }

    if let Some(token) = find_prefixed_token(trimmed, "sk-", 24) {
        return Some(("openai_api_key", mask(token)));
    }
    if let Some(token) = find_prefixed_token(trimmed, "ghp_", 24) {
        return Some(("github_token", mask(token)));
    }
    if let Some(token) = find_prefixed_token(trimmed, "AKIA", 20) {
        return Some(("aws_access_key_id", mask(token)));
    }

    let lower = trimmed.to_ascii_lowercase();
    if ![
        "secret",
        "token",
        "api_key",
        "apikey",
        "password",
        "private_key",
        "access_key",
    ]
    .iter()
    .any(|keyword| lower.contains(keyword))
    {
        return None;
    }

    let value = assignment_value(trimmed)?;
    if is_placeholder(value) || value.len() < 12 || !has_secret_shape(value) {
        return None;
    }

    Some(("credential_assignment", mask(value)))
}

fn assignment_value(line: &str) -> Option<&str> {
    let delimiter = line.find('=').or_else(|| line.find(':'))?;
    let value = line[delimiter + 1..].trim();
    Some(value.trim_matches(|character| matches!(character, '"' | '\'' | '`' | ',' | ';' | ' ')))
}

fn has_secret_shape(value: &str) -> bool {
    let alphanumeric = value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .count();
    let symbol = value
        .chars()
        .any(|character| matches!(character, '_' | '-' | '/' | '+' | '='));

    alphanumeric >= 12 && (symbol || value.len() >= 20)
}

fn is_placeholder(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.is_empty()
        || lower.contains("example")
        || lower.contains("placeholder")
        || lower.contains("changeme")
        || lower.contains("replace_me")
        || lower.contains("your_")
        || lower == "password"
}

fn find_prefixed_token<'a>(line: &'a str, prefix: &str, min_len: usize) -> Option<&'a str> {
    let start = line.find(prefix)?;
    let token = line[start..]
        .split(|character: char| {
            !(character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
        })
        .next()?;
    (token.len() >= min_len).then_some(token)
}

fn mask(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 8 {
        return String::from("********");
    }
    let prefix: String = chars.iter().take(4).collect();
    let suffix: String = chars
        .iter()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{prefix}...{suffix}")
}

#[cfg(test)]
mod tests {
    use super::{detect_secret, scan_content};

    #[test]
    fn detects_prefixed_tokens() {
        let detected = detect_secret("OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz123456")
            .expect("secret detected");

        assert_eq!(detected.0, "openai_api_key");
        assert_eq!(detected.1, "sk-a...3456");
    }

    #[test]
    fn ignores_placeholder_assignments() {
        assert!(detect_secret("API_KEY=replace_me").is_none());
    }

    #[test]
    fn reports_line_numbers() {
        let findings = scan_content(
            ".env",
            "SAFE=example\nDATABASE_PASSWORD=prod-very-secret-value\n",
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 2);
    }
}
