use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use descry_core::{
    ActionClass, EvidenceRef, EvidenceSource, ScopeContract, ScopePermit, ScopePermitKind,
};
use serde_json::json;

use crate::{commands::task, CliError, Result, ScopeAction};

pub fn run(action: ScopeAction, output: &mut dyn Write) -> Result<()> {
    match action {
        ScopeAction::Build {
            project,
            context,
            project_index,
            cache,
            ttl_seconds,
            created_at_epoch_seconds,
        } => {
            let created_at_epoch_seconds =
                created_at_epoch_seconds.unwrap_or_else(current_epoch_seconds);
            let contract = build_scope_contract(ScopeBuildConfig {
                project,
                context,
                project_index,
                created_at_epoch_seconds,
                ttl_seconds,
            })?;
            descry_memory::append_scope_contract(&cache, &contract)
                .map_err(|error| CliError::new(error.to_string(), 1))?;
            writeln!(
                output,
                "{}",
                json!({
                    "cache": cache,
                    "contract": contract,
                    "verified": contract.verify_signature()
                })
            )?;
            Ok(())
        }
        ScopeAction::Show {
            cache,
            now_epoch_seconds,
        } => {
            let now_epoch_seconds = now_epoch_seconds.unwrap_or_else(current_epoch_seconds);
            let contracts = descry_memory::active_scope_contracts(&cache, now_epoch_seconds)
                .map_err(|error| CliError::new(error.to_string(), 1))?;
            writeln!(
                output,
                "{}",
                json!({
                    "cache": cache,
                    "contracts": contracts,
                    "count": contracts.len(),
                    "now_epoch_seconds": now_epoch_seconds
                })
            )?;
            Ok(())
        }
    }
}

struct ScopeBuildConfig {
    project: PathBuf,
    context: PathBuf,
    project_index: PathBuf,
    created_at_epoch_seconds: u64,
    ttl_seconds: u64,
}

fn build_scope_contract(config: ScopeBuildConfig) -> Result<ScopeContract> {
    if config.ttl_seconds == 0 {
        return Err(CliError::new(
            "scope contract ttl_seconds must be positive",
            2,
        ));
    }

    let index = if config.project_index.exists() {
        descry_context::read_project_index(&config.project_index)?
    } else {
        let index = descry_context::build_project_index(&config.project)?;
        descry_context::write_project_index(&index, &config.project_index)?;
        index
    };
    let active_task = task::read_active_task(&config.context)?;
    let codeowners_patterns =
        descry_context::read_codeowners_patterns(&config.project).unwrap_or_default();

    let evidence = scope_evidence(&index, active_task.as_deref(), &codeowners_patterns);
    let permits = scope_permits(&index, active_task.as_deref(), &codeowners_patterns);
    let task_summary = active_task
        .or_else(|| {
            index
                .branch
                .clone()
                .map(|branch| format!("branch {branch}"))
        })
        .unwrap_or_else(|| format!("project {}", index.repo_name));
    let confidence = if task_summary.starts_with("project ") {
        0.45
    } else if task_summary.starts_with("branch ") {
        0.65
    } else {
        0.8
    };

    ScopeContract::signed(
        task_summary,
        evidence,
        permits,
        config.created_at_epoch_seconds,
        config.created_at_epoch_seconds + config.ttl_seconds,
        confidence,
    )
    .map_err(|error| CliError::new(error.to_string(), 1))
}

fn scope_evidence(
    index: &descry_context::ProjectIndex,
    active_task: Option<&str>,
    codeowners_patterns: &[String],
) -> Vec<EvidenceRef> {
    let mut evidence = Vec::new();
    if let Some(active_task) = active_task {
        evidence.push(EvidenceRef::new(
            EvidenceSource::ActiveTask,
            "active-task",
            active_task,
        ));
    }
    if let Some(branch) = index.branch.as_deref() {
        evidence.push(EvidenceRef::new(
            EvidenceSource::Branch,
            format!("branch:{branch}"),
            branch,
        ));
    }
    evidence.push(EvidenceRef::new(
        EvidenceSource::ProjectIndex,
        format!("project:{}", index.repo_name),
        project_index_summary(index),
    ));
    for pattern in codeowners_patterns {
        evidence.push(EvidenceRef::new(
            EvidenceSource::Codeowners,
            format!("codeowners:{pattern}"),
            pattern,
        ));
    }
    evidence
}

fn scope_permits(
    index: &descry_context::ProjectIndex,
    active_task: Option<&str>,
    codeowners_patterns: &[String],
) -> Vec<ScopePermit> {
    let mut permits = Vec::new();
    for pattern in index.source_paths.iter().chain(index.test_paths.iter()) {
        permits.push(ScopePermit::new(
            ScopePermitKind::Path,
            pattern,
            vec![
                ActionClass::FileRead,
                ActionClass::FileWrite,
                ActionClass::ShellTest,
            ],
            "source or test path from project index",
        ));
    }
    for pattern in codeowners_patterns {
        if looks_like_source_pattern(pattern) {
            permits.push(ScopePermit::new(
                ScopePermitKind::Path,
                normalize_codeowners_pattern(pattern),
                vec![ActionClass::FileRead, ActionClass::FileWrite],
                "source path from CODEOWNERS",
            ));
        }
    }
    if let Some(active_task) = active_task {
        for path in path_like_terms(active_task) {
            permits.push(ScopePermit::new(
                ScopePermitKind::Path,
                path,
                vec![ActionClass::FileRead, ActionClass::FileWrite],
                "path mentioned in active task",
            ));
        }
    }
    if permits.is_empty() {
        permits.push(ScopePermit::new(
            ScopePermitKind::Action,
            "test",
            vec![ActionClass::ShellTest],
            "thin evidence permits tests only",
        ));
    }
    permits
}

fn project_index_summary(index: &descry_context::ProjectIndex) -> String {
    format!(
        "repo={} languages={} source_paths={} test_paths={}",
        index.repo_name,
        index.languages.join(","),
        index.source_paths.join(","),
        index.test_paths.join(",")
    )
}

fn looks_like_source_pattern(pattern: &str) -> bool {
    let normalized = pattern.trim_start_matches('/');
    normalized.starts_with("src/")
        || normalized.starts_with("crates/")
        || normalized.starts_with("app/")
        || normalized.starts_with("pages/")
        || normalized.starts_with("tests/")
}

fn normalize_codeowners_pattern(pattern: &str) -> String {
    let pattern = pattern.trim_start_matches('/');
    if pattern.contains('*') || pattern.ends_with('/') {
        pattern.to_string()
    } else if fs::metadata(pattern)
        .map(|metadata| metadata.is_dir())
        .unwrap_or(false)
    {
        format!("{pattern}/**")
    } else {
        pattern.to_string()
    }
}

fn path_like_terms(value: &str) -> Vec<String> {
    let mut paths = value
        .split_whitespace()
        .map(|term| {
            term.trim_matches(|character: char| {
                !(character.is_ascii_alphanumeric()
                    || matches!(character, '/' | '\\' | '.' | '_' | '-'))
            })
        })
        .filter(|term| term.contains('/'))
        .map(|term| term.trim_start_matches("./").replace('\\', "/"))
        .collect::<Vec<_>>();
    paths.sort();
    paths.dedup();
    paths
}

fn current_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
