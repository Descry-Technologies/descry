use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};

use descry_audit::{AuditEvent, VerifyOutcome};
use serde_json::json;

use crate::{CliError, LogsAction, Result};

pub fn run(action: LogsAction, output: &mut dyn Write, _error: &mut dyn Write) -> Result<()> {
    match action {
        LogsAction::Verify { path, repo_id_hash } => {
            match descry_audit::verify_file(&path, &repo_id_hash) {
                VerifyOutcome::Ok { records } => {
                    writeln!(output, "{}", json!({ "ok": true, "records": records }))?;
                    Ok(())
                }
                VerifyOutcome::Broken { at_seq, reason } => {
                    writeln!(
                        output,
                        "{}",
                        json!({
                            "ok": false,
                            "broken_at_seq": at_seq,
                            "reason": reason
                        })
                    )?;
                    Err(CliError::new("", 1))
                }
            }
        }
        LogsAction::Tail { path, lines } => {
            let records = tail_records(&path, lines)?;
            for record in records {
                writeln!(
                    output,
                    "{}",
                    serde_json::to_string(&record).expect("event serializes")
                )?;
            }
            Ok(())
        }
        LogsAction::Search { query, path } => {
            let query = query.to_ascii_lowercase();
            for record in read_records(&path)? {
                if event_matches(&record.event, &query) {
                    writeln!(
                        output,
                        "{}",
                        serde_json::to_string(&record.event).expect("event serializes")
                    )?;
                }
            }
            Ok(())
        }
    }
}

struct RawAuditRecord {
    event: AuditEvent,
}

fn tail_records(path: &std::path::Path, lines: usize) -> Result<Vec<AuditEvent>> {
    let mut tail = VecDeque::new();
    for record in read_records(path)? {
        if lines == 0 {
            continue;
        }
        if tail.len() == lines {
            tail.pop_front();
        }
        tail.push_back(record.event);
    }
    Ok(tail.into_iter().collect())
}

fn read_records(path: &std::path::Path) -> Result<Vec<RawAuditRecord>> {
    let file = File::open(path).map_err(|error| {
        CliError::new(
            format!("failed to open audit log {}: {error}", path.display()),
            1,
        )
    })?;
    let mut records = Vec::new();
    for (index, line) in BufReader::new(file).lines().enumerate() {
        let raw = line?;
        if raw.trim().is_empty() {
            continue;
        }
        let event = serde_json::from_str::<AuditEvent>(&raw).map_err(|error| {
            CliError::new(
                format!(
                    "failed to parse audit log {} at line {}: {error}",
                    path.display(),
                    index + 1
                ),
                1,
            )
        })?;
        records.push(RawAuditRecord { event });
    }
    Ok(records)
}

fn event_matches(event: &AuditEvent, query: &str) -> bool {
    [
        Some(event.decision.as_str()),
        event.rule_id.as_deref(),
        event.reason.as_deref(),
        event.action_type.as_deref(),
        event.asset_id.as_deref(),
        event.host.as_deref(),
        event.sanitized_target.as_deref(),
    ]
    .into_iter()
    .flatten()
    .any(|value| value.to_ascii_lowercase().contains(query))
}
