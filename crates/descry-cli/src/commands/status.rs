use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use descry_audit::AuditEvent;

use crate::Result;

pub fn run(audit: PathBuf, context: PathBuf, recent: usize, output: &mut dyn Write) -> Result<()> {
    writeln!(output)?;
    writeln!(output, "Descry status")?;
    writeln!(output)?;

    // Read audit events if the file exists
    let events: Vec<AuditEvent> = if audit.exists() {
        let body = fs::read_to_string(&audit)?;
        body.lines()
            .filter(|line| !line.trim().is_empty())
            .filter_map(|line| serde_json::from_str::<AuditEvent>(line).ok())
            .collect()
    } else {
        Vec::new()
    };

    // Protection status
    let protection_status = if audit.exists() {
        "active"
    } else {
        "no hooks detected"
    };
    writeln!(output, "  {:<14}{}", "Protection", protection_status)?;

    // Task from context.md
    let task = read_task(&context);
    writeln!(output, "  {:<14}{}", "Task", task)?;

    // Compute decision counts
    let total = events.len();
    let now_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let one_hour_ago = now_epoch.saturating_sub(3600);

    let last_hour = events
        .iter()
        .filter(|e| parse_epoch_seconds(&e.timestamp) >= one_hour_ago)
        .count();

    let allow_count = events
        .iter()
        .filter(|e| e.decision == "allow" || e.decision == "allow_with_log")
        .count();
    let block_count = events.iter().filter(|e| e.decision == "block").count();
    let approval_count = events
        .iter()
        .filter(|e| e.decision == "require_approval" || e.decision == "ask")
        .count();

    let decisions_summary = if total == 0 {
        String::from("none yet")
    } else {
        format!(
            "{total} total, {last_hour} in last hour  ({allow_count} allow · {block_count} block · {approval_count} require_approval)"
        )
    };
    writeln!(output, "  {:<14}{}", "Decisions", decisions_summary)?;

    writeln!(output)?;

    // Recent decisions
    if !events.is_empty() {
        writeln!(output, "  Recent decisions:")?;
        let start = events.len().saturating_sub(recent);
        for event in events[start..].iter().rev() {
            let target = event
                .sanitized_target
                .as_deref()
                .or(event.action_type.as_deref())
                .unwrap_or("(unknown)");
            let age = relative_time(parse_epoch_seconds(&event.timestamp), now_epoch);
            writeln!(
                output,
                "  {:<8}  {:<40}  {}",
                event.decision,
                truncate(target, 40),
                age
            )?;
        }
        writeln!(output)?;
    }

    writeln!(output, "  Run  descry logs tail  for full history.")?;

    Ok(())
}

fn read_task(context: &PathBuf) -> String {
    if !context.exists() {
        return String::from("(none — inferred from branch/files)");
    }
    let Ok(body) = fs::read_to_string(context) else {
        return String::from("(none — inferred from branch/files)");
    };
    for line in body.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("task:") {
            let task = value.trim();
            if !task.is_empty() {
                return task.to_string();
            }
        }
    }
    String::from("(none — inferred from branch/files)")
}

/// Parse an RFC3339 timestamp to epoch seconds without external crates.
/// Handles "2026-05-11T20:00:00Z" and similar formats.
fn parse_epoch_seconds(timestamp: &str) -> u64 {
    // Split on 'T' to get date and time parts
    let Some((date_part, time_part)) = timestamp.split_once('T') else {
        return 0;
    };

    let date_parts: Vec<&str> = date_part.split('-').collect();
    if date_parts.len() < 3 {
        return 0;
    }
    let Ok(year) = date_parts[0].parse::<i64>() else {
        return 0;
    };
    let Ok(month) = date_parts[1].parse::<i64>() else {
        return 0;
    };
    let Ok(day) = date_parts[2].parse::<i64>() else {
        return 0;
    };

    // Strip timezone suffix for time parsing
    let time_clean = time_part
        .trim_end_matches('Z')
        .split('+')
        .next()
        .unwrap_or("")
        .split('-')
        .next()
        .unwrap_or("");

    let time_parts: Vec<&str> = time_clean.split(':').collect();
    if time_parts.len() < 3 {
        return 0;
    }
    let Ok(hour) = time_parts[0].parse::<i64>() else {
        return 0;
    };
    let Ok(minute) = time_parts[1].parse::<i64>() else {
        return 0;
    };
    // Handle fractional seconds
    let seconds_str = time_parts[2].split('.').next().unwrap_or("0");
    let Ok(second) = seconds_str.parse::<i64>() else {
        return 0;
    };

    // Days since epoch using a simple formula (Julian Day -> Unix epoch)
    // Days from epoch (1970-01-01) to given date
    let days = days_since_epoch(year, month, day);
    let epoch = days * 86400 + hour * 3600 + minute * 60 + second;
    if epoch < 0 {
        0
    } else {
        epoch as u64
    }
}

/// Compute days since Unix epoch for a given date (Gregorian).
fn days_since_epoch(year: i64, month: i64, day: i64) -> i64 {
    // Algorithm: compute Julian Day Number, subtract Unix epoch JDN (2440588)
    let a = (14 - month) / 12;
    let y = year + 4800 - a;
    let m = month + 12 * a - 3;
    let jdn = day + (153 * m + 2) / 5 + 365 * y + y / 4 - y / 100 + y / 400 - 32045;
    jdn - 2440588
}

fn relative_time(event_epoch: u64, now_epoch: u64) -> String {
    if now_epoch < event_epoch {
        return String::from("just now");
    }
    let diff = now_epoch - event_epoch;
    if diff < 120 {
        String::from("just now")
    } else if diff < 3600 {
        format!("{}m ago", diff / 60)
    } else if diff < 86400 {
        format!("{}h ago", diff / 3600)
    } else {
        // Show a simple date
        format!("{}d ago", diff / 86400)
    }
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        s
    } else {
        &s[..max]
    }
}
