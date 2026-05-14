use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use descry_memory::Approval;
use serde_json::json;

use crate::{ApprovalsAction, CliError, Result};

const MAX_APPROVAL_TTL_SECONDS: u64 = 24 * 60 * 60;

pub fn run(
    scope: String,
    ttl: String,
    path: PathBuf,
    approver: String,
    output: &mut dyn Write,
) -> Result<()> {
    let now = current_epoch_seconds()?;
    let ttl_seconds = parse_ttl_seconds(&ttl)?;
    let parsed_scope = descry_memory::validate_approval_scope(&scope)
        .map_err(|error| CliError::new(error.to_string(), 2))?;
    let approval = Approval {
        scope,
        created_at_epoch_seconds: now,
        expires_at_epoch_seconds: now + ttl_seconds,
        approver,
    };

    descry_memory::append_approval(&path, &approval)
        .map_err(|error| CliError::new(error.to_string(), 1))?;
    writeln!(
        output,
        "{}",
        json!({
            "scope": approval.scope,
            "scope_kind": parsed_scope.kind.as_str(),
            "scope_pattern": parsed_scope.pattern,
            "created_at_epoch_seconds": approval.created_at_epoch_seconds,
            "expires_at_epoch_seconds": approval.expires_at_epoch_seconds,
            "approver": approval.approver,
            "path": path
        })
    )?;
    Ok(())
}

pub fn run_approvals(action: ApprovalsAction, output: &mut dyn Write) -> Result<()> {
    match action {
        ApprovalsAction::List { path } => {
            let now = current_epoch_seconds()?;
            let approvals = descry_memory::load_approvals(&path)
                .map_err(|error| CliError::new(error.to_string(), 1))?;
            let approvals_json: Vec<_> = approvals
                .iter()
                .map(|approval| {
                    json!({
                        "scope": approval.scope,
                        "created_at_epoch_seconds": approval.created_at_epoch_seconds,
                        "expires_at_epoch_seconds": approval.expires_at_epoch_seconds,
                        "approver": approval.approver,
                        "live": approval.is_live_at(now)
                    })
                })
                .collect();
            writeln!(
                output,
                "{}",
                json!({
                    "path": path,
                    "approvals": approvals_json
                })
            )?;
            Ok(())
        }
        ApprovalsAction::Revoke { path, scope } => {
            descry_memory::validate_approval_scope(&scope)
                .map_err(|error| CliError::new(error.to_string(), 2))?;
            let now = current_epoch_seconds()?;
            let revoked = descry_memory::revoke_approval_scope(&path, &scope, now)
                .map_err(|error| CliError::new(error.to_string(), 1))?;
            writeln!(
                output,
                "{}",
                json!({
                    "path": path,
                    "scope": scope,
                    "revoked": revoked
                })
            )?;
            Ok(())
        }
    }
}

fn current_epoch_seconds() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| CliError::new(error.to_string(), 1))
}

fn parse_ttl_seconds(ttl: &str) -> Result<u64> {
    let trimmed = ttl.trim();
    if trimmed.is_empty() {
        return Err(CliError::new("ttl cannot be empty", 2));
    }
    let (number, multiplier) = match trimmed.as_bytes().last().copied() {
        Some(b's') => (&trimmed[..trimmed.len() - 1], 1),
        Some(b'm') => (&trimmed[..trimmed.len() - 1], 60),
        Some(b'h') => (&trimmed[..trimmed.len() - 1], 60 * 60),
        Some(b'd') => (&trimmed[..trimmed.len() - 1], 24 * 60 * 60),
        Some(byte) if byte.is_ascii_digit() => (trimmed, 1),
        _ => {
            return Err(CliError::new(
                "ttl must use seconds, m, h, or d suffix, e.g. 30m",
                2,
            ));
        }
    };
    let value = number
        .parse::<u64>()
        .map_err(|_| CliError::new("ttl must start with a positive integer", 2))?;
    if value == 0 {
        return Err(CliError::new("ttl must be greater than zero", 2));
    }
    let ttl_seconds = value
        .checked_mul(multiplier)
        .ok_or_else(|| CliError::new("ttl is too large", 2))?;
    if ttl_seconds > MAX_APPROVAL_TTL_SECONDS {
        return Err(CliError::new("ttl cannot exceed 24h", 2));
    }
    Ok(ttl_seconds)
}

#[cfg(test)]
mod tests {
    use super::parse_ttl_seconds;

    #[test]
    fn parses_ttl_suffixes() {
        assert_eq!(parse_ttl_seconds("30").expect("ttl parses"), 30);
        assert_eq!(parse_ttl_seconds("30s").expect("ttl parses"), 30);
        assert_eq!(parse_ttl_seconds("30m").expect("ttl parses"), 1_800);
        assert_eq!(parse_ttl_seconds("2h").expect("ttl parses"), 7_200);
        assert_eq!(parse_ttl_seconds("1d").expect("ttl parses"), 86_400);
    }

    #[test]
    fn rejects_invalid_ttl() {
        assert_eq!(
            parse_ttl_seconds("0m").expect_err("zero fails").exit_code(),
            2
        );
        assert_eq!(
            parse_ttl_seconds("soon")
                .expect_err("invalid suffix fails")
                .exit_code(),
            2
        );
        assert_eq!(
            parse_ttl_seconds("25h")
                .expect_err("ttl cap fails")
                .exit_code(),
            2
        );
    }
}
