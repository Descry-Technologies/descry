use std::io::Write;

use descry_audit::VerifyOutcome;
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
    }
}
