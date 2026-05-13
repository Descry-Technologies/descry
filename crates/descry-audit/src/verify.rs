use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::canonical::canonical_minus_record_hash;
use crate::chain::GENESIS_PREV_HASH;
use crate::hash::record_hash;
use crate::{AuditError, AuditEvent};

#[derive(Debug, Eq, PartialEq)]
pub enum VerifyOutcome {
    Ok { records: u64 },
    Broken { at_seq: u64, reason: String },
}

pub fn verify_file(path: &Path, repo_id_hash: &str) -> VerifyOutcome {
    match verify_file_inner(path, repo_id_hash) {
        Ok(records) => VerifyOutcome::Ok { records },
        Err(error) => {
            let at_seq = match &error {
                AuditError::MalformedRecord { line, .. } => *line,
                AuditError::HashMismatch { seq } => *seq,
                AuditError::SeqGap { expected, .. } => *expected,
                AuditError::PrevHashMismatch { seq } => *seq,
                AuditError::Io(_) | AuditError::Serde(_) => 0,
            };
            VerifyOutcome::Broken {
                at_seq,
                reason: error.to_string(),
            }
        }
    }
}

fn verify_file_inner(path: &Path, repo_id_hash: &str) -> Result<u64, AuditError> {
    let file = File::open(path)?;
    let mut expected_prev_hash = GENESIS_PREV_HASH.to_string();
    let mut records = 0;

    for (expected_seq, (index, line)) in (1_u64..).zip(BufReader::new(file).lines().enumerate()) {
        let line_number = index as u64 + 1;
        let line = line?;
        if line.is_empty() {
            return Err(AuditError::MalformedRecord {
                line: line_number,
                reason: String::from("empty line"),
            });
        }

        let event: AuditEvent =
            serde_json::from_str(&line).map_err(|error| AuditError::MalformedRecord {
                line: line_number,
                reason: error.to_string(),
            })?;

        if event.seq != expected_seq {
            return Err(AuditError::SeqGap {
                expected: expected_seq,
                found: event.seq,
            });
        }
        if event.prev_hash != expected_prev_hash {
            return Err(AuditError::PrevHashMismatch { seq: event.seq });
        }

        let canonical = canonical_minus_record_hash(&event)?;
        let expected_hash = record_hash(repo_id_hash, event.seq, &event.prev_hash, &canonical);
        if event.record_hash != expected_hash {
            return Err(AuditError::HashMismatch { seq: event.seq });
        }

        expected_prev_hash = event.record_hash;
        records += 1;
    }

    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::{verify_file, VerifyOutcome};
    use crate::AuditChain;

    #[test]
    fn verifies_two_event_chain() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("audit.log");
        let mut chain = AuditChain::open(&path, "test-repo").expect("chain opens");
        chain
            .append("2026-05-11T20:00:00Z", "allow", "acp-1", None, None)
            .expect("append one");
        chain
            .append(
                "2026-05-11T20:00:01Z",
                "block",
                "acp-2",
                Some(String::from("rule")),
                Some(String::from("reason")),
            )
            .expect("append two");

        assert_eq!(
            verify_file(&path, "test-repo"),
            VerifyOutcome::Ok { records: 2 }
        );
    }
}
