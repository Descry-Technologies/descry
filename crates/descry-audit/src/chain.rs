use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::canonical::canonical_minus_record_hash;
use crate::hash::record_hash;
use crate::{verify_file, AuditError, AuditEvent, AuditEventContext, VerifyOutcome};

pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug)]
pub struct AuditChain {
    path: PathBuf,
    repo_id_hash: String,
    head: Option<AuditEvent>,
    next_seq: u64,
}

impl AuditChain {
    pub fn open(
        path: impl AsRef<Path>,
        repo_id_hash: impl Into<String>,
    ) -> Result<Self, AuditError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)?;

        // Shared lock: blocks until any concurrent exclusive writer has fsynced and
        // released, so we never read a partially-written record.
        file.lock_shared()?;

        let scan_result = scan_tail(&file);

        // Lock released on drop; explicit unlock is cleaner.
        let _ = file.unlock();

        let (head, next_seq) = scan_result?;

        Ok(Self {
            path,
            repo_id_hash: repo_id_hash.into(),
            head,
            next_seq,
        })
    }

    pub fn open_verified(
        path: impl AsRef<Path>,
        repo_id_hash: impl Into<String>,
    ) -> Result<Self, AuditError> {
        let path = path.as_ref().to_path_buf();
        let repo_id_hash = repo_id_hash.into();
        if path.exists() {
            match verify_file(&path, &repo_id_hash) {
                VerifyOutcome::Ok { .. } => {}
                VerifyOutcome::Broken { reason, .. } => {
                    return Err(AuditError::BrokenChain { reason });
                }
            }
        }
        Self::open(path, repo_id_hash)
    }

    /// Appends a record and fsyncs the file before returning.
    pub fn append(
        &mut self,
        timestamp: impl Into<String>,
        decision: impl Into<String>,
        acp_hash: impl Into<String>,
        rule_id: Option<String>,
        reason: Option<String>,
    ) -> Result<&AuditEvent, AuditError> {
        self.append_with_context(
            timestamp,
            decision,
            acp_hash,
            rule_id,
            reason,
            AuditEventContext::default(),
        )
    }

    pub fn append_with_context(
        &mut self,
        timestamp: impl Into<String>,
        decision: impl Into<String>,
        acp_hash: impl Into<String>,
        rule_id: Option<String>,
        reason: Option<String>,
        context: AuditEventContext,
    ) -> Result<&AuditEvent, AuditError> {
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&self.path)?;

        // Exclusive lock before read-then-write: prevents interleaved bytes from
        // concurrent hook invocations and ensures prev_hash is from the actual tail.
        file.lock()?;

        let (prev_hash, next_seq) = current_tail(&mut file)?;

        let mut event = AuditEvent::pending(
            next_seq,
            timestamp,
            decision,
            acp_hash,
            rule_id,
            reason,
            prev_hash,
        )
        .with_context(context);
        let canonical = canonical_minus_record_hash(&event)?;
        event.record_hash =
            record_hash(&self.repo_id_hash, event.seq, &event.prev_hash, &canonical);

        serde_json::to_writer(&mut file, &event)?;
        file.write_all(b"\n")?;
        file.flush()?;
        file.sync_data()?;
        let _ = file.unlock();

        self.next_seq = next_seq + 1;
        self.head = Some(event);
        Ok(self.head.as_ref().expect("head was just assigned"))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn head(&self) -> Option<&AuditEvent> {
        self.head.as_ref()
    }

    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }
}

/// Scans the file (under a caller-held shared lock) for the last valid record.
/// Returns (head, next_seq).
fn scan_tail(file: &std::fs::File) -> Result<(Option<AuditEvent>, u64), AuditError> {
    let mut head = None;
    let lines: Vec<_> = BufReader::new(file).lines().collect();
    let total = lines.len();

    for (index, line) in lines.into_iter().enumerate() {
        let line_number = index as u64 + 1;
        let line = line?;
        let trimmed = line.trim_matches('\0').trim();
        if trimmed.is_empty() || !trimmed.starts_with('{') {
            continue;
        }
        match serde_json::from_str::<AuditEvent>(trimmed) {
            Ok(event) => head = Some(event),
            Err(error) => {
                // Tolerate a truncated last line — a concurrent writer may not
                // have finished flushing. Fail hard on interior corruption.
                let is_last = line_number == total as u64;
                if !is_last {
                    return Err(AuditError::MalformedRecord {
                        line: line_number,
                        reason: error.to_string(),
                    });
                }
            }
        }
    }

    let next_seq = head.as_ref().map_or(1, |event| event.seq + 1);
    Ok((head, next_seq))
}

/// Reads the last valid record from the file under an already-held exclusive lock.
/// Returns (prev_hash, next_seq).
fn current_tail(file: &mut std::fs::File) -> Result<(String, u64), AuditError> {
    let file_len = file.seek(SeekFrom::End(0))?;
    if file_len == 0 {
        return Ok((GENESIS_PREV_HASH.to_string(), 1));
    }

    // Read the last 8 KiB — enough for one full record plus some slack.
    let read_start = file_len.saturating_sub(8192);
    file.seek(SeekFrom::Start(read_start))?;
    let mut buf = String::new();
    file.read_to_string(&mut buf)?;

    // Use next_back() — Lines is DoubleEndedIterator, so this is O(1) from tail.
    let last_event = buf
        .lines()
        .filter(|l| {
            let t = l.trim_matches('\0').trim();
            !t.is_empty() && t.starts_with('{')
        })
        .filter_map(|l| serde_json::from_str::<AuditEvent>(l.trim()).ok())
        .next_back();

    match last_event {
        Some(event) => Ok((event.record_hash.clone(), event.seq + 1)),
        None => Ok((GENESIS_PREV_HASH.to_string(), 1)),
    }
}

#[cfg(test)]
fn read_first_event(path: &Path) -> Result<Option<AuditEvent>, AuditError> {
    use std::fs::File;

    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(0))?;
    let mut reader = BufReader::new(file);
    let mut line = String::new();
    let bytes = reader.read_line(&mut line)?;
    if bytes == 0 {
        return Ok(None);
    }
    let event = serde_json::from_str(line.trim_end()).map_err(AuditError::from)?;
    Ok(Some(event))
}

#[cfg(test)]
mod tests {
    use super::{read_first_event, AuditChain, GENESIS_PREV_HASH};

    #[test]
    fn append_writes_one_jsonl_record() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("audit.log");
        let mut chain = AuditChain::open(&path, "test-repo").expect("chain opens");

        let event = chain
            .append(
                "2026-05-11T20:00:00Z",
                "allow",
                "acp",
                None,
                Some(String::from("ok")),
            )
            .expect("append succeeds")
            .clone();

        let read_back = read_first_event(&path)
            .expect("record reads")
            .expect("record exists");
        assert_eq!(read_back, event);
        assert_eq!(read_back.seq, 1);
        assert_eq!(read_back.prev_hash, GENESIS_PREV_HASH);
        assert_eq!(read_back.record_hash.len(), 64);
    }

    #[test]
    fn open_verified_refuses_tampered_chain_before_append() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("audit.log");
        let mut chain = AuditChain::open_verified(&path, "test-repo").expect("chain opens");
        chain
            .append("2026-05-11T20:00:00Z", "allow", "acp-1", None, None)
            .expect("append one");
        chain
            .append("2026-05-11T20:00:01Z", "block", "acp-2", None, None)
            .expect("append two");

        let body = std::fs::read_to_string(&path)
            .expect("audit log reads")
            .replacen("allow", "block", 1);
        std::fs::write(&path, body).expect("audit log mutates");

        AuditChain::open_verified(&path, "test-repo").expect_err("tampered chain fails");
    }

    #[test]
    fn concurrent_appends_produce_valid_chain() {
        use std::thread;

        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("audit.log");

        let handles: Vec<_> = (0..8)
            .map(|i| {
                let p = path.clone();
                thread::spawn(move || {
                    let mut chain = AuditChain::open(&p, "test-repo").expect("chain opens");
                    chain
                        .append(
                            format!("2026-05-11T20:00:{i:02}Z"),
                            "allow",
                            format!("acp-{i}"),
                            None,
                            None,
                        )
                        .expect("append succeeds");
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread did not panic");
        }

        // All 8 records must be parseable and have unique seqs 1..=8.
        let body = std::fs::read_to_string(&path).expect("reads");
        let events: Vec<super::AuditEvent> = body
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).expect("valid JSON"))
            .collect();
        assert_eq!(events.len(), 8);
        let mut seqs: Vec<u64> = events.iter().map(|e| e.seq).collect();
        seqs.sort_unstable();
        assert_eq!(seqs, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    }
}
