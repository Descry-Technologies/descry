use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use crate::canonical::canonical_minus_record_hash;
use crate::hash::record_hash;
use crate::{AuditError, AuditEvent};

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
        let mut head = None;

        for (index, line) in BufReader::new(file).lines().enumerate() {
            let line_number = index as u64 + 1;
            let line = line?;
            if line.is_empty() {
                continue;
            }
            let event: AuditEvent =
                serde_json::from_str(&line).map_err(|error| AuditError::MalformedRecord {
                    line: line_number,
                    reason: error.to_string(),
                })?;
            head = Some(event);
        }

        let next_seq = head.as_ref().map_or(1, |event| event.seq + 1);

        Ok(Self {
            path,
            repo_id_hash: repo_id_hash.into(),
            head,
            next_seq,
        })
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
        let prev_hash = self.head.as_ref().map_or_else(
            || GENESIS_PREV_HASH.to_string(),
            |event| event.record_hash.clone(),
        );
        let mut event = AuditEvent::pending(
            self.next_seq,
            timestamp,
            decision,
            acp_hash,
            rule_id,
            reason,
            prev_hash,
        );
        let canonical = canonical_minus_record_hash(&event)?;
        event.record_hash =
            record_hash(&self.repo_id_hash, event.seq, &event.prev_hash, &canonical);

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        serde_json::to_writer(&mut file, &event)?;
        file.write_all(b"\n")?;
        file.flush()?;
        file.sync_data()?;

        self.next_seq += 1;
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

#[cfg(test)]
fn read_first_event(path: &Path) -> Result<Option<AuditEvent>, AuditError> {
    use std::fs::File;
    use std::io::{Seek, SeekFrom};

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
}
