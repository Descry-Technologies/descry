use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{AuditError, AuditEvent};

/// Number of records per Merkle checkpoint window.
pub const CHECKPOINT_INTERVAL: u64 = 100;

/// A Merkle checkpoint proves the integrity of a window of audit records.
/// The `merkle_root` is the root of a balanced binary hash tree over the
/// `record_hash` values of all records in [seq_start, seq_end].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MerkleCheckpoint {
    pub seq_start: u64,
    pub seq_end: u64,
    pub record_count: u64,
    pub merkle_root: String,
    pub chain_head_hash: String,
}

/// A self-contained proof bundle that an auditor can verify independently.
#[derive(Debug, Serialize)]
pub struct ExportBundle {
    pub schema_version: u32,
    pub repo_id_hash: String,
    pub total_records: u64,
    pub checkpoints: Vec<MerkleCheckpoint>,
    pub events: Vec<AuditEvent>,
}

/// Compute the Merkle root of a list of hash strings.
/// Uses SHA-256 at each node: `H("merkle-node\n" || left || "\n" || right)`.
/// Pads to the next power of two with the last hash repeated.
pub fn compute_merkle_root(hashes: &[&str]) -> String {
    if hashes.is_empty() {
        return "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    }
    if hashes.len() == 1 {
        return hashes[0].to_string();
    }

    let next_pow2 = hashes.len().next_power_of_two();
    let last = *hashes.last().expect("non-empty");
    let mut level: Vec<String> = hashes
        .iter()
        .map(|&s| s.to_string())
        .chain(std::iter::repeat_n(last.to_string(), next_pow2 - hashes.len()))
        .collect();

    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            let mut hasher = Sha256::new();
            hasher.update(b"descry-merkle-v1\n");
            hasher.update(pair[0].as_bytes());
            hasher.update(b"\n");
            hasher.update(pair[1].as_bytes());
            let digest = hasher.finalize();
            let mut hex = String::with_capacity(64);
            for byte in digest {
                hex.push_str(&format!("{byte:02x}"));
            }
            next.push(hex);
        }
        level = next;
    }

    level.into_iter().next().expect("level is non-empty")
}

/// Read all events from a chain file and compute Merkle checkpoints over
/// windows of `CHECKPOINT_INTERVAL` records.
pub fn build_checkpoints(path: &Path) -> Result<Vec<MerkleCheckpoint>, AuditError> {
    let events = read_all_events(path)?;
    Ok(checkpoints_from_events(&events))
}

pub(crate) fn checkpoints_from_events(events: &[AuditEvent]) -> Vec<MerkleCheckpoint> {
    let mut checkpoints = Vec::new();
    for window in events.chunks(CHECKPOINT_INTERVAL as usize) {
        let hashes: Vec<&str> = window.iter().map(|e| e.record_hash.as_str()).collect();
        let merkle_root = compute_merkle_root(&hashes);
        let seq_start = window.first().expect("non-empty window").seq;
        let seq_end = window.last().expect("non-empty window").seq;
        let chain_head_hash = window.last().expect("non-empty window").record_hash.clone();
        checkpoints.push(MerkleCheckpoint {
            seq_start,
            seq_end,
            record_count: window.len() as u64,
            merkle_root,
            chain_head_hash,
        });
    }
    checkpoints
}

/// Export a self-contained proof bundle from a chain file.
pub fn export_bundle(path: &Path, repo_id_hash: &str) -> Result<ExportBundle, AuditError> {
    let events = read_all_events(path)?;
    let total_records = events.len() as u64;
    let checkpoints = checkpoints_from_events(&events);
    Ok(ExportBundle {
        schema_version: 2,
        repo_id_hash: repo_id_hash.to_string(),
        total_records,
        checkpoints,
        events,
    })
}

pub(crate) fn read_all_events(path: &Path) -> Result<Vec<AuditEvent>, AuditError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = File::open(path)?;
    let mut events = Vec::new();
    for (index, line) in BufReader::new(file).lines().enumerate() {
        let line = line?;
        if line.is_empty() {
            continue;
        }
        let event: AuditEvent =
            serde_json::from_str(&line).map_err(|error| AuditError::MalformedRecord {
                line: index as u64 + 1,
                reason: error.to_string(),
            })?;
        events.push(event);
    }
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::{
        build_checkpoints, checkpoints_from_events, compute_merkle_root, CHECKPOINT_INTERVAL,
    };
    use crate::AuditChain;

    #[test]
    fn merkle_root_of_one_hash_is_identity() {
        let hash = "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234";
        assert_eq!(compute_merkle_root(&[hash]), hash);
    }

    #[test]
    fn merkle_root_of_two_hashes_is_deterministic() {
        let a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let root1 = compute_merkle_root(&[a, b]);
        let root2 = compute_merkle_root(&[a, b]);
        assert_eq!(root1, root2);
        assert_ne!(root1, a);
        assert_ne!(root1, b);
        assert_eq!(root1.len(), 64);
    }

    #[test]
    fn checkpoint_window_covers_interval() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("audit.log");
        let mut chain = AuditChain::open(&path, "test-repo").expect("chain opens");
        for i in 0..(CHECKPOINT_INTERVAL + 1) {
            chain
                .append(
                    "2026-05-11T20:00:00Z",
                    "allow",
                    &format!("acp-{i}"),
                    None,
                    None,
                )
                .expect("append");
        }
        let checkpoints = build_checkpoints(&path).expect("checkpoints build");
        assert_eq!(checkpoints.len(), 2);
        assert_eq!(checkpoints[0].seq_start, 1);
        assert_eq!(checkpoints[0].seq_end, CHECKPOINT_INTERVAL);
        assert_eq!(checkpoints[0].record_count, CHECKPOINT_INTERVAL);
        assert_eq!(checkpoints[1].seq_start, CHECKPOINT_INTERVAL + 1);
        assert_eq!(checkpoints[1].record_count, 1);
    }
}
