use sha2::{Digest, Sha256};

pub(crate) fn record_hash(
    repo_id_hash: &str,
    seq: u64,
    prev_hash: &str,
    canonical: &[u8],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"descry-audit-v1\n");
    hasher.update(repo_id_hash.as_bytes());
    hasher.update(b"\n");
    hasher.update(seq.to_string().as_bytes());
    hasher.update(b"\n");
    hasher.update(prev_hash.as_bytes());
    hasher.update(b"\n");
    hasher.update(canonical);

    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::record_hash;

    #[test]
    fn known_input_hash_is_locked() {
        let hash = record_hash(
            "test-repo",
            1,
            "0000000000000000000000000000000000000000000000000000000000000000",
            b"genesis-event",
        );

        assert_eq!(
            hash,
            "30504250db443daedc423dd292153e7c9cd7d496ccbbfef229f9a1e1c92ba110"
        );
    }
}
