use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEvent {
    pub seq: u64,
    pub timestamp: String,
    pub decision: String,
    pub acp_hash: String,
    pub rule_id: Option<String>,
    pub reason: Option<String>,
    pub prev_hash: String,
    pub record_hash: String,
}

impl AuditEvent {
    pub fn pending(
        seq: u64,
        timestamp: impl Into<String>,
        decision: impl Into<String>,
        acp_hash: impl Into<String>,
        rule_id: Option<String>,
        reason: Option<String>,
        prev_hash: impl Into<String>,
    ) -> Self {
        Self {
            seq,
            timestamp: timestamp.into(),
            decision: decision.into(),
            acp_hash: acp_hash.into(),
            rule_id,
            reason,
            prev_hash: prev_hash.into(),
            record_hash: String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::AuditEvent;

    #[test]
    fn deserializes_known_jsonl_line() {
        let line = r#"{"seq":1,"timestamp":"2026-05-11T20:00:00Z","decision":"allow","acp_hash":"acp","rule_id":null,"reason":"ok","prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","record_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;

        let event: AuditEvent = serde_json::from_str(line).expect("event deserializes");

        assert_eq!(event.seq, 1);
        assert_eq!(event.decision, "allow");
        assert_eq!(event.record_hash.len(), 64);
    }

    #[test]
    fn rejects_unknown_fields() {
        let line = r#"{"seq":1,"timestamp":"2026-05-11T20:00:00Z","decision":"allow","acp_hash":"acp","rule_id":null,"reason":null,"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","record_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","extra":true}"#;

        serde_json::from_str::<AuditEvent>(line).expect_err("unknown field is denied");
    }
}
