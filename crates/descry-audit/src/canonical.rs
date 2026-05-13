use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::{AuditError, AuditEvent};

pub(crate) fn canonical_minus_record_hash(event: &AuditEvent) -> Result<Vec<u8>, AuditError> {
    let mut value = serde_json::to_value(event)?;
    match &mut value {
        Value::Object(fields) => {
            fields.remove("record_hash");
            let sorted = sort_value(Value::Object(std::mem::take(fields)));
            serde_json::to_vec(&sorted).map_err(AuditError::from)
        }
        _ => Err(AuditError::MalformedRecord {
            line: 0,
            reason: String::from("event did not serialize as object"),
        }),
    }
}

fn sort_value(value: Value) -> Value {
    match value {
        Value::Object(fields) => {
            let sorted: BTreeMap<String, Value> = fields
                .into_iter()
                .map(|(key, value)| (key, sort_value(value)))
                .collect();
            Value::Object(Map::from_iter(sorted))
        }
        Value::Array(values) => Value::Array(values.into_iter().map(sort_value).collect()),
        value => value,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::sort_value;
    use crate::{canonical::canonical_minus_record_hash, AuditEvent};

    #[test]
    fn canonical_event_order_is_stable() {
        let event = AuditEvent::pending(
            7,
            "2026-05-11T20:00:00Z",
            "allow_with_log",
            "acp",
            Some(String::from("rule")),
            Some(String::from("reason")),
            "0000000000000000000000000000000000000000000000000000000000000000",
        );

        let canonical = canonical_minus_record_hash(&event).expect("canonicalizes");

        assert_eq!(
            canonical,
            br#"{"acp_hash":"acp","decision":"allow_with_log","prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","reason":"reason","rule_id":"rule","seq":7,"timestamp":"2026-05-11T20:00:00Z"}"#
        );
    }

    #[test]
    fn recursive_sort_is_independent_of_insertion_order() {
        let first = json!({
            "z": 1,
            "a": {
                "b": true,
                "a": "first"
            }
        });
        let second = json!({
            "a": {
                "a": "first",
                "b": true
            },
            "z": 1
        });

        let first = serde_json::to_vec(&sort_value(first)).expect("json encodes");
        let second = serde_json::to_vec(&sort_value(second)).expect("json encodes");

        assert_eq!(first, second);
    }
}
