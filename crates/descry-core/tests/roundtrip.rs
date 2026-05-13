use descry_core::{ActionContextPacket, Confidence, Decision, DecisionOutput, RiskScore};

fn assert_acp_roundtrip(json: &str) {
    let decoded: ActionContextPacket = serde_json::from_str(json).expect("fixture parses");
    let encoded = serde_json::to_string(&decoded).expect("fixture serializes");
    let reparsed: ActionContextPacket = serde_json::from_str(&encoded).expect("roundtrip parses");

    assert_eq!(decoded, reparsed);
}

fn assert_decision_roundtrip(decision: Decision) {
    let output = DecisionOutput {
        decision,
        risk_score: RiskScore::try_from(42).expect("valid risk score"),
        confidence: Confidence::try_from(0.87).expect("valid confidence"),
        reason: String::from("Round-trip test decision."),
        conditions: vec![String::from("Keep JSON stable")],
    };

    let encoded = serde_json::to_string(&output).expect("decision serializes");
    let reparsed: DecisionOutput = serde_json::from_str(&encoded).expect("roundtrip parses");

    assert_eq!(output, reparsed);
}

#[test]
fn roundtrip_acp_minimal_fixture() {
    assert_acp_roundtrip(include_str!("fixtures/minimal.json"));
}

#[test]
fn roundtrip_acp_full_fixture() {
    assert_acp_roundtrip(include_str!("fixtures/full.json"));
}

#[test]
fn roundtrip_acp_spec_example_fixture() {
    assert_acp_roundtrip(include_str!("fixtures/spec_example.json"));
}

#[test]
fn roundtrip_decision_allow() {
    assert_decision_roundtrip(Decision::Allow);
}

#[test]
fn roundtrip_decision_allow_with_log() {
    let output = DecisionOutput {
        decision: Decision::AllowWithLog,
        risk_score: RiskScore::try_from(42).expect("valid risk score"),
        confidence: Confidence::try_from(0.87).expect("valid confidence"),
        reason: String::from("The edit targets an auth-sensitive file."),
        conditions: Vec::new(),
    };

    let encoded = serde_json::to_string(&output).expect("decision serializes");

    assert!(encoded.contains(r#""decision":"allow_with_log""#));

    let reparsed: DecisionOutput = serde_json::from_str(&encoded).expect("roundtrip parses");
    assert_eq!(output, reparsed);
}

#[test]
fn roundtrip_decision_ask() {
    assert_decision_roundtrip(Decision::Ask);
}

#[test]
fn roundtrip_decision_require_approval() {
    assert_decision_roundtrip(Decision::RequireApproval);
}

#[test]
fn roundtrip_decision_block() {
    assert_decision_roundtrip(Decision::Block);
}
