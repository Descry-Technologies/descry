use std::path::Path;

use descry_core::{ActionContextPacket, Decision};
use descry_policy::Policy;

#[derive(Debug)]
struct FixtureCase {
    path: String,
    expected_decision: String,
    expected_rule: Option<String>,
}

#[test]
fn safe_defaults_match_manifest_hard_block_fixtures() {
    let policy = Policy::load_yaml(include_str!("../../../policies/safe-defaults.yml"))
        .expect("safe defaults policy loads");

    for case in manifest_cases() {
        if case.expected_decision == "require_approval"
            || (case.expected_decision == "block" && case.expected_rule.is_none())
        {
            continue;
        }
        let body = std::fs::read_to_string(repo_path(&case.path)).expect("fixture reads");
        let acp: ActionContextPacket = serde_yml::from_str(&body).expect("fixture deserializes");
        let decision = policy.evaluate(&acp);
        let expected = decision_from_manifest(&case.expected_decision);

        assert_eq!(decision.decision, expected, "{}", case.path);
        if let Some(rule_id) = case.expected_rule {
            assert_eq!(decision.decision, Decision::Block, "{}", case.path);
            assert!(decision.reason.contains(&format!("(rule: {rule_id})")));
            assert_eq!(decision.risk_score.0, 100, "{}", case.path);
            assert_eq!(decision.confidence.0, 0.98, "{}", case.path);
        }
    }
}

#[test]
fn manifest_references_existing_fixture_files() {
    for case in manifest_cases() {
        assert!(repo_path(&case.path).exists(), "{}", case.path);
    }
}

fn manifest_cases() -> Vec<FixtureCase> {
    parse_manifest(include_str!("../../../fixtures/manifest.yml"))
}

fn parse_manifest(body: &str) -> Vec<FixtureCase> {
    let mut cases = Vec::new();
    let mut current = FixtureCase {
        path: String::new(),
        expected_decision: String::new(),
        expected_rule: None,
    };
    for line in body.lines() {
        if let Some(path) = line.strip_prefix("- path: ") {
            if !current.path.is_empty() {
                cases.push(current);
            }
            current = FixtureCase {
                path: path.trim().to_string(),
                expected_decision: String::new(),
                expected_rule: None,
            };
        } else if let Some(value) = line.trim().strip_prefix("expected_decision: ") {
            current.expected_decision = value.trim().to_string();
        } else if let Some(value) = line.trim().strip_prefix("expected_rule: ") {
            current.expected_rule = Some(value.trim().to_string());
        }
    }
    if !current.path.is_empty() {
        cases.push(current);
    }
    cases
}

fn decision_from_manifest(value: &str) -> Decision {
    match value {
        "allow" => Decision::Allow,
        "block" => Decision::Block,
        other => panic!("unsupported hard-block manifest decision {other}"),
    }
}

fn repo_path(path: impl AsRef<Path>) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}
