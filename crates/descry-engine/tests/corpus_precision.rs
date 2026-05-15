use std::path::{Path, PathBuf};

use descry_core::ActionContextPacket;
use descry_engine::{build_decision_input, evaluate, EvaluationRuntime};
use descry_policy::{Policy, ProjectPolicy};
use serde::Deserialize;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("engine crate has crates parent")
        .parent()
        .expect("crates dir has workspace parent")
        .to_path_buf()
}

#[derive(Debug, Deserialize)]
struct ManifestEntry {
    path: String,
    expected_decision: String,
    #[serde(default)]
    category: String,
}

fn load_policy() -> Policy {
    let root = workspace_root();
    let body = std::fs::read_to_string(root.join("policies/safe-defaults.yml"))
        .expect("policy file readable");
    Policy::load_yaml(&body).expect("policy parses")
}

fn evaluate_fixture(acp: ActionContextPacket, policy: &Policy) -> String {
    let project_config = ProjectPolicy::default();
    let approvals = std::env::temp_dir().join("corpus-precision-approvals.jsonl");
    let behavior = std::env::temp_dir().join("corpus-precision-behavior.json");
    let output = evaluate(
        build_decision_input(acp),
        EvaluationRuntime {
            policy,
            project_config: &project_config,
            approvals_path: &approvals,
            behavior_path: &behavior,
            project_index: None,
            shadow: false,
        },
    );
    decision_name(&output.decision)
}

fn decision_name(d: &descry_core::Decision) -> String {
    use descry_core::Decision;
    match d {
        Decision::Allow => "allow",
        Decision::AllowWithLog => "allow_with_log",
        Decision::Ask => "require_approval",
        Decision::RequireApproval => "require_approval",
        Decision::Block => "block",
    }
    .to_string()
}

#[test]
fn corpus_precision() {
    let root = workspace_root();
    let manifest_path = root.join("fixtures/manifest.yml");
    let manifest_body =
        std::fs::read_to_string(&manifest_path).expect("fixtures/manifest.yml readable");
    let entries: Vec<ManifestEntry> =
        serde_yml::from_str(&manifest_body).expect("manifest parses");

    let policy = load_policy();
    let gate: f64 = std::env::var("DESCRY_PRECISION_GATE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.95);

    let mut total_allows = 0usize;
    let mut correct_allows = 0usize;
    let mut mismatches: Vec<String> = Vec::new();

    for entry in &entries {
        let fixture_path = root.join(&entry.path);
        let body = match std::fs::read_to_string(&fixture_path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("warning: cannot read {}: {e}", entry.path);
                continue;
            }
        };
        let acp: ActionContextPacket = match serde_json::from_str(&body) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("warning: cannot parse {}: {e}", entry.path);
                continue;
            }
        };

        let actual = evaluate_fixture(acp, &policy);

        if entry.expected_decision == "allow" {
            total_allows += 1;
            if actual == "allow" {
                correct_allows += 1;
            } else {
                mismatches.push(format!(
                    "{} (category: {}) expected=allow actual={}",
                    entry.path, entry.category, actual
                ));
            }
        } else if actual != entry.expected_decision {
            mismatches.push(format!(
                "{} (category: {}) expected={} actual={}",
                entry.path, entry.category, entry.expected_decision, actual
            ));
        }
    }

    let precision = if total_allows == 0 {
        1.0f64
    } else {
        correct_allows as f64 / total_allows as f64
    };

    if !mismatches.is_empty() {
        eprintln!("Corpus mismatches:");
        for m in &mismatches {
            eprintln!("  {m}");
        }
    }

    assert!(
        precision >= gate,
        "precision {:.3} < gate {:.3} ({correct_allows}/{total_allows} allows correct)",
        precision,
        gate,
    );
}
