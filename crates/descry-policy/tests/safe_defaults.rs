use descry_core::{ActionContextPacket, Decision};
use descry_policy::Policy;

#[test]
fn safe_defaults_match_tier_one_fixtures() {
    let policy = Policy::load_yaml(include_str!("../../../policies/safe-defaults.yml"))
        .expect("safe defaults policy loads");

    let cases = [
        ("../../../fixtures/rm-rf-home.json", Decision::Block),
        ("../../../fixtures/rm-rf-slash.json", Decision::Block),
        ("../../../fixtures/rm-rf-home-var.json", Decision::Block),
        ("../../../fixtures/rm-rf-home-glob.json", Decision::Block),
        ("../../../fixtures/rm-rf-sudo-home.json", Decision::Block),
        ("../../../fixtures/force-push-main.json", Decision::Block),
        ("../../../fixtures/force-push-release.json", Decision::Block),
        ("../../../fixtures/railway-delete.json", Decision::Block),
        ("../../../fixtures/fly-destroy.json", Decision::Block),
        ("../../../fixtures/aws-rds-delete.json", Decision::Block),
        ("../../../fixtures/gcloud-sql-delete.json", Decision::Block),
        ("../../../fixtures/db-drop-database.json", Decision::Block),
        ("../../../fixtures/db-truncate-table.json", Decision::Block),
        ("../../../fixtures/normal-edit.json", Decision::Allow),
        ("../../../fixtures/cargo-test.json", Decision::Allow),
    ];

    for (fixture, expected) in cases {
        let acp: ActionContextPacket =
            serde_yml::from_str(include_str_by_path(fixture)).expect("fixture deserializes");
        let decision = policy.evaluate(&acp);

        assert_eq!(decision.decision, expected, "{fixture}");

        if decision.decision == Decision::Block {
            assert_eq!(decision.risk_score.0, 100, "{fixture}");
            assert_eq!(decision.confidence.0, 0.98, "{fixture}");
        }
    }
}

fn include_str_by_path(path: &str) -> &'static str {
    match path {
        "../../../fixtures/rm-rf-home.json" => include_str!("../../../fixtures/rm-rf-home.json"),
        "../../../fixtures/rm-rf-slash.json" => include_str!("../../../fixtures/rm-rf-slash.json"),
        "../../../fixtures/rm-rf-home-var.json" => {
            include_str!("../../../fixtures/rm-rf-home-var.json")
        }
        "../../../fixtures/rm-rf-home-glob.json" => {
            include_str!("../../../fixtures/rm-rf-home-glob.json")
        }
        "../../../fixtures/rm-rf-sudo-home.json" => {
            include_str!("../../../fixtures/rm-rf-sudo-home.json")
        }
        "../../../fixtures/force-push-main.json" => {
            include_str!("../../../fixtures/force-push-main.json")
        }
        "../../../fixtures/force-push-release.json" => {
            include_str!("../../../fixtures/force-push-release.json")
        }
        "../../../fixtures/railway-delete.json" => {
            include_str!("../../../fixtures/railway-delete.json")
        }
        "../../../fixtures/fly-destroy.json" => include_str!("../../../fixtures/fly-destroy.json"),
        "../../../fixtures/aws-rds-delete.json" => {
            include_str!("../../../fixtures/aws-rds-delete.json")
        }
        "../../../fixtures/gcloud-sql-delete.json" => {
            include_str!("../../../fixtures/gcloud-sql-delete.json")
        }
        "../../../fixtures/db-drop-database.json" => {
            include_str!("../../../fixtures/db-drop-database.json")
        }
        "../../../fixtures/db-truncate-table.json" => {
            include_str!("../../../fixtures/db-truncate-table.json")
        }
        "../../../fixtures/normal-edit.json" => include_str!("../../../fixtures/normal-edit.json"),
        "../../../fixtures/cargo-test.json" => include_str!("../../../fixtures/cargo-test.json"),
        _ => unreachable!("fixture path is defined in the test table"),
    }
}
