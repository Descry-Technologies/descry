use std::fs;

use descry_audit::{verify_file, AuditChain, VerifyOutcome};

#[test]
fn append_three_records_and_detect_tamper_at_second_record() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let path = tempdir.path().join("audit.log");
    let mut chain = AuditChain::open(&path, "test-repo").expect("chain opens");

    for seq in 1..=3 {
        chain
            .append(
                format!("2026-05-11T20:00:0{seq}Z"),
                "allow",
                format!("acp-{seq}"),
                None,
                Some(format!("reason-{seq}")),
            )
            .expect("append succeeds");
    }

    assert_eq!(
        verify_file(&path, "test-repo"),
        VerifyOutcome::Ok { records: 3 }
    );

    let mut body = fs::read_to_string(&path).expect("audit log reads");
    body = body.replacen("reason-2", "Reason-2", 1);
    fs::write(&path, body).expect("audit log mutates");

    match verify_file(&path, "test-repo") {
        VerifyOutcome::Broken { at_seq, reason } => {
            assert_eq!(at_seq, 2);
            assert!(!reason.is_empty());
        }
        outcome => panic!("expected broken chain, got {outcome:?}"),
    }
}
