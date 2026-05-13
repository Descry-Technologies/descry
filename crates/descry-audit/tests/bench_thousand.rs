use std::time::Instant;

use descry_audit::{verify_file, AuditChain, VerifyOutcome};

#[test]
fn append_and_verify_one_thousand_records() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let path = tempdir.path().join("audit.log");
    let start = Instant::now();
    let mut chain = AuditChain::open(&path, "test-repo").expect("chain opens");

    for seq in 1..=1000 {
        chain
            .append(
                format!("2026-05-11T20:{:02}:{:02}Z", (seq / 60) % 60, seq % 60),
                "allow",
                format!("acp-{seq}"),
                None,
                Some(format!("reason-{seq}")),
            )
            .expect("append succeeds");
    }

    assert_eq!(
        verify_file(&path, "test-repo"),
        VerifyOutcome::Ok { records: 1000 }
    );
    assert!(start.elapsed().as_secs_f64() < 2.0);
}
