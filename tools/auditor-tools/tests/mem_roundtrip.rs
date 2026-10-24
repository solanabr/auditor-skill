//! Round-trip test for the findings memory: dedup, regression, suppression.

use auditor_tools::mem;

fn put(conn: &rusqlite::Connection, verdict: &str) -> mem::PutOutcome {
    mem::put_finding(
        conn,
        &mem::PutFinding {
            program_id: "Prog1111111111111111111111111111111111111111",
            signature: "checked_sub@vault.balance",
            root_cause: "unchecked subtraction can underflow vault balance",
            title: "Vault balance underflow",
            severity: 3,
            commit: Some("abc123"),
            audit_n: Some("audit-1"),
            file: Some("src/withdraw.rs"),
            line: Some(42),
            verdict: Some(verdict),
        },
    )
    .expect("put_finding should succeed")
}

#[test]
fn dedup_regression_and_suppression() {
    let conn = mem::open_in_memory().expect("open in-memory db");

    // First observation -> OPEN, one findings row.
    let first = put(&conn, "TRUE_POSITIVE");
    assert_eq!(first.status, "OPEN");
    assert!(!first.regressed);

    // Second observation with same signature -> still one findings row, two occurrences.
    let second = put(&conn, "TRUE_POSITIVE");
    assert_eq!(second.finding_id, first.finding_id, "same finding id");

    let findings_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM findings", [], |r| r.get(0))
        .unwrap();
    assert_eq!(findings_count, 1, "exact dedup: one findings row");

    let occ_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM occurrences", [], |r| r.get(0))
        .unwrap();
    assert_eq!(occ_count, 2, "two occurrences recorded");

    // Mark FIXED, then re-observe -> REGRESSED.
    let changed = mem::set_status(
        &conn,
        "Prog1111111111111111111111111111111111111111",
        "checked_sub@vault.balance",
        "unchecked subtraction can underflow vault balance",
        "FIXED",
    )
    .unwrap();
    assert_eq!(changed, 1);

    let third = put(&conn, "TRUE_POSITIVE");
    assert!(third.regressed, "re-observing a FIXED finding regresses it");
    assert_eq!(third.status, "REGRESSED");

    let regs = mem::regressions(&conn, "Prog1111111111111111111111111111111111111111").unwrap();
    assert_eq!(regs.len(), 1, "one regressed finding listed");
    assert_eq!(regs[0].status, "REGRESSED");

    // Rule the signature a FALSE_POSITIVE, then check -> suppressed.
    mem::add_ruling(
        &conn,
        "Prog1111111111111111111111111111111111111111",
        "checked_sub@vault.balance",
        "FALSE_POSITIVE",
        "subtraction is guarded by a prior require! on balance",
        "auditor",
        None,
    )
    .unwrap();

    let check = mem::check(
        &conn,
        "Prog1111111111111111111111111111111111111111",
        "checked_sub@vault.balance",
    )
    .unwrap();
    assert!(check.suppressed, "FALSE_POSITIVE ruling suppresses");
    assert!(check.ruling.is_some());

    // A different signature is not suppressed.
    let miss = mem::check(
        &conn,
        "Prog1111111111111111111111111111111111111111",
        "some_other_signature",
    )
    .unwrap();
    assert!(!miss.suppressed);

    // Warm context surfaces the ruling.
    let warm = mem::warm(&conn, "Prog1111111111111111111111111111111111111111").unwrap();
    assert_eq!(warm.open_fp_rulings.len(), 1);
    assert!(warm.profile.is_none(), "no profile inserted in this test");
}

#[test]
fn profile_and_invariants_reach_warm() {
    let conn = mem::open_in_memory().expect("open in-memory db");
    mem::put_profile(
        &conn,
        "Prog1111111111111111111111111111111111111111",
        &mem::ProfileFields {
            protocol_class: Some("vault"),
            notes: Some("first pass"),
            ..Default::default()
        },
    )
    .unwrap();
    mem::put_profile(
        &conn,
        "Prog1111111111111111111111111111111111111111",
        &mem::ProfileFields {
            oracle_set: Some("pyth SOL/USD"),
            ..Default::default()
        },
    )
    .unwrap();
    let (id, new) = mem::put_invariant(
        &conn,
        "Prog1111111111111111111111111111111111111111",
        "total_shares == shares_mint.supply",
        &mem::InvariantFields {
            status: Some("Unproven"),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(new);
    let (again, new) = mem::put_invariant(
        &conn,
        "Prog1111111111111111111111111111111111111111",
        "total_shares == shares_mint.supply",
        &mem::InvariantFields {
            status: Some("Manually verified"),
            cited_line: Some("src/vault.rs:88"),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        (again, new),
        (id, false),
        "the same statement is one invariant"
    );
    let warm = mem::warm(&conn, "Prog1111111111111111111111111111111111111111").unwrap();
    let profile = warm.profile.expect("the profile");
    assert_eq!(profile.protocol_class, "vault");
    assert_eq!(profile.oracle_set, "pyth SOL/USD");
    assert_eq!(
        profile.notes, "first pass",
        "a later write keeps the fields it does not give"
    );
    assert_eq!(warm.invariants.len(), 1);
    assert_eq!(warm.invariants[0].status, "Manually verified");
    assert_eq!(warm.invariants[0].cited_line, "src/vault.rs:88");
    assert!(mem::warm(&conn, "OtherProg").unwrap().profile.is_none());
}
