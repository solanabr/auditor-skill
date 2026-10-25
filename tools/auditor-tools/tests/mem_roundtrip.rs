//! Round-trip test for the findings memory: dedup, regression, suppression.

use auditor_tools::mem;

const PROG: &str = "Prog1111111111111111111111111111111111111111";
const SIG: &str = "checked_sub@vault.balance";
const GUARDED: &[u8] =
    b"fn withdraw() {\n    require!(vault.balance >= amount);\n    vault.balance -= amount;\n}\n";

fn put(conn: &rusqlite::Connection, verdict: &str) -> mem::PutOutcome {
    mem::put_finding(
        conn,
        &mem::PutFinding {
            program_id: PROG,
            signature: SIG,
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

fn guard(text: &[u8], first: u32, last: u32) -> mem::Guard {
    mem::Guard {
        file: "src/withdraw.rs".into(),
        first,
        last,
        hash: mem::guard_hash(text, first, last).expect("the lines exist"),
    }
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
        PROG,
        SIG,
        "unchecked subtraction can underflow vault balance",
        "FIXED",
    )
    .unwrap();
    assert_eq!(changed, 1);

    let third = put(&conn, "TRUE_POSITIVE");
    assert!(third.regressed, "re-observing a FIXED finding regresses it");
    assert_eq!(third.status, "REGRESSED");

    let regs = mem::regressions(&conn, PROG).unwrap();
    assert_eq!(regs.regressions.len(), 1, "one regressed finding listed");
    assert_eq!(regs.regressions[0].status, "REGRESSED");
    assert_eq!(regs.truncated, 0);

    // Rule the signature a FALSE_POSITIVE, anchored to its commit and guard, then
    // check at that commit with the guard unchanged -> suppressed.
    let g = guard(GUARDED, 2, 2);
    mem::add_ruling(
        &conn,
        &mem::NewRuling {
            program_id: PROG,
            signature: SIG,
            ruling: "FALSE_POSITIVE",
            rationale: "subtraction is guarded by a prior require! on balance",
            by: "auditor",
            scope: None,
            commit: Some("c0ffee1"),
            guard: Some(&g),
        },
    )
    .unwrap();

    let unchanged = |_: &str| -> Result<Vec<u8>, String> { Ok(GUARDED.to_vec()) };
    let check = mem::check(&conn, PROG, SIG, Some("c0ffee1"), &unchanged).unwrap();
    assert!(check.suppressed, "FALSE_POSITIVE ruling suppresses");
    assert!(check.stale.is_none());
    let ruling = check.ruling.expect("the ruling");
    assert_eq!(ruling.guard.as_deref(), Some("src/withdraw.rs:2"));
    assert_eq!(ruling.commit.as_deref(), Some("c0ffee1"));

    // A different signature is not suppressed.
    let miss = mem::check(
        &conn,
        PROG,
        "some_other_signature",
        Some("c0ffee1"),
        &unchanged,
    )
    .unwrap();
    assert!(!miss.suppressed);
    assert!(miss.ruling.is_none() && miss.stale.is_none());

    // Warm context surfaces the ruling.
    let warm = mem::warm(&conn, PROG).unwrap();
    assert_eq!(warm.open_fp_rulings.len(), 1);
    assert!(warm.profile.is_none(), "no profile inserted in this test");
}

/// A full commit id, as the CLI takes them, and another.
const C1: &str = "c0ffee1c0ffee1c0ffee1c0ffee1c0ffee1c0ffe";
const C2: &str = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

fn rule_at(conn: &rusqlite::Connection, commit: Option<&str>, g: &mem::Guard) {
    mem::add_ruling(
        conn,
        &mem::NewRuling {
            program_id: PROG,
            signature: SIG,
            ruling: "FALSE_POSITIVE",
            rationale: "guarded",
            by: "auditor",
            scope: None,
            commit,
            guard: Some(g),
        },
    )
    .unwrap();
}

#[test]
fn a_ruling_goes_stale_when_its_commit_or_guard_changes() {
    let conn = mem::open_in_memory().expect("open in-memory db");
    rule_at(&conn, Some(C1), &guard(GUARDED, 2, 3));
    let stale = |commit: Option<&str>, text: &'static [u8]| {
        let read = move |_: &str| -> Result<Vec<u8>, String> { Ok(text.to_vec()) };
        let r = mem::check(&conn, PROG, SIG, commit, &read).unwrap();
        assert_eq!(r.suppressed, r.stale.is_none());
        r.stale
    };
    assert_eq!(stale(Some(C1), GUARDED), None);
    for other in [
        &C1[..7],
        &C1[..39],
        "c0ffee1c0ffee1c0ffee1c0ffee1c0ffee1c0ffe00",
        C2,
    ] {
        assert_eq!(
            stale(Some(other), GUARDED),
            Some(format!("ruled at commit {C1}, checked at {other}")),
            "only the same full id is the same commit"
        );
    }
    assert_eq!(
        stale(None, GUARDED),
        Some(format!(
            "ruled at commit {C1}, and no --commit was given to compare"
        ))
    );
    let edited: &[u8] = b"fn withdraw() {\n    require!(vault.balance > amount);\n    vault.balance -= amount;\n}\n";
    assert_eq!(
        stale(Some(C1), edited).as_deref(),
        Some("the guard at src/withdraw.rs:2-3 no longer holds the lines ruled on")
    );
    let moved: &[u8] = b"// moved\nfn withdraw() {\n    require!(vault.balance >= amount);\n    vault.balance -= amount;\n}\n";
    assert!(
        stale(Some(C1), moved).is_some(),
        "lines that moved are a change"
    );
    assert_eq!(
        stale(Some(C2), b"fn x() {}\n"),
        Some(format!("ruled at commit {C1}, checked at {C2}; the guard at src/withdraw.rs:2-3 cannot be read: names line 3, and the file has 1 line(s)"))
    );
    let gone = |_: &str| -> Result<Vec<u8>, String> { Err("it does not exist".to_string()) };
    let r = mem::check(&conn, PROG, SIG, Some(C1), &gone).unwrap();
    assert!(!r.suppressed);
    assert_eq!(
        r.stale.as_deref(),
        Some("the guard at src/withdraw.rs:2-3 cannot be read: it does not exist")
    );
}

#[test]
fn a_ruling_without_a_commit_never_holds() {
    let read = |_: &str| -> Result<Vec<u8>, String> { Ok(GUARDED.to_vec()) };
    let conn = mem::open_in_memory().expect("open in-memory db");
    rule_at(&conn, None, &guard(GUARDED, 2, 2));
    for commit in [None, Some(C1)] {
        let r = mem::check(&conn, PROG, SIG, commit, &read).unwrap();
        assert!(!r.suppressed);
        assert_eq!(r.stale.as_deref(), Some("ruled with no commit"));
    }
    // A stored commit that is not the id given, an empty one included, never holds.
    let conn = mem::open_in_memory().expect("open in-memory db");
    rule_at(&conn, Some(C1), &guard(GUARDED, 2, 2));
    conn.execute("UPDATE fp_rulings SET anchor_commit = ''", [])
        .unwrap();
    let r = mem::check(&conn, PROG, SIG, Some(C1), &read).unwrap();
    assert!(!r.suppressed);
    assert_eq!(r.stale, Some(format!("ruled at commit , checked at {C1}")));
}

#[test]
fn guard_lines_hash_with_their_newlines() {
    let text = b"a\nb\r\nc";
    assert!(mem::guard_hash(text, 1, 3).is_ok());
    assert_ne!(
        mem::guard_hash(text, 2, 2),
        mem::guard_hash(b"a\nb\nc", 2, 2)
    );
    assert_eq!(
        mem::guard_hash(text, 4, 4),
        Err("names line 4, and the file has 3 line(s)".to_string())
    );
    assert_eq!(
        mem::guard_hash(text, 0, 1),
        Err("is not a range of lines".to_string())
    );
    assert_eq!(
        mem::guard_hash(text, 2, 1),
        Err("is not a range of lines".to_string())
    );
}

#[test]
fn profile_and_invariants_reach_warm() {
    let conn = mem::open_in_memory().expect("open in-memory db");
    mem::put_profile(
        &conn,
        PROG,
        &mem::ProfileFields {
            protocol_class: Some("vault"),
            notes: Some("first pass"),
            ..Default::default()
        },
    )
    .unwrap();
    mem::put_profile(
        &conn,
        PROG,
        &mem::ProfileFields {
            oracle_set: Some("pyth SOL/USD"),
            ..Default::default()
        },
    )
    .unwrap();
    let (id, new, replaced) = mem::put_invariant(
        &conn,
        PROG,
        "total_shares == shares_mint.supply",
        &mem::InvariantFields {
            status: Some("Unproven"),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(new);
    assert!(replaced.is_empty());
    let (again, new, replaced) = mem::put_invariant(
        &conn,
        PROG,
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
    assert_eq!(
        replaced,
        ["status"],
        "a status set before is replaced, not erased"
    );
    let warm = mem::warm(&conn, PROG).unwrap();
    let profile = warm.profile.expect("the profile");
    assert_eq!(profile.protocol_class, "vault");
    assert_eq!(profile.oracle_set, "pyth SOL/USD");
    assert_eq!(
        profile.notes, "first pass",
        "a later write keeps the fields it does not give"
    );
    assert!(
        profile.changed.is_empty(),
        "a field set for the first time replaces nothing"
    );
    assert_eq!(warm.invariants.len(), 1);
    assert_eq!(warm.invariants[0].status, "Manually verified");
    assert_eq!(warm.invariants[0].cited_line, "src/vault.rs:88");
    let changed: Vec<(&str, &str)> = warm.invariants[0]
        .changed
        .iter()
        .map(|c| (c.field.as_str(), c.previous.as_str()))
        .collect();
    assert_eq!(changed, [("status", "Unproven")]);
    assert!(mem::warm(&conn, "OtherProg").unwrap().profile.is_none());
}

#[test]
fn a_replaced_profile_value_is_kept_and_warm_lists_it() {
    let conn = mem::open_in_memory().expect("open in-memory db");
    let put = |notes: &str, admin: Option<&str>| {
        mem::put_profile(
            &conn,
            PROG,
            &mem::ProfileFields {
                notes: Some(notes),
                admin_set: admin,
                ..Default::default()
            },
        )
        .unwrap()
    };
    assert!(put("first", Some("3-of-5 multisig; upgrades timelocked 48h")).is_empty());
    assert!(
        put("first", None).is_empty(),
        "the same value replaces nothing"
    );
    assert_eq!(put("second", Some("fully trusted")), ["admin_set", "notes"]);
    assert_eq!(put("", None), ["notes"], "a value erased is kept too");
    let profile = mem::warm(&conn, PROG)
        .unwrap()
        .profile
        .expect("the profile");
    assert_eq!(profile.notes, "");
    assert_eq!(profile.admin_set, "fully trusted");
    let changed: Vec<(&str, &str)> = profile
        .changed
        .iter()
        .map(|c| (c.field.as_str(), c.previous.as_str()))
        .collect();
    assert_eq!(
        changed,
        [
            ("notes", "second"),
            ("notes", "first"),
            ("admin_set", "3-of-5 multisig; upgrades timelocked 48h"),
        ],
        "newest first"
    );
    assert!(profile.changed.iter().all(|c| !c.recorded_at.is_empty()));
}

#[test]
fn warm_and_regressions_hold_the_newest_rows_and_count_the_rest() {
    let conn = mem::open_in_memory().expect("open in-memory db");
    for i in 0..250 {
        mem::put_invariant(&conn, PROG, &format!("invariant {i}"), &Default::default()).unwrap();
    }
    for i in 0..210 {
        mem::add_ruling(
            &conn,
            &mem::NewRuling {
                program_id: PROG,
                signature: &format!("sig {i}"),
                ruling: "ACCEPTED_RISK",
                rationale: "r",
                by: "a",
                scope: None,
                commit: None,
                guard: None,
            },
        )
        .unwrap();
    }
    for i in 0..205 {
        mem::put_profile(
            &conn,
            PROG,
            &mem::ProfileFields {
                notes: Some(&format!("notes {i}")),
                ..Default::default()
            },
        )
        .unwrap();
    }
    let warm = mem::warm(&conn, PROG).unwrap();
    assert_eq!(warm.invariants.len(), 200);
    assert_eq!(
        warm.invariants[0].statement, "invariant 50",
        "the newest, as recorded"
    );
    assert_eq!(warm.invariants[199].statement, "invariant 249");
    assert_eq!(warm.open_fp_rulings.len(), 200);
    assert_eq!(
        warm.open_fp_rulings[0].code_signature, "sig 209",
        "newest first"
    );
    let profile = warm.profile.expect("the profile");
    assert_eq!(profile.changed.len(), 10, "the newest ten");
    assert_eq!(profile.changed[0].previous, "notes 203");
    assert_eq!(profile.changed[9].previous, "notes 194");
    assert_eq!(
        warm.truncated,
        50 + 10 + 194,
        "invariants, rulings and replaced values left out"
    );
    for i in 0..230 {
        let sig = format!("sig {i}");
        let f = |severity| mem::PutFinding {
            program_id: PROG,
            signature: &sig,
            root_cause: "rc",
            title: "t",
            severity,
            commit: None,
            audit_n: None,
            file: None,
            line: None,
            verdict: None,
        };
        mem::put_finding(&conn, &f(1 + i % 10)).unwrap();
        mem::set_status(&conn, PROG, &sig, "rc", "FIXED").unwrap();
        mem::put_finding(&conn, &f(1 + i % 10)).unwrap();
    }
    let regs = mem::regressions(&conn, PROG).unwrap();
    assert_eq!(regs.regressions.len(), 200);
    assert_eq!(regs.truncated, 30);
    let kept: std::collections::BTreeSet<String> = regs
        .regressions
        .iter()
        .map(|r| r.code_signature.clone())
        .collect();
    let newest: std::collections::BTreeSet<String> =
        (30..230).map(|i| format!("sig {i}")).collect();
    assert_eq!(
        kept, newest,
        "the 200 seen most recently, not the most severe"
    );
    assert!(
        regs.regressions
            .windows(2)
            .all(|w| w[0].severity >= w[1].severity),
        "the most severe first"
    );
    assert_eq!(
        regs.regressions[0].code_signature, "sig 229",
        "the most recently seen first among equals"
    );
    assert_eq!(regs.regressions[199].code_signature, "sig 30");
}

/// The finding of `sig` put with `severity` and `title`.
fn put_one(conn: &rusqlite::Connection, sig: &str, severity: i64, title: &str) -> mem::PutOutcome {
    mem::put_finding(
        conn,
        &mem::PutFinding {
            program_id: PROG,
            signature: sig,
            root_cause: "rc",
            title,
            severity,
            commit: None,
            audit_n: None,
            file: None,
            line: None,
            verdict: None,
        },
    )
    .unwrap()
}

#[test]
fn a_replaced_severity_and_title_are_kept_and_regressions_lists_them() {
    let conn = mem::open_in_memory().expect("open in-memory db");
    put_one(&conn, SIG, 9, "Vault drained through an unchecked withdraw");
    mem::set_status(&conn, PROG, SIG, "rc", "FIXED").unwrap();
    assert!(put_one(&conn, SIG, 9, "Vault drained through an unchecked withdraw").regressed);
    // A later call with the same signature rewrites what the next audit reads.
    put_one(&conn, SIG, 1, "cosmetic: rename variable");
    let regs = mem::regressions(&conn, PROG).unwrap();
    assert_eq!(regs.regressions.len(), 1);
    let row = &regs.regressions[0];
    assert_eq!(
        (row.severity, row.title.as_str()),
        (1, "cosmetic: rename variable")
    );
    let changed: Vec<(&str, &str)> = row
        .changed
        .iter()
        .map(|c| (c.field.as_str(), c.previous.as_str()))
        .collect();
    assert_eq!(
        changed,
        [
            ("title", "Vault drained through an unchecked withdraw"),
            ("severity", "9"),
        ],
        "newest first"
    );
    assert_eq!(regs.truncated, 0);
    put_one(&conn, SIG, 1, "cosmetic: rename variable");
    assert_eq!(
        mem::regressions(&conn, PROG).unwrap().regressions[0]
            .changed
            .len(),
        2,
        "the same values replace nothing"
    );
}

#[test]
fn each_answer_lists_ten_changes_an_item_and_two_hundred_in_all() {
    let conn = mem::open_in_memory().expect("open in-memory db");
    for i in 0..30 {
        let statement = format!("invariant {i}");
        for round in 0..16 {
            mem::put_invariant(
                &conn,
                PROG,
                &statement,
                &mem::InvariantFields {
                    status: Some(&format!("status {round}")),
                    ..Default::default()
                },
            )
            .unwrap();
        }
    }
    let warm = mem::warm(&conn, PROG).unwrap();
    let counts: Vec<usize> = warm.invariants.iter().map(|i| i.changed.len()).collect();
    assert_eq!(counts, [[10; 20].as_slice(), &[0; 10]].concat());
    assert_eq!(warm.invariants[0].changed[0].previous, "status 14");
    assert_eq!(
        warm.truncated,
        30 * 15 - 200,
        "the replaced values left out"
    );

    for i in 0..25 {
        let sig = format!("sig {i}");
        put_one(&conn, &sig, 1, "t0");
        mem::set_status(&conn, PROG, &sig, "rc", "FIXED").unwrap();
        for round in 1..=6 {
            put_one(&conn, &sig, 1 + round % 2, &format!("t{round}"));
        }
    }
    let regs = mem::regressions(&conn, PROG).unwrap();
    let counts: Vec<usize> = regs.regressions.iter().map(|r| r.changed.len()).collect();
    assert_eq!(counts.iter().sum::<usize>(), 200);
    assert!(counts.iter().all(|&n| n <= 10));
    assert_eq!(
        regs.truncated,
        25 * 12 - 200,
        "the replaced values left out"
    );
}
