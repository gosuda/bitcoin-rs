use super::*;

// -----------------------------------------------------------------------
// A2.4: Oversized file is ignored
// -----------------------------------------------------------------------

#[test]
fn oversized_evidence_file_is_ignored() {
    let dir = tempfile::tempdir().expect("tempdir");
    let genesis = "aaaa";

    // Write a valid witness.
    let w = AppliedTipWitness::new(genesis, 1, 100, "aaa", 1000);
    write_witness(dir.path(), &w).expect("write");

    // Overwrite current with oversized garbage.
    let big = "x".repeat(MAX_FILE_BYTES + 1);
    std::fs::write(dir.path().join(WITNESS_FILE), &big).expect("overwrite");

    // No .prev exists, so read_witness returns None.
    assert_eq!(
        read_witness(dir.path(), genesis),
        None,
        "oversized file is ignored"
    );
}

// -----------------------------------------------------------------------
// A2.4: getblockchaininfo warnings from one immutable load
// -----------------------------------------------------------------------

#[test]
fn getblockchaininfo_reports_atomic_rollback_warnings() {
    let store = WarningStore::new();

    store.set_checkpoint("checkpoint fallback at 200");
    store.add_index("index 'txindex' watermark at 250 is 150 block(s) ahead");
    store.add_index("index 'scriptindex' watermark at 300 is 200 block(s) ahead");

    // One immutable load produces all warnings in deterministic order.
    let snapshot = store.load();
    let warnings = snapshot.warnings();

    assert_eq!(warnings.len(), 3);
    assert_eq!(warnings[0], "checkpoint fallback at 200");
    // Index warnings sorted alphabetically.
    assert!(
        warnings[1].contains("scriptindex"),
        "sorted: scriptindex before txindex"
    );
    assert!(warnings[2].contains("txindex"));
}

// -----------------------------------------------------------------------
// A2 repair (RecA12c4): semantic rotation — a parseable but foreign-genesis
// or wrong-format current cannot displace a valid .prev
// -----------------------------------------------------------------------

#[test]
fn foreign_genesis_current_cannot_displace_valid_prev() {
    let dir = tempfile::tempdir().expect("tempdir");
    let genesis = "aaaa";
    let w1 = AppliedTipWitness::new(genesis, 1, 100, "aaa", 1000);
    let w2 = AppliedTipWitness::new(genesis, 2, 200, "bbb", 2000);

    // Establish a valid current (w2) and a valid .prev (w1).
    write_witness(dir.path(), &w1).expect("write w1");
    write_witness(dir.path(), &w2).expect("write w2 -> w1 rotates to .prev");
    assert_eq!(read_witness(dir.path(), genesis), Some(w2.clone()));

    // Plant a parseable but FOREIGN-GENESIS current directly. This is the
    // bug class: parseable JSON that the old parse-only validator accepted.
    let foreign = AppliedTipWitness::new("bbbb", 3, 300, "ccc", 3000);
    let foreign_bytes = format!("{}\n", foreign.to_json());
    std::fs::write(dir.path().join(WITNESS_FILE), foreign_bytes.as_bytes())
        .expect("plant foreign current");
    assert!(
        AppliedTipWitness::from_json(&std::fs::read(dir.path().join(WITNESS_FILE)).unwrap())
            .is_some(),
        "foreign current is parseable JSON"
    );

    // A subsequent valid write must classify the foreign current INVALID:
    // remove it, keep the valid .prev (w1), then publish the new current.
    let w3 = AppliedTipWitness::new(genesis, 4, 400, "ddd", 4000);
    write_witness(dir.path(), &w3).expect("write w3 over foreign current");
    assert_eq!(read_witness(dir.path(), genesis), Some(w3.clone()));

    // Removal path: delete the current; the valid .prev (w1) must survive
    // and read_bounded must never surface the foreign record.
    std::fs::remove_file(dir.path().join(WITNESS_FILE)).expect("remove current");
    assert_eq!(
        read_witness(dir.path(), genesis),
        Some(w1.clone()),
        "valid .prev survives; foreign current never displaced it"
    );
    let raw = read_bounded(dir.path(), WITNESS_FILE, WITNESS_PREV)
        .expect("bounded read returns .prev bytes");
    assert!(
        AppliedTipWitness::from_json(&raw).is_some_and(|w| w.genesis_hash == genesis),
        "read_bounded returns the valid .prev, never the foreign record"
    );

    // Same contract for a WRONG-FORMAT current (parseable, our genesis, bad format).
    let dir2 = tempfile::tempdir().expect("tempdir");
    write_witness(dir2.path(), &w1).expect("write w1");
    write_witness(dir2.path(), &w2).expect("write w2 -> w1 to .prev");
    let mut wrong_format = w2;
    wrong_format.format = "999".to_owned();
    std::fs::write(
        dir2.path().join(WITNESS_FILE),
        format!("{}\n", wrong_format.to_json()).as_bytes(),
    )
    .expect("plant wrong-format current");
    write_witness(dir2.path(), &w3).expect("write w3 over wrong-format current");
    std::fs::remove_file(dir2.path().join(WITNESS_FILE)).expect("remove current");
    assert_eq!(
        read_witness(dir2.path(), genesis),
        Some(w1),
        "valid .prev survives a wrong-format current"
    );
}
