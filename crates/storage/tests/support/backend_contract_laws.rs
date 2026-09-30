//! Semantic laws every supported backend must pass for the atomic durable
//! batch contract (issue #630): a reader sees one committed version
//! throughout a query while commits land in the middle of that query, and
//! failed versus uncertain writes have explicit, distinguishable outcomes.
//!
//! The limits of the fault model used here — what a green run does and does
//! not prove about filesystems and hardware — are documented in
//! `tests/backend_equivalence.rs` and `README.md`; keep the three in step.

use bitcoin_rs_storage::{
    ColumnFamily, KvSnapshot, KvStore, PersistFault, PrefixScanLimit, StorageError, WriteCondition,
};
use std::sync::{Arc, Barrier};

/// Commits interleaved inside the held query. Every commit lands between two
/// reads of the same query, so a reader that observed a newer version
/// mid-query would be detected on every round.
const ROUNDS: u32 = 32;

/// Bounded scan limit for the query's prefix read.
const QUERY_SCAN: PrefixScanLimit = PrefixScanLimit {
    max_rows: 64,
    max_bytes: usize::MAX,
};

/// The version tag one commit writes to every key of the query.
fn version_tag(round: u32) -> Vec<u8> {
    let mut tag = b"version-".to_vec();
    tag.extend_from_slice(&round.to_le_bytes());
    tag
}

/// One query's shape: the family, its keys, and the prefix covering them.
#[derive(Copy, Clone)]
struct Query<'a> {
    cf: ColumnFamily,
    keys: &'a [&'a [u8]],
    prefix: &'a [u8],
}

/// A reader sees one committed version throughout a query (#630).
///
/// PRE: `keys` holds at least two strictly ascending keys in `cf`, all under
/// `prefix`, and no other row in `cf` shares `prefix`. The function seeds
/// every key to version 0 with one durable multi-key batch, then holds one
/// snapshot open as one query while a writer thread commits one multi-key
/// batch per round. Each round's commit lands between two halves of the
/// query — after its first read and before the rest — so the query spans
/// concurrent commits rather than running between them.
///
/// POST: every read of the held query (`get`, `get_many_sorted`, and a
/// bounded `scan_prefix_bounded` over the query's prefix) observed version 0
/// on every key across all rounds, before and after each interleaved commit,
/// and a fresh snapshot taken after each commit observed exactly that
/// round's version on every key — one committed version per query, never a
/// mix of two commits.
pub(crate) fn run_reader_sees_one_committed_version<S: KvStore>(
    store: &S,
    cf: ColumnFamily,
    keys: &[&[u8]],
    prefix: &[u8],
) -> Result<(), StorageError> {
    assert!(keys.len() > 1, "the query needs at least two keys");
    assert!(
        keys.windows(2).all(|pair| pair[0] < pair[1]),
        "get_many_sorted needs strictly ascending keys"
    );
    let query = Query { cf, keys, prefix };

    let mut seed = store.new_batch();
    for key in keys {
        seed.put(cf, key, &version_tag(0));
    }
    store.write_durable(seed)?;

    let reader_ready = Arc::new(Barrier::new(2));
    let before_commit = Arc::new(Barrier::new(2));
    let after_commit = Arc::new(Barrier::new(2));

    let (read_failures, write_report) = std::thread::scope(|scope| {
        let reader = {
            let reader_ready = Arc::clone(&reader_ready);
            let before_commit = Arc::clone(&before_commit);
            let after_commit = Arc::clone(&after_commit);
            scope.spawn(move || {
                read_one_committed_version(
                    store,
                    &query,
                    &reader_ready,
                    &before_commit,
                    &after_commit,
                )
            })
        };
        let writer = {
            let reader_ready = Arc::clone(&reader_ready);
            let before_commit = Arc::clone(&before_commit);
            let after_commit = Arc::clone(&after_commit);
            scope.spawn(move || {
                write_versions(store, &query, &reader_ready, &before_commit, &after_commit)
            })
        };
        (join_scoped(reader), join_scoped(writer))
    });

    write_report?;
    assert!(
        read_failures.is_empty(),
        "the reader observed a mixed or stale committed version: {read_failures:?}"
    );
    Ok(())
}

/// Failed and uncertain durable writes have explicit outcomes (#630).
///
/// PRE: `key` and `other` are distinct keys of `cf` the backend serves.
///
/// POST: an apply-boundary fault (`FailApply`, `PartialApply`) returns `Err`
/// with the pre-batch state untouched — the only outcomes that prove
/// non-application. A failed or lost durability completion (`FailSync`,
/// `LostSync`) returns `Err` with the whole atomic batch already visible, on
/// `write_durable` and on `write_durable_if` alike: `Err` is not a rollback
/// receipt and not `Ok(false)`, so a caller that blindly retried the same
/// guarded mutation would see `Ok(false)` from its own already-applied batch
/// and could not tell that apart from a competitor's pre-image. The caller
/// must reconcile the outcome instead of retrying.
pub(crate) fn run_uncertain_commit_outcome_laws<S: KvStore>(
    store: &S,
    cf: ColumnFamily,
    key: &[u8],
    other: &[u8],
) -> Result<(), StorageError> {
    let mut seed = store.new_batch();
    seed.put(cf, key, b"v1");
    seed.put(cf, other, b"o1");
    store.write_durable(seed)?;

    // Failed applies are the outcomes that prove non-application: the error
    // precedes the batch (or aborts its uncommitted prefix), so the pre-batch
    // state must stand untouched on both keys.
    for fault in [PersistFault::FailApply, PersistFault::PartialApply] {
        store.arm_persist_fault(fault);
        let mut batch = store.new_batch();
        batch.put(cf, key, b"v2");
        batch.put(cf, other, b"o2");
        assert!(
            store.write_durable(batch).is_err(),
            "{fault:?} must surface as Err on write_durable"
        );
        assert_eq!(
            store.get(cf, key)?,
            Some(b"v1".to_vec()),
            "{fault:?} must not apply any batch row"
        );
        assert_eq!(
            store.get(cf, other)?,
            Some(b"o1".to_vec()),
            "{fault:?} must not apply any batch row"
        );
    }

    // A failed durability completion is not a rollback receipt: the atomic
    // batch became visible before the completion failed.
    store.arm_persist_fault(PersistFault::FailSync);
    let mut batch = store.new_batch();
    batch.put(cf, key, b"v2");
    batch.put(cf, other, b"o2");
    assert!(
        store.write_durable(batch).is_err(),
        "FailSync must surface as Err on write_durable"
    );
    assert_eq!(
        store.get(cf, key)?,
        Some(b"v2".to_vec()),
        "Err from a durability API must not be read as non-application"
    );
    assert_eq!(
        store.get(cf, other)?,
        Some(b"o2".to_vec()),
        "the atomic batch applied as a whole before the completion failed"
    );

    // The same uncertainty on the guarded mutation: the result is `Err`, not
    // `Ok(false)`, and the claim landed. A blind retry of the same claim then
    // reports `Ok(false)` — the retry cannot distinguish its own applied
    // mutation from a competitor's pre-image, so it is not a recovery. The
    // state owner must reconcile the outcome instead.
    store.arm_persist_fault(PersistFault::LostSync);
    let mut claim = store.new_batch();
    claim.put(cf, key, b"v3");
    assert!(
        store
            .write_durable_if(
                &[WriteCondition::Equals {
                    cf,
                    key,
                    expected: b"v2"
                }],
                claim
            )
            .is_err(),
        "an uncertain guarded commit must not report Ok(true) or Ok(false)"
    );
    assert_eq!(
        store.get(cf, key)?,
        Some(b"v3".to_vec()),
        "the guarded batch applied before its durability completion was lost"
    );
    let mut retry = store.new_batch();
    retry.put(cf, key, b"v3");
    let retried = store.write_durable_if(
        &[WriteCondition::Equals {
            cf,
            key,
            expected: b"v2",
        }],
        retry,
    )?;
    assert!(
        !retried,
        "a blind retry of an uncertain mutation must not be mistaken for a recovery"
    );
    assert_eq!(store.get(cf, key)?, Some(b"v3".to_vec()));
    Ok(())
}

/// One reader thread: takes the held snapshot, then runs one query per round
/// against it while the writer commits in the middle of each round's query.
/// Never returns early and never panics — a stranded barrier would deadlock
/// the scope instead of failing the test — so every observation failure is
/// collected and asserted by the caller after both threads joined.
fn read_one_committed_version<S: KvStore>(
    store: &S,
    query: &Query<'_>,
    reader_ready: &Barrier,
    before_commit: &Barrier,
    after_commit: &Barrier,
) -> Vec<String> {
    let Query { cf, keys, .. } = *query;
    let mut failures = Vec::new();
    let held = match store.snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => {
            failures.push(format!("held snapshot failed: {error}"));
            reader_ready.wait();
            for _ in 0..ROUNDS {
                before_commit.wait();
                after_commit.wait();
            }
            return failures;
        }
    };
    reader_ready.wait();
    for round in 1..=ROUNDS {
        // First half of the query: the head key is read before the round's
        // commit lands.
        match held.get(cf, keys[0]) {
            Ok(value) if value.as_deref() == Some(version_tag(0).as_slice()) => {}
            Ok(value) => failures.push(format!(
                "round {round} held: head key read before the commit as {value:?}"
            )),
            Err(error) => failures.push(format!("round {round} held: head key error {error}")),
        }
        // The writer's commit for this round lands between the two halves of
        // this query.
        before_commit.wait();
        after_commit.wait();
        // Second half of the query: every read must still observe version 0,
        // not the commit that just landed mid-query.
        check_query(&*held, query, &version_tag(0), round, "held", &mut failures);
        // A fresh snapshot taken after the commit sees exactly that round's
        // version — complete, not a mix with the previous one.
        match store.snapshot() {
            Ok(fresh) => check_query(
                &*fresh,
                query,
                &version_tag(round),
                round,
                "fresh",
                &mut failures,
            ),
            Err(error) => failures.push(format!("round {round}: fresh snapshot failed: {error}")),
        }
    }
    failures
}

/// One writer thread: one multi-key batch per round. Never returns early —
/// the barrier peer must not be stranded mid-query — so the first error is
/// reported after the dance completes.
fn write_versions<S: KvStore>(
    store: &S,
    query: &Query<'_>,
    reader_ready: &Barrier,
    before_commit: &Barrier,
    after_commit: &Barrier,
) -> Result<(), StorageError> {
    let Query { cf, keys, .. } = *query;
    reader_ready.wait();
    let mut first_error = None;
    for round in 1..=ROUNDS {
        before_commit.wait();
        let mut batch = store.new_batch();
        for key in keys {
            batch.put(cf, key, &version_tag(round));
        }
        if let Err(error) = store.write(batch) {
            if first_error.is_none() {
                first_error = Some(error);
            }
        }
        after_commit.wait();
    }
    first_error.map_or(Ok(()), Err)
}

/// Reads one query — point gets, a sorted multi-get, and a bounded prefix
/// scan — through `snapshot` and records every observation that differs from
/// `expected`.
fn check_query(
    snapshot: &dyn KvSnapshot,
    query: &Query<'_>,
    expected: &[u8],
    round: u32,
    view: &str,
    failures: &mut Vec<String>,
) {
    let Query { cf, keys, prefix } = *query;
    for key in keys {
        match snapshot.get(cf, key) {
            Ok(value) if value.as_deref() == Some(expected) => {}
            Ok(value) => failures.push(format!(
                "round {round} {view}: key {key:?} read {value:?}, expected {expected:?}"
            )),
            Err(error) => failures.push(format!("round {round} {view}: key {key:?} error {error}")),
        }
    }
    match snapshot.get_many_sorted(cf, keys) {
        Ok(values) => {
            if values.len() != keys.len() {
                failures.push(format!(
                    "round {round} {view}: multi-get returned {} values for {} keys",
                    values.len(),
                    keys.len()
                ));
            }
            for (key, value) in keys.iter().zip(values.iter()) {
                if value.as_deref() != Some(expected) {
                    failures.push(format!(
                        "round {round} {view}: multi-get key {key:?} read {value:?}, expected {expected:?}"
                    ));
                }
            }
        }
        Err(error) => failures.push(format!("round {round} {view}: multi-get error {error}")),
    }
    match snapshot.scan_prefix_bounded(cf, prefix, QUERY_SCAN) {
        Ok(scan) => {
            for key in keys {
                match scan.rows.iter().find(|(found, _)| found.as_slice() == *key) {
                    Some((_, value)) if value.as_slice() == expected => {}
                    Some((_, value)) => failures.push(format!(
                        "round {round} {view}: scan key {key:?} read {value:?}, expected {expected:?}"
                    )),
                    None => failures.push(format!("round {round} {view}: scan missed key {key:?}")),
                }
            }
        }
        Err(error) => failures.push(format!("round {round} {view}: scan error {error}")),
    }
}

/// Joins a scoped thread, resuming any panic on the caller.
fn join_scoped<T>(handle: std::thread::ScopedJoinHandle<'_, T>) -> T {
    match handle.join() {
        Ok(value) => value,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}
