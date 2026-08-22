//! Pareto-front fee priority ordering coverage.

extern crate alloc;

use alloc::sync::Arc;
use std::error::Error;

use bitcoin::hashes::Hash as _;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use bitcoin_rs_mempool::{MempoolEntry, ParetoFront, SortedParetoFront};

#[test]
fn top_n_returns_highest_rate_entries() -> Result<(), Box<dyn Error>> {
    let mut front = ParetoFront::new();
    let mut expected = Vec::with_capacity(100);

    for i in 0_u32..100 {
        let fee = u64::from(i + 1) * 1_000;
        let entry = MempoolEntry::new(Arc::new(tx(u8::try_from(i)?)), 100, fee, u64::from(i), 1);
        front.insert(i, &entry);
        expected.push((i, entry.fee_rate));
    }

    expected.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    let actual: Vec<u32> = front.top_n(10).collect();
    let want: Vec<u32> = expected.into_iter().take(10).map(|(id, _)| id).collect();

    assert_eq!(actual, want);

    Ok(())
}

/// An entry whose priority fields are a function of `seed`, so a sequence of
/// them exercises every tiebreak the ordering has.
///
/// Fee is deliberately not monotonic in the seed — a multiplicative hash spreads
/// it — because an index that happened to receive its entries in priority order
/// would look correct while ordering nothing. Ages collide every fourth entry so
/// the `time` tiebreak is reached, and one fee value repeats often enough that
/// the `id` tiebreak is reached too.
fn seeded_entry(seed: u32) -> MempoolEntry {
    let fee = u64::from(seed.wrapping_mul(2_654_435_761) % 50) * 100 + 100;
    let time = u64::from(seed % 4);
    MempoolEntry::new(
        Arc::new(tx(u8::try_from(seed % 251).unwrap_or(0))),
        100,
        fee,
        time,
        1,
    )
}

/// The replacement must order identically to the implementation it replaced.
///
/// Compared over the *whole* index rather than a prefix: a `top_n(10)` check
/// passes while everything below the tenth entry is misordered, and the miner
/// reads the whole index (`mining::policy` calls `top_n(len())`).
#[test]
fn ordering_matches_the_sorted_front_it_replaced() {
    let mut front = ParetoFront::new();
    let mut oracle = SortedParetoFront::new();

    for seed in 0_u32..400 {
        let entry = seeded_entry(seed);
        front.insert(seed, &entry);
        oracle.insert(seed, &entry);
    }

    assert_eq!(
        front.len(),
        oracle.len(),
        "the indexes hold different counts"
    );
    assert_eq!(
        front.top_n(front.len()).collect::<Vec<_>>(),
        oracle.top_n(oracle.len()).collect::<Vec<_>>(),
        "the replacement must order exactly as the sorted front did"
    );
}

/// The same, driven through a mixed sequence of inserts, replacements and
/// removals rather than a single fill — the shape the mempool actually applies.
#[test]
fn ordering_matches_the_sorted_front_under_inserts_removals_and_replacements() {
    let mut front = ParetoFront::new();
    let mut oracle = SortedParetoFront::new();

    for seed in 0_u32..300 {
        let entry = seeded_entry(seed);
        front.insert(seed, &entry);
        oracle.insert(seed, &entry);

        if seed % 3 == 0 {
            // Re-insert with different priority fields: a replacement, which is
            // what `recompute_all_metadata` does when an ancestor fee changes.
            let replacement = seeded_entry(seed.wrapping_add(1_000));
            front.insert(seed, &replacement);
            oracle.insert(seed, &replacement);
        }
        if seed % 5 == 0 {
            let target = seed / 2;
            assert_eq!(
                front.remove(target),
                oracle.remove(target),
                "removal must agree on whether {target} was indexed"
            );
        }

        assert_eq!(
            front.top_n(front.len()).collect::<Vec<_>>(),
            oracle.top_n(oracle.len()).collect::<Vec<_>>(),
            "diverged after seed {seed}"
        );
    }
}

/// Pins that a replacement leaves one entry indexed, not two.
///
/// The ordered set is keyed by priority, so re-inserting an entry whose
/// ancestor fee rate changed inserts a *different* key. Without evicting the
/// stale one the entry appears twice, and the miner would build a template
/// containing the same transaction twice.
#[test]
fn replacing_an_entry_does_not_leave_the_stale_key_behind() {
    let mut front = ParetoFront::new();
    let low = MempoolEntry::new(Arc::new(tx(1)), 100, 1_000, 0, 1);
    let high = MempoolEntry::new(Arc::new(tx(1)), 100, 90_000, 0, 1);

    front.insert(7, &low);
    front.insert(7, &high);

    assert_eq!(front.len(), 1, "a replaced entry must be indexed once");
    assert_eq!(front.top_n(4).collect::<Vec<_>>(), vec![7]);
    assert!(front.remove(7), "the surviving key must be removable by id");
    assert!(
        front.is_empty(),
        "removing the only entry must empty the index"
    );
}

/// Pins that entries sharing every priority field stay distinct.
///
/// The index is an ordered *set* of keys, so entries whose keys compared equal
/// would collapse into one and a transaction would silently leave the mempool's
/// priority index. Only the tiebreak on entry id prevents that.
#[test]
fn entries_with_identical_priority_fields_are_all_retained() {
    let mut front = ParetoFront::new();
    for id in 0_u32..8 {
        // Same fee, same vsize, same time: every ordering field collides.
        front.insert(id, &MempoolEntry::new(Arc::new(tx(2)), 100, 5_000, 42, 1));
    }

    assert_eq!(front.len(), 8, "identical priorities must not collapse");
    let mut ids = front.top_n(8).collect::<Vec<_>>();
    ids.sort_unstable();
    assert_eq!(ids, (0_u32..8).collect::<Vec<_>>());
}

fn tx(label: u8) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint(label, 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51, label]),
        }],
    }
}

fn outpoint(label: u8, vout: u32) -> OutPoint {
    let mut bytes = [0_u8; 32];
    bytes[0] = label;
    OutPoint::new(Txid::from_byte_array(bytes), vout)
}
