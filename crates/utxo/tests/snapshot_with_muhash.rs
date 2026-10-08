//! Differential integration tests for the coinstats listener and the snapshot
//! trailer: every commit-path shape must leave the listener holding exactly the
//! stats a serial reference computes, and the trailer must be that `MuHash`.
use bitcoin_rs_primitives::{Amount, Hash256, OutPoint, TxOut};
use bitcoin_rs_utxo::contract::{BlockChanges, UtxoAdd, commit_block_changes};
use bitcoin_rs_utxo::stats::{CoinStats, CoinStatsListener};
use bitcoin_rs_utxo::{UtxoSet, write_snapshot_observed};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const TRAILER_LEN: usize = 384;

/// What the second commit does to the outputs the first one created.
#[derive(Clone, Copy)]
enum SecondCommit {
    /// Re-adds every outpoint with a new payload, newest shard first.
    Overwrite,
    /// Spends every outpoint and creates a fresh one in the same shard.
    Replace,
    /// Spends every outpoint and creates nothing.
    SpendAll,
}

struct Plan {
    name: &'static str,
    shards: u8,
    entries: u32,
    second: SecondCommit,
}

/// Every commit-path shape the listener has to survive: one shard, two shards
/// with enough entries to chunk, and twenty shards committed in parallel, each
/// followed by an overwrite, a cross-shard replacement, or a full spend.
#[test]
fn listener_stats_and_snapshot_trailer_match_a_serial_reference() -> TestResult {
    let plans = [
        Plan {
            name: "single shard runs",
            shards: 1,
            entries: 2_048,
            second: SecondCommit::SpendAll,
        },
        Plan {
            name: "two shards chunked",
            shards: 2,
            entries: 2_048,
            second: SecondCommit::Replace,
        },
        Plan {
            name: "twenty shards in parallel",
            shards: 20,
            entries: 20,
            second: SecondCommit::Replace,
        },
        Plan {
            name: "twenty shards coalesced overwrite",
            shards: 20,
            entries: 20,
            second: SecondCommit::Overwrite,
        },
        Plan {
            name: "duplicate txid overwrite",
            shards: 1,
            entries: 1,
            second: SecondCommit::Overwrite,
        },
    ];
    for plan in &plans {
        run(plan)?;
    }
    Ok(())
}

fn run(plan: &Plan) -> TestResult {
    let listener = CoinStatsListener::new(CoinStats::new());
    let mut set = UtxoSet::new();
    set.track_coin_stats(listener.clone());
    let mut expected = CoinStats::new();

    let capacity = usize::try_from(plan.entries)?;
    let mut first = BlockChanges::with_capacity(capacity, 0);
    let mut seeded = Vec::with_capacity(capacity);
    for index in 0..plan.entries {
        // Four outputs per (shard, txid) pair, so each shard's commit carries
        // same-transaction runs rather than one isolated output each.
        let shard = u8::try_from(index % u32::from(plan.shards))?;
        let slot = index / u32::from(plan.shards);
        let outpoint = OutPoint::new(
            txid_in_shard(shard, 3_000 + u64::from(slot / 4)).into(),
            slot % 4,
        );
        let txout = txout(3_000 + index);
        let coinbase = index % 2 == 0;
        assert_eq!(shard_of(&outpoint), shard, "{}: wrong shard", plan.name);
        expected.insert_utxo(&outpoint, &txout, 200, coinbase);
        first.add(UtxoAdd::new(outpoint, txout.clone(), coinbase, 200));
        seeded.push((outpoint, txout, coinbase));
    }
    commit_block_changes(&set, &first, &txid(3_000))?;
    assert_stats_eq(plan.name, &listener.snapshot(), &expected);

    let mut second = BlockChanges::with_capacity(capacity, capacity);
    let mut live = Vec::with_capacity(capacity);
    let mut spent = Vec::with_capacity(capacity);
    for (index, (outpoint, seeded_txout, coinbase)) in seeded.iter().enumerate().rev() {
        let index = u32::try_from(index)?;
        expected.remove_utxo(outpoint, seeded_txout, 200, *coinbase);
        match plan.second {
            SecondCommit::Overwrite => {
                let replacement = txout(6_000 + index);
                expected.insert_utxo(outpoint, &replacement, 201, false);
                second.add(UtxoAdd::new(*outpoint, replacement.clone(), false, 201));
                live.push((*outpoint, replacement));
            }
            SecondCommit::Replace => {
                let shard = shard_of(outpoint);
                let slot = index / u32::from(plan.shards);
                let fresh = OutPoint::new(
                    txid_in_shard(shard, 6_000 + u64::from(slot / 4)).into(),
                    slot % 4,
                );
                let replacement = txout(6_000 + index);
                assert_eq!(shard_of(&fresh), shard, "{}: wrong shard", plan.name);
                expected.insert_utxo(&fresh, &replacement, 201, false);
                second.remove(*outpoint);
                second.add(UtxoAdd::new(fresh, replacement.clone(), false, 201));
                live.push((fresh, replacement));
                spent.push(*outpoint);
            }
            SecondCommit::SpendAll => {
                second.remove(*outpoint);
                spent.push(*outpoint);
            }
        }
    }
    commit_block_changes(&set, &second, &txid(3_001))?;
    assert_stats_eq(plan.name, &listener.snapshot(), &expected);

    for (outpoint, txout) in live {
        assert_eq!(
            set.get(&outpoint),
            Some(txout),
            "{}: lost a coin",
            plan.name
        );
    }
    for outpoint in spent {
        assert_eq!(set.get(&outpoint), None, "{}: kept a spent coin", plan.name);
    }

    let mut snapshot = Vec::new();
    let (trailer, ()) = write_snapshot_observed(&set, &txid(3_001), 201, &mut snapshot, ())?;
    let expected_trailer = expected.muhash.finalize();
    assert_eq!(trailer, expected_trailer, "{}: trailer", plan.name);
    assert_ne!(
        trailer, [0_u8; TRAILER_LEN],
        "{}: identity trailer",
        plan.name
    );
    assert_eq!(
        &snapshot[snapshot.len() - TRAILER_LEN..],
        expected_trailer,
        "{}: trailer bytes",
        plan.name
    );
    Ok(())
}

fn assert_stats_eq(name: &str, left: &CoinStats, right: &CoinStats) {
    assert_eq!(left.height, right.height, "{name}: height");
    assert_eq!(left.total_amount, right.total_amount, "{name}: amount");
    assert_eq!(left.bogo_size, right.bogo_size, "{name}: bogo size");
    assert_eq!(left.tx_count, right.tx_count, "{name}: tx count");
    assert_eq!(left.utxo_count, right.utxo_count, "{name}: utxo count");
    assert_eq!(
        left.muhash.finalize(),
        right.muhash.finalize(),
        "{name}: muhash"
    );
    assert_eq!(
        left.muhash.finalize_hash(),
        right.muhash.finalize_hash(),
        "{name}: muhash digest"
    );
}

fn txout(index: u32) -> TxOut {
    TxOut {
        value: Amount::from_sat(50_000 + u64::from(index)),
        script_pubkey: vec![0x51, index.to_le_bytes()[0]].into(),
    }
}

/// The shard a UTXO key selects: the first little-endian txid byte.
fn shard_of(outpoint: &OutPoint) -> u8 {
    outpoint.txid.0.to_le_bytes()[0]
}

fn txid(index: u32) -> Hash256 {
    let mut bytes = [0_u8; 32];
    bytes[..4].copy_from_slice(&index.to_le_bytes());
    Hash256::from_le_bytes(&bytes)
}

fn txid_in_shard(shard: u8, suffix: u64) -> Hash256 {
    let mut bytes = [0_u8; 32];
    bytes[0] = shard;
    bytes[1..9].copy_from_slice(&suffix.to_le_bytes());
    bytes[9..17].copy_from_slice(&suffix.rotate_left(13).to_le_bytes());
    bytes[17..25].copy_from_slice(&suffix.wrapping_mul(29).to_le_bytes());
    Hash256::from_le_bytes(&bytes)
}
