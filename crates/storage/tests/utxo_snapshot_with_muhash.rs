use bitcoin_rs_consensus::primitives::{Amount, Hash256, OutPoint, TxOut};
use bitcoin_rs_storage::utxo::contract::{BlockChanges, UtxoAdd};
use bitcoin_rs_storage::utxo::stats::{CoinStats, CoinStatsAccumulator};
use bitcoin_rs_storage::utxo::{UtxoSet, write_snapshot_observed};

use crate::support::utxo::TestResult;

const TRAILER_LEN: usize = 384;

#[derive(Clone, Copy)]
enum SecondCommit {
    Overwrite,
    Replace,
    SpendAll,
}

struct Plan {
    name: &'static str,
    shards: u8,
    entries: u32,
    second: SecondCommit,
}

#[test]
fn snapshot_trailer_matches_a_serial_reference() -> TestResult {
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
    let set = UtxoSet::new();
    let mut expected = CoinStats::new();

    let capacity = usize::try_from(plan.entries)?;
    let mut first = BlockChanges::with_capacity(capacity, 0);
    let mut seeded = Vec::with_capacity(capacity);
    for index in 0..plan.entries {
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
    use std::collections::HashMap;
    let mut by_txid: HashMap<Hash256, Vec<bitcoin_rs_storage::utxo::record::OwnedUtxoOut>> =
        HashMap::new();
    for (outpoint, txout) in &live {
        by_txid.entry(outpoint.txid.into()).or_default().push(
            bitcoin_rs_storage::utxo::record::OwnedUtxoOut {
                vout: outpoint.vout,
                value: txout.value.to_sat(),
                script_pubkey: txout.script_pubkey.to_vec(),
                coinbase: false,
                height: 201,
            },
        );
    }
    for (txid, mut outs) in by_txid {
        outs.sort_by_key(|o| o.vout);
        let rec = bitcoin_rs_storage::utxo::record::UtxoRecord::from_owned_outputs(txid, &outs)?;
        set.insert_parsed_record(rec);
    }
    let mut snapshot = Vec::new();
    let (trailer, _) = write_snapshot_observed(
        &set,
        &txid(3_001),
        201,
        &mut snapshot,
        CoinStatsAccumulator::with_parallel_muhash(201),
    )?;
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
    if let Some((outpoint, txout)) = live.first() {
        let mut bumped = txout.clone();
        bumped.value = Amount::from_sat(txout.value.to_sat().saturating_add(1));
        let mut perturbed = expected.clone();
        perturbed.remove_utxo(outpoint, txout, 201, false);
        perturbed.insert_utxo(outpoint, &bumped, 201, false);
        assert_ne!(
            trailer,
            perturbed.muhash.finalize(),
            "{}: perturbed trailer must differ",
            plan.name
        );
    }
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
    Ok(())
}

fn txout(index: u32) -> TxOut {
    TxOut {
        value: Amount::from_sat(50_000 + u64::from(index)),
        script_pubkey: vec![0x51, index.to_le_bytes()[0]].into(),
    }
}

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
