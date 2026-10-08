//! Shared mining integration fixtures.
#![allow(dead_code)]

use std::error::Error;
use std::sync::Arc;

use bitcoin_rs_mempool::{
    Mempool, MempoolEntry, MempoolLimits, MempoolMiningSnapshot, SnapshotEntry,
};
use bitcoin_rs_mining::CandidateContext;
use bitcoin_rs_primitives::{
    Amount, CompactTarget, Hash256, LockTime, Network, OutPoint, Script, Sequence, Tx, TxIn, TxOut,
    Txid, Witness, encode::consensus_bytes,
};

/// Anyone-can-spend payout script used wherever the payout itself is not under test.
pub(crate) const PAYOUT: &[u8] = &[0x51];

pub(crate) fn p2pkh() -> Vec<u8> {
    [vec![0x76, 0xa9, 0x14], vec![0x11; 20], vec![0x88, 0xac]].concat()
}

/// Generous regtest context: segwit and CSV active, limits far above any fixture.
pub(crate) fn context() -> CandidateContext {
    CandidateContext {
        previous_block_hash: Hash256::from_le_bytes(&[0x11; 32]),
        height: 100,
        version: 0x2000_0000,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        min_time: 1,
        current_time: 2,
        locktime_cutoff: 1,
        network: Network::Regtest,
        csv_active: true,
        segwit_active: true,
        max_weight: 4_000_000,
        max_size: 4_000_000,
        max_sigops: 80_000,
    }
}

/// Mempool that admits every fixture fee rate.
pub(crate) fn zero_fee_pool() -> Mempool {
    Mempool::new(MempoolLimits {
        min_relay_fee_sat_per_kvb: 0,
        ..MempoolLimits::default()
    })
}

pub(crate) fn insert(
    pool: &mut Mempool,
    tx: Tx,
    vsize: u32,
    fee: u64,
    sequence: u64,
    height: u32,
) -> Result<(), Box<dyn Error>> {
    insert_with_cost(pool, tx, vsize, fee, sequence, height, 0)
}

pub(crate) fn insert_with_cost(
    pool: &mut Mempool,
    tx: Tx,
    vsize: u32,
    fee: u64,
    sequence: u64,
    height: u32,
    sigop_cost: u32,
) -> Result<(), Box<dyn Error>> {
    pool.insert_entry(MempoolEntry::new(
        Arc::new(tx),
        vsize,
        fee,
        sequence,
        height,
        sigop_cost,
    ))?;
    Ok(())
}

pub(crate) fn snapshot(sequence: u64, entries: Vec<SnapshotEntry>) -> MempoolMiningSnapshot {
    MempoolMiningSnapshot { sequence, entries }
}

/// Snapshot entry whose weight, size, and vsize are measured from `tx`.
pub(crate) fn measured_entry(
    tx: &Arc<Tx>,
    fee: u64,
    fee_delta: i64,
    ancestors: Vec<u32>,
) -> SnapshotEntry {
    let size = u32::try_from(tx.total_size()).unwrap_or(u32::MAX);
    let vsize = u32::try_from(tx.vsize()).unwrap_or(u32::MAX);
    let mut entry = forged_entry(
        Arc::clone(tx),
        fee,
        fee_delta,
        tx.weight(),
        size,
        0,
        ancestors,
    );
    entry.vsize = vsize;
    entry.bip141_vsize = vsize;
    entry.ancestor_size = u64::from(vsize);
    entry
}

/// Snapshot entry with resource fields chosen by the caller, so limit tests can
/// place a package exactly on a boundary without building a matching wire image.
pub(crate) fn forged_entry(
    tx: Arc<Tx>,
    fee: u64,
    fee_delta: i64,
    weight: u64,
    size: u32,
    sigop_cost: u32,
    ancestors: Vec<u32>,
) -> SnapshotEntry {
    let vsize = size.max(1);
    SnapshotEntry {
        txid: tx.txid(),
        wtxid: tx.wtxid(),
        vsize,
        bip141_vsize: vsize,
        size,
        weight,
        sigop_cost,
        fee,
        fee_delta,
        time: 0,
        height: 0,
        ancestor_size: u64::from(vsize),
        ancestor_fee: fee,
        ancestor_fee_delta: i128::from(fee_delta),
        ancestors,
        tx,
    }
}

/// Single-input, single-output transaction spending `parent` or a label-derived outpoint.
pub(crate) fn tx(label: u8, value: u64, parent: Option<Txid>) -> Tx {
    build_tx(label, value, parent, Witness::new())
}

/// Same shape as [`tx`] with a 32-byte witness item, so wtxid differs from txid.
pub(crate) fn witnessed_tx(label: u8, value: u64, parent: Option<Txid>) -> Tx {
    build_tx(label, value, parent, vec![vec![label; 32]].into())
}

fn build_tx(label: u8, value: u64, parent: Option<Txid>, witness: Witness) -> Tx {
    let mut bytes = [0_u8; 32];
    bytes[0] = label;
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(
                parent.unwrap_or_else(|| Txid(Hash256::from_le_bytes(&bytes))),
                0,
            ),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness,
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: vec![0x51, label].into(),
        }],
        lock_time: LockTime::ZERO,
    }
}

pub(crate) fn oracle_transaction(tx: &Tx) -> Result<bitcoin::Transaction, Box<dyn Error>> {
    Ok(bitcoin::consensus::deserialize(&consensus_bytes(tx))?)
}

/// rust-bitcoin's independent sigop-cost implementation over the same wire image.
pub(crate) fn oracle_sigop_cost(tx: &Tx) -> Result<u64, Box<dyn Error>> {
    Ok(u64::try_from(
        oracle_transaction(tx)?.total_sigop_cost(|_| None),
    )?)
}
