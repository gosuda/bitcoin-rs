use std::path::Path;

use bitcoin::consensus::encode::serialize;
use bitcoin_rs_consensus::primitives::{Block as PrimitiveBlock, OutPoint, deserialize};
use bitcoin_rs_storage::utxo::contract::{BlockChanges, UtxoAdd, populate_block_changes};
use bitcoin_rs_storage::utxo::stats::{CoinStats, CoinStatsListener, scan_coin_stats};
use bitcoin_rs_storage::utxo::{UtxoError, UtxoSet, write_snapshot_observed};

use crate::chain::Chain;
use crate::convert;
use crate::error::Error;

#[derive(Clone, Debug)]
pub struct ReconstructReport {
    pub stats: CoinStats,
    pub muhash: bitcoin_rs_consensus::primitives::Hash256,
    pub blocks: u32,
    pub coins: u64,
    pub tx_count: u64,
    pub prevout_reads: u64,
    pub coins_written: u64,
    pub undo_entries: u64,
    pub body_bytes: u64,
    pub accounted_bytes: u64,
    pub snapshot_bytes: Option<u64>,
}

pub fn reconstruct(chain: &Chain, snapshot: Option<&Path>) -> Result<ReconstructReport, Error> {
    let store = std::sync::Arc::new(bitcoin_rs_storage::MemoryKvStore::new());
    let coin_store = bitcoin_rs_storage::CoinStore::open(store.clone(), 64 * 1024 * 1024);
    let mut listener = CoinStats::new();
    let mut counters = Counters::default();
    for carried in &chain.blocks {
        replay_block(&coin_store, carried, &mut counters, &mut listener)?;
    }
    let mut set = UtxoSet::new();
    let coin_stats_listener = CoinStatsListener::new(listener);
    set.track_coin_stats(coin_stats_listener.clone());
    use bitcoin_rs_storage::KvStore;
    for pair in store
        .iter_prefix(bitcoin_rs_storage::ColumnFamily::Coins, &[])
        .map_err(|e| Error::from(UtxoError::Storage(e)))?
    {
        let (_key, val) = pair.map_err(|e| Error::from(UtxoError::Storage(e)))?;
        let record = bitcoin_rs_storage::utxo::record::UtxoRecord::from_encoded(
            val.to_vec().into_boxed_slice(),
        )
        .map_err(Error::from)?;
        set.insert_parsed_record(record);
    }
    let height = chain.height();
    let (stats, accounted_bytes) = set
        .with_stable_view(|view| {
            let accounted =
                u64::try_from(view.memory_report().accounted_bytes()).unwrap_or(u64::MAX);
            let stats = scan_coin_stats(view, height, true)?;
            Ok::<_, UtxoError>((stats, accounted))
        })
        .map_err(Error::from)?;
    let listener_muhash = coin_stats_listener.snapshot().muhash.finalize_hash();
    let scan_muhash = stats.muhash.finalize_hash();
    if listener_muhash != scan_muhash {
        return Err(Error::StatsDivergence {
            listener: listener_muhash.to_string_be(),
            scan: scan_muhash.to_string_be(),
        });
    }
    let snapshot_bytes = match snapshot {
        Some(path) => Some(export_snapshot(&set, chain, height, path)?),
        None => None,
    };
    Ok(ReconstructReport {
        muhash: scan_muhash,
        stats,
        blocks: chain.height().saturating_add(1),
        coins: u64::try_from(set.len()).unwrap_or(u64::MAX),
        tx_count: counters.tx_count,
        prevout_reads: counters.prevout_reads,
        coins_written: counters.coins_written,
        undo_entries: counters.undo_entries,
        body_bytes: counters.body_bytes,
        accounted_bytes,
        snapshot_bytes,
    })
}

fn replay_block(
    coin_store: &bitcoin_rs_storage::CoinStore,
    carried: &crate::chain::ChainBlock,
    counters: &mut Counters,
    listener: &mut CoinStats,
) -> Result<(), Error> {
    let wire = serialize(&carried.block);
    counters.body_bytes = counters
        .body_bytes
        .saturating_add(u64::try_from(wire.len()).unwrap_or(u64::MAX));
    let decoded: PrimitiveBlock = deserialize(&wire).map_err(|source| Error::Decode {
        height: carried.height,
        source,
    })?;
    let txids = decoded.txids();
    check_txids(&txids, carried)?;
    let tx_count = u64::try_from(decoded.txs.len()).unwrap_or(u64::MAX);
    counters.tx_count = counters.tx_count.saturating_add(tx_count);
    if carried.height == 0 {
        return Ok(());
    }
    let mut changes: BlockChanges = BlockChanges::with_capacity(
        usize::try_from(counted_outputs(carried)).unwrap_or(0),
        carried.undo.len(),
    );
    let mut ctx = ReplayContext {
        carried,
        counters,
        listener,
    };
    for (tx, txid) in decoded.txs.iter().zip(&txids) {
        let coinbase = tx.is_coinbase();
        collect_created(&mut changes, &mut ctx, tx, *txid, coinbase)?;
        if coinbase {
            continue;
        }
        collect_spent(coin_store, &mut changes, tx, &mut ctx)?;
    }
    for add in changes.adds() {
        ctx.listener
            .insert_utxo(&add.outpoint, &add.txout, add.height, add.coinbase);
    }
    populate_block_changes(coin_store, &changes).map_err(Error::from)?;
    ctx.listener.finish_block(carried.height, tx_count);
    Ok(())
}

struct ReplayContext<'a> {
    carried: &'a crate::chain::ChainBlock,
    counters: &'a mut Counters,
    listener: &'a mut CoinStats,
}

fn collect_created(
    changes: &mut BlockChanges,
    ctx: &mut ReplayContext<'_>,
    tx: &bitcoin_rs_consensus::primitives::Tx,
    txid: bitcoin_rs_consensus::primitives::Txid,
    coinbase: bool,
) -> Result<(), Error> {
    for (index, txout) in tx.outputs.iter().enumerate() {
        let Ok(vout) = u32::try_from(index) else {
            return Err(Error::InvalidBlock {
                height: ctx.carried.height,
                check: "output index",
            });
        };
        changes.add(UtxoAdd::new(
            OutPoint::new(txid, vout),
            txout.clone(),
            coinbase,
            ctx.carried.height,
        ));
        ctx.counters.coins_written = ctx.counters.coins_written.saturating_add(1);
    }
    Ok(())
}

fn collect_spent(
    coin_store: &bitcoin_rs_storage::CoinStore,
    changes: &mut BlockChanges,
    tx: &bitcoin_rs_consensus::primitives::Tx,
    ctx: &mut ReplayContext<'_>,
) -> Result<(), Error> {
    for input in &tx.inputs {
        let key = bitcoin_rs_storage::CoinKey(input.previous_output.txid.0.to_le_bytes());
        let coin = coin_store
            .get(&key)
            .map_err(|e| Error::from(UtxoError::Storage(e)))?
            .and_then(|bytes| {
                bitcoin_rs_storage::utxo::record::UtxoRecord::from_encoded(
                    bytes.to_vec().into_boxed_slice(),
                )
                .ok()
            })
            .and_then(|rec| {
                rec.find_output(input.previous_output.vout).map(|out| {
                    (
                        bitcoin_rs_consensus::primitives::TxOut {
                            value: bitcoin_rs_consensus::primitives::Amount::from_sat(out.value),
                            script_pubkey: out.script_pubkey.to_vec().into(),
                        },
                        out.height,
                        out.coinbase,
                    )
                })
            });
        let Some((txout, height, coinbase)) = coin else {
            let previous = input.previous_output;
            let txid = previous.txid;
            let vout = previous.vout;
            return Err(Error::UnknownPrevout {
                height: ctx.carried.height,
                outpoint: format!("{txid}:{vout}"),
            });
        };
        ctx.listener
            .remove_utxo(&input.previous_output, &txout, height, coinbase);
        ctx.counters.prevout_reads = ctx.counters.prevout_reads.saturating_add(1);
        ctx.counters.undo_entries = ctx.counters.undo_entries.saturating_add(1);
        changes.remove(input.previous_output);
    }
    Ok(())
}

fn export_snapshot(set: &UtxoSet, chain: &Chain, height: u32, path: &Path) -> Result<u64, Error> {
    let mut file = std::fs::File::create(path).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let (_muhash_trailer, ()) = write_snapshot_observed(
        set,
        &convert::block_hash(chain.tip()),
        height,
        &mut file,
        (),
    )?;
    let metadata = file.metadata().map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(metadata.len())
}

#[derive(Default)]
struct Counters {
    tx_count: u64,
    prevout_reads: u64,
    coins_written: u64,
    undo_entries: u64,
    body_bytes: u64,
}

fn counted_outputs(carried: &crate::chain::ChainBlock) -> u64 {
    carried
        .block
        .txdata
        .iter()
        .map(|tx| u64::try_from(tx.output.len()).unwrap_or(u64::MAX))
        .sum()
}

fn check_txids(
    txids: &[bitcoin_rs_consensus::primitives::Txid],
    carried: &crate::chain::ChainBlock,
) -> Result<(), Error> {
    if txids.len() != carried.block.txdata.len() {
        return Err(Error::TxidCount {
            height: carried.height,
            mine: txids.len(),
            wire: carried.block.txdata.len(),
        });
    }
    for (mine, tx) in txids.iter().zip(&carried.block.txdata) {
        let wire = convert::txid(tx.compute_txid());
        if *mine != wire {
            return Err(Error::TxidMismatch {
                height: carried.height,
                mine: mine.to_string(),
                wire: wire.to_string(),
            });
        }
    }
    Ok(())
}
