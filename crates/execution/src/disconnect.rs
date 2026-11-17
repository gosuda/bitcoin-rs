//! Disconnect a block: compute the coin delta from its undo record, commit the
//! reversed head and coin mutations in one atomic batch, then publish.

use super::durable::commit_disconnect_head;
use super::tx_count_delta_for;
use super::{Chainstate, DisconnectOutcome, DisconnectPlan};
use crate::chain::{ChainTxCount, TipSnapshot};
use crate::error::ApplyError;
use bitcoin_rs_consensus::primitives::{Block, Hash256, Tx, Txid};
use bitcoin_rs_storage::utxo::contract::{BlockUndoCheck, UndoBatch, load_block_undo_for_block};
use bitcoin_rs_storage::utxo::record::{OwnedUtxoOut, UtxoRecord};
use bitcoin_rs_storage::{CoinKey, WindowDelta};
use hashbrown::HashMap;

pub(super) fn plan_disconnect(
    handles: &Chainstate,
    block: &Block,
    block_hash: Hash256,
) -> core::result::Result<DisconnectPlan, ApplyError> {
    let applied = handles
        .applied_tip
        .load_full()
        .ok_or(ApplyError::DisconnectNotTip {
            hash: block_hash,
            tip: block_hash,
        })?;
    let height = applied.height;
    if applied.hash != block_hash {
        return Err(ApplyError::DisconnectNotTip {
            hash: block_hash,
            tip: applied.hash,
        });
    }

    if let crate::assumeutxo::ChainstateRole::AssumedActive { base_height, .. } = handles.role() {
        if height <= base_height {
            return Err(ApplyError::DisconnectBelowSnapshotBase {
                height,
                base_height,
            });
        }
    }

    let head = handles
        .durable_head
        .load()
        .map_err(ApplyError::DurableHeadCommit)?;
    if head.as_ref().map(|head| head.tip) != Some(block_hash) {
        return Err(ApplyError::DisconnectOffDurableHead {
            hash: block_hash,
            head: head.map(|head| head.tip),
        });
    }

    let txids: Vec<Txid> = block.txs.iter().map(Tx::txid).collect();
    bitcoin_rs_consensus::verify_merkle_root_with_txids(block, &txids)
        .map_err(|_| ApplyError::DisconnectBodyMismatch { hash: block_hash })?;

    let (parent_tip, parent_prev_hash) = {
        let tree = handles.block_tree.read();
        let node = tree.node(applied.tip_id)?;
        let parent_id = node.parent.ok_or(ApplyError::DisconnectNotTip {
            hash: block_hash,
            tip: applied.hash,
        })?;
        let parent = tree.node(parent_id)?;
        let parent_prev_hash = match parent.parent {
            Some(grandparent_id) => tree.node(grandparent_id)?.hash,
            None => Hash256::default(),
        };
        (
            TipSnapshot {
                tip_id: parent_id,
                height: parent.height,
                chainwork: parent.chainwork,
                hash: parent.hash,
                chain_tx_count: ChainTxCount::UNKNOWN,
            },
            parent_prev_hash,
        )
    };

    let undo = load_block_undo_for_block(
        handles.undo_store.as_ref(),
        height,
        block_hash,
        &BlockUndoCheck {
            block,
            txids: &txids,
            max_script_size: bitcoin_rs_consensus::MAX_SCRIPT_SIZE,
        },
    )?;

    let tx_count_delta = tx_count_delta_for(block);
    handles
        .coin_stats
        .check_rewind(height, tx_count_delta)
        .map_err(ApplyError::CoinStatsRewind)?;
    let rewound = applied.chain_tx_count.rewind(tx_count_delta);
    if applied.chain_tx_count.get().is_some() && rewound.get().is_none() {
        tracing::warn!(
            height,
            hash = %block.block_hash().0,
            "cumulative chain transaction count rewound below zero; marking it unknown"
        );
    }
    let parent_tip = TipSnapshot {
        chain_tx_count: rewound,
        ..parent_tip
    };

    Ok(DisconnectPlan {
        parent_tip,
        parent_prev_hash,
        undo,
        height,
        tx_count_delta,
    })
}

pub(super) fn disconnect_block_admitted(
    handles: &Chainstate,
    block: &Block,
) -> core::result::Result<DisconnectOutcome, crate::DisconnectError> {
    let block_hash = block.block_hash().0;
    let DisconnectPlan {
        parent_tip,
        parent_prev_hash: _,
        undo,
        height,
        tx_count_delta,
    } = plan_disconnect(handles, block, block_hash)
        .map_err(|error| crate::DisconnectError::Refused(Box::new(error)))?;

    let poison = |error| {
        handles.admission.close_permanently();
        error
    };
    let fatal = |source: ApplyError| {
        poison(crate::DisconnectError::Fatal {
            hash: block_hash,
            height,
            source: Box::new(source),
        })
    };

    handles
        .undo_store
        .arm_disconnect(height, block_hash)
        .map_err(|source| {
            crate::DisconnectError::Refused(Box::new(ApplyError::UndoPersistence(source)))
        })?;
    let coin_delta = build_disconnect_delta(&handles.coins, &undo)
        .map_err(|e| fatal(ApplyError::CoinStoreRead(e)))?;

    handles
        .coin_stats
        .check_rewind(height, tx_count_delta)
        .map_err(|source| fatal(ApplyError::CoinStatsRewind(source)))?;
    handles
        .coin_stats
        .rewind_block(height, parent_tip.height, tx_count_delta)
        .map_err(|source| fatal(ApplyError::CoinStatsRewind(source)))?;

    let receipt = commit_disconnect_head(
        handles,
        &parent_tip,
        block_hash,
        parent_tip.chain_tx_count.to_wire(),
        coin_delta,
    )
    .map_err(fatal)?;
    let parent_tip = receipt.certify(parent_tip);
    handles
        .block_tree
        .write()
        .restore_chain_tx_count(parent_tip.tip_id, parent_tip.chain_tx_count)
        .map_err(|error| fatal(ApplyError::Chain(error)))?;
    handles.publish_applied(&parent_tip, crate::events::HintKind::Disconnected);

    handles
        .undo_store
        .complete_disconnect(height, block_hash)
        .map_err(|source| fatal(ApplyError::UndoPersistence(source)))?;
    handles.undo_store.disarm_disconnect().map_err(|error| {
        poison(crate::DisconnectError::MarkerStuck {
            hash: block_hash,
            height,
            source: Box::new(ApplyError::UndoPersistence(error)),
        })
    })?;

    Ok(DisconnectOutcome {
        hash: block_hash,
        restored_parents: undo
            .restores()
            .iter()
            .map(|restored| restored.outpoint.txid)
            .collect(),
    })
}

/// Builds a [`WindowDelta`] that reverses one block's coin effects using the
/// undo record and the current engine state.
pub(crate) fn build_disconnect_delta(
    coins: &bitcoin_rs_storage::CoinStore,
    undo: &UndoBatch,
) -> Result<WindowDelta, bitcoin_rs_storage::StorageError> {
    let mut affected: HashMap<Txid, (Vec<OwnedUtxoOut>, Vec<u32>)> = HashMap::new();
    for restore in undo.restores() {
        let txid = restore.outpoint.txid;
        let entry = affected.entry(txid).or_default();
        entry.0.push(OwnedUtxoOut::new(
            restore.outpoint.vout,
            restore.txout.value.to_sat(),
            restore.txout.script_pubkey.to_vec(),
            restore.coinbase,
            restore.height,
        ));
    }
    for remove in undo.removes() {
        let txid = remove.txid;
        let entry = affected.entry(txid).or_default();
        entry.1.push(remove.vout);
    }

    let txids: Vec<Txid> = affected.keys().copied().collect();
    let coin_keys: Vec<CoinKey> = txids
        .iter()
        .map(|txid| CoinKey(txid.0.to_le_bytes()))
        .collect();
    let current_records = coins.multi_get(&coin_keys)?;

    let mut delta = WindowDelta::default();
    for (i, txid) in txids.iter().enumerate() {
        let (to_restore, to_remove) = &affected[txid];
        let mut outputs: Vec<OwnedUtxoOut> = match &current_records[i] {
            Some(bytes) => {
                let record =
                    UtxoRecord::from_encoded(bytes.to_vec().into_boxed_slice()).map_err(|e| {
                        bitcoin_rs_storage::StorageError::IncompatibleData(format!(
                            "corrupt coin record for txid {}: {e}",
                            txid.0.to_string_be()
                        ))
                    })?;
                record
                    .outputs()
                    .map(|out| {
                        OwnedUtxoOut::new(
                            out.vout,
                            out.value,
                            out.script_pubkey.to_vec(),
                            out.coinbase,
                            out.height,
                        )
                    })
                    .collect()
            }
            None => Vec::new(),
        };

        for vout in to_remove {
            outputs.retain(|o| o.vout != *vout);
        }

        for restored in to_restore {
            if !outputs.iter().any(|o| o.vout == restored.vout) {
                outputs.push(restored.clone());
            }
        }

        let key = CoinKey(txid.0.to_le_bytes());
        if outputs.is_empty() {
            delta.push_final(key, None);
        } else {
            let record = UtxoRecord::from_owned_outputs(
                Hash256::from_le_bytes(&txid.0.to_le_bytes()),
                &outputs,
            )
            .map_err(|e| {
                bitcoin_rs_storage::StorageError::IncompatibleData(format!(
                    "failed to rebuild coin record for txid {}: {e}",
                    txid.0.to_string_be()
                ))
            })?;
            delta.push_final(key, Some(bytes::Bytes::copy_from_slice(record.bytes())));
        }
    }
    delta.records.sort_by_key(|(key, _)| *key);
    Ok(delta)
}
