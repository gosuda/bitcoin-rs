//! UTXO connect accounting for one block.
//!
//! The node crate coordinates *when* to connect a block and *what* resolved
//! prevouts to pass; this module owns the mechanics of walking the block's
//! transactions to produce the [`BorrowedBlockChanges`], [`UndoBatch`], and
//! [`BlockValueTotals`] that the [`UtxoSet`] consumes.

use bitcoin_rs_primitives::{Block, OutPoint, Tx, Txid};
use hashbrown::HashSet;

use crate::set::{BorrowedBlockChanges, BorrowedUtxoAdd, UndoBatch};
use crate::{UtxoAdd, UtxoSet, shard::LiveOutput};

/// Returns true when `tx` is a coinbase: one input with the null outpoint.
pub fn is_coinbase_tx(tx: &Tx) -> bool {
    tx.inputs.len() == 1
        && tx.inputs[0].previous_output.txid == Txid::default()
        && tx.inputs[0].previous_output.vout == u32::MAX
}

/// What a block pays its coinbase and what it earned in fees.
///
/// Gathered by [`build_block_changes`] because that walk already visits exactly
/// the right two sets. Outputs created and spent inside the same block are
/// skipped there, and they cancel in the fee sum — a same-block output is one
/// transaction's output and another's input — so leaving both out is exact,
/// not an approximation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlockValueTotals {
    /// Total value the coinbase outputs claim.
    pub coinbase_out: u64,
    /// Input value of the block's non-coinbase transactions, same-block
    /// spends excluded.
    pub spent_in: u64,
    /// Output value of the block's non-coinbase transactions, outputs spent
    /// in the same block excluded.
    pub created_out: u64,
}

impl BlockValueTotals {
    /// Fees the block earned, or `None` if the totals are inconsistent.
    ///
    /// Returns `None` rather than saturating: outputs exceeding inputs is a
    /// consensus failure that per-transaction verification should already have
    /// rejected, and silently reporting zero fees would let it through here.
    pub const fn fees(self) -> Option<u64> {
        self.spent_in.checked_sub(self.created_out)
    }
}

/// Errors produced while building UTXO connect changes for one block.
#[derive(Debug, thiserror::Error)]
pub enum BlockChangeError {
    /// Summing a block's input or output values left the satoshi range.
    #[error("block value total overflows the satoshi range")]
    BlockValueOverflow,
    /// Height or vout arithmetic overflowed `u32::MAX`.
    #[error("height overflow at tip {0}")]
    HeightOverflow(u32),
    /// A spent output had no resolved prevout, so the undo record would be
    /// unable to restore it.
    #[error("undo record cannot restore spent output {txid}:{vout}")]
    UndoPrevoutMissing {
        /// Transaction id of the unresolvable spend.
        txid: Txid,
        /// Output index of the unresolvable spend.
        vout: u32,
    },
}

/// Lookup for the full resolved entry of a spent output, including creation
/// metadata.
///
/// Implemented by the node crate's `ResolvedUtxoView`, which resolves a
/// block's external prevouts from the committed set (or a window overlay).
pub trait SpentOutputLookup {
    /// Full resolved entry for a spent outpoint, or `None` if it is not live.
    fn entry(&self, outpoint: &OutPoint) -> Option<&LiveOutput>;
}

/// Builds the UTXO mutation, undo batch, and value totals for one connected
/// block.
///
/// # Parameters
///
/// - `block`: the block being connected.
/// - `height`: the height at which it connects.
/// - `txids`: precomputed txids for the block's transactions, in order.
/// - `same_block_spent`: outpoints spent within the same block (netted out),
///   or `None` when no same-block detection ran.
/// - `add_capacity` / `remove_capacity`: pre-reserved capacities for the
///   change sets.
/// - `resolved`: lookup for the full entries of outputs the block spends.
/// - `overwritten`: the committed set, passed only at BIP30 exception heights
///   where a coinbase reuses a still-live txid.
/// - `max_script_size`: consensus limit; outputs whose script exceeds this are
///   not added to the UTXO set.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
pub fn build_block_changes<'a>(
    block: &'a Block,
    height: u32,
    txids: &[Txid],
    same_block_spent: Option<&HashSet<OutPoint>>,
    add_capacity: usize,
    remove_capacity: usize,
    resolved: &impl SpentOutputLookup,
    overwritten: Option<&UtxoSet>,
    max_script_size: usize,
) -> Result<(BorrowedBlockChanges<'a>, UndoBatch, BlockValueTotals), BlockChangeError> {
    // Bitcoin Core indexes genesis but does not connect its transactions into
    // CoinsView; its coinbase is unspendable and absent from UTXO/MuHash state.
    if height == 0 {
        return Ok((
            BorrowedBlockChanges::default(),
            UndoBatch::default(),
            BlockValueTotals::default(),
        ));
    }

    let net_same_block_spends = same_block_spent.is_some_and(|s| !s.is_empty());
    let mut changes = BorrowedBlockChanges::with_capacity(add_capacity, remove_capacity);
    let mut undo = UndoBatch::default();
    let mut totals = BlockValueTotals::default();
    for (tx, txid) in block.txs.iter().zip(txids) {
        let txid = *txid;
        let coinbase = is_coinbase_tx(tx);
        for (vout_idx, txout) in tx.outputs.iter().enumerate() {
            // Before the unspendable-output skip below: an OP_RETURN output
            // never enters the UTXO set, but the transaction that created it
            // still paid for it, so it counts against the fee.
            let value = txout.value;
            let vout =
                u32::try_from(vout_idx).map_err(|_| BlockChangeError::HeightOverflow(height))?;
            let outpoint = OutPoint::new(txid, vout);
            let same_block =
                net_same_block_spends && same_block_spent.is_some_and(|s| s.contains(&outpoint));
            if coinbase {
                totals.coinbase_out = totals
                    .coinbase_out
                    .checked_add(value)
                    .ok_or(BlockChangeError::BlockValueOverflow)?;
            } else if !same_block {
                totals.created_out = totals
                    .created_out
                    .checked_add(value)
                    .ok_or(BlockChangeError::BlockValueOverflow)?;
            }
            if same_block
                || txout.script_pubkey.first() == Some(&0x6a)
                || txout.script_pubkey.len() > max_script_size
            {
                continue;
            }
            // At a BIP30 exception height the coinbase reuses an earlier txid
            // whose outputs are still live, so this add OVERWRITES a coin
            // rather than creating one. `overwritten` is `Some` only at those
            // two mainnet heights, so every other block pays no lookup.
            let replaced = overwritten.and_then(|set| set.get_entry(&outpoint));
            changes.add(BorrowedUtxoAdd::new(outpoint, txout, coinbase, height));
            match replaced {
                // The inverse of overwriting is writing the old coin back, not
                // deleting the outpoint. Emitting a remove as well would depend
                // on `undo_block` applying restores after removes, and it does
                // the opposite, so the older coin would be lost and the rewound
                // UTXO set, MuHash, and coinstats would not match the parent.
                Some(previous) => undo.restore(UtxoAdd::new(
                    outpoint,
                    previous.txout,
                    previous.coinbase,
                    previous.height,
                )),
                // Disconnecting the block deletes what it created.
                None => undo.remove(outpoint),
            }
        }

        if !coinbase {
            for tx_input in &tx.inputs {
                let previous_output = tx_input.previous_output;
                if net_same_block_spends
                    && same_block_spent.is_some_and(|s| s.contains(&previous_output))
                {
                    continue;
                }
                changes.remove(previous_output);
                // ...and restores what it spent. A spend with no resolved
                // prevout would make the record unable to restore that output,
                // so refuse rather than persist an undo that silently loses it.
                let spent = resolved.entry(&tx_input.previous_output).ok_or(
                    BlockChangeError::UndoPrevoutMissing {
                        txid: previous_output.txid,
                        vout: previous_output.vout,
                    },
                )?;
                totals.spent_in = totals
                    .spent_in
                    .checked_add(spent.txout.value)
                    .ok_or(BlockChangeError::BlockValueOverflow)?;
                undo.restore(UtxoAdd::new(
                    previous_output,
                    spent.txout.clone(),
                    spent.coinbase,
                    spent.height,
                ));
            }
        }
    }
    Ok((changes, undo, totals))
}
