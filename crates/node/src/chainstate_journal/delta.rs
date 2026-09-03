//! Semantic-delta extraction: turns the apply path's UTXO mutations into
//! journal records.
//!
//! Ownership: this module is the single owner of the mapping from
//! [`BorrowedBlockChanges`] + [`UndoBatch`] to the journal's semantic delta
//! ([`Mutation`] lists in commit order). The apply path calls
//! [`journal_record_for_block`]; nothing else re-derives this mapping.
//!
//! Mapping contract (mirrors `build_block_changes` in `crates/utxo/src/
//! connect.rs`, which owns the mutation order):
//! - every non-skipped `changes.add` becomes `Mutation::Create` with the full
//!   coin (`OP_RETURN` and oversized-script outputs never enter the UTXO set, so
//!   they are not journal mutations either);
//! - every non-same-block spend becomes `Mutation::Spend` with the full spent
//!   coin, taken from the undo batch's restore list (same order as the
//!   `changes.remove` list: one restore per spend);
//! - same-block spends are netted out upstream and produce no journal
//!   mutation.
//!
//! BIP30 overwrite restores are distinguished from spend restores by
//! outpoint: a restore matching an add carries the replaced old coin; a
//! restore matching a remove carries the spent coin. This mapping has one
//! owner here and rejects any leftover or missing restore.

use bitcoin_rs_utxo::BorrowedBlockChanges;
use hashbrown::HashMap;
use thiserror::Error;

use super::record::{Coin, JournalRecord, Mutation};

#[derive(Debug, Error)]
pub(crate) enum JournalDeltaError {
    /// A spend has no full-coin undo preimage.
    #[error("journal spend {0:?} has no undo coin")]
    MissingSpend(bitcoin_rs_primitives::OutPoint),
    /// More than one undo restore named the same outpoint.
    #[error("journal undo restores duplicate outpoint {0:?}")]
    DuplicateRestore(bitcoin_rs_primitives::OutPoint),
    /// An undo restore matched neither an add nor a spend.
    #[error("journal undo restore {0:?} matches no block mutation")]
    UnmatchedRestore(bitcoin_rs_primitives::OutPoint),
}

/// Inputs for one fully applied block's semantic-delta record.
///
/// Groups the header/identity fields so the emission call site stays readable
/// and the mapping function keeps a short parameter list.
#[derive(Clone, Copy)]
pub(crate) struct BlockDeltaInputs {
    /// Applied block height.
    pub height: u32,
    /// Applied block hash.
    pub block_hash: [u8; 32],
    /// Parent hash (`block.header.prev_blockhash`).
    pub prev_hash: [u8; 32],
    /// Cumulative transaction count through this block.
    pub block_tx_count: u64,
    /// Net coin-stats height delta for this block.
    pub coin_stats_height_delta: i64,
    /// The block's 80-byte consensus header (journal-carried `TipSnapshot`
    /// reconstruction, plan rev 5).
    pub raw_header: [u8; 80],
}

/// Builds the semantic-delta record for one fully applied block.
///
/// `spent_coins` must carry the full spent coin for each entry of
/// `changes.spent_outpoints()`, in the same order: `build_block_changes`
/// pushes exactly one undo restore per non-netted spend, in input order.
///
/// Mutation order is the commit order: creates (in block-output order) first,
/// then spends (in block-input order) — matching how replay must observe them
/// so that a same-block create-then-spend replays correctly (the create is
/// already in the set when the spend resolves it).
pub(crate) fn journal_record_for_block(
    inputs: BlockDeltaInputs,
    changes: &BorrowedBlockChanges<'_>,
    undo_coins: impl IntoIterator<Item = Coin>,
) -> Result<JournalRecord, JournalDeltaError> {
    Ok(JournalRecord {
        height: inputs.height,
        block_hash: inputs.block_hash,
        prev_hash: inputs.prev_hash,
        block_tx_count: inputs.block_tx_count,
        coin_stats_height_delta: inputs.coin_stats_height_delta,
        raw_header: inputs.raw_header,
        mutations: mutations_for_block(changes, undo_coins)?,
    })
}

/// Extracts the ordered mutation list from the apply path's change set.
///
/// See the module docs for the mapping contract.
pub(crate) fn mutations_for_block(
    changes: &BorrowedBlockChanges<'_>,
    undo_coins: impl IntoIterator<Item = Coin>,
) -> Result<Vec<Mutation>, JournalDeltaError> {
    let mut restores = HashMap::new();
    for coin in undo_coins {
        let outpoint = coin.outpoint;
        if restores.insert(outpoint, coin).is_some() {
            return Err(JournalDeltaError::DuplicateRestore(outpoint));
        }
    }
    let mut mutations = Vec::with_capacity(changes.add_count() + changes.remove_count());
    for add in changes.adds() {
        let new_coin = Coin {
            outpoint: add.outpoint,
            txout: add.txout.clone(),
            height: add.height,
            coinbase: add.coinbase,
        };
        match restores.remove(&add.outpoint) {
            Some(old_coin) => mutations.push(Mutation::Overwrite { old_coin, new_coin }),
            None => mutations.push(Mutation::Create { coin: new_coin }),
        }
    }
    for outpoint in changes.spent_outpoints() {
        let coin = restores
            .remove(outpoint)
            .ok_or(JournalDeltaError::MissingSpend(*outpoint))?;
        mutations.push(Mutation::Spend { coin });
    }
    if let Some((outpoint, _)) = restores.into_iter().next() {
        return Err(JournalDeltaError::UnmatchedRestore(outpoint));
    }
    Ok(mutations)
}

#[cfg(test)]
mod tests {
    use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut, Txid};
    use bitcoin_rs_utxo::{BorrowedBlockChanges, BorrowedUtxoAdd};

    use super::{Coin, Mutation, mutations_for_block};

    fn coin(marker: u8, height: u32, value: u64) -> Coin {
        Coin {
            outpoint: OutPoint::new(Txid(Hash256::from_le_bytes(&[marker; 32])), 0),
            txout: TxOut {
                value,
                script_pubkey: vec![0x51],
            },
            height,
            coinbase: true,
        }
    }

    #[test]
    fn classifies_bip30_restore_as_overwrite_before_spends() -> Result<(), super::JournalDeltaError>
    {
        let old = coin(1, 10, 50);
        let mut new = old.clone();
        new.height = 100;
        new.txout.value = 25;
        let spent = coin(2, 20, 12);
        let mut changes = BorrowedBlockChanges::with_capacity(1, 1);
        changes.add(BorrowedUtxoAdd::new(
            new.outpoint,
            &new.txout,
            new.coinbase,
            new.height,
        ));
        changes.remove(spent.outpoint);

        let mutations = mutations_for_block(&changes, vec![old.clone(), spent.clone()])?;

        assert_eq!(
            mutations,
            vec![
                Mutation::Overwrite {
                    old_coin: old,
                    new_coin: new,
                },
                Mutation::Spend { coin: spent },
            ]
        );
        Ok(())
    }
}
