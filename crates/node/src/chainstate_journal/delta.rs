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
//! BIP30 overwrite note: at the two exception heights the coinbase add
//! overwrites a live coin. The undo batch carries the replaced coin so
//! disconnect can restore it; the journal replay reaches the same state
//! without an explicit `Overwrite` because replay resolves creates the same
//! way `build_block_changes` does (the pre-existing coin is simply
//! replaced in place), and the undo parity is preserved by the replay's own
//! undo construction. The `Overwrite` variant stays reserved for a future
//! replay need; emitting it here would require distinguishing replaced adds
//! from fresh adds per outpoint, which the borrowed change set does not
//! expose.

use bitcoin_rs_utxo::BorrowedBlockChanges;

use super::record::{Coin, JournalRecord, Mutation};

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
    spent_coins: impl IntoIterator<Item = Coin>,
) -> JournalRecord {
    JournalRecord {
        height: inputs.height,
        block_hash: inputs.block_hash,
        prev_hash: inputs.prev_hash,
        block_tx_count: inputs.block_tx_count,
        coin_stats_height_delta: inputs.coin_stats_height_delta,
        raw_header: inputs.raw_header,
        mutations: mutations_for_block(changes, spent_coins),
    }
}

/// Extracts the ordered mutation list from the apply path's change set.
///
/// See the module docs for the mapping contract.
#[must_use]
pub(crate) fn mutations_for_block(
    changes: &BorrowedBlockChanges<'_>,
    spent_coins: impl IntoIterator<Item = Coin>,
) -> Vec<Mutation> {
    let spent: Vec<Coin> = spent_coins.into_iter().collect();
    debug_assert_eq!(
        spent.len(),
        changes.spent_outpoints().len(),
        "one full coin per spend is required to build the journal delta"
    );
    let mut mutations = Vec::with_capacity(changes.add_count() + changes.remove_count());
    for add in changes.adds() {
        mutations.push(Mutation::Create {
            coin: Coin {
                outpoint: add.outpoint,
                txout: add.txout.clone(),
                height: add.height,
                coinbase: add.coinbase,
            },
        });
    }
    for (outpoint, coin) in changes.spent_outpoints().iter().zip(spent) {
        debug_assert_eq!(
            outpoint, &coin.outpoint,
            "spend/restore order must match between changes and undo"
        );
        mutations.push(Mutation::Spend { coin });
    }
    mutations
}
