//! Parse-once block preparation and authoritative spent-script anchoring.

use super::{
    capability::{IndexCapabilities, IndexCapability},
    error::IndexError,
    rows::LiveOp,
    rows::PendingRows,
    rows::PositionedRow,
};
use crate::{
    types::HashPrefixRow, types::MAX_POSITION_END_BYTES, types::ScriptHash,
    types::SpendingPrefixRow, types::TxidRow, types::U24_MAX, types::encode_height,
};
use bitcoin_rs_primitives::{Hash256, OutPoint, Txid, encode, layout::ParsedBlock};

/// Source of exact scripts for coins an incoming block spends.
///
/// A block body carries only each input's previous outpoint; the spent coin's
/// `script_pubkey` lives in authoritative UTXO state, and on disconnect in the
/// block's undo record. Live deletes are anchored to that authoritative
/// script, so preparation of a `ScriptLive` transition takes one of these
/// instead of guessing from the parse.
pub trait SpentCoinScripts {
    /// The exact `script_pubkey` bytes of the coin `txid:vout`, if known.
    ///
    /// `txid` is in little-endian byte order, as serialized in the input.
    fn script_bytes(&self, txid: &[u8; 32], vout: u32) -> Option<&[u8]>;
}

/// The anchorless source: answers nothing.
///
/// Used by the legacy prepare path, which refuses `ScriptLive` outright rather
/// than producing a Live transition with unanchored deletes.
pub(crate) struct NoSpentScripts;

impl SpentCoinScripts for NoSpentScripts {
    fn script_bytes(&self, _txid: &[u8; 32], _vout: u32) -> Option<&[u8]> {
        None
    }
}

/// Upper bound on a `script_pubkey` admitted into the authoritative UTXO set.
///
/// Single source: `bitcoin_rs_script::MAX_SCRIPT_SIZE`, applied by
/// `build_utxo_changes` — outputs with `is_op_return()` or a script longer
/// than this never enter the UTXO set, so they must never enter the Live view
/// either. The spendability predicate matches authoritative UTXO admission
/// exactly. History rows deliberately keep oversized scripts (real on-chain
/// activity, pinned by `live_predicate_matches_utxo_admission_not_history`);
/// that asymmetry is bounded by consensus block size, not by this constant.
pub use bitcoin_rs_script::MAX_SCRIPT_SIZE as MAX_LIVE_SCRIPT_SIZE;

/// Derives the capability-selected rows of one serialized block body.
///
/// PRE: `block` holds one complete serialized block body, and `height` is the
/// height being indexed.
/// POST: The rows carry every funding, spending, transaction-id, and header
/// row the capabilities select, and the returned header is the body's exact
/// 80-byte prefix.
/// INVARIANT: A rejected parse contributes no rows.
pub(super) fn pending_rows_for_block_with_header(
    block: &[u8],
    height: u32,
    capabilities: IndexCapabilities,
    spent_scripts: &dyn SpentCoinScripts,
) -> Result<(PendingRows, [u8; crate::types::HEADER_ROW_SIZE]), IndexError> {
    let parsed = ParsedBlock::parse_exact(block).map_err(IndexError::BlockParse)?;
    let header_bytes = parsed
        .span_bytes(parsed.header_span())
        .unwrap_or_else(|| unreachable!("header span belongs to the parsed image"));
    let header_row: [u8; crate::types::HEADER_ROW_SIZE] = header_bytes
        .try_into()
        .unwrap_or_else(|_| unreachable!("the layout parser fixes the header at 80 bytes"));

    let height_bytes = encode_height(height);
    let mut rows = PendingRows::default();
    rows.header_rows.push(header_row);
    let mut live_created: Vec<([u8; 32], u32, Option<ScriptHash>)> = Vec::new();
    let mut live_spent: Vec<([u8; 32], u32)> = Vec::new();

    for tx in parsed.transactions() {
        let span = tx.span();
        // The stored position must satisfy the same predicate every reader
        // applies: u24-addressable and ending inside one serialized block.
        // A body larger than the consensus cap is refused here, so a row the
        // writer admits is never corrupt to an exporter or a restore.
        let end = u64::from(span.start()).saturating_add(u64::from(span.len()));
        let past_cap = u64::try_from(MAX_POSITION_END_BYTES).map_or(true, |cap| end > cap);
        if span.start() > U24_MAX || span.len() > U24_MAX || past_cap {
            return Err(IndexError::UnaddressablePosition {
                offset: u64::from(span.start()),
            });
        }
        let position = crate::types::TxPosition::new(span.start(), span.len());

        // A live output's row needs the transaction id, and that id is only
        // computed when something needs it, so the outputs of one transaction
        // are staged here until its id exists.
        let mut pending_live: Vec<(u32, Option<ScriptHash>)> = Vec::new();

        for input in tx.inputs() {
            let outpoint = tx
                .span_bytes(input.outpoint())
                .unwrap_or_else(|| unreachable!("input span belongs to the parsed image"));
            let (prevout_txid, vout_bytes) = outpoint.split_at(32);
            let vout = u32::from_le_bytes(
                vout_bytes
                    .try_into()
                    .unwrap_or_else(|_| unreachable!("an outpoint vout is four bytes")),
            );
            if is_null_prevout(prevout_txid, vout) {
                continue;
            }
            if capabilities.contains(IndexCapability::ScriptHistory) {
                rows.spending_rows.push(PositionedRow {
                    row: SpendingPrefixRow::row_parts(prevout_txid, vout, height_bytes),
                    position,
                });
            }
            if capabilities.contains(IndexCapability::ScriptLive) {
                let mut txid = [0_u8; 32];
                txid.copy_from_slice(prevout_txid);
                live_spent.push((txid, vout));
            }
        }

        for (index, output) in tx.outputs().iter().enumerate() {
            let script = tx
                .span_bytes(output.script_pubkey())
                .unwrap_or_else(|| unreachable!("output span belongs to the parsed image"));
            // History keeps every non-OP_RETURN output, including scripts past
            // MAX_LIVE_SCRIPT_SIZE: it records on-chain activity, while Live
            // mirrors UTXO admission. The asymmetry is deliberate (pinned by
            // live_predicate_matches_utxo_admission_not_history) and bounded
            // by consensus block size.
            if capabilities.contains(IndexCapability::ScriptHistory) && !is_op_return_script(script)
            {
                rows.funding_rows.push(PositionedRow {
                    row: HashPrefixRow {
                        prefix: ScriptHash::from_script_bytes(script).prefix(),
                        height: height_bytes,
                    },
                    position,
                });
            }
            // Genesis is exempt: its coinbase output never entered the UTXO
            // set, so it must not enter the live view either.
            if capabilities.contains(IndexCapability::ScriptLive)
                && height_bytes != [0_u8; crate::types::HEIGHT_SIZE]
                && let Ok(vout) = u32::try_from(index)
            {
                pending_live.push((vout, live_admission(script)));
            }
        }

        if capabilities.contains(IndexCapability::TxLookup) || !pending_live.is_empty() {
            let txid = tx.txid();
            for (vout, scripthash) in pending_live {
                live_created.push((*txid.as_bytes(), vout, scripthash));
            }
            if capabilities.contains(IndexCapability::TxLookup) {
                rows.txid_rows.push(PositionedRow {
                    row: TxidRow::row_bytes(txid.as_bytes(), height_bytes),
                    position,
                });
            }
        }
    }

    if capabilities.contains(IndexCapability::ScriptLive) {
        push_live_ops(&mut rows, live_created, live_spent, height, spent_scripts)?;
    }
    if capabilities.contains(IndexCapability::CompactFilters) {
        let hash = encode::double_sha256(header_bytes).to_le_bytes();
        rows.filter_rows.push((
            hash,
            super::filters::build(&parsed, height, &hash, spent_scripts)?,
        ));
    }
    Ok((rows, header_row))
}

/// Turns a block's created and spent outputs into ordered live mutations.
///
/// Outputs created and spent within the same block cancel before the spent-coin
/// anchor is consulted: those outputs never entered the committed UTXO set.
/// Every surviving spend must resolve its exact script through the authoritative
/// anchor, otherwise preparation fails closed rather than leaving a stale live
/// row behind.
fn push_live_ops(
    rows: &mut PendingRows,
    created: Vec<([u8; 32], u32, Option<ScriptHash>)>,
    spent: Vec<([u8; 32], u32)>,
    height: u32,
    spent_scripts: &dyn SpentCoinScripts,
) -> Result<(), IndexError> {
    let created_keys: hashbrown::HashSet<([u8; 32], u32)> = created
        .iter()
        .map(|(txid, vout, _)| (*txid, *vout))
        .collect();
    let mut cancelled = hashbrown::HashSet::new();
    let mut deletes = Vec::new();
    for (txid, vout) in spent {
        if created_keys.contains(&(txid, vout)) {
            cancelled.insert((txid, vout));
            continue;
        }
        let script = spent_scripts
            .script_bytes(&txid, vout)
            .ok_or(IndexError::MissingSpentCoin { txid, vout, height })?;
        let outpoint = OutPoint::new(Txid(Hash256::from_le_bytes(&txid)), vout);
        deletes.push(LiveOp::Delete(crate::types::ScriptLiveRow::new(
            ScriptHash::from_script_bytes(script),
            &outpoint,
        )));
    }
    for (txid, vout, scripthash) in created {
        if cancelled.contains(&(txid, vout)) {
            continue;
        }
        let Some(scripthash) = scripthash else {
            continue;
        };
        let outpoint = OutPoint::new(Txid(Hash256::from_le_bytes(&txid)), vout);
        // At a BIP30 exception height the output outpoint can already be
        // live. The undo record carries that replaced coin as a restore, so
        // use the same anchor to remove its old script row before publishing
        // the new one. The inverse operation restores the old row on rollback.
        if let Some(old_script) = spent_scripts.script_bytes(&txid, vout) {
            rows.live_ops
                .push(LiveOp::Delete(crate::types::ScriptLiveRow::new(
                    ScriptHash::from_script_bytes(old_script),
                    &outpoint,
                )));
        }
        rows.live_ops
            .push(LiveOp::Insert(crate::types::ScriptLiveRow::new(
                scripthash, &outpoint,
            )));
    }
    rows.live_ops.extend(deletes);
    Ok(())
}

/// Whether a previous outpoint is the coinbase null outpoint: a zero
/// transaction id carried with the maximum output index.
fn is_null_prevout(prevout_txid: &[u8], vout: u32) -> bool {
    vout == u32::MAX && prevout_txid.iter().all(|byte| *byte == 0)
}

#[inline]
pub(super) fn is_op_return_script(script: &[u8]) -> bool {
    matches!(script.first(), Some(0x6a))
}

/// The scripthash a live row carries for one output, when it carries one.
///
/// PRE: `script` is one output's `script_pubkey` bytes.
/// POST: `Some` exactly when authoritative UTXO admission accepts the output.
/// INVARIANT: This predicate mirrors `build_utxo_changes`, which skips
/// `is_op_return()` and scripts longer than `MAX_LIVE_SCRIPT_SIZE`. The
/// spendability predicate matches authoritative UTXO admission exactly, so a
/// live row never points at a coin no lookup can resolve.
fn live_admission(script: &[u8]) -> Option<ScriptHash> {
    let admitted = !is_op_return_script(script) && script.len() <= MAX_LIVE_SCRIPT_SIZE;
    admitted.then(|| ScriptHash::from_script_bytes(script))
}
