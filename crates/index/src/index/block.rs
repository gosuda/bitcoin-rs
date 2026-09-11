//! Parse-once block preparation and authoritative spent-script anchoring.

use super::{
    capability::IndexCapabilities, error::IndexError, prepared::PreparedBlock, rows::LiveOp,
    rows::PendingRows, rows::PositionedRow, write::IndexWriter,
};
use crate::{
    types::HashPrefixRow, types::HeaderRow, types::ScriptHash, types::SpendingPrefixRow,
    types::TxidRow,
};
use bitcoin_rs_primitives::{Hash256, OutPoint, Txid, encode};
use bitcoin_rs_storage::KvStore;
use bitcoin_slices::{Visit as _, Visitor, bsl};
use std::ops::ControlFlow;

/// Source of exact scripts for coins an incoming block spends.
///
/// A block body carries only each input's previous outpoint; the spent coin's
/// `script_pubkey` lives in authoritative UTXO state, and on disconnect in the
/// block's undo record. #225 requires Live deletes to be anchored to that
/// authoritative script, so preparation of a `ScriptLive` transition takes one
/// of these instead of guessing from the parse.
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
pub struct NoSpentScripts;

impl SpentCoinScripts for NoSpentScripts {
    fn script_bytes(&self, _txid: &[u8; 32], _vout: u32) -> Option<&[u8]> {
        None
    }
}

/// Upper bound on a `script_pubkey` admitted into the authoritative UTXO set.
///
/// Mirrors `bitcoin_rs_consensus::MAX_SCRIPT_SIZE` as applied by the node's
/// `build_utxo_changes`: outputs with `is_op_return()` or a script longer than
/// this never enter the UTXO set, so they must never enter the Live view
/// either -- #225 requires the spendability predicate to match authoritative
/// UTXO admission exactly. Duplicated as a literal because this crate does not
/// depend on the consensus crate; the node crate asserts the two are equal.
pub const MAX_LIVE_SCRIPT_SIZE: usize = 10_000;

fn pending_rows_for_block_with_header(
    block: &[u8],
    height: u32,
    capabilities: IndexCapabilities,
    spent_scripts: &dyn SpentCoinScripts,
) -> Result<(PendingRows, Option<[u8; crate::types::HEADER_ROW_SIZE]>), IndexError> {
    let mut rows = PendingRows::default();
    let mut header = None;
    let (live_created, live_spent) = {
        let mut visitor = IndexBlockVisitor {
            rows: &mut rows,
            header: &mut header,
            height_bytes: height.to_le_bytes(),
            invalid_header_len: None,
            block,
            pending_funding: Vec::new(),
            pending_spending: Vec::new(),
            pending_live: Vec::new(),
            live_created: Vec::new(),
            live_spent: Vec::new(),
            capabilities,
        };
        match bsl::Block::visit(block, &mut visitor) {
            Ok(_) => (visitor.live_created, visitor.live_spent),
            Err(bitcoin_slices::Error::VisitBreak) => {
                if let Some(len) = visitor.invalid_header_len {
                    return Err(IndexError::InvalidHeaderLength { len });
                }
                return Err(IndexError::BlockParse(bitcoin_slices::Error::VisitBreak));
            }
            Err(error) => return Err(IndexError::BlockParse(error)),
        }
    };
    if capabilities.script_live {
        push_live_ops(&mut rows, live_created, live_spent, height, spent_scripts)?;
    }
    Ok((rows, header))
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

struct IndexBlockVisitor<'a> {
    rows: &'a mut PendingRows,
    header: &'a mut Option<[u8; crate::types::HEADER_ROW_SIZE]>,
    height_bytes: [u8; crate::types::HEIGHT_SIZE],
    invalid_header_len: Option<usize>,
    /// The serialized block being visited, used as the base for byte offsets.
    block: &'a [u8],
    /// Funding and spending prefixes seen for the transaction currently being parsed.
    ///
    /// `visit_tx_in` and `visit_tx_out` fire while the transaction is still
    /// being parsed, so its byte range is not known yet — `visit_transaction`
    /// runs at the end and is the first point where the position exists. Inputs
    /// and outputs are therefore buffered here and drained once, in emission
    /// order.
    pending_funding: Vec<crate::types::HashPrefix>,
    pending_spending: Vec<HashPrefixRow>,
    /// Outputs of the transaction currently being parsed, as `(vout,
    /// optional scripthash)`. `None` means the output is not admitted to the
    /// UTXO set (`OP_RETURN` or oversize), but it still participates in
    /// same-block cancellation. Buffered for the same reason as
    /// `pending_funding`, and additionally because the txid is unknown until
    /// `visit_transaction`.
    pending_live: Vec<(u32, Option<ScriptHash>)>,
    /// Outputs this block created, pre-cancellation. The option preserves
    /// same-block cancellation for outputs that never enter UTXO state.
    live_created: Vec<([u8; 32], u32, Option<ScriptHash>)>,
    /// Full previous outpoints this block spends, pre-cancellation.
    live_spent: Vec<([u8; 32], u32)>,
    capabilities: IndexCapabilities,
}

impl IndexBlockVisitor<'_> {
    /// Byte range of `tx` within the block being visited.
    ///
    /// The slice `bitcoin_slices` hands back borrows from `self.block`, so the
    /// difference of their addresses is that transaction's offset. Computed from
    /// addresses only — nothing is dereferenced.
    fn push_txid_row(&mut self, txid_bytes: &[u8], position: crate::types::TxPosition) {
        self.rows.txid_rows.push(PositionedRow {
            row: TxidRow::row_bytes(txid_bytes, self.height_bytes),
            position,
        });
    }

    fn position_of(&self, tx: &bsl::Transaction<'_>) -> Option<crate::types::TxPosition> {
        let bytes: &[u8] = tx.as_ref();
        let offset = bytes
            .as_ptr()
            .addr()
            .checked_sub(self.block.as_ptr().addr())?;
        Some(crate::types::TxPosition::new(
            u32::try_from(offset).ok()?,
            u32::try_from(bytes.len()).ok()?,
        ))
    }
}

impl Visitor for IndexBlockVisitor<'_> {
    fn visit_block_header(&mut self, header: &bsl::BlockHeader<'_>) -> ControlFlow<()> {
        let Some(row) = HeaderRow::from_header_bytes(header.as_ref()) else {
            self.invalid_header_len = Some(header.as_ref().len());
            return ControlFlow::Break(());
        };
        *self.header = Some(row.to_db_row());
        self.rows.header_rows.push(row.to_db_row());
        ControlFlow::Continue(())
    }

    fn visit_transaction(&mut self, tx: &bsl::Transaction<'_>) -> ControlFlow<()> {
        let Some(position) = self.position_of(tx) else {
            // A transaction that does not lie inside the block slice, or whose
            // offset does not fit `u32`, cannot be addressed by a position.
            // Refuse the block rather than write a row that points nowhere.
            return ControlFlow::Break(());
        };
        for prefix in self.pending_funding.drain(..) {
            self.rows.funding_rows.push(PositionedRow {
                row: HashPrefixRow {
                    prefix,
                    height: self.height_bytes,
                },
                position,
            });
        }
        for row in self.pending_spending.drain(..) {
            self.rows
                .spending_rows
                .push(PositionedRow { row, position });
        }
        let txid =
            (self.capabilities.tx_lookup || !self.pending_live.is_empty()).then(|| tx.txid_sha2());
        if let Some(hash) = txid {
            let mut txid_bytes = [0_u8; 32];
            txid_bytes.copy_from_slice(hash.as_slice());
            for (vout, scripthash) in self.pending_live.drain(..) {
                self.live_created.push((txid_bytes, vout, scripthash));
            }
            if self.capabilities.tx_lookup {
                self.push_txid_row(hash.as_slice(), position);
            }
        }
        ControlFlow::Continue(())
    }

    fn visit_tx_in(&mut self, _vin: usize, tx_in: &bsl::TxIn<'_>) -> ControlFlow<()> {
        let prevout = tx_in.prevout();
        if is_null_prevout(prevout) {
            return ControlFlow::Continue(());
        }
        if self.capabilities.script_history {
            self.pending_spending.push(SpendingPrefixRow::row_parts(
                prevout.txid(),
                prevout.vout(),
                self.height_bytes,
            ));
        }
        if self.capabilities.script_live {
            let mut txid = [0_u8; 32];
            txid.copy_from_slice(prevout.txid());
            self.live_spent.push((txid, prevout.vout()));
        }
        ControlFlow::Continue(())
    }

    fn visit_tx_out(&mut self, vout: usize, tx_out: &bsl::TxOut<'_>) -> ControlFlow<()> {
        let script = tx_out.script_pubkey();
        if self.capabilities.script_history && !is_op_return_script(script) {
            self.pending_funding
                .push(ScriptHash::from_script_bytes(script).prefix());
        }
        // The live predicate is UTXO admission, not the history predicate:
        // `build_utxo_changes` skips `is_op_return()` and oversized scripts,
        // and the genesis coinbase never enters the UTXO set at all. History
        // deliberately keeps oversized-script outputs (they are historical
        // activity); Live must not, or it would carry locators no
        // authoritative lookup can resolve.
        if self.capabilities.script_live
            && self.height_bytes != [0_u8; crate::types::HEIGHT_SIZE]
            && let Ok(vout) = u32::try_from(vout)
        {
            let scripthash = (!is_op_return_script(script) && script.len() <= MAX_LIVE_SCRIPT_SIZE)
                .then(|| ScriptHash::from_script_bytes(script));
            self.pending_live.push((vout, scripthash));
        }
        ControlFlow::Continue(())
    }
}

fn is_null_prevout(prevout: &bsl::OutPoint<'_>) -> bool {
    prevout.vout() == u32::MAX && prevout.txid().iter().all(|byte| *byte == 0)
}

#[inline]
pub(super) fn is_op_return_script(script: &[u8]) -> bool {
    matches!(script.first(), Some(0x6a))
}

impl<S: KvStore> IndexWriter<S> {
    /// Derives a `PreparedBlock` from a serialized body without allocating a decoded block.
    pub fn prepare_block(
        &self,
        height: u32,
        hash: [u8; 32],
        body: &[u8],
    ) -> Result<PreparedBlock, IndexError> {
        self.prepare_block_for(IndexCapabilities::HISTORICAL, height, hash, body)
    }

    /// Derives capability-selected row mutations from one serialized block scan.
    pub fn prepare_block_for(
        &self,
        capabilities: IndexCapabilities,
        height: u32,
        hash: [u8; 32],
        body: &[u8],
    ) -> Result<PreparedBlock, IndexError> {
        if capabilities.script_live {
            return Err(IndexError::MissingSpentScripts);
        }
        self.prepare_block_with_spent_scripts(capabilities, height, hash, body, &NoSpentScripts)
    }

    /// [`Self::prepare_block_for`] with the spent-coin script source
    /// `ScriptLive` preparation requires (#225).
    pub fn prepare_block_with_spent_scripts(
        &self,
        capabilities: IndexCapabilities,
        height: u32,
        hash: [u8; 32],
        body: &[u8],
        spent_scripts: &dyn SpentCoinScripts,
    ) -> Result<PreparedBlock, IndexError> {
        if capabilities.is_empty() {
            return Err(IndexError::NonContiguousPrepared {
                watermark: self.watermark()?,
            });
        }
        let (mut rows, header) =
            pending_rows_for_block_with_header(body, height, capabilities, spent_scripts)?;
        let header = header.ok_or(IndexError::InvalidHeaderLength { len: 0 })?;
        let actual_hash = encode::double_sha256(header.as_slice()).to_le_bytes();
        if actual_hash != hash {
            return Err(IndexError::BlockIdentityMismatch {
                height,
                expected: hash,
                actual: actual_hash,
            });
        }
        let mut parent_hash = [0_u8; 32];
        parent_hash.copy_from_slice(&header[4..36]);
        rows.sort();
        let row_count = rows.total();
        let encoded_bytes = rows.encoded_bytes()?;
        Ok(PreparedBlock {
            height,
            hash,
            parent_hash,
            row_count,
            encoded_bytes,
            capabilities,
            rows,
        })
    }
}
