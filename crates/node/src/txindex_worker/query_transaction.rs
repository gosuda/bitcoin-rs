//! Budgeted, hash-verified transaction and byte-position resolution.

use super::MAX_SERIALIZED_BLOCK_BYTES;
use super::QueryBudget;
use super::TxIndexQueryEngine;
use bitcoin_rs_chain::BlockTree;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_index::TxIndexSnapshot;
use bitcoin_rs_index::types::TxPosition;
use bitcoin_rs_index::types::TxPositionValue;
use bitcoin_rs_primitives::Block;
use bitcoin_rs_primitives::BlockHash;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::OutPoint;
use bitcoin_rs_primitives::Tx;
use bitcoin_rs_primitives::Txid;
use bitcoin_rs_primitives::deserialize;
use bitcoin_rs_rpc::context::TxQueryError;

impl TxIndexQueryEngine {
    pub(super) fn resolve_hash_at_height(
        &self,
        height: u32,
        tip: &TipSnapshot,
    ) -> Result<Hash256, TxQueryError> {
        let tree = self.block_tree.read();
        Self::hash_at_height(&tree, tip.tip_id, height).ok_or(TxQueryError::Retry)
    }

    pub(super) fn hash_at_height(
        tree: &BlockTree,
        tip_id: bitcoin_rs_chain::NodeId,
        height: u32,
    ) -> Option<Hash256> {
        let node_id = tree.node_at_height_from(tip_id, height)?;
        tree.node(node_id).ok().map(|n| n.hash)
    }

    pub(super) fn resolve_block(
        &self,
        budget: &mut QueryBudget,
        height: u32,
        hash: Hash256,
    ) -> Result<Block, TxQueryError> {
        budget.reserve_body_read(MAX_SERIALIZED_BLOCK_BYTES)?;
        let bytes = self.resolve_block_body_bytes(height, BlockHash::from(hash))?;
        budget.charge_body_bytes(bytes.len())?;
        Self::verify_block(&bytes, height, hash)
    }

    pub(super) fn resolve_block_body_bytes(
        &self,
        height: u32,
        hash: BlockHash,
    ) -> Result<Vec<u8>, TxQueryError> {
        if let Some(body_source) = self.body_source.as_ref() {
            if let Some(bytes) = body_source.block_body(height, hash) {
                return Ok(bytes);
            }
        }
        self.block_source
            .block_body_bytes_for(height, hash)
            .ok_or_else(|| {
                TxQueryError::Unavailable(
                    format!("block body missing for txindex query at height {height}").into(),
                )
            })
    }

    pub(super) fn verify_block(
        bytes: &[u8],
        height: u32,
        hash: Hash256,
    ) -> Result<Block, TxQueryError> {
        let block = deserialize::<Block>(bytes).map_err(|_| {
            TxQueryError::Storage(format!("corrupt serialized block at height {height}").into())
        })?;
        let decoded = block.block_hash().0;
        if decoded != hash {
            return Err(TxQueryError::Storage(
                format!("block identity mismatch at height {height}").into(),
            ));
        }
        Ok(block)
    }

    pub(super) fn validated_positions(value: &[u8]) -> Option<&[TxPosition]> {
        let positions = TxPositionValue::decode(value)?;
        let mut previous: Option<TxPosition> = None;
        for &position in positions {
            let end = position.end()?;
            if position.byte_len() == 0
                || usize::try_from(end).ok()? > MAX_SERIALIZED_BLOCK_BYTES
                || previous.is_some_and(|prior| {
                    position.offset() <= prior.offset()
                        || position.offset() < prior.end().unwrap_or(u32::MAX)
                })
            {
                return None;
            }
            previous = Some(position);
        }
        Some(positions)
    }

    pub(super) fn resolve_positioned_transaction(
        &self,
        tip: &TipSnapshot,
        budget: &mut QueryBudget,
        height: u32,
        position: TxPosition,
    ) -> Result<Option<Tx>, TxQueryError> {
        let hash = self.resolve_hash_at_height(height, tip)?;
        let Some(body_source) = self.body_source.as_ref() else {
            return Ok(None);
        };
        let byte_len = usize::try_from(position.byte_len())
            .map_err(|_| TxQueryError::Storage("transaction position length overflow".into()))?;
        budget.reserve_body_read(byte_len)?;
        let Some(bytes) = body_source.block_body_range(
            height,
            BlockHash::from(hash),
            position.offset(),
            position.byte_len(),
        ) else {
            return Ok(None);
        };
        budget.charge_body_bytes(bytes.len())?;
        if bytes.len() != byte_len {
            return Ok(None);
        }
        Ok(deserialize::<Tx>(&bytes).ok())
    }

    pub(super) fn transaction_from_full_block(
        &self,
        tip: &TipSnapshot,
        budget: &mut QueryBudget,
        height: u32,
        txid: &Txid,
    ) -> Result<Option<Tx>, TxQueryError> {
        let hash = self.resolve_hash_at_height(height, tip)?;
        let block = self.resolve_block(budget, height, hash)?;
        Ok(block
            .txs
            .into_iter()
            .find(|transaction| transaction.txid() == *txid))
    }

    pub(super) fn transaction_for(
        &self,
        snapshot: &dyn TxIndexSnapshot,
        tip: &TipSnapshot,
        budget: &mut QueryBudget,
        txid: &Txid,
    ) -> Result<Option<Tx>, TxQueryError> {
        Ok(self
            .locate_transaction_for(snapshot, tip, budget, txid)?
            .map(|(_, transaction)| transaction))
    }

    /// Resolves both the confirming height and the transaction itself.
    ///
    /// `transaction_for` and `transaction_height_for` are the same walk, so they
    /// share it rather than keeping two copies of the row/position/full-block
    /// fallback ladder. The height caller pays for the deserialization it does
    /// not use, which is the price of not answering with an unverified row: a
    /// row surviving from a reorged block would otherwise name a height whose
    /// block never held the transaction.
    pub(super) fn locate_transaction_for(
        &self,
        snapshot: &dyn TxIndexSnapshot,
        tip: &TipSnapshot,
        budget: &mut QueryBudget,
        txid: &Txid,
    ) -> Result<Option<(u32, Tx)>, TxQueryError> {
        let limit = budget.next_scan_limit()?;
        let scan = snapshot
            .transaction_rows(txid, limit)
            .map_err(|error| TxQueryError::Storage(error.to_string().into()))?;
        let rows = budget.accept_scan(scan)?;
        if rows.is_empty() {
            return Ok(None);
        }

        for row in rows {
            let height = row.row.height();
            let Some(positions) = Self::validated_positions(&row.value) else {
                if let Some(transaction) =
                    self.transaction_from_full_block(tip, budget, height, txid)?
                {
                    return Ok(Some((height, transaction)));
                }
                continue;
            };
            let position = positions[0];
            match self.resolve_positioned_transaction(tip, budget, height, position)? {
                Some(transaction) if transaction.txid() == *txid => {
                    return Ok(Some((height, transaction)));
                }
                _ => {
                    if let Some(transaction) =
                        self.transaction_from_full_block(tip, budget, height, txid)?
                    {
                        return Ok(Some((height, transaction)));
                    }
                }
            }
        }
        Ok(None)
    }

    pub(super) fn outpoint_value_for(
        &self,
        snapshot: &dyn TxIndexSnapshot,
        tip: &TipSnapshot,
        budget: &mut QueryBudget,
        outpoint: &OutPoint,
    ) -> Result<Option<u64>, TxQueryError> {
        let tx = self.transaction_for(snapshot, tip, budget, &outpoint.txid)?;
        let Some(tx) = tx else {
            return Ok(None);
        };
        let vout = usize::try_from(outpoint.vout)
            .map_err(|_| TxQueryError::Storage("outpoint vout overflow".into()))?;
        Ok(tx.outputs.get(vout).map(|o| o.value.to_sat()))
    }
}
