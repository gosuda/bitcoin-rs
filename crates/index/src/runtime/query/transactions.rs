//! Exact-identity block reads and transaction position verification.

use super::{
    Arc, Block, BlockTree, DerivedIndexQueryEngine, Hash256, MAX_SERIALIZED_BLOCK_BYTES, OutPoint,
    PrefixBound, QueryBudget, ReadPrefix, Tx, TxIndexSnapshot, TxPosition, TxPositionValue,
    TxQueryError, TxUnavailableCause, Txid, deserialize,
};
use bitcoin_rs_primitives::BlockHash;

impl DerivedIndexQueryEngine {
    pub(super) fn resolve_hash_at_height(
        &self,
        height: u32,
        prefix: &ReadPrefix,
    ) -> Result<Hash256, TxQueryError> {
        match prefix.bound {
            PrefixBound::ExactTip => {
                let tree = self.block_tree.read();
                Self::hash_at_height(&tree, prefix.anchor_id, height).ok_or(TxQueryError::Retry)
            }
            PrefixBound::AtMost => {
                let tree = self.block_tree.read();
                let mut remaining = super::HISTORICAL_ANCESTRY_BUDGET;
                let found = tree
                    .node_at_height_from_bounded(prefix.anchor_id, height, &mut remaining)
                    .map_err(|_| TxQueryError::Retry)?;
                found
                    .and_then(|id| tree.node(id).ok().map(|n| n.hash))
                    .ok_or(TxQueryError::Retry)
            }
        }
    }

    fn hash_at_height(
        tree: &BlockTree,
        tip_id: bitcoin_rs_chain::NodeId,
        height: u32,
    ) -> Option<Hash256> {
        let node_id = tree.node_at_height_from(tip_id, height)?;
        tree.node(node_id).ok().map(|n| n.hash)
    }

    /// Returns the verified block at `(height, hash)`, reusing the query's one
    /// retained block on consecutive reads at the same identity: the first
    /// fetch verifies and pins the block on the query budget, while later
    /// reads at the same identity return the shared handle with no further
    /// body read, byte charge, or deserialization. A read at any other
    /// identity evicts the retained block before fetching, so older identities
    /// are re-read and re-charged. Only successfully verified blocks are
    /// pinned, so a failure leaves the memo empty and the next read
    /// re-attempts the body fetch.
    pub(super) fn resolve_block(
        &self,
        budget: &mut QueryBudget,
        height: u32,
        hash: Hash256,
    ) -> Result<Arc<Block>, TxQueryError> {
        if let Some(hit) = budget.memoized_block(height, hash) {
            return Ok(hit);
        }
        budget.reserve_body_read(MAX_SERIALIZED_BLOCK_BYTES)?;
        let bytes = self.resolve_block_body_bytes(height, BlockHash::from(hash))?;
        budget.charge_body_bytes(bytes.len())?;
        let block = Arc::new(Self::verify_block(&bytes, height, hash)?);
        Ok(budget.memoize_block(height, hash, block))
    }

    fn resolve_block_body_bytes(
        &self,
        height: u32,
        hash: BlockHash,
    ) -> Result<Vec<u8>, TxQueryError> {
        let Some(body_source) = self.body_source.as_ref() else {
            return Err(TxQueryError::Unavailable(
                TxUnavailableCause::BlockBodyMissing { height },
            ));
        };
        match body_source.block_body(height, hash) {
            Ok(Some(bytes)) => Ok(bytes),
            Ok(None) => Err(TxQueryError::Unavailable(
                TxUnavailableCause::BlockBodyMissing { height },
            )),
            Err(error) => Err(TxQueryError::Storage(
                format!("block body read failed at height {height}: {error}").into(),
            )),
        }
    }

    fn verify_block(bytes: &[u8], height: u32, hash: Hash256) -> Result<Block, TxQueryError> {
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
        budget: &mut QueryBudget,
        height: u32,
        hash: Hash256,
        position: TxPosition,
    ) -> Result<Option<Tx>, TxQueryError> {
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

    fn transaction_from_full_block(
        &self,
        budget: &mut QueryBudget,
        height: u32,
        hash: Hash256,
        txid: &Txid,
    ) -> Result<Option<Tx>, TxQueryError> {
        let block = self.resolve_block(budget, height, hash)?;
        Ok(block
            .txs
            .iter()
            .find(|transaction| transaction.txid() == *txid)
            .cloned())
    }

    pub(super) fn transaction_for(
        &self,
        snapshot: &dyn TxIndexSnapshot,
        prefix: &ReadPrefix,
        budget: &mut QueryBudget,
        txid: &Txid,
    ) -> Result<Option<Tx>, TxQueryError> {
        Ok(self
            .locate_transaction_for(snapshot, prefix, budget, txid)?
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
        prefix: &ReadPrefix,
        budget: &mut QueryBudget,
        txid: &Txid,
    ) -> Result<Option<(u32, Tx)>, TxQueryError> {
        let limit = budget.next_scan_limit()?;
        let scan = snapshot
            .transaction_rows(txid, limit)
            .map_err(|error| TxQueryError::Storage(error.to_string().into()))?;
        let rows = budget.accept_scan(scan)?;
        if rows.is_empty() {
            return Self::scoped_absence(prefix, "transaction index");
        }

        for row in rows {
            let height = row.row.height();
            if !prefix.covers(height) {
                continue;
            }
            let Some(positions) = Self::validated_positions(&row.value) else {
                let hash = self.resolve_hash_at_height(height, prefix)?;
                if let Some(transaction) =
                    self.transaction_from_full_block(budget, height, hash, txid)?
                {
                    return Ok(Some((height, transaction)));
                }
                continue;
            };
            let position = positions[0];
            let hash = self.resolve_hash_at_height(height, prefix)?;
            match self.resolve_positioned_transaction(budget, height, hash, position)? {
                Some(transaction) if transaction.txid() == *txid => {
                    return Ok(Some((height, transaction)));
                }
                _ => {
                    if let Some(transaction) =
                        self.transaction_from_full_block(budget, height, hash, txid)?
                    {
                        return Ok(Some((height, transaction)));
                    }
                }
            }
        }
        Self::scoped_absence(prefix, "transaction index")
    }

    /// A row's absence is only proven when the index covers the chain from
    /// genesis; below a pruned prefix, answer `Unavailable` instead.
    pub(super) fn none_below_floor<T>(
        floor: u32,
        family: &'static str,
    ) -> Result<Option<T>, TxQueryError> {
        if floor > 0 {
            Err(TxQueryError::Unavailable(
                TxUnavailableCause::PrunedPrefixUnproven { family, floor },
            ))
        } else {
            Ok(None)
        }
    }

    /// Scoped absence for one [`ReadPrefix`].
    ///
    /// `ExactTip` preserves [`Self::none_below_floor`]; `AtMost` reports
    /// scoped `Ok(None)` for transaction-family absence in
    /// `[floor, anchor]`, never a pruned-prefix refusal. Full history never
    /// reaches here on a positive floor: it returns `HistoryUnproven`
    /// before scanning.
    pub(super) fn scoped_absence<T>(
        prefix: &ReadPrefix,
        family: &'static str,
    ) -> Result<Option<T>, TxQueryError> {
        match prefix.bound {
            PrefixBound::ExactTip => Self::none_below_floor(prefix.floor, family),
            PrefixBound::AtMost => Ok(None),
        }
    }

    pub(super) fn outpoint_value_for(
        &self,
        snapshot: &dyn TxIndexSnapshot,
        prefix: &ReadPrefix,
        budget: &mut QueryBudget,
        outpoint: &OutPoint,
    ) -> Result<Option<u64>, TxQueryError> {
        let tx = self.transaction_for(snapshot, prefix, budget, &outpoint.txid)?;
        let Some(tx) = tx else {
            return Ok(None);
        };
        let vout = usize::try_from(outpoint.vout)
            .map_err(|_| TxQueryError::Storage("outpoint vout overflow".into()))?;
        Ok(tx.outputs.get(vout).map(|o| o.value.to_sat()))
    }
}
