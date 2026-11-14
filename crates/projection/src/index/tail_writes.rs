use super::capability::{IndexCapabilities, IndexCapability, IndexWatermark};
use super::error::IndexError;
use super::rows::IndexRowBytes;
use super::write::IndexWriter;
use crate::segment::format::SCRIPT_STATS_VALUE_LEN;
use crate::segment::tail::{
    self, CreationOrdinals, PreparedTail, SealedTxOrdinals, TailWriterState,
};
use crate::segment::{self, SealedGen, sealed_generations};
use bitcoin_rs_storage::{
    BatchOp, BufferedWriteBatch, ColumnFamily, CommittedBlock, KvSnapshot, KvStore,
};
use std::collections::BTreeMap;

/// A stats row's undo-log entry carries its prior value: a length prefix and
/// the fixed stats value.
const STATS_PRIOR_LOG_BYTES: usize = 4 + SCRIPT_STATS_VALUE_LEN;

/// One rollback step's tail plan (`REO-04`, `REO-05`). The plan carries the
/// group's sealed generations, so neither the rewind nor the descriptor write
/// has to guess which capability's records are authoritative.
pub(super) enum RollbackTail {
    /// `current` still lives in the undo-logged tail; replay its log.
    Unwind { newest: Option<SealedGen> },
    /// `current` lies inside the newest sealed generation; retire it.
    Retire {
        newest: SealedGen,
        older: Option<SealedGen>,
    },
}

/// Everything one rollback step needs beyond the writer's own state.
pub(super) struct RollbackStep<'a> {
    pub plan: RollbackTail,
    pub capabilities: IndexCapabilities,
    pub current: IndexWatermark,
    pub prev: Option<IndexWatermark>,
    pub batch: &'a mut BufferedWriteBatch,
}
struct CreationsAcross<'a> {
    tail_gens: SealedTxOrdinals<'a>,
    script_gens: SealedTxOrdinals<'a>,
}

impl CreationOrdinals for CreationsAcross<'_> {
    fn creation_ordinal(&self, txid: &[u8; 32]) -> Result<Option<u32>, IndexError> {
        match self.script_gens.creation_ordinal(txid)? {
            Some(ordinal) => Ok(Some(ordinal)),
            None => self.tail_gens.creation_ordinal(txid),
        }
    }
}

impl RollbackTail {
    /// The generation the post-rollback descriptors publish: the newest
    /// generation the capability group still holds after this step.
    fn published_newest(&self) -> Option<SealedGen> {
        match self {
            Self::Unwind { newest } => *newest,
            Self::Retire { older, .. } => *older,
        }
    }

    /// The watermark this step rewinds to. Retiring a generation moves the
    /// group to the adjacent older generation, so the plan carries that
    /// generation itself instead of re-reading a TxLookup-only list.
    pub(super) fn rewind(
        &self,
        prev: Option<IndexWatermark>,
    ) -> Result<Option<IndexWatermark>, IndexError> {
        let Self::Retire { newest, older } = self else {
            return Ok(prev);
        };
        if newest.coverage.first_height == 0 {
            return Ok(None);
        }
        let older = older.ok_or(IndexError::CorruptTailLog {
            height: newest.coverage.first_height,
        })?;
        if older.coverage.last_height.checked_add(1) != Some(newest.coverage.first_height) {
            return Err(IndexError::CorruptTailLog {
                height: newest.coverage.first_height,
            });
        }
        Ok(Some(IndexWatermark {
            height: older.coverage.last_height,
            hash: older.coverage.last_hash,
        }))
    }
}

/// The sealed generations the capability group holds, ascending by generation
/// id (`REO-04`, `REO-05`).
///
/// Each tail-bound capability keeps its own sealed records, and a seal writes
/// records only for the capabilities enabled at the time. Reading one
/// capability's list therefore misses generations that a differently enabled
/// configuration sealed, so the plan unions every capability in the group and
/// refuses a generation whose records disagree on coverage.
fn group_sealed_generations(
    snapshot: &dyn KvSnapshot,
    capabilities: IndexCapabilities,
) -> Result<Vec<SealedGen>, IndexError> {
    let mut sealed: BTreeMap<u64, SealedGen> = BTreeMap::new();
    for capability in segment_capabilities(capabilities) {
        for record in sealed_generations(snapshot, capability)? {
            let existing = sealed.get(&record.gen_id);
            if existing.is_some_and(|existing| existing != &record) {
                return Err(IndexError::CorruptTailLog {
                    height: record.coverage.first_height,
                });
            }
            sealed.entry(record.gen_id).or_insert(record);
        }
    }
    Ok(sealed.into_values().collect())
}

impl<S: KvStore> IndexWriter<S> {
    pub(super) fn tail_for(
        &mut self,
        current: Option<IndexWatermark>,
    ) -> Result<TailWriterState, IndexError> {
        let expected = current.map(|watermark| (watermark.height, watermark.hash));
        if let Some(state) = self.tail.take().filter(|state| state.at == expected) {
            return Ok(state);
        }
        let snapshot = self.indexer.store.snapshot()?;
        tail::load(snapshot.as_ref())
    }

    pub(super) fn append_forward_tail(
        &self,
        state: &mut TailWriterState,
        blocks: &[(CommittedBlock, PreparedTail)],
        batch: &mut BufferedWriteBatch,
    ) -> Result<(), IndexError> {
        let snapshot = self.indexer.store.snapshot()?;
        let gens = state.sealed.clone();
        let script_gens = sealed_generations(snapshot.as_ref(), IndexCapability::ScriptHistory)?;
        let older = CreationsAcross {
            tail_gens: SealedTxOrdinals {
                snapshot: snapshot.as_ref(),
                gens: &gens,
            },
            script_gens: SealedTxOrdinals {
                snapshot: snapshot.as_ref(),
                gens: &script_gens,
            },
        };
        for (block, prepared) in blocks {
            tail::append_prepared_tail_block(
                batch,
                block,
                prepared,
                state,
                &older,
                snapshot
                    .get(ColumnFamily::IdxMeta, &tail::log_key_for(block.height))?
                    .as_deref(),
            )?;
        }
        Ok(())
    }

    /// Plans one rollback step from the sealed state of the capability group
    /// being rolled back (`REO-04`, `REO-05`): a generation counts as sealed
    /// only for the capabilities that hold its record.
    pub(super) fn plan_rollback_tail(
        snapshot: &dyn KvSnapshot,
        capabilities: IndexCapabilities,
        current: IndexWatermark,
    ) -> Result<RollbackTail, IndexError> {
        let sealed = group_sealed_generations(snapshot, capabilities)?;
        let Some(newest) = sealed.last().copied() else {
            return Ok(RollbackTail::Unwind { newest: None });
        };
        if newest.coverage.last_height < current.height {
            return Ok(RollbackTail::Unwind {
                newest: Some(newest),
            });
        }
        let older = sealed
            .iter()
            .copied()
            .filter(|sealed| sealed.gen_id < newest.gen_id)
            .max_by_key(|sealed| sealed.gen_id);
        Ok(RollbackTail::Retire { newest, older })
    }

    pub(super) fn apply_rollback_tail(
        &self,
        state: &mut TailWriterState,
        step: RollbackStep<'_>,
    ) -> Result<(), IndexError> {
        if step.capabilities == IndexCapabilities::SCRIPT_LIVE
            && self
                .indexer
                .store
                .get(
                    ColumnFamily::IdxMeta,
                    &tail::log_key_for(step.current.height),
                )?
                .is_none()
        {
            return Ok(());
        }
        let RollbackStep {
            plan,
            capabilities,
            current,
            prev,
            batch,
        } = step;
        let published_newest = plan.published_newest();
        let first_height = match plan {
            RollbackTail::Unwind { .. } => {
                let snapshot = self.indexer.store.snapshot()?;
                let undone = tail::unwind_tail_block(batch, snapshot.as_ref(), current.height)?;
                drop(snapshot);
                if !undone {
                    return Err(IndexError::CorruptTailLog {
                        height: current.height,
                    });
                }
                state.pop_newest_block();
                state.first_height()
            }
            RollbackTail::Retire { newest, .. } => {
                state.sealed.retain(|sealed| sealed.gen_id != newest.gen_id);
                segment::stage_retirement(
                    self.indexer.store.as_ref(),
                    batch,
                    segment_capabilities(capabilities).collect(),
                    newest.gen_id,
                )?;
                None
            }
        };
        tail::put_generation_descriptors(
            batch,
            segment_capabilities(capabilities),
            tail::TailBounds {
                newest: published_newest,
                first_height,
                at: prev.map(|watermark| (watermark.height, watermark.hash)),
            },
        );
        Ok(())
    }

    pub fn restore_tail_bounds(&mut self) -> Result<(), IndexError> {
        let (_, watermarks) = self.fenced_watermarks()?;
        let state = self.tail_for(watermarks.tx_lookup)?;
        if !state.admits(0, 0) {
            let cut = state
                .cut_before_append(0)
                .ok_or(IndexError::CorruptTailLog { height: 0 })?;
            self.seal_through(&state, cut, IndexCapabilities::ALL)?;
        }
        self.tail = None;
        Ok(())
    }

    pub(super) fn seal_through(
        &self,
        state: &TailWriterState,
        cut: u32,
        capabilities: IndexCapabilities,
    ) -> Result<(), IndexError> {
        segment::seal_tail_generation(
            self.indexer.store.as_ref(),
            state.next_gen_id,
            cut,
            capabilities,
            self.seal_scratch
                .as_deref()
                .ok_or(IndexError::SealScratchUnset)?,
        )
    }
}

fn segment_capabilities(capabilities: IndexCapabilities) -> impl Iterator<Item = IndexCapability> {
    capabilities
        .iter()
        .filter(|capability| *capability != IndexCapability::ScriptLive)
}

/// Upper bound on the bytes one block's tail append writes. The append runs
/// on a scratch state that takes every state-dependent branch at its widest:
/// each spend resolves, ordinals take the widest varint, and each stats row
/// is charged the prior value its undo-log entry may carry.
pub(super) fn planned_tail_bytes(
    block: &CommittedBlock,
    prepared: &PreparedTail,
) -> Result<IndexRowBytes, IndexError> {
    let mut batch = BufferedWriteBatch::default();
    let mut state = TailWriterState::new();
    state.next_ordinal = u32::MAX;
    tail::append_prepared_tail_block(
        &mut batch,
        block,
        prepared,
        &mut state,
        &tail::AllCreated,
        None,
    )?;
    let mut bytes = IndexRowBytes::ZERO;
    let mut stats_rows = 0usize;
    for op in batch.into_ops() {
        let BatchOp::Put { cf, key, value } = op else {
            continue;
        };
        if cf == ColumnFamily::ScriptStats {
            stats_rows += 1;
        }
        let family = match cf {
            ColumnFamily::TxDir => &mut bytes.tx_lookup,
            ColumnFamily::ScriptDict
            | ColumnFamily::ScriptPost
            | ColumnFamily::SpendDir
            | ColumnFamily::ScriptStats => &mut bytes.script_history,
            ColumnFamily::Filters => &mut bytes.filters,
            ColumnFamily::IdxMeta => &mut bytes.tail_log,
            _ => continue,
        };
        let added = key
            .len()
            .checked_add(value.len())
            .ok_or(IndexError::MutationSizeOverflow)?;
        *family = family
            .checked_add(added)
            .ok_or(IndexError::MutationSizeOverflow)?;
    }
    let prior_log_bytes = stats_rows
        .checked_mul(STATS_PRIOR_LOG_BYTES)
        .ok_or(IndexError::MutationSizeOverflow)?;
    bytes.tail_log = bytes
        .tail_log
        .checked_add(prior_log_bytes)
        .ok_or(IndexError::MutationSizeOverflow)?;
    Ok(bytes)
}

#[cfg(test)]
mod rollback_retire_tests {
    use super::super::{
        ConsumerCursorUpdate, IndexCapabilities, IndexCapability, IndexError, IndexWatermark,
        IndexWriter, PreparedBatch, PreparedBatchLimits, SpentCoin, SpentCoins,
    };
    use crate::{IndexReader, ScriptHash};
    use bitcoin_rs_consensus::primitives::{
        Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, OutPoint, Script,
        Sequence, Tx, TxIn, TxOut, Txid, Witness, consensus_bytes, encode,
    };
    use bitcoin_rs_storage::{ColumnFamily, KvStore, MemoryKvStore, PrefixScanLimit};
    use std::sync::Arc;

    #[derive(Debug, PartialEq, Eq)]
    struct StoredRow {
        family: ColumnFamily,
        key: Vec<u8>,
        value: Vec<u8>,
    }

    struct FixtureScripts;

    static FIXTURE_SPENT_SCRIPT: [u8; 2] = [0x51, 0x01];

    impl SpentCoins for FixtureScripts {
        fn spent_coin(&self, _txid: &[u8; 32], _vout: u32) -> Option<SpentCoin<'_>> {
            Some(SpentCoin {
                script: FIXTURE_SPENT_SCRIPT.as_slice(),
                value: 0,
                height: 0,
                coinbase: false,
            })
        }
    }

    fn tx(previous_output: OutPoint, script_pubkey: Vec<u8>) -> Tx {
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output,
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(5_000),
                script_pubkey: script_pubkey.into(),
            }],
        }
    }

    fn block_with_prev(txs: Vec<Tx>, prev: BlockHash, nonce: u32) -> Block {
        Block {
            header: Header {
                version: 1,
                prev_blockhash: prev,
                merkle_root: Hash256::default(),
                time: 0,
                bits: CompactTarget::from_consensus(0),
                nonce,
            },
            txs,
        }
    }

    fn commit_block(
        writer: &mut IndexWriter<MemoryKvStore>,
        height: u32,
        body: &[u8],
    ) -> Result<IndexWatermark, crate::portable::TestError> {
        let header = body
            .get(..crate::types::HEADER_ROW_SIZE)
            .ok_or("short body")?;
        let hash = encode::double_sha256(header).to_le_bytes();
        let prepared = writer.prepare_block_with_spent_scripts(
            IndexCapabilities::HISTORICAL,
            height,
            hash,
            body,
            &FixtureScripts,
        )?;
        let mut batch = PreparedBatch::new(PreparedBatchLimits {
            max_rows: usize::MAX,
            max_bytes: usize::MAX,
        });
        if batch.try_push(prepared).is_err() {
            return Err("non-contiguous prepare".into());
        }
        Ok(writer.commit_forward(batch)?)
    }

    fn data_rows(store: &MemoryKvStore) -> Result<Vec<StoredRow>, crate::portable::TestError> {
        let mut rows = Vec::new();
        for cf in [
            ColumnFamily::TxDir,
            ColumnFamily::ScriptDict,
            ColumnFamily::ScriptPost,
            ColumnFamily::SpendDir,
            ColumnFamily::ScriptStats,
            ColumnFamily::Filters,
            ColumnFamily::BlockHeaders,
            ColumnFamily::ScriptLive,
        ] {
            for row in store.iter_prefix(cf, &[])? {
                let (key, value) = row?;
                rows.push(StoredRow {
                    family: cf,
                    key,
                    value,
                });
            }
        }
        rows.sort_by(|left, right| {
            (
                left.family.name(),
                left.key.as_slice(),
                left.value.as_slice(),
            )
                .cmp(&(
                    right.family.name(),
                    right.key.as_slice(),
                    right.value.as_slice(),
                ))
        });
        Ok(rows)
    }

    fn sealed_record_count(store: &MemoryKvStore) -> Result<usize, crate::portable::TestError> {
        Ok(store
            .iter_prefix(
                ColumnFamily::IdxMeta,
                &crate::segment::sealed_gen_prefix(IndexCapability::TxLookup),
            )?
            .count())
    }

    fn sealed_count(
        store: &MemoryKvStore,
        capability: IndexCapability,
    ) -> Result<usize, crate::portable::TestError> {
        Ok(store
            .iter_prefix(
                ColumnFamily::IdxMeta,
                &crate::segment::sealed_gen_prefix(capability),
            )?
            .count())
    }

    fn prefix_rows(
        store: &MemoryKvStore,
        family: ColumnFamily,
        prefix: &[u8],
    ) -> Result<Vec<Vec<u8>>, crate::portable::TestError> {
        let mut keys = Vec::new();
        for item in store.iter_prefix(family, prefix)? {
            let (key, _value) = item?;
            keys.push(key);
        }
        Ok(keys)
    }

    fn generation(
        store: &MemoryKvStore,
        capability: IndexCapability,
    ) -> Result<Option<crate::segment::GenerationDescriptor>, crate::portable::TestError> {
        Ok(store
            .get(
                ColumnFamily::IdxMeta,
                &crate::segment::meta_gen_key(capability),
            )?
            .as_deref()
            .and_then(crate::segment::IndexGeneration::decode_meta_value))
    }

    fn commit_filter_block(
        writer: &mut IndexWriter<MemoryKvStore>,
        height: u32,
        body: &[u8],
    ) -> Result<IndexWatermark, crate::portable::TestError> {
        let header = body
            .get(..crate::types::HEADER_ROW_SIZE)
            .ok_or("short body")?;
        let hash = encode::double_sha256(header).to_le_bytes();
        let prepared = writer.prepare_block_with_spent_scripts(
            IndexCapabilities::COMPACT_FILTERS,
            height,
            hash,
            body,
            &FixtureScripts,
        )?;
        let mut batch = PreparedBatch::new(PreparedBatchLimits {
            max_rows: usize::MAX,
            max_bytes: usize::MAX,
        });
        if batch.try_push(prepared).is_err() {
            return Err("non-contiguous prepare".into());
        }
        Ok(writer.commit_forward(batch)?)
    }

    fn filter_chain() -> (Vec<u8>, Vec<u8>) {
        let first = block_with_prev(
            vec![tx(
                OutPoint::new(Txid(Hash256::from_le_bytes(&[0xa1; 32])), 0),
                vec![0x51],
            )],
            BlockHash::default(),
            1,
        );
        let first_body = consensus_bytes(&first);
        let second = block_with_prev(
            vec![tx(
                OutPoint::new(Txid(Hash256::from_le_bytes(&[0xb2; 32])), 0),
                vec![0x52],
            )],
            first.block_hash(),
            2,
        );
        (first_body, consensus_bytes(&second))
    }

    // PRJ-05, REO-04, REO-05
    #[test]
    fn filter_only_rollback_across_a_seal_retires_the_generation()
    -> Result<(), crate::portable::TestError> {
        let scratch = tempfile::tempdir()?;
        let store = Arc::new(MemoryKvStore::new());
        let mut writer = IndexWriter::open(Arc::clone(&store), 1)?
            .with_seal_scratch(scratch.path().to_path_buf());
        let (first_body, second_body) = filter_chain();
        let base = commit_filter_block(&mut writer, 0, &first_body)?;
        let tip = commit_filter_block(&mut writer, 1, &second_body)?;

        let state = writer.tail_for(Some(tip))?;
        writer.seal_through(&state, tip.height, IndexCapabilities::COMPACT_FILTERS)?;
        writer.tail = None;
        assert_eq!(sealed_count(&store, IndexCapability::CompactFilters)?, 1);
        assert_eq!(sealed_count(&store, IndexCapability::TxLookup)?, 0);
        assert!(
            prefix_rows(
                &store,
                ColumnFamily::IdxMeta,
                crate::segment::tail::LOG_PREFIX
            )?
            .is_empty(),
            "the seal moves every undo log into the generation"
        );
        let sealed_filters = prefix_rows(
            &store,
            ColumnFamily::Filters,
            &crate::segment::format::gen_prefix_start(1),
        )?;
        assert_eq!(sealed_filters.len(), 2, "both heights live in generation 1");

        let (fence, watermarks) = writer.fenced_watermarks()?;
        assert_eq!(watermarks.compact_filters, Some(tip));
        writer.commit_rollback_one_for_with_cursor_with_spent_scripts(
            fence,
            IndexCapabilities::COMPACT_FILTERS,
            Some(base),
            &second_body,
            ConsumerCursorUpdate::Clear,
            &FixtureScripts,
        )?;

        assert_eq!(
            writer.watermarks()?.compact_filters,
            None,
            "retiring the generation removes every covered height, including the block below the sealed tip"
        );
        assert_eq!(
            sealed_count(&store, IndexCapability::CompactFilters)?,
            0,
            "the retired generation leaves the published set"
        );
        assert!(
            prefix_rows(
                &store,
                ColumnFamily::Filters,
                &crate::segment::format::gen_prefix_start(1)
            )?
            .is_empty(),
            "retirement clears the sealed filter rows"
        );
        assert!(
            prefix_rows(&store, ColumnFamily::IdxMeta, b"retire/")?.is_empty(),
            "retirement leaves no tombstone behind"
        );
        let desc = generation(&store, IndexCapability::CompactFilters)?.ok_or("descriptor")?;
        assert_eq!(desc.gen_id, 0, "the descriptor names no retired generation");
        assert!(
            desc.tail.tail_lo > desc.tail.tail_hi,
            "the retired tail window is empty"
        );
        Ok(())
    }

    // REO-04, REO-05
    #[test]
    fn joint_historical_rollback_reclaims_the_shared_transaction_directory()
    -> Result<(), crate::portable::TestError> {
        const ROW_LIMIT: PrefixScanLimit = PrefixScanLimit {
            max_rows: 16,
            max_bytes: 1 << 20,
        };
        let scratch = tempfile::tempdir()?;
        let store = Arc::new(MemoryKvStore::new());
        let mut writer = IndexWriter::open(Arc::clone(&store), 1)?
            .with_seal_scratch(scratch.path().to_path_buf());

        let funded = tx(
            OutPoint::new(Txid(Hash256::from_le_bytes(&[0xa1; 32])), 0),
            vec![0x51],
        );
        let funding_txid = funded.txid();
        let first = block_with_prev(vec![funded], BlockHash::default(), 1);
        let first_body = consensus_bytes(&first);
        let base = commit_block(&mut writer, 0, &first_body)?;

        let spender = tx(
            OutPoint::new(Txid(Hash256::from_le_bytes(&[0xb2; 32])), 0),
            vec![0x52],
        );
        let second = block_with_prev(vec![spender], first.block_hash(), 2);
        let second_body = consensus_bytes(&second);
        let tip = commit_block(&mut writer, 1, &second_body)?;

        let state = writer.tail_for(Some(tip))?;
        writer.seal_through(&state, tip.height, IndexCapabilities::HISTORICAL)?;
        writer.tail = None;

        assert_eq!(sealed_count(&store, IndexCapability::TxLookup)?, 1);
        assert_eq!(sealed_count(&store, IndexCapability::ScriptHistory)?, 1);
        let gen_prefix = crate::segment::format::gen_prefix_start(1);
        assert!(!prefix_rows(&store, ColumnFamily::TxDir, &gen_prefix)?.is_empty());
        assert!(!prefix_rows(&store, ColumnFamily::ScriptPost, &gen_prefix)?.is_empty());
        assert_eq!(
            writer
                .snapshot()?
                .transaction_rows(&funding_txid, ROW_LIMIT)?
                .rows
                .len(),
            1,
            "the sealed generation answers the funding transaction"
        );

        let (fence, _) = writer.fenced_watermarks()?;
        writer.commit_rollback_one_for_with_cursor_with_spent_scripts(
            fence,
            IndexCapabilities::HISTORICAL,
            Some(base),
            &second_body,
            ConsumerCursorUpdate::Clear,
            &FixtureScripts,
        )?;

        for family in [
            ColumnFamily::TxDir,
            ColumnFamily::ScriptDict,
            ColumnFamily::ScriptPost,
            ColumnFamily::SpendDir,
            ColumnFamily::ScriptStats,
        ] {
            assert!(
                prefix_rows(&store, family, &gen_prefix)?.is_empty(),
                "joint retirement reclaims the generation's {family:?} rows"
            );
        }
        assert_eq!(sealed_count(&store, IndexCapability::TxLookup)?, 0);
        assert_eq!(sealed_count(&store, IndexCapability::ScriptHistory)?, 0);
        assert!(prefix_rows(&store, ColumnFamily::IdxMeta, b"retire/")?.is_empty());
        let snapshot = writer.snapshot()?;
        assert!(
            snapshot
                .transaction_rows(&funding_txid, ROW_LIMIT)?
                .rows
                .is_empty(),
            "the retired generation answers no transaction rows"
        );
        assert!(
            snapshot
                .funding_rows(ScriptHash::from_script_bytes(&[0x51]), ROW_LIMIT)?
                .rows
                .is_empty(),
            "the retired generation answers no funding rows"
        );
        Ok(())
    }

    // REO-02, REO-04
    #[test]
    fn rollback_without_a_required_undo_log_refuses_as_corrupt_tail_log()
    -> Result<(), crate::portable::TestError> {
        let scratch = tempfile::tempdir()?;
        let store = Arc::new(MemoryKvStore::new());
        let mut writer = IndexWriter::open(Arc::clone(&store), 1)?
            .with_seal_scratch(scratch.path().to_path_buf());
        let (first_body, second_body) = filter_chain();
        let base = commit_filter_block(&mut writer, 0, &first_body)?;
        let tip = commit_filter_block(&mut writer, 1, &second_body)?;

        let mut batch = store.new_batch();
        batch.delete(
            ColumnFamily::IdxMeta,
            &crate::segment::tail::log_key_for(tip.height),
        );
        store.write_durable(batch)?;
        writer.tail = None;

        let (fence, watermarks) = writer.fenced_watermarks()?;
        assert_eq!(watermarks.compact_filters, Some(tip));
        let outcome = writer.commit_rollback_one_for_with_cursor_with_spent_scripts(
            fence,
            IndexCapabilities::COMPACT_FILTERS,
            Some(base),
            &second_body,
            ConsumerCursorUpdate::Clear,
            &FixtureScripts,
        );
        assert!(
            matches!(
                outcome,
                Err(IndexError::CorruptTailLog { height }) if height == tip.height
            ),
            "a height that must hold an undo log refuses instead of committing a rewind: {outcome:?}"
        );
        assert_eq!(
            writer.watermarks()?.compact_filters,
            Some(tip),
            "the refused rollback commits nothing"
        );
        assert_eq!(
            prefix_rows(
                &store,
                ColumnFamily::Filters,
                &crate::segment::format::gen_prefix_start(0)
            )?
            .len(),
            2,
            "the refused rollback keeps every filter row"
        );
        Ok(())
    }

    // REO-04, REO-05
    #[test]
    fn fault_between_retire_plan_and_commit_leaves_watermark_and_rows_in_agreement()
    -> Result<(), crate::portable::TestError> {
        let dir = tempfile::tempdir()?;
        let scratch = tempfile::tempdir()?;
        let store = Arc::new(MemoryKvStore::new());
        let mut writer = IndexWriter::open(Arc::clone(&store), 1)?
            .with_seal_scratch(scratch.path().to_path_buf());

        let funded = tx(
            OutPoint::new(Txid(Hash256::from_le_bytes(&[0xa1; 32])), 0),
            vec![0x51],
        );
        let first = block_with_prev(vec![funded], BlockHash::default(), 1);
        let first_body = consensus_bytes(&first);
        let base = commit_block(&mut writer, 0, &first_body)?;

        let spender = tx(
            OutPoint::new(Txid(Hash256::from_le_bytes(&[0xb2; 32])), 0),
            vec![0x52],
        );
        let second = block_with_prev(vec![spender], first.block_hash(), 2);
        let second_body = consensus_bytes(&second);
        let tip = commit_block(&mut writer, 1, &second_body)?;

        let state = writer.tail_for(Some(tip))?;
        writer.seal_through(&state, tip.height, IndexCapabilities::HISTORICAL)?;
        writer.tail = None;

        assert_eq!(writer.watermarks()?.tx_lookup, Some(tip));
        assert_eq!(sealed_record_count(&store)?, 1);
        let before = data_rows(&store)?;
        assert!(!before.is_empty());

        crate::segment::arm_retire_fault(Some(crate::segment::RetireFault::AfterTombstone));
        let (fence, _) = writer.fenced_watermarks()?;
        let outcome = writer.commit_rollback_one_for_with_cursor_with_spent_scripts(
            fence,
            IndexCapabilities::HISTORICAL,
            Some(base),
            &second_body,
            ConsumerCursorUpdate::Clear,
            &FixtureScripts,
        );
        crate::segment::arm_retire_fault(None);
        assert!(matches!(
            outcome,
            Err(IndexError::InjectedFault { stage: "retire" })
        ));
        store.flush()?;
        store.checkpoint(dir.path())?;
        drop(writer);
        drop(store);

        let store = Arc::new(MemoryKvStore::open_checkpoint(dir.path())?);
        let writer = IndexWriter::open(Arc::clone(&store), 2)?;
        assert_eq!(writer.watermarks()?.tx_lookup, Some(tip));
        assert_eq!(sealed_record_count(&store)?, 1);
        assert_eq!(data_rows(&store)?, before);
        Ok(())
    }

    struct FrontierCoins(Vec<Txid>);

    impl SpentCoins for FrontierCoins {
        fn spent_coin(&self, txid: &[u8; 32], vout: u32) -> Option<SpentCoin<'_>> {
            let height = self.0.iter().position(|id| id.as_bytes() == txid)?;
            (vout == 0).then_some(SpentCoin {
                script: &FIXTURE_SPENT_SCRIPT,
                value: 5_000,
                height: u32::try_from(height).ok()?,
                coinbase: height < 2,
            })
        }
    }

    struct PriorFrontierCoins<'a> {
        coins: &'a FrontierCoins,
        height: usize,
    }

    impl SpentCoins for PriorFrontierCoins<'_> {
        fn spent_coin(&self, txid: &[u8; 32], vout: u32) -> Option<SpentCoin<'_>> {
            self.coins.0[..self.height]
                .iter()
                .find(|id| id.as_bytes() == txid)?;
            self.coins.spent_coin(txid, vout)
        }
    }

    fn frontier_chain() -> (Vec<Block>, FrontierCoins) {
        let mut blocks = Vec::new();
        let mut ids = Vec::new();
        let mut previous = OutPoint::null();
        let mut parent = BlockHash::default();
        for nonce in 0..3 {
            let mut transaction = tx(previous, FIXTURE_SPENT_SCRIPT.to_vec());
            if nonce == 1 {
                transaction.inputs[0].previous_output = OutPoint::null();
                transaction.inputs[0].script_sig = vec![1].into();
            }
            previous = OutPoint::new(transaction.txid(), 0);
            ids.push(transaction.txid());
            let block = block_with_prev(vec![transaction], parent, nonce);
            parent = block.block_hash();
            blocks.push(block);
        }
        (blocks, FrontierCoins(ids))
    }

    fn commit_frontier_block(
        writer: &mut IndexWriter<MemoryKvStore>,
        caps: IndexCapabilities,
        height: u32,
        block: &Block,
        coins: &FrontierCoins,
    ) -> Result<IndexWatermark, crate::portable::TestError> {
        let prepared = writer.prepare_block_with_spent_scripts(
            caps,
            height,
            *block.block_hash().as_bytes(),
            &consensus_bytes(block),
            &PriorFrontierCoins {
                coins,
                height: usize::try_from(height)?,
            },
        )?;
        let mut batch = PreparedBatch::new(PreparedBatchLimits {
            max_rows: usize::MAX,
            max_bytes: usize::MAX,
        });
        if batch.try_push(prepared).is_err() {
            return Err("one frontier fixture block must fit".into());
        }
        Ok(writer.commit_forward(batch)?)
    }

    const FRONTIER_LIMIT: PrefixScanLimit = PrefixScanLimit {
        max_rows: 100,
        max_bytes: 1 << 20,
    };

    fn assert_frontier_queries(
        writer: &IndexWriter<MemoryKvStore>,
        blocks: &[Block],
        present: usize,
    ) -> Result<(), crate::portable::TestError> {
        let snapshot = writer.snapshot()?;
        for (height, block) in blocks.iter().enumerate() {
            let rows = snapshot.transaction_rows(&block.txs[0].txid(), FRONTIER_LIMIT)?;
            assert!(rows.complete);
            assert_eq!(rows.rows.len(), usize::from(height < present));
            if height < present {
                let positions = crate::types::TxPositionValue::decode(&rows.rows[0].value)
                    .ok_or("fixture transaction positions decode")?;
                assert_eq!(positions.len(), 1);
                assert_eq!(positions[0].offset(), 81);
                assert_eq!(
                    positions[0].byte_len(),
                    u32::try_from(consensus_bytes(block).len() - 81)?
                );
            }
        }
        let history = snapshot.funding_rows(
            ScriptHash::from_script_bytes(&FIXTURE_SPENT_SCRIPT),
            FRONTIER_LIMIT,
        )?;
        assert!(history.complete);
        let mut actual = Vec::new();
        for row in history.rows {
            for occurrence in crate::types::ScriptHistoryOccurrence::decode_all(&row.value)
                .ok_or("fixture script occurrences decode")?
            {
                assert_eq!(
                    occurrence.scripthash,
                    ScriptHash::from_script_bytes(&FIXTURE_SPENT_SCRIPT),
                );
                actual.push((
                    row.row.height(),
                    occurrence.txid,
                    occurrence.position.offset(),
                    occurrence.position.byte_len(),
                    occurrence.flags,
                ));
            }
        }
        actual.sort();
        let mut expected = Vec::new();
        for (height, block) in blocks.iter().take(present).enumerate() {
            let mut events = vec![crate::types::ScriptHistoryOccurrence::FUNDING];
            if blocks[height].txs[0].inputs[0].previous_output != OutPoint::null() {
                events.push(crate::types::ScriptHistoryOccurrence::SPENDING);
            }
            for flags in events {
                expected.push((
                    u32::try_from(height)?,
                    *block.txs[0].txid().as_bytes(),
                    81,
                    u32::try_from(consensus_bytes(block).len() - 81)?,
                    flags,
                ));
            }
        }
        expected.sort();
        assert_eq!(
            actual, expected,
            "fixture-derived transaction identities and positions"
        );
        Ok(())
    }

    // REO-02, REO-04, REO-05
    #[test]
    fn sealed_history_rollback_rewinds_every_script_live_block()
    -> Result<(), crate::portable::TestError> {
        let scratch = tempfile::tempdir()?;
        let store = Arc::new(MemoryKvStore::new());
        let mut writer = IndexWriter::open(Arc::clone(&store), 1)?
            .with_seal_scratch(scratch.path().to_path_buf());
        let (blocks, coins) = frontier_chain();
        let mut marks = Vec::new();
        for (height, block) in blocks.iter().enumerate() {
            marks.push(commit_frontier_block(
                &mut writer,
                IndexCapabilities::TX_AND_SCRIPTS,
                u32::try_from(height)?,
                block,
                &coins,
            )?);
        }
        assert_frontier_queries(&writer, &blocks, 3)?;
        let state = writer.tail_for(Some(marks[2]))?;
        writer.seal_through(&state, 2, IndexCapabilities::HISTORICAL)?;
        writer.tail = None;
        assert_eq!(sealed_count(&store, IndexCapability::ScriptHistory)?, 1);
        for height in (0..3).rev() {
            let before = writer.snapshot()?.live_rows(
                ScriptHash::from_script_bytes(&FIXTURE_SPENT_SCRIPT),
                FRONTIER_LIMIT,
            )?;
            assert!(before.complete);
            assert_eq!(
                before.rows.len(),
                usize::from(height > 0),
                "only the current non-genesis fixture output is live"
            );
            if height > 0 {
                assert_eq!(
                    before.rows[0].as_bytes(),
                    crate::ScriptLiveRow::new(
                        ScriptHash::from_script_bytes(&FIXTURE_SPENT_SCRIPT),
                        &OutPoint::new(coins.0[height], 0),
                    )
                    .as_bytes(),
                );
                let encoded = store
                    .get(ColumnFamily::ScriptLive, before.rows[0].as_bytes())?
                    .ok_or("queried fixture coin must be stored")?;
                let coin = crate::ScriptLiveCoin::decode_value(&encoded)?;
                assert_eq!(coin.value, 5_000);
                assert_eq!(coin.height, u32::try_from(height)?);
                assert_eq!(coin.coinbase, height == 1);
            }
            let prev = height.checked_sub(1).map(|index| marks[index]);
            let (fence, _) = writer.fenced_watermarks()?;
            writer.commit_rollback_one_for_with_cursor_with_spent_scripts(
                fence,
                if height == 2 {
                    IndexCapabilities::TX_AND_SCRIPTS
                } else {
                    IndexCapabilities::SCRIPT_LIVE
                },
                prev,
                &consensus_bytes(&blocks[height]),
                ConsumerCursorUpdate::Keep,
                &PriorFrontierCoins {
                    coins: &coins,
                    height,
                },
            )?;
            assert_eq!(
                writer.watermarks()?.script_live,
                prev,
                "live frontier moves one actual block even when history retires as a group",
            );
            assert_eq!(writer.watermarks()?.script_history, None);
            assert_eq!(writer.watermarks()?.tx_lookup, None);
        }
        assert!(
            writer
                .snapshot()?
                .live_rows(
                    ScriptHash::from_script_bytes(&FIXTURE_SPENT_SCRIPT),
                    FRONTIER_LIMIT,
                )?
                .rows
                .is_empty()
        );
        Ok(())
    }

    // PRJ-05, REO-02, IDX-07
    #[test]
    fn filter_first_restart_preserves_backfilled_transaction_identities()
    -> Result<(), crate::portable::TestError> {
        let checkpoint = tempfile::tempdir()?;
        let store = Arc::new(MemoryKvStore::new());
        let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
        let (blocks, coins) = frontier_chain();
        for (height, block) in blocks.iter().take(2).enumerate() {
            commit_frontier_block(
                &mut writer,
                IndexCapabilities::COMPACT_FILTERS,
                u32::try_from(height)?,
                block,
                &coins,
            )?;
        }
        commit_frontier_block(
            &mut writer,
            IndexCapabilities::HISTORICAL,
            0,
            &blocks[0],
            &coins,
        )?;
        store.flush()?;
        store.checkpoint(checkpoint.path())?;
        drop(writer);
        drop(store);
        let store = Arc::new(MemoryKvStore::open_checkpoint(checkpoint.path())?);
        let mut writer = IndexWriter::open(store, 2)?;
        commit_frontier_block(
            &mut writer,
            IndexCapabilities::HISTORICAL,
            1,
            &blocks[1],
            &coins,
        )?;
        assert_frontier_queries(&writer, &blocks, 2)?;
        Ok(())
    }

    // PRJ-05, REO-02, IDX-07
    #[test]
    fn filter_artifact_restart_preserves_transaction_ordinal_frontier()
    -> Result<(), crate::portable::TestError> {
        use crate::portable::{
            ManifestArtifactTarget, SpillBudget, attach_compact_filter_artifact,
            write_compact_filter_artifact,
        };
        let scratch = tempfile::tempdir()?;
        let checkpoint = tempfile::tempdir()?;
        let store = Arc::new(MemoryKvStore::new());
        let mut writer = IndexWriter::open(Arc::clone(&store), 1)?
            .with_seal_scratch(scratch.path().to_path_buf());
        let (blocks, coins) = frontier_chain();
        let mut base = None;
        let source_store = Arc::new(MemoryKvStore::new());
        let mut source = IndexWriter::open(source_store, 1)?;
        for (height, block) in blocks.iter().take(2).enumerate() {
            base = Some(commit_frontier_block(
                &mut writer,
                IndexCapabilities::HISTORICAL,
                u32::try_from(height)?,
                block,
                &coins,
            )?);
            commit_frontier_block(
                &mut source,
                IndexCapabilities::COMPACT_FILTERS,
                u32::try_from(height)?,
                block,
                &coins,
            )?;
        }
        let base = base.ok_or("fixture base")?;
        assert_frontier_queries(&writer, &blocks, 2)?;
        let state = writer.tail_for(Some(base))?;
        writer.seal_through(&state, 1, IndexCapabilities::HISTORICAL)?;
        let hashes: Vec<_> = blocks
            .iter()
            .take(2)
            .map(|block| *block.block_hash().as_bytes())
            .collect();
        let artifact_path = scratch.path().join("frontier-filters.dat");
        let artifact = write_compact_filter_artifact(
            &source,
            bitcoin_rs_consensus::primitives::Network::Regtest,
            &hashes,
            &artifact_path,
        )?;
        let receiver = parking_lot::RwLock::new(writer);
        let target = ManifestArtifactTarget {
            artifact_path,
            base_height: base.height,
            base_hash: base.hash,
            floor: 0,
            network: bitcoin_rs_consensus::primitives::Network::Regtest,
            index_format: crate::index_format_version(),
            sha256: artifact.sha256,
            size_bytes: artifact.bytes,
            chain_tx_count: 2,
        };
        assert_eq!(
            attach_compact_filter_artifact(
                &receiver,
                &target,
                scratch.path(),
                &SpillBudget::new(u64::MAX),
            )?,
            2
        );
        assert_frontier_queries(&receiver.read(), &blocks, 2)?;
        store.flush()?;
        store.checkpoint(checkpoint.path())?;
        drop(receiver);
        drop(store);
        let store = Arc::new(MemoryKvStore::open_checkpoint(checkpoint.path())?);
        let mut writer = IndexWriter::open(store, 2)?;
        commit_frontier_block(
            &mut writer,
            IndexCapabilities::HISTORICAL,
            2,
            &blocks[2],
            &coins,
        )?;
        assert_frontier_queries(&writer, &blocks, 3)?;
        assert_eq!(
            writer
                .tail_for(Some(IndexWatermark {
                    height: 2,
                    hash: *blocks[2].block_hash().as_bytes(),
                }))?
                .next_ordinal,
            3,
            "three fixture transactions occupy distinct ordinals"
        );
        Ok(())
    }

    // IDX-07, REO-02, REO-04
    #[test]
    fn lagging_backfill_preserves_original_undo_and_preblock_ordinal()
    -> Result<(), crate::portable::TestError> {
        for backfill in [
            IndexCapabilities::SCRIPT_HISTORY,
            IndexCapabilities::COMPACT_FILTERS,
        ] {
            let store = Arc::new(MemoryKvStore::new());
            let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
            let (blocks, coins) = frontier_chain();
            let initial = if backfill == IndexCapabilities::SCRIPT_HISTORY {
                IndexCapabilities::TX_LOOKUP
            } else {
                IndexCapabilities::HISTORICAL
            };
            let base = commit_frontier_block(&mut writer, initial, 0, &blocks[0], &coins)?;
            let tip = commit_frontier_block(&mut writer, initial, 1, &blocks[1], &coins)?;
            for (height, block) in blocks.iter().take(2).enumerate() {
                commit_frontier_block(
                    &mut writer,
                    backfill,
                    u32::try_from(height)?,
                    block,
                    &coins,
                )?;
            }
            assert_frontier_queries(&writer, &blocks, 2)?;
            let (fence, _) = writer.fenced_watermarks()?;
            writer.commit_rollback_one_for_with_cursor_with_spent_scripts(
                fence,
                IndexCapabilities::HISTORICAL,
                Some(base),
                &consensus_bytes(&blocks[1]),
                ConsumerCursorUpdate::Keep,
                &PriorFrontierCoins {
                    coins: &coins,
                    height: 1,
                },
            )?;
            assert_frontier_queries(&writer, &blocks, 1)?;
            assert_eq!(
                writer.tail_for(Some(base))?.next_ordinal,
                1,
                "rollback restores the ordinal before the original block, not before backfill"
            );
            assert_eq!(
                commit_frontier_block(
                    &mut writer,
                    IndexCapabilities::HISTORICAL,
                    1,
                    &blocks[1],
                    &coins,
                )?,
                tip
            );
            assert_frontier_queries(&writer, &blocks, 2)?;
            for height in (0_usize..2).rev() {
                let (fence, _) = writer.fenced_watermarks()?;
                writer.commit_rollback_one_for_with_cursor_with_spent_scripts(
                    fence,
                    IndexCapabilities::HISTORICAL,
                    height.checked_sub(1).map(|_| base),
                    &consensus_bytes(&blocks[height]),
                    ConsumerCursorUpdate::Keep,
                    &PriorFrontierCoins {
                        coins: &coins,
                        height,
                    },
                )?;
                assert_frontier_queries(&writer, &blocks, height)?;
            }
            for family in [
                ColumnFamily::TxDir,
                ColumnFamily::ScriptDict,
                ColumnFamily::ScriptPost,
                ColumnFamily::ScriptStats,
                ColumnFamily::SpendDir,
                ColumnFamily::Filters,
            ] {
                assert!(
                    prefix_rows(&store, family, &crate::segment::format::gen_prefix_start(0),)?
                        .is_empty(),
                    "rollback reclaims every fixture-owned {family:?} row"
                );
            }
        }
        Ok(())
    }
}
