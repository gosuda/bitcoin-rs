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
        match self.tail_gens.creation_ordinal(txid)? {
            Some(ordinal) => Ok(Some(ordinal)),
            None => self.script_gens.creation_ordinal(txid),
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
            tail::append_prepared_tail_block(batch, block, prepared, state, &older)?;
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
    tail::append_prepared_tail_block(&mut batch, block, prepared, &mut state, &tail::AllCreated)?;
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
}
