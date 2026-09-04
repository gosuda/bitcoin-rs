//! `ScriptLive` behavior over the prepared/commit path (#225).
//!
//! Everything here drives the same `IndexWriter` API the node's worker uses,
//! with a map-backed [`SpentCoinScripts`] standing in for the undo-record
//! anchor the node supplies in production. The properties under test are the
//! ones #225 names as acceptance criteria: anchored deletes, same-block
//! cancellation, the UTXO-admission spendability predicate, identity-specific
//! point deletes, fail-closed unresolvable spends, watermark independence
//! from history, and seed-then-stamp ordering.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bitcoin::absolute::LockTime;
use bitcoin::block::{self, Header};
use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::Hash as _;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, Block, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxMerkleNode, TxOut, Txid, Witness,
};
use bitcoin_rs_index::{
    IndexCapabilities, IndexCapability, IndexError, IndexWatermark, IndexWriter,
    MAX_LIVE_SCRIPT_SIZE, PreparedBatch, PreparedBatchLimits, ScriptHash, ScriptLiveRow,
    SpentCoinScripts,
};
use bitcoin_rs_primitives::{Hash256, OutPoint as NativeOutPoint, Txid as NativeTxid};
use bitcoin_rs_storage::{
    ColumnFamily, KvIter, KvSnapshot, KvStore, PrefixScanLimit, StorageError, WriteBatch,
    WriteCondition,
};
use parking_lot::RwLock;

// --- Minimal in-memory KvStore -------------------------------------------

#[derive(Default)]
struct MemoryStore {
    cfs: RwLock<[BTreeMap<Vec<u8>, Vec<u8>>; ColumnFamily::ALL.len()]>,
    fail_next_deferred: AtomicBool,
}

struct MemoryBatch {
    ops: Vec<(ColumnFamily, Vec<u8>, Option<Vec<u8>>)>,
}

impl WriteBatch for MemoryBatch {
    fn put(&mut self, cf: ColumnFamily, key: &[u8], value: &[u8]) {
        self.ops.push((cf, key.to_vec(), Some(value.to_vec())));
    }
    fn delete(&mut self, cf: ColumnFamily, key: &[u8]) {
        self.ops.push((cf, key.to_vec(), None));
    }
    fn delete_range(&mut self, _cf: ColumnFamily, _start: &[u8], _end: &[u8]) {
        panic!("range deletes are not exercised by these tests")
    }
}

impl KvStore for MemoryStore {
    type WriteBatch = MemoryBatch;

    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.cfs.read()[cf.index()].get(key).cloned())
    }
    fn new_batch(&self) -> Self::WriteBatch {
        MemoryBatch { ops: Vec::new() }
    }
    fn write(&self, batch: Self::WriteBatch) -> Result<(), StorageError> {
        let mut guard = self.cfs.write();
        for (cf, key, value) in batch.ops {
            match value {
                Some(value) => {
                    guard[cf.index()].insert(key, value);
                }
                None => {
                    guard[cf.index()].remove(&key);
                }
            }
        }
        Ok(())
    }
    fn write_durable_if(
        &self,
        conditions: &[WriteCondition<'_>],
        batch: Self::WriteBatch,
    ) -> Result<bool, StorageError> {
        let mut guard = self.cfs.write();
        let matched = conditions.iter().all(|condition| {
            let (cf, key) = condition.location();
            condition.matches(guard[cf.index()].get(key).map(Vec::as_slice))
        });
        if !matched {
            return Ok(false);
        }
        for (cf, key, value) in batch.ops {
            match value {
                Some(value) => {
                    guard[cf.index()].insert(key, value);
                }
                None => {
                    guard[cf.index()].remove(&key);
                }
            }
        }
        Ok(true)
    }
    fn write_deferred(&self, batch: Self::WriteBatch) -> Result<(), StorageError> {
        if self.fail_next_deferred.swap(false, Ordering::SeqCst) {
            return Err(StorageError::Backend(
                "injected deferred write failure".into(),
            ));
        }
        self.write(batch)
    }
    fn write_durable(&self, batch: Self::WriteBatch) -> Result<(), StorageError> {
        self.write(batch)
    }
    fn flush(&self) -> Result<(), StorageError> {
        Ok(())
    }
    // The collect is what ends the borrow of the RwLock guard; handing the
    // iterator out directly would return a reference into a dropped guard.
    #[expect(clippy::needless_collect, reason = "decouples from the lock guard")]
    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<KvIter<'a>, StorageError> {
        let rows = self.cfs.read()[cf.index()]
            .range(prefix.to_vec()..)
            .take_while(|(key, _)| key.starts_with(prefix))
            .map(|(key, value)| Ok((key.clone(), value.clone())))
            .collect::<Vec<_>>();
        Ok(Box::new(rows.into_iter()))
    }
    fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError> {
        Ok(Box::new(MemorySnapshot {
            cfs: self.cfs.read().clone(),
        }))
    }
    fn scan_prefix_bounded(
        &self,
        cf: ColumnFamily,
        prefix: &[u8],
        limit: PrefixScanLimit,
    ) -> Result<bitcoin_rs_storage::PrefixScan, StorageError> {
        let mut rows = Vec::new();
        let mut bytes = 0_usize;
        let mut complete = true;
        for (key, value) in self.cfs.read()[cf.index()]
            .range(prefix.to_vec()..)
            .take_while(|(key, _)| key.starts_with(prefix))
        {
            if rows.len() >= limit.max_rows || bytes >= limit.max_bytes {
                complete = false;
                break;
            }
            bytes += key.len() + value.len();
            rows.push((key.clone(), value.clone()));
        }
        Ok(bitcoin_rs_storage::PrefixScan { rows, complete })
    }
}

struct MemorySnapshot {
    cfs: [BTreeMap<Vec<u8>, Vec<u8>>; ColumnFamily::ALL.len()],
}

impl KvSnapshot for MemorySnapshot {
    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.cfs[cf.index()].get(key).cloned())
    }

    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<KvIter<'a>, StorageError> {
        let prefix = prefix.to_vec();
        Ok(Box::new(
            self.cfs[cf.index()]
                .iter()
                .filter(move |(key, _)| key.starts_with(&prefix))
                .map(|(key, value)| Ok((key.clone(), value.clone()))),
        ))
    }
}

// --- Anchor + block fixtures ---------------------------------------------

/// Map-backed spent-coin source: the test's stand-in for the undo record.
#[derive(Default)]
struct MapScripts(hashbrown::HashMap<(Txid, u32), Vec<u8>>);

impl MapScripts {
    fn insert(&mut self, outpoint: OutPoint, script: &ScriptBuf) {
        self.0
            .insert((outpoint.txid, outpoint.vout), script.to_bytes());
    }
}

impl SpentCoinScripts for MapScripts {
    fn script_bytes(&self, txid: &[u8; 32], vout: u32) -> Option<&[u8]> {
        self.0
            .get(&(Txid::from_byte_array(*txid), vout))
            .map(Vec::as_slice)
    }
}

fn coinbase(tag: u8) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![tag]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50),
            script_pubkey: script(0xc0 ^ tag),
        }],
    }
}

fn script(tag: u8) -> ScriptBuf {
    ScriptBuf::from_bytes(vec![0x51, tag])
}

fn spend(inputs: &[OutPoint], outputs: &[ScriptBuf]) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: inputs
            .iter()
            .map(|previous_output| TxIn {
                previous_output: *previous_output,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect(),
        output: outputs
            .iter()
            .map(|script_pubkey| TxOut {
                value: Amount::from_sat(10),
                script_pubkey: script_pubkey.clone(),
            })
            .collect(),
    }
}

fn block_bytes(prev: [u8; 32], txdata: Vec<Transaction>) -> (Vec<u8>, [u8; 32]) {
    let block = Block {
        header: Header {
            version: block::Version::ONE,
            prev_blockhash: BlockHash::from_byte_array(prev),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 0,
            bits: CompactTarget::from_consensus(0),
            nonce: 0,
        },
        txdata,
    };
    let hash = block.block_hash().to_byte_array();
    (serialize(&block), hash)
}

struct Chain {
    writer: IndexWriter<MemoryStore>,
    tip: [u8; 32],
    height: u32,
}

impl Chain {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let store = Arc::new(MemoryStore::default());
        let writer = IndexWriter::open(store, 0)?;
        Ok(Self {
            writer,
            tip: [0_u8; 32],
            height: 0,
        })
    }

    /// Prepares and commits one block carrying `txdata` with the given anchor.
    fn connect(
        &mut self,
        txdata: Vec<Transaction>,
        anchor: &MapScripts,
    ) -> Result<[u8; 32], IndexError> {
        let (body, hash) = block_bytes(self.tip, txdata);
        let prepared = self.writer.prepare_block_with_spent_scripts(
            IndexCapabilities::ALL,
            self.height,
            hash,
            &body,
            anchor,
        )?;
        let mut batch = PreparedBatch::new(PreparedBatchLimits {
            max_rows: 10_000,
            max_bytes: 10_000_000,
        });
        assert!(batch.try_push(prepared).is_ok(), "batch must admit block");
        self.writer.commit_forward(batch)?;
        self.tip = hash;
        self.height += 1;
        Ok(hash)
    }

    fn live(&self, script: &ScriptBuf) -> Vec<OutPoint> {
        let mut outpoints = self
            .writer
            .indexer()
            .iter_live_outpoints(ScriptHash::from_script_bytes(script.as_bytes()))
            .unwrap_or_else(|error| panic!("live scan failed: {error}"))
            .into_iter()
            .map(|outpoint| {
                let txid = outpoint.txid;
                let vout = outpoint.vout;
                bitcoin::OutPoint {
                    txid: bitcoin::Txid::from_byte_array(*txid.as_bytes()),
                    vout,
                }
            })
            .collect::<Vec<_>>();
        outpoints.sort_by_key(|outpoint| (*outpoint.txid.as_byte_array(), outpoint.vout));
        outpoints
    }
}

// --- Tests ----------------------------------------------------------------

/// Connect writes live rows for created outputs; a later block's anchored
/// spend removes exactly the spent outpoint and no other row of the same
/// script; disconnect restores it from the anchor.
#[test]
fn live_rows_follow_connect_spend_and_disconnect() -> Result<(), Box<dyn std::error::Error>> {
    let mut chain = Chain::new()?;
    let empty = MapScripts::default();

    // Height 0: genesis-shaped block. Its coinbase must produce no live rows.
    chain.connect(vec![coinbase(0)], &empty)?;

    // Height 1: a payment creating two outputs of one script.
    let wallet = script(0xaa);
    let pay = spend(&[OutPoint::null()], &[wallet.clone(), wallet.clone()]);
    // A null-prevout non-coinbase would be nonsense; give it a fake external
    // input the anchor can resolve.
    let external = OutPoint {
        txid: Txid::from_byte_array([7_u8; 32]),
        vout: 0,
    };
    let funding_script = script(0xbb);
    let pay = {
        let mut pay = pay;
        pay.input[0].previous_output = external;
        pay
    };
    let pay_txid = pay.compute_txid();
    let mut anchor = MapScripts::default();
    anchor.insert(external, &funding_script);
    chain.connect(vec![coinbase(1), pay], &anchor)?;

    let o0 = OutPoint {
        txid: pay_txid,
        vout: 0,
    };
    let o1 = OutPoint {
        txid: pay_txid,
        vout: 1,
    };
    assert_eq!(chain.live(&wallet), sorted(vec![o0, o1]));

    // Height 2: spend vout 0 only. The point delete must leave vout 1 alone --
    // both rows share the full 8-byte script prefix, so anything short of an
    // exact-key delete would take both.
    let sweep = spend(&[o0], &[script(0xcc)]);
    let mut anchor2 = MapScripts::default();
    anchor2.insert(o0, &wallet);
    let (body2, hash2) = block_bytes(chain.tip, vec![coinbase(2), sweep]);
    let prepared = chain.writer.prepare_block_with_spent_scripts(
        IndexCapabilities::ALL,
        chain.height,
        hash2,
        &body2,
        &anchor2,
    )?;
    let mut batch = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 10_000,
        max_bytes: 10_000_000,
    });
    assert!(batch.try_push(prepared).is_ok());
    chain.writer.commit_forward(batch)?;
    assert_eq!(chain.live(&wallet), vec![o1]);

    // Disconnect height 2: the spent output returns, the block's own outputs
    // leave. The restore script comes from the anchor, exactly as the node
    // reads it from the undo record.
    let prev = IndexWatermark {
        height: 1,
        hash: chain.tip,
    };
    chain.writer.commit_rollback_one_with_spent_scripts(
        IndexCapabilities::ALL,
        Some(prev),
        &body2,
        &anchor2,
    )?;
    assert_eq!(chain.live(&wallet), sorted(vec![o0, o1]));
    assert_eq!(chain.live(&script(0xcc)), Vec::<OutPoint>::new());
    Ok(())
}

/// A BIP30-style outpoint overwrite removes the old script row on connect and
/// restores it from the undo anchor on disconnect.
#[test]
fn live_rows_restore_a_replaced_outpoint() -> Result<(), Box<dyn std::error::Error>> {
    let mut chain = Chain::new()?;
    chain.connect(vec![coinbase(0)], &MapScripts::default())?;

    let external = OutPoint {
        txid: Txid::from_byte_array([0x71_u8; 32]),
        vout: 0,
    };
    let old_script = script(0x72);
    let new_script = script(0x73);
    let mut creator = spend(&[external], std::slice::from_ref(&new_script));
    creator.input[0].previous_output = external;
    let creator_txid = creator.compute_txid();
    let replaced = OutPoint {
        txid: creator_txid,
        vout: 0,
    };
    let mut anchor = MapScripts::default();
    anchor.insert(external, &script(0x74));
    anchor.insert(replaced, &old_script);

    let (body, hash) = block_bytes(chain.tip, vec![coinbase(1), creator]);
    let prepared = chain.writer.prepare_block_with_spent_scripts(
        IndexCapabilities::ALL,
        chain.height,
        hash,
        &body,
        &anchor,
    )?;
    let mut batch = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 10_000,
        max_bytes: 10_000_000,
    });
    assert!(batch.try_push(prepared).is_ok());
    chain.writer.commit_forward(batch)?;

    assert_eq!(chain.live(&old_script), Vec::<OutPoint>::new());
    assert_eq!(chain.live(&new_script), vec![replaced]);

    let prev = IndexWatermark {
        height: 0,
        hash: chain.tip,
    };
    chain.writer.commit_rollback_one_with_spent_scripts(
        IndexCapabilities::ALL,
        Some(prev),
        &body,
        &anchor,
    )?;
    assert_eq!(chain.live(&new_script), Vec::<OutPoint>::new());
    assert_eq!(chain.live(&old_script), vec![replaced]);
    Ok(())
}

/// An output created and spent inside one block never touches the live view,
/// and needs no anchor entry -- the cancellation happens before resolution.
#[test]
fn same_block_create_and_spend_cancels_without_an_anchor() -> Result<(), Box<dyn std::error::Error>>
{
    let mut chain = Chain::new()?;
    let empty = MapScripts::default();
    chain.connect(vec![coinbase(0)], &empty)?;

    let transient = script(0xdd);
    let transient_op_return = ScriptBuf::from_bytes(vec![0x6a, 0x01, 0x01]);
    let transient_oversized = ScriptBuf::from_bytes(vec![0x51; MAX_LIVE_SCRIPT_SIZE + 1]);
    let survivor = script(0xee);
    let external = OutPoint {
        txid: Txid::from_byte_array([9_u8; 32]),
        vout: 3,
    };
    let creator = {
        let mut tx = spend(
            &[external],
            &[
                transient.clone(),
                transient_op_return.clone(),
                transient_oversized.clone(),
            ],
        );
        tx.input[0].previous_output = external;
        tx
    };
    let creator_txid = creator.compute_txid();
    let spender = spend(
        &[
            OutPoint {
                txid: creator_txid,
                vout: 0,
            },
            OutPoint {
                txid: creator_txid,
                vout: 1,
            },
            OutPoint {
                txid: creator_txid,
                vout: 2,
            },
        ],
        std::slice::from_ref(&survivor),
    );
    let spender_txid = spender.compute_txid();

    let mut anchor = MapScripts::default();
    anchor.insert(external, &script(0xef));
    // Deliberately no entry for the transient outpoint: if cancellation did
    // not precede resolution, this connect would fail with MissingSpentCoin.
    chain.connect(vec![coinbase(1), creator, spender], &anchor)?;

    assert_eq!(chain.live(&transient), Vec::<OutPoint>::new());
    assert_eq!(chain.live(&transient_op_return), Vec::<OutPoint>::new());
    assert_eq!(chain.live(&transient_oversized), Vec::<OutPoint>::new());
    assert_eq!(
        chain.live(&survivor),
        vec![OutPoint {
            txid: spender_txid,
            vout: 0,
        }]
    );
    Ok(())
}

/// An external spend the anchor cannot resolve fails the whole preparation,
/// and the anchorless prepare path refuses `ScriptLive` outright.
#[test]
fn unresolvable_spends_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let mut chain = Chain::new()?;
    let empty = MapScripts::default();
    chain.connect(vec![coinbase(0)], &empty)?;

    let external = OutPoint {
        txid: Txid::from_byte_array([5_u8; 32]),
        vout: 1,
    };
    let tx = {
        let mut tx = spend(&[external], &[script(0x11)]);
        tx.input[0].previous_output = external;
        tx
    };
    let (body, hash) = block_bytes(chain.tip, vec![coinbase(1), tx]);

    let unresolved = chain.writer.prepare_block_with_spent_scripts(
        IndexCapabilities::ALL,
        chain.height,
        hash,
        &body,
        &empty,
    );
    let unresolved_err = unresolved.err();
    assert!(
        matches!(
            unresolved_err,
            Some(IndexError::MissingSpentCoin { vout: 1, .. })
        ),
        "a spend the anchor cannot resolve must refuse the block: {unresolved_err:?}"
    );

    let anchorless =
        chain
            .writer
            .prepare_block_for(IndexCapabilities::ALL, chain.height, hash, &body);
    let anchorless_err = anchorless.err();
    assert!(
        matches!(anchorless_err, Some(IndexError::MissingSpentScripts)),
        "the anchorless path must refuse ScriptLive: {anchorless_err:?}"
    );
    Ok(())
}

/// The live predicate is UTXO admission: `OP_RETURN` and oversized scripts never
/// enter, while history deliberately keeps the oversized ones.
#[test]
fn live_predicate_matches_utxo_admission_not_history() -> Result<(), Box<dyn std::error::Error>> {
    let mut chain = Chain::new()?;
    let empty = MapScripts::default();
    chain.connect(vec![coinbase(0)], &empty)?;

    let op_return = ScriptBuf::from_bytes(vec![0x6a, 0x01, 0x02]);
    let oversized = ScriptBuf::from_bytes(vec![0x51; MAX_LIVE_SCRIPT_SIZE + 1]);
    let normal = script(0x22);
    let external = OutPoint {
        txid: Txid::from_byte_array([6_u8; 32]),
        vout: 0,
    };
    let tx = {
        let mut tx = spend(
            &[external],
            &[op_return.clone(), oversized.clone(), normal.clone()],
        );
        tx.input[0].previous_output = external;
        tx
    };
    let txid = tx.compute_txid();
    let mut anchor = MapScripts::default();
    anchor.insert(external, &script(0x23));
    chain.connect(vec![coinbase(1), tx], &anchor)?;

    assert_eq!(chain.live(&op_return), Vec::<OutPoint>::new());
    assert_eq!(chain.live(&oversized), Vec::<OutPoint>::new());
    assert_eq!(chain.live(&normal), vec![OutPoint { txid, vout: 2 }]);

    // History keeps the oversized output: it is real historical activity,
    // and this asymmetry against Live is deliberate.
    let funding = chain
        .writer
        .indexer()
        .iter_funding_rows(ScriptHash::from_script_bytes(oversized.as_bytes()))?;
    assert_eq!(
        funding.len(),
        1,
        "history must keep the oversized-script funding row"
    );
    Ok(())
}

/// The live watermark is stamped by live-selecting commits and only those, so
/// a ready history is never invalidated by adding the live capability, and
/// vice versa.
#[test]
fn live_and_history_watermarks_advance_independently() -> Result<(), Box<dyn std::error::Error>> {
    let mut chain = Chain::new()?;
    let (body, hash) = block_bytes(chain.tip, vec![coinbase(0)]);
    let prepared = chain
        .writer
        .prepare_block_for(IndexCapabilities::HISTORICAL, 0, hash, &body)?;
    let mut batch = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 10_000,
        max_bytes: 10_000_000,
    });
    assert!(batch.try_push(prepared).is_ok());
    chain.writer.commit_forward(batch)?;

    let watermarks = chain.writer.watermarks()?;
    assert!(watermarks.script_history.is_some());
    assert!(
        watermarks.script_live.is_none(),
        "a historical commit must not stamp the live cursor"
    );
    Ok(())
}

/// CONTRACT: IDX-07. Seeding writes rows and stamps the watermark last; recovery resets any
/// partial rows before a fresh seed, and a second seed over the stamped
/// watermark is refused.
///
/// CONTRACT: IDX-07 — partial `ScriptLive` rows remain unavailable until the
/// live watermark is durably stamped.
#[test]
fn seeding_resets_partial_rows_and_stamps_once() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    let mut writer = IndexWriter::open(Arc::clone(&store), 0)?;

    let wallet = script(0x44);
    let scripthash = ScriptHash::from_script_bytes(wallet.as_bytes());
    let stale_script = script(0x45);
    let stale_scripthash = ScriptHash::from_script_bytes(stale_script.as_bytes());
    let stale_outpoint = NativeOutPoint::new(NativeTxid(Hash256::from_le_bytes(&[0x32_u8; 32])), 0);
    let stale_row = ScriptLiveRow::new(stale_scripthash, &stale_outpoint);
    let mut partial = store.new_batch();
    partial.put(ColumnFamily::ScriptLive, stale_row.as_bytes(), &[]);
    store.write(partial)?;
    assert!(
        writer
            .indexer()
            .capability_watermark(IndexCapability::ScriptLive)?
            .is_none()
    );
    assert!(
        writer
            .indexer()
            .iter_live_outpoints(stale_scripthash)?
            .is_empty(),
        "partial rows must remain unavailable until the live watermark is stamped"
    );

    writer.reset_capabilities(IndexCapabilities::SCRIPT_LIVE)?;
    assert!(
        writer
            .indexer()
            .capability_watermark(IndexCapability::ScriptLive)?
            .is_none()
    );
    assert!(
        writer
            .indexer()
            .iter_live_outpoints(stale_scripthash)?
            .is_empty(),
        "reset must remove rows left while the live watermark was absent"
    );

    let coins = (0_u32..3)
        .map(|vout| {
            (
                NativeOutPoint::new(NativeTxid(Hash256::from_le_bytes(&[0x33_u8; 32])), vout),
                scripthash,
            )
        })
        .collect::<Vec<_>>();
    let seed_tip = IndexWatermark {
        height: 42,
        hash: [0x42_u8; 32],
    };

    let written = writer.seed_script_live(coins.clone(), seed_tip)?;
    assert_eq!(written, 3);
    assert_eq!(
        writer
            .indexer()
            .capability_watermark(IndexCapability::ScriptLive)?,
        Some(seed_tip)
    );
    assert_eq!(writer.indexer().iter_live_outpoints(scripthash)?.len(), 3);

    let again = writer.seed_script_live(coins, seed_tip);
    assert!(
        matches!(again, Err(IndexError::LiveAlreadySeeded)),
        "re-seeding over a stamped watermark must be refused: {again:?}"
    );
    Ok(())
}

/// CONTRACT: IDX-07. A deferred seed-batch failure must not publish the live
/// watermark over an incomplete view.
#[test]
fn seed_stream_deferred_write_failure_does_not_publish_watermark()
-> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore {
        fail_next_deferred: AtomicBool::new(true),
        ..MemoryStore::default()
    });
    let mut writer = IndexWriter::open(Arc::clone(&store), 0)?;
    let scripthash = ScriptHash::from_script_bytes(script(0x46).as_bytes());
    let coins = (0_u32..4_096)
        .map(|vout| {
            (
                NativeOutPoint::new(NativeTxid(Hash256::from_le_bytes(&[0x34_u8; 32])), vout),
                scripthash,
            )
        })
        .collect::<Vec<_>>();
    let seed_tip = IndexWatermark {
        height: 7,
        hash: [0x07_u8; 32],
    };

    let result = writer.seed_script_live(coins, seed_tip);
    assert!(
        matches!(result, Err(IndexError::Storage(_))),
        "a deferred batch failure must surface: {result:?}"
    );
    assert!(
        writer
            .indexer()
            .capability_watermark(IndexCapability::ScriptLive)?
            .is_none(),
        "the live watermark must stay unpublished after a seed write failure"
    );
    assert!(
        writer.indexer().iter_live_outpoints(scripthash)?.is_empty(),
        "partial seed rows must remain unavailable without a live watermark"
    );
    Ok(())
}

fn sorted(mut outpoints: Vec<OutPoint>) -> Vec<OutPoint> {
    outpoints.sort_unstable();
    outpoints
}
