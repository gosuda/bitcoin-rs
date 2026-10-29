//! `ScriptLive` behavior over the prepared/commit path (`IDX-01`, `IDX-07`, #225).

#[path = "support/common.rs"]
mod common;

#[cfg(any(feature = "redb", feature = "fjall"))]
use bitcoin_rs_index::IndexReader;
use common::MemoryStore;
use std::sync::Arc;
use std::sync::atomic::Ordering;

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
    ConsumerCursorUpdate, IndexCapabilities, IndexCapability, IndexError, IndexWatermark,
    IndexWatermarks, IndexWriter, MAX_LIVE_SCRIPT_SIZE, PreparedBatch, PreparedBatchLimits,
    ScriptHash, ScriptLiveRow, SpentCoinScripts,
};
use bitcoin_rs_primitives::{Hash256, OutPoint as NativeOutPoint, Txid as NativeTxid};
use bitcoin_rs_storage::{ColumnFamily, KvStore};

fn commit_rollback_one_with_spent_scripts<S: KvStore>(
    writer: &mut IndexWriter<S>,
    capabilities: IndexCapabilities,
    prev: Option<IndexWatermark>,
    body: &[u8],
    spent_scripts: &dyn SpentCoinScripts,
) -> Result<(), IndexError> {
    let (fence, _) = writer.fenced_watermarks()?;
    writer.commit_rollback_one_for_with_cursor_with_spent_scripts(
        fence,
        capabilities,
        prev,
        body,
        ConsumerCursorUpdate::Clear,
        spent_scripts,
    )
}

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

    fn connect(
        &mut self,
        txdata: Vec<Transaction>,
        anchor: &MapScripts,
    ) -> Result<[u8; 32], IndexError> {
        let (body, hash) = block_bytes(self.tip, txdata);
        let prepared = self.writer.prepare_block_with_spent_scripts(
            IndexCapabilities::TX_AND_SCRIPTS,
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

#[cfg(any(feature = "redb", feature = "fjall"))]
fn persistent_writer_live_roundtrip<S: KvStore>(
    open: impl Fn() -> Result<S, bitcoin_rs_storage::StorageError>,
    capabilities: IndexCapabilities,
) -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(open()?);
    let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
    let empty = MapScripts::default();
    let (genesis, genesis_hash) = block_bytes([0; 32], vec![coinbase(0)]);
    let mut funding_tx = coinbase(1);
    funding_tx.output.push(funding_tx.output[0].clone());
    funding_tx.output[0].script_pubkey = script(0xab);
    let (funding, funding_hash) = block_bytes(genesis_hash, vec![funding_tx.clone()]);
    for (height, body, hash) in [(0, &genesis, genesis_hash), (1, &funding, funding_hash)] {
        let prepared =
            writer.prepare_block_with_spent_scripts(capabilities, height, hash, body, &empty)?;
        writer.commit_forward(common::single_block_batch(prepared))?;
    }
    let funding_tip = IndexWatermark {
        height: 1,
        hash: funding_hash,
    };
    assert_eq!(
        writer.watermarks()?,
        IndexWatermarks {
            compact_filters: None,
            tx_lookup: (capabilities != IndexCapabilities::SCRIPT_LIVE).then_some(funding_tip),
            script_history: (capabilities == IndexCapabilities::TX_AND_SCRIPTS)
                .then_some(funding_tip),
            script_live: (capabilities != IndexCapabilities::TX_LOOKUP).then_some(funding_tip),
        }
    );
    if capabilities == IndexCapabilities::TX_LOOKUP {
        return tx_lookup_only_reopen(open, store, writer, funding_tip);
    }
    let wallet = funding_tx.output[1].script_pubkey.clone();
    let scripthash = ScriptHash::from_script_bytes(wallet.as_bytes());
    let outpoint = OutPoint::new(funding_tx.compute_txid(), 1);
    let native = NativeOutPoint::new(
        NativeTxid(Hash256::from_le_bytes(outpoint.txid.as_byte_array())),
        1,
    );
    let row = ScriptLiveRow::new(scripthash, &native);
    assert_eq!(row.as_bytes().len(), 43);
    assert_eq!(
        store.get(ColumnFamily::ScriptLive, row.as_bytes())?,
        Some(Vec::new())
    );
    let scan = writer.snapshot()?.live_rows(
        scripthash,
        bitcoin_rs_storage::PrefixScanLimit {
            max_rows: 10,
            max_bytes: 1_024,
        },
    )?;
    assert!(scan.complete);
    assert_eq!(scan.rows.len(), 1);
    assert_eq!(scan.rows[0].as_bytes(), row.as_bytes());

    let mut anchor = MapScripts::default();
    anchor.insert(outpoint, &wallet);
    let (spending, spending_hash) = block_bytes(
        funding_hash,
        vec![coinbase(2), spend(&[outpoint], &[script(0xdd)])],
    );
    let prepared = writer.prepare_block_with_spent_scripts(
        capabilities,
        2,
        spending_hash,
        &spending,
        &anchor,
    )?;
    writer.commit_forward(common::single_block_batch(prepared))?;
    assert_eq!(store.get(ColumnFamily::ScriptLive, row.as_bytes())?, None);
    commit_rollback_one_with_spent_scripts(
        &mut writer,
        capabilities,
        Some(IndexWatermark {
            height: 1,
            hash: funding_hash,
        }),
        &spending,
        &anchor,
    )?;
    store.flush()?;
    drop(writer);
    drop(store);

    let store = Arc::new(open()?);
    let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
    assert_eq!(
        writer.indexer().iter_live_outpoints(scripthash)?,
        vec![native]
    );
    commit_rollback_one_with_spent_scripts(
        &mut writer,
        capabilities,
        Some(IndexWatermark {
            height: 0,
            hash: genesis_hash,
        }),
        &funding,
        &empty,
    )?;
    assert_eq!(store.get(ColumnFamily::ScriptLive, row.as_bytes())?, None);
    seed_live_and_reopen(open, store, writer, native, scripthash)
}

#[cfg(any(feature = "redb", feature = "fjall"))]
fn tx_lookup_only_reopen<S: KvStore>(
    open: impl Fn() -> Result<S, bitcoin_rs_storage::StorageError>,
    store: Arc<S>,
    writer: IndexWriter<S>,
    funding_tip: IndexWatermark,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        writer
            .indexer()
            .capability_watermark(IndexCapability::ScriptLive)?,
        None
    );
    assert!(
        store
            .iter_prefix(ColumnFamily::ScriptLive, &[])?
            .next()
            .is_none()
    );
    store.flush()?;
    drop(writer);
    drop(store);
    let writer = IndexWriter::open(Arc::new(open()?), 1)?;
    assert_eq!(
        writer
            .indexer()
            .capability_watermark(IndexCapability::TxLookup)?,
        Some(funding_tip)
    );
    assert_eq!(
        writer
            .indexer()
            .capability_watermark(IndexCapability::ScriptLive)?,
        None
    );
    Ok(())
}

#[cfg(any(feature = "redb", feature = "fjall"))]
fn seed_live_and_reopen<S: KvStore>(
    open: impl Fn() -> Result<S, bitcoin_rs_storage::StorageError>,
    store: Arc<S>,
    mut writer: IndexWriter<S>,
    native: NativeOutPoint,
    scripthash: ScriptHash,
) -> Result<(), Box<dyn std::error::Error>> {
    writer.reset_capabilities(IndexCapabilities::SCRIPT_LIVE)?;
    let (_, before_seed) = writer.fenced_watermarks()?;
    let seed_tip = IndexWatermark {
        height: 42,
        hash: [0x42; 32],
    };
    let high_vout = NativeOutPoint::new(native.txid, 256);
    let coins = [(native, scripthash), (high_vout, scripthash)];
    assert_eq!(writer.seed_script_live(coins, seed_tip)?, 2);
    let (_, after_seed) = writer.fenced_watermarks()?;
    assert_eq!(after_seed.script_live, Some(seed_tip));
    assert_eq!(after_seed.tx_lookup, before_seed.tx_lookup);
    assert_eq!(after_seed.script_history, before_seed.script_history);
    assert!(matches!(
        writer.seed_script_live(coins, seed_tip),
        Err(IndexError::LiveAlreadySeeded)
    ));
    store.flush()?;
    drop(writer);
    drop(store);
    let writer = IndexWriter::open(Arc::new(open()?), 1)?;
    let live = writer.indexer().iter_live_outpoints(scripthash)?;
    assert_eq!(live.len(), 2);
    assert!(live.contains(&native) && live.contains(&high_vout));
    assert_eq!(
        writer
            .indexer()
            .capability_watermark(IndexCapability::ScriptLive)?,
        Some(seed_tip)
    );
    Ok(())
}

#[cfg(feature = "redb")]
#[test]
fn dedicated_redb_writer_live_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    for capabilities in [
        IndexCapabilities::SCRIPT_LIVE,
        IndexCapabilities::TX_AND_SCRIPTS,
        IndexCapabilities::TX_LOOKUP,
    ] {
        let temp = tempfile::TempDir::new()?;
        persistent_writer_live_roundtrip(
            || bitcoin_rs_storage::open_redb_tx_index_store(temp.path()),
            capabilities,
        )?;
    }
    Ok(())
}

#[cfg(feature = "redb")]
#[test]
fn generic_redb_writer_live_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    for capabilities in [
        IndexCapabilities::SCRIPT_LIVE,
        IndexCapabilities::TX_AND_SCRIPTS,
        IndexCapabilities::TX_LOOKUP,
    ] {
        let temp = tempfile::TempDir::new()?;
        persistent_writer_live_roundtrip(
            || bitcoin_rs_storage::RedbStore::open(temp.path()),
            capabilities,
        )?;
    }
    Ok(())
}

#[cfg(feature = "fjall")]
#[test]
fn fjall_writer_live_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    for capabilities in [
        IndexCapabilities::SCRIPT_LIVE,
        IndexCapabilities::TX_AND_SCRIPTS,
        IndexCapabilities::TX_LOOKUP,
    ] {
        let temp = tempfile::TempDir::new()?;
        persistent_writer_live_roundtrip(
            || bitcoin_rs_storage::FjallStore::open(temp.path()),
            capabilities,
        )?;
    }
    Ok(())
}

#[test]
fn live_rows_follow_connect_spend_and_disconnect() -> Result<(), Box<dyn std::error::Error>> {
    let mut chain = Chain::new()?;
    let empty = MapScripts::default();

    chain.connect(vec![coinbase(0)], &empty)?;

    let wallet = script(0xaa);
    let pay = spend(&[OutPoint::null()], &[wallet.clone(), wallet.clone()]);
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

    let sweep = spend(&[o0], &[script(0xcc)]);
    let mut anchor2 = MapScripts::default();
    anchor2.insert(o0, &wallet);
    let (body2, hash2) = block_bytes(chain.tip, vec![coinbase(2), sweep]);
    let prepared = chain.writer.prepare_block_with_spent_scripts(
        IndexCapabilities::TX_AND_SCRIPTS,
        chain.height,
        hash2,
        &body2,
        &anchor2,
    )?;
    let batch = common::batch_with_limits(
        prepared,
        PreparedBatchLimits {
            max_rows: 10_000,
            max_bytes: 10_000_000,
        },
    );
    chain.writer.commit_forward(batch)?;
    assert_eq!(chain.live(&wallet), vec![o1]);

    let prev = IndexWatermark {
        height: 1,
        hash: chain.tip,
    };
    commit_rollback_one_with_spent_scripts(
        &mut chain.writer,
        IndexCapabilities::TX_AND_SCRIPTS,
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
        IndexCapabilities::TX_AND_SCRIPTS,
        chain.height,
        hash,
        &body,
        &anchor,
    )?;
    let batch = common::batch_with_limits(
        prepared,
        PreparedBatchLimits {
            max_rows: 10_000,
            max_bytes: 10_000_000,
        },
    );
    chain.writer.commit_forward(batch)?;

    assert_eq!(chain.live(&old_script), Vec::<OutPoint>::new());
    assert_eq!(chain.live(&new_script), vec![replaced]);

    let prev = IndexWatermark {
        height: 0,
        hash: chain.tip,
    };
    commit_rollback_one_with_spent_scripts(
        &mut chain.writer,
        IndexCapabilities::TX_AND_SCRIPTS,
        Some(prev),
        &body,
        &anchor,
    )?;
    assert_eq!(chain.live(&new_script), Vec::<OutPoint>::new());
    assert_eq!(chain.live(&old_script), vec![replaced]);
    Ok(())
}

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
        IndexCapabilities::TX_AND_SCRIPTS,
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

    let anchorless = chain.writer.prepare_block_for(
        IndexCapabilities::TX_AND_SCRIPTS,
        chain.height,
        hash,
        &body,
    );
    let anchorless_err = anchorless.err();
    assert!(
        matches!(anchorless_err, Some(IndexError::MissingSpentScripts)),
        "the anchorless path must refuse ScriptLive: {anchorless_err:?}"
    );
    Ok(())
}

/// The live predicate is UTXO admission: `OP_RETURN` and oversized scripts never
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

#[test]
fn live_and_history_watermarks_advance_independently() -> Result<(), Box<dyn std::error::Error>> {
    let mut chain = Chain::new()?;
    let (body, hash) = block_bytes(chain.tip, vec![coinbase(0)]);
    let prepared = chain
        .writer
        .prepare_block_for(IndexCapabilities::HISTORICAL, 0, hash, &body)?;
    let batch = common::batch_with_limits(
        prepared,
        PreparedBatchLimits {
            max_rows: 10_000,
            max_bytes: 10_000_000,
        },
    );
    chain.writer.commit_forward(batch)?;

    let watermarks = chain.writer.watermarks()?;
    assert!(watermarks.script_history.is_some());
    assert!(
        watermarks.script_live.is_none(),
        "a historical commit must not stamp the live cursor"
    );
    Ok(())
}

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

#[test]
fn seed_stream_fenced_write_failure_does_not_publish_watermark()
-> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    let mut writer = IndexWriter::open(Arc::clone(&store), 0)?;
    store.fail_next_fenced_write.store(true, Ordering::SeqCst);
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
        "a fenced batch failure must surface: {result:?}"
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

#[test]
fn leftover_capabilities_are_persisted_families_outside_the_selection() {
    let cursor = IndexWatermark {
        height: 1,
        hash: [1_u8; 32],
    };
    let watermarks = IndexWatermarks {
        compact_filters: None,
        tx_lookup: Some(cursor),
        script_history: Some(cursor),
        script_live: Some(cursor),
    };
    assert_eq!(
        IndexCapabilities::SCRIPT_LIVE.leftover(watermarks),
        IndexCapabilities::HISTORICAL
    );
    assert!(
        IndexCapabilities::TX_AND_SCRIPTS
            .leftover(watermarks)
            .is_empty()
    );
}
