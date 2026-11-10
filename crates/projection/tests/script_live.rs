use crate::support::{TestError, common};

use bitcoin_rs_projection::IndexReader;
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
use bitcoin_rs_consensus::primitives::{Hash256, OutPoint as NativeOutPoint, Txid as NativeTxid};
use bitcoin_rs_projection::{
    ConsumerCursorUpdate, IndexCapabilities, IndexCapability, IndexError, IndexWatermark,
    IndexWatermarks, IndexWriter, MAX_LIVE_SCRIPT_SIZE, PreparedBatch, PreparedBatchLimits,
    ScriptHash, ScriptLiveCoin, ScriptLiveRow, ScriptLiveValueError, SpentCoin, SpentCoins,
};
use bitcoin_rs_storage::{ColumnFamily, KvStore};
use proptest::prelude::*;

fn commit_rollback_one_with_spent_scripts<S: KvStore>(
    writer: &mut IndexWriter<S>,
    capabilities: IndexCapabilities,
    prev: Option<IndexWatermark>,
    body: &[u8],
    spent_scripts: &dyn SpentCoins,
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
struct MapScripts(hashbrown::HashMap<(Txid, u32), FixtureCoin>);

#[derive(Clone)]
struct FixtureCoin {
    script: Vec<u8>,
    value: u64,
    height: u32,
    coinbase: bool,
}

impl MapScripts {
    fn insert(&mut self, outpoint: OutPoint, coin: FixtureCoin) {
        self.0.insert((outpoint.txid, outpoint.vout), coin);
    }
}

impl FixtureCoin {
    /// A coin the fixture chain paid to `script` at `height`; the canonical
    /// value of fixture coinbase outputs is 50 sat.
    fn paying(script: &ScriptBuf, height: u32) -> Self {
        Self {
            script: script.to_bytes(),
            value: 50,
            height,
            coinbase: true,
        }
    }

    /// A coin that predates the fixture chain; only its script identity is
    /// observable through the index.
    fn external(script: &ScriptBuf) -> Self {
        Self {
            script: script.to_bytes(),
            value: 0,
            height: 0,
            coinbase: false,
        }
    }
}

impl SpentCoins for MapScripts {
    fn spent_coin(&self, txid: &[u8; 32], vout: u32) -> Option<SpentCoin<'_>> {
        self.0
            .get(&(Txid::from_byte_array(*txid), vout))
            .map(|coin| SpentCoin {
                script: &coin.script,
                value: coin.value,
                height: coin.height,
                coinbase: coin.coinbase,
            })
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
    fn new() -> Result<Self, TestError> {
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

fn persistent_writer_live_roundtrip<S: KvStore>(
    open: impl Fn() -> Result<S, bitcoin_rs_storage::StorageError>,
    capabilities: IndexCapabilities,
) -> Result<(), TestError> {
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
    let Some(stored) = store.get(ColumnFamily::ScriptLive, row.as_bytes())? else {
        return Err(TestError::from("the funding output row is stored"));
    };
    let stored_coin = bitcoin_rs_projection::ScriptLiveCoin::decode_value(&stored)
        .map_err(|_| TestError::from("format 8 rows carry a coin payload"))?;
    assert_eq!(stored_coin.scripthash, scripthash);
    assert_eq!(stored_coin.value, funding_tx.output[1].value.to_sat());
    assert_eq!(stored_coin.height, 1);
    assert!(stored_coin.coinbase);
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
    anchor.insert(outpoint, FixtureCoin::paying(&wallet, 1));
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

fn tx_lookup_only_reopen<S: KvStore>(
    open: impl Fn() -> Result<S, bitcoin_rs_storage::StorageError>,
    store: Arc<S>,
    writer: IndexWriter<S>,
    funding_tip: IndexWatermark,
) -> Result<(), TestError> {
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

fn seed_live_and_reopen<S: KvStore>(
    open: impl Fn() -> Result<S, bitcoin_rs_storage::StorageError>,
    store: Arc<S>,
    mut writer: IndexWriter<S>,
    native: NativeOutPoint,
    scripthash: ScriptHash,
) -> Result<(), TestError> {
    writer.reset_capabilities(IndexCapabilities::SCRIPT_LIVE)?;
    let (_, before_seed) = writer.fenced_watermarks()?;
    let seed_tip = IndexWatermark {
        height: 42,
        hash: [0x42; 32],
    };
    let high_vout = NativeOutPoint::new(native.txid, 256);
    let coins = [
        (
            native,
            bitcoin_rs_projection::ScriptLiveCoin::new(scripthash, 1, 7, false),
        ),
        (
            high_vout,
            bitcoin_rs_projection::ScriptLiveCoin::new(scripthash, 2, 7, false),
        ),
    ];
    let rows = coins
        .into_iter()
        .map(|(outpoint, coin)| -> Result<Vec<u8>, TestError> {
            let row = ScriptLiveRow::new(coin.scripthash, &outpoint);
            let mut bytes = row.as_bytes().to_vec();
            bytes.extend_from_slice(&coin.encode_value()?);
            Ok(bytes)
        })
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(writer.stage_script_live_rows(&mut rows.into_iter())?, 2);
    writer.publish_script_live_seed(seed_tip)?;
    let (_, after_seed) = writer.fenced_watermarks()?;
    assert_eq!(after_seed.script_live, Some(seed_tip));
    assert_eq!(after_seed.tx_lookup, before_seed.tx_lookup);
    assert_eq!(after_seed.script_history, before_seed.script_history);
    assert!(matches!(
        writer.publish_script_live_seed(seed_tip),
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

#[test]
fn rocksdb_writer_live_roundtrip() -> Result<(), TestError> {
    for capabilities in [
        IndexCapabilities::SCRIPT_LIVE,
        IndexCapabilities::TX_AND_SCRIPTS,
        IndexCapabilities::TX_LOOKUP,
    ] {
        let temp = tempfile::TempDir::new()?;
        persistent_writer_live_roundtrip(
            || bitcoin_rs_storage::RocksDbStore::open(temp.path()),
            capabilities,
        )?;
    }
    Ok(())
}

#[test]
fn live_rows_follow_connect_spend_and_disconnect() -> Result<(), TestError> {
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
    anchor.insert(external, FixtureCoin::external(&funding_script));
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
    anchor2.insert(o0, FixtureCoin::paying(&wallet, chain.height));
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

#[test]
fn disconnect_restores_the_full_coin_payload() -> Result<(), TestError> {
    let mut chain = Chain::new()?;
    let empty = MapScripts::default();
    chain.connect(vec![coinbase(0)], &empty)?;

    let wallet = script(0xaa);
    let funding = spend(&[OutPoint::null()], std::slice::from_ref(&wallet));
    let funding_txid = funding.compute_txid();
    let funding_outpoint = OutPoint {
        txid: funding_txid,
        vout: 0,
    };
    chain.connect(vec![funding], &MapScripts::default())?;

    let sweep = spend(&[funding_outpoint], &[script(0xdd)]);
    let mut anchor = MapScripts::default();
    anchor.insert(funding_outpoint, FixtureCoin::paying(&wallet, 1));
    let (body, hash) = block_bytes(chain.tip, vec![coinbase(1), sweep]);
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
    assert_eq!(chain.live(&wallet), Vec::<OutPoint>::new());

    let prev = IndexWatermark {
        height: 1,
        hash: chain.tip,
    };
    commit_rollback_one_with_spent_scripts(
        &mut chain.writer,
        IndexCapabilities::TX_AND_SCRIPTS,
        Some(prev),
        &body,
        &anchor,
    )?;

    let scripthash = bitcoin_rs_projection::ScriptHash::from_script_bytes(wallet.as_bytes());
    let scan = chain
        .writer
        .snapshot()?
        .live_rows(
            scripthash,
            bitcoin_rs_storage::PrefixScanLimit {
                max_rows: 10,
                max_bytes: 10_000,
            },
        )
        .map_err(TestError::from)?;
    assert_eq!(scan.rows.len(), 1);
    let coin = scan.coins[0];
    assert_eq!(coin.scripthash, scripthash);
    assert_eq!(coin.value, 50);
    assert_eq!(coin.height, 1);
    assert!(coin.coinbase);
    Ok(())
}

#[test]
fn live_rows_restore_a_replaced_outpoint() -> Result<(), TestError> {
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
    anchor.insert(external, FixtureCoin::external(&script(0x74)));
    anchor.insert(replaced, FixtureCoin::external(&old_script));

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
fn same_block_create_and_spend_cancels_without_an_anchor() -> Result<(), TestError> {
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
    anchor.insert(external, FixtureCoin::external(&script(0xef)));
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
fn unresolvable_spends_fail_closed() -> Result<(), TestError> {
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

#[test]
fn live_predicate_matches_utxo_admission_not_history() -> Result<(), TestError> {
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
    anchor.insert(external, FixtureCoin::external(&script(0x23)));
    chain.connect(vec![coinbase(1), tx], &anchor)?;

    assert_eq!(chain.live(&op_return), Vec::<OutPoint>::new());
    assert_eq!(chain.live(&oversized), Vec::<OutPoint>::new());
    assert_eq!(chain.live(&normal), vec![OutPoint { txid, vout: 2 }]);

    let funding = {
        use bitcoin_rs_projection::IndexReader;
        chain
            .writer
            .indexer()
            .snapshot()?
            .funding_rows(
                ScriptHash::from_script_bytes(oversized.as_bytes()),
                bitcoin_rs_storage::PrefixScanLimit {
                    max_rows: 100_000,
                    max_bytes: 64 << 20,
                },
            )?
            .rows
    };
    assert_eq!(
        funding.len(),
        1,
        "history must keep the oversized-script funding row"
    );
    Ok(())
}

struct NoSpend;

static NO_SPEND_SCRIPT: [u8; 2] = [0x51, 0x01];

impl bitcoin_rs_projection::SpentCoins for NoSpend {
    fn spent_coin(
        &self,
        _txid: &[u8; 32],
        _vout: u32,
    ) -> Option<bitcoin_rs_projection::SpentCoin<'_>> {
        Some(bitcoin_rs_projection::SpentCoin {
            script: NO_SPEND_SCRIPT.as_slice(),
            value: 0,
            height: 0,
            coinbase: false,
        })
    }
}

#[test]
fn live_and_history_watermarks_advance_independently() -> Result<(), TestError> {
    let mut chain = Chain::new()?;
    let (body, hash) = block_bytes(chain.tip, vec![coinbase(0)]);
    let prepared = chain.writer.prepare_block_with_spent_scripts(
        IndexCapabilities::HISTORICAL,
        0,
        hash,
        &body,
        &NoSpend,
    )?;
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
fn seeding_resets_partial_rows_and_stamps_once() -> Result<(), TestError> {
    let store = Arc::new(MemoryStore::default());
    let writer = IndexWriter::open(Arc::clone(&store), 0)?;

    let wallet = script(0x44);
    let scripthash = ScriptHash::from_script_bytes(wallet.as_bytes());
    let stale_script = script(0x45);
    let stale_scripthash = ScriptHash::from_script_bytes(stale_script.as_bytes());
    let stale_outpoint = NativeOutPoint::new(NativeTxid(Hash256::from_le_bytes(&[0x32_u8; 32])), 0);
    let stale_row = ScriptLiveRow::new(stale_scripthash, &stale_outpoint);
    let stale_coin = bitcoin_rs_projection::ScriptLiveCoin::new(stale_scripthash, 500, 1, false);
    let mut partial = store.new_batch();
    partial.put(
        ColumnFamily::ScriptLive,
        stale_row.as_bytes(),
        &stale_coin.encode_value()?,
    );
    store.write(partial)?;
    let bare_row = stale_row.as_bytes().to_vec();
    assert!(matches!(
        writer.stage_script_live_rows(&mut [bare_row].into_iter()),
        Err(IndexError::InvalidLiveRowValue { len: 43 })
    ));
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
                bitcoin_rs_projection::ScriptLiveCoin::new(scripthash, 3, 8, false),
            )
        })
        .collect::<Vec<_>>();
    let seed_tip = IndexWatermark {
        height: 42,
        hash: [0x42_u8; 32],
    };

    let rows = coins
        .iter()
        .map(|(outpoint, coin)| -> Result<Vec<u8>, TestError> {
            let row = ScriptLiveRow::new(coin.scripthash, outpoint);
            let mut bytes = row.as_bytes().to_vec();
            bytes.extend_from_slice(&coin.encode_value()?);
            Ok(bytes)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let written = writer.stage_script_live_rows(&mut rows.into_iter())?;
    assert_eq!(written, 3);
    assert_eq!(
        writer
            .indexer()
            .capability_watermark(IndexCapability::ScriptLive)?,
        None,
        "SNP-07: staged rows stay unpublished until the seed tip commits"
    );
    writer.publish_script_live_seed(seed_tip)?;
    assert_eq!(
        writer
            .indexer()
            .capability_watermark(IndexCapability::ScriptLive)?,
        Some(seed_tip)
    );
    assert_eq!(writer.indexer().iter_live_outpoints(scripthash)?.len(), 3);

    let again = writer.publish_script_live_seed(seed_tip);
    assert!(
        matches!(again, Err(IndexError::LiveAlreadySeeded)),
        "re-seeding over a stamped watermark must be refused: {again:?}"
    );
    Ok(())
}

#[test]
fn seed_stream_fenced_write_failure_does_not_publish_watermark() -> Result<(), TestError> {
    let store = Arc::new(MemoryStore::default());
    let writer = IndexWriter::open(Arc::clone(&store), 0)?;
    store.fail_next_fenced_write.store(true, Ordering::SeqCst);
    let scripthash = ScriptHash::from_script_bytes(script(0x46).as_bytes());
    let coins = (0_u32..4_096)
        .map(|vout| {
            (
                NativeOutPoint::new(NativeTxid(Hash256::from_le_bytes(&[0x34_u8; 32])), vout),
                bitcoin_rs_projection::ScriptLiveCoin::new(scripthash, 1, 0, false),
            )
        })
        .collect::<Vec<_>>();
    let _seed_tip = IndexWatermark {
        height: 7,
        hash: [0x07_u8; 32],
    };

    let rows = coins
        .iter()
        .map(|(outpoint, coin)| -> Result<Vec<u8>, TestError> {
            let row = ScriptLiveRow::new(coin.scripthash, outpoint);
            let mut bytes = row.as_bytes().to_vec();
            bytes.extend_from_slice(&coin.encode_value()?);
            Ok(bytes)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let result = writer.stage_script_live_rows(&mut rows.into_iter());
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

// IDX-04
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

const COIN: u64 = 100_000_000;
const MAX_MONEY: u64 = 21_000_000 * COIN;

fn row_codec() -> impl proptest::strategy::Strategy<Value = ScriptLiveCoin> {
    (
        proptest::array::uniform32(proptest::arbitrary::any::<u8>()),
        0..=MAX_MONEY,
        proptest::arbitrary::any::<u32>(),
        proptest::arbitrary::any::<bool>(),
    )
        .prop_map(|(scripthash, value, height, coinbase)| {
            ScriptLiveCoin::new(
                ScriptHash::from_byte_array(scripthash),
                value,
                height,
                coinbase,
            )
        })
}

// PRJ-11
#[test]
fn script_live_value_matches_compress_amount_vectors() -> Result<(), TestError> {
    let vectors: [(u64, &[u8]); 6] = [
        (0, &[0x00]),
        (1, &[0x01]),
        (1_000_000, &[0x07]),
        (COIN, &[0x09]),
        (50 * COIN, &[0x32]),
        (21_000_000 * COIN, &[0xC0, 0xDE, 0x81, 0x0A]),
    ];
    for (amount, compressed) in vectors {
        let coin = ScriptLiveCoin::new(ScriptHash::from_byte_array([7; 32]), amount, 0, false);
        let encoded = coin.encode_value()?;
        let mut expected = vec![7_u8; 32];
        expected.extend_from_slice(compressed);
        expected.push(0x00);
        assert_eq!(encoded, expected, "compress_amount({amount}) vector");
        assert_eq!(ScriptLiveCoin::decode_value(&encoded)?, coin);
    }
    Ok(())
}

// PRJ-11
#[test]
fn script_live_value_round_trips_core_test_encode_sweeps() -> Result<(), TestError> {
    fn assert_round_trip(amount: u64) -> Result<(), TestError> {
        let coin = ScriptLiveCoin::new(ScriptHash::from_byte_array([9; 32]), amount, 842_113, true);
        let encoded = coin.encode_value()?;
        assert_eq!(ScriptLiveCoin::decode_value(&encoded)?, coin);
        Ok(())
    }
    for amount in 1..=100_000 {
        assert_round_trip(amount)?;
    }
    for amount in 1..=10_000 {
        assert_round_trip(amount * 1_000_000)?;
    }
    for amount in 1..=10_000 {
        assert_round_trip(amount * COIN)?;
    }
    for amount in 1..=420_000 {
        assert_round_trip(amount * 50 * COIN)?;
    }
    let vectors: [(u64, &[u8], Option<u64>); 11] = [
        (0, &[0x00], Some(0)),
        (1, &[0x01], Some(1)),
        (7, &[0x07], Some(1_000_000)),
        (9, &[0x09], Some(COIN)),
        (50, &[0x32], Some(50 * COIN)),
        (127, &[0x7F], Some(14_000_000)),
        (128, &[0x80, 0x01], Some(140_000_000)),
        (300, &[0xAC, 0x02], Some(30_000_000_000)),
        (16_384, &[0x80, 0x80, 0x01], Some(1_821_000)),
        (21_000_000, &[0xC0, 0xDE, 0x81, 0x0A], Some(MAX_MONEY)),
        (100_000_000, &[0x80, 0xC2, 0xD7, 0x2F], None),
    ];
    for (compressed, varint, expected) in vectors {
        let mut bytes = vec![0_u8; 32];
        bytes.extend_from_slice(varint);
        bytes.push(0x00);
        match expected {
            Some(value) => {
                let coin = ScriptLiveCoin::decode_value(&bytes).map_err(|e| e.to_string())?;
                assert_eq!(coin.value, value, "decompressed value of {compressed}");
                assert_eq!(coin.height, 0, "decode vector carries height zero");
                assert!(!coin.coinbase, "decode vector is not a coinbase");
                assert_eq!(coin.scripthash, ScriptHash::from_byte_array([0; 32]));
            }
            None => assert_eq!(
                ScriptLiveCoin::decode_value(&bytes),
                Err(ScriptLiveValueError::AmountOverflow),
                "compressed {compressed} exceeds the money range"
            ),
        }
    }
    Ok(())
}

// PRJ-11
#[test]
fn script_live_value_refuses_out_of_range_amounts() {
    let coin = ScriptLiveCoin::new(
        ScriptHash::from_byte_array([1; 32]),
        MAX_MONEY + 1,
        0,
        false,
    );
    assert_eq!(
        coin.encode_value(),
        Err(ScriptLiveValueError::AmountOutOfRange {
            value: MAX_MONEY + 1,
        })
    );
    assert_eq!(coin.encoded_value_len(), None);
}

// PRJ-11
proptest! {
    #![proptest_config(proptest::test_runner::Config {
        cases: std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(1024),
        ..proptest::test_runner::Config::default()
    })]
    #[test]
    fn script_live_value_round_trips_and_refuses_mutation(
        coin in row_codec(),
        cut in 0_usize..76,
        filler in proptest::collection::vec(proptest::arbitrary::any::<u8>(), 1..=8),
    ) {
        let encoded = coin.encode_value().map_err(|error| {
            proptest::test_runner::TestCaseError::fail(format!("encode failed: {error}"))
        })?;
        prop_assert!(encoded.len() >= 33);
        let expected_len = match coin.encoded_value_len() {
            Some(len) => len,
            None => {
                return Err(proptest::test_runner::TestCaseError::fail(
                    "in-range amount must have an encoded length",
                ));
            }
        };
        prop_assert_eq!(encoded.len(), expected_len);
        prop_assert_eq!(ScriptLiveCoin::decode_value(&encoded), Ok(coin));

        let cut = cut % encoded.len();
        let truncated = &encoded[..cut];
        prop_assert!(
            ScriptLiveCoin::decode_value(truncated).is_err(),
            "truncated value must be refused"
        );

        let mut overlong = encoded.clone();
        overlong.extend_from_slice(&filler);
        prop_assert_eq!(
            ScriptLiveCoin::decode_value(&overlong),
            Err(ScriptLiveValueError::TrailingBytes)
        );
    }
}
