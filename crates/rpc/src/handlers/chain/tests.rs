use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use bitcoin_rs_primitives::{OutPoint, Tx, TxIn, Txid};

use super::*;
use bitcoin_rs_chain::{ChainWork, NodeId, TipSnapshot};
use bitcoin_rs_index::block_log::BlockLog;

struct SingleBlockSource {
    height: u32,
    hash: BlockHash,
    body: Vec<u8>,
    calls: core::sync::atomic::AtomicUsize,
}

use crate::context::BlockBodies;

impl bitcoin_rs_chain::BlockBodySource for SingleBlockSource {
    fn block_body(
        &self,
        height: u32,
        hash: BlockHash,
    ) -> Result<Option<Vec<u8>>, bitcoin_rs_chain::BlockBodyReadError> {
        self.calls
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        Ok((height == self.height && hash == self.hash).then(|| self.body.clone()))
    }
}

fn context_with_tip(
    network: bitcoin_rs_primitives::Network,
    bits: u32,
    times: &[u32],
) -> Arc<Context> {
    let mut context = Context::new();
    context.chain.chain_network = network;
    let ctx = Arc::new(context);
    let (tip_id, tip_hash) = {
        let mut tree = ctx.chain.block_tree.write();
        let mut parent = None;
        let mut previous_hash = BlockHash::default();
        let mut tip_id = NodeId::new(0);
        let mut tip_hash = Hash256::default();
        for (index, time) in times.iter().copied().enumerate() {
            let header = Header {
                version: 1,
                prev_blockhash: previous_hash,
                merkle_root: Hash256::default(),
                time,
                bits: CompactTarget::from_consensus(bits),
                nonce: u32::try_from(index).unwrap_or(u32::MAX),
            };
            previous_hash = header.compute_hash();
            tip_id = tree
                .insert_node(parent, header, NodeStatus::Active)
                .unwrap_or(tip_id);
            tip_hash = previous_hash.0;
            parent = Some(tip_id);
        }
        (tip_id, tip_hash)
    };
    let tip = TipSnapshot {
        tip_id,
        height: u32::try_from(times.len().saturating_sub(1)).unwrap_or(u32::MAX),
        chainwork: ChainWork::ZERO,
        hash: tip_hash,
        chain_tx_count: bitcoin_rs_chain::ChainTxCount::UNKNOWN,
    };
    ctx.chain.chain_tip.store(Some(Arc::new(tip.clone())));
    ctx.chain.applied_tip.store(Some(Arc::new(tip)));
    ctx
}

fn seed_block(ctx: &Arc<Context>, block: &Block, record: BlockRecord) {
    {
        let mut tree = ctx.chain.block_tree.write();
        let _ = tree.insert_node(None, block.header, NodeStatus::Active);
    }
    ctx.chain.add_block(record);
}

fn fixture_genesis() -> Block {
    let coinbase = Tx {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(5_000_000_000),
            script_pubkey: Script::new(),
        }],
        lock_time: LockTime::ZERO,
    };
    Block {
        header: Header {
            version: 1,
            prev_blockhash: BlockHash::default(),
            merkle_root: coinbase.txid().0,
            time: 1_296_688_602,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txs: vec![coinbase],
    }
}

fn fixture_block_with_spend() -> Block {
    let mut block = fixture_genesis();
    let Some(coinbase) = block.txs.first() else {
        panic!("fixture genesis lost its coinbase");
    };
    let spend = Tx {
        version: 2,
        inputs: vec![
            TxIn {
                previous_output: OutPoint::new(coinbase.txid(), 0),
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            },
            TxIn {
                previous_output: OutPoint::new(Txid::default(), 7),
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            },
        ],
        outputs: vec![
            TxOut {
                value: Amount::from_sat(3_000_000_000),
                script_pubkey: Script::new(),
            },
            TxOut {
                value: Amount::from_sat(1_999_000_000),
                script_pubkey: Script::new(),
            },
        ],
        lock_time: LockTime::ZERO,
    };
    block.txs.push(spend);
    block.header.merkle_root = bitcoin_rs_chain::regtest_fixture::merkle_root(&block.txs)
        .expect("merkle root over two transactions");
    block
}

#[test]
fn percentiles_by_weight_matches_core_thresholds() {
    for (scores, total_weight, expected) in [
        (vec![], 0_u64, [0, 0, 0, 0, 0]),
        (vec![(12, 400)], 400, [12, 12, 12, 12, 12]),
        (vec![(20, 100), (5, 100)], 200, [5, 5, 5, 20, 20]),
        (vec![(2, 1), (5, 1)], 100, [5, 5, 5, 5, 5]),
        (vec![(3, 70), (1, 10), (2, 20)], 100, [1, 2, 3, 3, 3]),
    ] {
        let mut scores = scores;
        assert_eq!(
            percentiles_by_weight(&mut scores, total_weight),
            expected,
            "{scores:?} of {total_weight}"
        );
    }
}

#[test]
fn truncated_median_handles_odd_and_even_lengths() {
    let mut odd = vec![7, 1, 3];
    let mut even = vec![1, 4];

    assert_eq!(truncated_median(&mut odd), 3);
    assert_eq!(truncated_median(&mut even), 2);
}

#[test]
fn compute_fee_fields_skips_indexer_for_coinbase_only_blocks() {
    let ctx = Context::new();
    let block = fixture_genesis();

    let fields = compute_fee_fields(&ctx, &block)
        .unwrap_or_else(|err| panic!("coinbase-only fees should not need txindex: {err}"));
    assert_eq!(fields, FeeFields::default());
}

#[test]
fn undo_read_failures_preserve_core_integrity_and_availability_codes() {
    use bitcoin_rs_utxo::contract::{BlockSpendsError, HistoryUnavailable};
    let corruption = block_spends_error(BlockSpendsError::Corrupt("fixture"));
    assert_eq!(corruption.code(), -32603);
    assert_eq!(
        corruption.to_string(),
        "Undo data expected but can't be read. This could be due to disk corruption or a conflict with a pruning event."
    );
    assert_eq!(
        block_spends_error(BlockSpendsError::History(HistoryUnavailable::Pruned {
            below: 10
        }))
        .code(),
        -1
    );
    assert_eq!(
        block_spends_error(BlockSpendsError::History(HistoryUnavailable::Missing)).code(),
        -1
    );
    assert_eq!(block_spends_error(BlockSpendsError::Retry).code(), -1);
    assert_eq!(
        block_spends_error(BlockSpendsError::BodyRead(
            bitcoin_rs_utxo::contract::BoundedReadError::Unsupported
        ))
        .code(),
        -1
    );
}

#[test]
fn unknown_hashes_are_not_found_on_every_block_response_form() {
    let ctx = Arc::new(Context::new());
    let hash = Hash256::from_le_bytes(&[0xab_u8; 32]).to_string_be();
    for verbosity in [0, 1, 2] {
        assert!(matches!(
            getblock(&ctx, &json!([hash.as_str(), verbosity])),
            Err(RpcError::NotFound("block not found"))
        ));
    }
    for verbose in [false, true] {
        assert!(matches!(
            getblockheader(&ctx, &json!([hash.as_str(), verbose])),
            Err(RpcError::NotFound("block not found"))
        ));
    }
}

#[test]
fn getblock_populates_real_header_fields_from_stored_record()
-> Result<(), Box<dyn std::error::Error>> {
    let genesis = fixture_genesis();
    let record = BlockRecord::from_block(0, &genesis);
    let mut ctx = Context::new();
    ctx.chain.block_body_source = Some(Arc::new(SingleBlockSource {
        height: 0,
        hash: record.hash,
        body: consensus_bytes(&genesis),
        calls: core::sync::atomic::AtomicUsize::new(0),
    }));
    let ctx = Arc::new(ctx);
    let block_hash_hex = record.hash.to_string();
    let block_size = u64::try_from(record.body_size)?;
    let tx_count = u64::try_from(record.tx_count)?;
    seed_block(&ctx, &genesis, record);

    let block_json = getblock(&ctx, &json!([block_hash_hex.as_str(), 1]))?;
    let header_json = getblockheader(&ctx, &json!([block_hash_hex.as_str(), true]))?;
    let header = &genesis.header;
    let version_hex_value = u32::from_le_bytes(header.version.to_le_bytes());
    let version_hex = format!("{version_hex_value:08x}");
    let bits = header.bits;
    let bits_hex = format!("{bits:08x}");
    let merkle_root = header.merkle_root.to_string();
    let previous_block_hash = header.prev_blockhash.to_string();
    let expected_txid = genesis
        .txs
        .first()
        .ok_or("genesis block must contain a coinbase transaction")?
        .txid()
        .to_string();

    for value in [&block_json, &header_json] {
        assert_eq!(value.get("hash").as_str(), Some(block_hash_hex.as_str()));
        assert_eq!(value.get("height").as_u64(), Some(0));
        assert_eq!(
            value.get("version").as_u64(),
            Some(u64::from(u32::from_le_bytes(header.version.to_le_bytes())))
        );
        assert_eq!(value.get("versionHex").as_str(), Some(version_hex.as_str()));
        assert_eq!(value.get("merkleroot").as_str(), Some(merkle_root.as_str()));
        assert_eq!(value.get("time").as_u64(), Some(u64::from(header.time)));
        assert_eq!(value.get("nonce").as_u64(), Some(u64::from(header.nonce)));
        assert_eq!(value.get("bits").as_str(), Some(bits_hex.as_str()));
        assert_eq!(
            value.get("previousblockhash").as_str(),
            Some(previous_block_hash.as_str())
        );
        assert_eq!(value.get("nTx").as_u64(), Some(tx_count));
    }

    assert_eq!(block_json.get("size").as_u64(), Some(block_size));
    assert_eq!(block_json.get("strippedsize").as_u64(), Some(block_size));
    assert_eq!(block_json.get("weight").as_u64(), Some(block_size * 4));
    let tx_value = block_json.get("tx");
    let tx = tx_value
        .as_array()
        .ok_or("getblock tx field must be an array")?;
    assert_eq!(tx.len(), 1);
    assert_eq!(
        tx.first().and_then(JsonValueTrait::as_str),
        Some(expected_txid.as_str())
    );

    Ok(())
}

#[test]
fn getblock_reads_metadata_only_record_from_body_source() -> Result<(), Box<dyn std::error::Error>>
{
    struct SingleBlockSource {
        height: u32,
        hash: BlockHash,
        body: Vec<u8>,
        calls: AtomicUsize,
    }

    impl bitcoin_rs_chain::BlockBodySource for SingleBlockSource {
        fn block_body(
            &self,
            height: u32,
            hash: BlockHash,
        ) -> Result<Option<Vec<u8>>, bitcoin_rs_chain::BlockBodyReadError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok((height == self.height && hash == self.hash).then(|| self.body.clone()))
        }
    }

    let genesis = fixture_genesis();
    let body = consensus_bytes(&genesis);
    let record = BlockRecord::from_block(0, &genesis);
    let block_hash_hex = record.hash.to_string();
    let source = Arc::new(SingleBlockSource {
        height: 0,
        hash: record.hash,
        body: body.clone(),
        calls: AtomicUsize::new(0),
    });
    let calls = Arc::clone(&source);
    let mut ctx = Context::new();
    ctx.chain.block_body_source = Some(source);
    let ctx = Arc::new(ctx);
    seed_block(&ctx, &genesis, record);

    let expected_hex = body.to_lower_hex_string();
    assert_eq!(
        getblock(&ctx, &json!([block_hash_hex.as_str(), 0]))?.as_str(),
        Some(expected_hex.as_str())
    );
    assert_eq!(calls.calls.load(Ordering::Relaxed), 1);
    let block_json = getblock(&ctx, &json!([block_hash_hex.as_str(), 1]))?;
    assert_eq!(calls.calls.load(Ordering::Relaxed), 2);
    assert_eq!(
        block_json.get("size").as_u64(),
        Some(u64::try_from(body.len())?)
    );
    assert_eq!(
        block_json.get("hash").as_str(),
        Some(block_hash_hex.as_str())
    );
    Ok(())
}
#[test]
fn getblock_reports_corrupt_stored_body() {
    let genesis = fixture_genesis();
    let record = BlockRecord::from_block(0, &genesis);
    let hash = record.hash.to_string();
    let mut ctx = Context::new();
    ctx.chain.block_body_source = Some(Arc::new(SingleBlockSource {
        height: 0,
        hash: record.hash,
        body: vec![0x00],
        calls: core::sync::atomic::AtomicUsize::new(0),
    }));
    let ctx = Arc::new(ctx);
    seed_block(&ctx, &genesis, record);

    assert!(matches!(
        getblock(&ctx, &json!([hash.as_str(), 1])),
        Err(RpcError::Internal(message))
            if message == "stored block body is corrupt"
    ));
}

#[test]
fn getblock_verbosity_2_emits_every_transaction_of_the_stored_body() {
    let block = fixture_block_with_spend();
    let record = BlockRecord::from_block(0, &block);
    let mut ctx = Context::new();
    ctx.chain.block_body_source = Some(Arc::new(SingleBlockSource {
        height: 0,
        hash: record.hash,
        body: consensus_bytes(&block),
        calls: core::sync::atomic::AtomicUsize::new(0),
    }));
    let ctx = Arc::new(ctx);
    seed_block(&ctx, &block, record);
    let block_hash = block.block_hash().0;
    let result = getblock(&ctx, &json!([block_hash.to_string_be(), 2]))
        .unwrap_or_else(|err| panic!("getblock failed: {err}"));
    let Some(tx_array) = result.get("tx").and_then(|value| value.as_array()) else {
        panic!("tx field missing: {result:?}");
    };
    assert_eq!(
        tx_array.len(),
        block.txs.len(),
        "one object per transaction: {result:?}"
    );
    for (object, tx) in tx_array.iter().zip(&block.txs) {
        let bytes = consensus_bytes(tx);
        assert_eq!(
            object.get("hex").and_then(JsonValueTrait::as_str),
            Some(bytes.to_lower_hex_string().as_str()),
            "hex must serialize the transaction itself: {object:?}"
        );
        assert_eq!(
            object.get("vsize").and_then(JsonValueTrait::as_u64),
            u64::try_from(bytes.len()).ok(),
            "a witnessless transaction weighs its serialized size: {object:?}"
        );
        assert_eq!(
            object
                .get("vin")
                .and_then(|value| value.as_array())
                .map(sonic_rs::Array::len),
            Some(tx.inputs.len()),
            "vin must carry every input: {object:?}"
        );
        assert_eq!(
            object
                .get("vout")
                .and_then(|value| value.as_array())
                .map(sonic_rs::Array::len),
            Some(tx.outputs.len()),
            "vout must carry every output: {object:?}"
        );
    }
}

#[test]
fn verbose_block_and_raw_consumers_preserve_unsigned_transaction_versions() {
    let mut block = fixture_block_with_spend();
    block.header.version = -1;
    block.txs[0].version = u32::MAX;
    block.txs[1].version = 1_u32 << 31;
    block.header.merkle_root =
        bitcoin_rs_chain::regtest_fixture::merkle_root(&block.txs).expect("fixture merkle root");
    let record = BlockRecord::from_block(0, &block);
    let mut ctx = Context::new();
    ctx.chain.block_body_source = Some(Arc::new(SingleBlockSource {
        height: 0,
        hash: record.hash,
        body: consensus_bytes(&block),
        calls: AtomicUsize::new(0),
    }));
    let ctx = Arc::new(ctx);
    seed_block(&ctx, &block, record);
    let hash = block.block_hash().to_string();
    let header = getblockheader(&ctx, &json!([hash, true])).expect("header");
    assert_eq!(header["version"].as_i64(), Some(-1));
    assert_eq!(header["versionHex"].as_str(), Some("ffffffff"));
    for verbosity in [1, 2, 3] {
        let value = getblock(&ctx, &json!([hash, verbosity])).expect("verbose block");
        assert_eq!(value["version"].as_i64(), Some(-1));
        assert_eq!(value["versionHex"].as_str(), Some("ffffffff"));
        assert_eq!(
            value["coinbase_tx"]["version"].as_u64(),
            Some(4_294_967_295)
        );
        if verbosity == 1 {
            assert!(value.get("nextblockhash").is_some_and(Value::is_null));
            assert_eq!(
                value["tx"][0].as_str(),
                Some(block.txs[0].txid().to_string().as_str())
            );
            continue;
        }
        assert!(value.get("nextblockhash").is_none());
        for (index, expected) in [4_294_967_295, 2_147_483_648].into_iter().enumerate() {
            let object = &value["tx"][index];
            assert_eq!(object["version"].as_u64(), Some(expected));
            assert_eq!(
                object["hex"].as_str(),
                Some(
                    consensus_bytes(&block.txs[index])
                        .to_lower_hex_string()
                        .as_str()
                )
            );
            for field in [
                "fee",
                "blockhash",
                "confirmations",
                "time",
                "blocktime",
                "in_active_chain",
            ] {
                assert!(
                    object.get(field).is_none(),
                    "block transaction omits {field}"
                );
            }
            assert!(object["vin"][0].get("prevout").is_none());
            let raw = super::super::tx::getrawtransaction(
                &ctx,
                &json!([block.txs[index].txid().to_string(), true, hash]),
            )
            .expect("explicit verbose transaction");
            assert_eq!(raw["version"].as_u64(), Some(expected));
            assert_eq!(raw["confirmations"].as_u64(), Some(0));
            assert_eq!(raw["in_active_chain"].as_bool(), Some(false));
            for field in ["time", "blocktime", "fee"] {
                assert!(
                    raw.get(field).is_none(),
                    "inactive raw transaction omits {field}"
                );
            }
        }
    }
}

#[test]
fn gettxoutsetinfo_omits_core_optionals_for_hash_type_none() {
    let ctx = Arc::new(Context::new());
    let result = gettxoutsetinfo(&ctx, &json!(["none"]))
        .unwrap_or_else(|err| panic!("gettxoutsetinfo failed: {err}"));
    assert!(
        result.get("muhash").is_none(),
        "muhash should be absent for hash_type=none: {result:?}"
    );
    assert!(
        result.get("hash_serialized_3").is_none(),
        "hash_serialized_3 should be absent for hash_type=none: {result:?}"
    );
    assert!(
        result.get("total_unspendable_amount").is_none(),
        "total_unspendable_amount should be absent for hash_type=none: {result:?}"
    );
    assert!(
        result.get("block_info").is_none(),
        "block_info should be absent for hash_type=none: {result:?}"
    );
    assert!(result.get("height").is_some());
}

#[test]
fn gettxoutsetinfo_accepts_production_muhash_triplet() {
    let ctx = Arc::new(Context::new());
    let result = gettxoutsetinfo(&ctx, &json!(["muhash", null, false]))
        .unwrap_or_else(|err| panic!("production triplet must be accepted: {err}"));
    assert_eq!(
        result.get("muhash").and_then(JsonValueTrait::as_str),
        Some("dd5ad2a105c2d29495f577245c357409002329b9f4d6182c0af3dc2f462555c8")
    );
    assert!(result.get("height").is_some());
    assert!(result.get("bestblock").is_some());
}

#[test]
fn gettxoutsetinfo_refuses_unsupported_arguments() {
    let ctx = Arc::new(Context::new());
    let unknown_type =
        gettxoutsetinfo(&ctx, &json!(["sha3"])).expect_err("an unknown hash type must be refused");
    assert_eq!(
        unknown_type.to_string(),
        "invalid params: hash_type must be one of: hash_serialized_3, muhash, none"
    );

    let historical_hash = "aa".repeat(32);
    for params in [
        json!(["muhash", 1000, false]),
        json!(["muhash", 1000]),
        json!(["muhash", historical_hash]),
    ] {
        let error = gettxoutsetinfo(&ctx, &params).expect_err("historical height must be refused");
        assert_eq!(
            error.code(),
            RpcError::CORE_INVALID_PARAMETER,
            "{params:?} -> {error}"
        );
        assert!(
            error
                .to_string()
                .contains("Querying specific block heights requires coinstatsindex"),
            "{error}"
        );
    }
}

/// Contract clause: `docs/contracts/muhash-rpc.md` `MRPC-01`.
#[test]
fn gettxoutsetinfo_rejects_trailing_parameters() {
    let ctx = Arc::new(Context::new());
    let trailing = gettxoutsetinfo(&ctx, &json!(["muhash", null, false, true]))
        .expect_err("trailing parameters must be refused");
    assert_eq!(trailing.code(), RpcError::INVALID_PARAMS, "{trailing}");
}

#[test]
fn gettxoutsetinfo_pairs_one_height_with_one_hash_across_a_swap() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let ctx = context_with_tip(
        bitcoin_rs_primitives::Network::Regtest,
        0x207f_ffff,
        &[1_000_000; 6],
    );
    let a = ctx
        .chain
        .applied_tip
        .load_full()
        .expect("fixture publishes an applied tip");
    let b = Arc::new(TipSnapshot {
        tip_id: NodeId::new(u32::MAX),
        height: 7,
        chainwork: ChainWork::ZERO,
        hash: Hash256::from_le_bytes(&[0x0b; 32]),
        chain_tx_count: bitcoin_rs_chain::ChainTxCount::UNKNOWN,
    });
    assert_ne!(a.height, b.height, "the fixture tips must differ");
    assert_ne!(a.hash, b.hash, "the fixture tips must differ");

    let stop = Arc::new(AtomicBool::new(false));
    let (cell, swap_a, swap_b, flag) = (
        ctx.chain.applied_tip.clone(),
        Arc::clone(&a),
        Arc::clone(&b),
        Arc::clone(&stop),
    );
    let swapper = std::thread::spawn(move || {
        let mut flip = false;
        while !flag.load(Ordering::Relaxed) {
            flip = !flip;
            let tip = if flip { &swap_b } else { &swap_a };
            cell.store(Some(Arc::clone(tip)));
        }
    });

    let mut seen_a = false;
    let mut seen_b = false;
    for iteration in 0..100_000 {
        let result = gettxoutsetinfo(&ctx, &json!(null))
            .unwrap_or_else(|error| panic!("gettxoutsetinfo failed: {error}"));
        let height = result
            .get("height")
            .and_then(Value::as_i64)
            .expect("height");
        let best = result
            .get("bestblock")
            .and_then(Value::as_str)
            .expect("best_block");
        assert!(
            result.get("hash_serialized_3").is_some(),
            "the scan must still run and report its hash"
        );
        if height == 7 {
            assert_eq!(best, b.hash.to_string_be(), "a foreign hash rode height 7");
            seen_b = true;
        } else {
            assert_eq!(height, 5, "the route reported an unpublished height");
            assert_eq!(best, a.hash.to_string_be(), "a foreign hash rode height 5");
            seen_a = true;
        }
        if iteration >= 199 && seen_a && seen_b {
            break;
        }
        std::thread::yield_now();
    }
    stop.store(true, Ordering::Relaxed);
    swapper.join().expect("swapper thread panicked");
    assert!(
        seen_a && seen_b,
        "a publication was never observed, so coherence proved nothing"
    );
}

struct Fork {
    ctx: Arc<Context>,
    applied: Hash256,
    fork: Hash256,
    header_tip: Hash256,
    applied_header: Header,
    fork_header: Header,
}

fn forked_ctx() -> Result<Fork, Box<dyn std::error::Error>> {
    use bitcoin_rs_chain::NodeStatus;

    let ctx = Context::new();
    let header = |prev: BlockHash, nonce: u32, time: u32| Header {
        version: 1,
        prev_blockhash: prev,
        merkle_root: Hash256::default(),
        time,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce,
    };

    let (applied_tip, header_tip, fork_hash, applied_header, fork_header) = {
        let mut tree = ctx.chain.block_tree.write();
        let genesis = header(BlockHash::default(), 0, 1_000_000);
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::Active)?;

        let applied = header(genesis.compute_hash(), 1, 1_000_900);
        let applied_id = tree.insert_node(Some(genesis_id), applied, NodeStatus::Active)?;
        let applied_tip = tree
            .tip()
            .ok_or_else(|| std::io::Error::other("missing applied tip"))?;
        assert_eq!(applied_tip.tip_id, applied_id);

        let fork = header(genesis.compute_hash(), 2, 1_000_901);
        let fork_id = tree.insert_node(Some(genesis_id), fork, NodeStatus::HeaderValid)?;
        let fork_hash = tree.node(fork_id)?.hash;
        let fork_tip = header(fork.compute_hash(), 3, 1_001_800);
        let _header_tip_id = tree.insert_node(Some(fork_id), fork_tip, NodeStatus::HeaderValid)?;
        let header_tip = tree
            .tip()
            .ok_or_else(|| std::io::Error::other("missing header tip"))?;
        (applied_tip, header_tip, fork_hash, applied, fork)
    };

    ctx.chain
        .applied_tip
        .store(Some(Arc::new((*applied_tip).clone())));
    ctx.chain
        .chain_tip
        .store(Some(Arc::new((*header_tip).clone())));
    Ok(Fork {
        ctx: Arc::new(ctx),
        applied: applied_tip.hash,
        fork: fork_hash,
        header_tip: header_tip.hash,
        applied_header,
        fork_header,
    })
}

#[test]
fn confirmations_count_applied_depth_and_answer_minus_one_off_the_chain()
-> Result<(), Box<dyn std::error::Error>> {
    let Fork {
        ctx,
        applied: applied_hash,
        fork: fork_hash,
        header_tip: header_tip_hash,
        ..
    } = forked_ctx()?;
    let view = ctx.chain.applied_view();

    assert_eq!(confirmations(&ctx, &view, applied_hash, 1), 1);

    assert_ne!(applied_hash, fork_hash, "the fixture branches must differ");
    let unknown = Hash256::from_le_bytes(&[0xab_u8; 32]);
    for (label, hash, height) in [
        ("a branch that lost the reorg", fork_hash, 1),
        ("a header above the applied tip", header_tip_hash, 2),
        ("a hash the tree never saw", unknown, 1),
    ] {
        assert_eq!(
            confirmations(&ctx, &view, hash, height),
            -1,
            "{label} is not in the applied chain at any depth"
        );
    }
    Ok(())
}

#[test]
fn verbose_block_facts_never_straddle_two_applied_publications()
-> Result<(), Box<dyn std::error::Error>> {
    use std::sync::atomic::{AtomicBool, Ordering};

    use bitcoin_rs_chain::NodeStatus;

    let ctx = Context::new();
    let header = |prev: BlockHash, nonce: u32, time: u32| Header {
        version: 1,
        prev_blockhash: prev,
        merkle_root: Hash256::default(),
        time,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce,
    };
    let genesis = header(BlockHash::default(), 0, 1_000_000);
    let a1 = header(genesis.compute_hash(), 1, 1_000_900);
    let b1 = header(genesis.compute_hash(), 2, 1_000_901);
    let b2 = header(b1.compute_hash(), 3, 1_001_800);
    let (a1_hash, b2_hash) = (a1.compute_hash(), b2.compute_hash());

    let (a_tip, b_tip) = {
        let mut tree = ctx.chain.block_tree.write();
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::Active)?;
        let a1_id = tree.insert_node(Some(genesis_id), a1, NodeStatus::Active)?;
        let b1_id = tree.insert_node(Some(genesis_id), b1, NodeStatus::HeaderValid)?;
        let b2_id = tree.insert_node(Some(b1_id), b2, NodeStatus::HeaderValid)?;
        (
            Arc::new(TipSnapshot {
                tip_id: a1_id,
                height: 1,
                chainwork: ChainWork::ZERO,
                hash: a1_hash.0,
                chain_tx_count: bitcoin_rs_chain::ChainTxCount::UNKNOWN,
            }),
            Arc::new(TipSnapshot {
                tip_id: b2_id,
                height: 2,
                chainwork: ChainWork::ZERO,
                hash: b2_hash.0,
                chain_tx_count: bitcoin_rs_chain::ChainTxCount::UNKNOWN,
            }),
        )
    };
    let mut block = fixture_genesis();
    block.header = a1;
    ctx.chain.add_block(BlockRecord::from_block(1, &block));
    let record = ctx
        .chain
        .block_by_hash(Hash256::from(a1_hash))
        .expect("fixture record resolves through the tree");
    ctx.chain.applied_tip.store(Some(Arc::clone(&a_tip)));

    let stop = Arc::new(AtomicBool::new(false));
    let (cell, swap_a, swap_b, flag) = (
        ctx.chain.applied_tip.clone(),
        a_tip,
        b_tip,
        Arc::clone(&stop),
    );
    let swapper = std::thread::spawn(move || {
        let mut flip = false;
        while !flag.load(Ordering::Relaxed) {
            flip = !flip;
            let tip = if flip { &swap_b } else { &swap_a };
            cell.store(Some(Arc::clone(tip)));
        }
    });

    let ctx = Arc::new(ctx);
    let mut seen_a = false;
    let mut seen_b = false;
    for iteration in 0..100_000 {
        let value = block_verbose_typed(&ctx, &record, false, 1)?;
        let confirmations = value
            .get("confirmations")
            .and_then(Value::as_i64)
            .expect("confirmations");
        let next = value.get("nextblockhash");
        seen_a |= confirmations == 1;
        seen_b |= confirmations == -1;
        match confirmations {
            1 => assert!(
                next.is_none_or(Value::is_null),
                "under the a1 tip the next applied height is unmined, yet {next:?} appeared"
            ),
            -1 => assert!(
                next.is_none_or(Value::is_null),
                "Core omits the successor of a block outside the applied chain"
            ),
            other => panic!("confirmations {other} matches no published branch"),
        }
        if iteration >= 199 && seen_a && seen_b {
            break;
        }
        std::thread::yield_now();
    }
    stop.store(true, Ordering::Relaxed);
    swapper.join().expect("swapper thread panicked");
    assert!(
        seen_a && seen_b,
        "a publication was never observed, so coherence proved nothing"
    );
    Ok(())
}

#[test]
fn getblockheader_answers_a_header_only_tree_node() -> Result<(), Box<dyn std::error::Error>> {
    let Fork {
        ctx,
        fork,
        fork_header,
        ..
    } = forked_ctx()?;
    let hash = fork.to_string_be();

    let raw = getblockheader(&ctx, &json!([hash.as_str(), false]))?;
    assert_eq!(
        raw.as_str(),
        Some(consensus_bytes(&fork_header).to_lower_hex_string().as_str())
    );

    let verbose = getblockheader(&ctx, &json!([hash.as_str(), true]))?;
    assert_eq!(verbose.get("hash").as_str(), Some(hash.as_str()));
    assert_eq!(verbose.get("confirmations").as_i64(), Some(-1));
    assert_eq!(verbose.get("height").as_u64(), Some(1));
    assert_eq!(
        verbose.get("version").as_i64(),
        Some(i64::from(u32::from_le_bytes(
            fork_header.version.to_le_bytes(),
        )))
    );
    assert_eq!(
        verbose.get("merkleroot").as_str(),
        Some(fork_header.merkle_root.to_string().as_str())
    );
    assert_eq!(
        verbose.get("time").as_u64(),
        Some(u64::from(fork_header.time))
    );
    assert_eq!(
        verbose.get("nonce").as_u64(),
        Some(u64::from(fork_header.nonce))
    );
    assert_eq!(verbose.get("nTx").as_u64(), Some(0));
    Ok(())
}

#[test]
fn getblockstats_rejects_a_stale_block_hash() -> Result<(), Box<dyn std::error::Error>> {
    let Fork {
        ctx,
        fork: fork_hash,
        ..
    } = forked_ctx()?;
    ctx.chain
        .add_block(BlockRecord::synthetic(1, BlockHash::from(fork_hash)));

    let result = getblockstats(&ctx, &json!([fork_hash.to_string_be()]));
    assert!(
        matches!(
            result,
            Err(RpcError::InvalidParams("Block is not in main chain"))
        ),
        "stale hash must not compute fees from the active index, got {result:?}"
    );
    Ok(())
}

fn coinbase_only_block(header: Header) -> Block {
    let coinbase = Tx {
        version: 1,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: vec![0x51].into(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(50 * 100_000_000),
            script_pubkey: vec![0x51].into(),
        }],
    };
    Block {
        header,
        txs: vec![coinbase],
    }
}

fn record_for(header: Header, with_body: bool) -> BlockRecord {
    if !with_body {
        let hash = header.compute_hash().0;
        return BlockRecord::synthetic(1, BlockHash::from(hash));
    }
    BlockRecord::from_block(1, &coinbase_only_block(header))
}

fn assert_reorged_block_reports_negative_confirmations(
    with_body: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let Fork {
        mut ctx,
        applied: applied_hash,
        fork: fork_hash,
        applied_header,
        fork_header,
        ..
    } = forked_ctx()?;
    let applied_record = record_for(applied_header, with_body);
    let fork_record = record_for(fork_header, with_body);
    if with_body {
        let applied_block = coinbase_only_block(applied_header);
        let fork_block = coinbase_only_block(fork_header);
        Arc::get_mut(&mut ctx)
            .expect("unique fork fixture context")
            .chain
            .block_body_source = Some(Arc::new(BlockBodies {
            bodies: vec![
                (
                    applied_record.height,
                    applied_record.hash,
                    consensus_bytes(&applied_block),
                ),
                (
                    fork_record.height,
                    fork_record.hash,
                    consensus_bytes(&fork_block),
                ),
            ],
        }));
    }
    ctx.chain.add_block(applied_record);
    ctx.chain.add_block(fork_record);

    let handler = crate::Handler::new(Arc::clone(&ctx));
    let confirmations_of =
        |method: &str, hash: Hash256| -> Result<i64, Box<dyn std::error::Error>> {
            let value = handler.dispatch(method, &json!([hash.to_string_be(), true]))?;
            value
                .get("confirmations")
                .and_then(JsonValueTrait::as_i64)
                .ok_or_else(|| {
                    Box::<dyn std::error::Error>::from(format!(
                        "confirmations missing or not an integer: {value:?}"
                    ))
                })
        };

    let methods = if with_body {
        &["getblockheader", "getblock"][..]
    } else {
        &["getblockheader"][..]
    };
    for method in methods {
        assert_eq!(confirmations_of(method, applied_hash)?, 1, "{method}");
        assert_eq!(
            confirmations_of(method, fork_hash)?,
            -1,
            "{method} must carry the -1 through, not clamp it"
        );
    }
    if !with_body {
        for hash in [applied_hash, fork_hash] {
            assert!(matches!(
                handler.dispatch("getblock", &json!([hash.to_string_be(), true])),
                Err(RpcError::NotFound("block data pruned"))
            ));
        }
    }
    Ok(())
}

#[test]
fn reorged_block_reports_negative_confirmations_stored_or_pruned()
-> Result<(), Box<dyn std::error::Error>> {
    for with_body in [true, false] {
        assert_reorged_block_reports_negative_confirmations(with_body)?;
    }
    Ok(())
}

#[test]
fn getblockchaininfo_verificationprogress_follows_the_two_tips() {
    let tip = |height: u32| {
        Arc::new(TipSnapshot {
            tip_id: NodeId::new(0),
            height,
            chainwork: ChainWork::ZERO,
            hash: Hash256::from_le_bytes(&[7_u8; 32]),
            chain_tx_count: bitcoin_rs_chain::ChainTxCount::UNKNOWN,
        })
    };
    let cases: [(&str, Option<u32>, Option<u32>, f64); 3] = [
        ("half applied", Some(100), Some(50), 0.5),
        ("no header tip", None, None, 0.0),
        ("applied past headers", Some(50), Some(100), 1.0),
    ];

    for (label, headers, applied, expected) in cases {
        let ctx = Arc::new(Context::new());
        ctx.chain.chain_tip.store(headers.map(tip));
        ctx.chain.applied_tip.store(applied.map(tip));
        let result = getblockchaininfo(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getblockchaininfo failed: {err}"));
        let Some(progress) = result
            .get("verificationprogress")
            .and_then(JsonValueTrait::as_f64)
        else {
            panic!("{label}: verificationprogress missing: {result:?}");
        };
        assert!(
            (progress - expected).abs() < 1e-6,
            "{label}: expected {expected}, got {progress}"
        );
    }
}

#[test]
fn getblockchaininfo_names_testnet4_separately_from_testnet3() {
    let mut context = Context::new();
    context.chain.chain_network = bitcoin_rs_primitives::Network::Testnet4;
    let result = getblockchaininfo(&Arc::new(context), &json!([]))
        .unwrap_or_else(|err| panic!("getblockchaininfo failed: {err}"));

    assert_eq!(
        result.get("chain").and_then(JsonValueTrait::as_str),
        Some("testnet4")
    );
}

#[test]
fn getblockchaininfo_size_on_disk_zero_for_empty_blocks() {
    let ctx = Arc::new(Context::new());
    let result = getblockchaininfo(&ctx, &json!([]))
        .unwrap_or_else(|err| panic!("getblockchaininfo failed: {err}"));
    assert_eq!(
        result.get("size_on_disk").and_then(JsonValueTrait::as_u64),
        Some(0)
    );
}

#[test]
fn difficulty_matches_core_for_mainnet_and_regtest_targets() {
    let ctx = Context::new();
    let mainnet = ctx
        .chain
        .difficulty_for_bits(CompactTarget::from_consensus(0x1d00_ffff));
    assert_eq!(mainnet.to_bits(), 1.0_f64.to_bits());
    let regtest = ctx
        .chain
        .difficulty_for_bits(CompactTarget::from_consensus(0x207f_ffff));
    let expected = 4.656_542_373_906_924_7e-10_f64;
    assert_eq!(regtest.to_bits(), expected.to_bits());
}

#[test]
fn getblockchaininfo_reports_tip_time_and_median_time_past() {
    let ctx = context_with_tip(
        bitcoin_rs_primitives::Network::Regtest,
        0x207f_ffff,
        &[100, 300, 200],
    );
    let result = getblockchaininfo(&ctx, &json!([]))
        .unwrap_or_else(|err| panic!("getblockchaininfo failed: {err}"));

    assert_eq!(
        result.get("time").and_then(JsonValueTrait::as_u64),
        Some(200)
    );
    assert_eq!(
        result.get("mediantime").and_then(JsonValueTrait::as_u64),
        Some(200)
    );
    let difficulty = result
        .get("difficulty")
        .and_then(JsonValueTrait::as_f64)
        .unwrap_or_default();
    assert_eq!(
        difficulty.to_bits(),
        4.656_542_373_906_924_7e-10_f64.to_bits()
    );
}

#[test]
fn getblockchaininfo_uses_one_applied_tip_snapshot() {
    use bitcoin_rs_chain::ChainWork;

    let ctx = context_with_tip(
        bitcoin_rs_primitives::Network::Regtest,
        0x207f_ffff,
        &[100, 300, 200],
    );
    let Some(applied) = ctx.chain.applied_tip.load_full() else {
        panic!("applied tip missing");
    };
    let applied_chainwork = ChainWork::from_be_bytes([1; 32]);
    ctx.chain.applied_tip.store(Some(Arc::new(TipSnapshot {
        chainwork: applied_chainwork,
        ..(*applied).clone()
    })));
    ctx.chain.chain_tip.store(Some(Arc::new(TipSnapshot {
        tip_id: applied.tip_id,
        height: 99,
        chainwork: ChainWork::from_be_bytes([2; 32]),
        hash: Hash256::from_le_bytes(&[9; 32]),
        chain_tx_count: bitcoin_rs_chain::ChainTxCount::UNKNOWN,
    })));

    let result = getblockchaininfo(&ctx, &json!([]))
        .unwrap_or_else(|err| panic!("getblockchaininfo failed: {err}"));
    let expected_hash = applied.hash.to_string_be();
    let expected_chainwork = "01".repeat(32);
    assert_eq!(
        result.get("blocks").and_then(JsonValueTrait::as_u64),
        Some(2)
    );
    assert_eq!(
        result.get("headers").and_then(JsonValueTrait::as_u64),
        Some(99)
    );
    assert_eq!(
        result.get("bestblockhash").and_then(JsonValueTrait::as_str),
        Some(expected_hash.as_str())
    );
    assert_eq!(
        result.get("chainwork").and_then(JsonValueTrait::as_str),
        Some(expected_chainwork.as_str())
    );
}

#[test]
fn getblockchaininfo_size_on_disk_uses_metadata_body_size() {
    let genesis = fixture_genesis();
    let body = consensus_bytes(&genesis);
    let record = BlockRecord::from_block(0, &genesis);
    let ctx = Arc::new(Context::new());
    ctx.chain.add_block(record);

    let result = getblockchaininfo(&ctx, &json!([]))
        .unwrap_or_else(|err| panic!("getblockchaininfo failed: {err}"));

    assert_eq!(
        result.get("size_on_disk").and_then(JsonValueTrait::as_u64),
        Some(u64::try_from(body.len()).unwrap_or(u64::MAX))
    );
}

#[test]
fn getblockchaininfo_size_on_disk_comes_from_the_block_store() {
    struct SizedStore(u64);

    impl bitcoin_rs_chain::BlockBodySource for SizedStore {
        fn block_body(
            &self,
            _height: u32,
            _hash: BlockHash,
        ) -> Result<Option<Vec<u8>>, bitcoin_rs_chain::BlockBodyReadError> {
            Ok(None)
        }
        fn disk_usage(&self) -> Option<u64> {
            Some(self.0)
        }
    }

    let genesis = fixture_genesis();
    let record = BlockRecord::from_block(0, &genesis);
    let record_bytes = u64::try_from(record.body_size).unwrap_or(u64::MAX);
    let store_bytes = record_bytes.saturating_add(4_096);
    let ctx = Arc::new(Context::new().with_block_body_source(Arc::new(SizedStore(store_bytes))));
    ctx.chain.add_block(record);

    let result = getblockchaininfo(&ctx, &json!([]))
        .unwrap_or_else(|err| panic!("getblockchaininfo failed: {err}"));

    assert_eq!(
        result.get("size_on_disk").and_then(JsonValueTrait::as_u64),
        Some(store_bytes),
        "size_on_disk must come from the store that owns the bytes"
    );
}

#[test]
fn getchaintxstats_emits_core_shape_with_zero_blocks() {
    use alloc::sync::Arc;

    let ctx = Arc::new(Context::new());
    let result = getchaintxstats(&ctx, &json!([]))
        .unwrap_or_else(|err| panic!("getchaintxstats failed: {err}"));
    assert!(result.get("time").is_some());
    assert!(result.get("window_final_block_height").is_some());
    assert!(result.get("txcount").is_none(), "{result:?}");
}

#[test]
fn getchaintxstats_window_tx_count_includes_in_range_blocks() {
    use alloc::sync::Arc;

    let ctx = Arc::new(Context::new());
    let genesis = fixture_genesis();
    let tip = {
        let mut tree = ctx.chain.block_tree.write();
        let id = tree
            .insert_node(None, genesis.header, NodeStatus::Active)
            .unwrap_or_else(|err| panic!("insert genesis: {err}"));
        tree.restore_chain_tx_count(id, bitcoin_rs_chain::ChainTxCount::established(1))
            .unwrap_or_else(|err| panic!("record genesis: {err}"));
        let node = tree
            .node(id)
            .unwrap_or_else(|err| panic!("genesis node: {err}"));
        TipSnapshot {
            tip_id: id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
            chain_tx_count: bitcoin_rs_chain::ChainTxCount::established(42),
        }
    };
    ctx.chain.applied_tip.store(Some(Arc::new(tip)));
    let result = getchaintxstats(&ctx, &json!([]))
        .unwrap_or_else(|err| panic!("getchaintxstats failed: {err}"));
    let Some(txcount) = result.get("txcount").and_then(JsonValueTrait::as_u64) else {
        panic!("txcount missing: {result:?}");
    };
    assert_eq!(txcount, 1);
}

#[test]
fn getchaintxstats_uses_the_applied_tip_count_when_per_node_count_is_unset() {
    use alloc::sync::Arc;

    let ctx = Arc::new(Context::new());
    let genesis = fixture_genesis();
    let tip = {
        let mut tree = ctx.chain.block_tree.write();
        let id = tree
            .insert_node(None, genesis.header, NodeStatus::Active)
            .unwrap_or_else(|err| panic!("insert genesis: {err}"));
        let node = tree
            .node(id)
            .unwrap_or_else(|err| panic!("genesis node: {err}"));
        TipSnapshot {
            tip_id: id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
            chain_tx_count: bitcoin_rs_chain::ChainTxCount::established(42),
        }
    };
    ctx.chain.applied_tip.store(Some(Arc::new(tip)));
    let result = getchaintxstats(&ctx, &json!([]))
        .unwrap_or_else(|err| panic!("getchaintxstats failed: {err}"));
    let Some(txcount) = result.get("txcount").and_then(JsonValueTrait::as_u64) else {
        panic!("txcount missing: {result:?}");
    };
    assert_eq!(txcount, 42);
}

#[test]
fn getchaintxstats_time_reflects_tip_block_header_timestamp() {
    let ctx = Arc::new(Context::new());
    let genesis = fixture_genesis();
    let expected_time = genesis.header.time;
    let tip = {
        let mut tree = ctx.chain.block_tree.write();
        let id = tree
            .insert_node(None, genesis.header, NodeStatus::Active)
            .unwrap_or_else(|err| panic!("insert genesis: {err}"));
        let node = tree
            .node(id)
            .unwrap_or_else(|err| panic!("genesis node: {err}"));
        TipSnapshot {
            tip_id: id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
            chain_tx_count: bitcoin_rs_chain::ChainTxCount::established(42),
        }
    };
    ctx.chain.applied_tip.store(Some(Arc::new(tip)));
    let result = getchaintxstats(&ctx, &json!([]))
        .unwrap_or_else(|err| panic!("getchaintxstats failed: {err}"));
    let Some(time) = result.get("time").and_then(JsonValueTrait::as_u64) else {
        panic!("time missing: {result:?}");
    };
    assert_eq!(time, u64::from(expected_time));
}

fn shaped_log() -> BlockLog {
    const HEIGHTS: [u32; 10] = [0, 1, 2, 3, 3, 4, 5, 6, 7, 8];
    const TIMES: [u32; 10] = [
        1_000, 1_010, 1_020, 1_030, 1_031, 1_040, 1_035, 1_060, 1_070, 1_080,
    ];
    let mut log = BlockLog::new();
    for (index, (height, time)) in HEIGHTS.into_iter().zip(TIMES).enumerate() {
        log.push(BlockRecord {
            hash: BlockHash::from(Hash256::from_le_bytes(
                &[u8::try_from(index).unwrap_or(0); 32],
            )),
            height,
            body_size: 100 + index * 7,
            header: None,
            tx_count: 1 + index * 3,
            time,
        });
    }
    log
}

#[test]
fn cumulative_tx_count_through_requires_a_genesis_prefix() {
    let log = shaped_log();
    assert_eq!(
        cumulative_tx_count_through(&log, 3),
        Some(1 + 4 + 7 + 10 + 13)
    );
    assert_eq!(cumulative_tx_count_through(&log, 8), Some(145));
    assert_eq!(
        cumulative_tx_count_through(&log, 9),
        None,
        "a height the log has not reached is unknown"
    );

    let mut without_genesis = BlockLog::new();
    for record in log.iter().skip(1).cloned() {
        without_genesis.push(record);
    }
    assert_eq!(
        cumulative_tx_count_through(&without_genesis, 3),
        None,
        "a prefix that does not start at genesis is not a chain total"
    );
}

#[test]
fn block_log_running_sums_track_push_pop_and_clear() {
    let mut log = shaped_log();
    assert_eq!(log.size_on_disk(), 1_315);
    assert_eq!(log.total_tx_count(), 145);
    assert_eq!(log.tx_count_before(4), 1 + 4 + 7 + 10);
    assert_eq!(log.tx_count_before(0), 0);
    assert_eq!(log.tx_count_before(usize::MAX), 145);

    let _popped = log.pop();
    assert_eq!(log.size_on_disk(), 1_315 - 163);
    assert_eq!(log.total_tx_count(), 145 - 28);
    assert_eq!(log.tx_count_before(usize::MAX), 145 - 28);

    log.clear();
    assert_eq!(log.size_on_disk(), 0, "clear must reset the running sums");
    assert_eq!(log.total_tx_count(), 0, "clear must reset the running sums");
}

#[test]
fn block_log_running_sums_saturate_instead_of_wrapping() {
    let max = usize::try_from(u64::MAX).unwrap_or(usize::MAX);
    let record = |body_size: usize, tx_count: usize| BlockRecord {
        hash: BlockHash::from(Hash256::from_le_bytes(&[0_u8; 32])),
        height: 0,
        body_size,
        header: None,
        tx_count,
        time: 0,
    };
    let mut log = BlockLog::new();
    log.push(record(max, max));
    assert_eq!(log.size_on_disk(), u64::MAX);
    assert_eq!(log.total_tx_count(), u64::MAX);
    log.push(record(1, 1));
    assert_eq!(log.size_on_disk(), u64::MAX);
    assert_eq!(log.total_tx_count(), u64::MAX);
}

#[test]
fn getchaintxstats_two_block_window_uses_one_folded_window()
-> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());
    let tip = {
        let mut tree = ctx.chain.block_tree.write();
        let mut parent = None;
        let mut prev = BlockHash::default();
        let mut tip = None;
        let mut cumulative = 0_u64;
        for height in 0_u32..4 {
            let header = Header {
                version: 1,
                prev_blockhash: prev,
                merkle_root: Hash256::default(),
                time: 1_000_u32.saturating_add(height.saturating_mul(10)),
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: height,
            };
            prev = header.compute_hash();
            let id = tree.insert_node(parent, header, NodeStatus::Active)?;
            cumulative = cumulative.saturating_add(u64::from(height.saturating_add(1)));
            tree.restore_chain_tx_count(
                id,
                bitcoin_rs_chain::ChainTxCount::established(cumulative),
            )?;
            parent = Some(id);
            let node = tree.node(id)?;
            tip = Some(TipSnapshot {
                tip_id: id,
                height: node.height,
                chainwork: node.chainwork,
                hash: node.hash,
                chain_tx_count: node.chain_tx_count,
            });
        }
        tip.ok_or("missing tip")?
    };
    ctx.chain.applied_tip.store(Some(Arc::new(tip)));

    let result = getchaintxstats(&ctx, &json!([2]))
        .unwrap_or_else(|err| panic!("getchaintxstats failed: {err}"));

    assert_eq!(
        result.get("txcount").and_then(JsonValueTrait::as_u64),
        Some(10)
    );
    assert_eq!(
        result
            .get("window_block_count")
            .and_then(JsonValueTrait::as_u64),
        Some(2)
    );
    assert_eq!(
        result
            .get("window_tx_count")
            .and_then(JsonValueTrait::as_u64),
        Some(7)
    );
    assert_eq!(
        result
            .get("window_interval")
            .and_then(JsonValueTrait::as_i64),
        Some(10)
    );
    assert_eq!(
        result.get("time").and_then(JsonValueTrait::as_u64),
        Some(1_030)
    );
    Ok(())
}

#[test]
fn getchaintxstats_rejects_nblocks_equal_to_selected_height()
-> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());
    let tip = {
        let mut tree = ctx.chain.block_tree.write();
        let mut parent = None;
        let mut prev = BlockHash::default();
        let mut tip = None;
        for height in 0_u32..4 {
            let header = Header {
                version: 1,
                prev_blockhash: prev,
                merkle_root: Hash256::default(),
                time: 1_000_u32.saturating_add(height.saturating_mul(10)),
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: height,
            };
            prev = header.compute_hash();
            let id = tree.insert_node(parent, header, NodeStatus::Active)?;
            parent = Some(id);
            let node = tree.node(id)?;
            tip = Some(TipSnapshot {
                tip_id: id,
                height: node.height,
                chainwork: node.chainwork,
                hash: node.hash,
                chain_tx_count: node.chain_tx_count,
            });
        }
        tip.ok_or("missing tip")?
    };
    ctx.chain.applied_tip.store(Some(Arc::new(tip)));

    let rejected = getchaintxstats(&ctx, &json!([3]));
    assert!(
        matches!(
            &rejected,
            Err(RpcError::InvalidParameter(message))
                if message == "Invalid block count: should be between 0 and the block's height - 1"
        ),
        "nblocks equal to height must be rejected, got {rejected:?}"
    );
    getchaintxstats(&ctx, &json!([2]))
        .unwrap_or_else(|err| panic!("height - 1 must remain accepted: {err}"));
    Ok(())
}

#[test]
fn getchaintxstats_tip_time_uses_first_applied_height_record() {
    let ctx = Arc::new(Context::new());
    let tip = {
        let mut tree = ctx.chain.block_tree.write();
        let mut parent = None;
        let mut prev = BlockHash::default();
        let mut tip = None;
        for (height, time) in [(0_u32, 100_u32), (1, 150), (2, 200)] {
            let header = Header {
                version: 1,
                prev_blockhash: prev,
                merkle_root: Hash256::default(),
                time,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: height,
            };
            prev = header.compute_hash();
            let id = tree
                .insert_node(parent, header, NodeStatus::Active)
                .unwrap_or_else(|err| panic!("insert {height}: {err}"));
            tree.restore_chain_tx_count(
                id,
                bitcoin_rs_chain::ChainTxCount::established(u64::from(height) + 1),
            )
            .unwrap_or_else(|err| panic!("count {height}: {err}"));
            parent = Some(id);
            let node = tree
                .node(id)
                .unwrap_or_else(|err| panic!("node {height}: {err}"));
            tip = Some(TipSnapshot {
                tip_id: id,
                height: node.height,
                chainwork: node.chainwork,
                hash: node.hash,
                chain_tx_count: node.chain_tx_count,
            });
        }
        tip.unwrap_or_else(|| panic!("missing tip"))
    };
    ctx.chain.applied_tip.store(Some(Arc::new(tip)));

    let result = getchaintxstats(&ctx, &json!([]))
        .unwrap_or_else(|err| panic!("getchaintxstats failed: {err}"));

    assert_eq!(
        result.get("time").and_then(JsonValueTrait::as_u64),
        Some(200)
    );
}

#[test]
fn getchaintips_marks_active_from_applied_tip() {
    let ctx = Arc::new(Context::new());
    let genesis = fixture_genesis();
    let applied_hash = genesis.block_hash().0;
    let applied_id = {
        let mut tree = ctx.chain.block_tree.write();
        tree.insert_node(None, genesis.header, NodeStatus::Active)
            .expect("genesis")
    };
    let header_only = Header {
        version: 1,
        prev_blockhash: genesis.header.compute_hash(),
        merkle_root: Hash256::default(),
        time: genesis.header.time.saturating_add(600),
        bits: genesis.header.bits,
        nonce: 7,
    };
    let header_hash = header_only.compute_hash().0;
    let header_id = {
        let mut tree = ctx.chain.block_tree.write();
        tree.insert_node(Some(applied_id), header_only, NodeStatus::HeaderValid)
            .expect("header")
    };
    ctx.chain.applied_tip.store(Some(Arc::new(TipSnapshot {
        tip_id: applied_id,
        height: 0,
        chainwork: ChainWork::ZERO,
        hash: applied_hash,
        chain_tx_count: bitcoin_rs_chain::ChainTxCount::UNKNOWN,
    })));
    ctx.chain.chain_tip.store(Some(Arc::new(TipSnapshot {
        tip_id: header_id,
        height: 1,
        chainwork: ChainWork::ZERO,
        hash: header_hash,
        chain_tx_count: bitcoin_rs_chain::ChainTxCount::UNKNOWN,
    })));
    let tips = getchaintips(&ctx, &json!([])).unwrap();
    let tips = tips.as_array().expect("array");
    let active = tips
        .iter()
        .find(|tip| tip.get("status").and_then(JsonValueTrait::as_str) == Some("active"))
        .expect("active tip");
    let expected = applied_hash.to_string_be();
    assert_eq!(
        active.get("hash").and_then(JsonValueTrait::as_str),
        Some(expected.as_str())
    );
}
