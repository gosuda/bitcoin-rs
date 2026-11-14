use alloc::sync::Arc;

use bitcoin_rs_consensus::primitives::{
    Block, BlockHash, Hash256, Header, OutPoint, Tx, TxIn, TxOut, Txid, consensus_bytes,
};
use bitcoin_rs_execution::chain::{LatchReader, NodeId, NodeStatus, TipSnapshot};
use bitcoin_rs_mempool::{AdmissionOrigin, MempoolEntry, arm_admission_park, reset_admission_park};
use bitcoin_rs_storage::utxo::contract::{BlockChanges, UtxoAdd};
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, Value, json};
use std::sync::mpsc;
use std::thread;

use super::{getrawtransaction, gettxout};
use crate::Handler;
use crate::context::{Context, DerivedIndexQuery, TxQueryError};
use crate::error::RpcError;
use bitcoin::hex::DisplayHex as _;
use bitcoin_rs_projection::block_log::BlockRecord;

fn fixture_genesis() -> Block {
    use bitcoin_rs_consensus::primitives::{
        Amount, CompactTarget, LockTime, Script, Sequence, Witness,
    };
    let coinbase = Tx {
        version: 1,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: Script::from_bytes(vec![0x51; 4]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(50),
            script_pubkey: Script::from_bytes(vec![0x51]),
        }],
    };
    let mut block = Block {
        header: Header {
            version: 1,
            prev_blockhash: BlockHash::default(),
            merkle_root: Hash256::default(),
            time: 0,
            bits: CompactTarget::from_consensus(0),
            nonce: 0,
        },
        txs: vec![coinbase],
    };
    block.header.merkle_root =
        bitcoin_rs_execution::chain::regtest_fixture::merkle_root(&block.txs).unwrap_or_default();
    block
}

#[test]
fn getrawtransaction_falls_back_to_mempool_for_unconfirmed()
-> Result<(), crate::test_error::TestError> {
    let ctx = Arc::new(Context::new());
    let genesis = fixture_genesis();
    let coinbase = genesis
        .txs
        .first()
        .ok_or_else(|| RpcError::Internal("genesis has no transactions".to_owned()))?
        .clone();
    let txid = coinbase.txid();
    {
        let mut pool = ctx.mempool.gateway.pool().write();
        let vsize = u32::try_from(coinbase.vsize())?;
        let entry = MempoolEntry::new(Arc::new(coinbase.clone()), vsize, u64::from(vsize), 0, 0, 0);
        pool.insert_entry(entry)?;
    }

    let result = getrawtransaction(&ctx, &json!([txid.to_string()]))?;

    let expected = consensus_bytes(&coinbase).to_lower_hex_string();
    assert_eq!(result.as_str(), Some(expected.as_str()));
    let output = gettxout(&ctx, &json!([txid.to_string(), 0]))?;
    assert_eq!(output["confirmations"], json!(0));
    assert_eq!(output["coinbase"], json!(false));
    assert_eq!(
        output["bestblock"],
        json!(ctx.chain.applied_hash().to_string())
    );
    assert_eq!(output["value"], json!(0.000_000_5));
    assert!(gettxout(&ctx, &json!([txid.to_string(), 0, false]))?.is_null());
    assert!(gettxout(&ctx, &json!([txid.to_string(), 1]))?.is_null());
    Ok(())
}
struct SpentRows {
    block: Block,
}

impl bitcoin_rs_storage::utxo::contract::BlockUndoSource for SpentRows {
    fn block_spends(
        &self,
        _hash: Hash256,
        _expected: Hash256,
    ) -> Result<
        bitcoin_rs_storage::utxo::contract::BlockSpends,
        bitcoin_rs_storage::utxo::contract::BlockSpendsError,
    > {
        use bitcoin_rs_consensus::primitives::{Amount, Script};
        let Some(spend) = self.block.txs.get(1) else {
            return Err(bitcoin_rs_storage::utxo::contract::BlockSpendsError::UnknownBlock);
        };
        let spent = spend
            .inputs
            .iter()
            .map(|input| bitcoin_rs_storage::utxo::UtxoCoin {
                outpoint: input.previous_output,
                txout: TxOut {
                    value: Amount::from_sat(5_000_000_000),
                    script_pubkey: Script::new(),
                },
                coinbase: false,
                height: 0,
            })
            .collect();
        Ok(bitcoin_rs_storage::utxo::contract::BlockSpends {
            block: self.block.clone(),
            spent: Ok(vec![vec![], spent]),
        })
    }
}

#[test]
fn getrawtransaction_clamps_out_of_range_verbosity_like_core()
-> Result<(), crate::test_error::TestError> {
    let block = block_with_two_txs(9);
    let spend = block
        .txs
        .get(1)
        .cloned()
        .ok_or_else(|| RpcError::Internal("fixture lost its spend".to_owned()))?;
    let mut ctx = Context::new();
    ctx.chain
        .block_tree
        .write()
        .insert_node(None, block.header, NodeStatus::Active)
        .expect("header");
    ctx.chain.block_undo_source = Some(Arc::new(SpentRows {
        block: block.clone(),
    }));
    attach_body_for_block(&mut ctx, &block, 0);
    let ctx = Arc::new(ctx);
    let hash = block.block_hash().to_string();
    let txid = spend.txid().to_string();
    let expected_hex = consensus_bytes(&spend).to_lower_hex_string();
    for verbosity in [json!(-1), json!(0), json!(false)] {
        let value = getrawtransaction(&ctx, &json!([txid.as_str(), verbosity, hash.as_str()]))?;
        assert_eq!(
            value.as_str(),
            Some(expected_hex.as_str()),
            "verbosity {verbosity} renders hex"
        );
    }
    let level_one = getrawtransaction(&ctx, &json!([txid.as_str(), true, hash.as_str()]))?;
    assert!(level_one["vin"][0].get("prevout").is_none());
    for verbosity in [json!(2), json!(3), json!(4), json!(99)] {
        let value = getrawtransaction(&ctx, &json!([txid.as_str(), verbosity, hash.as_str()]))?;
        assert!(
            value["vin"][0].get("prevout").is_some(),
            "verbosity {verbosity} renders level two: {value:?}"
        );
    }
    Ok(())
}
#[test]
fn sendrawtransaction_rejects_odd_length_and_invalid_and_oversize_hex() {
    let ctx = Arc::new(Context::new());
    let odd =
        super::sendrawtransaction(&ctx, &json!(["abc"])).expect_err("odd length hex must fail");
    assert_eq!(odd.code(), RpcError::CORE_DESERIALIZATION_ERROR);

    let invalid =
        super::sendrawtransaction(&ctx, &json!(["zz"])).expect_err("invalid hex must fail");
    assert_eq!(invalid.code(), RpcError::CORE_DESERIALIZATION_ERROR);

    let limit = usize::try_from(super::MAX_BROADCAST_HEX_CHARS / 2).unwrap_or(0);
    let oversize = "00".repeat(limit + 1);
    let too_large =
        super::sendrawtransaction(&ctx, &json!([oversize])).expect_err("oversize hex must fail");
    assert_eq!(too_large.code(), RpcError::CORE_DESERIALIZATION_ERROR);
}

#[test]
fn decoderawtransaction_rejects_odd_length_and_invalid_and_oversize_hex() {
    let ctx = Arc::new(Context::new());
    let latch = bitcoin_rs_execution::chain::LatchWriter::new().reader();
    let odd = super::decoderawtransaction(&ctx, &json!(["abc"]), &latch)
        .expect_err("odd length hex must fail");
    assert_eq!(odd.code(), RpcError::CORE_DESERIALIZATION_ERROR);

    let invalid = super::decoderawtransaction(&ctx, &json!(["zz"]), &latch)
        .expect_err("invalid hex must fail");
    assert_eq!(invalid.code(), RpcError::CORE_DESERIALIZATION_ERROR);

    let oversize = "00".repeat(1_000_001);
    let too_large = super::decoderawtransaction(&ctx, &json!([oversize]), &latch)
        .expect_err("oversize hex must fail");
    assert_eq!(too_large.code(), RpcError::CORE_DESERIALIZATION_ERROR);
}
// API-10
#[test]
fn sendrawtransaction_answers_core_oversize_for_hex_beyond_the_broadcast_bound() {
    let ctx = Context::new();
    fund_coin(
        &ctx,
        OutPoint::new(Txid(Hash256::from_le_bytes(&[0x5a; 32])), 0),
        29_424_000,
    );
    let ctx = Arc::new(ctx);
    let raw = consensus_bytes(&many_output_tx(29_424)).to_lower_hex_string();
    let error = ctx
        .chain
        .with_stable_chainstate(|| super::sendrawtransaction(&ctx, &json!([raw.clone()])))
        .expect_err("a transaction over the consensus bound must answer Core bad-txns-oversize");

    assert_eq!(
        error.code(),
        RpcError::CORE_VERIFY_REJECTED,
        "Core answers -26 for an oversize transaction: {error}"
    );
    assert_eq!(
        error.to_string(),
        "bad-txns-oversize",
        "Core CheckTransaction answers bad-txns-oversize before the standard weight check"
    );
}

// API-10
#[test]
fn sendrawtransaction_maps_the_gateway_weight_reject_to_core_tx_size() {
    let ctx = Context::new();
    fund_coin(
        &ctx,
        OutPoint::new(Txid(Hash256::from_le_bytes(&[0x5a; 32])), 0),
        2_954_000,
    );
    let ctx = Arc::new(ctx);
    let raw = consensus_bytes(&many_output_tx(2_954)).to_lower_hex_string();
    let error = ctx
        .chain
        .with_stable_chainstate(|| super::sendrawtransaction(&ctx, &json!([raw.clone()])))
        .expect_err("a transaction above the standard weight must answer Core tx-size");

    assert_eq!(
        error.code(),
        RpcError::CORE_VERIFY_REJECTED,
        "Core answers -26 for an oversize transaction: {error}"
    );
    assert_eq!(error.to_string(), "tx-size");
}

// API-10
#[test]
fn testmempoolaccept_reports_core_tx_size_on_the_oversize_row() {
    let ctx = Context::new();
    fund_coin(
        &ctx,
        OutPoint::new(Txid(Hash256::from_le_bytes(&[0x5a; 32])), 0),
        2_954_000,
    );
    let ctx = Arc::new(ctx);
    let raw = consensus_bytes(&many_output_tx(2_954)).to_lower_hex_string();
    let rows = ctx
        .chain
        .with_stable_chainstate(|| super::testmempoolaccept(&ctx, &json!([[raw.clone()]])))
        .unwrap_or_else(|err| panic!("one oversize row must not fail the request: {err}"));
    let rows = rows.as_array().unwrap_or_else(|| panic!("rows: {rows:?}"));
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row["allowed"].as_bool(), Some(false), "row: {row}");
    assert_eq!(row["reject-reason"].as_str(), Some("tx-size"), "row: {row}");
    assert_eq!(
        row["reject-details"].as_str(),
        Some("tx-size"),
        "row: {row}"
    );
}

// API-10
#[test]
fn testmempoolaccept_survives_one_oversize_row_with_package_too_large() {
    let ctx = Context::new();
    let outpoint = retry_fund_utxo(&ctx, 1, 10_000);
    let small = retry_tx(outpoint, 9_000);
    let oversize_raw = consensus_bytes(&many_output_tx(29_424)).to_lower_hex_string();
    let small_raw = consensus_bytes(&small).to_lower_hex_string();
    let ctx = Arc::new(ctx);
    let rows = ctx
        .chain
        .with_stable_chainstate(|| {
            super::testmempoolaccept(&ctx, &json!([[oversize_raw, small_raw]]))
        })
        .unwrap_or_else(|err| panic!("one oversize row must not fail the request: {err}"));
    let rows = rows.as_array().unwrap_or_else(|| panic!("rows: {rows:?}"));
    assert_eq!(rows.len(), 2);
    for row in rows {
        assert_eq!(
            row["package-error"].as_str(),
            Some("package-too-large"),
            "row: {row}"
        );
        assert!(
            row["allowed"].is_null(),
            "unfinished rows carry no allowed key: {row}"
        );
    }
}

// API-02
#[test]
fn decoderawtransaction_decodes_oversize_hex_like_core() {
    let ctx = Arc::new(Context::new());
    let latch = bitcoin_rs_execution::chain::LatchWriter::new().reader();
    let raw = consensus_bytes(&many_output_tx(117_700)).to_lower_hex_string();
    let value = super::decoderawtransaction(&ctx, &json!([raw]), &latch)
        .unwrap_or_else(|err| panic!("Core decodes any hex that fits the request: {err}"));
    assert_eq!(
        value["vout"].as_array().map(|items| items.len()),
        Some(117_700),
        "the decoded transaction renders every output"
    );
}

#[test]
fn testmempoolaccept_binds_named_parameters_and_rejects_excess() {
    let ctx = Arc::new(Context::new());
    let excess = super::testmempoolaccept(&ctx, &json!([[], 0, "extra"]))
        .expect_err("excess parameters must fail");
    assert!(matches!(excess, RpcError::InvalidParams(_)));

    let handler = crate::Handler::new(Arc::clone(&ctx));
    let named = handler.dispatch("testmempoolaccept", &json!({"rawtxs": []}));
    let positional = handler.dispatch("testmempoolaccept", &json!([[]]));
    assert_eq!(
        named.expect_err("named empty rawtxs").to_string(),
        positional.expect_err("positional empty rawtxs").to_string()
    );
}

#[test]
fn getrawtransaction_checks_mempool_before_failing_txindex()
-> Result<(), crate::test_error::TestError> {
    struct FailingQuery;

    impl DerivedIndexQuery for FailingQuery {
        fn transaction(&self, _txid: &Txid) -> Result<Option<Tx>, TxQueryError> {
            Err(TxQueryError::Storage("disk full".into()))
        }

        fn outpoint_value(&self, _outpoint: &OutPoint) -> Result<Option<u64>, TxQueryError> {
            Ok(None)
        }

        fn index_info(&self) -> Result<crate::context::DerivedIndexInfo, TxQueryError> {
            Ok(crate::context::DerivedIndexInfo {
                synced: false,
                best_block_height: 0,
            })
        }
    }

    let mut ctx = Context::new();
    ctx.indexes.derived_index = Some(Arc::new(FailingQuery));
    let ctx = Arc::new(ctx);
    let genesis = fixture_genesis();
    let mut coinbase = genesis
        .txs
        .first()
        .ok_or_else(|| RpcError::Internal("genesis has no transactions".to_owned()))?
        .clone();
    coinbase.version = u32::MAX;
    let txid = coinbase.txid();
    {
        let mut pool = ctx.mempool.gateway.pool().write();
        let vsize = u32::try_from(coinbase.vsize())?;
        let entry = MempoolEntry::new(Arc::new(coinbase.clone()), vsize, u64::from(vsize), 0, 0, 0);
        pool.insert_entry(entry)?;
    }

    let result = getrawtransaction(&ctx, &json!([txid.to_string()]))?;

    let expected = consensus_bytes(&coinbase).to_lower_hex_string();
    assert_eq!(result.as_str(), Some(expected.as_str()));
    for verbosity in [json!(true), json!(1), json!(2)] {
        let verbose = getrawtransaction(&ctx, &json!([txid.to_string(), verbosity]))?;
        assert_eq!(verbose["version"].as_u64(), Some(4_294_967_295));
        assert_eq!(verbose["hex"].as_str(), Some(expected.as_str()));
        for field in [
            "blockhash",
            "confirmations",
            "time",
            "blocktime",
            "in_active_chain",
            "fee",
        ] {
            assert!(verbose.get(field).is_none(), "mempool omits {field}");
        }
    }
    Ok(())
}

#[test]
fn getrawtransaction_explicit_coinbase_preserves_undo_failures_and_render_budget() {
    use bitcoin_rs_storage::utxo::contract::{BlockSpends, BlockSpendsError, BlockUndoSource};

    struct FailingSource(fn() -> BlockSpendsError);
    impl BlockUndoSource for FailingSource {
        fn block_spends(&self, _: Hash256, _: Hash256) -> Result<BlockSpends, BlockSpendsError> {
            Err((self.0)())
        }
    }
    let mut block = fixture_genesis();
    let mut spend = block.txs[0].clone();
    spend.inputs[0].previous_output = OutPoint::new(block.txs[0].txid(), 0);
    block.txs.push(spend);
    block.header.merkle_root =
        bitcoin_rs_execution::chain::regtest_fixture::merkle_root(&block.txs).expect("merkle root");
    let context = |failure| {
        let mut ctx = Context::new();
        ctx.chain
            .block_tree
            .write()
            .insert_node(None, block.header, NodeStatus::Active)
            .expect("header");
        ctx.chain.block_undo_source = Some(Arc::new(FailingSource(failure)));
        Arc::new(ctx)
    };
    let args = json!([
        block.txs[0].txid().to_string(),
        2,
        block.block_hash().to_string()
    ]);
    let retry: fn() -> BlockSpendsError = || BlockSpendsError::Retry;
    for (failure, code) in [
        (retry, -1),
        (|| BlockSpendsError::Closed, -1),
        (|| BlockSpendsError::ResourceLimit, -1),
        (|| BlockSpendsError::Corrupt("fixture"), -32603),
        (
            || {
                BlockSpendsError::Undo(bitcoin_rs_storage::utxo::contract::UndoReadError::Missing {
                    block: Hash256::default(),
                    height: 1,
                })
            },
            -32603,
        ),
    ] {
        let mut ctx = context(failure);
        assert_eq!(
            getrawtransaction(&ctx, &args)
                .expect_err("read failure")
                .code(),
            code
        );
        attach_body_for_block(Arc::get_mut(&mut ctx).expect("unique context"), &block, 0);
        for verbosity in [json!(1), json!(true)] {
            let value = getrawtransaction(
                &ctx,
                &json!([
                    block.txs[0].txid().to_string(),
                    verbosity,
                    block.block_hash().to_string()
                ]),
            )
            .expect("coinbase body is readable without undo");
            assert!(value.get("fee").is_none());
            assert!(value["vin"][0].get("prevout").is_none());
        }
        assert_eq!(
            getrawtransaction(&ctx, &args)
                .expect_err("v2 still requires undo")
                .code(),
            code
        );
    }
    let ctx = context(|| BlockSpendsError::Corrupt("fixture"));
    let first = ctx.try_acquire_block_render().expect("first permit");
    let second = ctx.try_acquire_block_render().expect("second permit");
    let error = getrawtransaction(&ctx, &args).expect_err("budget refusal");
    assert!(
        error
            .to_string()
            .contains("too many concurrent full-block reads")
    );
    drop((first, second));
    assert_eq!(
        getrawtransaction(&ctx, &args)
            .expect_err("undo failure")
            .code(),
        -32603
    );
}

#[test]
fn getrawtransaction_detailed_read_omits_unavailable_undo_and_rejects_partial_rows() {
    use bitcoin_rs_consensus::primitives::Amount;
    use bitcoin_rs_storage::utxo::contract::{
        BlockSpends, BlockSpendsError, BlockUndoSource, HistoryUnavailable,
    };

    struct Source {
        block: Block,
        mode: u8,
        expected: Hash256,
    }
    impl BlockUndoSource for Source {
        fn block_spends(
            &self,
            hash: Hash256,
            expected: Hash256,
        ) -> Result<BlockSpends, BlockSpendsError> {
            assert_eq!(hash, Hash256::from(self.block.block_hash()));
            assert_eq!(expected, self.expected);
            let spent = match self.mode {
                0 => Err(HistoryUnavailable::Missing),
                1 => Err(HistoryUnavailable::Pruned { below: 1 }),
                2 => Ok(vec![vec![]]),
                _ => Ok(vec![vec![], vec![]]),
            };
            Ok(BlockSpends {
                block: self.block.clone(),
                spent,
            })
        }
    }
    let mut block = fixture_genesis();
    let mut spend = block.txs[0].clone();
    spend.inputs[0].previous_output = OutPoint::new(block.txs[0].txid(), 0);
    spend.outputs[0].value = Amount::from_sat(49);
    block.txs.push(spend.clone());
    block.header.merkle_root =
        bitcoin_rs_execution::chain::regtest_fixture::merkle_root(&block.txs).expect("merkle root");
    for mode in 0..4 {
        let mut ctx = Context::new();
        ctx.chain
            .block_tree
            .write()
            .insert_node(None, block.header, NodeStatus::Active)
            .expect("header");
        ctx.chain.block_undo_source = Some(Arc::new(Source {
            block: block.clone(),
            mode,
            expected: ctx.chain.applied_hash(),
        }));
        let result = getrawtransaction(
            &Arc::new(ctx),
            &json!([spend.txid().to_string(), 2, block.block_hash().to_string()]),
        );
        if mode < 2 {
            let value = result.expect("uncertified undo is omitted");
            assert!(value.get("fee").is_none());
            assert!(value["vin"][0].get("prevout").is_none());
            assert_eq!(value["in_active_chain"].as_bool(), Some(false));
        } else {
            assert_eq!(result.expect_err("partial undo").code(), -32603);
        }
    }
}

#[test]
fn getrawtransaction_uses_applied_ancestry_for_explicit_block_metadata() {
    let genesis = distinct_block(1);
    let mut sibling = distinct_block(2);
    sibling.header.prev_blockhash = genesis.block_hash();
    let mut active = distinct_block(3);
    active.header.prev_blockhash = genesis.block_hash();
    let mut higher = distinct_block(4);
    higher.header.prev_blockhash = sibling.block_hash();
    let mut ctx = Context::new();
    let blocks = [(&genesis, 0), (&sibling, 1), (&active, 1), (&higher, 2)];
    ctx.chain.block_body_source = Some(Arc::new(BlockBodies {
        bodies: blocks
            .iter()
            .map(|(block, height)| (*height, block.block_hash(), consensus_bytes(*block)))
            .collect(),
    }));
    for (block, height) in blocks {
        ctx.chain.add_block(BlockRecord::from_block(height, block));
    }
    let active_tip = {
        let mut tree = ctx.chain.block_tree.write();
        let genesis_id = tree
            .insert_node(None, genesis.header, NodeStatus::Active)
            .expect("genesis");
        let sibling_id = tree
            .insert_node(Some(genesis_id), sibling.header, NodeStatus::Active)
            .expect("sibling");
        let active_id = tree
            .insert_node(Some(genesis_id), active.header, NodeStatus::Active)
            .expect("active sibling");
        tree.insert_node(Some(sibling_id), higher.header, NodeStatus::HeaderValid)
            .expect("higher header fork");
        let node = tree.node(active_id).expect("active node");
        bitcoin_rs_execution::chain::TipSnapshot {
            tip_id: active_id,
            chain_tx_count: node.chain_tx_count,
            hash: node.hash,
            height: node.height,
            chainwork: node.chainwork,
        }
    };
    ctx.chain.applied_tip.store(Some(Arc::new(active_tip)));
    let ctx = Arc::new(ctx);
    for (block, depth) in [(&genesis, 2), (&active, 1), (&sibling, 0), (&higher, 0)] {
        let tx = &block.txs[0];
        let args = json!([tx.txid().to_string(), true, block.block_hash().to_string()]);
        let value = getrawtransaction(&ctx, &args).expect("verbose lookup");
        assert_eq!(
            value.get("in_active_chain").and_then(Value::as_bool),
            Some(depth > 0)
        );
        assert_eq!(
            value.get("confirmations").and_then(Value::as_u64),
            Some(depth)
        );
        assert_eq!(
            value.get("blockhash").and_then(Value::as_str),
            Some(block.block_hash().to_string().as_str())
        );
        for field in ["time", "blocktime"] {
            assert_eq!(
                value.get(field).and_then(Value::as_u64),
                (depth > 0).then_some(u64::from(block.header.time))
            );
            if depth == 0 {
                assert!(
                    value.get(field).is_none(),
                    "inactive {field} must be absent"
                );
            }
        }
        let raw = getrawtransaction(
            &ctx,
            &json!([tx.txid().to_string(), false, block.block_hash().to_string()]),
        )
        .expect("raw lookup");
        assert_eq!(
            raw.as_str(),
            Some(consensus_bytes(tx).to_lower_hex_string().as_str())
        );
    }
    let missing = getrawtransaction(
        &ctx,
        &json!([
            sibling.txs[0].txid().to_string(),
            true,
            active.block_hash().to_string()
        ]),
    );
    assert!(matches!(
        missing,
        Err(RpcError::NotFound("transaction not in specified block"))
    ));
}

#[test]
fn getrawtransaction_resolves_confirmed_transaction_from_txindex_without_cache() {
    struct StaticQuery {
        tx: Tx,
    }

    impl DerivedIndexQuery for StaticQuery {
        fn transaction(&self, txid: &Txid) -> Result<Option<Tx>, TxQueryError> {
            Ok((self.tx.txid() == *txid).then(|| self.tx.clone()))
        }

        fn outpoint_value(&self, _outpoint: &OutPoint) -> Result<Option<u64>, TxQueryError> {
            Ok(None)
        }

        fn transaction_height(&self, txid: &Txid) -> Result<Option<u32>, TxQueryError> {
            Ok((self.tx.txid() == *txid).then_some(0))
        }

        fn index_info(&self) -> Result<crate::context::DerivedIndexInfo, TxQueryError> {
            Ok(crate::context::DerivedIndexInfo {
                synced: true,
                best_block_height: 1,
            })
        }
    }

    let mut genesis = fixture_genesis();
    genesis.txs[0].version = 1_u32 << 31;
    genesis.header.merkle_root = genesis.txs[0].txid().0;
    let Some(coinbase) = genesis.txs.first().cloned() else {
        panic!("genesis has no transactions");
    };
    let txid = coinbase.txid();
    let mut ctx = Context::new();
    ctx.indexes.derived_index = Some(Arc::new(StaticQuery {
        tx: coinbase.clone(),
    }));
    ctx.chain.add_block(BlockRecord::from_block(0, &genesis));
    let tip = {
        let mut tree = ctx.chain.block_tree.write();
        tree.insert_node(None, genesis.header, NodeStatus::Active)
            .expect("genesis");
        tree.tip().expect("genesis tip")
    };
    ctx.chain.applied_tip.store(Some(Arc::new((*tip).clone())));
    let ctx = Arc::new(ctx);

    let result = getrawtransaction(&ctx, &json!([txid.to_string()]))
        .unwrap_or_else(|err| panic!("txindex lookup failed: {err}"));

    let expected = consensus_bytes(&coinbase).to_lower_hex_string();
    assert_eq!(result.as_str(), Some(expected.as_str()));
    let verbose =
        getrawtransaction(&ctx, &json!([txid.to_string(), true])).expect("verbose txindex lookup");
    assert!(verbose.get("in_active_chain").is_none());
    assert_eq!(verbose["version"].as_u64(), Some(2_147_483_648));
    for field in ["time", "blocktime"] {
        assert_eq!(
            verbose[field].as_u64(),
            Some(u64::from(genesis.header.time))
        );
    }
    assert_eq!(
        verbose.get("confirmations").and_then(Value::as_u64),
        Some(1)
    );
}

#[test]
fn getrawtransaction_with_blockhash_reports_pruned_block_body() {
    let ctx = Arc::new(Context::new());
    let genesis = fixture_genesis();
    let Some(coinbase) = genesis.txs.first() else {
        panic!("genesis has no transactions");
    };
    let txid = coinbase.txid();
    let record = BlockRecord::from_block(0, &genesis);
    let block_hash = record.hash;
    ctx.chain
        .block_tree
        .write()
        .insert_node(None, genesis.header, NodeStatus::Active)
        .expect("insert genesis header");
    ctx.chain.add_block(record);

    let result = getrawtransaction(
        &ctx,
        &json!([txid.to_string(), false, block_hash.to_string()]),
    );

    assert!(matches!(
        result,
        Err(RpcError::NotFound("block data pruned"))
    ));
}

#[test]
fn getrawtransaction_with_blockhash_reports_pruned_body_for_a_header_only_block() {
    let ctx = Arc::new(Context::new());
    let genesis = fixture_genesis();
    let Some(coinbase) = genesis.txs.first() else {
        panic!("genesis has no transactions");
    };
    let block_hash = genesis.block_hash();
    ctx.chain
        .block_tree
        .write()
        .insert_node(None, genesis.header, NodeStatus::HeaderValid)
        .expect("insert header-only block");

    let result = getrawtransaction(
        &ctx,
        &json!([coinbase.txid().to_string(), false, block_hash.to_string()]),
    );

    assert!(matches!(
        result,
        Err(RpcError::NotFound("block data pruned"))
    ));
}

#[test]
fn getrawtransaction_with_unknown_blockhash_errors() {
    let ctx = Arc::new(Context::new());
    let handler = Handler::new(Arc::clone(&ctx));
    let bogus_hash =
        bitcoin_rs_consensus::primitives::Hash256::from_le_bytes(&[7_u8; 32]).to_string_be();
    let result = handler.dispatch(
        "getrawtransaction",
        &json!([
            "0000000000000000000000000000000000000000000000000000000000000000",
            false,
            bogus_hash
        ]),
    );
    assert!(result.is_err());
}

#[test]
fn gettxoutproof_finds_genesis_coinbase_through_the_index() {
    let genesis = fixture_genesis();
    let Some(coinbase) = genesis.txs.first() else {
        panic!("genesis has no transactions");
    };
    let txid = coinbase.txid();
    let mut ctx = Context::new();
    ctx.indexes.derived_index = Some(Arc::new(HeightQuery(|_: &Txid| Ok(Some(0)))));
    install_chain_blocks(&mut ctx, std::slice::from_ref(&genesis));
    let ctx = Arc::new(ctx);
    let handler = Handler::new(Arc::clone(&ctx));
    let result = handler
        .dispatch("gettxoutproof", &json!([[txid.to_string()]]))
        .unwrap_or_else(|err| panic!("gettxoutproof failed: {err}"));
    let Some(proof_hex) = result.as_str() else {
        panic!("expected string, got {result:?}");
    };

    let extracted = handler
        .dispatch("verifytxoutproof", &json!([proof_hex]))
        .unwrap_or_else(|err| panic!("verifytxoutproof failed: {err}"));
    let Some(arr) = extracted.as_array() else {
        panic!("expected array, got {extracted:?}");
    };
    assert_eq!(arr.len(), 1);
}

// API-02
#[test]
fn gettxoutproof_with_blockhash_answers_core_message_for_a_bodyless_block() {
    let ctx = Arc::new(Context::new());
    let genesis = fixture_genesis();
    let Some(coinbase) = genesis.txs.first() else {
        panic!("genesis has no transactions");
    };
    let txid = coinbase.txid();
    let record = BlockRecord::from_block(0, &genesis);
    ctx.chain
        .block_tree
        .write()
        .insert_node(None, genesis.header, NodeStatus::Active)
        .expect("insert genesis header");
    let block_hash = record.hash;
    ctx.chain.add_block(record);
    let handler = Handler::new(Arc::clone(&ctx));

    let result = handler.dispatch(
        "gettxoutproof",
        &json!([[txid.to_string()], block_hash.to_string()]),
    );

    assert!(
        matches!(
            result,
            Err(RpcError::Misc(reason))
                if reason == "Block not available (not fully downloaded)"
        ),
        "Core v31.1 answers RPC_MISC_ERROR not fully downloaded for a bodyless block"
    );
}

// API-02
#[test]
fn gettxoutproof_with_blockhash_answers_core_message_for_a_header_only_block() {
    let ctx = Arc::new(Context::new());
    let genesis = fixture_genesis();
    let Some(coinbase) = genesis.txs.first() else {
        panic!("genesis has no transactions");
    };
    let block_hash = genesis.block_hash();
    ctx.chain
        .block_tree
        .write()
        .insert_node(None, genesis.header, NodeStatus::HeaderValid)
        .expect("insert header-only block");
    let handler = Handler::new(Arc::clone(&ctx));

    let result = handler.dispatch(
        "gettxoutproof",
        &json!([[coinbase.txid().to_string()], block_hash.to_string()]),
    );

    assert!(
        matches!(
            result,
            Err(RpcError::Misc(reason))
                if reason == "Block not available (not fully downloaded)"
        ),
        "Core v31.1 answers RPC_MISC_ERROR not fully downloaded for a header-only block"
    );
}

// API-02
#[test]
fn gettxoutproof_without_blockhash_answers_from_the_utxo_set() {
    let mut genesis = fixture_genesis();
    let tx = many_output_tx(8);
    let txid = tx.txid();
    let live_vout = 7;
    let live_output = tx.outputs[live_vout].clone();
    genesis.txs.push(tx);
    genesis.header.merkle_root =
        bitcoin_rs_execution::chain::regtest_fixture::merkle_root(&genesis.txs)
            .expect("fixture merkle root");
    let mut ctx = Context::new();
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(
        OutPoint::new(
            txid,
            u32::try_from(live_vout).expect("fixture output index"),
        ),
        live_output,
        false,
        0,
    ));
    ctx.populate_fixture_coins(&changes)
        .unwrap_or_else(|err| panic!("commit_block failed: {err}"));
    assert!(
        ctx.chain
            .utxo
            .get_entry(&OutPoint::new(txid, 0))
            .expect("read absent output")
            .is_none()
    );
    install_chain_blocks(&mut ctx, std::slice::from_ref(&genesis));
    let ctx = Arc::new(ctx);
    let handler = Handler::new(Arc::clone(&ctx));

    let value = handler
        .dispatch("gettxoutproof", &json!([[txid.to_string()]]))
        .unwrap_or_else(|err| panic!("gettxoutproof failed: {err}"));
    let Some(proof_hex) = value.as_str() else {
        panic!("expected proof hex, got {value:?}");
    };
    let extracted = handler
        .dispatch("verifytxoutproof", &json!([proof_hex]))
        .unwrap_or_else(|err| panic!("verifytxoutproof failed: {err}"));
    let Some(arr) = extracted.as_array() else {
        panic!("expected array, got {extracted:?}");
    };
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0].as_str(), Some(txid.to_string()).as_deref());
}

#[test]
fn gettxoutproof_reports_unreadable_coin_instead_of_transaction_absence()
-> Result<(), crate::test_error::TestError> {
    let txid = many_output_tx(8).txid();
    let mut ctx = Context::new();
    ctx.chain.utxo = crate::test_coins::utxo_reader_with_undecodable_coin(&Hash256::from(txid))?;
    let result = proof_for(&Arc::new(ctx), &[txid]);
    assert!(matches!(result, Err(RpcError::Internal(_))));
    Ok(())
}

// API-02
#[test]
fn gettxoutproof_without_blockhash_answers_core_message_when_the_transaction_is_unknown() {
    let genesis = fixture_genesis();
    let Some(coinbase) = genesis.txs.first() else {
        panic!("genesis has no transactions");
    };
    let txid = coinbase.txid();
    let mut ctx = Context::new();
    let source = Arc::new(CountingBodySource::default());
    let body_source: Arc<dyn bitcoin_rs_storage::block_body::BlockBodySource> =
        Arc::<CountingBodySource>::clone(&source);
    ctx.chain.block_body_source = Some(body_source);
    ctx.chain.add_block(BlockRecord::from_block(0, &genesis));
    ctx.chain.add_block(BlockRecord::from_block(1, &genesis));
    let ctx = Arc::new(ctx);
    let handler = Handler::new(Arc::clone(&ctx));

    let error = handler
        .dispatch("gettxoutproof", &json!([[txid.to_string()]]))
        .expect_err("a transaction with no coin and no index must answer Core's miss");

    assert_eq!(
        error.code(),
        RpcError::CORE_NOT_FOUND,
        "Core answers -5 for a transaction it cannot place: {error}"
    );
    assert_eq!(
        error.to_string(),
        "Transaction not yet in block",
        "Core's miss text for a transaction outside the UTXO set and index"
    );
    assert_eq!(
        source.calls.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "the miss must not read any block body"
    );
}

fn many_output_tx(output_count: usize) -> Tx {
    use bitcoin_rs_consensus::primitives::{Amount, LockTime, Script, Sequence, Witness};
    let mut script = vec![0x76, 0xa9, 0x14];
    script.extend_from_slice(&[0x11_u8; 20]);
    script.push(0x88);
    script.push(0xac);
    let script = Script::from_bytes(script);
    let outputs = (0..output_count)
        .map(|_index| TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: script.clone(),
        })
        .collect::<Vec<_>>();
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[0x5a; 32])), 0),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs,
    }
}

fn fund_coin(ctx: &Context, outpoint: OutPoint, value_sat: u64) {
    use bitcoin_rs_consensus::primitives::{Amount, Script};
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(
        outpoint,
        TxOut {
            value: Amount::from_sat(value_sat),
            script_pubkey: Script::from_bytes(vec![0x51]),
        },
        false,
        0,
    ));
    ctx.populate_fixture_coins(&changes)
        .unwrap_or_else(|err| panic!("commit_block failed: {err}"));
}

fn distinct_block(marker: u8) -> Block {
    use bitcoin_rs_consensus::primitives::Script;
    let mut block = fixture_genesis();
    if let Some(input) = block.txs.first_mut().and_then(|tx| tx.inputs.first_mut()) {
        input.script_sig = Script::from_bytes(vec![marker; 4]);
    }
    block.header.merkle_root =
        bitcoin_rs_execution::chain::regtest_fixture::merkle_root(&block.txs).unwrap_or_default();
    block
}

fn block_with_two_txs(marker: u8) -> Block {
    use bitcoin_rs_consensus::primitives::{Amount, LockTime, Script, Sequence, Witness};
    let mut block = distinct_block(marker);
    let extra = Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[marker; 32])), 0),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1_000 + u64::from(marker)),
            script_pubkey: Script::from_bytes(vec![0x51]),
        }],
    };
    block.txs.push(extra);
    block.header.merkle_root =
        bitcoin_rs_execution::chain::regtest_fixture::merkle_root(&block.txs).unwrap_or_default();
    block
}

struct HeightQuery<F>(F);

impl<F> DerivedIndexQuery for HeightQuery<F>
where
    F: Fn(&Txid) -> Result<Option<u32>, TxQueryError> + Send + Sync,
{
    fn transaction(&self, _txid: &Txid) -> Result<Option<Tx>, TxQueryError> {
        Ok(None)
    }

    fn outpoint_value(&self, _outpoint: &OutPoint) -> Result<Option<u64>, TxQueryError> {
        Ok(None)
    }

    fn index_info(&self) -> Result<crate::context::DerivedIndexInfo, TxQueryError> {
        Ok(crate::context::DerivedIndexInfo {
            synced: true,
            best_block_height: 0,
        })
    }

    fn transaction_height(&self, txid: &Txid) -> Result<Option<u32>, TxQueryError> {
        (self.0)(txid)
    }
}

fn resolving(resolvable: Vec<(Txid, u32)>) -> impl Fn(&Txid) -> Result<Option<u32>, TxQueryError> {
    move |txid| {
        Ok(resolvable
            .iter()
            .find(|(known, _)| known == txid)
            .map(|(_, height)| *height))
    }
}

struct PanicUnlessBodySource {
    height: u32,
    hash: BlockHash,
    body: Vec<u8>,
}

impl bitcoin_rs_storage::block_body::BlockBodySource for PanicUnlessBodySource {
    fn block_body(
        &self,
        height: u32,
        hash: BlockHash,
    ) -> Result<Option<Vec<u8>>, bitcoin_rs_storage::block_body::BlockBodyReadError> {
        if height == self.height && hash == self.hash {
            Ok(Some(self.body.clone()))
        } else {
            panic!("should not load unrelated body {height}:{hash}");
        }
    }
}

use crate::context::BlockBodies;

#[derive(Default)]
struct CountingBodySource {
    calls: core::sync::atomic::AtomicUsize,
}

impl bitcoin_rs_storage::block_body::BlockBodySource for CountingBodySource {
    fn block_body(
        &self,
        _height: u32,
        _hash: BlockHash,
    ) -> Result<Option<Vec<u8>>, bitcoin_rs_storage::block_body::BlockBodyReadError> {
        self.calls
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        Ok(None)
    }
}

fn install_blocks(ctx: &mut Context, blocks: &[Block]) {
    let mut records = Vec::with_capacity(blocks.len());
    let mut bodies = Vec::with_capacity(blocks.len());
    for (height, block) in blocks.iter().enumerate() {
        let record = BlockRecord::from_block(
            u32::try_from(height).unwrap_or_else(|err| panic!("height: {err}")),
            block,
        );
        bodies.push((record.height, record.hash, consensus_bytes(block)));
        records.push(record);
    }
    ctx.chain.block_body_source = Some(Arc::new(BlockBodies { bodies }));
    for record in records {
        ctx.chain.add_block(record);
    }
}

fn install_chain_blocks(ctx: &mut Context, blocks: &[Block]) {
    install_blocks(ctx, blocks);
    let tip = {
        let mut tree = ctx.chain.block_tree.write();
        let mut parent: Option<NodeId> = None;
        for block in blocks {
            parent = Some(
                tree.insert_node(parent, block.header, NodeStatus::Active)
                    .unwrap_or_else(|err| panic!("insert chain header: {err}")),
            );
        }
        let tip_id = parent.expect("chain blocks produce a tip");
        let node = tree.node(tip_id).expect("tip node");
        Arc::new(TipSnapshot {
            tip_id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
            chain_tx_count: node.chain_tx_count,
        })
    };
    ctx.chain.applied_tip.store(Some(tip));
}

fn attach_body_for_block(ctx: &mut Context, block: &Block, height: u32) {
    let record = BlockRecord::from_block(height, block);
    ctx.chain.block_body_source = Some(Arc::new(BlockBodies {
        bodies: vec![(record.height, record.hash, consensus_bytes(block))],
    }));
}

fn proof_for(ctx: &Arc<Context>, txids: &[Txid]) -> Result<sonic_rs::Value, RpcError> {
    let names = txids.iter().map(ToString::to_string).collect::<Vec<_>>();
    super::gettxoutproof(ctx, &json!([names]), &LatchReader::fixture_never())
}

#[test]

fn gettxoutproof_index_path_does_not_read_unrelated_block_bodies() {
    let block = distinct_block(3);
    let Some(wanted) = block.txs.first().map(Tx::txid) else {
        panic!("block has no transactions");
    };
    let indexed = BlockRecord::from_block(2, &block);
    let mut ctx = Context::new();
    ctx.indexes.derived_index = Some(Arc::new(HeightQuery(|_: &Txid| Ok(Some(2)))));
    ctx.chain.block_body_source = Some(Arc::new(PanicUnlessBodySource {
        height: indexed.height,
        hash: indexed.hash,
        body: consensus_bytes(&block),
    }));
    ctx.chain.add_block(BlockRecord::synthetic(
        0,
        BlockHash::from(Hash256::from_le_bytes(&[7_u8; 32])),
    ));
    ctx.chain.add_block(BlockRecord::synthetic(
        1,
        BlockHash::from(Hash256::from_le_bytes(&[8_u8; 32])),
    ));
    ctx.chain.add_block(indexed);
    let ctx = Arc::new(ctx);

    let result = proof_for(&ctx, &[wanted]);

    assert!(
        result.as_ref().is_ok_and(|value| value.as_str().is_some()),
        "index path should answer from the indexed block alone: {result:?}"
    );
}

// API-02
#[test]
fn gettxoutproof_keeps_its_error_when_no_block_holds_every_txid() {
    let blocks = [distinct_block(1), distinct_block(2)];
    let wanted = blocks
        .iter()
        .filter_map(|block| block.txs.first().map(Tx::txid))
        .collect::<Vec<_>>();

    let mut index_ctx = Context::new();
    index_ctx.indexes.derived_index = Some(Arc::new(HeightQuery(|_: &Txid| Ok(Some(0)))));
    install_blocks(&mut index_ctx, &blocks);
    let index_ctx = Arc::new(index_ctx);

    let result = proof_for(&index_ctx, &wanted);

    assert!(
        matches!(
            &result,
            Err(RpcError::InvalidAddressOrKey(reason))
                if reason == "Not all transactions found in specified or retrieved block"
        ),
        "a resolved block missing txids must answer Core's not-all error: {result:?}"
    );
}

#[test]
fn gettxoutproof_index_path_answers_for_several_txids_in_one_block() {
    let genesis = fixture_genesis();
    let mut block = block_with_two_txs(11);
    block.header.prev_blockhash = genesis.block_hash();
    let wanted = block.txs.iter().map(Tx::txid).collect::<Vec<_>>();
    let resolvable = wanted.iter().map(|txid| (*txid, 1)).collect::<Vec<_>>();

    let mut ctx = Context::new();
    ctx.indexes.derived_index = Some(Arc::new(HeightQuery(resolving(resolvable))));
    install_chain_blocks(&mut ctx, &[genesis, block]);
    let ctx = Arc::new(ctx);

    let proof = proof_for(&ctx, &wanted).expect("proof generation must succeed");
    let proof_hex = proof.as_str().expect("proof hex string");
    let verified = super::verifytxoutproof(&ctx, &json!([proof_hex]))
        .unwrap_or_else(|err| panic!("verifytxoutproof failed: {err}"));
    let mut verified_txids: Vec<_> = verified
        .as_array()
        .expect("array of txids")
        .iter()
        .map(|v| v.as_str().expect("txid string").to_owned())
        .collect();
    let mut expected_txids: Vec<_> = wanted.iter().map(ToString::to_string).collect();
    verified_txids.sort();
    expected_txids.sort();
    assert_eq!(verified_txids, expected_txids);
}

// API-02
#[test]
fn gettxoutproof_asks_the_index_about_the_first_txid_only() {
    let block = block_with_two_txs(12);
    let mut wanted: Vec<Txid> = block.txs.iter().map(Tx::txid).collect();
    wanted.sort_unstable();
    let Some(first) = wanted.first().copied() else {
        panic!("block has no transactions");
    };

    let mut ctx = Context::new();
    ctx.indexes.derived_index = Some(Arc::new(HeightQuery(move |txid: &Txid| {
        if *txid == first {
            Ok(Some(1))
        } else {
            panic!("the index must not be asked about later txids: {txid}")
        }
    })));
    let indexed = BlockRecord::from_block(1, &block);
    ctx.chain.block_body_source = Some(Arc::new(PanicUnlessBodySource {
        height: indexed.height,
        hash: indexed.hash,
        body: consensus_bytes(&block),
    }));
    ctx.chain.add_block(BlockRecord::synthetic(
        0,
        BlockHash::from(Hash256::from_le_bytes(&[6_u8; 32])),
    ));
    ctx.chain.add_block(indexed);
    let ctx = Arc::new(ctx);

    let result = proof_for(&ctx, &wanted);

    assert!(
        result.as_ref().is_ok_and(|value| value.as_str().is_some()),
        "one index answer for the first txid must resolve the whole proof: {result:?}"
    );
}

#[test]
fn gettxoutproof_maps_a_transient_index_error_instead_of_reporting_absence() {
    let block = distinct_block(5);
    let Some(wanted) = block.txs.first().map(Tx::txid) else {
        panic!("block has no transactions");
    };
    let mut ctx = Context::new();
    ctx.indexes.derived_index = Some(Arc::new(HeightQuery(
        |_: &Txid| -> Result<Option<u32>, TxQueryError> { Err(TxQueryError::Retry) },
    )));
    install_blocks(&mut ctx, std::slice::from_ref(&block));
    let ctx = Arc::new(ctx);

    let error =
        proof_for(&ctx, &[wanted]).expect_err("a transient index failure is not an absence answer");

    assert_eq!(
        error.code(),
        -32603,
        "a transient index failure must not read as 'no block contains the txid': {error}"
    );
    assert_eq!(
        error.to_string(),
        "internal error: transaction index is still catching up; retry later"
    );
}

// API-02
#[test]
fn gettxoutproof_index_path_reports_the_missing_body() {
    let block = distinct_block(6);
    let Some(wanted) = block.txs.first().map(Tx::txid) else {
        panic!("block has no transactions");
    };
    let mut ctx = Context::new();
    ctx.indexes.derived_index = Some(Arc::new(HeightQuery(|_: &Txid| Ok(Some(1)))));
    ctx.chain.add_block(BlockRecord::synthetic(
        0,
        BlockHash::from(Hash256::from_le_bytes(&[9_u8; 32])),
    ));
    ctx.chain.add_block(BlockRecord::from_block(1, &block));
    let ctx = Arc::new(ctx);

    let error = proof_for(&ctx, &[wanted]).expect_err("a missing indexed body is not absence");

    assert!(
        matches!(
            error,
            RpcError::Misc(reason)
                if reason == "Block not available (not fully downloaded)"
        ),
        "the indexed height holds no body, so the answer is Core's not-downloaded error"
    );
}

// API-02
#[test]
fn gettxoutproof_answers_core_pruned_message_when_the_node_has_pruned() {
    let block = distinct_block(6);
    let Some(wanted) = block.txs.first().map(Tx::txid) else {
        panic!("block has no transactions");
    };
    let mut ctx = Context::new();
    ctx.indexes.derived_index = Some(Arc::new(HeightQuery(|_: &Txid| Ok(Some(1)))));
    ctx.chain.add_block(BlockRecord::synthetic(
        0,
        BlockHash::from(Hash256::from_le_bytes(&[9_u8; 32])),
    ));
    ctx.chain.add_block(BlockRecord::from_block(1, &block));
    ctx.chain.prune_service = Some(Arc::new(PrunedStub));
    let ctx = Arc::new(ctx);

    let error = proof_for(&ctx, &[wanted]).expect_err("a missing body on a pruned node");

    assert!(
        matches!(
            error,
            RpcError::Misc(reason) if reason == "Block not available (pruned data)"
        ),
        "Core v31.1 answers RPC_MISC_ERROR pruned data once the node has pruned"
    );
}

struct PrunedStub;

impl crate::context::PruneService for PrunedStub {
    fn prune_to_height(
        &self,
        _requested_height: u32,
    ) -> Result<crate::context::PruneResult, crate::context::PruneServiceError> {
        Err(crate::context::PruneServiceError::Failed(
            "pruning is stubbed".to_owned(),
        ))
    }

    fn status(&self) -> crate::context::PruneStatus {
        crate::context::PruneStatus {
            pruned: true,
            pruneheight: Some(0),
        }
    }
}

// API-02
#[test]
fn gettxoutproof_answers_core_message_for_an_empty_txid_list() {
    let ctx = Arc::new(Context::new());
    let handler = Handler::new(Arc::clone(&ctx));

    let result = handler.dispatch("gettxoutproof", &json!([[]]));

    assert!(
        matches!(
            result,
            Err(RpcError::InvalidParameter(reason))
                if reason == "Parameter 'txids' cannot be empty"
        ),
        "Core v31.1 answers RPC_INVALID_PARAMETER for an empty txid list"
    );
}

// API-02
#[test]
fn gettxoutproof_answers_core_message_for_a_duplicated_txid() {
    let block = distinct_block(7);
    let Some(txid) = block.txs.first().map(Tx::txid) else {
        panic!("block has no transactions");
    };
    let raw = txid.to_string();
    let handler = Handler::new(Arc::new(Context::new()));

    let result = handler.dispatch("gettxoutproof", &json!([[raw.clone(), raw.clone()]]));

    assert!(
        matches!(
            result,
            Err(RpcError::InvalidParameter(reason))
                if reason == format!("Invalid parameter, duplicated txid: {raw}")
        ),
        "Core v31.1 rejects a duplicated txid naming the raw input"
    );
}

// API-02
#[test]
fn gettxoutproof_answers_a_type_error_for_a_non_string_blockhash() {
    let block = distinct_block(8);
    let Some(txid) = block.txs.first().map(Tx::txid) else {
        panic!("block has no transactions");
    };
    let handler = Handler::new(Arc::new(Context::new()));

    let result = handler.dispatch("gettxoutproof", &json!([[txid.to_string()], 123]));

    let message = match result {
        Err(RpcError::InvalidType(message)) => message,
        other => panic!("Core v31.1 answers a -3 type error for a numeric blockhash: {other:?}"),
    };
    assert_eq!(
        message,
        "Wrong type passed:\n{\n    \"Position 2 (blockhash)\": \"JSON value of type number is not of expected type string\"\n}",
        "Core v31.1 answers the RPCHelpMan wrong type shape for a numeric blockhash"
    );
}

// API-02
#[test]
fn gettxoutproof_answers_core_wrong_type_for_a_non_array_txid_list() {
    let handler = Handler::new(Arc::new(Context::new()));

    let result = handler.dispatch("gettxoutproof", &json!([42]));

    let message = match result {
        Err(RpcError::InvalidType(message)) => message,
        other => {
            panic!(
                "Core v31.1 answers the RPCHelpMan wrong type shape for a non array txids: {other:?}"
            )
        }
    };
    assert_eq!(
        message,
        "Wrong type passed:\n{\n    \"Position 1 (txids)\": \"JSON value of type number is not of expected type array\"\n}",
        "Core v31.1 names Position 1 for a non array txids argument"
    );
}

// API-02
#[test]
fn gettxoutproof_answers_core_type_error_for_a_non_string_txid_element() {
    let handler = Handler::new(Arc::new(Context::new()));

    let result = handler.dispatch("gettxoutproof", &json!([[42]]));

    let message = match result {
        Err(RpcError::InvalidType(message)) => message,
        other => {
            panic!("Core v31.1 answers the univalue type error shape for a numeric txid: {other:?}")
        }
    };
    assert_eq!(
        message, "JSON value of type number is not of expected type string",
        "Core v31.1 keeps the plain type error for an inner array element"
    );
}

// API-02
#[test]
fn gettxoutproof_answers_index_corrupt_when_the_index_names_an_absent_block() {
    let block = distinct_block(13);
    let Some(txid) = block.txs.first().map(Tx::txid) else {
        panic!("block has no transactions");
    };
    let mut ctx = Context::new();
    ctx.indexes.derived_index = Some(Arc::new(HeightQuery(|_: &Txid| Ok(Some(3)))));
    ctx.chain.add_block(BlockRecord::from_block(0, &block));
    let ctx = Arc::new(ctx);

    let result = proof_for(&ctx, &[txid]);

    let reason = match result {
        Err(RpcError::CoreInternal(reason)) => reason,
        other => panic!(
            "Core v31.1 answers -32603 when the index names a block the chain lacks: {other:?}"
        ),
    };
    assert_eq!(
        reason, "Transaction index corrupt",
        "Core v31.1 keeps the index corrupt text instead of the not yet in block answer"
    );
}

// API-02
#[test]
fn gettxoutproof_answers_block_not_found_for_an_unknown_blockhash() {
    let block = distinct_block(9);
    let Some(txid) = block.txs.first().map(Tx::txid) else {
        panic!("block has no transactions");
    };
    let unknown = Hash256::from_le_bytes(&[0xEE; 32]);
    let handler = Handler::new(Arc::new(Context::new()));

    let result = handler.dispatch(
        "gettxoutproof",
        &json!([[txid.to_string()], unknown.to_string()]),
    );

    assert!(
        matches!(
            result,
            Err(RpcError::InvalidAddressOrKey(reason)) if reason == "Block not found"
        ),
        "Core v31.1 answers Block not found for an unknown blockhash"
    );
}

struct CorruptBodySource {
    height: u32,
    hash: BlockHash,
}

impl bitcoin_rs_storage::block_body::BlockBodySource for CorruptBodySource {
    fn block_body(
        &self,
        height: u32,
        hash: BlockHash,
    ) -> Result<Option<Vec<u8>>, bitcoin_rs_storage::block_body::BlockBodyReadError> {
        if height == self.height && hash == self.hash {
            Ok(Some(vec![0xFF_u8; 80]))
        } else {
            Ok(None)
        }
    }
}

// API-02
#[test]
fn gettxoutproof_answers_core_read_error_for_an_undecodable_body() {
    let block = distinct_block(10);
    let Some(wanted) = block.txs.first().map(Tx::txid) else {
        panic!("block has no transactions");
    };
    let mut ctx = Context::new();
    ctx.indexes.derived_index = Some(Arc::new(HeightQuery(|_: &Txid| Ok(Some(1)))));
    ctx.chain.add_block(BlockRecord::synthetic(
        0,
        BlockHash::from(Hash256::from_le_bytes(&[9_u8; 32])),
    ));
    let record = BlockRecord::from_block(1, &block);
    ctx.chain.block_body_source = Some(Arc::new(CorruptBodySource {
        height: record.height,
        hash: record.hash,
    }));
    ctx.chain.add_block(record);
    let ctx = Arc::new(ctx);

    let error = proof_for(&ctx, &[wanted]).expect_err("an undecodable body is not absence");

    assert!(
        matches!(
            error,
            RpcError::CoreInternal(reason) if reason == "Can't read block from disk"
        ),
        "Core v31.1 answers Can't read block from disk instead of hiding storage damage"
    );
}

// API-02
#[test]
fn gettxoutproof_utxo_path_answers_interrupted_when_cancelled() {
    let block = distinct_block(11);
    let Some(txid) = block.txs.first().map(Tx::txid) else {
        panic!("block has no transactions");
    };
    let mut ctx = Context::new();
    attach_body_for_block(&mut ctx, &block, 1);
    ctx.chain.add_block(BlockRecord::synthetic(
        0,
        BlockHash::from(Hash256::from_le_bytes(&[3_u8; 32])),
    ));
    ctx.chain.add_block(BlockRecord::from_block(1, &block));
    let ctx = Arc::new(ctx);
    let latch = bitcoin_rs_execution::chain::LatchWriter::new();
    latch.trigger();

    let cancelled = super::gettxoutproof(&ctx, &json!([[txid.to_string()]]), &latch.reader());
    assert!(
        matches!(
            cancelled,
            Err(RpcError::Misc(reason)) if reason == "gettxoutproof interrupted"
        ),
        "a cancelled request must stop the utxo probe"
    );
}

// API-02
#[test]
fn gettxoutproof_utxo_path_interrupts_for_a_mixed_txid_list() {
    let block = distinct_block(12);
    let Some(txid) = block.txs.first().map(Tx::txid) else {
        panic!("block has no transactions");
    };
    let unknown = Hash256::from_le_bytes(&[0x77; 32]);
    let unknown_txid = Txid(unknown);
    let mut ctx = Context::new();
    attach_body_for_block(&mut ctx, &block, 1);
    ctx.chain.add_block(BlockRecord::from_block(1, &block));
    let ctx = Arc::new(ctx);
    let latch = bitcoin_rs_execution::chain::LatchWriter::new();
    latch.trigger();

    let cancelled = super::gettxoutproof(
        &ctx,
        &json!([[unknown_txid.to_string(), txid.to_string()]]),
        &latch.reader(),
    );
    assert!(
        matches!(
            cancelled,
            Err(RpcError::Misc(reason)) if reason == "gettxoutproof interrupted"
        ),
        "the per-txid check must fire before any lookup"
    );
}

#[test]
fn gettxoutproof_with_blockhash_never_consults_the_index() {
    let block = distinct_block(4);
    let Some(wanted) = block.txs.first().map(Tx::txid) else {
        panic!("block has no transactions");
    };
    let record = BlockRecord::from_block(0, &block);
    let block_hash = record.hash;
    let mut ctx = Context::new();
    ctx.indexes.derived_index = Some(Arc::new(HeightQuery(
        |_: &Txid| -> Result<Option<u32>, TxQueryError> {
            panic!("the explicit-blockhash path must not consult the index");
        },
    )));
    attach_body_for_block(&mut ctx, &block, 0);
    ctx.chain
        .block_tree
        .write()
        .insert_node(None, block.header, NodeStatus::Active)
        .expect("insert block header");
    ctx.chain.add_block(record);
    let ctx = Arc::new(ctx);

    let result = super::gettxoutproof(
        &ctx,
        &json!([[wanted.to_string()], block_hash.to_string()]),
        &LatchReader::fixture_never(),
    );

    assert!(
        result.as_ref().is_ok_and(|value| value.as_str().is_some()),
        "the explicit-blockhash path should answer without the index: {result:?}"
    );
}

fn retry_spendable_script() -> Vec<u8> {
    let mut script = vec![0x00, 0x20];
    script.extend_from_slice(&[
        0x4a, 0xe8, 0x15, 0x72, 0xf0, 0x6e, 0x1b, 0x88, 0xfd, 0x5c, 0xed, 0x7a, 0x1a, 0x00, 0x09,
        0x45, 0x43, 0x2e, 0x83, 0xe1, 0x55, 0x1e, 0x6f, 0x72, 0x1e, 0xe9, 0xc0, 0x0b, 0x8c, 0xc3,
        0x32, 0x60,
    ]);
    script
}

fn retry_fund_utxo(ctx: &Context, label: u8, value: u64) -> OutPoint {
    use bitcoin_rs_consensus::primitives::{Amount, Script};
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(
        OutPoint::new(Txid(Hash256::from_le_bytes(&[label; 32])), 0),
        TxOut {
            value: Amount::from_sat(value),
            script_pubkey: Script::from_bytes(retry_spendable_script()),
        },
        false,
        1,
    ));
    ctx.populate_fixture_coins(&changes)
        .unwrap_or_else(|err| panic!("commit_block failed: {err}"));
    OutPoint::new(Txid(Hash256::from_le_bytes(&[label; 32])), 0)
}

fn retry_tx(prevout: OutPoint, output_value: u64) -> Tx {
    use bitcoin_rs_consensus::primitives::{Amount, LockTime, Script, Sequence, Witness};
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: prevout,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_stack(vec![vec![0x51]]),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(output_value),
            script_pubkey: Script::from_bytes(retry_spendable_script()),
        }],
    }
}

fn retry_raw_hex(tx: &Tx) -> String {
    consensus_bytes(tx).to_lower_hex_string()
}

#[test]
fn sendrawtransaction_rebuilds_admission_context_after_transient_rejection() {
    let ctx = Arc::new(Context::new());
    reset_admission_park();

    let parent_prevout = retry_fund_utxo(&ctx, 0x70, 100_000);
    let parent = retry_tx(parent_prevout, 90_000);
    let parent_txid = parent.txid();
    let child_prevout = OutPoint::new(parent_txid, 0);
    let child = retry_tx(child_prevout, 80_000);
    let child_txid = child.txid();
    let child_hex = retry_raw_hex(&child);

    let (parked_tx, parked_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let target = Arc::as_ptr(&ctx.mempool.gateway).expose_provenance();
    arm_admission_park(target, parked_tx, release_rx);

    let ctx_clone = Arc::clone(&ctx);
    let handler = Handler::new(Arc::clone(&ctx));
    let admission =
        thread::spawn(move || handler.dispatch("sendrawtransaction", &json!([child_hex])));

    parked_rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("first admission parked at the gateway seam");

    let guard = ctx_clone
        .mempool
        .gateway
        .begin_chain_change()
        .expect("begin chain change on even generation");
    guard
        .finish()
        .expect("finish chain change to next even generation");

    let parent_vsize = u32::try_from(parent.vsize()).unwrap_or(u32::MAX);
    ctx_clone
        .mempool
        .gateway
        .insert_entry(
            AdmissionOrigin::Rpc,
            MempoolEntry::new(
                Arc::new(parent),
                parent_vsize,
                10_000,
                bitcoin_rs_consensus::primitives::unix_time_secs(),
                1,
                0,
            ),
        )
        .expect("parent admitted to the mempool");

    release_tx.send(()).expect("release the parked admission");

    let result = admission.join().expect("admission thread did not panic");

    reset_admission_park();

    let txid_str = result
        .as_ref()
        .map_err(|err| format!("sendrawtransaction failed: {err}"))
        .and_then(|value| {
            value
                .as_str()
                .map(ToString::to_string)
                .ok_or_else(|| format!("expected txid string, got {value:?}"))
        });
    assert_eq!(
        txid_str.expect("child admitted on retry"),
        child_txid.to_string(),
        "the retried admission must observe the fresh mempool state"
    );

    assert!(
        ctx.mempool.gateway.read().contains_txid(&child_txid),
        "the child must be pooled after successful retry"
    );
    assert!(
        ctx.mempool.gateway.read().contains_txid(&parent_txid),
        "the parent must remain pooled"
    );
}

// API-02
#[test]
fn verifytxoutproof_refuses_a_header_outside_the_active_chain()
-> Result<(), crate::test_error::TestError> {
    let genesis = fixture_genesis();
    let Some(txid) = genesis.txs.first().map(Tx::txid) else {
        panic!("genesis has no transactions");
    };
    let mut ctx = Context::new();
    ctx.indexes.derived_index = Some(Arc::new(HeightQuery(|_: &Txid| Ok(Some(0)))));
    install_chain_blocks(&mut ctx, std::slice::from_ref(&genesis));
    let ctx = Arc::new(ctx);

    let proof = proof_for(&ctx, &[txid])?;
    let proof_hex = proof.as_str().expect("proof hex string");
    let bytes = bitcoin_rs_consensus::primitives::hex::hex_decode(proof_hex).expect("proof hex");
    let mut merkle_block =
        bitcoin::consensus::encode::deserialize::<bitcoin::merkle_tree::MerkleBlock>(&bytes)
            .expect("proof decodes");
    merkle_block.header.nonce = merkle_block.header.nonce.wrapping_add(1);
    let tampered = bitcoin::consensus::encode::serialize(&merkle_block).to_lower_hex_string();

    let refusal = match super::verifytxoutproof(&ctx, &json!([tampered])) {
        Err(RpcError::InvalidAddressOrKey(reason)) => reason,
        other => {
            panic!("Core v31.1 answers -5 for a header the active chain does not name: {other:?}")
        }
    };
    assert_eq!(
        refusal, "Block not found in chain",
        "Core v31.1 names the missing chain entry"
    );
    Ok(())
}

// API-02
#[test]
fn verifytxoutproof_answers_an_empty_list_when_the_transaction_count_differs()
-> Result<(), crate::test_error::TestError> {
    let genesis = fixture_genesis();
    let Some(txid) = genesis.txs.first().map(Tx::txid) else {
        panic!("genesis has no transactions");
    };
    let proof_hex = {
        let mut ctx = Context::new();
        ctx.indexes.derived_index = Some(Arc::new(HeightQuery(|_: &Txid| Ok(Some(0)))));
        install_chain_blocks(&mut ctx, std::slice::from_ref(&genesis));
        let proof = proof_for(&Arc::new(ctx), &[txid])?;
        proof.as_str().expect("proof hex string").to_owned()
    };

    let matching = {
        let mut ctx = Context::new();
        install_chain_blocks(&mut ctx, std::slice::from_ref(&genesis));
        Arc::new(ctx)
    };
    let listed = super::verifytxoutproof(&matching, &json!([proof_hex]))?;
    assert_eq!(
        listed.as_array().map(|items| items.len()),
        Some(1),
        "the same proof lists its transaction when the recorded count matches"
    );

    let mismatching = {
        let mut ctx = Context::new();
        let mut stale = BlockRecord::from_block(0, &genesis);
        stale.tx_count = 2;
        let hash = stale.hash;
        ctx.chain.block_body_source = Some(Arc::new(BlockBodies {
            bodies: vec![(0, hash, consensus_bytes(&genesis))],
        }));
        ctx.chain.add_block(stale);
        {
            let mut tree = ctx.chain.block_tree.write();
            tree.insert_node(None, genesis.header, NodeStatus::Active)
                .expect("genesis header");
        }
        let tip = ctx.chain.block_tree.read().tip().expect("chain tip");
        ctx.chain.applied_tip.store(Some(Arc::new((*tip).clone())));
        Arc::new(ctx)
    };
    let mismatched = super::verifytxoutproof(&mismatching, &json!([proof_hex]))?;
    assert_eq!(
        mismatched.as_array().map(|items| items.len()),
        Some(0),
        "Core v31.1 lists nothing when the recorded transaction count differs"
    );

    let ctx = Context::new();
    {
        let mut tree = ctx.chain.block_tree.write();
        tree.insert_node(None, genesis.header, NodeStatus::Active)
            .expect("genesis header");
    }
    let header_only = Arc::new(ctx);
    let uncounted = super::verifytxoutproof(&header_only, &json!([proof_hex]));
    let uncounted_message = match uncounted {
        Err(RpcError::InvalidAddressOrKey(reason)) => reason,
        other => panic!(
            "Core v31.1 answers -5 while the chain entry records no transaction count: {other:?}"
        ),
    };
    assert_eq!(
        uncounted_message, "Block not found in chain",
        "Core v31.1 names the missing chain entry"
    );
    Ok(())
}
