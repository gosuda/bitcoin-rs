use alloc::sync::Arc;

use bitcoin_rs_chain::NodeStatus;
use bitcoin_rs_mempool::{AdmissionOrigin, MempoolEntry, arm_admission_park, reset_admission_park};
use bitcoin_rs_primitives::{
    Block, BlockHash, Hash256, Header, OutPoint, Tx, TxIn, TxOut, Txid, consensus_bytes,
};
use bitcoin_rs_utxo::contract::{BlockChanges, UtxoAdd};
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, Value, json};
use std::sync::mpsc;
use std::thread;

use super::{getrawtransaction, gettxout};
use crate::Handler;
use crate::context::{Context, DerivedIndexQuery, TxQueryError, TxUnavailableCause};
use crate::error::RpcError;
use bitcoin::hex::DisplayHex as _;
use bitcoin_rs_index::block_log::BlockRecord;

fn fixture_genesis() -> Block {
    use bitcoin_rs_primitives::{Amount, CompactTarget, LockTime, Script, Sequence, Witness};
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
        bitcoin_rs_chain::regtest_fixture::merkle_root(&block.txs).unwrap_or_default();
    block
}

#[test]
fn getrawtransaction_falls_back_to_mempool_for_unconfirmed()
-> Result<(), Box<dyn std::error::Error>> {
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

#[test]
fn getrawtransaction_checks_mempool_before_failing_txindex()
-> Result<(), Box<dyn std::error::Error>> {
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
fn getrawtransaction_with_blockhash_finds_tx_in_specific_block() {
    let genesis = fixture_genesis();
    let Some(coinbase) = genesis.txs.first() else {
        panic!("genesis has no transactions");
    };
    let txid = coinbase.txid();
    let block_hash = genesis.block_hash();
    let mut ctx = Context::new();
    attach_body_for_block(&mut ctx, &genesis, 0);
    ctx.chain
        .block_tree
        .write()
        .insert_node(None, genesis.header, NodeStatus::Active)
        .expect("insert genesis header");
    ctx.chain.add_block(BlockRecord::from_block(0, &genesis));
    let ctx = Arc::new(ctx);
    let handler = Handler::new(Arc::clone(&ctx));
    let result = handler
        .dispatch(
            "getrawtransaction",
            &json!([txid.to_string(), false, block_hash.to_string()]),
        )
        .unwrap_or_else(|err| panic!("getrawtransaction with blockhash: {err}"));
    assert!(result.is_str(), "expected hex string, got {result:?}");
}

#[test]
fn getrawtransaction_explicit_coinbase_preserves_undo_failures_and_render_budget() {
    use bitcoin_rs_utxo::contract::{BlockSpends, BlockSpendsError, BlockUndoSource};

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
        bitcoin_rs_chain::regtest_fixture::merkle_root(&block.txs).expect("merkle root");
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
                BlockSpendsError::Undo(bitcoin_rs_utxo::contract::UndoLoadError::Missing {
                    hash: Hash256::default(),
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
    use bitcoin_rs_primitives::Amount;
    use bitcoin_rs_utxo::contract::{
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
        bitcoin_rs_chain::regtest_fixture::merkle_root(&block.txs).expect("merkle root");
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
        bitcoin_rs_chain::TipSnapshot {
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
    let bogus_hash = bitcoin_rs_primitives::Hash256::from_le_bytes(&[7_u8; 32]).to_string_be();
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
fn gettxoutproof_finds_genesis_coinbase() {
    let genesis = fixture_genesis();
    let Some(coinbase) = genesis.txs.first() else {
        panic!("genesis has no transactions");
    };
    let txid = coinbase.txid();
    let ctx = context_with_blocks(std::slice::from_ref(&genesis));
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

#[test]
fn gettxoutproof_skips_pruned_blocks_before_matching_block() {
    let genesis = fixture_genesis();
    let Some(coinbase) = genesis.txs.first() else {
        panic!("genesis has no transactions");
    };
    let txid = coinbase.txid();
    let mut ctx = Context::new();
    ctx.chain.block_body_source = Some(Arc::new(ScriptedBodySource {
        responses: parking_lot::Mutex::new(std::collections::VecDeque::from([
            None,
            Some(consensus_bytes(&genesis)),
        ])),
    }));
    ctx.chain.add_block(BlockRecord::from_block(0, &genesis));
    ctx.chain.add_block(BlockRecord::from_block(0, &genesis));
    let ctx = Arc::new(ctx);
    let handler = Handler::new(Arc::clone(&ctx));

    let result = handler.dispatch("gettxoutproof", &json!([[txid.to_string()]]));

    assert!(
        result.as_ref().is_ok_and(|value| value.as_str().is_some()),
        "gettxoutproof should skip pruned blocks before matching retained blocks: {result:?}"
    );
}

#[test]
fn gettxoutproof_with_blockhash_skips_unrelated_records() {
    let genesis = fixture_genesis();
    let Some(coinbase) = genesis.txs.first() else {
        panic!("genesis has no transactions");
    };
    let txid = coinbase.txid();
    let unrelated_hash = BlockHash::from(Hash256::from_le_bytes(&[7_u8; 32]));
    let record = BlockRecord::from_block(0, &genesis);
    let block_hash = record.hash;
    let mut ctx = Context::new();
    ctx.chain.block_body_source = Some(Arc::new(PanicUnlessBodySource {
        height: record.height,
        hash: record.hash,
        body: consensus_bytes(&genesis),
    }));
    ctx.chain
        .block_tree
        .write()
        .insert_node(None, genesis.header, NodeStatus::Active)
        .expect("insert genesis header");
    ctx.chain
        .add_block(BlockRecord::synthetic(0, unrelated_hash));
    ctx.chain.add_block(record);
    let ctx = Arc::new(ctx);
    let handler = Handler::new(Arc::clone(&ctx));

    let result = handler.dispatch(
        "gettxoutproof",
        &json!([[txid.to_string()], block_hash.to_string()]),
    );

    assert!(
        result.as_ref().is_ok_and(|value| value.as_str().is_some()),
        "gettxoutproof should inspect only the specified block: {result:?}"
    );
}

#[test]
fn gettxoutproof_with_blockhash_reports_pruned_block_body() {
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

    assert!(matches!(
        result,
        Err(RpcError::NotFound("block data pruned"))
    ));
}

#[test]
fn gettxoutproof_with_blockhash_reports_pruned_body_for_a_header_only_block() {
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

    assert!(matches!(
        result,
        Err(RpcError::NotFound("block data pruned"))
    ));
}

fn distinct_block(marker: u8) -> Block {
    use bitcoin_rs_primitives::Script;
    let mut block = fixture_genesis();
    if let Some(input) = block.txs.first_mut().and_then(|tx| tx.inputs.first_mut()) {
        input.script_sig = Script::from_bytes(vec![marker; 4]);
    }
    block.header.merkle_root =
        bitcoin_rs_chain::regtest_fixture::merkle_root(&block.txs).unwrap_or_default();
    block
}

fn block_with_two_txs(marker: u8) -> Block {
    use bitcoin_rs_primitives::{Amount, LockTime, Script, Sequence, Witness};
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
        bitcoin_rs_chain::regtest_fixture::merkle_root(&block.txs).unwrap_or_default();
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

impl bitcoin_rs_chain::BlockBodySource for PanicUnlessBodySource {
    fn block_body(
        &self,
        height: u32,
        hash: BlockHash,
    ) -> Result<Option<Vec<u8>>, bitcoin_rs_chain::BlockBodyReadError> {
        if height == self.height && hash == self.hash {
            Ok(Some(self.body.clone()))
        } else {
            panic!("should not load unrelated body {height}:{hash}");
        }
    }
}

use crate::context::BlockBodies;

#[derive(Default)]
struct ScriptedBodySource {
    responses: parking_lot::Mutex<std::collections::VecDeque<Option<Vec<u8>>>>,
}

impl bitcoin_rs_chain::BlockBodySource for ScriptedBodySource {
    fn block_body(
        &self,
        _height: u32,
        _hash: BlockHash,
    ) -> Result<Option<Vec<u8>>, bitcoin_rs_chain::BlockBodyReadError> {
        Ok(self.responses.lock().pop_front().flatten())
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

fn context_with_blocks(blocks: &[Block]) -> Arc<Context> {
    let mut ctx = Context::new();
    install_blocks(&mut ctx, blocks);
    Arc::new(ctx)
}

fn attach_body_for_block(ctx: &mut Context, block: &Block, height: u32) {
    let record = BlockRecord::from_block(height, block);
    ctx.chain.block_body_source = Some(Arc::new(BlockBodies {
        bodies: vec![(record.height, record.hash, consensus_bytes(block))],
    }));
}

fn proof_for(ctx: &Arc<Context>, txids: &[Txid]) -> Result<sonic_rs::Value, RpcError> {
    let names = txids.iter().map(ToString::to_string).collect::<Vec<_>>();
    super::gettxoutproof(ctx, &json!([names]))
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

#[test]
fn gettxoutproof_falls_back_to_the_scan_when_the_index_cannot_answer() {
    let blocks = [distinct_block(1), distinct_block(2)];
    let Some(wanted) = blocks[1].txs.first().map(Tx::txid) else {
        panic!("block has no transactions");
    };

    let mut ctx = Context::new();
    install_blocks(&mut ctx, &blocks);
    let ctx = Arc::new(ctx);

    let result = proof_for(&ctx, &[wanted]);

    assert!(
        result.as_ref().is_ok_and(|value| value.as_str().is_some()),
        "an index that cannot answer must not turn a findable proof into an error: {result:?}"
    );
}

#[test]
fn gettxoutproof_falls_back_when_the_indexed_block_lacks_some_wanted_txids() {
    let both = block_with_two_txs(9);
    let blocks = [distinct_block(1), both.clone()];
    let wanted = both.txs.iter().map(Tx::txid).collect::<Vec<_>>();

    let scan_ctx = context_with_blocks(&blocks);
    let scanned =
        proof_for(&scan_ctx, &wanted).unwrap_or_else(|err| panic!("scan path failed: {err}"));

    let mut index_ctx = Context::new();
    index_ctx.indexes.derived_index = Some(Arc::new(HeightQuery(|_: &Txid| Ok(Some(0)))));
    install_blocks(&mut index_ctx, &blocks);
    let index_ctx = Arc::new(index_ctx);
    let fell_back =
        proof_for(&index_ctx, &wanted).unwrap_or_else(|err| panic!("fallback path failed: {err}"));

    assert_eq!(
        fell_back.as_str(),
        scanned.as_str(),
        "a candidate block missing some wanted txids must fall back to the scan"
    );
}

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
            result,
            Err(RpcError::NotFound("no block contains all requested txids"))
        ),
        "txids spread across blocks must keep the pre-index error: {result:?}"
    );
}

#[test]
fn gettxoutproof_index_path_answers_for_several_txids_in_one_block() {
    let block = block_with_two_txs(11);
    let wanted = block.txs.iter().map(Tx::txid).collect::<Vec<_>>();
    let resolvable = wanted.iter().map(|txid| (*txid, 1)).collect::<Vec<_>>();

    let mut ctx = Context::new();
    ctx.indexes.derived_index = Some(Arc::new(HeightQuery(resolving(resolvable))));
    let indexed = BlockRecord::from_block(1, &block);
    ctx.chain.block_body_source = Some(Arc::new(PanicUnlessBodySource {
        height: indexed.height,
        hash: indexed.hash,
        body: consensus_bytes(&block),
    }));
    ctx.chain.add_block(BlockRecord::synthetic(
        0,
        BlockHash::from(Hash256::from_le_bytes(&[5_u8; 32])),
    ));
    ctx.chain.add_block(indexed);
    let ctx = Arc::new(ctx);

    let result = proof_for(&ctx, &wanted);

    assert!(
        result.as_ref().is_ok_and(|value| value.as_str().is_some()),
        "several txids in one block should resolve through the index: {result:?}"
    );
}

#[test]
fn gettxoutproof_probes_every_txid_before_giving_up_on_the_index() {
    let block = block_with_two_txs(12);
    let wanted = block.txs.iter().map(Tx::txid).collect::<Vec<_>>();
    let Some(only_one) = wanted.last().copied() else {
        panic!("block has no transactions");
    };

    let mut ctx = Context::new();
    ctx.indexes.derived_index = Some(Arc::new(HeightQuery(resolving(vec![(only_one, 1)]))));
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
        "one unresolvable probe must not abandon the index path: {result:?}"
    );
}

#[test]
fn gettxoutproof_falls_back_to_the_scan_when_the_index_errors() {
    for error in [
        TxQueryError::Retry,
        TxQueryError::Unavailable(TxUnavailableCause::Other("worker stopped".into())),
        TxQueryError::Storage("disk full".into()),
    ] {
        let blocks = [distinct_block(1), distinct_block(2)];
        let Some(wanted) = blocks[1].txs.first().map(Tx::txid) else {
            panic!("block has no transactions");
        };

        let scan_ctx = context_with_blocks(&blocks);
        let scanned =
            proof_for(&scan_ctx, &[wanted]).unwrap_or_else(|err| panic!("scan path failed: {err}"));

        let failure = error.clone();
        let mut ctx = Context::new();
        ctx.indexes.derived_index =
            Some(Arc::new(HeightQuery(move |_: &Txid| Err(failure.clone()))));
        install_blocks(&mut ctx, &blocks);
        let ctx = Arc::new(ctx);

        let result = proof_for(&ctx, &[wanted]);

        assert_eq!(
            result.as_ref().ok().and_then(|value| value.as_str()),
            scanned.as_str(),
            "an index reporting {error} must fall back to the scan, \
                 not fail or answer the call: {result:?}"
        );
    }
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

    let result = super::gettxoutproof(&ctx, &json!([[wanted.to_string()], block_hash.to_string()]));

    assert!(
        result.as_ref().is_ok_and(|value| value.as_str().is_some()),
        "the explicit-blockhash path should answer without the index: {result:?}"
    );
}

#[test]
fn gettxoutproof_asks_the_index_about_every_wanted_txid() {
    let block = block_with_two_txs(13);
    let wanted = block.txs.iter().map(Tx::txid).collect::<Vec<_>>();
    let probes = Arc::new(core::sync::atomic::AtomicUsize::new(0));

    let counter = Arc::clone(&probes);
    let mut ctx = Context::new();
    ctx.indexes.derived_index = Some(Arc::new(HeightQuery(move |_: &Txid| {
        counter.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        Ok(None)
    })));
    install_blocks(&mut ctx, std::slice::from_ref(&block));
    let ctx = Arc::new(ctx);

    let result = proof_for(&ctx, &wanted);
    assert!(
        result.as_ref().is_ok_and(|value| value.as_str().is_some()),
        "the scan must still answer when the index resolves nothing: {result:?}"
    );

    assert_eq!(
        probes.load(core::sync::atomic::Ordering::Relaxed),
        wanted.len(),
        "every wanted txid must be probed before the index path gives up"
    );
}

#[test]
fn gettxoutproof_keeps_probing_after_a_candidate_block_fails_verification() {
    let block = block_with_two_txs(14);
    let wanted = block.txs.iter().map(Tx::txid).collect::<Vec<_>>();
    let probes = Arc::new(core::sync::atomic::AtomicUsize::new(0));

    let counter = Arc::clone(&probes);
    let mut ctx = Context::new();
    ctx.indexes.derived_index = Some(Arc::new(HeightQuery(move |_: &Txid| {
        counter.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        Ok(Some(0))
    })));
    install_blocks(&mut ctx, &[distinct_block(15), block]);
    let ctx = Arc::new(ctx);

    let result = proof_for(&ctx, &wanted);
    assert!(
        result.as_ref().is_ok_and(|value| value.as_str().is_some()),
        "the scan must still answer when no candidate verifies: {result:?}"
    );

    assert_eq!(
        probes.load(core::sync::atomic::Ordering::Relaxed),
        wanted.len(),
        "a candidate that does not hold every wanted txid must not end the walk"
    );
}

#[test]
fn scan_does_not_hold_the_block_log_lock_across_a_body_load() {
    struct LockProbeSource {
        blocks: bitcoin_rs_index::BlockLogReader,
        bodies: Vec<(u32, Vec<u8>)>,
    }

    impl bitcoin_rs_chain::BlockBodySource for LockProbeSource {
        fn block_body(
            &self,
            height: u32,
            _hash: BlockHash,
        ) -> Result<Option<Vec<u8>>, bitcoin_rs_chain::BlockBodyReadError> {
            assert!(
                self.blocks.raw_handle().try_write().is_some(),
                "the block-record lock must not be held across a body load"
            );
            Ok(self
                .bodies
                .iter()
                .find(|(known, _)| *known == height)
                .map(|(_, bytes)| bytes.clone()))
        }
    }

    let blocks = [distinct_block(21), distinct_block(22), distinct_block(23)];
    let Some(wanted) = blocks[2].txs.first().map(Tx::txid) else {
        panic!("block has no transactions");
    };

    let mut ctx = Context::new();
    let log = ctx.chain.blocks.clone();
    let bodies = blocks
        .iter()
        .enumerate()
        .map(|(height, block)| {
            let height = u32::try_from(height).unwrap_or_else(|err| panic!("height: {err}"));
            (height, consensus_bytes(block))
        })
        .collect::<Vec<_>>();
    ctx.chain.block_body_source = Some(Arc::new(LockProbeSource {
        blocks: log,
        bodies,
    }));
    let ctx = Arc::new(ctx);

    for (height, block) in blocks.iter().enumerate() {
        let height = u32::try_from(height).unwrap_or_else(|err| panic!("height: {err}"));
        let hash = block.block_hash();
        ctx.chain.add_block(BlockRecord::synthetic(height, hash));
    }

    let result = proof_for(&ctx, &[wanted]);

    assert!(
        result.as_ref().is_ok_and(|value| value.as_str().is_some()),
        "the scan should answer from the body source: {result:?}"
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
    use bitcoin_rs_primitives::{Amount, Script};
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
    bitcoin_rs_utxo::contract::commit_block_changes(
        &ctx.chain.utxo.fixture_set(),
        &changes,
        &Hash256::from_le_bytes(&[0xaa; 32]),
    )
    .unwrap_or_else(|err| panic!("commit_block failed: {err}"));
    OutPoint::new(Txid(Hash256::from_le_bytes(&[label; 32])), 0)
}

fn retry_tx(prevout: OutPoint, output_value: u64) -> Tx {
    use bitcoin_rs_primitives::{Amount, LockTime, Script, Sequence, Witness};
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
                bitcoin_rs_primitives::unix_time_secs(),
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
