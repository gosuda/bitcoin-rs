fn scantxoutset(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    super::scantxoutset(ctx, params, &bitcoin_rs_chain::LatchReader::fixture_never())
}

use alloc::sync::Arc;

use bitcoin_rs_chain::{ChainWork, NodeId, TipSnapshot};
use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut, Txid};
use bitcoin_rs_utxo::contract::{BlockChanges, UtxoAdd};

use super::*;

fn test_txid(seed: u64) -> Hash256 {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    bytes[8..16].copy_from_slice(&seed.rotate_left(7).to_le_bytes());
    bytes[16..24].copy_from_slice(&seed.wrapping_mul(17).to_le_bytes());
    bytes[24..32].copy_from_slice(&seed.wrapping_add(99).to_le_bytes());
    Hash256::from_le_bytes(&bytes)
}

fn burn_p2pkh_script() -> Vec<u8> {
    let mut script = vec![0x76, 0xa9, 0x14];
    script.extend_from_slice(&[0_u8; 20]);
    script.extend_from_slice(&[0x88, 0xac]);
    script
}

fn commit_test_utxo(ctx: &Context, outpoint: OutPoint, txout: TxOut, coinbase: bool, height: u32) {
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(outpoint, txout, coinbase, height));
    bitcoin_rs_utxo::contract::commit_block_changes(
        &ctx.chain.utxo.fixture_set(),
        &changes,
        &test_txid(8_000),
    )
    .unwrap_or_else(|err| panic!("commit utxo failed: {err}"));
}

#[test]
fn scantxoutset_addr_returns_matching_unspents() {
    let ctx = Arc::new(Context::new());
    let address = "1111111111111111111114oLvT2";
    let script = burn_p2pkh_script();
    let txout = TxOut {
        value: Amount::from_sat(12_345),
        script_pubkey: script.clone().into(),
    };
    let outpoint = OutPoint::new(Txid::from(test_txid(11)), 0);
    commit_test_utxo(&ctx, outpoint, txout, true, 0);
    commit_test_utxo(
        &ctx,
        OutPoint::new(Txid::from(test_txid(12)), 0),
        TxOut {
            value: Amount::from_sat(9_999),
            script_pubkey: vec![0x51].into(),
        },
        false,
        0,
    );

    let result = scantxoutset(&ctx, &json!(["start", [format!("addr({address})")]]))
        .unwrap_or_else(|err| panic!("scantxoutset failed: {err}"));
    let Some(unspents) = result.get("unspents").and_then(Value::as_array) else {
        panic!("unspents missing: {result:?}");
    };

    assert_eq!(result.get("txouts").and_then(Value::as_u64), Some(2));
    assert_eq!(
        result.get("total_amount").and_then(Value::as_f64),
        Some(0.000_123_45)
    );
    assert_eq!(unspents.len(), 1);
    let first = &unspents[0];
    let expected_txid = {
        let txid = outpoint.txid;
        txid.to_string()
    };
    assert_eq!(
        first.get("txid").and_then(Value::as_str),
        Some(expected_txid.as_str())
    );
    assert_eq!(first.get("vout").and_then(Value::as_u64), Some(0));
    assert_eq!(
        first.get("scriptPubKey").and_then(Value::as_str),
        Some(script.to_lower_hex_string().as_str())
    );
    assert_eq!(
        first.get("amount").and_then(Value::as_f64),
        Some(0.000_123_45)
    );
    assert_eq!(first.get("coinbase").and_then(Value::as_bool), Some(true));
    assert_eq!(first.get("height").and_then(Value::as_u64), Some(0));
    assert_eq!(first.get("confirmations").and_then(Value::as_u64), Some(1));
    let Some(desc) = first.get("desc").and_then(Value::as_str) else {
        panic!("desc missing: {first:?}");
    };
    assert!(desc.starts_with("addr(1111111111111111111114oLvT2)#"));
}

#[test]
fn scantxoutset_waits_for_one_consistent_utxo_and_tip_transition() {
    let transition = bitcoin_rs_chain::TransitionDomain::new().stable_read();
    let context = Context::new().with_chain_transition(transition.clone());
    let old_tip = TipSnapshot {
        tip_id: NodeId::new(0),
        height: 0,
        chainwork: ChainWork::ZERO,
        hash: test_txid(100),
        chain_tx_count: bitcoin_rs_chain::ChainTxCount::UNKNOWN,
    };
    context.chain.applied_tip.store(Some(Arc::new(old_tip)));
    let ctx = Arc::new(context);
    let address = "1111111111111111111114oLvT2";
    let script = burn_p2pkh_script();
    commit_test_utxo(
        &ctx,
        OutPoint::new(Txid::from(test_txid(101)), 0),
        TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: script.clone().into(),
        },
        false,
        1,
    );

    let transition_guard = transition.lock();
    let (started_tx, started_rx) = crossbeam_channel::bounded(1);
    let scan_ctx = Arc::clone(&ctx);
    let scanner = std::thread::spawn(move || {
        started_tx
            .send(())
            .unwrap_or_else(|err| panic!("started signal failed: {err}"));
        scantxoutset(&scan_ctx, &json!(["start", [format!("addr({address})")]]))
    });
    started_rx
        .recv()
        .unwrap_or_else(|err| panic!("started receive failed: {err}"));

    commit_test_utxo(
        &ctx,
        OutPoint::new(Txid::from(test_txid(102)), 0),
        TxOut {
            value: Amount::from_sat(20_000),
            script_pubkey: script.into(),
        },
        false,
        1,
    );
    let new_tip = TipSnapshot {
        tip_id: NodeId::new(1),
        height: 1,
        chainwork: ChainWork::from(1_u64),
        hash: test_txid(103),
        chain_tx_count: bitcoin_rs_chain::ChainTxCount::UNKNOWN,
    };
    ctx.chain.applied_tip.store(Some(Arc::new(new_tip.clone())));
    drop(transition_guard);

    let result = scanner
        .join()
        .unwrap_or_else(|_| panic!("scanner thread panicked"))
        .unwrap_or_else(|err| panic!("scantxoutset failed: {err}"));
    assert_eq!(result.get("txouts").and_then(Value::as_u64), Some(2));
    assert_eq!(result.get("height").and_then(Value::as_u64), Some(1));
    assert_eq!(
        result.get("bestblock").and_then(Value::as_str),
        Some(new_tip.hash.to_string_be().as_str())
    );
    let unspents = result
        .get("unspents")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("unspents missing: {result:?}"));
    assert_eq!(unspents.len(), 2);
    assert!(unspents.iter().all(|entry| {
        entry.get("height").and_then(Value::as_u64) == Some(1)
            && entry.get("confirmations").and_then(Value::as_u64) == Some(1)
    }));
}

#[test]
fn scantxoutset_accepts_object_form_addr_descriptor() {
    let ctx = Arc::new(Context::new());
    let address = "1111111111111111111114oLvT2";
    let script = burn_p2pkh_script();
    let txout = TxOut {
        value: Amount::from_sat(12_345),
        script_pubkey: script.into(),
    };
    let outpoint = OutPoint::new(Txid::from(test_txid(13)), 0);
    commit_test_utxo(&ctx, outpoint, txout, true, 0);

    let result = scantxoutset(
        &ctx,
        &json!(["start", [{"desc": format!("addr({address})"), "range": [0, 1]}]]),
    )
    .unwrap_or_else(|err| panic!("scantxoutset failed: {err}"));
    let Some(unspents) = result.get("unspents").and_then(Value::as_array) else {
        panic!("unspents missing: {result:?}");
    };

    assert_eq!(result.get("txouts").and_then(Value::as_u64), Some(1));
    assert_eq!(unspents.len(), 1);
    let first = &unspents[0];
    let expected_txid = {
        let txid = outpoint.txid;
        txid.to_string()
    };
    assert_eq!(
        first.get("txid").and_then(Value::as_str),
        Some(expected_txid.as_str())
    );
}

#[test]
fn scantxoutset_refuses_malformed_requests() {
    let ctx = Arc::new(Context::new());
    let cases: &[(&str, Value, &str)] = &[
        (
            "missing scanobjects",
            json!(["start"]),
            "scanobjects argument is required",
        ),
        (
            "non-array scanobjects",
            json!(["start", "addr(1111111111111111111114oLvT2)"]),
            "is not of expected type array",
        ),
        (
            "object without desc",
            json!(["start", [{"range": 0}]]),
            "Descriptor needs to be provided",
        ),
        (
            "inverted range",
            json!(["start", [{"desc": "addr(1111111111111111111114oLvT2)", "range": [2, 1]}]]),
            "must not have begin after end",
        ),
        (
            "unsupported descriptor in object form",
            json!(["start", [{"desc": "wsh(pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798))"}]]),
            "Supported scan descriptors",
        ),
        (
            "unsupported descriptor",
            json!([
                "start",
                ["pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)"]
            ]),
            "Supported scan descriptors",
        ),
        (
            "bad descriptor checksum",
            json!(["start", ["addr(1111111111111111111114oLvT2)#badbadba"]]),
            "does not match computed checksum",
        ),
        (
            "address from another network",
            json!([
                "start",
                ["addr(tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx)"]
            ]),
            "Address is not valid",
        ),
    ];

    for (name, params, message) in cases {
        match scantxoutset(&ctx, params) {
            Ok(value) => panic!("{name} succeeded: {value:?}"),
            Err(err) => assert!(
                err.to_string().contains(message),
                "{name}: wanted {message:?}, got {err}"
            ),
        }
    }
}

#[test]
fn scantxoutset_empty_and_named_start_match_genesis() {
    let ctx = Arc::new(Context::new());
    let result = scantxoutset(&ctx, &json!({"action":"start", "scanobjects":[]}))
        .unwrap_or_else(|error| panic!("empty scan: {error}"));
    assert_eq!(result["success"].as_bool(), Some(true));
    assert_eq!(
        result["bestblock"].as_str(),
        Some(
            ctx.chain
                .chain_network
                .genesis_block_hash()
                .to_string()
                .as_str()
        )
    );
    assert_eq!(result["txouts"].as_u64(), Some(0));
    assert!(
        result["unspents"]
            .as_array()
            .unwrap_or_else(|| panic!("expected array"))
            .is_empty()
    );
}

#[test]
fn scantxoutset_status_abort_release_and_failure_cleanup() {
    let ctx = Arc::new(Context::new());
    let permit = ctx
        .chain
        .utxo
        .reserve_scan()
        .unwrap_or_else(|error| panic!("reserve: {error}"));
    assert_eq!(
            scantxoutset(&ctx, &json!(["status"]))
                .unwrap_or_else(|error| panic!("status: {error}"))["progress"]
                .as_u64(),
            Some(0)
        );
    assert_eq!(
        scantxoutset(&ctx, &json!(["start", []]))
            .err()
            .unwrap_or_else(|| panic!("reserved"))
            .code(),
        -8
    );
    assert_eq!(
        scantxoutset(&ctx, &json!(["abort"]))
            .unwrap_or_else(|error| panic!("abort: {error}"))
            .as_bool(),
        Some(true)
    );
    let result = scantxoutset_scan(
        &ctx,
        &permit,
        &std::collections::BTreeMap::new(),
        &bitcoin_rs_chain::LatchReader::fixture_never(),
    )
    .unwrap_or_else(|error| panic!("cancel result: {error}"));
    assert_eq!(result["success"].as_bool(), Some(false));
    drop(permit);
    assert!(
        scantxoutset(&ctx, &json!(["status"]))
            .unwrap_or_else(|error| panic!("idle: {error}"))
            .is_null()
    );
    assert!(scantxoutset(&ctx, &json!(["start", ["invalid"]])).is_err());
    assert!(
        scantxoutset(&ctx, &json!(["status"]))
            .unwrap_or_else(|error| panic!("idle after error: {error}"))
            .is_null()
    );
}

#[test]
fn scan_can_abort_while_waiting_for_chain_transition() {
    let transition = bitcoin_rs_chain::TransitionDomain::new().stable_read();
    let ctx = Arc::new(Context::new().with_chain_transition(transition.clone()));
    let held = transition.lock();
    let worker_ctx = Arc::clone(&ctx);
    let (sent, received) = crossbeam_channel::bounded(1);
    let worker = std::thread::spawn(move || {
        let result = scantxoutset(&worker_ctx, &json!(["start", []]));
        sent.send(result)
            .unwrap_or_else(|error| panic!("send scan result: {error}"));
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while ctx.chain.utxo.scan_progress().is_none() {
        assert!(std::time::Instant::now() < deadline, "scan never reserved");
        std::thread::yield_now();
    }
    assert!(ctx.chain.utxo.abort_scan());
    let result = received
        .recv_timeout(std::time::Duration::from_secs(1))
        .unwrap_or_else(|error| panic!("abort blocked behind transition: {error}"))
        .unwrap_or_else(|error| panic!("cancel response: {error}"));
    assert_eq!(result["success"].as_bool(), Some(false));
    assert_eq!(result["txouts"].as_u64(), Some(0));
    drop(held);
    worker.join().unwrap_or_else(|_| panic!("worker panicked"));
    assert_eq!(ctx.chain.utxo.scan_progress(), None);
}

#[test]
fn scan_projection_uses_retained_branch_after_tip_changes() {
    let ctx = Context::new();
    let tip = TipSnapshot {
        tip_id: NodeId::new(0),
        height: 3,
        chainwork: ChainWork::ZERO,
        hash: test_txid(300),
        chain_tx_count: bitcoin_rs_chain::ChainTxCount::UNKNOWN,
    };
    ctx.chain.applied_tip.store(Some(Arc::new(tip.clone())));
    let applied = ctx.chain.applied_view();
    let script = burn_p2pkh_script();
    let scan = bitcoin_rs_utxo::UtxoScan {
        txouts: 1,
        unspents: vec![bitcoin_rs_utxo::UtxoCoin {
            outpoint: OutPoint::new(test_txid(301).into(), 0),
            txout: TxOut {
                value: Amount::from_sat(7),
                script_pubkey: script.clone().into(),
            },
            coinbase: false,
            height: 3,
        }],
    };
    let mut changed = tip.clone();
    changed.hash = test_txid(302);
    ctx.chain.applied_tip.store(Some(Arc::new(changed)));
    let descs = std::collections::BTreeMap::from([(script, "original descriptor".into())]);
    let hashes = scan_ancestry(&ctx, &scan, &applied, || Ok(false), 1)
        .unwrap_or_else(|error| panic!("ancestry: {error}"))
        .unwrap_or_else(|| panic!("unexpected cancellation"));
    let (unspents, _, _) = scan_unspents(&scan, &descs, &hashes, applied.height(), || Ok(false))
        .unwrap_or_else(|error| panic!("retained view: {error}"));
    assert_eq!(unspents[0].block_hash, tip.hash.to_string());
}

fn stale_branch_fixture()
-> anyhow::Result<(Context, AppliedView, bitcoin_rs_utxo::UtxoScan, Hash256)> {
    let ctx = Context::new();
    let (old, new, expected) = {
        let mut tree = ctx.chain.block_tree.write();
        let genesis = Header {
            version: 1,
            prev_blockhash: BlockHash::default(),
            merkle_root: Hash256::default(),
            time: 1_000_000,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        };
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::Active)?;
        let mut parent = genesis_id;
        let mut expected = Hash256::default();
        for height in 1..=300 {
            let header = Header {
                prev_blockhash: BlockHash::from(tree.node(parent)?.hash),
                time: 1_000_000 + height,
                nonce: height,
                ..genesis
            };
            parent = tree.insert_node(Some(parent), header, NodeStatus::Active)?;
            if height == 1 {
                expected = tree.node(parent)?.hash;
            }
        }
        let old = tree
            .tip()
            .ok_or_else(|| anyhow::anyhow!("missing old tip"))?;
        parent = genesis_id;
        for height in 1..=301 {
            let header = Header {
                prev_blockhash: BlockHash::from(tree.node(parent)?.hash),
                time: 1_000_000 + height,
                nonce: 1000 + height,
                ..genesis
            };
            parent = tree.insert_node(Some(parent), header, NodeStatus::Active)?;
        }
        let new = tree
            .tip()
            .ok_or_else(|| anyhow::anyhow!("missing new tip"))?;
        (old, new, expected)
    };
    ctx.chain.applied_tip.store(Some(old));
    let applied = ctx.chain.applied_view();
    ctx.chain.applied_tip.store(Some(new));
    let scan = bitcoin_rs_utxo::UtxoScan {
        txouts: 100,
        unspents: (0..100)
            .map(|index| bitcoin_rs_utxo::UtxoCoin {
                outpoint: OutPoint::new(test_txid(index).into(), 0),
                txout: TxOut {
                    value: Amount::from_sat(7),
                    script_pubkey: vec![0x51].into(),
                },
                height: 1,
                coinbase: false,
            })
            .collect(),
    };
    Ok((ctx, applied, scan, expected))
}

#[test]
fn scan_stale_ancestry_walk_is_shared_bounded_and_cancellable() -> anyhow::Result<()> {
    let (ctx, applied, scan, expected) = stale_branch_fixture()?;
    let checks = std::cell::Cell::new(0);
    let hashes = scan_ancestry(
        &ctx,
        &scan,
        &applied,
        || {
            checks.set(checks.get() + 1);
            Ok(false)
        },
        301,
    )?
    .ok_or_else(|| anyhow::anyhow!("unexpected abort"))?;
    assert_eq!(
        hashes.len(),
        1,
        "only requested distinct heights are retained"
    );
    assert_eq!(hashes.get(&1), Some(&expected));
    assert!(
        checks.get() < 10,
        "duplicates must not repeat the ancestry walk"
    );
    assert!(matches!(
        scan_ancestry(&ctx, &scan, &applied, || Ok(false), 100),
        Err(RpcError::Misc(_))
    ));
    checks.set(0);
    assert!(
        scan_ancestry(
            &ctx,
            &scan,
            &applied,
            || {
                checks.set(checks.get() + 1);
                Ok(checks.get() == 3)
            },
            301
        )?
        .is_none(),
        "abort during an old-branch walk"
    );
    checks.set(0);
    assert!(
        scan_ancestry(
            &ctx,
            &scan,
            &applied,
            || {
                checks.set(checks.get() + 1);
                if checks.get() == 3 {
                    Err(RpcError::Misc("deadline reached".into()))
                } else {
                    Ok(false)
                }
            },
            301
        )
        .is_err(),
        "deadline errors must survive ancestry projection"
    );
    let held = ctx.chain.block_tree.write();
    checks.set(0);
    assert!(
        scan_ancestry(
            &ctx,
            &scan,
            &applied,
            || {
                checks.set(checks.get() + 1);
                Ok(checks.get() == 2)
            },
            301
        )?
        .is_none(),
        "abort while waiting for the tree writer"
    );
    drop(held);
    Ok(())
}

#[test]
fn scan_projection_abort_totals_only_the_completed_prefix() -> anyhow::Result<()> {
    let (ctx, applied, scan, expected) = stale_branch_fixture()?;
    let hashes = std::collections::BTreeMap::from([(1, expected)]);
    let descs = std::collections::BTreeMap::from([(vec![0x51], "raw(51)#8lvh9jxk".into())]);
    let checks = std::cell::Cell::new(0);
    let (unspents, amount, complete) =
        scan_unspents(&scan, &descs, &hashes, applied.height(), || {
            checks.set(checks.get() + 1);
            Ok(checks.get() == 2)
        })?;
    assert!(!complete);
    assert_eq!(unspents.len(), 1);
    assert_eq!(amount, 7);
    assert_eq!(unspents[0].block_hash, expected.to_string());
    assert_ne!(
        ctx.chain.applied_hash(),
        applied.hash(ctx.chain.chain_network)
    );
    Ok(())
}

#[test]
fn scan_descriptor_limits_and_public_fixed_forms() {
    let ctx = Arc::new(Context::new());
    let key = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    for desc in [
        "raw(51)".to_string(),
        format!("pkh({key})"),
        format!("wpkh({key})"),
        format!("sh(wpkh({key}))"),
        format!("tr({key})"),
    ] {
        assert!(scantxoutset(&ctx, &json!(["start", [desc]])).is_ok());
    }
    for range in [
        json!(-1),
        json!([-1, 1]),
        json!([2, 1]),
        json!(2_147_483_648u64),
        json!([0, 1_000_000]),
    ] {
        assert_eq!(
            scantxoutset(&ctx, &json!(["start", [{"desc":"raw(51)","range":range}]]))
                .err()
                .unwrap_or_else(|| panic!("range refused"))
                .code(),
            -8
        );
    }
    let descriptors = vec!["raw(51)"; bitcoin_rs_utxo::scan::MAX_SCAN_SCRIPTS + 1];
    assert_eq!(
        scantxoutset(&ctx, &json!(["start", descriptors]))
            .err()
            .unwrap_or_else(|| panic!("count bound"))
            .code(),
        -8
    );
    let secret = "tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK";
    assert_eq!(
        scantxoutset(&ctx, &json!(["start", [format!("wpkh({secret}/0)")]]))
            .err()
            .unwrap_or_else(|| panic!("private descriptor refused"))
            .code(),
        -5
    );
    let repeated = vec![format!("raw({})", "51".repeat(550)); 1024];
    assert_eq!(
        scantxoutset(&ctx, &json!(["start", repeated]))
            .err()
            .unwrap_or_else(|| panic!("aggregate bytes bounded before scan"))
            .code(),
        -8
    );
    let oversized = format!("raw({})", "51".repeat(MAX_SCAN_DESCRIPTOR_BYTES));
    assert_eq!(
        scantxoutset(&ctx, &json!(["start", [oversized]]))
            .err()
            .unwrap_or_else(|| panic!("byte bound"))
            .code(),
        -8
    );
}

const SCAN_XPUB: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

#[test]
fn scan_expansion_budget_counts_ranges_paths_and_duplicates() -> anyhow::Result<()> {
    let ctx = Arc::new(Context::new());
    let single = format!("wpkh({SCAN_XPUB}/0/*)");
    let multi = format!("wpkh({SCAN_XPUB}/<0;1>/*)");
    for objects in [
        json!([{"desc":single,"range":1024}]),
        json!([{"desc":multi,"range":512}]),
        json!([multi]),
        json!([{"desc":single,"range":512},{"desc":single,"range":512}]),
        json!([{"desc":format!("wpkh({SCAN_XPUB}/*h)"),"range":1023},"raw(51)"]),
    ] {
        let error = scantxoutset(&ctx, &json!(["start", objects]))
            .err()
            .ok_or_else(|| anyhow::anyhow!("oversized scan succeeded"))?;
        assert_eq!(error.code(), -8);
        assert!(error.to_string().contains("1024 scan script expansions"));
        assert_eq!(ctx.chain.utxo.scan_progress(), None);
    }
    for objects in [
        json!([{"desc":single,"range":1023}]),
        json!([{"desc":multi,"range":511}]),
        json!([single]),
        json!([{"desc":format!("wpkh({SCAN_XPUB}/<0;1>/7)"),"range":999_999}]),
    ] {
        let result = scantxoutset(&ctx, &json!(["start", objects]))?;
        assert_eq!(result["success"].as_bool(), Some(true));
        assert_eq!(ctx.chain.utxo.scan_progress(), None);
    }
    Ok(())
}

#[test]
fn scan_ranged_keys_preserve_refusals_and_release_reservation() -> anyhow::Result<()> {
    let ctx = Arc::new(Context::new());
    let tpub = "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B";
    let secret = "tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK";
    for desc in [
        format!("wpkh({SCAN_XPUB}/0h/*)"),
        format!("wpkh({SCAN_XPUB}/<0;1h>/*)"),
        format!("wpkh({SCAN_XPUB}/*h)"),
        format!("wpkh({SCAN_XPUB}/<0;1>/*h)"),
        format!("wpkh({SCAN_XPUB}/<0;0>/*)"),
        format!("wpkh({tpub}/0/*)"),
        format!("wpkh({secret}/<0;1>/*)"),
        format!("wpkh({SCAN_XPUB}/0/*)#badbadba"),
        "addr(foo*)".into(),
    ] {
        let error = scantxoutset(&ctx, &json!(["start", [{"desc":desc,"range":[0,1]}]]))
            .err()
            .ok_or_else(|| anyhow::anyhow!("invalid descriptor succeeded: {desc}"))?;
        assert_eq!(error.code(), -5, "{desc}: {error}");
        assert_eq!(ctx.chain.utxo.scan_progress(), None);
        assert_eq!(
            scantxoutset(&ctx, &json!(["start", []]))?["success"].as_bool(),
            Some(true)
        );
    }
    Ok(())
}

#[test]
fn scan_expansion_observes_abort_shutdown_and_deadline() -> anyhow::Result<()> {
    use std::cell::Cell;

    let ctx = Arc::new(Context::new());
    for cause in ["abort", "shutdown", "deadline"] {
        let permit = ctx.chain.utxo.reserve_scan()?;
        let cancellation = bitcoin_rs_chain::LatchReader::fixture_never();
        let descriptor = scan_descriptor(
            &format!("wpkh({SCAN_XPUB}/<0;1>/*)"),
            Some((0, 9)),
            ctx.chain.chain_network,
        )?;
        let emitted = Cell::new(0);
        let result = descriptor.expand(
            &|| {
                if emitted.get() >= 2 {
                    if cause == "deadline" {
                        return Err(scan_error(&bitcoin_rs_utxo::scan::UtxoScanError::Limit(
                            "60 seconds",
                        )));
                    }
                    if cause == "shutdown" {
                        cancellation.store(true);
                    } else {
                        ctx.chain.utxo.abort_scan();
                    }
                }
                permit
                    .cancelled(|| cancellation.is_triggered())
                    .map_err(|error| scan_error(&error))
            },
            |_| {
                emitted.set(emitted.get() + 1);
                Ok(())
            },
        );
        assert!(emitted.get() > 0 && emitted.get() < 20);
        if cause == "deadline" {
            assert!(
                result
                    .err()
                    .ok_or_else(|| anyhow::anyhow!("deadline ignored"))?
                    .to_string()
                    .contains("60 seconds")
            );
        } else {
            result?;
            let response = scantxoutset_scan(
                &ctx,
                &permit,
                &std::collections::BTreeMap::new(),
                &cancellation,
            )?;
            assert_eq!(response["success"].as_bool(), Some(false));
            assert_eq!(response["txouts"].as_u64(), Some(0));
        }
        drop(permit);
        assert_eq!(ctx.chain.utxo.scan_progress(), None);
        assert_eq!(
            scantxoutset(&ctx, &json!(["start", []]))?["success"].as_bool(),
            Some(true)
        );
    }
    Ok(())
}

#[test]
fn scantxoutset_abort_returns_false() {
    let ctx = Arc::new(Context::new());
    let result = scantxoutset(&ctx, &json!(["abort"]))
        .unwrap_or_else(|err| panic!("scantxoutset abort failed: {err}"));
    assert_eq!(result.as_bool(), Some(false));
}

#[test]
fn ranged_descriptor_matches_fixed_descriptors() {
    let ctx = Arc::new(Context::new());
    let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
    let ranged_desc = format!("wpkh({xpub}/0/*)");
    let fixed_0 = format!("wpkh({xpub}/0/0)");
    let fixed_1 = format!("wpkh({xpub}/0/1)");
    let fixed_2 = format!("wpkh({xpub}/0/2)");

    let scripts = scan_descriptor_range(&ranged_desc, Network::Mainnet, Some((0, 2)), || Ok(false))
        .unwrap_or_else(|err| panic!("derive ranged scripts: {err}"));
    assert_eq!(scripts.len(), 3);

    let single = scan_descriptor_range(&fixed_0, Network::Mainnet, None, || Ok(false))
        .unwrap_or_else(|err| panic!("scan_descriptor fixed form: {err}"))
        .pop()
        .unwrap_or_else(|| panic!("scan_descriptor fixed form produced no script"));
    assert_eq!(single.script_pubkey, scripts[0].script_pubkey);
    assert_eq!(single.desc, scripts[0].desc);

    for (i, s) in scripts.iter().enumerate() {
        let idx_u64 = u64::try_from(i).unwrap_or(0);
        let idx_u32 = u32::try_from(i).unwrap_or(0);
        let outpoint = OutPoint::new(Txid::from(test_txid(50 + idx_u64)), idx_u32);
        let txout = TxOut {
            value: Amount::from_sat(10_000 * (idx_u64 + 1)),
            script_pubkey: s.script_pubkey.clone().into(),
        };
        commit_test_utxo(&ctx, outpoint, txout, false, 0);
    }

    let ranged_result = scantxoutset(
        &ctx,
        &json!(["start", [{"desc": ranged_desc, "range": [0, 2]}]]),
    )
    .unwrap_or_else(|err| panic!("ranged scan failed: {err}"));

    let fixed_result = scantxoutset(&ctx, &json!(["start", [fixed_0, fixed_1, fixed_2]]))
        .unwrap_or_else(|err| panic!("fixed scan failed: {err}"));

    assert_eq!(ranged_result["txouts"], fixed_result["txouts"]);
    assert_eq!(ranged_result["total_amount"], fixed_result["total_amount"]);
    assert_eq!(ranged_result["unspents"], fixed_result["unspents"]);

    let unspents = ranged_result["unspents"]
        .as_array()
        .unwrap_or_else(|| panic!("unspents missing: {ranged_result:?}"));
    assert_eq!(unspents.len(), 3);
    for entry in unspents {
        assert!(entry.get("txid").is_some());
        assert!(entry.get("vout").is_some());
        assert!(entry.get("amount").is_some());
        assert!(entry.get("desc").is_some());
    }
}

#[test]
fn multipath_expansion_uses_index_major_branch_inner_order() {
    let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
    let desc = format!("wpkh({xpub}/<0;1>/*)");
    let scripts = scan_descriptor_range(&desc, Network::Mainnet, Some((0, 2)), || Ok(false))
        .unwrap_or_else(|err| panic!("scan_descriptor_range failed: {err}"));
    assert_eq!(scripts.len(), 6);
    let descs: Vec<&str> = scripts.iter().map(|s| s.desc.as_str()).collect();
    assert!(
        descs[0].contains("/0/0]"),
        "expected /0/0, got {}",
        descs[0]
    );
    assert!(
        descs[1].contains("/1/0]"),
        "expected /1/0, got {}",
        descs[1]
    );
    assert!(
        descs[2].contains("/0/1]"),
        "expected /0/1, got {}",
        descs[2]
    );
    assert!(
        descs[3].contains("/1/1]"),
        "expected /1/1, got {}",
        descs[3]
    );
    assert!(
        descs[4].contains("/0/2]"),
        "expected /0/2, got {}",
        descs[4]
    );
    assert!(
        descs[5].contains("/1/2]"),
        "expected /1/2, got {}",
        descs[5]
    );
}

#[test]
fn ranged_descriptor_budget_bounds_and_omitted_multipath_default() {
    let ctx = Arc::new(Context::new());
    let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

    let ok = scantxoutset(
        &ctx,
        &json!(["start", [{"desc": format!("wpkh({xpub}/0/*)"), "range": [0, 1023]}]]),
    );
    assert!(ok.is_ok(), "range [0, 1023] must succeed: {ok:?}");

    let err_1024 = scantxoutset(
        &ctx,
        &json!(["start", [{"desc": format!("wpkh({xpub}/0/*)"), "range": [0, 1024]}]]),
    )
    .err()
    .unwrap_or_else(|| panic!("range [0, 1024] must fail"));
    assert_eq!(err_1024.code(), -8);
    assert!(
        err_1024
            .to_string()
            .contains("At most 1024 scan script expansions are supported"),
        "unexpected scan error: {err_1024}"
    );

    let err_multipath = scantxoutset(&ctx, &json!(["start", [format!("wpkh({xpub}/<0;1>/*)")]]))
        .err()
        .unwrap_or_else(|| panic!("omitted multipath default must fail on 2002 scripts"));
    assert_eq!(err_multipath.code(), -8);
    assert!(
        err_multipath
            .to_string()
            .contains("At most 1024 scan script expansions are supported"),
        "unexpected multipath scan error: {err_multipath}"
    );
}

#[test]
fn cancellation_during_ranged_scan_releases_reservation() {
    let ctx = Arc::new(Context::new());
    let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
    let stop = Arc::new(core::sync::atomic::AtomicBool::new(true));
    let cancel_reader = bitcoin_rs_chain::LatchReader::new(stop);

    let result = super::scantxoutset(
        &ctx,
        &json!(["start", [{"desc": format!("wpkh({xpub}/0/*)"), "range": [0, 10]}]]),
        &cancel_reader,
    )
    .unwrap_or_else(|err| panic!("cancelled scan returned error: {err}"));
    assert_eq!(result["success"].as_bool(), Some(false));
    assert_eq!(ctx.chain.utxo.scan_progress(), None);
}
