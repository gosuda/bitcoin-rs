//! Mempool policy compatibility contract through the RPC surface: every
//! policy row in `docs/policies/mempool-policy.md` that has an RPC-facing
//! verdict cites one fixture here. Each fixture asserts the observable RPC
//! verdict (accept, or error code + message; per-row `reject-reason` for
//! `testmempoolaccept`) and that the bare `Mempool` path decides the same
//! class the same way for the same fixture tx.
//!
//! Contract clause: `docs/contracts/mempool-policy.md` `POL-01`.
#![deny(clippy::expect_used)]

extern crate alloc;

use alloc::sync::Arc;

use bitcoin_rs_mempool::{
    Mempool, MempoolEntry, MempoolGateway, MempoolLimits, MempoolObserver, MutationEnvelope,
    MutationOutcome, PolicyError, RbfError, RemovalReason, ReplacementCandidate,
    eviction::mempool_min_fee_sat_per_kvb,
};

use bitcoin_rs_chain::{ChainWork, NodeId, TipSnapshot};

use bitcoin_rs_node::{
    Network, NodeConfig,
    reorg::{ReorgError, invalidate_block},
    state::NodeState,
};

use bitcoin_rs_primitives::{
    Amount, Block, CompactTarget, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut,
    Txid, Witness, consensus_bytes, encode::double_sha256,
};

use bitcoin_rs_rpc::{
    Handler, RpcError,
    context::{
        ChainControl, ChainControlError, ChainHandles, Context, ContextHandles, IndexHandles,
        MempoolHandles, MiningHandles, NetworkHandles,
    },
};

use bitcoin_rs_utxo::contract::{BlockChanges, UtxoAdd};

use sonic_rs::{JsonContainerTrait as _, JsonValueTrait, json};

use std::error::Error;

fn p2wpkh_script() -> Vec<u8> {
    // P2WPKH: `OP_0`, push-20, and a fixed 20-byte key hash.
    [vec![0x00, 0x14], vec![0x11; 20]].concat()
}

fn op_true_script() -> Vec<u8> {
    vec![0x51]
}

fn tx(prevout: OutPoint, output_value: u64, sequence: u32) -> Tx {
    Tx {
        version: 2,
        lock_time: LockTime::from_consensus(0),
        inputs: vec![TxIn {
            previous_output: prevout,
            script_sig: Script::new(),
            sequence: Sequence::from_consensus(sequence),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(output_value),
            script_pubkey: Script::from_bytes(p2wpkh_script()),
        }],
    }
}

fn rpc_txid(tx: &Tx) -> Txid {
    tx.txid()
}

/// Native consensus hex for RPC submission: the exact wire image the node
/// decoder consumes.
fn raw_tx_hex(tx: &Tx) -> String {
    hex_encode(&consensus_bytes(tx))
}

/// Encodes `bytes` as lowercase hexadecimal.
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

/// Commits one funded UTXO to the context's UTXO set and returns the RPC-side
/// outpoint that spends it.
fn fund_utxo(ctx: &Context, label: u8, value: u64) -> OutPoint {
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(
        OutPoint::new(Txid(Hash256::from_le_bytes(&[label; 32])), 0),
        TxOut {
            value: Amount::from_sat(value),
            script_pubkey: Script::from_bytes(op_true_script()),
        },
        false,
        1,
    ));
    bitcoin_rs_utxo::contract::commit_block_changes(
        &ctx.chain.utxo,
        &changes,
        &Hash256::from_le_bytes(&[0xaa; 32]),
    )
    .unwrap_or_else(|error| panic!("commit_block failed: {error}"));
    OutPoint {
        txid: Txid(Hash256::from_le_bytes(&[label; 32])),
        vout: 0,
    }
}

/// The confirmed outpoint `fund_utxo(ctx, label, _)` creates.
fn confirmed_outpoint(label: u8) -> OutPoint {
    OutPoint {
        txid: Txid(Hash256::from_le_bytes(&[label; 32])),
        vout: 0,
    }
}

fn reject_message(error: &RpcError) -> String {
    assert_eq!(
        error.code(),
        RpcError::CORE_VERIFY_REJECTED,
        "policy rejects surface as transaction rejections"
    );
    error.to_string()
}

// ---------------------------------------------------------------------------
// Min relay fee
// ---------------------------------------------------------------------------

#[test]
fn sendrawtransaction_rejects_below_min_relay_fee_and_agrees_with_the_pool()
-> Result<(), Box<dyn Error>> {
    let ctx = Arc::new(Context::new());
    let prevout = fund_utxo(&ctx, 0x50, 10_000);
    // fee 1 sat over vsize 82 → ~12 sat/kvB, far below the 1000 sat/kvB floor.
    let tx = tx(prevout, 9_999, 0xffff_ffff);
    let handler = Handler::new(Arc::clone(&ctx));

    let message = reject_message(
        &handler
            .dispatch("sendrawtransaction", &json!([raw_tx_hex(&tx)]))
            .err()
            .ok_or("expected below-min-relay-fee rejection")?,
    );
    assert!(
        message.contains("min relay fee not met"),
        "unexpected rejection message: {message}"
    );
    assert!(
        !ctx.mempool.read().contains_txid(&rpc_txid(&tx)),
        "rejected tx must not enter the pool"
    );

    // Pool-path agreement: the same shape rejects at the same floor.
    let mut pool = Mempool::new(MempoolLimits::default());
    let error = pool
        .insert_entry(MempoolEntry::new(Arc::new(tx), 82, 1, 0, 1))
        .err()
        .ok_or("pool path must also reject")?;
    assert!(matches!(
        error,
        bitcoin_rs_mempool::MempoolError::Policy(PolicyError::BelowMinRelayFee { .. })
    ));
    Ok(())
}

/// One funded input and one 10 000 sat P2WPKH output, so the fee is chosen
/// exactly by the funding value (rate = fee x 1000 / 82 vB).
fn funded_fee_tx(ctx: &Context, label: u8, fee: u64) -> Tx {
    tx(fund_utxo(ctx, label, 10_000 + fee), 10_000, 0xffff_ffff)
}

/// Whether the context's pool currently holds `tx`.
fn pool_holds(ctx: &Context, tx: &Tx) -> bool {
    ctx.mempool.read().contains_txid(&rpc_txid(tx))
}

/// Raises the pool's minimum relay fee floor to `sat_per_kvb`.
fn set_relay_floor(ctx: &Context, sat_per_kvb: u64) {
    ctx.mempool.pool().write().limits.min_relay_fee_sat_per_kvb = sat_per_kvb;
}

#[test]
fn sendrawtransaction_and_testmempoolaccept_quote_the_floor_before_maxfeerate()
-> Result<(), Box<dyn Error>> {
    // 1 230 sat over 82 vB is exactly 15 000 sat/kvB: between the two guards
    // under default limits (1 000 <= 15 000 <= 10 000 000).
    let plain = Arc::new(Context::new());
    let ordinary = funded_fee_tx(&plain, 0x80, 1_230);
    let handler = Handler::new(Arc::clone(&plain));
    handler.dispatch("sendrawtransaction", &json!([raw_tx_hex(&ordinary)]))?;
    assert!(
        pool_holds(&plain, &ordinary),
        "an ordinary between-the-guards tx must admit"
    );

    // Both predicates at once: a configured floor (0.20 BTC/kvB) ABOVE the
    // default client maxfeerate (0.10 BTC/kvB) makes the same 15 000 sat/kvB
    // tx below the floor AND above maxfeerate. The floor class wins on both
    // outlets — the order Core 31.1 uses (admission failure first, then the
    // fee cap).
    let strict = Arc::new(Context::new());
    set_relay_floor(&strict, 20_000_000);
    let both = funded_fee_tx(&strict, 0x81, 1_230);
    let handler = Handler::new(Arc::clone(&strict));
    let message = reject_message(
        &handler
            .dispatch("sendrawtransaction", &json!([raw_tx_hex(&both)]))
            .err()
            .ok_or("expected the floor to reject the both-predicates tx")?,
    );
    assert!(
        message.contains("min relay fee not met"),
        "the floor class must win: {message}"
    );
    assert!(
        !message.contains("max-fee-exceeded"),
        "maxfeerate must not be quoted first: {message}"
    );
    let rows = handler
        .dispatch("testmempoolaccept", &json!([[raw_tx_hex(&both)]]))?
        .as_array()
        .ok_or("expected an array of results")?
        .clone();
    assert_eq!(
        rows.first()
            .ok_or("expected one row")?
            .get("allowed")
            .and_then(JsonValueTrait::as_bool),
        Some(false)
    );
    assert_eq!(
        rows.first()
            .ok_or("expected one row")?
            .get("reject-reason")
            .and_then(JsonValueTrait::as_str),
        Some("min relay fee not met"),
        "testmempoolaccept must report the floor class, not max-fee"
    );
    assert!(
        !pool_holds(&strict, &both),
        "rejected tx must not enter the pool"
    );

    // Pool-path agreement: the raw insert gate quotes the same floor.
    let mut pool = Mempool::new(MempoolLimits {
        min_relay_fee_sat_per_kvb: 20_000_000,
        ..MempoolLimits::default()
    });
    let error = pool
        .insert_entry(MempoolEntry::new(Arc::new(both), 82, 1_230, 0, 1))
        .err()
        .ok_or("pool path must also reject")?;
    assert!(matches!(
        error,
        bitcoin_rs_mempool::MempoolError::Policy(PolicyError::BelowMinRelayFee { .. })
    ));

    // The other branch of the order: above the floor, the client maxfeerate
    // decides. Capping at 0.00005 BTC/kvB (5 000 sat/kvB) rejects the
    // ordinary 15 000 sat/kvB tx with the max-fee class on both outlets.
    let capped = Arc::new(Context::new());
    let high = funded_fee_tx(&capped, 0x82, 1_230);
    let handler = Handler::new(Arc::clone(&capped));
    let error = handler
        .dispatch("sendrawtransaction", &json!([raw_tx_hex(&high), 0.00005]))
        .err()
        .ok_or("expected the client maxfeerate to reject")?;
    assert_eq!(error.code(), RpcError::INVALID_PARAMS);
    assert!(
        error.to_string().contains("max-fee-exceeded"),
        "unexpected message: {error}"
    );
    let rows = handler
        .dispatch("testmempoolaccept", &json!([[raw_tx_hex(&high)], 0.00005]))?
        .as_array()
        .ok_or("expected an array of results")?
        .clone();
    assert_eq!(
        rows.first()
            .ok_or("expected one row")?
            .get("allowed")
            .and_then(JsonValueTrait::as_bool),
        Some(false)
    );
    assert_eq!(
        rows.first()
            .ok_or("expected one row")?
            .get("reject-reason")
            .and_then(JsonValueTrait::as_str),
        Some("max-fee-exceeded")
    );
    Ok(())
}

#[test]
fn rpc_outlets_enforce_the_configured_floor() -> Result<(), Box<dyn Error>> {
    let ctx = Arc::new(Context::new());
    ctx.mempool.pool().write().limits.min_relay_fee_sat_per_kvb = 5_000;
    let handler = Handler::new(Arc::clone(&ctx));

    // 164 sat over 82 vB is exactly 2 000 sat/kvB: below the configured floor.
    let below = tx(fund_utxo(&ctx, 0x83, 10_164), 10_000, 0xffff_ffff);
    let message = reject_message(
        &handler
            .dispatch("sendrawtransaction", &json!([raw_tx_hex(&below)]))
            .err()
            .ok_or("expected the configured floor to reject")?,
    );
    assert!(
        message.contains("min relay fee not met"),
        "unexpected message: {message}"
    );
    let rows = handler
        .dispatch("testmempoolaccept", &json!([[raw_tx_hex(&below)]]))?
        .as_array()
        .ok_or("expected an array of results")?
        .clone();
    assert_eq!(
        rows.first()
            .ok_or("expected one row")?
            .get("reject-reason")
            .and_then(JsonValueTrait::as_str),
        Some("min relay fee not met")
    );

    // Exactly at the floor admits.
    let at_floor = tx(fund_utxo(&ctx, 0x84, 10_410), 10_000, 0xffff_ffff);
    handler.dispatch("sendrawtransaction", &json!([raw_tx_hex(&at_floor)]))?;
    assert!(
        ctx.mempool.read().contains_txid(&rpc_txid(&at_floor)),
        "exactly-at-floor tx must be pooled"
    );

    // Pool-path agreement at the same configured floor.
    let mut pool = Mempool::new(MempoolLimits {
        min_relay_fee_sat_per_kvb: 5_000,
        ..MempoolLimits::default()
    });
    let error = pool
        .insert_entry(MempoolEntry::new(Arc::new(below), 82, 164, 0, 1))
        .err()
        .ok_or("pool path must also reject")?;
    assert_eq!(
        error,
        bitcoin_rs_mempool::MempoolError::Policy(PolicyError::BelowMinRelayFee {
            tx_rate: 2_000,
            min_rate: 5_000,
        })
    );
    pool.insert_entry(MempoolEntry::new(Arc::new(at_floor), 82, 410, 0, 1))?;
    Ok(())
}

#[test]
fn rpc_outlets_enforce_the_pressure_floor() -> Result<(), Box<dyn Error>> {
    let ctx = Arc::new(Context::new());
    {
        let mut pool = ctx.mempool.pool().write();
        pool.limits.max_total_bytes = 400;
        // Fill to exactly half of -maxmempool, the pressure threshold, with
        // packages at 1 000 and 2 000 sat/kvB.
        let first = tx(
            OutPoint {
                txid: Txid(Hash256::from_le_bytes(&[0x85; 32])),
                vout: 0,
            },
            1_000,
            0xffff_ffff,
        );
        pool.insert_entry(MempoolEntry::new(Arc::new(first), 100, 100, 0, 1))?;
        let second = tx(
            OutPoint {
                txid: Txid(Hash256::from_le_bytes(&[0x86; 32])),
                vout: 0,
            },
            1_000,
            0xffff_ffff,
        );
        pool.insert_entry(MempoolEntry::new(Arc::new(second), 100, 200, 0, 1))?;
    }
    let handler = Handler::new(Arc::clone(&ctx));
    // Effective floor = cheapest evictable (1 000) + incremental (1 000).
    assert_eq!(
        mempool_min_fee_sat_per_kvb(&ctx.mempool.read(), 1_000),
        2_000
    );

    // 82 sat over 82 vB is exactly 1 000 sat/kvB: clears the configured
    // floor, misses the pressure floor. Both outlets quote the pressure floor.
    let lukewarm = tx(fund_utxo(&ctx, 0x87, 10_082), 10_000, 0xffff_ffff);
    let message = reject_message(
        &handler
            .dispatch("sendrawtransaction", &json!([raw_tx_hex(&lukewarm)]))
            .err()
            .ok_or("expected the pressure floor to reject")?,
    );
    assert!(
        message.contains("min relay fee not met"),
        "unexpected message: {message}"
    );
    assert!(
        !message.contains("max-fee-exceeded"),
        "unexpected message: {message}"
    );
    let rows = handler
        .dispatch("testmempoolaccept", &json!([[raw_tx_hex(&lukewarm)]]))?
        .as_array()
        .ok_or("expected an array of results")?
        .clone();
    assert_eq!(
        rows.first()
            .ok_or("expected one row")?
            .get("reject-reason")
            .and_then(JsonValueTrait::as_str),
        Some("min relay fee not met")
    );

    // The raw insert gate checks only the configured floor, so the same tx
    // admits there (deviation ledger, pressure-floor surface).
    ctx.mempool
        .pool()
        .write()
        .insert_entry(MempoolEntry::new(Arc::new(lukewarm), 82, 82, 0, 1))?;
    assert_eq!(ctx.mempool.read().len(), 3);

    // Control: with no pressure the same rate admits over the same outlets.
    let idle = Arc::new(Context::new());
    let control = tx(fund_utxo(&idle, 0x88, 10_082), 10_000, 0xffff_ffff);
    Handler::new(Arc::clone(&idle))
        .dispatch("sendrawtransaction", &json!([raw_tx_hex(&control)]))?;
    assert!(
        idle.mempool.read().contains_txid(&rpc_txid(&control)),
        "unpressured control tx must be pooled"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Standardness
// ---------------------------------------------------------------------------

#[test]
fn package_preview_leaves_other_rows_unfinished_after_a_precheck_failure()
-> Result<(), Box<dyn Error>> {
    let ctx = Arc::new(Context::new());
    let good = tx(fund_utxo(&ctx, 0x51, 10_000), 9_000, 0xffff_ffff);
    let below_min = tx(fund_utxo(&ctx, 0x52, 10_000), 9_999, 0xffff_ffff);
    let later = tx(fund_utxo(&ctx, 0x53, 10_000), 9_000, 0xffff_ffff);
    let handler = Handler::new(Arc::clone(&ctx));
    let rows = handler.dispatch(
        "testmempoolaccept",
        &json!([[
            raw_tx_hex(&good),
            raw_tx_hex(&below_min),
            raw_tx_hex(&later),
        ]]),
    )?;
    for index in [0, 2] {
        assert!(rows[index].get("allowed").is_none());
        assert!(rows[index].get("fees").is_none());
        assert!(rows[index].get("reject-reason").is_none());
    }
    assert_eq!(rows[1]["allowed"].as_bool(), Some(false));
    assert_eq!(
        rows[1]["reject-reason"].as_str(),
        Some("min relay fee not met")
    );
    assert!(rows[1].get("fees").is_none());
    assert_eq!(ctx.mempool.read().len(), 0);
    Ok(())
}

#[test]
fn sendrawtransaction_rejects_oversized_and_nonstandard_txs() -> Result<(), Box<dyn Error>> {
    let ctx = Arc::new(Context::new());
    let handler = Handler::new(Arc::clone(&ctx));

    // 3400 P2WPKH outputs ≈ 435 000 weight units > 400 000.
    let mut oversized = tx(fund_utxo(&ctx, 0x55, 10_000), 1_000, 0xffff_ffff);
    oversized.outputs = (0..3_400)
        .map(|_| TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: Script::from_bytes(p2wpkh_script()),
        })
        .collect();
    let message = reject_message(
        &handler
            .dispatch("sendrawtransaction", &json!([raw_tx_hex(&oversized)]))
            .err()
            .ok_or("expected oversized rejection")?,
    );
    assert!(
        message.contains("transaction weight exceeds maximum standard weight"),
        "unexpected message: {message}"
    );

    let weird = Tx {
        outputs: vec![TxOut {
            value: Amount::from_sat(9_000),
            script_pubkey: Script::from_bytes(op_true_script()),
        }],
        ..tx(fund_utxo(&ctx, 0x56, 10_000), 9_000, 0xffff_ffff)
    };
    let message = reject_message(
        &handler
            .dispatch("sendrawtransaction", &json!([raw_tx_hex(&weird)]))
            .err()
            .ok_or("expected non-standard rejection")?,
    );
    assert!(message.contains("non-standard output script"));
    Ok(())
}

// ---------------------------------------------------------------------------
// BIP125 replacement policy
// ---------------------------------------------------------------------------

/// Inserts the conflicting original directly (the way an earlier relay round
/// would have) and returns its tx.
fn insert_original(
    ctx: &Context,
    label: u8,
    sequence: u32,
    vsize: u32,
    fee: u64,
) -> Result<Tx, Box<dyn Error>> {
    let original = tx(fund_utxo(ctx, label, 100_000), 92_000, sequence);
    ctx.mempool.pool().write().insert_entry(MempoolEntry::new(
        Arc::new(original.clone()),
        vsize,
        fee,
        0,
        1,
    ))?;
    Ok(original)
}

#[test]
fn sendrawtransaction_applies_an_rbf_replacement_and_sweeps_the_conflicts()
-> Result<(), Box<dyn Error>> {
    let ctx = Arc::new(Context::new());
    let original = insert_original(&ctx, 0x60, 0xffff_fffd, 4_000, 8_000)?;
    // A conflicting spend of the SAME confirmed outpoint. Its 10 000 sat fee
    // pays the 8 000 sat original (rule 3), its own 82 vB of incremental fee
    // (rule 4), and outranks the original's 2000 sat/kvB stored rate (rule 6).
    let replacement = tx(confirmed_outpoint(0x60), 90_000, 0xffff_ffff);
    let handler = Handler::new(Arc::clone(&ctx));

    let result = handler.dispatch("sendrawtransaction", &json!([raw_tx_hex(&replacement)]))?;
    assert_eq!(
        result.as_str().map(ToString::to_string),
        Some(rpc_txid(&replacement).to_string())
    );
    {
        let pool = ctx.mempool.read();
        assert!(
            !pool.contains_txid(&rpc_txid(&original)),
            "the replaced original must be evicted"
        );
        assert!(
            pool.contains_txid(&rpc_txid(&replacement)),
            "the replacement must be pooled"
        );
    }

    // Pool-path agreement: the same candidate replaces through the pool API.
    let mut pool = Mempool::new(MempoolLimits::default());
    pool.insert_entry(MempoolEntry::new(Arc::new(original), 4_000, 8_000, 0, 1))?;
    pool.replace_transaction(
        ReplacementCandidate::new(Arc::new(replacement.clone()), 82, 10_000, 1_000),
        0,
        1,
        0,
    )?;
    assert!(pool.contains_txid(&rpc_txid(&replacement)));
    Ok(())
}

/// Records every published change as `(sequence, txid, outcome)`.
#[derive(Default)]
struct RecordingGatewayObserver {
    changes: parking_lot::Mutex<Vec<(u64, Hash256, MutationOutcome)>>,
}

impl MempoolObserver for RecordingGatewayObserver {
    fn on_mutation(&self, envelope: &MutationEnvelope) {
        let result = &envelope.result;
        let mut changes = self.changes.lock();
        for (offset, change) in result.changes.iter().enumerate() {
            let sequence = result.sequence_of(offset).unwrap_or(u64::MAX);
            changes.push((sequence, change.txid, change.outcome));
        }
    }
}

/// `sendrawtransaction` publishes through the process-wide gateway: a
/// plain submit emits one Accepted change with origin `Rpc`, and an RBF
/// replacement emits one envelope in commit order — R(Replaced), then
/// R(Descendant), then A. Staged inserts move the pool sequence without
/// publishing, exactly like the apply path's raw sweep.
#[test]
fn sendrawtransaction_publishes_admission_through_gateway() -> Result<(), Box<dyn Error>> {
    let observer = Arc::new(RecordingGatewayObserver::default());
    let ctx = Arc::new(Context::new_with_mempool_observer(observer.clone()));
    // Plain admission: exactly one Accepted change for the txid.
    let plain = tx(fund_utxo(&ctx, 0x51, 100_000), 90_000, 0xffff_ffff);
    let plain_txid = rpc_txid(&plain);
    let handler = Handler::new(Arc::clone(&ctx));
    handler.dispatch("sendrawtransaction", &json!([raw_tx_hex(&plain)]))?;
    {
        let changes = observer.changes.lock();
        assert_eq!(
            *changes,
            vec![(1, Hash256::from(plain_txid), MutationOutcome::Accepted)],
            "the first production A event: one Accepted change"
        );
    }

    // RBF replacement over the existing fixture: original plus its
    // signaling child staged the way an earlier relay round would have.
    let original = insert_original(&ctx, 0x52, 0xffff_fffd, 4_000, 8_000)?;
    let original_txid = rpc_txid(&original);
    let child = tx(OutPoint::new(original_txid, 0), 91_000, 0xffff_fffd);
    let child_txid = rpc_txid(&child);
    ctx.mempool.pool().write().insert_entry(MempoolEntry::new(
        Arc::new(child.clone()),
        u32::try_from(child.vsize()).unwrap_or(u32::MAX),
        1_000,
        0,
        1,
    ))?;
    observer.changes.lock().clear();

    // Its 12 000 sat fee pays both evicted fees (9 000) plus the
    // incremental relay charge, so rules 3, 4, and 6 all clear.
    let replacement = tx(confirmed_outpoint(0x52), 88_000, 0xffff_ffff);
    let replacement_txid = rpc_txid(&replacement);
    handler.dispatch("sendrawtransaction", &json!([raw_tx_hex(&replacement)]))?;

    let changes = observer.changes.lock();
    assert_eq!(
        *changes,
        vec![
            (
                4,
                Hash256::from(original_txid),
                MutationOutcome::Removed(RemovalReason::Replaced),
            ),
            (
                5,
                Hash256::from(child_txid),
                MutationOutcome::Removed(RemovalReason::Descendant),
            ),
            (
                6,
                Hash256::from(replacement_txid),
                MutationOutcome::Accepted,
            ),
        ],
        "one result, commit order: conflicts first (parent before descendant), then the replacement"
    );
    Ok(())
}

#[test]
fn new_unconfirmed_inputs_are_allowed_on_both_rpcs() -> Result<(), Box<dyn Error>> {
    let ctx = Arc::new(Context::new());
    let original = insert_original(&ctx, 0x98, 0xffff_fffd, 4_000, 8_000)?;
    let mut unrelated = tx(fund_utxo(&ctx, 0x99, 10_000), 9_000, 0xffff_ffff);
    unrelated.outputs[0].script_pubkey = Script::from_bytes(op_true_script());
    ctx.mempool.pool().write().insert_entry(MempoolEntry::new(
        Arc::new(unrelated.clone()),
        100,
        1_000,
        0,
        1,
    ))?;
    let replacement = tx_spending(
        &[
            (confirmed_outpoint(0x98), 0xffff_ffff),
            (OutPoint::new(rpc_txid(&unrelated), 0), 0xffff_ffff),
        ],
        100_000,
    );
    let handler = Handler::new(Arc::clone(&ctx));
    let before = ctx.mempool.read().sequence_number();
    let rows = handler.dispatch("testmempoolaccept", &json!([[raw_tx_hex(&replacement)]]))?;
    assert_eq!(rows[0]["allowed"].as_bool(), Some(true), "{rows:?}");
    assert_eq!(ctx.mempool.read().sequence_number(), before);
    let candidate = ReplacementCandidate::new(
        Arc::new(replacement.clone()),
        u32::try_from(replacement.vsize())?,
        9_000,
        1_000,
    );
    ctx.mempool.read().check_replacement(&candidate)?;
    handler.dispatch("sendrawtransaction", &json!([raw_tx_hex(&replacement)]))?;
    let pool = ctx.mempool.read();
    assert!(!pool.contains_txid(&rpc_txid(&original)));
    assert!(pool.contains_txid(&rpc_txid(&unrelated)));
    assert!(pool.contains_txid(&rpc_txid(&replacement)));
    Ok(())
}

#[test]
fn sendrawtransaction_rejects_rule3_replacements_that_underpay_evicted_fees()
-> Result<(), Box<dyn Error>> {
    let ctx = Arc::new(Context::new());
    let original = insert_original(&ctx, 0x9a, 0xffff_fffd, 4_000, 8_000)?;
    // 4 000 sat < the 8 000 sat direct conflict: rule 3 rejects before any
    // rate rule applies (48 780 sat/kvB clears the floor comfortably).
    let replacement = tx(confirmed_outpoint(0x9a), 96_000, 0xffff_ffff);
    let handler = Handler::new(Arc::clone(&ctx));
    let message = reject_message(
        &handler
            .dispatch("sendrawtransaction", &json!([raw_tx_hex(&replacement)]))
            .err()
            .ok_or("expected rule 3 rejection")?,
    );
    assert!(
        message.contains("insufficient fee"),
        "unexpected message: {message}"
    );
    let rows = handler
        .dispatch("testmempoolaccept", &json!([[raw_tx_hex(&replacement)]]))?
        .as_array()
        .ok_or("expected an array of results")?
        .clone();
    assert_eq!(
        rows.first()
            .ok_or("expected one row")?
            .get("reject-reason")
            .and_then(JsonValueTrait::as_str),
        Some("insufficient fee")
    );
    assert!(
        ctx.mempool.read().contains_txid(&rpc_txid(&original)),
        "a rejected replacement leaves the original pooled"
    );

    // Direct pool outcome: the same candidate fails check_replacement with
    // the same rule.
    let candidate = ReplacementCandidate::new(Arc::new(replacement), 82, 4_000, 1_000);
    assert_eq!(
        ctx.mempool.read().check_replacement(&candidate),
        Err(RbfError::Rule3InsufficientAbsoluteFee)
    );
    Ok(())
}

#[test]
fn sendrawtransaction_rejects_a_crossing_replacement_diagram() -> Result<(), Box<dyn Error>> {
    let ctx = Arc::new(Context::new());
    // Original at 4 000 vsize / 8 000 sat fee = 2 000 sat/kvB stored rate,
    // funded at 200 000 so the replacement has fee headroom to tune.
    let original = tx(fund_utxo(&ctx, 0x9b, 200_000), 192_000, 0xffff_fffd);
    ctx.mempool.pool().write().insert_entry(MempoolEntry::new(
        Arc::new(original.clone()),
        4_000,
        8_000,
        0,
        1,
    ))?;

    // Search the output count (500 sat each, never dust) for a candidate
    // that pays rules 3 and 4 (fee >= 8 000 + vsize, the 1 sat/vB
    // incremental boundary) while its rate does not IMPROVE on 2 000
    // sat/kvB — exactly what rule 6 forbids.
    let (replacement, fee) = {
        let mut found = None;
        for count in 320_usize..=400 {
            let candidate = many_output_tx(confirmed_outpoint(0x9b), 500, count);
            let vsize = u64::from(u32::try_from(candidate.vsize()).unwrap_or(u32::MAX));
            let candidate_fee = 200_000 - 500 * u64::try_from(count).unwrap_or(u64::MAX);
            let rate = candidate_fee * 1_000 / vsize;
            if candidate_fee >= 8_000 + vsize && (1_000..=2_000).contains(&rate) {
                found = Some((candidate, candidate_fee));
                break;
            }
        }
        found.ok_or("no output count satisfies the rule-6 shape")?
    };
    let handler = Handler::new(Arc::clone(&ctx));
    let message = reject_message(
        &handler
            .dispatch("sendrawtransaction", &json!([raw_tx_hex(&replacement)]))
            .err()
            .ok_or("expected rule 6 rejection")?,
    );
    assert!(
        message.contains("replacement-failed"),
        "unexpected message: {message}"
    );
    let rows = handler
        .dispatch("testmempoolaccept", &json!([[raw_tx_hex(&replacement)]]))?
        .as_array()
        .ok_or("expected an array of results")?
        .clone();
    assert_eq!(
        rows.first()
            .ok_or("expected one row")?
            .get("reject-reason")
            .and_then(JsonValueTrait::as_str),
        Some("replacement-failed")
    );
    assert!(
        ctx.mempool.read().contains_txid(&rpc_txid(&original)),
        "a rejected replacement leaves the original pooled"
    );

    // Direct pool outcome: the same candidate fails check_replacement with
    // the same rule.
    let vsize = u32::try_from(replacement.vsize()).unwrap_or(u32::MAX);
    let candidate = ReplacementCandidate::new(Arc::new(replacement), vsize, fee, 1_000);
    assert_eq!(
        ctx.mempool.read().check_replacement(&candidate),
        Err(RbfError::InsufficientFeerateDiagram)
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Signal-independent replacement and retained BIP125 both-RPC coverage
// ---------------------------------------------------------------------------

/// Asserts that `sendrawtransaction` and `testmempoolaccept` agree on the
/// verdict for `tx_hex`, and that the direct pool `check_replacement` agrees
/// on the error class. Returns the preview row for further inspection.
fn assert_both_rpcs_agree_on_replacement_rejection(
    handler: &Handler,
    tx_hex: &str,
    tx: &Tx,
    expected_reason_fragment: &str,
    expected_rbf_error: RbfError,
    mempool: &Arc<MempoolGateway>,
) -> Result<sonic_rs::Value, Box<dyn Error>> {
    // sendrawtransaction must reject.
    let message = reject_message(
        &handler
            .dispatch("sendrawtransaction", &json!([tx_hex]))
            .err()
            .ok_or("expected sendrawtransaction rejection")?,
    );
    assert!(
        message.contains(expected_reason_fragment),
        "sendrawtransaction: unexpected message: {message}"
    );

    // testmempoolaccept must reject with the same class.
    let rows = handler
        .dispatch("testmempoolaccept", &json!([[tx_hex]]))?
        .as_array()
        .ok_or("expected an array of results")?
        .clone();
    let row = rows.first().ok_or("expected one row")?.clone();
    assert_eq!(
        row.get("allowed").and_then(JsonValueTrait::as_bool),
        Some(false),
        "preview must reject"
    );
    let reject_reason = row
        .get("reject-reason")
        .and_then(JsonValueTrait::as_str)
        .ok_or("expected reject-reason")?;
    assert!(
        reject_reason.contains(expected_reason_fragment),
        "testmempoolaccept: unexpected reject-reason: {reject_reason}"
    );

    // Direct pool cross-check: the exact RbfError variant must match so a
    // fee-increment fixture cannot pass on an eviction-limit rejection.
    let vsize = u32::try_from(tx.vsize()).unwrap_or(u32::MAX);
    let fee = {
        // WHY: the fee is the input value minus output value; for a
        // single-input single-output tx funded at 100 000 with output
        // 100_000 - fee, the fee is 100_000 - output_value.
        let input_value = 100_000_u64;
        let output_value = tx
            .outputs
            .iter()
            .fold(0_u64, |sum, o| sum.saturating_add(o.value.to_sat()));
        input_value.saturating_sub(output_value)
    };
    let candidate = ReplacementCandidate::new(Arc::new(tx.clone()), vsize, fee, 1_000);
    let pool = mempool.read();
    assert_eq!(
        pool.check_replacement(&candidate),
        Err(expected_rbf_error),
        "pool check_replacement must reject with the exact BIP125 rule"
    );
    Ok(row)
}

#[test]
fn nonsignaling_replacements_agree_on_both_rpcs() -> Result<(), Box<dyn Error>> {
    let ctx = Arc::new(Context::new());
    let original = insert_original(&ctx, 0xa1, 0xffff_ffff, 4_000, 8_000)?;
    let replacement = tx(confirmed_outpoint(0xa1), 90_000, 0xffff_ffff);
    let handler = Handler::new(Arc::clone(&ctx));

    let sequence = ctx.mempool.read().sequence_number();
    let rows = handler.dispatch("testmempoolaccept", &json!([[raw_tx_hex(&replacement)]]))?;
    let row = rows
        .as_array()
        .and_then(|rows| rows.first())
        .ok_or("expected preview row")?;
    assert_eq!(
        row.get("allowed").and_then(JsonValueTrait::as_bool),
        Some(true)
    );
    assert_eq!(ctx.mempool.read().sequence_number(), sequence);
    assert!(ctx.mempool.read().contains_txid(&rpc_txid(&original)));
    let result = handler.dispatch("sendrawtransaction", &json!([raw_tx_hex(&replacement)]))?;
    assert_eq!(result, json!(rpc_txid(&replacement).to_string()));
    let pool = ctx.mempool.read();
    assert!(!pool.contains_txid(&rpc_txid(&original)));
    assert!(pool.contains_txid(&rpc_txid(&replacement)));
    assert_eq!(pool.len(), 1);
    assert!(pool.sequence_number() > sequence);
    Ok(())
}

#[test]
fn bip125_rule4_replacement_must_pay_incremental_relay_fee_on_both_rpcs()
-> Result<(), Box<dyn Error>> {
    let ctx = Arc::new(Context::new());
    // Original: RBF-signaling, 4 000 vB, 8 000 sat fee.
    let _original = insert_original(&ctx, 0xa4, 0xffff_fffd, 4_000, 8_000)?;
    // Replacement spends the same outpoint, pays 8 000 sat fee (equal to
    // evicted fee) but does NOT pay the incremental relay fee on top:
    // incremental = 82 vB * 1_000 / 1_000 = 82 sat; 8_000 - 8_000 = 0 < 82.
    let replacement = tx(confirmed_outpoint(0xa4), 92_000, 0xffff_ffff);
    let handler = Handler::new(Arc::clone(&ctx));

    let _row = assert_both_rpcs_agree_on_replacement_rejection(
        &handler,
        &raw_tx_hex(&replacement),
        &replacement,
        "insufficient fee",
        RbfError::Rule4InsufficientIncrementalFee,
        &ctx.mempool,
    )?;
    Ok(())
}

#[test]
fn replacement_counts_conflicting_clusters_instead_of_descendants() -> Result<(), Box<dyn Error>> {
    let ctx = Arc::new(Context::new());
    // Raise package limits so 100 descendants can be inserted; the
    // replacement evicts 101 (original + 100 descendants) > 100.
    //
    // A 101-transaction chain is one cluster of 101, so the cluster caps must
    // be lifted alongside the ancestor/descendant caps or admission refuses
    // the fixture before the replacement rules are reached. This test is about
    // BIP125, not cluster limits.
    {
        let mut pool = ctx.mempool.pool().write();
        pool.limits.cluster_count = 400;
        pool.limits.cluster_size_vbytes = 1_000_000;
    }
    let original = insert_original(&ctx, 0xa5, 0xffff_fffd, 4_000, 8_000)?;
    let original_txid = rpc_txid(&original);
    // Chain 100 descendants from the original, each at 50 vB / 100 sat fee.
    {
        let mut pool = ctx.mempool.pool().write();
        let mut prev = OutPoint::new(original_txid, 0);
        for i in 0..100_u32 {
            let child = tx(prev, 400, 0xffff_ffff);
            prev = OutPoint::new(rpc_txid(&child), 0);
            pool.insert_entry(MempoolEntry::new(Arc::new(child), 50, 100, u64::from(i), 1))?;
        }
    }
    // Replacement spends the same confirmed outpoint, fee 20_000.
    // Evicted fee = 8_000 + 100*100 = 18_000; 20_000 > 18_000 + 82 (rule 4).
    // Eviction count = 101 > 100 (rule 5).
    let replacement = tx(confirmed_outpoint(0xa5), 80_000, 0xffff_ffff);
    let handler = Handler::new(Arc::clone(&ctx));

    let rows = handler.dispatch("testmempoolaccept", &json!([[raw_tx_hex(&replacement)]]))?;
    assert_eq!(rows[0]["allowed"].as_bool(), Some(true), "{rows:?}");
    assert_eq!(ctx.mempool.read().len(), 101);
    handler.dispatch("sendrawtransaction", &json!([raw_tx_hex(&replacement)]))?;
    assert_eq!(ctx.mempool.read().len(), 1);
    assert!(ctx.mempool.read().contains_txid(&rpc_txid(&replacement)));
    Ok(())
}

// ---------------------------------------------------------------------------
// Package limits
// ---------------------------------------------------------------------------

/// Builds a 25-tx unconfirmed chain in the pool starting from a fictional
/// confirmed root, all entries at the 1000 sat/kvB boundary.
fn chain_pool(ctx: &Context) -> Result<Vec<Tx>, Box<dyn Error>> {
    let mut pool = ctx.mempool.pool().write();
    let mut txs = Vec::new();
    let mut previous = OutPoint {
        txid: Txid(Hash256::from_le_bytes(&[0x62; 32])),
        vout: 0,
    };
    for _ in 0..25 {
        let mut next = tx(previous, 1_000, 0xffff_ffff);
        next.outputs[0].script_pubkey = Script::from_bytes(op_true_script());
        previous = OutPoint::new(next.txid(), 0);
        pool.insert_entry(MempoolEntry::new(
            Arc::new(next.clone()),
            4_000,
            4_000,
            0,
            1,
        ))?;
        txs.push(next);
    }
    Ok(txs)
}

/// Builds the 26th chain member that also spends a funded confirmed outpoint,
/// so its fee is high and its only failing gate is the ancestor limit.
fn tx_multi_child(funded: &OutPoint, tip: &Tx) -> Tx {
    Tx {
        version: 2,
        lock_time: LockTime::from_consensus(0),
        inputs: vec![
            TxIn {
                previous_output: *funded,
                script_sig: Script::new(),
                sequence: Sequence::from_consensus(0xffff_ffff),
                witness: Witness::new(),
            },
            TxIn {
                previous_output: OutPoint::new(tip.txid(), 0),
                script_sig: Script::new(),
                sequence: Sequence::from_consensus(0xffff_ffff),
                witness: Witness::new(),
            },
        ],
        outputs: vec![TxOut {
            value: Amount::from_sat(90_000),
            script_pubkey: Script::from_bytes(p2wpkh_script()),
        }],
    }
}

#[test]
fn both_rpcs_allow_more_than_25_ancestors_within_cluster_limits() -> Result<(), Box<dyn Error>> {
    let ctx = Arc::new(Context::new());
    let chain = chain_pool(&ctx)?;
    let tip = chain.last().ok_or("empty chain")?;
    let follower = tx_multi_child(&fund_utxo(&ctx, 0x64, 100_000), tip);
    let handler = Handler::new(Arc::clone(&ctx));
    let rows = handler.dispatch("testmempoolaccept", &json!([[raw_tx_hex(&follower)]]))?;
    assert_eq!(rows[0]["allowed"].as_bool(), Some(true), "{rows:?}");
    handler.dispatch("sendrawtransaction", &json!([raw_tx_hex(&follower)]))?;
    assert_eq!(ctx.mempool.read().len(), 26);
    Ok(())
}

#[test]
fn testmempoolaccept_and_sendrawtransaction_agree_on_cluster_count_limits()
-> Result<(), Box<dyn Error>> {
    // Root plus the candidate is two; a limit of one must refuse. Ancestor
    // and descendant packages are size two, so only the cluster check can
    // refuse — the contract the preview and admission must share.
    let ctx = Arc::new(Context::new());
    let root = {
        let mut pool = ctx.mempool.pool().write();
        pool.limits.cluster_count = 1;
        let root = tx(
            OutPoint {
                txid: Txid(Hash256::from_le_bytes(&[0xc1; 32])),
                vout: 0,
            },
            50_000,
            0xffff_ffff,
        );
        pool.insert_entry(MempoolEntry::new(Arc::new(root.clone()), 100, 10_000, 0, 1))?;
        root
    };
    let follower = tx_multi_child(&fund_utxo(&ctx, 0xc2, 100_000), &root);
    let handler = Handler::new(Arc::clone(&ctx));

    let rows = handler
        .dispatch("testmempoolaccept", &json!([[raw_tx_hex(&follower)]]))?
        .as_array()
        .ok_or("expected an array of results")?
        .clone();
    let row = rows.first().ok_or("expected one row")?;
    assert_eq!(
        row.get("allowed").and_then(JsonValueTrait::as_bool),
        Some(false),
        "preview must surface cluster count limits"
    );
    let reject_reason = row
        .get("reject-reason")
        .and_then(JsonValueTrait::as_str)
        .ok_or("expected reject-reason")?;
    assert!(
        reject_reason.contains("too-large-cluster"),
        "unexpected reject-reason: {reject_reason}"
    );

    let message = reject_message(
        &handler
            .dispatch("sendrawtransaction", &json!([raw_tx_hex(&follower)]))
            .err()
            .ok_or("expected admission to enforce the cluster count")?,
    );
    assert!(
        message.contains("too-large-cluster"),
        "unexpected message: {message}"
    );

    let mut pool = Mempool::new(MempoolLimits {
        cluster_count: 1,
        ..MempoolLimits::default()
    });
    pool.insert_entry(MempoolEntry::new(Arc::new(root), 100, 10_000, 0, 1))?;
    let error = pool
        .insert_entry(MempoolEntry::new(Arc::new(follower), 82, 10_000, 0, 1))
        .err()
        .ok_or("pool path must also reject")?;
    assert_eq!(
        error,
        bitcoin_rs_mempool::MempoolError::Policy(PolicyError::ClusterCountLimit)
    );
    Ok(())
}

#[test]
fn testmempoolaccept_and_sendrawtransaction_agree_on_cluster_size_limits()
-> Result<(), Box<dyn Error>> {
    let ctx = Arc::new(Context::new());
    let root = {
        let mut pool = ctx.mempool.pool().write();
        pool.limits.cluster_count = 100;
        pool.limits.cluster_size_vbytes = 250;
        let root = tx(
            OutPoint {
                txid: Txid(Hash256::from_le_bytes(&[0xc3; 32])),
                vout: 0,
            },
            50_000,
            0xffff_ffff,
        );
        pool.insert_entry(MempoolEntry::new(Arc::new(root.clone()), 200, 10_000, 0, 1))?;
        root
    };
    let follower = tx_multi_child(&fund_utxo(&ctx, 0xc4, 100_000), &root);
    let handler = Handler::new(Arc::clone(&ctx));

    let rows = handler
        .dispatch("testmempoolaccept", &json!([[raw_tx_hex(&follower)]]))?
        .as_array()
        .ok_or("expected an array of results")?
        .clone();
    let row = rows.first().ok_or("expected one row")?;
    assert_eq!(
        row.get("allowed").and_then(JsonValueTrait::as_bool),
        Some(false),
        "preview must surface cluster size limits"
    );
    let reject_reason = row
        .get("reject-reason")
        .and_then(JsonValueTrait::as_str)
        .ok_or("expected reject-reason")?;
    assert!(
        reject_reason.contains("too-large-cluster"),
        "unexpected reject-reason: {reject_reason}"
    );

    let message = reject_message(
        &handler
            .dispatch("sendrawtransaction", &json!([raw_tx_hex(&follower)]))
            .err()
            .ok_or("expected admission to enforce the cluster size")?,
    );
    assert!(
        message.contains("too-large-cluster"),
        "unexpected message: {message}"
    );
    Ok(())
}

#[test]
fn testmempoolaccept_and_sendrawtransaction_agree_on_replacement_into_a_full_cluster()
-> Result<(), Box<dyn Error>> {
    // {root, original} sits at cluster_count = 2. Replacing the original
    // leaves the cluster at two; preview and admission must both allow it.
    let ctx = Arc::new(Context::new());
    let (root, original) = {
        let mut pool = ctx.mempool.pool().write();
        pool.limits.cluster_count = 2;
        // OP_TRUE so the RPC path can spend the root without a witness.
        // P2WPKH here is what produced consensus-verification-failed.
        let root = Tx {
            outputs: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: Script::from_bytes(op_true_script()),
            }],
            ..tx(
                OutPoint {
                    txid: Txid(Hash256::from_le_bytes(&[0xc5; 32])),
                    vout: 0,
                },
                50_000,
                0xffff_ffff,
            )
        };
        let original = tx(OutPoint::new(rpc_txid(&root), 0), 40_000, 0xffff_fffd);
        pool.insert_entry(MempoolEntry::new(Arc::new(root.clone()), 100, 10_000, 0, 1))?;
        pool.insert_entry(MempoolEntry::new(
            Arc::new(original.clone()),
            100,
            10_000,
            0,
            1,
        ))?;
        (root, original)
    };
    let replacement = tx(OutPoint::new(rpc_txid(&root), 0), 30_000, 0xffff_ffff);
    let handler = Handler::new(Arc::clone(&ctx));

    let rows = handler
        .dispatch("testmempoolaccept", &json!([[raw_tx_hex(&replacement)]]))?
        .as_array()
        .ok_or("expected an array of results")?
        .clone();
    let row = rows.first().ok_or("expected one row")?;
    assert_eq!(
        row.get("allowed").and_then(JsonValueTrait::as_bool),
        Some(true),
        "preview must allow a replacement that does not grow the cluster: {row:?}"
    );

    let result = handler.dispatch("sendrawtransaction", &json!([raw_tx_hex(&replacement)]))?;
    assert_eq!(
        result.as_str().map(ToString::to_string),
        Some(rpc_txid(&replacement).to_string())
    );
    {
        let pool = ctx.mempool.read();
        assert!(
            !pool.contains_txid(&rpc_txid(&original)),
            "the replaced original must leave"
        );
        assert!(
            pool.contains_txid(&rpc_txid(&replacement)),
            "the replacement must be pooled"
        );
        assert!(
            pool.contains_txid(&rpc_txid(&root)),
            "the shared parent must remain"
        );
    }
    Ok(())
}

/// Multi-input variant of `tx`, used for replacement and fan-out shapes.
fn tx_spending(inputs: &[(OutPoint, u32)], output_value: u64) -> Tx {
    Tx {
        version: 2,
        lock_time: LockTime::from_consensus(0),
        inputs: inputs
            .iter()
            .map(|(prevout, sequence)| TxIn {
                previous_output: *prevout,
                script_sig: Script::new(),
                sequence: Sequence::from_consensus(*sequence),
                witness: Witness::new(),
            })
            .collect(),
        outputs: vec![TxOut {
            value: Amount::from_sat(output_value),
            script_pubkey: Script::from_bytes(p2wpkh_script()),
        }],
    }
}

/// One funded input and `count` identical P2WPKH outputs, used to tune a
/// replacement's real vsize against its fee (the rule-6 shape).
fn many_output_tx(prevout: OutPoint, value_each: u64, count: usize) -> Tx {
    Tx {
        version: 2,
        lock_time: LockTime::from_consensus(0),
        inputs: vec![TxIn {
            previous_output: prevout,
            script_sig: Script::new(),
            sequence: Sequence::from_consensus(0xffff_ffff),
            witness: Witness::new(),
        }],
        outputs: vec![
            TxOut {
                value: Amount::from_sat(value_each),
                script_pubkey: Script::from_bytes(p2wpkh_script()),
            };
            count
        ],
    }
}

#[test]
fn sendrawtransaction_admission_evicts_the_lowest_fee_packages_under_size_pressure()
-> Result<(), Box<dyn Error>> {
    let ctx = Arc::new(Context::new());
    let root = |label: u8| OutPoint {
        txid: Txid(Hash256::from_le_bytes(&[label; 32])),
        vout: 0,
    };
    let (high_txid, low_txid, mid_txid) = {
        let mut pool = ctx.mempool.pool().write();
        // Three independent packages at 3 000 / 1 000 / 2 000 sat/kvB.
        let high = tx(root(0x90), 1_000, 0xffff_ffff);
        let high_txid = high.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(high), 1_000, 3_000, 0, 1))?;
        let low = tx(root(0x91), 1_000, 0xffff_ffff);
        let low_txid = low.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(low), 1_000, 1_000, 0, 1))?;
        let mid = tx(root(0x92), 1_000, 0xffff_ffff);
        let mid_txid = mid.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(mid), 1_000, 2_000, 0, 1))?;
        // Shrink after filling: eviction runs only inside insert paths.
        pool.limits.max_total_bytes = 2_000;
        (high_txid, low_txid, mid_txid)
    };
    // 6 000 sat over 82 vB clears the pressure floor the eviction candidate
    // faces (cheapest evictable 1 000 + incremental 1 000 = 2 000 sat/kvB).
    let overflow = tx(fund_utxo(&ctx, 0x93, 106_000), 100_000, 0xffff_ffff);
    let handler = Handler::new(Arc::clone(&ctx));

    let result = handler.dispatch("sendrawtransaction", &json!([raw_tx_hex(&overflow)]))?;
    assert_eq!(
        result.as_str().map(ToString::to_string),
        Some(rpc_txid(&overflow).to_string())
    );

    // Post-submission membership IS the eviction order: the two lowest-rate
    // packages had to go, in rate order, before the pool fits again.
    let pool = ctx.mempool.read();
    assert!(
        pool.contains_txid(&high_txid),
        "the highest-rate package must survive"
    );
    assert!(
        !pool.contains_txid(&low_txid),
        "the lowest-rate package must evict first"
    );
    assert!(
        !pool.contains_txid(&mid_txid),
        "the mid-rate package must evict next"
    );
    assert_eq!(pool.len(), 2);
    assert!(
        pool.total_vsize() <= 2_000,
        "pool must fit the size bound again"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Cross-surface agreement
// ---------------------------------------------------------------------------

#[test]
fn testmempoolaccept_and_sendrawtransaction_agree_on_each_class() -> Result<(), Box<dyn Error>> {
    let ctx = Arc::new(Context::new());
    let good = tx(fund_utxo(&ctx, 0x70, 10_000), 9_000, 0xffff_ffff);
    let below_min = tx(fund_utxo(&ctx, 0x71, 10_000), 9_999, 0xffff_ffff);
    let nonstandard = Tx {
        outputs: vec![TxOut {
            value: Amount::from_sat(9_000),
            script_pubkey: Script::from_bytes(op_true_script()),
        }],
        ..tx(fund_utxo(&ctx, 0x72, 10_000), 9_000, 0xffff_ffff)
    };
    let dust = Tx {
        outputs: vec![TxOut {
            value: Amount::from_sat(100),
            script_pubkey: Script::from_bytes(p2wpkh_script()),
        }],
        ..tx(fund_utxo(&ctx, 0x73, 10_000), 100, 0xffff_ffff)
    };
    let txs = [&good, &below_min, &nonstandard, &dust];

    let handler = Handler::new(Arc::clone(&ctx));
    for tx in txs {
        let rows = handler.dispatch("testmempoolaccept", &json!([[raw_tx_hex(tx)]]))?;
        let preview_allowed = rows[0]["allowed"].as_bool().ok_or("row missing allowed")?;
        let submitted = handler.dispatch("sendrawtransaction", &json!([raw_tx_hex(tx)]));
        assert_eq!(submitted.is_ok(), preview_allowed, "{rows:?}");
    }
    Ok(())
}

#[test]
fn decode_failures_reject_with_deserialization_error() -> Result<(), Box<dyn Error>> {
    let ctx = Arc::new(Context::new());
    let handler = Handler::new(Arc::clone(&ctx));
    let error = handler
        .dispatch("sendrawtransaction", &json!(["zznotahexzz"]))
        .err()
        .ok_or("expected a decode rejection")?;
    // Core answers -22 (RPC_DESERIALIZATION_ERROR) for undecodable hex.
    assert_eq!(error.code(), -22);
    Ok(())
}

// ---------------------------------------------------------------------------
// Reorg reconsideration
// ---------------------------------------------------------------------------

/// Regtest seed-chain constants mirroring the node-side seed shape.
const REORG_SEED_BLOCKS: u32 = 100;
const REORG_SEED_BASE_TIME: u32 = 1_296_688_603;
const REORG_SEED_BLOCK_INTERVAL: u32 = 600;
const REORG_REGTEST_BITS: u32 = 0x207f_ffff;
const REORG_SUBSIDY_SATS: u64 = 50 * 100_000_000;
const REORG_SPEND_FEE_SATS: u64 = 10_000;

/// Routes `invalidateblock` through the production reorg path.
struct NodeInvalidator {
    handles: Arc<bitcoin_rs_chainstate::Chainstate>,
    followers: bitcoin_rs_node::ChainFollowers,
}

impl ChainControl for NodeInvalidator {
    fn invalidate_block(&self, hash: Hash256) -> core::result::Result<(), ChainControlError> {
        invalidate_block(&self.handles, &self.followers, hash)
            .map(|_| ())
            .map_err(|error| match error {
                ReorgError::UnknownBlock(_) => ChainControlError::UnknownBlock,
                ReorgError::CannotInvalidateGenesis => ChainControlError::Genesis,
                other => ChainControlError::Failed(other.to_string()),
            })
    }
}

fn open_regtest_state() -> Result<(NodeState, tempfile::TempDir), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    let state = NodeState::open(config, None)?;
    Ok((state, dir))
}

/// The one-input null-prevout coinbase outpoint (Core `COINBASE_OUTPOINT`).
fn null_prevout() -> OutPoint {
    OutPoint::new(Txid::default(), u32::MAX)
}

/// Minimal script push of a small integer, mirroring rust-bitcoin
/// `Builder::push_int`: `OP_0` for zero, `OP_N` for 1..=16, otherwise a
/// length-prefixed little-endian payload (BIP34 heights).
fn script_push_int(value: i64) -> Vec<u8> {
    match value {
        0 => vec![0x00],
        // `value` is pinned to 1..=16 by the match arm.
        1..=16 => vec![0x50 + u8::try_from(value).unwrap_or_default()],
        _ => {
            let mut payload = Vec::new();
            let mut magnitude = value.unsigned_abs();
            while magnitude > 0 {
                // Low byte only; the shift below consumes it fully.
                payload.push(u8::try_from(magnitude & 0xff).unwrap_or_default());
                magnitude >>= 8;
            }
            let mut out = Vec::with_capacity(payload.len() + 1);
            // A small-int push never exceeds 8 payload bytes.
            out.push(u8::try_from(payload.len()).unwrap_or_default());
            out.extend(payload);
            out
        }
    }
}

/// Core `IsCoinBase` shape: exactly one input spending the null prevout.
fn is_coinbase(tx: &Tx) -> bool {
    tx.inputs.len() == 1 && tx.inputs[0].previous_output == null_prevout()
}

fn reorg_seed_coinbase(height: u32) -> Tx {
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: null_prevout(),
            // BIP34 height push plus one pad byte: consensus requires a
            // 2..=100 byte coinbase scriptSig (Core bad-cb-length).
            script_sig: Script::from_bytes(
                [script_push_int(i64::from(height)), script_push_int(0)].concat(),
            ),
            sequence: Sequence::from_consensus(0xffff_ffff),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(REORG_SUBSIDY_SATS),
            script_pubkey: Script::from_bytes(vec![0x51]),
        }],
        lock_time: LockTime::from_consensus(0),
    }
}

/// The spend of the height-1 seed coinbase with a caller-chosen fee; it
/// matures exactly at height 101.
fn reorg_seed_coinbase_spend_with_fee(fee_sats: u64) -> Tx {
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(reorg_seed_coinbase(1).txid(), 0),
            script_sig: Script::new(),
            sequence: Sequence::from_consensus(0xffff_ffff),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(REORG_SUBSIDY_SATS - fee_sats),
            // A standard P2SH output: re-admission runs the same
            // standardness rules as ingress.
            script_pubkey: Script::from_bytes(
                [vec![0xa9, 0x14], vec![0x22; 20], vec![0x87]].concat(),
            ),
        }],
        lock_time: LockTime::from_consensus(0),
    }
}

fn reorg_grind_pow(block: &mut Block) -> Result<(), Box<dyn Error>> {
    loop {
        if pow_is_met(
            block.header.bits.to_consensus(),
            &block.header.compute_hash().into(),
        ) {
            return Ok(());
        }
        let Some(next) = block.header.nonce.checked_add(1) else {
            return Err("nonce exhausted while grinding block".into());
        };
        block.header.nonce = next;
    }
}

/// Returns true when the header hash, read as a little-endian integer, meets
/// the compact bits target (Core `CheckProofOfWork` shape).
fn pow_is_met(bits: u32, hash: &Hash256) -> bool {
    let exponent = usize::try_from(bits >> 24).unwrap_or(usize::MAX);
    let mantissa = bits & 0x00ff_ffff;
    if mantissa == 0 || mantissa & 0x0080_0000 != 0 || exponent > 32 {
        return false;
    }
    let shift = exponent.saturating_sub(3);
    // Little-endian target bytes: mantissa placed `shift` bytes from the
    // least-significant end (mantissa is masked below 2^24, so three bytes).
    let mantissa_le = mantissa.to_le_bytes();
    let mut target = [0_u8; 32];
    for (offset, byte) in mantissa_le.iter().take(3).enumerate() {
        let position = shift + offset;
        if position < 32 {
            target[position] = *byte;
        }
    }
    // Both sides are little-endian 32-byte integers: compare from the most
    // significant byte downward (Core `CheckProofOfWork`).
    let hash_le = hash.to_le_bytes();
    for index in (0..32).rev() {
        match hash_le[index].cmp(&target[index]) {
            std::cmp::Ordering::Less => return true,
            std::cmp::Ordering::Greater => return false,
            std::cmp::Ordering::Equal => {}
        }
    }
    true
}

/// Native BIP141-style txid merkle fold with the odd-leaf duplication rule.
fn compute_merkle_root(txs: &[Tx]) -> Option<Hash256> {
    if txs.is_empty() {
        return None;
    }
    let mut level: Vec<[u8; 32]> = txs.iter().map(|tx| *tx.txid().as_bytes()).collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pos in 0..level.len().div_ceil(2) {
            let left = level[2 * pos];
            let right = level[(2 * pos + 1).min(level.len() - 1)];
            let mut pair = [0_u8; 64];
            pair[..32].copy_from_slice(&left);
            pair[32..].copy_from_slice(&right);
            next.push(*double_sha256(&pair).as_byte_array());
        }
        level = next;
    }
    Some(Hash256::from_le_bytes(&level[0]))
}

/// Mines and applies the regtest block at `height` over `prev`: the seed
/// coinbase plus `txs`, through ordinary validation.
fn reorg_mine_and_apply(
    state: &NodeState,
    prev: Hash256,
    height: u32,
    txs: Vec<Tx>,
) -> Result<Block, Box<dyn Error>> {
    let mut block = Block {
        header: bitcoin_rs_primitives::Header {
            version: 0x2000_0000,
            prev_blockhash: bitcoin_rs_primitives::BlockHash::from(prev),
            merkle_root: Hash256::from_le_bytes(&[0_u8; 32]),
            time: REORG_SEED_BASE_TIME
                .saturating_add(REORG_SEED_BLOCK_INTERVAL.saturating_mul(height)),
            bits: CompactTarget::from_consensus(REORG_REGTEST_BITS),
            nonce: 0,
        },
        txs: std::iter::once(reorg_seed_coinbase(height))
            .chain(txs)
            .collect(),
    };
    block.header.merkle_root =
        compute_merkle_root(&block.txs).ok_or("mined block must have a merkle root")?;
    reorg_grind_pow(&mut block)?;
    state.apply_block(&block)?;
    Ok(block)
}

fn applied_tip_pair(state: &NodeState) -> Result<(Hash256, u32), Box<dyn Error>> {
    let applied = state.chainstate().applied_tip_handle();
    let Some(tip) = applied.load_full() else {
        return Err("applied tip must exist".into());
    };
    Ok((tip.hash, tip.height))
}

fn invalidation_handler(state: &NodeState) -> Handler {
    let chainstate = state.chainstate();
    let ibd = Arc::new(bitcoin_rs_chain::InitialBlockDownload::new(
        bitcoin_rs_chain::TipReader::new(chainstate.applied_tip_handle()),
        bitcoin_rs_chain::BlockTreeReader::new(chainstate.block_tree_handle()),
    ));
    Handler::new(Arc::new(
        Context::from_handles(ContextHandles {
            chain: ChainHandles::new(
                chainstate.chain_tip_handle(),
                chainstate.applied_tip_handle(),
                state.blocks(),
                state.transactions(),
                chainstate.utxo_handle(),
                chainstate.coin_stats_handle(),
                chainstate.block_tree_handle(),
                Network::Regtest,
                ibd,
            ),
            mempool: MempoolHandles {
                mempool: MempoolGateway::shared(state.mempool()),
            },
            indexes: IndexHandles {
                derived_index: None,
                esplora_tx_index: None,
                script_index: None,
                derived_index_status: None,
            },
            network: NetworkHandles {
                network: state.network(),
                network_active: state.network_active(),
                peer_table: state.peer_table(),
                p2p_outbound_sender: Some(state.p2p_outbound_sender()),
                banned: state.banned_subnets(),
                added_nodes: Arc::new(parking_lot::RwLock::new(Vec::new())),
            },
            mining: MiningHandles {
                mining_control: None,
            },
        })
        .with_chain_control(Arc::new(NodeInvalidator {
            handles: chainstate,
            followers: state.chain_followers(),
        })),
    ))
}

#[test]
fn invalidateblock_returns_a_mature_coinbase_spend_to_the_mempool_and_excludes_the_coinbase()
-> Result<(), Box<dyn Error>> {
    let (state, _dir) = open_regtest_state()?;
    let genesis = Network::Regtest.genesis_block();
    state.apply_block(&genesis)?;
    for height in 1..=REORG_SEED_BLOCKS {
        let (prev, _) = applied_tip_pair(&state)?;
        reorg_mine_and_apply(&state, prev, height, Vec::new())?;
    }
    let (seed_tip, seed_height) = applied_tip_pair(&state)?;
    assert_eq!(seed_height, REORG_SEED_BLOCKS);

    // The matured spend enters the mempool, then a block at height 101
    // confirms it and drains the pool.
    let spend = reorg_seed_coinbase_spend_with_fee(REORG_SPEND_FEE_SATS);
    let spend_txid = spend.txid();
    {
        let mempool = state.mempool();
        let mut guard = mempool.write();
        let vsize = u32::try_from(spend.vsize()).unwrap_or(u32::MAX);
        guard.insert_entry(MempoolEntry::new(
            Arc::new(spend.clone()),
            vsize,
            REORG_SPEND_FEE_SATS,
            1,
            REORG_SEED_BLOCKS,
        ))?;
    }
    let mined_block = reorg_mine_and_apply(&state, seed_tip, REORG_SEED_BLOCKS + 1, vec![spend])?;
    assert!(
        state.mempool().read().is_empty(),
        "connect must drain the confirmed spend"
    );

    let handler = invalidation_handler(&state);
    let mined_hash = mined_block.block_hash();
    handler.dispatch("invalidateblock", &json!([mined_hash.to_string()]))?;

    let (tip, tip_height) = applied_tip_pair(&state)?;
    assert_eq!(
        tip_height, REORG_SEED_BLOCKS,
        "the mined block must roll back"
    );
    assert_eq!(tip, seed_tip, "the seed tip must become active again");

    let raw = handler.dispatch("getrawmempool", &json!([]))?;
    let entries = raw.as_array().ok_or("getrawmempool must answer an array")?;
    let txids: Vec<&str> = entries.iter().filter_map(|value| value.as_str()).collect();
    assert_eq!(
        txids,
        vec![spend_txid.to_string()],
        "the matured spend returns and the coinbase never does"
    );

    // Pool-path agreement: the same structural filter over a bare gateway
    // admits the spend once and keeps the coinbase out.
    let gateway = MempoolGateway::shared(Arc::new(parking_lot::RwLock::new(Mempool::new(
        MempoolLimits::default(),
    ))));
    let chainstate = state.chainstate();
    let chain = bitcoin_rs_rpc::context::ChainAdmissionView::new(
        chainstate.utxo_handle(),
        chainstate.applied_tip_reader(),
        chainstate.block_tree_reader(),
        chainstate.network(),
    );
    let change = gateway.begin_chain_change()?;
    let committed = gateway.reconsider_disconnected(
        &change,
        &chain,
        1,
        mined_block
            .txs
            .iter()
            .filter(|tx| !is_coinbase(tx))
            .map(|tx| Arc::new(tx.clone())),
    );
    assert_eq!(committed.len(), 1, "one admitted candidate: the spend");
    change.finish()?;
    assert!(gateway.read().contains_txid(&spend_txid));
    Ok(())
}

// ---------------------------------------------------------------------------
// BIP68 sequence locks and coinbase maturity at admission (policy §3)
// ---------------------------------------------------------------------------

/// Commits one funded coinbase UTXO created at `height` and returns the
/// RPC-side outpoint that spends it.
fn fund_coinbase_utxo(ctx: &Context, label: u8, value: u64, height: u32) -> OutPoint {
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(
        OutPoint::new(Txid(Hash256::from_le_bytes(&[label; 32])), 0),
        TxOut {
            value: Amount::from_sat(value),
            script_pubkey: Script::from_bytes(op_true_script()),
        },
        true,
        height,
    ));
    bitcoin_rs_utxo::contract::commit_block_changes(
        &ctx.chain.utxo,
        &changes,
        &Hash256::from_le_bytes(&[0xaa; 32]),
    )
    .unwrap_or_else(|error| panic!("commit_block failed: {error}"));
    OutPoint {
        txid: Txid(Hash256::from_le_bytes(&[label; 32])),
        vout: 0,
    }
}

#[test]
fn immature_coinbase_spends_reject_on_both_rpcs_and_admit_at_maturity() -> Result<(), Box<dyn Error>>
{
    let ctx = Arc::new(Context::new());
    let coinbase = fund_coinbase_utxo(&ctx, 0x70, 10_000, 20);
    let spend = tx(coinbase, 9_000, 0xffff_ffff);
    let handler = Handler::new(Arc::clone(&ctx));

    // Depth 99: `sendrawtransaction` refuses with the consensus class and
    // the pool stays empty.
    let message = reject_message(
        &handler
            .dispatch("sendrawtransaction", &json!([raw_tx_hex(&spend)]))
            .err()
            .ok_or("expected immature coinbase rejection")?,
    );
    assert!(
        message.contains("consensus-verification-failed"),
        "unexpected rejection message: {message}"
    );
    assert!(
        !ctx.mempool.read().contains_txid(&rpc_txid(&spend)),
        "rejected spend must not enter the pool"
    );

    // `testmempoolaccept` quotes the shared consensus class for the row.
    let rows = handler
        .dispatch("testmempoolaccept", &json!([[raw_tx_hex(&spend)]]))?
        .as_array()
        .ok_or("expected an array of results")?
        .clone();
    assert_eq!(rows.len(), 1, "one row per submitted tx");
    assert_eq!(
        rows[0].get("allowed").and_then(JsonValueTrait::as_bool),
        Some(false)
    );
    assert_eq!(
        rows[0]
            .get("reject-reason")
            .and_then(JsonValueTrait::as_str),
        Some("script-verify-flag-failed")
    );

    // At depth 100 the same spend admits through the same outlet.
    ctx.chain.set_applied_tip(TipSnapshot {
        tip_id: NodeId::new(0),
        height: 119,
        chainwork: ChainWork::ZERO,
        hash: Hash256::from_le_bytes(&[0x71; 32]),
        chain_tx_count: bitcoin_rs_chain::ChainTxCount::UNKNOWN,
    });
    handler.dispatch("sendrawtransaction", &json!([raw_tx_hex(&spend)]))?;
    assert!(
        ctx.mempool.read().contains_txid(&rpc_txid(&spend)),
        "mature spend must commit to the pool"
    );
    Ok(())
}

#[test]
fn bip68_locked_tx_admits_while_csv_is_inactive_on_the_rpc_surface() -> Result<(), Box<dyn Error>> {
    let ctx = Arc::new(Context::new());
    let prevout = fund_utxo(&ctx, 0x72, 10_000);
    // The coin is one confirmation old with a relative lock of 5: under an
    // active CSV this transaction is non-BIP68-final. This context has no
    // CSV deployment state, so the admission producer reports csv_active
    // false and the gate stays inert — the mempool-surface fixtures pin the
    // enforced side of the same gate.
    let locked = tx(prevout, 9_000, 5);
    let handler = Handler::new(Arc::clone(&ctx));
    let rows = handler
        .dispatch("testmempoolaccept", &json!([[raw_tx_hex(&locked)]]))?
        .as_array()
        .ok_or("expected an array of results")?
        .clone();
    assert_eq!(rows.len(), 1, "one row per submitted tx");
    assert_eq!(
        rows[0].get("allowed").and_then(JsonValueTrait::as_bool),
        Some(true)
    );
    assert_eq!(
        rows[0]
            .get("reject-reason")
            .and_then(JsonValueTrait::as_str),
        None
    );
    Ok(())
}
