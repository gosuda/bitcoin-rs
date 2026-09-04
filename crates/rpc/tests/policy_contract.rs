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
use std::error::Error;

use bitcoin_rs_mempool::eviction::mempool_min_fee_sat_per_kvb;
use bitcoin_rs_mempool::{
    AdmissionOrigin, Mempool, MempoolEntry, MempoolGateway, MempoolLimits, MempoolObserver,
    MutationEnvelope, MutationOutcome, PolicyError, RbfError, RemovalReason, ReplacementCandidate,
};
use bitcoin_rs_node::reorg::{ReorgError, invalidate_block};
use bitcoin_rs_node::{Network, NodeConfig, state::NodeState};
use bitcoin_rs_primitives::encode::double_sha256;
use bitcoin_rs_primitives::{Block, Hash256, OutPoint, Tx, TxIn, TxOut, Txid, consensus_bytes};
use bitcoin_rs_rpc::context::{
    ChainControl, ChainControlError, ChainHandles, Context, ContextHandles, IndexHandles,
    MempoolHandles, MiningHandles, NetworkHandles,
};
use bitcoin_rs_rpc::{Handler, RpcError};
use bitcoin_rs_utxo::{BlockChanges, UtxoAdd};
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait, json};

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
        lock_time: 0,
        inputs: vec![TxIn {
            previous_output: prevout,
            script_sig: Vec::new(),
            sequence,
            witness: Vec::new(),
        }],
        outputs: vec![TxOut {
            value: output_value,
            script_pubkey: p2wpkh_script(),
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
            value,
            script_pubkey: op_true_script(),
        },
        false,
        1,
    ));
    ctx.utxo
        .commit_block(&changes, &Hash256::from_le_bytes(&[0xaa; 32]))
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
        message.contains("min-relay-fee-not-met"),
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
        plain.mempool.read().contains_txid(&rpc_txid(&ordinary)),
        "an ordinary between-the-guards tx must admit"
    );

    // Both predicates at once: a configured floor (0.20 BTC/kvB) ABOVE the
    // default client maxfeerate (0.10 BTC/kvB) makes the same 15 000 sat/kvB
    // tx below the floor AND above maxfeerate. The floor class wins on both
    // outlets — the order Core 31.1 uses (admission failure first, then the
    // fee cap).
    let strict = Arc::new(Context::new());
    strict
        .mempool
        .pool()
        .write()
        .limits
        .min_relay_fee_sat_per_kvb = 20_000_000;
    let both = funded_fee_tx(&strict, 0x81, 1_230);
    let handler = Handler::new(Arc::clone(&strict));
    let message = reject_message(
        &handler
            .dispatch("sendrawtransaction", &json!([raw_tx_hex(&both)]))
            .err()
            .ok_or("expected the floor to reject the both-predicates tx")?,
    );
    assert!(
        message.contains("min-relay-fee-not-met"),
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
        Some("min-relay-fee-not-met"),
        "testmempoolaccept must report the floor class, not max-fee"
    );
    assert!(
        !strict.mempool.read().contains_txid(&rpc_txid(&both)),
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
        message.contains("min-relay-fee-not-met"),
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
        Some("min-relay-fee-not-met")
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
        message.contains("min-relay-fee-not-met"),
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
        Some("min-relay-fee-not-met")
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
fn testmempoolaccept_reports_a_policy_verdict_per_row() -> Result<(), Box<dyn Error>> {
    let ctx = Arc::new(Context::new());
    let funded = fund_utxo(&ctx, 0x51, 10_000);
    let good = tx(funded, 9_000, 0xffff_ffff);
    let below_min = tx(fund_utxo(&ctx, 0x52, 10_000), 9_999, 0xffff_ffff);
    let nonstandard = Tx {
        outputs: vec![TxOut {
            value: 9_000,
            script_pubkey: op_true_script(),
        }],
        ..tx(fund_utxo(&ctx, 0x53, 10_000), 9_000, 0xffff_ffff)
    };
    let dust = Tx {
        outputs: vec![TxOut {
            value: 100,
            script_pubkey: p2wpkh_script(),
        }],
        ..tx(fund_utxo(&ctx, 0x54, 10_000), 100, 0xffff_ffff)
    };
    // Core 31 accepts v3 under TRUC; bitcoin-rs rejects it at the version
    // gate (deviation ledger, item 5).
    let version_three = Tx {
        version: 3,
        ..tx(fund_utxo(&ctx, 0x5a, 10_000), 9_000, 0xffff_ffff)
    };

    let handler = Handler::new(Arc::clone(&ctx));
    let rows = handler
        .dispatch(
            "testmempoolaccept",
            &json!([[
                raw_tx_hex(&good),
                raw_tx_hex(&below_min),
                raw_tx_hex(&nonstandard),
                raw_tx_hex(&dust),
                raw_tx_hex(&version_three),
            ]]),
        )?
        .as_array()
        .ok_or("expected an array of results")?
        .clone();

    let allowed = |row: &sonic_rs::Value| row.get("allowed").and_then(JsonValueTrait::as_bool);
    let reason = |row: &sonic_rs::Value| {
        row.get("reject-reason")
            .and_then(JsonValueTrait::as_str)
            .map(ToString::to_string)
    };

    assert_eq!(rows.len(), 5, "one row per submitted tx");
    assert_eq!(allowed(&rows[0]), Some(true));
    assert_eq!(reason(&rows[0]), None);
    // The typed wire contract serializes amounts as JSON numbers; parity is
    // value parity (1000 sat == 0.00001 BTC), not decimal spelling.
    let base = rows[0]
        .get("fees")
        .and_then(|fees| fees.get("base"))
        .and_then(JsonValueTrait::as_f64)
        .ok_or("accepted row must quote its base fee")?;
    assert!((base - 0.00001).abs() < 1e-12);
    assert_eq!(reason(&rows[1]).as_deref(), Some("min-relay-fee-not-met"));
    assert_eq!(
        reason(&rows[2]).as_deref(),
        Some("non-standard output script")
    );
    assert_eq!(reason(&rows[3]).as_deref(), Some("dust output"));
    assert_eq!(
        reason(&rows[4]).as_deref(),
        Some("non-standard transaction version")
    );
    for row in &rows {
        let txid = row
            .get("txid")
            .and_then(JsonValueTrait::as_str)
            .ok_or("row missing txid")?;
        assert_eq!(txid.len(), 64, "txid renders as 64 hex characters");
    }

    // Dry run: nothing may enter the pool.
    assert_eq!(
        ctx.mempool.read().len(),
        0,
        "testmempoolaccept is a dry run"
    );
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
            value: 1_000,
            script_pubkey: p2wpkh_script(),
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
            value: 9_000,
            script_pubkey: op_true_script(),
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
fn sendrawtransaction_rejects_nonsignaling_replacements_with_rule1() -> Result<(), Box<dyn Error>> {
    let ctx = Arc::new(Context::new());
    let original = insert_original(&ctx, 0x61, 0xffff_ffff, 4_000, 8_000)?;
    let replacement = tx(confirmed_outpoint(0x61), 90_000, 0xffff_ffff);
    let handler = Handler::new(Arc::clone(&ctx));

    let message = reject_message(
        &handler
            .dispatch("sendrawtransaction", &json!([raw_tx_hex(&replacement)]))
            .err()
            .ok_or("expected rule 1 rejection")?,
    );
    assert!(
        message.contains("BIP125 rule 1"),
        "unexpected message: {message}"
    );
    assert!(
        ctx.mempool.read().contains_txid(&rpc_txid(&original)),
        "a rejected replacement leaves the originals pooled"
    );
    Ok(())
}

#[test]
fn sendrawtransaction_rejects_rule2_replacements_adding_unconfirmed_inputs()
-> Result<(), Box<dyn Error>> {
    let ctx = Arc::new(Context::new());
    let original = insert_original(&ctx, 0x98, 0xffff_fffd, 4_000, 8_000)?;
    // An unrelated pooled tx whose output the replacement would add.
    let unrelated = tx(fund_utxo(&ctx, 0x99, 10_000), 9_000, 0xffff_ffff);
    let handler = Handler::new(Arc::clone(&ctx));
    handler.dispatch("sendrawtransaction", &json!([raw_tx_hex(&unrelated)]))?;

    // Inputs 100 000 + 9 000 - 100 000 = 9 000 sat over ~150 vB: clears the
    // floor and every other gate; only rule 2 can reject it.
    let replacement = tx_spending(
        &[
            (confirmed_outpoint(0x98), 0xffff_ffff),
            (OutPoint::new(rpc_txid(&unrelated), 0), 0xffff_ffff),
        ],
        100_000,
    );
    let message = reject_message(
        &handler
            .dispatch("sendrawtransaction", &json!([raw_tx_hex(&replacement)]))
            .err()
            .ok_or("expected rule 2 rejection")?,
    );
    assert!(
        message.contains("BIP125 rule 2"),
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
        Some("BIP125 rule 2: replacement adds a new unconfirmed input")
    );
    // A rejected replacement leaves both originals pooled.
    let pool = ctx.mempool.read();
    assert!(pool.contains_txid(&rpc_txid(&original)));
    assert!(pool.contains_txid(&rpc_txid(&unrelated)));

    // Direct pool outcome: the same candidate fails check_replacement with
    // the same rule.
    let vsize = u32::try_from(replacement.vsize()).unwrap_or(u32::MAX);
    let candidate = ReplacementCandidate::new(Arc::new(replacement), vsize, 9_000, 1_000);
    assert_eq!(
        pool.check_replacement(&candidate),
        Err(RbfError::Rule2NewUnconfirmedInput)
    );
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
        message.contains("BIP125 rule 3"),
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
        Some("BIP125 rule 3: replacement fee does not pay evicted fees")
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
fn sendrawtransaction_rejects_rule6_replacements_that_do_not_improve_the_rate()
-> Result<(), Box<dyn Error>> {
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
        message.contains("BIP125 rule 6"),
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
        Some("BIP125 rule 6: replacement fee rate is not higher than originals")
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
        Err(RbfError::Rule6InsufficientFeeRate)
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// BIP125 both-RPC coverage (rules 1, 4, 5)
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
    // rule-1 fixture cannot pass on a rule-6 rejection.
    let vsize = u32::try_from(tx.vsize()).unwrap_or(u32::MAX);
    let fee = {
        // WHY: the fee is the input value minus output value; for a
        // single-input single-output tx funded at 100 000 with output
        // 100_000 - fee, the fee is 100_000 - output_value.
        let input_value = 100_000_u64;
        let output_value = tx
            .outputs
            .iter()
            .fold(0_u64, |sum, o| sum.saturating_add(o.value));
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
fn bip125_rule1_nonsignaling_originals_reject_on_both_rpcs() -> Result<(), Box<dyn Error>> {
    let ctx = Arc::new(Context::new());
    let original = insert_original(&ctx, 0xa1, 0xffff_ffff, 4_000, 8_000)?;
    let replacement = tx(confirmed_outpoint(0xa1), 90_000, 0xffff_ffff);
    let handler = Handler::new(Arc::clone(&ctx));

    let _row = assert_both_rpcs_agree_on_replacement_rejection(
        &handler,
        &raw_tx_hex(&replacement),
        &replacement,
        "BIP125 rule 1",
        RbfError::Rule1NoOptIn,
        &ctx.mempool,
    )?;

    // A rejected replacement leaves the original pooled.
    assert!(ctx.mempool.read().contains_txid(&rpc_txid(&original)));
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
        "BIP125 rule 4",
        RbfError::Rule4InsufficientIncrementalFee,
        &ctx.mempool,
    )?;
    Ok(())
}

#[test]
fn bip125_rule5_too_many_evicted_descendants_reject_on_both_rpcs() -> Result<(), Box<dyn Error>> {
    let ctx = Arc::new(Context::new());
    // Raise package limits so 100 descendants can be inserted; the
    // replacement evicts 101 (original + 100 descendants) > 100.
    {
        let mut pool = ctx.mempool.pool().write();
        pool.limits.max_ancestors = 200;
        pool.limits.max_descendants = 200;
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

    let _row = assert_both_rpcs_agree_on_replacement_rejection(
        &handler,
        &raw_tx_hex(&replacement),
        &replacement,
        "BIP125 rule 5",
        RbfError::Rule5TooManyEvictions,
        &ctx.mempool,
    )?;
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
        let next = tx(previous, 1_000, 0xffff_ffff);
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

#[test]
fn sendrawtransaction_enforces_ancestor_count_limits_at_admission() -> Result<(), Box<dyn Error>> {
    let ctx = Arc::new(Context::new());
    let chain = chain_pool(&ctx)?;
    // The 26th descendant funds itself richly enough to pass every other
    // policy gate: only the package limit may reject it.
    let tip = chain.last().ok_or("empty chain")?;
    let follower = {
        let funded = fund_utxo(&ctx, 0x63, 100_000);
        tx_multi_child(&funded, tip)
    };
    let handler = Handler::new(Arc::clone(&ctx));

    let message = reject_message(
        &handler
            .dispatch("sendrawtransaction", &json!([raw_tx_hex(&follower)]))
            .err()
            .ok_or("expected TooManyAncestors rejection")?,
    );
    assert!(
        message.contains("too many unconfirmed ancestors"),
        "unexpected message: {message}"
    );

    // Pool-path agreement: the gate lives in the pool's insert path.
    let mut pool = Mempool::new(MempoolLimits::default());
    let mut previous = OutPoint {
        txid: Txid(Hash256::from_le_bytes(&[0x62; 32])),
        vout: 0,
    };
    for _ in 0..25 {
        let next = tx(previous, 1_000, 0xffff_ffff);
        previous = OutPoint::new(next.txid(), 0);
        pool.insert_entry(MempoolEntry::new(Arc::new(next), 4_000, 4_000, 0, 1))?;
    }
    let error = pool
        .insert_entry(MempoolEntry::new(
            Arc::new(tx(previous, 1_000, 0xffff_ffff)),
            82,
            10_000,
            0,
            1,
        ))
        .err()
        .ok_or("pool path must also reject")?;
    assert!(matches!(
        error,
        bitcoin_rs_mempool::MempoolError::Policy(PolicyError::TooManyAncestors)
    ));
    Ok(())
}

/// Builds the 26th chain member that also spends a funded confirmed outpoint,
/// so its fee is high and its only failing gate is the ancestor limit.
fn tx_multi_child(funded: &OutPoint, tip: &Tx) -> Tx {
    Tx {
        version: 2,
        lock_time: 0,
        inputs: vec![
            TxIn {
                previous_output: *funded,
                script_sig: Vec::new(),
                sequence: 0xffff_ffff,
                witness: Vec::new(),
            },
            TxIn {
                previous_output: OutPoint::new(tip.txid(), 0),
                script_sig: Vec::new(),
                sequence: 0xffff_ffff,
                witness: Vec::new(),
            },
        ],
        outputs: vec![TxOut {
            value: 90_000,
            script_pubkey: p2wpkh_script(),
        }],
    }
}

#[test]
fn testmempoolaccept_and_sendrawtransaction_agree_on_ancestor_count_limits()
-> Result<(), Box<dyn Error>> {
    // The preview and the admission gate must quote the same verdict for
    // ancestor count limits. Core's testmempoolaccept enforces package
    // limits up front; so must the preview.
    let ctx = Arc::new(Context::new());
    let chain = chain_pool(&ctx)?;
    let tip = chain.last().ok_or("empty chain")?;
    let follower = tx_multi_child(&fund_utxo(&ctx, 0x64, 100_000), tip);
    let handler = Handler::new(Arc::clone(&ctx));

    // Preview must reject — the 26th unconfirmed ancestor exceeds the limit.
    let rows = handler
        .dispatch("testmempoolaccept", &json!([[raw_tx_hex(&follower)]]))?
        .as_array()
        .ok_or("expected an array of results")?
        .clone();
    let row = rows.first().ok_or("expected one row")?;
    assert_eq!(
        row.get("allowed").and_then(JsonValueTrait::as_bool),
        Some(false),
        "preview must surface ancestor count limits"
    );
    let reject_reason = row
        .get("reject-reason")
        .and_then(JsonValueTrait::as_str)
        .ok_or("expected reject-reason")?;
    assert!(
        reject_reason.contains("too many unconfirmed ancestors"),
        "unexpected reject-reason: {reject_reason}"
    );

    // Admission must reject with the same class.
    let message = reject_message(
        &handler
            .dispatch("sendrawtransaction", &json!([raw_tx_hex(&follower)]))
            .err()
            .ok_or("expected admission to enforce the limit")?,
    );
    assert!(message.contains("too many unconfirmed ancestors"));

    // Pool-path agreement: the direct insert gate rejects the same package.
    let mut pool = Mempool::new(MempoolLimits::default());
    let mut previous = OutPoint {
        txid: Txid(Hash256::from_le_bytes(&[0x93; 32])),
        vout: 0,
    };
    for _ in 0..25 {
        let next = tx(previous, 1_000, 0xffff_ffff);
        previous = OutPoint::new(next.txid(), 0);
        pool.insert_entry(MempoolEntry::new(Arc::new(next), 4_000, 4_000, 0, 1))?;
    }
    let error = pool
        .insert_entry(MempoolEntry::new(
            Arc::new(tx(previous, 1_000, 0xffff_ffff)),
            4_000,
            4_000,
            0,
            1,
        ))
        .err()
        .ok_or("pool path must also reject")?;
    assert_eq!(
        error,
        bitcoin_rs_mempool::MempoolError::Policy(PolicyError::TooManyAncestors)
    );
    Ok(())
}

/// Multi-input variant of `tx`, used for replacement and fan-out shapes.
fn tx_spending(inputs: &[(OutPoint, u32)], output_value: u64) -> Tx {
    Tx {
        version: 2,
        lock_time: 0,
        inputs: inputs
            .iter()
            .map(|(prevout, sequence)| TxIn {
                previous_output: *prevout,
                script_sig: Vec::new(),
                sequence: *sequence,
                witness: Vec::new(),
            })
            .collect(),
        outputs: vec![TxOut {
            value: output_value,
            script_pubkey: p2wpkh_script(),
        }],
    }
}

/// Multi-output variant of `tx`, used for the descendant-count parent.
fn tx_outputs(prevout: OutPoint, sequence: u32, values: &[u64]) -> Tx {
    Tx {
        version: 2,
        lock_time: 0,
        inputs: vec![TxIn {
            previous_output: prevout,
            script_sig: Vec::new(),
            sequence,
            witness: Vec::new(),
        }],
        outputs: values
            .iter()
            .map(|value| TxOut {
                value: *value,
                script_pubkey: p2wpkh_script(),
            })
            .collect(),
    }
}

/// One funded input and `count` identical P2WPKH outputs, used to tune a
/// replacement's real vsize against its fee (the rule-6 shape).
fn many_output_tx(prevout: OutPoint, value_each: u64, count: usize) -> Tx {
    Tx {
        version: 2,
        lock_time: 0,
        inputs: vec![TxIn {
            previous_output: prevout,
            script_sig: Vec::new(),
            sequence: 0xffff_ffff,
            witness: Vec::new(),
        }],
        outputs: vec![
            TxOut {
                value: value_each,
                script_pubkey: p2wpkh_script(),
            };
            count
        ],
    }
}

#[test]
fn sendrawtransaction_enforces_ancestor_size_limits_at_admission() -> Result<(), Box<dyn Error>> {
    let ctx = Arc::new(Context::new());
    // Shrink -limitancestorsize so a 3 x 4 000 vB chain leaves the follower's
    // real 82 vB as the only gate that can fail: 12 000 + 82 > 12 000.
    ctx.mempool.pool().write().limits.max_ancestor_size = 12_000;
    let tip = {
        let mut pool = ctx.mempool.pool().write();
        let mut previous = OutPoint {
            txid: Txid(Hash256::from_le_bytes(&[0x94; 32])),
            vout: 0,
        };
        let mut tip = None;
        for _ in 0..3 {
            let next = tx(previous, 1_000, 0xffff_ffff);
            previous = OutPoint::new(next.txid(), 0);
            pool.insert_entry(MempoolEntry::new(
                Arc::new(next.clone()),
                4_000,
                4_000,
                0,
                1,
            ))?;
            tip = Some(next);
        }
        tip.ok_or("empty chain")?
    };
    let follower = tx_multi_child(&fund_utxo(&ctx, 0x95, 100_000), &tip);
    let handler = Handler::new(Arc::clone(&ctx));

    // Preview must reject — ancestor size 12 000 + 82 > 12 000.
    let rows = handler
        .dispatch("testmempoolaccept", &json!([[raw_tx_hex(&follower)]]))?
        .as_array()
        .ok_or("expected an array of results")?
        .clone();
    let row = rows.first().ok_or("expected one row")?;
    assert_eq!(
        row.get("allowed").and_then(JsonValueTrait::as_bool),
        Some(false),
        "preview must surface ancestor size limits"
    );
    let reject_reason = row
        .get("reject-reason")
        .and_then(JsonValueTrait::as_str)
        .ok_or("expected reject-reason")?;
    assert!(
        reject_reason.contains("ancestor package is too large"),
        "unexpected reject-reason: {reject_reason}"
    );

    let message = reject_message(
        &handler
            .dispatch("sendrawtransaction", &json!([raw_tx_hex(&follower)]))
            .err()
            .ok_or("expected AncestorSizeLimit rejection")?,
    );
    assert!(
        message.contains("ancestor package is too large"),
        "unexpected message: {message}"
    );
    assert!(
        !ctx.mempool.read().contains_txid(&rpc_txid(&follower)),
        "rejected tx must not enter the pool"
    );

    // Pool-path agreement: the direct insert gate rejects the same package.
    let mut pool = Mempool::new(MempoolLimits {
        max_ancestor_size: 12_000,
        ..MempoolLimits::default()
    });
    let mut previous = OutPoint {
        txid: Txid(Hash256::from_le_bytes(&[0x94; 32])),
        vout: 0,
    };
    for _ in 0..3 {
        let next = tx(previous, 1_000, 0xffff_ffff);
        previous = OutPoint::new(next.txid(), 0);
        pool.insert_entry(MempoolEntry::new(Arc::new(next), 4_000, 4_000, 0, 1))?;
    }
    let error = pool
        .insert_entry(MempoolEntry::new(
            Arc::new(tx(previous, 1_000, 0xffff_ffff)),
            4_000,
            4_000,
            0,
            1,
        ))
        .err()
        .ok_or("pool path must also reject")?;
    assert_eq!(
        error,
        bitcoin_rs_mempool::MempoolError::Policy(PolicyError::AncestorSizeLimit)
    );
    Ok(())
}

#[test]
fn sendrawtransaction_enforces_descendant_count_limits_at_admission() -> Result<(), Box<dyn Error>>
{
    let ctx = Arc::new(Context::new());
    // Parent with two outputs: out 0 fans out to the 24 in-pool children
    // that fill the parent's descendant budget, out 1 is the RPC child's
    // non-conflicting entry point.
    let parent_txid = {
        let mut pool = ctx.mempool.pool().write();
        let parent = tx_outputs(
            OutPoint {
                txid: Txid(Hash256::from_le_bytes(&[0x96; 32])),
                vout: 0,
            },
            0xffff_ffff,
            &[1_000, 2_000],
        );
        let parent_txid = rpc_txid(&parent);
        pool.insert_entry(MempoolEntry::new(Arc::new(parent), 4_000, 4_000, 0, 1))?;
        let parent_out = OutPoint::new(parent_txid, 0);
        for value in 1_000_u64..1_024 {
            let child = tx(parent_out, value, 0xffff_ffff);
            pool.insert_entry(MempoolEntry::new(Arc::new(child), 4_000, 4_000, 0, 1))?;
        }
        parent_txid
    };
    // Inputs 2 000 + 100 000 - 91 000 = 11 000 sat over ~150 vB: clears
    // every other gate; only the parent's descendant count can reject it.
    let child = tx_spending(
        &[
            (OutPoint::new(parent_txid, 1), 0xffff_ffff),
            (fund_utxo(&ctx, 0x97, 100_000), 0xffff_ffff),
        ],
        91_000,
    );
    let handler = Handler::new(Arc::clone(&ctx));

    // Preview must reject — the parent's descendant count exceeds the limit.
    let rows = handler
        .dispatch("testmempoolaccept", &json!([[raw_tx_hex(&child)]]))?
        .as_array()
        .ok_or("expected an array of results")?
        .clone();
    let row = rows.first().ok_or("expected one row")?;
    assert_eq!(
        row.get("allowed").and_then(JsonValueTrait::as_bool),
        Some(false),
        "preview must surface descendant count limits"
    );
    let reject_reason = row
        .get("reject-reason")
        .and_then(JsonValueTrait::as_str)
        .ok_or("expected reject-reason")?;
    assert!(
        reject_reason.contains("too many unconfirmed descendants"),
        "unexpected reject-reason: {reject_reason}"
    );

    let message = reject_message(
        &handler
            .dispatch("sendrawtransaction", &json!([raw_tx_hex(&child)]))
            .err()
            .ok_or("expected TooManyDescendants rejection")?,
    );
    assert!(
        message.contains("too many unconfirmed descendants"),
        "unexpected message: {message}"
    );
    assert!(!ctx.mempool.read().contains_txid(&rpc_txid(&child)));

    // Pool-path agreement: the direct insert gate rejects the same package.
    let mut pool = Mempool::new(MempoolLimits::default());
    let root = OutPoint {
        txid: Txid(Hash256::from_le_bytes(&[0x96; 32])),
        vout: 0,
    };
    let parent = tx_outputs(root, 0xffff_ffff, &[1_000, 2_000]);
    let parent_txid = parent.txid();
    let parent_out = OutPoint::new(parent_txid, 0);
    pool.insert_entry(MempoolEntry::new(Arc::new(parent), 4_000, 4_000, 0, 1))?;
    for value in 1_000_u64..1_024 {
        let child = tx(parent_out, value, 0xffff_ffff);
        pool.insert_entry(MempoolEntry::new(Arc::new(child), 4_000, 4_000, 0, 1))?;
    }
    let error = pool
        .insert_entry(MempoolEntry::new(
            Arc::new(tx(OutPoint::new(parent_txid, 1), 9_999, 0xffff_ffff)),
            4_000,
            4_000,
            0,
            1,
        ))
        .err()
        .ok_or("pool path must also reject")?;
    assert_eq!(
        error,
        bitcoin_rs_mempool::MempoolError::Policy(PolicyError::TooManyDescendants)
    );
    Ok(())
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
            value: 9_000,
            script_pubkey: op_true_script(),
        }],
        ..tx(fund_utxo(&ctx, 0x72, 10_000), 9_000, 0xffff_ffff)
    };
    let dust = Tx {
        outputs: vec![TxOut {
            value: 100,
            script_pubkey: p2wpkh_script(),
        }],
        ..tx(fund_utxo(&ctx, 0x73, 10_000), 100, 0xffff_ffff)
    };
    let txs = [&good, &below_min, &nonstandard, &dust];

    let handler = Handler::new(Arc::clone(&ctx));
    let rows = handler
        .dispatch(
            "testmempoolaccept",
            &json!([txs.iter().map(|tx| raw_tx_hex(tx)).collect::<Vec<_>>()]),
        )?
        .as_array()
        .ok_or("expected an array of results")?
        .clone();

    for (index, tx) in txs.iter().enumerate() {
        let row = rows.get(index).ok_or("missing row")?;
        let preview_allowed = row
            .get("allowed")
            .and_then(JsonValueTrait::as_bool)
            .ok_or("row missing allowed")?;
        // The submission verdict must match the preview verdict per row.
        let submitted = handler.dispatch("sendrawtransaction", &json!([raw_tx_hex(tx)]));
        assert_eq!(
            submitted.is_ok(),
            preview_allowed,
            "row {index}: preview and submission must agree"
        );
    }
    Ok(())
}

#[test]
fn decode_failures_reject_with_invalid_params() -> Result<(), Box<dyn Error>> {
    let ctx = Arc::new(Context::new());
    let handler = Handler::new(Arc::clone(&ctx));
    let error = handler
        .dispatch("sendrawtransaction", &json!(["zznotahexzz"]))
        .err()
        .ok_or("expected a decode rejection")?;
    assert_eq!(error.code(), RpcError::INVALID_PARAMS);
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
    handles: bitcoin_rs_node::apply::ApplyHandles,
}

impl ChainControl for NodeInvalidator {
    fn invalidate_block(&self, hash: Hash256) -> core::result::Result<(), ChainControlError> {
        invalidate_block(&self.handles, hash).map_err(|error| match error {
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
    config.p2p_listen.clear();
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
            script_sig: [script_push_int(i64::from(height)), script_push_int(0)].concat(),
            sequence: 0xffff_ffff,
            witness: Vec::new(),
        }],
        outputs: vec![TxOut {
            value: REORG_SUBSIDY_SATS,
            script_pubkey: vec![0x51],
        }],
        lock_time: 0,
    }
}

/// The spend of the height-1 seed coinbase with a caller-chosen fee; it
/// matures exactly at height 101.
fn reorg_seed_coinbase_spend_with_fee(fee_sats: u64) -> Tx {
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(reorg_seed_coinbase(1).txid(), 0),
            script_sig: Vec::new(),
            sequence: 0xffff_ffff,
            witness: Vec::new(),
        }],
        outputs: vec![TxOut {
            value: REORG_SUBSIDY_SATS - fee_sats,
            script_pubkey: vec![0x51],
        }],
        lock_time: 0,
    }
}

fn reorg_grind_pow(block: &mut Block) -> Result<(), Box<dyn Error>> {
    loop {
        if pow_is_met(block.header.bits, &block.header.compute_hash().into()) {
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
            bits: REORG_REGTEST_BITS,
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
    let applied = state.applied_tip();
    let Some(tip) = applied.load_full() else {
        return Err("applied tip must exist".into());
    };
    Ok((tip.hash, tip.height))
}

fn invalidation_handler(state: &NodeState) -> Handler {
    Handler::new(Arc::new(
        Context::from_handles(ContextHandles {
            chain: ChainHandles {
                chain_tip: state.chain_tip(),
                applied_tip: state.applied_tip(),
                blocks: state.blocks(),
                transactions: state.transactions(),
                utxo: state.utxo(),
                coin_stats: state.coin_stats(),
                block_tree: state.block_tree(),
                chain_network: Network::Regtest,
            },
            mempool: MempoolHandles {
                mempool: MempoolGateway::shared(state.mempool()),
            },
            indexes: IndexHandles {
                tx_index: None,
                script_index: None,
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
            capabilities: None,
        })
        .with_chain_control(Arc::new(NodeInvalidator {
            handles: state.apply_handles(),
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
    let committed = gateway.reconsider_disconnected(
        AdmissionOrigin::Reorg,
        mined_block
            .txs
            .iter()
            .filter(|tx| !is_coinbase(tx))
            .map(|tx| {
                let vsize = u32::try_from(tx.vsize()).unwrap_or(u32::MAX);
                MempoolEntry::new(
                    Arc::new(tx.clone()),
                    vsize,
                    REORG_SPEND_FEE_SATS,
                    1,
                    REORG_SEED_BLOCKS,
                )
            }),
    );
    assert_eq!(committed.len(), 1, "one admitted candidate: the spend");
    assert!(gateway.read().contains_txid(&spend_txid));
    Ok(())
}
