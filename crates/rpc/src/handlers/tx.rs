use alloc::sync::Arc;
use core::str::FromStr as _;
use hashbrown::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::script_util::{
    Instruction, count_segwit, count_tx_legacy, instructions, is_p2sh, is_witness_program, opcode,
    push_data,
};
use bitcoin::consensus::encode::serialize as bitcoin_serialize;
use bitcoin::hashes::Hash as _;
use bitcoin::merkle_tree::MerkleBlock;
use bitcoin_rs_mempool::standardness::{
    AcceptanceRejectReason, PackageTxContext as MempoolPackageTxContext,
    evaluate_package_acceptance_all,
};
use bitcoin_rs_mempool::{
    AdmissionOrigin, AdmissionRequest, AdmitError, AdmitOutcome, MutationResult,
};
use bitcoin_rs_primitives::{
    Block as NativeBlock, Hash256, OutPoint, Tx, TxIn, TxOut, Txid, consensus_bytes,
    deserialize as native_deserialize,
};
use miniscript::psbt::PsbtExt as _;
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait, Value, json};

use crate::compat::convert::{
    self, VerboseTxChain, sat_to_btc, typed_to_sonic, typed_to_sonic_omitting_nulls,
};
use crate::context::{BlockRecord, Context};
use crate::error::RpcError;
use crate::handlers::{optional_bool, params_array, parse_txid, required_str, required_u64};
use corepc_types::v31;

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

/// Decodes a lowercase or uppercase hexadecimal string into bytes.
fn hex_decode(hex: &str) -> Result<Vec<u8>, RpcError> {
    let bytes = hex.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(RpcError::InvalidParams("hex string must have even length"));
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks(2) {
        let hi = decode_nibble(chunk[0]).ok_or(RpcError::InvalidParams("invalid hex character"))?;
        let lo = decode_nibble(chunk[1]).ok_or(RpcError::InvalidParams("invalid hex character"))?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

const fn decode_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub(crate) fn getrawtransaction(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let txid = parse_txid(required_str(params, 0, "txid is required")?)?;
    let verbose = raw_transaction_verbosity(params)?;
    let blockhash = params_array(params)?
        .get(2)
        .filter(|value| !value.is_null())
        .map(|value| {
            value
                .as_str()
                .ok_or(RpcError::InvalidType("blockhash must be a string"))
                .and_then(|hash| {
                    Hash256::from_str(hash)
                        .map_err(|_| RpcError::InvalidParams("blockhash must be 64 hex characters"))
                })
        })
        .transpose()?;

    if let Some(hash) = blockhash {
        let record = ctx
            .block_by_hash(hash)
            .ok_or(RpcError::NotFound("block not found"))?;
        let block = load_block(ctx, &record)?;
        let tx = block
            .txs
            .iter()
            .find(|tx| tx.txid() == txid)
            .ok_or(RpcError::NotFound("transaction not in specified block"))?;
        return render_raw_transaction(ctx, tx, verbose, Some(&record));
    }

    {
        let pool = ctx.mempool.read();
        if let Some(entry) = pool.entry_by_txid(&txid) {
            return render_raw_transaction(ctx, entry.tx.as_ref(), verbose, None);
        }
    }
    if let Some(tx_index) = ctx.tx_index.as_ref() {
        let tx = tx_index.transaction(&txid).map_err(RpcError::from)?;
        if let Some(tx) = tx {
            let record = tx_index
                .transaction_height(&txid)
                .map_err(RpcError::from)?
                .and_then(|height| ctx.block_by_height(height));
            return render_raw_transaction(ctx, &tx, verbose, record.as_ref());
        }
    }

    // Compatibility cache used by tests and early wiring; not confirmation proof.
    if let Some(tx) = ctx.transactions.read().get(&txid) {
        return render_raw_transaction(ctx, tx, verbose, None);
    }

    Err(RpcError::NotFound("transaction not found"))
}

fn raw_transaction_verbosity(params: &Value) -> Result<bool, RpcError> {
    let Some(value) = params_array(params)?.get(1) else {
        return Ok(false);
    };
    if value.is_null() {
        return Ok(false);
    }
    if let Some(verbose) = value.as_bool() {
        return Ok(verbose);
    }
    match value.as_u64() {
        Some(0) => Ok(false),
        Some(1 | 2) => Ok(true),
        Some(_) => Err(RpcError::InvalidParams("verbosity must be 0, 1, or 2")),
        None => Err(RpcError::InvalidType(
            "verbosity must be a boolean or integer",
        )),
    }
}

fn load_block(ctx: &Context, record: &BlockRecord) -> Result<NativeBlock, RpcError> {
    let bytes = ctx
        .block_body_bytes(record)
        .ok_or(RpcError::NotFound("block data pruned"))?;
    native_deserialize(&bytes)
        .map_err(|_| RpcError::Internal("stored block bytes failed decode".to_owned()))
}

fn render_raw_transaction(
    ctx: &Context,
    tx: &Tx,
    verbose: bool,
    record: Option<&BlockRecord>,
) -> Result<Value, RpcError> {
    if !verbose {
        return typed_to_sonic(&v31::GetRawTransaction(hex_encode(&consensus_bytes(tx))));
    }
    let chain = record.map(|record| VerboseTxChain {
        block_hash: record.hash.to_string(),
        confirmations: u64::from(
            ctx.applied_height()
                .saturating_sub(record.height)
                .saturating_add(1),
        ),
        time: u64::from(record.time),
        in_active_chain: Some(true),
    });
    typed_to_sonic(&convert::raw_transaction_verbose(
        tx,
        ctx.chain_network,
        chain,
    )?)
}

pub(crate) fn gettxout(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let txid = parse_txid(required_str(params, 0, "txid is required")?)?;
    let vout = required_u64(params, 1, "vout is required")?;
    let vout_u32 = u32::try_from(vout).map_err(|_| RpcError::InvalidParams("vout exceeds u32"))?;
    let include_mempool = optional_bool(params, 2, true)?;

    let outpoint = OutPoint::new(txid, vout_u32);

    if include_mempool {
        let pool = ctx.mempool.read();
        if pool.is_outpoint_spent(&outpoint) {
            return Ok(Value::new_null());
        }
        if let Some(entry) = pool.entry_by_txid(&txid)
            && let Ok(vout) = usize::try_from(vout_u32)
            && let Some(output) = entry.tx.outputs.get(vout)
        {
            return txout_typed(ctx, output, 0, false);
        }
    }

    let Some(live) = ctx.utxo.get_entry(&outpoint) else {
        // Spent or never existed: Core-spec returns JSON null.
        return Ok(Value::new_null());
    };
    let confirmations = ctx
        .applied_height()
        .saturating_sub(live.height)
        .saturating_add(1);
    txout_typed(ctx, &live.txout, confirmations, live.coinbase)
}

fn txout_typed(
    ctx: &Context,
    output: &TxOut,
    confirmations: u32,
    coinbase: bool,
) -> Result<Value, RpcError> {
    typed_to_sonic(&v31::GetTxOut {
        best_block: ctx.best_hash().to_string(),
        confirmations,
        value: sat_to_btc(output.value),
        script_pubkey: convert::script_pub_key_typed(&output.script_pubkey, ctx.chain_network)?,
        coinbase,
    })
}

pub(crate) fn gettxoutproof(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let array = params_array(params)?;
    let txids_value = array
        .first()
        .and_then(|value| value.as_array())
        .ok_or(RpcError::InvalidParams("txids must be an array"))?;
    if txids_value.is_empty() {
        return Err(RpcError::InvalidParams("txids are required"));
    }

    let mut wanted = hashbrown::HashSet::new();
    for value in txids_value {
        let Some(txid) = value.as_str() else {
            return Err(RpcError::InvalidType("each txid must be a string"));
        };
        wanted.insert(parse_txid(txid)?);
    }

    if let Some(hash_str) = array.get(1).and_then(JsonValueTrait::as_str) {
        let hash = Hash256::from_str(hash_str)
            .map_err(|_| RpcError::InvalidParams("blockhash must be 64 hex characters"))?;
        let Some(record) = ctx.block_by_hash(hash) else {
            return Err(RpcError::NotFound("block not found"));
        };
        return proof_from_single_record(ctx, &record, &wanted);
    }

    // Without a block hash the scan below reads, deserializes and hashes every
    // block on the chain to answer one call. The txindex already knows which
    // block confirms a txid, so ask it first and scan only when it cannot
    // answer — the same route Bitcoin Core takes, which requires the block hash
    // *unless* txindex is enabled.
    if let Some(proof) = proof_via_index(ctx, &wanted) {
        return Ok(proof);
    }
    proof_from_block_log(ctx, &wanted)
}

/// Answers `gettxoutproof` from the txindex, or `None` when it cannot.
///
/// Probes the wanted txids until one resolves to a confirming height, then tries
/// to build the proof from that block alone. Probing *every* txid rather than an
/// arbitrary one matters: `wanted` is a `HashSet`, so "the first" is whichever
/// the hasher happens to yield, and one unresolvable txid would otherwise drop
/// the call into the full chain scan non-deterministically — the very cost this
/// path exists to avoid.
///
/// Every miss returns `None` so the caller falls back to that scan: no index,
/// no row, a stale row, a pruned body, or a block that does not hold *all* the
/// wanted txids. The last of those is not belt-and-braces — BIP30's duplicate
/// coinbase txids mean a txid can confirm in more than one block, so a block
/// chosen from a single txid is a candidate, never a verdict.
///
/// An index that returns an error is a miss too, logged rather than propagated.
/// Before this path existed a broken txindex could not fail this call, and the
/// scan can still answer it; an optimization must not turn a working call into
/// an error. `TxQueryError::Retry` makes that concrete rather than defensive:
/// the index reconciles asynchronously, so it reports `Retry` while it is
/// catching up, and a call the scan can answer today must not be refused
/// because the index is behind.
fn proof_via_index(ctx: &Arc<Context>, wanted: &hashbrown::HashSet<Txid>) -> Option<Value> {
    let tx_index = ctx.tx_index.as_ref()?;
    for probe in wanted {
        let height = match tx_index.transaction_height(probe) {
            Ok(Some(height)) => height,
            Ok(None) => continue,
            Err(error) => {
                tracing::warn!(
                    txid = %probe,
                    %error,
                    "txindex lookup failed; answering from the block scan instead"
                );
                return None;
            }
        };
        let Some(record) = ctx.block_by_height(height) else {
            continue;
        };
        if let Some(proof) = proof_from_record(ctx, &record, wanted) {
            return Some(proof);
        }
    }
    None
}

/// Builds the proof from one named block, or reports why it could not.
///
/// The explicit-`blockhash` path: the caller named the block, so there is
/// nothing to scan and the two failures are distinguishable — a body that is not
/// there, and a block that does not hold every wanted txid. Both messages are
/// the ones this handler returned before the index path existed.
fn proof_from_single_record(
    ctx: &Arc<Context>,
    record: &crate::context::BlockRecord,
    wanted: &hashbrown::HashSet<Txid>,
) -> Result<Value, RpcError> {
    let Some(bytes) = ctx.block_body_bytes(record) else {
        return Err(RpcError::NotFound("block data pruned"));
    };
    proof_from_body(&bytes, wanted)
        .ok_or(RpcError::NotFound("no block contains all requested txids"))
}

/// Scans the whole block-record log for a block holding every wanted txid.
///
/// Deliberately does **not** clone the log, and deliberately does not hold its
/// lock either. Cloning it copies every record on the chain — about 160 MB at a
/// mainnet tip — to answer one call, on the exact path taken when the index
/// cannot. Holding the read guard instead would stall block application for the
/// length of a scan that loads a block body from disk per record.
///
/// So the length is snapshotted once and each record is copied out under a
/// momentary lock, released before its body is read. Records are only ever
/// appended, and the tail `pop` on disconnect only removes what was never in the
/// snapshot's range, so a stale length can miss a block appended mid-scan but
/// can never read a record that moved.
fn proof_from_block_log(
    ctx: &Arc<Context>,
    wanted: &hashbrown::HashSet<Txid>,
) -> Result<Value, RpcError> {
    let len = ctx.blocks.read().len();
    let mut saw_pruned_block = false;
    for index in 0..len {
        let Some(record) = ctx.blocks.read().get(index).cloned() else {
            break;
        };
        let Some(bytes) = ctx.block_body_bytes(&record) else {
            saw_pruned_block = true;
            continue;
        };
        if let Some(proof) = proof_from_body(&bytes, wanted) {
            return Ok(proof);
        }
    }

    if saw_pruned_block {
        Err(RpcError::NotFound("block data pruned"))
    } else {
        Err(RpcError::NotFound("no block contains all requested txids"))
    }
}

/// Builds the merkle proof for `wanted` from one block record, or `None` when
/// that block is pruned, undecodable, or does not hold every wanted txid.
fn proof_from_record(
    ctx: &Arc<Context>,
    record: &crate::context::BlockRecord,
    wanted: &hashbrown::HashSet<Txid>,
) -> Option<Value> {
    let bytes = ctx.block_body_bytes(record)?;
    proof_from_body(&bytes, wanted)
}

/// Builds the merkle proof for `wanted` from one serialized block, or `None`
/// when it does not decode or does not hold every wanted txid.
fn proof_from_body(bytes: &[u8], wanted: &hashbrown::HashSet<Txid>) -> Option<Value> {
    let block = native_deserialize::<NativeBlock>(bytes).ok()?;
    let block_txids = block
        .txs
        .iter()
        .map(Tx::txid)
        .collect::<hashbrown::HashSet<Txid>>();
    if !wanted.iter().all(|txid| block_txids.contains(txid)) {
        return None;
    }

    // MerkleBlock construction requires bitcoin::Block (sanctioned seam).
    let bitcoin_block = bitcoin::consensus::encode::deserialize::<bitcoin::Block>(bytes).ok()?;
    // WHY `Hash`: `from_byte_array` comes from the rust-bitcoin `Hash` trait
    // here; the wire txids ride the sanctioned MerkleBlock seam in native LE bytes.
    let bitcoin_wanted: hashbrown::HashSet<bitcoin::Txid> = wanted
        .iter()
        .map(|txid| bitcoin::Txid::from_byte_array(*txid.as_bytes()))
        .collect();
    let merkle_block = MerkleBlock::from_block_with_predicate(&bitcoin_block, |txid| {
        bitcoin_wanted.contains(txid)
    });
    Some(json!(hex_encode(&bitcoin_serialize(&merkle_block))))
}

pub(crate) fn verifytxoutproof(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let proof_hex = required_str(params, 0, "proof is required")?;

    let bytes = hex_decode(proof_hex)?;
    let Ok(merkle_block) = bitcoin::consensus::encode::deserialize::<MerkleBlock>(&bytes) else {
        return typed_to_sonic(&v31::VerifyTxOutProof(Vec::new()));
    };

    let mut matched_txids = Vec::new();
    let mut indexes = Vec::new();
    if merkle_block
        .extract_matches(&mut matched_txids, &mut indexes)
        .is_err()
    {
        return typed_to_sonic(&v31::VerifyTxOutProof(Vec::new()));
    }

    let result = matched_txids
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    typed_to_sonic(&v31::VerifyTxOutProof(result))
}

/// Admits one transaction through the R4 generation-revalidated gateway.
///
/// This is the shared typed admission operation: `sendrawtransaction` and
/// the embedded `Node::broadcast` both run it. Each attempt reads a fresh
/// stable generation, captures the exact mempool sequence under a read
/// guard, resolves UTXO data without the guard, then calls
/// [`MempoolGateway::admit_transaction`] with both tokens. A chain change
/// or mempool mutation between capture and commit returns a transient
/// error and the loop retries with fresh facts.
///
/// An already-known transaction succeeds with an empty [`MutationResult`],
/// matching Core's `sendrawtransaction` already-known success.
///
/// `max_feerate_sat_per_kvb` of `None` disables the max-fee cap, matching
/// `sendrawtransaction`'s `maxfeerate=0` behavior.
///
/// # Errors
///
/// Returns the policy rejection string (Core rejection strings) or the
/// failure verbatim; nothing is inserted when this fails.
pub(crate) fn admit_transaction(
    ctx: &Context,
    tx: Tx,
    max_feerate_sat_per_kvb: Option<u64>,
) -> Result<MutationResult, String> {
    let txid = tx.txid();

    // A tx already confirmed in the chain is always "known" — no
    // generation or mempool guard needed.
    if ctx.transactions.read().contains_key(&txid) {
        return Ok(MutationResult::empty());
    }

    // Bounded retry: each attempt reads a fresh stable generation, captures
    // the exact mempool sequence under a read guard, resolves UTXO data
    // without the guard, then calls admit_transaction with both tokens. A
    // chain change or mempool mutation between capture and commit returns a
    // transient error and the loop retries with fresh facts — it never
    // re-uses a captured even generation.
    #[allow(clippy::items_after_statements)]
    const MAX_ADMISSION_RETRIES: usize = 4;
    for _ in 0..MAX_ADMISSION_RETRIES {
        let Some(generation) = ctx.mempool.stable_generation() else {
            continue; // chain change active or failed — retry
        };

        // Under one gateway read guard: already-known lookup, capture exact
        // sequence, snapshot policy, resolve mempool-dependent context.
        let (sequence, _policy, mempool_prevouts) = {
            let pool = ctx.mempool.read();
            if pool.contains_txid(&txid) {
                return Ok(MutationResult::empty());
            }
            let sequence = pool.sequence_number();
            let policy = pool.policy_snapshot();
            let mempool_prevouts = resolve_mempool_prevouts(&pool, &tx);
            (sequence, policy, mempool_prevouts)
        };

        // Without a pool guard: resolve UTXO data and combine with the
        // mempool-dependent prevouts captured above.
        let (context, prevouts) = resolve_full_context(ctx, &tx, &mempool_prevouts);
        let locktime_cutoff = ctx
            .median_time_past_for_hash(ctx.applied_hash())
            .unwrap_or(0);

        let request = AdmissionRequest {
            tx: Arc::new(tx.clone()),
            context,
            prevouts,
            locktime_cutoff,
            max_feerate_sat_per_kvb,
            time: unix_time_secs(),
            height: ctx.applied_height(),
            origin: AdmissionOrigin::Rpc,
            expected_generation: generation,
            expected_sequence: sequence,
        };

        match ctx.mempool.admit_transaction(request) {
            Ok(AdmitOutcome::Committed(result)) => {
                let _ = ctx.add_transaction(tx);
                return Ok(result);
            }
            Ok(AdmitOutcome::AlreadyKnown) => {
                // The exact transaction was added between our read-guard
                // check and the write-guard commit. Return normal success
                // without a second add_transaction.
                return Ok(MutationResult::empty());
            }
            Err(AdmitError::GenerationChanged | AdmitError::MempoolChanged) => continue,
            Err(AdmitError::Policy(reason)) => {
                return Err(reason.to_string());
            }
            Err(AdmitError::Consensus) => {
                return Err("consensus-verification-failed".to_owned());
            }
        }
    }

    Err("admission retry exhausted: chain or mempool changed during submission".to_owned())
}

/// Fee rate above which `sendrawtransaction` refuses by default, in sat/kvB.
///
/// Bitcoin Core's `DEFAULT_MAX_RAW_TX_FEE_RATE`, `COIN / 10` — 0.1 BTC per kvB.
/// The guard exists because a change-output mistake shows up as an enormous
/// fee, and a fee is not recoverable once the transaction confirms.
use crate::context::DEFAULT_MAX_RAW_TX_FEE_RATE_SAT_PER_KVB;

pub(crate) fn sendrawtransaction(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let raw = required_str(params, 0, "raw transaction is required")?;
    let max_feerate = optional_max_feerate(params, 1)?;
    let tx = decode_tx(raw)?;
    let txid = tx.txid();

    // A tx already confirmed in the chain is always "known" — no
    // generation or mempool guard needed.
    if ctx.transactions.read().contains_key(&txid) {
        return typed_to_sonic(&v31::SendRawTransaction(txid.to_string()));
    }

    // Bounded retry: each attempt reads a fresh stable generation, captures
    // the exact mempool sequence under a read guard, resolves UTXO data
    // without the guard, then calls admit_transaction with both tokens. A
    // chain change or mempool mutation between capture and commit returns a
    // transient error and the loop retries with fresh facts — it never
    // re-uses a captured even generation.
    #[allow(clippy::items_after_statements)]
    const MAX_ADMISSION_RETRIES: usize = 4;
    for _ in 0..MAX_ADMISSION_RETRIES {
        let Some(generation) = ctx.mempool.stable_generation() else {
            continue; // chain change active or failed — retry
        };

        // Under one gateway read guard: already-known lookup, capture exact
        // sequence, snapshot policy, resolve mempool-dependent context.
        let (sequence, _policy, mempool_prevouts) = {
            let pool = ctx.mempool.read();
            if pool.contains_txid(&txid) {
                return typed_to_sonic(&v31::SendRawTransaction(txid.to_string()));
            }
            let sequence = pool.sequence_number();
            let policy = pool.policy_snapshot();
            let mempool_prevouts = resolve_mempool_prevouts(&pool, &tx);
            (sequence, policy, mempool_prevouts)
        };

        // Without a pool guard: resolve UTXO data and combine with the
        // mempool-dependent prevouts captured above.
        let (context, prevouts) = resolve_full_context(ctx, &tx, &mempool_prevouts);
        let locktime_cutoff = ctx
            .median_time_past_for_hash(ctx.applied_hash())
            .unwrap_or(0);

        let request = AdmissionRequest {
            tx: Arc::new(tx.clone()),
            context,
            prevouts,
            locktime_cutoff,
            max_feerate_sat_per_kvb: max_feerate,
            time: unix_time_secs(),
            height: ctx.applied_height(),
            origin: AdmissionOrigin::Rpc,
            expected_generation: generation,
            expected_sequence: sequence,
        };

        match ctx.mempool.admit_transaction(request) {
            Ok(AdmitOutcome::Committed(_)) => {
                let _ = ctx.add_transaction(tx);
                return typed_to_sonic(&v31::SendRawTransaction(txid.to_string()));
            }
            Ok(AdmitOutcome::AlreadyKnown) => {
                // The exact transaction was added between our read-guard
                // check and the write-guard commit. Return normal txid
                // success without a second add_transaction.
                return typed_to_sonic(&v31::SendRawTransaction(txid.to_string()));
            }
            Err(AdmitError::GenerationChanged | AdmitError::MempoolChanged) => continue,
            Err(AdmitError::Policy(reason)) => {
                return Err(reject_reason_to_rpc_error(reason));
            }
            Err(AdmitError::Consensus) => {
                return Err(RpcError::TxRejected(
                    "consensus-verification-failed".to_owned(),
                ));
            }
        }
    }

    Err(RpcError::Internal(
        "admission retry exhausted: chain or mempool changed during submission".to_owned(),
    ))
}

pub(crate) fn testmempoolaccept(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let array = params_array(params)?;
    let raw_txs = array
        .first()
        .and_then(|value| value.as_array())
        .ok_or(RpcError::InvalidParams("raw transaction array is required"))?;
    let max_feerate = optional_max_feerate(params, 1)?;

    let mut txs = Vec::with_capacity(raw_txs.len());
    for raw in raw_txs {
        let Some(raw) = raw.as_str() else {
            return Err(RpcError::InvalidType("raw transaction must be a string"));
        };
        txs.push(decode_tx(raw)?);
    }

    let pool = ctx.mempool.read();
    let policy = pool.policy_snapshot();
    let contexts = package_contexts(ctx, &pool, &txs);
    let facts = evaluate_package_acceptance_all(
        &pool,
        &policy.standardness,
        &txs,
        &contexts,
        max_feerate,
        policy.incremental_relay_fee_sat_per_kvb,
    );

    let mut rows = Vec::with_capacity(facts.results.len());
    for fact in &facts.results {
        let fees = fact.base_fee.map(|fee| v31::MempoolAcceptanceFees {
            base: sat_to_btc(fee),
            effective_fee_rate: None,
            effective_includes: Vec::new(),
        });
        rows.push(v31::MempoolAcceptance {
            txid: fact.txid.to_string(),
            wtxid: fact.wtxid.to_string(),
            allowed: fact.allowed.unwrap_or(false),
            vsize: fact.allowed.unwrap_or(false).then(|| i64::from(fact.vsize)),
            fees,
            reject_reason: fact.reject_reason.map(reject_reason_to_frozen_string),
            reject_details: None,
        });
    }
    typed_to_sonic_omitting_nulls(&v31::TestMempoolAccept(rows))
}

pub(crate) fn decoderawtransaction(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let raw = required_str(params, 0, "raw transaction is required")?;
    let tx = decode_tx(raw)?;
    typed_to_sonic(&v31::DecodeRawTransaction(convert::raw_transaction(
        &tx,
        ctx.chain_network,
    )?))
}

pub(crate) fn createrawtransaction(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let array = params_array(params)?;
    let inputs = array
        .first()
        .and_then(|value| value.as_array())
        .ok_or(RpcError::InvalidParams("inputs must be an array"))?;
    let outputs = array
        .get(1)
        .and_then(|value| value.as_object())
        .ok_or(RpcError::InvalidParams("outputs must be an object"))?;
    let locktime = match array.get(2) {
        None => 0_u32,
        Some(value) if value.is_null() => 0_u32,
        Some(value) => {
            let locktime = value
                .as_u64()
                .ok_or(RpcError::InvalidType("locktime must be an integer"))?;
            u32::try_from(locktime).map_err(|_| RpcError::InvalidParams("locktime exceeds u32"))?
        }
    };
    let replaceable = optional_bool(params, 3, false)?;

    // BIP125 opt-in sequence; 0xFFFFFFFF = final (no RBF, no locktime).
    let default_sequence: u32 = if replaceable {
        0xFFFF_FFFD
    } else {
        0xFFFF_FFFF
    };

    let mut tx_inputs = Vec::with_capacity(inputs.len());
    let mut seen = HashSet::new();
    for input in inputs {
        let object = input
            .as_object()
            .ok_or(RpcError::InvalidType("input must be an object"))?;
        let txid = parse_txid(
            object
                .get(&"txid")
                .and_then(JsonValueTrait::as_str)
                .ok_or(RpcError::InvalidParams("input txid is required"))?,
        )?;
        let vout = object
            .get(&"vout")
            .and_then(JsonValueTrait::as_u64)
            .ok_or(RpcError::InvalidParams("input vout is required"))?;
        let vout = u32::try_from(vout).map_err(|_| RpcError::InvalidParams("vout exceeds u32"))?;
        if !seen.insert((txid, vout)) {
            return Err(RpcError::InvalidParams("duplicate input specified"));
        }
        let sequence = match object.get(&"sequence") {
            None => default_sequence,
            Some(value) => {
                let sequence = value
                    .as_u64()
                    .ok_or(RpcError::InvalidType("sequence must be an integer"))?;
                u32::try_from(sequence)
                    .map_err(|_| RpcError::InvalidParams("sequence exceeds u32"))?
            }
        };
        tx_inputs.push(TxIn {
            previous_output: OutPoint::new(txid, vout),
            script_sig: Vec::new(),
            sequence,
            witness: Vec::new(),
        });
    }

    // Address parsing requires bitcoin::Network (sanctioned seam).
    let network = convert::bitcoin_network(ctx.chain_network);
    let mut tx_outputs = Vec::with_capacity(outputs.len());
    for (key, value) in outputs {
        if key == "data" {
            let data_hex = value
                .as_str()
                .ok_or(RpcError::InvalidType("data output must be a hex string"))?;
            let data = hex_decode(data_hex)?;
            let mut script = vec![opcode::OP_RETURN];
            script.extend_from_slice(&push_data(&data));
            tx_outputs.push(TxOut {
                value: 0,
                script_pubkey: script,
            });
            continue;
        }

        let address = bitcoin::Address::from_str(key)
            .map_err(|_| RpcError::InvalidParams("invalid Bitcoin address"))?
            .require_network(network)
            .map_err(|_| RpcError::InvalidParams("invalid Bitcoin address"))?;
        tx_outputs.push(TxOut {
            value: parse_btc_amount(value)?,
            script_pubkey: address.script_pubkey().as_bytes().to_vec(),
        });
    }

    let tx = Tx {
        version: 2,
        lock_time: locktime,
        inputs: tx_inputs,
        outputs: tx_outputs,
    };
    typed_to_sonic(&v31::CreateRawTransaction(hex_encode(&consensus_bytes(
        &tx,
    ))))
}

fn decode_tx(raw: &str) -> Result<Tx, RpcError> {
    let bytes = hex_decode(raw)?;
    native_deserialize(&bytes).map_err(|_| RpcError::InvalidParams("transaction decode failed"))
}

fn unix_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

/// f64 nearest to 2^64 — the value `u64::MAX` rounds to as a float, and the
/// first `f64` that no longer fits `u64` satoshis. A literal because
/// `as_conversions` bans the cast that would compute it.
const U64_MAX_F64: f64 = 18_446_744_073_709_551_616.0;

/// Converts a BTC-denominated float to satoshis, rejecting non-finite,
/// negative, and overflow values with `message`.
///
/// The final step is a scoped `as`: std offers no `TryFrom<f64> for u64`, and
/// the range check above already bounds `raw` to `[0, 2^64)`, so the cast
/// only truncates fractional satoshi dust, matching the historical behavior.
fn sats_from_btc(btc: f64, message: &'static str) -> Result<u64, RpcError> {
    let raw = btc * 100_000_000.0;
    if !raw.is_finite() || !(0.0..U64_MAX_F64).contains(&raw) {
        return Err(RpcError::InvalidParams(message));
    }
    #[allow(clippy::as_conversions)] // see fn doc: no TryFrom<f64> for u64 in std
    #[allow(clippy::cast_possible_truncation)] // fractional dust, per fn doc
    #[allow(clippy::cast_sign_loss)] // raw >= 0.0 checked above
    Ok(raw as u64)
}

fn optional_max_feerate(params: &Value, index: usize) -> Result<Option<u64>, RpcError> {
    let Some(value) = params_array(params)?.get(index) else {
        return Ok(Some(DEFAULT_MAX_RAW_TX_FEE_RATE_SAT_PER_KVB));
    };
    if value.is_null() {
        return Ok(Some(DEFAULT_MAX_RAW_TX_FEE_RATE_SAT_PER_KVB));
    }
    let btc_per_kvb = if let Some(number) = value.as_f64() {
        number
    } else if let Some(text) = value.as_str() {
        text.parse::<f64>()
            .map_err(|_| RpcError::InvalidType("maxfeerate must be a number"))?
    } else {
        return Err(RpcError::InvalidType("maxfeerate must be a number"));
    };
    if !btc_per_kvb.is_finite() || btc_per_kvb < 0.0 {
        return Err(RpcError::InvalidParams("maxfeerate must be non-negative"));
    }
    if btc_per_kvb == 0.0 {
        return Ok(None);
    }
    let sats = sats_from_btc(btc_per_kvb, "maxfeerate is out of range")?;
    // Core's `ParseFeeRate` refuses rates at or above 1 BTC/kvB, so the
    // ceiling is enforced on the integer domain to keep the parameter
    // contract identical.
    if sats >= 100_000_000 {
        return Err(RpcError::InvalidParams(
            "Fee rates larger than or equal to 1BTC/kvB are not accepted",
        ));
    }
    Ok(Some(sats))
}

fn parse_btc_amount(value: &Value) -> Result<u64, RpcError> {
    if let Some(number) = value.as_f64() {
        return sats_from_btc(number, "Invalid amount");
    }
    if let Some(text) = value.as_str() {
        let number: f64 = text
            .parse()
            .map_err(|_| RpcError::InvalidParams("Invalid amount"))?;
        return sats_from_btc(number, "Invalid amount");
    }
    Err(RpcError::InvalidType("amount must be a number or string"))
}

// ---------------------------------------------------------------------------
// Prevout / context resolution and frozen reason mapping.
// ---------------------------------------------------------------------------

/// Maps an [`AcceptanceRejectReason`] to the Core-compatible RPC error.
/// `MaxFeeExceeded` is a parameter error (`-32602`), pinned by the
/// policy-contract integration test. All other admission rejections are
/// transaction rejections (`-26`), matching Bitcoin Core's
/// `RPC_VERIFY_REJECTED` code. The string for `MinRelayFeeNotMet` uses
/// the frozen hyphenated form `min-relay-fee-not-met`, not the mempool's
/// Display.
fn reject_reason_to_rpc_error(reason: AcceptanceRejectReason) -> RpcError {
    match reason {
        AcceptanceRejectReason::MaxFeeExceeded => RpcError::InvalidParams("max-fee-exceeded"),
        other => RpcError::TxRejected(reject_reason_to_frozen_string(other)),
    }
}

/// Maps an [`AcceptanceRejectReason`] to the frozen RPC reject-reason string.
/// Every variant matches the mempool's `Display` except `MinRelayFeeNotMet`,
/// which uses the frozen hyphenated form.
fn reject_reason_to_frozen_string(reason: AcceptanceRejectReason) -> String {
    match reason {
        AcceptanceRejectReason::MinRelayFeeNotMet => "min-relay-fee-not-met".to_owned(),
        other => other.to_string(),
    }
}

/// Resolves mempool-dependent prevouts for a single tx under a read guard.
/// Returns `(txid, vout, value, script_pubkey)` tuples for inputs whose
/// prevout is a mempool parent transaction.
fn resolve_mempool_prevouts(
    pool: &bitcoin_rs_mempool::Mempool,
    tx: &Tx,
) -> HashMap<OutPoint, TxOut> {
    let mut prevouts = HashMap::new();
    for input in &tx.inputs {
        if input.previous_output == OutPoint::default() {
            continue;
        }
        if let Some(parent) = pool.transaction_by_txid(&input.previous_output.txid)
            && let Ok(vout) = usize::try_from(input.previous_output.vout)
            && let Some(output) = parent.outputs.get(vout)
        {
            prevouts.insert(input.previous_output, output.clone());
        }
    }
    prevouts
}

/// Combines mempool-dependent prevouts (captured under a read guard) with
/// UTXO-set prevouts (resolved without a pool guard) to build the full
/// per-transaction context. Inputs found in neither source are marked
/// missing.
fn resolve_full_context(
    ctx: &Context,
    tx: &Tx,
    mempool_prevouts: &HashMap<OutPoint, TxOut>,
) -> (MempoolPackageTxContext, Vec<(OutPoint, TxOut)>) {
    let mut missing_inputs = false;
    let mut input_value = 0_u64;
    let mut prevouts: Vec<(OutPoint, TxOut)> = Vec::new();

    for input in &tx.inputs {
        if input.previous_output == OutPoint::default() {
            missing_inputs = true;
            continue;
        }
        if let Some(output) = mempool_prevouts.get(&input.previous_output) {
            input_value = input_value.saturating_add(output.value);
            prevouts.push((input.previous_output, output.clone()));
            continue;
        }
        if let Some(live) = ctx.utxo.get_entry(&input.previous_output) {
            input_value = input_value.saturating_add(live.txout.value);
            prevouts.push((input.previous_output, live.txout.clone()));
            continue;
        }
        missing_inputs = true;
    }

    let output_value = tx
        .outputs
        .iter()
        .fold(0_u64, |sum, output| sum.saturating_add(output.value));
    let fee = input_value.saturating_sub(output_value);
    let vsize = u32::try_from(tx.vsize()).unwrap_or(u32::MAX);
    let sigop_cost = u32::try_from(total_sigop_cost(tx, &prevouts)).unwrap_or(u32::MAX);

    (
        MempoolPackageTxContext {
            fee,
            vsize,
            sigop_cost,
            missing_inputs,
        },
        prevouts,
    )
}

fn package_contexts(
    ctx: &Context,
    pool: &bitcoin_rs_mempool::Mempool,
    txs: &[Tx],
) -> Vec<MempoolPackageTxContext> {
    let mut package_outputs: HashMap<(Txid, u32), u64> = HashMap::new();
    let mut contexts = Vec::with_capacity(txs.len());

    for tx in txs {
        let mut missing_inputs = false;
        let mut input_value = 0_u64;
        let mut prevouts: Vec<(OutPoint, TxOut)> = Vec::new();

        for input in &tx.inputs {
            if input.previous_output == OutPoint::default() {
                missing_inputs = true;
                continue;
            }
            let key = (input.previous_output.txid, input.previous_output.vout);
            if let Some(value) = package_outputs.get(&key) {
                input_value = input_value.saturating_add(*value);
                prevouts.push((
                    input.previous_output,
                    TxOut {
                        value: *value,
                        script_pubkey: Vec::new(),
                    },
                ));
                continue;
            }
            if let Some(parent) = pool.transaction_by_txid(&input.previous_output.txid)
                && let Ok(vout) = usize::try_from(input.previous_output.vout)
                && let Some(output) = parent.outputs.get(vout)
            {
                input_value = input_value.saturating_add(output.value);
                prevouts.push((input.previous_output, output.clone()));
                continue;
            }
            if let Some(live) = ctx.utxo.get_entry(&input.previous_output) {
                input_value = input_value.saturating_add(live.txout.value);
                prevouts.push((input.previous_output, live.txout.clone()));
                continue;
            }
            missing_inputs = true;
        }

        let output_value = tx
            .outputs
            .iter()
            .fold(0_u64, |sum, output| sum.saturating_add(output.value));
        let fee = input_value.saturating_sub(output_value);
        let vsize = u32::try_from(tx.vsize()).unwrap_or(u32::MAX);
        let sigop_cost = u32::try_from(total_sigop_cost(tx, &prevouts)).unwrap_or(u32::MAX);

        contexts.push(MempoolPackageTxContext {
            fee,
            vsize,
            sigop_cost,
            missing_inputs,
        });

        let txid = tx.txid();
        for (vout, output) in tx.outputs.iter().enumerate() {
            let vout = u32::try_from(vout).unwrap_or(u32::MAX);
            package_outputs.insert((txid, vout), output.value);
        }
    }

    contexts
}

/// Computes the total sigop cost for a transaction given resolved prevouts.
///
/// Mirrors the consensus `total_sigop_cost` using public script-crate counters:
/// legacy sigops × 4, plus P2SH redeem-script accurate sigops × 4, plus
/// segwit witness-program sigops.
fn total_sigop_cost(tx: &Tx, prevouts: &[(OutPoint, TxOut)]) -> u64 {
    let mut cost = u64::from(count_tx_legacy(tx)).saturating_mul(4);
    for input in &tx.inputs {
        let prevout = prevouts
            .iter()
            .find(|(op, _)| *op == input.previous_output)
            .map(|(_, txout)| txout);
        let Some(prevout) = prevout else {
            continue;
        };
        let redeem_script = last_push(&input.script_sig);
        if is_p2sh(&prevout.script_pubkey) {
            if let Some(redeem) = redeem_script {
                cost = cost.saturating_add(u64::from(count_accurate(redeem)).saturating_mul(4));
            }
        }
        let witness_program = if is_witness_program(&prevout.script_pubkey) {
            Some(prevout.script_pubkey.as_slice())
        } else {
            redeem_script.filter(|script| is_witness_program(script))
        };
        if let Some(program) = witness_program {
            cost = cost.saturating_add(u64::from(count_segwit(program, &input.witness)));
        }
    }
    cost
}

/// Returns the last data push from a script, or `None`.
fn last_push(script: &[u8]) -> Option<&[u8]> {
    let mut last = None;
    for instruction in instructions(script) {
        match instruction.ok()? {
            Instruction::PushBytes(bytes) => last = Some(bytes),
            Instruction::Op(_) => last = None,
        }
    }
    last
}

/// Counts sigops accurately (multisig uses the preceding pushnum value).
fn count_accurate(script: &[u8]) -> u32 {
    let mut count = 0_u32;
    let mut pushed_number = None;
    for instruction in instructions(script) {
        match instruction {
            Ok(Instruction::Op(op)) => match op {
                opcode::OP_CHECKSIG | opcode::OP_CHECKSIGVERIFY => {
                    count = count.saturating_add(1);
                    pushed_number = None;
                }
                opcode::OP_CHECKMULTISIG | opcode::OP_CHECKMULTISIGVERIFY => {
                    count = count.saturating_add(u32::from(pushed_number.unwrap_or(20)));
                    pushed_number = None;
                }
                other => pushed_number = opcode::decode_pushnum(other),
            },
            Ok(Instruction::PushBytes(_)) => pushed_number = None,
            Err(_) => break,
        }
    }
    count
}

pub(crate) fn finalizepsbt(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let raw = required_str(params, 0, "psbt is required")?;
    let extract = optional_bool(params, 1, true)?;
    let decoded = decode_base64(raw)?;
    let Ok(mut psbt) = bitcoin::psbt::Psbt::deserialize(&decoded) else {
        return Err(RpcError::InvalidParams("invalid base64 PSBT"));
    };
    let secp = bitcoin::secp256k1::Secp256k1::verification_only();
    // The finalizer mutates every input it can satisfy and reports the rest.
    // Incomplete inputs are part of the RPC result, not an RPC-level failure.
    let _incomplete = psbt.finalize_mut(&secp);
    let finalized_tx = if psbt.inputs.is_empty() {
        None
    } else {
        psbt.extract(&secp).ok()
    };
    let complete = finalized_tx.is_some();
    if extract && let Some(tx) = finalized_tx {
        let hex = hex_encode(&bitcoin_serialize(&tx));
        typed_to_sonic(&v31::FinalizePsbt {
            psbt: None,
            hex: Some(hex),
            complete: true,
        })
    } else {
        let serialized = encode_base64(&psbt.serialize());
        typed_to_sonic(&v31::FinalizePsbt {
            psbt: Some(serialized),
            hex: None,
            complete,
        })
    }
}

pub(crate) fn combinepsbt(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let array = params_array(params)?
        .first()
        .and_then(|value| value.as_array())
        .ok_or(RpcError::InvalidParams("psbts must be an array"))?;
    if array.is_empty() {
        return Err(RpcError::InvalidParams("psbts array must not be empty"));
    }

    let mut iter = array.iter();
    let Some(first_val) = iter.next() else {
        return Err(RpcError::InvalidParams("psbts array must not be empty"));
    };
    let Some(first_str) = first_val.as_str() else {
        return Err(RpcError::InvalidType("each psbt must be a string"));
    };
    let mut psbt = bitcoin::psbt::Psbt::deserialize(&decode_base64(first_str)?)
        .map_err(|_| RpcError::InvalidParams("invalid base64 PSBT"))?;

    for value in iter {
        let Some(s) = value.as_str() else {
            return Err(RpcError::InvalidType("each psbt must be a string"));
        };
        let other = bitcoin::psbt::Psbt::deserialize(&decode_base64(s)?)
            .map_err(|_| RpcError::InvalidParams("invalid base64 PSBT"))?;
        psbt.combine(other)
            .map_err(|err| RpcError::Internal(format!("combine failed: {err}")))?;
    }

    typed_to_sonic(&v31::CombinePsbt(encode_base64(&psbt.serialize())))
}

const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn decode_base64(input: &str) -> Result<Vec<u8>, RpcError> {
    let bytes = input.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
        return Err(RpcError::InvalidParams("invalid base64 PSBT"));
    }

    let chunk_count = bytes.len() / 4;
    let mut out = Vec::with_capacity(chunk_count * 3);
    for (index, chunk) in bytes.chunks_exact(4).enumerate() {
        let last = index + 1 == chunk_count;
        let pad2 = chunk[2] == b'=';
        let pad3 = chunk[3] == b'=';
        if chunk[0] == b'=' || chunk[1] == b'=' || pad2 && !pad3 || pad3 && !last {
            return Err(RpcError::InvalidParams("invalid base64 PSBT"));
        }

        let Some(a) = base64_value(chunk[0]) else {
            return Err(RpcError::InvalidParams("invalid base64 PSBT"));
        };
        let Some(b) = base64_value(chunk[1]) else {
            return Err(RpcError::InvalidParams("invalid base64 PSBT"));
        };
        let c = if pad2 {
            0
        } else {
            let Some(value) = base64_value(chunk[2]) else {
                return Err(RpcError::InvalidParams("invalid base64 PSBT"));
            };
            value
        };
        let d = if pad3 {
            0
        } else {
            let Some(value) = base64_value(chunk[3]) else {
                return Err(RpcError::InvalidParams("invalid base64 PSBT"));
            };
            value
        };

        out.push((a << 2) | (b >> 4));
        if !pad2 {
            out.push((b << 4) | (c >> 2));
        }
        if !pad3 {
            out.push((c << 6) | d);
        }
    }

    Ok(out)
}

const fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn encode_base64(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);

        out.push(char::from(BASE64_ALPHABET[usize::from(b0 >> 2)]));
        out.push(char::from(
            BASE64_ALPHABET[usize::from(((b0 & 0b0000_0011) << 4) | (b1 >> 4))],
        ));
        if chunk.len() > 1 {
            out.push(char::from(
                BASE64_ALPHABET[usize::from(((b1 & 0b0000_1111) << 2) | (b2 >> 6))],
            ));
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(char::from(BASE64_ALPHABET[usize::from(b2 & 0b0011_1111)]));
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use alloc::sync::Arc;

    use bitcoin_rs_chain::NodeStatus;
    use bitcoin_rs_mempool::{
        AdmissionOrigin, MempoolEntry, arm_admission_park, reset_admission_park,
    };
    use bitcoin_rs_primitives::{
        Block, BlockHash, Hash256, Header, OutPoint, Tx, TxIn, TxOut, Txid, consensus_bytes,
        encode::double_sha256,
    };
    use bitcoin_rs_utxo::{BlockChanges, UtxoAdd};
    use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, json};
    use std::sync::mpsc;
    use std::thread;

    use super::getrawtransaction;
    use super::hex_encode;
    use crate::Handler;
    use crate::context::{BlockRecord, Context, TxIndexQuery, TxQueryError};
    use crate::error::RpcError;

    /// Minimal one-coinbase-tx fixture block standing in for the chain genesis.
    ///
    /// Identity is self-consistent via `block_hash()`; with a single transaction
    /// the merkle root is its txid, matching consensus layering.
    fn fixture_genesis() -> Block {
        let coinbase = Tx {
            version: 1,
            lock_time: 0,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid::default(), u32::MAX),
                script_sig: vec![0x51; 4],
                sequence: u32::MAX,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 50,
                script_pubkey: vec![0x51],
            }],
        };
        let mut block = Block {
            header: Header {
                version: 1,
                prev_blockhash: BlockHash::default(),
                merkle_root: Hash256::default(),
                time: 0,
                bits: 0,
                nonce: 0,
            },
            txs: vec![coinbase],
        };
        block.header.merkle_root = merkle_root_for(&block.txs);
        block
    }

    /// Test-local merkle root over fixture txids: a single tx contributes its
    /// txid, pairs fold with `double_sha256` over the concatenated 64 bytes,
    /// duplicating the last hash for odd counts, matching consensus.
    fn merkle_root_for(txs: &[Tx]) -> Hash256 {
        let mut layer: Vec<Hash256> = txs.iter().map(|tx| tx.txid().0).collect();
        while layer.len() > 1 {
            if layer.len() % 2 == 1
                && let Some(last) = layer.last().copied()
            {
                layer.push(last);
            }
            layer = layer
                .chunks(2)
                .map(|pair| {
                    let mut concat = [0_u8; 64];
                    concat[..32].copy_from_slice(pair[0].as_byte_array());
                    concat[32..].copy_from_slice(pair[1].as_byte_array());
                    double_sha256(&concat)
                })
                .collect();
        }
        layer.first().copied().unwrap_or_default()
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
            let mut pool = ctx.mempool.pool().write();
            let vsize = u32::try_from(coinbase.vsize())?;
            let entry =
                MempoolEntry::new(Arc::new(coinbase.clone()), vsize, u64::from(vsize), 0, 0);
            pool.insert_entry(entry)?;
        }

        let result = getrawtransaction(&ctx, &json!([txid.to_string()]))?;

        let expected = hex_encode(&consensus_bytes(&coinbase));
        assert_eq!(result.as_str(), Some(expected.as_str()));
        Ok(())
    }

    #[test]
    fn getrawtransaction_checks_mempool_before_failing_txindex()
    -> Result<(), Box<dyn std::error::Error>> {
        struct FailingQuery;

        impl TxIndexQuery for FailingQuery {
            fn transaction(&self, _txid: &Txid) -> Result<Option<Tx>, TxQueryError> {
                Err(TxQueryError::Storage("disk full".into()))
            }

            fn outpoint_value(&self, _outpoint: &OutPoint) -> Result<Option<u64>, TxQueryError> {
                Ok(None)
            }

            fn index_info(&self) -> Result<crate::context::TxIndexInfo, TxQueryError> {
                Ok(crate::context::TxIndexInfo {
                    synced: false,
                    best_block_height: 0,
                })
            }
        }

        let mut ctx = Context::new();
        ctx.tx_index = Some(Arc::new(FailingQuery));
        let ctx = Arc::new(ctx);
        let genesis = fixture_genesis();
        let coinbase = genesis
            .txs
            .first()
            .ok_or_else(|| RpcError::Internal("genesis has no transactions".to_owned()))?
            .clone();
        let txid = coinbase.txid();
        {
            let mut pool = ctx.mempool.pool().write();
            let vsize = u32::try_from(coinbase.vsize())?;
            let entry =
                MempoolEntry::new(Arc::new(coinbase.clone()), vsize, u64::from(vsize), 0, 0);
            pool.insert_entry(entry)?;
        }

        let result = getrawtransaction(&ctx, &json!([txid.to_string()]))?;

        let expected = hex_encode(&consensus_bytes(&coinbase));
        assert_eq!(result.as_str(), Some(expected.as_str()));
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
        ctx.block_tree
            .write()
            .insert_node(None, genesis.header, NodeStatus::Active)
            .expect("insert genesis header");
        ctx.add_block(BlockRecord::from_block(0, &genesis));
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
    fn getrawtransaction_resolves_confirmed_transaction_from_txindex_without_cache() {
        struct StaticQuery {
            tx: Tx,
        }

        impl TxIndexQuery for StaticQuery {
            fn transaction(&self, txid: &Txid) -> Result<Option<Tx>, TxQueryError> {
                Ok((self.tx.txid() == *txid).then(|| self.tx.clone()))
            }

            fn outpoint_value(&self, _outpoint: &OutPoint) -> Result<Option<u64>, TxQueryError> {
                Ok(None)
            }

            fn index_info(&self) -> Result<crate::context::TxIndexInfo, TxQueryError> {
                Ok(crate::context::TxIndexInfo {
                    synced: true,
                    best_block_height: 1,
                })
            }
        }

        let genesis = fixture_genesis();
        let Some(coinbase) = genesis.txs.first().cloned() else {
            panic!("genesis has no transactions");
        };
        let txid = coinbase.txid();
        let mut ctx = Context::new();
        ctx.tx_index = Some(Arc::new(StaticQuery {
            tx: coinbase.clone(),
        }));
        let ctx = Arc::new(ctx);

        assert!(
            ctx.transactions.read().is_empty(),
            "confirmed transaction cache must stay empty"
        );
        let result = getrawtransaction(&ctx, &json!([txid.to_string()]))
            .unwrap_or_else(|err| panic!("txindex lookup failed: {err}"));

        let expected = hex_encode(&consensus_bytes(&coinbase));
        assert_eq!(result.as_str(), Some(expected.as_str()));
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
        ctx.block_tree
            .write()
            .insert_node(None, genesis.header, NodeStatus::Active)
            .expect("insert genesis header");
        ctx.add_block(record);

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
        ctx.block_tree
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
        ctx.block_body_source = Some(Arc::new(ScriptedBodySource {
            responses: parking_lot::Mutex::new(std::collections::VecDeque::from([
                None,
                Some(consensus_bytes(&genesis)),
            ])),
        }));
        ctx.add_block(BlockRecord::from_block(0, &genesis));
        ctx.add_block(BlockRecord::from_block(0, &genesis));
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
        struct PanicBodySource;

        impl crate::context::BlockBodySource for PanicBodySource {
            fn block_body(&self, height: u32, hash: BlockHash) -> Option<Vec<u8>> {
                panic!("specified blockhash proof should not load unrelated body {height}:{hash}");
            }
        }

        let genesis = fixture_genesis();
        let Some(coinbase) = genesis.txs.first() else {
            panic!("genesis has no transactions");
        };
        let txid = coinbase.txid();
        let unrelated_hash = BlockHash::from(Hash256::from_le_bytes(&[7_u8; 32]));
        let record = BlockRecord::from_block(0, &genesis);
        let block_hash = record.hash;
        let mut ctx = Context::new().with_block_body_source(Arc::new(PanicBodySource));
        ctx.block_body_source = Some(Arc::new(SeededBodySource {
            bodies: vec![(0, record.hash, consensus_bytes(&genesis))],
        }));
        ctx.block_tree
            .write()
            .insert_node(None, genesis.header, NodeStatus::Active)
            .expect("insert genesis header");
        ctx.add_block(BlockRecord::synthetic(0, unrelated_hash));
        ctx.add_block(record);
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
        ctx.block_tree
            .write()
            .insert_node(None, genesis.header, NodeStatus::Active)
            .expect("insert genesis header");
        let block_hash = record.hash;
        ctx.add_block(record);
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
        ctx.block_tree
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

    /// Builds a block distinguishable from the blocks of other markers: the
    /// coinbase script makes the txid differ, and the merkle root is recomputed
    /// so `verifytxoutproof` can still extract matches from a proof over it.
    fn distinct_block(marker: u8) -> Block {
        let mut block = fixture_genesis();
        if let Some(input) = block.txs.first_mut().and_then(|tx| tx.inputs.first_mut()) {
            input.script_sig = vec![marker; 4];
        }
        block.header.merkle_root = merkle_root_for(&block.txs);
        block
    }

    /// Adds a second transaction so one block can hold two wanted txids.
    fn block_with_two_txs(marker: u8) -> Block {
        let mut block = distinct_block(marker);
        // The extra tx must carry at least one input: the gettxoutproof path
        // round-trips block bytes through the sanctioned rust-bitcoin
        // MerkleBlock seam, whose decoder rejects input-less transactions.
        let extra = Tx {
            version: 2,
            lock_time: 0,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[marker; 32])), 0),
                script_sig: Vec::new(),
                sequence: u32::MAX,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 1_000 + u64::from(marker),
                script_pubkey: vec![0x51],
            }],
        };
        block.txs.push(extra);
        block.header.merkle_root = merkle_root_for(&block.txs);
        block
    }

    /// Stands in for the txindex, answering only the query these tests are about.
    ///
    /// `gettxoutproof` calls nothing else on `TxIndexQuery`, so the other three
    /// methods answer emptily and every probe behaviour these tests need — a
    /// fixed height, a selective one, an error, a panic, a counter — is the
    /// closure rather than another stub type.
    struct HeightQuery<F>(F);

    impl<F> TxIndexQuery for HeightQuery<F>
    where
        F: Fn(&Txid) -> Result<Option<u32>, TxQueryError> + Send + Sync,
    {
        fn transaction(&self, _txid: &Txid) -> Result<Option<Tx>, TxQueryError> {
            Ok(None)
        }

        fn outpoint_value(&self, _outpoint: &OutPoint) -> Result<Option<u64>, TxQueryError> {
            Ok(None)
        }

        fn index_info(&self) -> Result<crate::context::TxIndexInfo, TxQueryError> {
            Ok(crate::context::TxIndexInfo {
                synced: true,
                best_block_height: 0,
            })
        }

        fn transaction_height(&self, txid: &Txid) -> Result<Option<u32>, TxQueryError> {
            (self.0)(txid)
        }
    }

    /// Resolves only the txids it was told about, so a probe can be made to miss.
    fn resolving(
        resolvable: Vec<(Txid, u32)>,
    ) -> impl Fn(&Txid) -> Result<Option<u32>, TxQueryError> {
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

    impl crate::context::BlockBodySource for PanicUnlessBodySource {
        fn block_body(&self, height: u32, hash: BlockHash) -> Option<Vec<u8>> {
            if height == self.height && hash == self.hash {
                Some(self.body.clone())
            } else {
                panic!("index path should not load unrelated body {height}:{hash}");
            }
        }
    }

    struct SeededBodySource {
        bodies: Vec<(u32, BlockHash, Vec<u8>)>,
    }

    impl crate::context::BlockBodySource for SeededBodySource {
        fn block_body(&self, height: u32, hash: BlockHash) -> Option<Vec<u8>> {
            self.bodies
                .iter()
                .find(|(h, k, _)| *h == height && *k == hash)
                .map(|(_, _, body)| body.clone())
        }
    }

    #[derive(Default)]
    struct ScriptedBodySource {
        responses: parking_lot::Mutex<std::collections::VecDeque<Option<Vec<u8>>>>,
    }

    impl crate::context::BlockBodySource for ScriptedBodySource {
        fn block_body(&self, _height: u32, _hash: BlockHash) -> Option<Vec<u8>> {
            self.responses.lock().pop_front().flatten()
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
        ctx.block_body_source = Some(Arc::new(SeededBodySource { bodies }));
        for record in records {
            ctx.add_block(record);
        }
    }

    fn context_with_blocks(blocks: &[Block]) -> Arc<Context> {
        let mut ctx = Context::new();
        install_blocks(&mut ctx, blocks);
        Arc::new(ctx)
    }

    fn attach_body_for_block(ctx: &mut Context, block: &Block, height: u32) {
        let record = BlockRecord::from_block(height, block);
        ctx.block_body_source = Some(Arc::new(SeededBodySource {
            bodies: vec![(record.height, record.hash, consensus_bytes(block))],
        }));
    }

    fn proof_for(ctx: &Arc<Context>, txids: &[Txid]) -> Result<sonic_rs::Value, RpcError> {
        let names = txids.iter().map(ToString::to_string).collect::<Vec<_>>();
        super::gettxoutproof(ctx, &json!([names]))
    }

    #[test]

    fn gettxoutproof_index_path_does_not_read_unrelated_block_bodies() {
        // Records without a body force a `BlockBodySource` read, so a scan over
        // them panics; only skipping them entirely keeps this test green.
        let block = distinct_block(3);
        let Some(wanted) = block.txs.first().map(Tx::txid) else {
            panic!("block has no transactions");
        };
        let indexed = BlockRecord::from_block(2, &block);
        let mut ctx = Context::new();
        ctx.tx_index = Some(Arc::new(HeightQuery(|_: &Txid| Ok(Some(2)))));
        ctx.block_body_source = Some(Arc::new(PanicUnlessBodySource {
            height: indexed.height,
            hash: indexed.hash,
            body: consensus_bytes(&block),
        }));
        ctx.add_block(BlockRecord::synthetic(
            0,
            BlockHash::from(Hash256::from_le_bytes(&[7_u8; 32])),
        ));
        ctx.add_block(BlockRecord::synthetic(
            1,
            BlockHash::from(Hash256::from_le_bytes(&[8_u8; 32])),
        ));
        ctx.add_block(indexed);
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
        // The candidate block holds one wanted txid; only the second block holds
        // both. A block chosen from a single txid is a candidate, not a verdict,
        // so pointing the index at the wrong one must still produce the proof.
        let both = block_with_two_txs(9);
        let blocks = [distinct_block(1), both.clone()];
        let wanted = both.txs.iter().map(Tx::txid).collect::<Vec<_>>();

        let scan_ctx = context_with_blocks(&blocks);
        let scanned =
            proof_for(&scan_ctx, &wanted).unwrap_or_else(|err| panic!("scan path failed: {err}"));

        let mut index_ctx = Context::new();
        index_ctx.tx_index = Some(Arc::new(HeightQuery(|_: &Txid| Ok(Some(0)))));
        install_blocks(&mut index_ctx, &blocks);
        let index_ctx = Arc::new(index_ctx);
        let fell_back = proof_for(&index_ctx, &wanted)
            .unwrap_or_else(|err| panic!("fallback path failed: {err}"));

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
        index_ctx.tx_index = Some(Arc::new(HeightQuery(|_: &Txid| Ok(Some(0)))));
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
        ctx.tx_index = Some(Arc::new(HeightQuery(resolving(resolvable))));
        let indexed = BlockRecord::from_block(1, &block);
        ctx.block_body_source = Some(Arc::new(PanicUnlessBodySource {
            height: indexed.height,
            hash: indexed.hash,
            body: consensus_bytes(&block),
        }));
        ctx.add_block(BlockRecord::synthetic(
            0,
            BlockHash::from(Hash256::from_le_bytes(&[5_u8; 32])),
        ));
        ctx.add_block(indexed);
        let ctx = Arc::new(ctx);

        let result = proof_for(&ctx, &wanted);

        assert!(
            result.as_ref().is_ok_and(|value| value.as_str().is_some()),
            "several txids in one block should resolve through the index: {result:?}"
        );
    }

    #[test]
    fn gettxoutproof_probes_every_txid_before_giving_up_on_the_index() {
        // `wanted` is a HashSet, so which txid is probed first is whatever the
        // hasher yields. Making only the *second*-added txid resolvable pins that
        // an unresolvable probe does not by itself drop the call into the scan —
        // the scan here would panic.
        let block = block_with_two_txs(12);
        let wanted = block.txs.iter().map(Tx::txid).collect::<Vec<_>>();
        let Some(only_one) = wanted.last().copied() else {
            panic!("block has no transactions");
        };

        let mut ctx = Context::new();
        ctx.tx_index = Some(Arc::new(HeightQuery(resolving(vec![(only_one, 1)]))));
        let indexed = BlockRecord::from_block(1, &block);
        ctx.block_body_source = Some(Arc::new(PanicUnlessBodySource {
            height: indexed.height,
            hash: indexed.hash,
            body: consensus_bytes(&block),
        }));
        ctx.add_block(BlockRecord::synthetic(
            0,
            BlockHash::from(Hash256::from_le_bytes(&[6_u8; 32])),
        ));
        ctx.add_block(indexed);
        let ctx = Arc::new(ctx);

        let result = proof_for(&ctx, &wanted);

        assert!(
            result.as_ref().is_ok_and(|value| value.as_str().is_some()),
            "one unresolvable probe must not abandon the index path: {result:?}"
        );
    }

    #[test]
    fn gettxoutproof_falls_back_to_the_scan_when_the_index_errors() {
        // Before this path existed, a broken txindex could not fail this call and
        // the scan answered it. An optimization must not turn a working call into
        // an error.
        //
        // Every variant, not just the interesting-looking ones. `Retry` is the
        // one that matters most: the index reconciles asynchronously, so it is
        // the *routine* answer while the index catches up, and it must not
        // refuse a call the scan can answer today.
        for error in [
            TxQueryError::Retry,
            TxQueryError::Unavailable("worker stopped".into()),
            TxQueryError::Storage("disk full".into()),
        ] {
            let blocks = [distinct_block(1), distinct_block(2)];
            let Some(wanted) = blocks[1].txs.first().map(Tx::txid) else {
                panic!("block has no transactions");
            };

            let scan_ctx = context_with_blocks(&blocks);
            let scanned = proof_for(&scan_ctx, &[wanted])
                .unwrap_or_else(|err| panic!("scan path failed: {err}"));

            let failure = error.clone();
            let mut ctx = Context::new();
            ctx.tx_index = Some(Arc::new(HeightQuery(move |_: &Txid| Err(failure.clone()))));
            install_blocks(&mut ctx, &blocks);
            let ctx = Arc::new(ctx);

            let result = proof_for(&ctx, &[wanted]);

            // Comparing against the scan's answer, not merely asserting that
            // *some* string came back: a failing index must not get to decide
            // what the answer is, only that it is not the one supplying it.
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
        // The explicit-blockhash path is unchanged by this work, and an index
        // that panics on use proves it stays that way.
        let block = distinct_block(4);
        let Some(wanted) = block.txs.first().map(Tx::txid) else {
            panic!("block has no transactions");
        };
        let record = BlockRecord::from_block(0, &block);
        let block_hash = record.hash;
        let mut ctx = Context::new();
        ctx.tx_index = Some(Arc::new(HeightQuery(
            |_: &Txid| -> Result<Option<u32>, TxQueryError> {
                panic!("the explicit-blockhash path must not consult the index");
            },
        )));
        attach_body_for_block(&mut ctx, &block, 0);
        ctx.block_tree
            .write()
            .insert_node(None, block.header, NodeStatus::Active)
            .expect("insert block header");
        ctx.add_block(record);
        let ctx = Arc::new(ctx);

        let result =
            super::gettxoutproof(&ctx, &json!([[wanted.to_string()], block_hash.to_string()]));

        assert!(
            result.as_ref().is_ok_and(|value| value.as_str().is_some()),
            "the explicit-blockhash path should answer without the index: {result:?}"
        );
    }

    /// Counts probes so the loop can be pinned deterministically.
    ///
    /// `probes_every_txid_before_giving_up_on_the_index` pins the *outcome*, but
    /// only probabilistically: `wanted` is a `HashSet`, so a one-probe
    /// implementation happens to pick the resolvable txid about half the time.
    /// Resolving nothing and counting instead is deterministic.
    #[test]
    fn gettxoutproof_asks_the_index_about_every_wanted_txid() {
        let block = block_with_two_txs(13);
        let wanted = block.txs.iter().map(Tx::txid).collect::<Vec<_>>();
        let probes = Arc::new(core::sync::atomic::AtomicUsize::new(0));

        let counter = Arc::clone(&probes);
        let mut ctx = Context::new();
        ctx.tx_index = Some(Arc::new(HeightQuery(move |_: &Txid| {
            counter.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            Ok(None)
        })));
        install_blocks(&mut ctx, std::slice::from_ref(&block));
        let ctx = Arc::new(ctx);

        // Resolves nothing, so this falls through to the scan and still answers.
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

    /// Pins that a candidate block failing verification does not end the walk.
    ///
    /// `falls_back_when_the_indexed_block_lacks_some_wanted_txids` pins the
    /// outcome, but its index answers the same height for every probe, so
    /// "keeps probing after a failed candidate" and "gives up on the first
    /// candidate" reach the same place: the fallback scan, which answers either
    /// way. Counting probes separates them — a walk that returns whatever the
    /// first candidate produced asks exactly once.
    #[test]
    fn gettxoutproof_keeps_probing_after_a_candidate_block_fails_verification() {
        let block = block_with_two_txs(14);
        let wanted = block.txs.iter().map(Tx::txid).collect::<Vec<_>>();
        let probes = Arc::new(core::sync::atomic::AtomicUsize::new(0));

        let counter = Arc::clone(&probes);
        // Every probe names height 0, whose block holds none of the wanted
        // txids, so every candidate fails verification.
        let mut ctx = Context::new();
        ctx.tx_index = Some(Arc::new(HeightQuery(move |_: &Txid| {
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

    /// Pins that the block-record lock is released before each body load.
    ///
    /// The scan reads a block body from disk per record. Holding the log's
    /// `RwLock` across that would stall block application for the whole scan,
    /// and cloning the log to avoid it copies every record on the chain — about
    /// 160 MB at a mainnet tip. The walk does neither, and this proves it: the
    /// body source tries to take the write lock, which can only succeed if the
    /// scan is not holding a read guard.
    #[test]
    fn scan_does_not_hold_the_block_log_lock_across_a_body_load() {
        struct LockProbeSource {
            blocks: Arc<parking_lot::RwLock<crate::context::BlockLog>>,
            bodies: Vec<(u32, Vec<u8>)>,
        }

        impl crate::context::BlockBodySource for LockProbeSource {
            fn block_body(&self, height: u32, _hash: BlockHash) -> Option<Vec<u8>> {
                assert!(
                    self.blocks.try_write().is_some(),
                    "the block-record lock must not be held across a body load"
                );
                self.bodies
                    .iter()
                    .find(|(known, _)| *known == height)
                    .map(|(_, bytes)| bytes.clone())
            }
        }

        let blocks = [distinct_block(21), distinct_block(22), distinct_block(23)];
        let Some(wanted) = blocks[2].txs.first().map(Tx::txid) else {
            panic!("block has no transactions");
        };

        let ctx = Context::new();
        let log = Arc::clone(&ctx.blocks);
        let bodies = blocks
            .iter()
            .enumerate()
            .map(|(height, block)| {
                let height = u32::try_from(height).unwrap_or_else(|err| panic!("height: {err}"));
                (height, consensus_bytes(block))
            })
            .collect::<Vec<_>>();
        let ctx = Arc::new(ctx.with_block_body_source(Arc::new(LockProbeSource {
            blocks: log,
            bodies,
        })));

        // Body-less records, so every body must come from the source above.
        for (height, block) in blocks.iter().enumerate() {
            let height = u32::try_from(height).unwrap_or_else(|err| panic!("height: {err}"));
            let hash = block.block_hash();
            ctx.add_block(BlockRecord::synthetic(height, hash));
        }

        let result = proof_for(&ctx, &[wanted]);

        assert!(
            result.as_ref().is_ok_and(|value| value.as_str().is_some()),
            "the scan should answer from the body source: {result:?}"
        );
    }

    /// `P2WSH(OP_TRUE)`: a version-0 push-32 program whose witness script is a
    /// bare `OP_TRUE`. It is a standard output template, and spendable by a
    /// one-item `[OP_TRUE]` witness, so the retry fixtures chain parent and
    /// child generations without signature material.
    fn retry_spendable_script() -> Vec<u8> {
        let mut script = vec![0x00, 0x20];
        script.extend_from_slice(&[
            0x4a, 0xe8, 0x15, 0x72, 0xf0, 0x6e, 0x1b, 0x88, 0xfd, 0x5c, 0xed, 0x7a, 0x1a, 0x00,
            0x09, 0x45, 0x43, 0x2e, 0x83, 0xe1, 0x55, 0x1e, 0x6f, 0x72, 0x1e, 0xe9, 0xc0, 0x0b,
            0x8c, 0xc3, 0x32, 0x60,
        ]);
        script
    }

    /// Funds a UTXO in the context's UTXO set and returns the outpoint.
    fn retry_fund_utxo(ctx: &Context, label: u8, value: u64) -> OutPoint {
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(
            OutPoint::new(Txid(Hash256::from_le_bytes(&[label; 32])), 0),
            TxOut {
                value,
                script_pubkey: retry_spendable_script(),
            },
            false,
            1,
        ));
        ctx.utxo
            .commit_block(&changes, &Hash256::from_le_bytes(&[0xaa; 32]))
            .unwrap_or_else(|err| panic!("commit_block failed: {err}"));
        OutPoint::new(Txid(Hash256::from_le_bytes(&[label; 32])), 0)
    }

    /// One-input one-output tx spending `prevout` with `output_value` sats.
    fn retry_tx(prevout: OutPoint, output_value: u64) -> Tx {
        Tx {
            version: 2,
            lock_time: 0,
            inputs: vec![TxIn {
                previous_output: prevout,
                script_sig: Vec::new(),
                sequence: 0xffff_ffff,
                witness: vec![vec![0x51]],
            }],
            outputs: vec![TxOut {
                value: output_value,
                script_pubkey: retry_spendable_script(),
            }],
        }
    }

    /// Consensus hex for RPC submission.
    fn retry_raw_hex(tx: &Tx) -> String {
        hex_encode(&consensus_bytes(tx))
    }

    /// Proves `sendrawtransaction` rebuilds admission context on retry: the
    /// first attempt captures context from a mempool state where the child's
    /// parent is absent (missing inputs), parks at the gateway seam, the test
    /// changes the chain generation (forcing `GenerationChanged`) and admits
    /// the parent, then releases the park. The retried attempt must observe
    /// the FRESH mempool state — the parent now provides the child's prevout —
    /// and succeed. If the context were reused from the first attempt (the
    /// r4c3 mutation), the stale `missing_inputs` flag would reject the child.
    #[test]
    fn sendrawtransaction_rebuilds_admission_context_after_transient_rejection() {
        let ctx = Arc::new(Context::new());
        reset_admission_park();

        // Parent spends a confirmed UTXO; child spends the parent's output.
        // The parent output is NOT in the UTXO set, so the child's prevout is
        // only available while the parent is in the mempool.
        let parent_prevout = retry_fund_utxo(&ctx, 0x70, 100_000);
        let parent = retry_tx(parent_prevout, 90_000);
        let parent_txid = parent.txid();
        let child_prevout = OutPoint::new(parent_txid, 0);
        let child = retry_tx(child_prevout, 80_000);
        let child_txid = child.txid();
        let child_hex = retry_raw_hex(&child);

        // Arm the admission park gate: the first `admit_transaction` on this
        // gateway will block before the write lock, signal `parked`, and wait
        // for `release`.
        let (parked_tx, parked_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let target = Arc::as_ptr(&ctx.mempool).expose_provenance();
        arm_admission_park(target, parked_tx, release_rx);

        let ctx_clone = Arc::clone(&ctx);
        let handler = Handler::new(Arc::clone(&ctx));
        let admission =
            thread::spawn(move || handler.dispatch("sendrawtransaction", &json!([child_hex])));

        // Wait for the first attempt to park at the gateway seam.
        parked_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("first admission parked at the gateway seam");

        // While the first attempt is parked (before the write lock, holding
        // no guard), change the chain generation so the first attempt's
        // captured generation token is stale, and admit the parent so the
        // mempool sequence bumps and the parent's output is available.
        let guard = ctx_clone
            .mempool
            .begin_chain_change()
            .expect("begin chain change on even generation");
        guard
            .finish()
            .expect("finish chain change to next even generation");

        let parent_vsize = u32::try_from(parent.vsize()).unwrap_or(u32::MAX);
        ctx_clone
            .mempool
            .insert_entry(
                AdmissionOrigin::Rpc,
                MempoolEntry::new(Arc::new(parent), parent_vsize, 10_000, 0, 1),
            )
            .expect("parent admitted to the mempool");

        // Release the park: the first attempt proceeds, sees the stale
        // generation token, and returns `GenerationChanged` — retrying with
        // fresh facts.
        release_tx.send(()).expect("release the parked admission");

        let result = admission.join().expect("admission thread did not panic");

        reset_admission_park();

        // The retried admission must succeed: the parent is now in the
        // mempool, the child's prevout is available, and the context was
        // rebuilt from the fresh mempool state.
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

        // The child must be in the mempool.
        assert!(
            ctx.mempool.read().contains_txid(&child_txid),
            "the child must be pooled after successful retry"
        );
        // The parent must still be in the mempool.
        assert!(
            ctx.mempool.read().contains_txid(&parent_txid),
            "the parent must remain pooled"
        );
    }
}

#[cfg(test)]
mod gettxout_via_utxo_tests {
    use super::*;

    #[test]
    fn gettxout_returns_null_for_unknown_outpoint() {
        let ctx = Arc::new(Context::new());
        let txid_hex = "a".repeat(64);
        let params = json!([txid_hex.as_str(), 0_u64]);
        let value = gettxout(&ctx, &params).unwrap_or_else(|err| panic!("gettxout failed: {err}"));
        assert!(
            value.is_null(),
            "expected null for unknown outpoint, got {value:?}"
        );
    }

    #[test]
    fn gettxout_returns_null_for_transaction_output_absent_from_utxo() {
        let ctx = Arc::new(Context::new());
        let tx = Tx {
            version: 2,
            lock_time: 0,
            inputs: Vec::new(),
            outputs: vec![TxOut {
                value: 50_000,
                script_pubkey: vec![0x51],
            }],
        };
        let txid = ctx.add_transaction(tx);
        let params = json!([txid.to_string(), 0_u64]);
        let value = gettxout(&ctx, &params).unwrap_or_else(|err| panic!("gettxout failed: {err}"));
        assert!(
            value.is_null(),
            "expected null for output absent from UTXO set, got {value:?}"
        );
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod acceptance_tests {
    use alloc::sync::Arc;

    use bitcoin::hex::DisplayHex as _;
    use bitcoin_rs_chain::{BlockHeader, NodeId, NodeStatus, TipSnapshot};
    use bitcoin_rs_primitives::{
        BlockHash, Hash256, OutPoint, Tx, TxIn, TxOut, Txid, consensus_bytes,
    };
    use bitcoin_rs_utxo::{BlockChanges, UtxoAdd};
    use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, json};

    use super::{sendrawtransaction, testmempoolaccept};
    use crate::context::Context;
    use crate::error::RpcError;

    fn internal_outpoint(tag: u8) -> OutPoint {
        OutPoint::new(Txid(Hash256::from_le_bytes(&[tag; 32])), 0)
    }

    fn spent_outpoint(tag: u8) -> OutPoint {
        OutPoint::new(Txid(Hash256::from_le_bytes(&[tag; 32])), 0)
    }

    /// Seeds one confirmed, anyone-can-spend output worth `value`.
    fn seed_utxo(ctx: &Context, tag: u8, value: u64) {
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(
            internal_outpoint(tag),
            TxOut {
                value,
                script_pubkey: vec![0x51],
            },
            false,
            7,
        ));
        ctx.utxo
            .commit_block(&changes, &Hash256::default())
            .unwrap_or_else(|err| panic!("commit_block failed: {err}"));
    }

    fn spending_tx(tag: u8, output_value: u64) -> Tx {
        Tx {
            version: 2,
            lock_time: 0,
            inputs: vec![TxIn {
                previous_output: spent_outpoint(tag),
                script_sig: Vec::new(),
                sequence: 0xffff_ffff,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: output_value,
                script_pubkey: {
                    let mut out = Vec::with_capacity(25);
                    out.push(0x76); // OP_DUP
                    out.push(0xa9); // OP_HASH160
                    out.push(0x14);
                    out.extend_from_slice(&[9_u8; 20]);
                    out.push(0x88); // OP_EQUALVERIFY
                    out.push(0xac); // OP_CHECKSIG
                    out
                },
            }],
        }
    }

    fn hex_of(tx: &Tx) -> String {
        consensus_bytes(tx).to_lower_hex_string()
    }

    /// The transaction must land in the mempool.
    ///
    /// It previously went into a side `HashMap` that nothing else treated as
    /// the mempool: `getmempoolinfo` reported an empty pool, mining saw no
    /// candidates, and no policy check ran at all.
    #[test]
    fn sendrawtransaction_admits_the_transaction_to_the_mempool() {
        let ctx = Arc::new(Context::new());
        seed_utxo(&ctx, 1, 100_000);
        let tx = spending_tx(1, 90_000);

        let Ok(value) = sendrawtransaction(&ctx, &json!([hex_of(&tx)])) else {
            panic!("a standard transaction spending a confirmed output must be accepted");
        };

        assert_eq!(value.as_str(), Some(tx.txid().to_string().as_str()));
        assert_eq!(ctx.mempool.read().len(), 1, "the pool must hold it");
        assert!(ctx.mempool.read().contains_txid(&tx.txid()));
    }

    /// The default fee guard stops a transaction that burns its change.
    ///
    /// The classic shape: an input worth 1 BTC, an output worth a hundredth of
    /// it, and the rest handed to the miner. Core refuses that by default and
    /// the sender has to say they meant it. This node used to send it, and a
    /// fee is not recoverable once the transaction confirms.
    #[test]
    fn sendrawtransaction_refuses_an_absurd_fee_by_default() {
        let ctx = Arc::new(Context::new());
        seed_utxo(&ctx, 8, 100_000_000);
        // 1 BTC in, 0.01 BTC out: a 0.99 BTC fee on a ~110 vbyte transaction,
        // which is thousands of times the 0.1 BTC/kvB default ceiling.
        let tx = spending_tx(8, 1_000_000);

        let error = sendrawtransaction(&ctx, &json!([hex_of(&tx)]))
            .err()
            .unwrap_or_else(|| panic!("an absurd fee must not be sent by default"));

        assert_eq!(
            error.code(),
            RpcError::INVALID_PARAMS,
            "max-fee-exceeded is a parameter error: {error:?}"
        );
        assert_eq!(ctx.mempool.read().len(), 0, "and nothing was admitted");
    }

    /// The guard is the caller's to lift, and the ceiling is a *rate*.
    ///
    /// Zero disables it outright. Any other value is BTC per kvB, turned into
    /// an absolute fee for this transaction's vsize -- so 0.99 BTC/kvB on a
    /// ~110-vbyte transaction is a ceiling near 0.109 BTC, and a 0.99 BTC fee
    /// is still far above it. Reading the argument as an absolute cap would
    /// send that transaction.
    #[test]
    fn the_fee_ceiling_is_a_rate_and_zero_disables_it() {
        let disabled = {
            let ctx = Arc::new(Context::new());
            seed_utxo(&ctx, 9, 100_000_000);
            let tx = spending_tx(9, 1_000_000);
            let sent = sendrawtransaction(&ctx, &json!([hex_of(&tx), 0]));
            assert_eq!(ctx.mempool.read().len(), 1, "zero sends it: {sent:?}");
            sent
        };
        assert!(disabled.is_ok(), "{disabled:?}");

        let ctx = Arc::new(Context::new());
        seed_utxo(&ctx, 12, 100_000_000);
        let tx = spending_tx(12, 1_000_000);
        let error = sendrawtransaction(&ctx, &json!([hex_of(&tx), 0.99]))
            .err()
            .unwrap_or_else(|| panic!("0.99 BTC/kvB is a ceiling, not a fee allowance"));
        assert_eq!(error.code(), RpcError::INVALID_PARAMS, "{error:?}");
        assert_eq!(ctx.mempool.read().len(), 0);
    }

    /// A ceiling the transaction stays under changes nothing.
    #[test]
    fn sendrawtransaction_admits_a_fee_below_the_ceiling() {
        let ctx = Arc::new(Context::new());
        seed_utxo(&ctx, 10, 100_000);
        // A ~10_000 sat fee on ~110 vbytes, well under the default ceiling.
        let tx = spending_tx(10, 90_000);

        let sent = sendrawtransaction(&ctx, &json!([hex_of(&tx)]));

        assert!(sent.is_ok(), "an ordinary fee is not capped: {sent:?}");
        assert_eq!(ctx.mempool.read().len(), 1);
    }

    /// Core's `ParseFeeRate` refuses ceilings at or above one whole coin per
    /// kvB, so the parameter itself is invalid no matter how small the fee.
    #[test]
    fn sendrawtransaction_rejects_a_fee_rate_of_a_whole_coin() {
        let ctx = Arc::new(Context::new());
        seed_utxo(&ctx, 11, 100_000);
        let tx = spending_tx(11, 90_000);

        let error = sendrawtransaction(&ctx, &json!([hex_of(&tx), 1.0]))
            .err()
            .unwrap_or_else(|| panic!("1 BTC/kvB is not an accepted ceiling"));

        assert_eq!(error.code(), RpcError::INVALID_PARAMS, "{error:?}");
        assert_eq!(ctx.mempool.read().len(), 0, "nothing admitted: {error:?}");
    }

    /// A rejection must say why, under Core's `RPC_VERIFY_REJECTED` code.
    #[test]
    fn sendrawtransaction_rejects_a_transaction_whose_inputs_do_not_exist() {
        let ctx = Arc::new(Context::new());
        let tx = spending_tx(4, 90_000);

        let outcome = sendrawtransaction(&ctx, &json!([hex_of(&tx)]));

        let Err(error) = outcome else {
            panic!("a transaction with no resolvable inputs must not be accepted");
        };
        assert!(
            matches!(error, RpcError::TxRejected(_)),
            "expected a rejection, got {error:?}"
        );
        assert_eq!(error.code(), RpcError::CORE_VERIFY_REJECTED);
        assert!(ctx.mempool.read().is_empty());
    }

    /// A transaction with duplicate inputs must be rejected by consensus
    /// verification, not admitted to the mempool.
    #[test]
    fn sendrawtransaction_rejects_a_transaction_with_duplicate_inputs() {
        let ctx = Arc::new(Context::new());
        seed_utxo(&ctx, 1, 100_000);
        let prev = spent_outpoint(1);
        let tx = Tx {
            version: 2,
            lock_time: 0,
            inputs: vec![
                TxIn {
                    previous_output: prev,
                    script_sig: Vec::new(),
                    sequence: 0xffff_ffff,
                    witness: Vec::new(),
                },
                TxIn {
                    previous_output: prev,
                    script_sig: Vec::new(),
                    sequence: 0xffff_ffff,
                    witness: Vec::new(),
                },
            ],
            outputs: vec![TxOut {
                value: 90_000,
                script_pubkey: vec![0x51],
            }],
        };

        let outcome = sendrawtransaction(&ctx, &json!([hex_of(&tx)]));

        let Err(error) = outcome else {
            panic!("a transaction with duplicate inputs must not be accepted");
        };
        assert!(
            matches!(error, RpcError::TxRejected(_)),
            "expected a rejection, got {error:?}"
        );
        assert!(ctx.mempool.read().is_empty());
    }

    /// Core rebroadcasts rather than failing, and callers retry on a dropped
    #[test]
    fn sendrawtransaction_is_idempotent_for_a_transaction_already_in_the_pool() {
        let ctx = Arc::new(Context::new());
        seed_utxo(&ctx, 1, 100_000);
        let tx = spending_tx(1, 90_000);
        let params = json!([hex_of(&tx)]);
        let Ok(first) = sendrawtransaction(&ctx, &params) else {
            panic!("the first submission must succeed");
        };

        let Ok(second) = sendrawtransaction(&ctx, &params) else {
            panic!("resubmitting a transaction already in the mempool must not fail");
        };

        assert_eq!(first.as_str(), second.as_str());
        assert_eq!(ctx.mempool.read().len(), 1, "it must not be inserted twice");
    }

    /// The verdict must come from the acceptance checks.
    ///
    /// This RPC used to answer `allowed: true` for anything that merely
    /// decoded, so a transaction spending outputs that do not exist was
    /// reported as acceptable.
    #[test]
    fn testmempoolaccept_rejects_a_transaction_that_only_decodes() {
        let ctx = Arc::new(Context::new());
        let tx = spending_tx(4, 90_000);

        let Ok(value) = testmempoolaccept(&ctx, &json!([[hex_of(&tx)]])) else {
            panic!("testmempoolaccept must answer");
        };

        let Some(rows) = value.as_array() else {
            panic!("testmempoolaccept must return an array");
        };
        let Some(row) = rows.first() else {
            panic!("one transaction in, one row out");
        };
        assert_eq!(row.get("allowed").as_bool(), Some(false));
        assert!(
            row.get("reject-reason")
                .as_str()
                .is_some_and(|r| !r.is_empty()),
            "a rejection must carry a reason"
        );
    }

    #[test]
    fn testmempoolaccept_allows_a_transaction_without_admitting_it() {
        let ctx = Arc::new(Context::new());
        seed_utxo(&ctx, 1, 100_000);
        let tx = spending_tx(1, 90_000);

        let Ok(value) = testmempoolaccept(&ctx, &json!([[hex_of(&tx)]])) else {
            panic!("testmempoolaccept must answer");
        };

        let Some(row) = value.as_array().and_then(|rows| rows.first()) else {
            panic!("one transaction in, one row out");
        };
        assert_eq!(row.get("allowed").as_bool(), Some(true));
        assert_eq!(
            row.get("vsize").as_u64(),
            Some(tx.vsize()),
            "vsize must be the transaction's, not a placeholder"
        );
        assert!(
            ctx.mempool.read().is_empty(),
            "testing acceptance must not accept"
        );
    }

    /// `wtxid` was a copy of `txid`. They differ for any witness transaction,
    /// and package relay identifies transactions by the witness id.
    #[test]
    fn testmempoolaccept_reports_the_witness_txid() {
        let ctx = Arc::new(Context::new());
        let mut tx = spending_tx(4, 90_000);
        tx.inputs[0].witness.push(vec![1_u8; 8]);
        assert_ne!(
            tx.txid().to_string(),
            tx.wtxid().to_string(),
            "the fixture must carry a witness or this proves nothing"
        );

        let Ok(value) = testmempoolaccept(&ctx, &json!([[hex_of(&tx)]])) else {
            panic!("testmempoolaccept must answer");
        };

        let Some(row) = value.as_array().and_then(|rows| rows.first()) else {
            panic!("one transaction in, one row out");
        };
        assert_eq!(
            row.get("txid").as_str(),
            Some(tx.txid().to_string().as_str())
        );
        assert_eq!(
            row.get("wtxid").as_str(),
            Some(tx.wtxid().to_string().as_str())
        );
    }

    /// Standardness is relay policy, enforced on mainnet.
    ///
    /// The mempool crate tests the gate itself; this covers the wiring that
    /// passes the policy through. Network-based relaxation (regtest) is not
    /// wired in the admission path yet — see the `require_standard` field
    /// gap in `PackageTxContext` / `evaluate_one`.
    #[test]
    fn standardness_is_enforced_on_mainnet() {
        let mainnet = Arc::new(Context::new());
        assert_eq!(
            mainnet.chain_network,
            bitcoin_rs_primitives::Network::Mainnet,
            "the fixture assumes the default context is mainnet"
        );
        seed_utxo(&mainnet, 1, 100_000);
        let mut tx = spending_tx(1, 90_000);
        // Consensus-valid, non-standard.
        tx.version = 4;
        assert!(
            sendrawtransaction(&mainnet, &json!([hex_of(&tx)])).is_err(),
            "mainnet must enforce standardness"
        );
    }
    /// Builds a 12-header chain in `ctx.block_tree`, with the applied tip 6
    /// blocks behind the header tip, and publishes both tips in `ctx`. Block
    /// times start above the lock-time threshold so the MTP values actually
    /// govern finality for the timestamp-locked transaction under test.
    fn build_divergent_tips(ctx: &Context) -> (u32, u32) {
        const BASE: u32 = 500_000_000;
        const STEP: u32 = 600;

        let mut ids = Vec::new();
        {
            let mut tree = ctx.block_tree.write();
            let mut prev_id: Option<NodeId> = None;
            for height in 0..=11_u32 {
                let prev_hash = match prev_id {
                    Some(id) => tree.node(id).expect("parent node exists").hash,
                    None => Hash256::default(),
                };
                let header = BlockHeader {
                    version: 1,
                    prev_blockhash: BlockHash::from(prev_hash),
                    merkle_root: Hash256::default(),
                    time: BASE + STEP * height,
                    bits: 0x207f_ffff,
                    nonce: 0,
                };
                let id = tree
                    .insert_node(prev_id, header, NodeStatus::HeaderValid)
                    .unwrap_or_else(|err| panic!("insert header {height}: {err}"));
                ids.push(id);
                prev_id = Some(id);
            }
        }

        let (applied_hash, best_hash) = {
            let tree = ctx.block_tree.read();
            let applied_id = ids[10];
            let best_id = ids[11];
            let applied_node = tree.node(applied_id).expect("applied node exists");
            let best_node = tree.node(best_id).expect("best node exists");
            ctx.set_applied_tip(TipSnapshot {
                tip_id: applied_id,
                height: applied_node.height,
                chainwork: applied_node.chainwork,
                hash: applied_node.hash,
            });
            ctx.set_chain_tip(TipSnapshot {
                tip_id: best_id,
                height: best_node.height,
                chainwork: best_node.chainwork,
                hash: best_node.hash,
            });
            (applied_node.hash, best_node.hash)
        };

        (
            ctx.median_time_past_for_hash(applied_hash)
                .expect("applied MTP exists"),
            ctx.median_time_past_for_hash(best_hash)
                .expect("best MTP exists"),
        )
    }

    /// `sendrawtransaction` must take the BIP113 median-time-past from the
    /// applied tip, not a header tip that has run ahead. A timestamp-locked
    /// transaction that is final only under the header-tip MTP must be
    /// rejected.
    #[test]
    fn sendrawtransaction_rejects_tx_final_only_under_header_tip_mtp() {
        const BASE: u32 = 500_000_000;
        let ctx = Arc::new(Context::new());
        let (applied_mtp, best_mtp) = build_divergent_tips(&ctx);

        assert!(
            applied_mtp < best_mtp,
            "fixture: header-tip MTP must exceed applied-tip MTP"
        );

        let lock_time = BASE + 3_300;
        assert!(
            applied_mtp < lock_time && lock_time < best_mtp,
            "fixture: lock time must sit between the two MTPs"
        );

        seed_utxo(&ctx, 1, 100_000);
        let mut tx = spending_tx(1, 90_000);
        tx.lock_time = lock_time;
        tx.inputs[0].sequence = 0xFFFF_FFFE; // non-final

        let result = sendrawtransaction(&ctx, &json!([hex_of(&tx)]));
        assert!(
            result.is_err(),
            "a tx final only under the header-tip MTP must be rejected; got {result:?}"
        );
        assert_eq!(
            ctx.mempool.read().len(),
            0,
            "rejected tx must not enter the pool"
        );
        assert_eq!(
            ctx.transactions.read().len(),
            0,
            "rejected tx must not be recorded as accepted"
        );
    }
}

#[cfg(test)]
mod combinepsbt_tests {
    use alloc::sync::Arc;

    use sonic_rs::JsonValueTrait as _;

    use super::*;

    fn empty_psbt_str() -> String {
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: Vec::new(),
            output: Vec::new(),
        };
        let psbt = bitcoin::psbt::Psbt::from_unsigned_tx(tx)
            .unwrap_or_else(|err| panic!("from_unsigned_tx: {err}"));
        encode_base64(&psbt.serialize())
    }

    #[test]
    fn combinepsbt_single_input_returns_same_psbt() {
        let ctx = Arc::new(Context::new());
        let psbt_str = empty_psbt_str();
        let result = combinepsbt(&ctx, &json!([[psbt_str.as_str()]]))
            .unwrap_or_else(|err| panic!("combinepsbt: {err}"));
        let Some(out) = result.as_str() else {
            panic!("expected string: {result:?}");
        };
        assert_eq!(out, psbt_str);
    }

    #[test]
    fn combinepsbt_empty_array_errors() {
        let ctx = Arc::new(Context::new());
        let result = combinepsbt(&ctx, &json!([[]]));
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod finalizepsbt_tests {
    use alloc::sync::Arc;

    use bitcoin::hashes::Hash as _;
    use bitcoin::sighash::SighashCache;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
    use sonic_rs::JsonValueTrait as _;

    use super::*;

    fn empty_psbt() -> String {
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: Vec::new(),
            output: Vec::new(),
        };
        let psbt =
            bitcoin::psbt::Psbt::from_unsigned_tx(tx).unwrap_or_else(|err| panic!("psbt: {err}"));
        encode_base64(&psbt.serialize())
    }

    #[test]
    fn finalizepsbt_returns_incomplete_for_unfinalized_inputs() {
        let ctx = Arc::new(Context::new());
        let raw = empty_psbt();
        let result = finalizepsbt(&ctx, &json!([raw.as_str()]))
            .unwrap_or_else(|err| panic!("finalizepsbt failed: {err}"));
        let Some(complete) = result.get("complete").and_then(Value::as_bool) else {
            panic!("complete missing: {result:?}");
        };
        assert!(!complete);
        assert!(result.get("hex").is_none_or(Value::is_null));
        assert!(result.get("psbt").and_then(Value::as_str).is_some());
    }

    fn signed_p2wpkh_psbts() -> (String, String) {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let secret = bitcoin::secp256k1::SecretKey::from_slice(&[7_u8; 32])
            .unwrap_or_else(|err| panic!("secret key: {err}"));
        let public_key = bitcoin::PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(
            &secp, &secret,
        ));
        let witness_hash = public_key
            .wpubkey_hash()
            .unwrap_or_else(|err| panic!("compressed public key: {err}"));
        let prevout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::new_p2wpkh(&witness_hash),
        };
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(bitcoin::Txid::all_zeros(), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(40_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let mut metadata =
            bitcoin::psbt::Psbt::from_unsigned_tx(tx).unwrap_or_else(|err| panic!("psbt: {err}"));
        metadata.inputs[0].witness_utxo = Some(prevout);
        let mut signatures = metadata.clone();
        let mut cache = SighashCache::new(&metadata.unsigned_tx);
        let (message, sighash_type) = metadata
            .sighash_ecdsa(0, &mut cache)
            .unwrap_or_else(|err| panic!("sighash: {err}"));
        signatures.inputs[0].witness_utxo = None;
        signatures.inputs[0].partial_sigs.insert(
            public_key,
            bitcoin::ecdsa::Signature {
                signature: secp.sign_ecdsa(&message, &secret),
                sighash_type,
            },
        );
        (
            encode_base64(&metadata.serialize()),
            encode_base64(&signatures.serialize()),
        )
    }

    #[test]
    fn finalizepsbt_honors_extract_false_for_complete_psbt() {
        let ctx = Arc::new(Context::new());
        let (metadata, signatures) = signed_p2wpkh_psbts();
        let combined = combinepsbt(&ctx, &json!([[metadata, signatures]]))
            .unwrap_or_else(|err| panic!("combinepsbt failed: {err}"));
        let combined = combined
            .as_str()
            .unwrap_or_else(|| panic!("combined PSBT missing: {combined:?}"));
        let result = finalizepsbt(&ctx, &json!([combined, false]))
            .unwrap_or_else(|err| panic!("finalizepsbt failed: {err}"));
        assert_eq!(result.get("complete").and_then(Value::as_bool), Some(true));
        assert!(result.get("hex").is_none_or(Value::is_null));
        assert!(result.get("psbt").and_then(Value::as_str).is_some());
    }

    #[test]
    fn combinepsbt_then_finalizepsbt_extracts_signed_transaction() {
        let ctx = Arc::new(Context::new());
        let (metadata, signatures) = signed_p2wpkh_psbts();
        let combined = combinepsbt(&ctx, &json!([[metadata, signatures]]))
            .unwrap_or_else(|err| panic!("combinepsbt failed: {err}"));
        let combined = combined
            .as_str()
            .unwrap_or_else(|| panic!("combined PSBT missing: {combined:?}"));
        let result = finalizepsbt(&ctx, &json!([combined]))
            .unwrap_or_else(|err| panic!("finalizepsbt failed: {err}"));
        assert_eq!(result.get("complete").and_then(Value::as_bool), Some(true));
        assert!(result.get("psbt").is_none_or(Value::is_null));
        assert!(result.get("hex").and_then(Value::as_str).is_some());
    }
}
