//! Authenticated management-only, key-free pool accounting extensions.
//!
//! BRPR/BRPT bytes are the ledger's canonical codecs. Recording a receipt
//! validates and persists an externally signed transaction; it never broadcasts it.
use pool_ledger::{
    CancelBasis, Hash32, Ledger, LedgerError, MinerId, PayoutBatch, PayoutPolicy, PayoutReceipt,
};
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, Value, json};
use std::sync::Arc;

use crate::{context::Context, error::RpcError};

fn ledger(ctx: &Context) -> Result<&Ledger, RpcError> {
    ctx.pool
        .operator
        .as_ref()
        .map(|owner| owner.ledger())
        .ok_or(RpcError::MethodDisabled("Pool service is disabled"))
}

fn params(params: &Value, min: usize, max: usize) -> Result<&sonic_rs::Array, RpcError> {
    let values = params.as_array().ok_or(RpcError::InvalidParams(
        "Expected positional parameter array",
    ))?;
    if values.len() < min || values.len() > max {
        return Err(RpcError::InvalidParams(
            "Incorrect number of pool parameters",
        ));
    }
    Ok(values)
}

fn number(value: &Value) -> Result<u64, RpcError> {
    value
        .as_u64()
        .ok_or(RpcError::InvalidParams("Expected unsigned integer"))
}

fn bytes(value: &Value, max: usize) -> Result<Vec<u8>, RpcError> {
    let text = value
        .as_str()
        .ok_or(RpcError::InvalidParams("Expected hexadecimal string"))?;
    if text.len() > max.saturating_mul(2) {
        return Err(RpcError::InvalidParams(
            "Hexadecimal payload length is invalid",
        ));
    }
    let (pairs, remainder) = text.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(RpcError::InvalidParams(
            "Hexadecimal payload length is invalid",
        ));
    }
    pairs
        .iter()
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                b'A'..=b'F' => Some(byte - b'A' + 10),
                _ => None,
            };
            digit(pair[0])
                .zip(digit(pair[1]))
                .map(|(a, b)| a * 16 + b)
                .ok_or(RpcError::InvalidParams("Invalid hexadecimal payload"))
        })
        .collect()
}

fn hash(value: &Value) -> Result<Hash32, RpcError> {
    bytes(value, 32)?
        .try_into()
        .map_err(|_| RpcError::InvalidParams("Expected exactly 32 bytes"))
}

fn failure(error: &LedgerError) -> RpcError {
    match error {
        LedgerError::InvalidInput(_)
        | LedgerError::Receipt(_)
        | LedgerError::Codec(_)
        | LedgerError::UnknownBatch(_)
        | LedgerError::IllegalTransition { .. } => RpcError::InvalidParameter(error.to_string()),
        _ => RpcError::Internal(error.to_string()),
    }
}

fn batch(batch: &PayoutBatch) -> Value {
    json!({"batch_id": pool_ledger::to_hex(&batch.id), "sequence": batch.seq,
    "state": match batch.state {
        pool_ledger::BatchState::Prepared => "prepared",
        pool_ledger::BatchState::ExternallySigned => "externally_signed",
        pool_ledger::BatchState::Broadcast => "broadcast",
        pool_ledger::BatchState::Confirmed => "confirmed",
        pool_ledger::BatchState::Cancelled => "cancelled",
        pool_ledger::BatchState::Failed => "failed",
    }, "revision": batch.rev,
    "total_sat": batch.total_sat, "outputs": batch.outputs.iter().map(|output|
        json!({"account": output.account.0, "script_pubkey": pool_ledger::to_hex(&output.script_pubkey),
            "amount_sat": output.amount_sat})).collect::<Vec<_>>(),
    "transactions": batch.transactions.iter().map(|tx| pool_ledger::to_hex(&tx.txid)).collect::<Vec<_>>(),
    "broadcast_txid": batch.broadcast_txid.map(|id| pool_ledger::to_hex(&id)),
    "confirmation": batch.confirmation.map(|value| json!({
        "txid": pool_ledger::to_hex(&value.txid),
        "block_hash": pool_ledger::to_hex(&value.block_hash), "height": value.height})),
    "closure": batch.closure.map(|value| match value {
        pool_ledger::Closure::Cancelled(basis) => json!({
            "state": "cancelled", "basis": match basis {
                CancelBasis::NeverHandedToSigner => "never_handed_to_signer",
                CancelBasis::SignerRevoked => "signer_revoked",
            }}),
        pool_ledger::Closure::Failed { conflicting_txid } => json!({
            "state": "failed", "conflicting_txid": pool_ledger::to_hex(&conflicting_txid)}),
    })})
}

pub(crate) fn registerpoolaccount(ctx: &Arc<Context>, input: &Value) -> Result<Value, RpcError> {
    let ledger = ledger(ctx)?;
    let p = params(input, 2, 2)?;
    let account = MinerId(number(&p[0])?);
    let script = bytes(&p[1], 10_000)?;
    ledger
        .set_payout_script(account, &script)
        .map_err(|error| failure(&error))?;
    Ok(json!({"account": account.0, "script_pubkey": pool_ledger::to_hex(&script)}))
}

pub(crate) fn preparepayoutbatch(ctx: &Arc<Context>, input: &Value) -> Result<Value, RpcError> {
    let ledger = ledger(ctx)?;
    let p = params(input, 3, 3)?;
    let policy = PayoutPolicy {
        min_payout_sat: number(&p[1])?,
        max_outputs: usize::try_from(number(&p[2])?)
            .map_err(|_| RpcError::InvalidParams("Output count out of range"))?,
    };
    let configured = ctx
        .pool
        .operator
        .as_ref()
        .ok_or(RpcError::MethodDisabled("Pool service is disabled"))?
        .payout_policy();
    if policy.min_payout_sat < configured.min_payout_sat
        || policy.max_outputs > configured.max_outputs.min(pool_ledger::MAX_BATCH_OUTPUTS)
    {
        return Err(RpcError::InvalidParameter(
            "Requested payout policy exceeds configured pool limits".to_owned(),
        ));
    }
    let Some(prepared) = ledger
        .prepare_payout_batch(hash(&p[0])?, policy)
        .map_err(|error| failure(&error))?
    else {
        return Ok(Value::new_null());
    };
    let request = ledger
        .request_for(&prepared.id)
        .map_err(|error| failure(&error))?;
    Ok(
        json!({"batch": batch(&prepared), "request": pool_ledger::to_hex(&request.encode().map_err(|error| failure(&error))?)}),
    )
}

pub(crate) fn getpayoutrequest(ctx: &Arc<Context>, input: &Value) -> Result<Value, RpcError> {
    let ledger = ledger(ctx)?;
    let p = params(input, 1, 1)?;
    let request = ledger
        .request_for(&hash(&p[0])?)
        .map_err(|error| failure(&error))?;
    Ok(json!({"batch_id": pool_ledger::to_hex(&request.batch_id),
        "request": pool_ledger::to_hex(&request.encode().map_err(|error| failure(&error))?)}))
}

pub(crate) fn recordpayoutreceipt(ctx: &Arc<Context>, input: &Value) -> Result<Value, RpcError> {
    let ledger = ledger(ctx)?;
    let p = params(input, 1, 1)?;
    let receipt = PayoutReceipt::decode(&bytes(&p[0], pool_ledger::MAX_RAW_TX_BYTES + 128)?)
        .map_err(|error| failure(&error))?;
    Ok(batch(
        &ledger
            .record_signed(&receipt)
            .map_err(|error| failure(&error))?,
    ))
}

pub(crate) fn getpayoutbatch(ctx: &Arc<Context>, input: &Value) -> Result<Value, RpcError> {
    let ledger = ledger(ctx)?;
    let p = params(input, 1, 1)?;
    Ok(ledger
        .batch(&hash(&p[0])?)
        .map_err(|error| failure(&error))?
        .as_ref()
        .map_or_else(Value::new_null, batch))
}

pub(crate) fn cancelpayoutbatch(ctx: &Arc<Context>, input: &Value) -> Result<Value, RpcError> {
    let ledger = ledger(ctx)?;
    let p = params(input, 2, 2)?;
    let basis = match p[1].as_str() {
        Some("never_handed_to_signer") => CancelBasis::NeverHandedToSigner,
        Some("signer_revoked") => CancelBasis::SignerRevoked,
        _ => {
            return Err(RpcError::InvalidParams(
                "Cancellation requires never_handed_to_signer or signer_revoked",
            ));
        }
    };
    Ok(batch(
        &ledger
            .cancel_prepared(&hash(&p[0])?, basis)
            .map_err(|error| failure(&error))?,
    ))
}

pub(crate) fn getpoolbalances(ctx: &Arc<Context>, input: &Value) -> Result<Value, RpcError> {
    let ledger = ledger(ctx)?;
    let p = params(input, 1, 1)?;
    let account = MinerId(number(&p[0])?);
    let balance = ledger.balance(account).map_err(|error| failure(&error))?;
    Ok(
        json!({"account": account.0, "available_sat": balance.available_sat,
        "reserved_sat": balance.reserved_sat, "paid_sat": balance.paid_sat,
        "deficit_sat": balance.deficit_sat,
        "script_pubkey": ledger.payout_script(account).map_err(|error| failure(&error))?.map(|script| pool_ledger::to_hex(&script))}),
    )
}

pub(crate) fn getpoolrounds(ctx: &Arc<Context>, input: &Value) -> Result<Value, RpcError> {
    let ledger = ledger(ctx)?;
    let p = params(input, 1, 2)?;
    let first = number(&p[0])?;
    let count = p.get(1).map(number).transpose()?.unwrap_or(100);
    if first == 0 || count > 1000 {
        return Err(RpcError::InvalidParams(
            "Round start must be positive and count at most 1000",
        ));
    }
    let mut rounds = Vec::new();
    for offset in 0..count {
        let id = first
            .checked_add(offset)
            .ok_or(RpcError::InvalidParams("Round range overflow"))?;
        let Some(round) = ledger.round(id).map_err(|error| failure(&error))? else {
            break;
        };
        rounds.push(json!({"round": round.id, "block_hash": pool_ledger::to_hex(&round.block_hash),
            "height": round.height, "state": match round.state {
                pool_ledger::RoundState::Pending => "pending",
                pool_ledger::RoundState::Immature => "immature",
                pool_ledger::RoundState::Matured => "matured",
                pool_ledger::RoundState::Orphaned => "orphaned",
            },
            "reward_fixed": round.reward_fixed, "gross_sat": round.gross_sat,
            "pool_fee_sat": round.pool_fee_sat, "net_sat": round.net_sat,
            "window_work": round.window_work_total.to_string(), "solving_sequence": round.solving_seq}));
    }
    Ok(json!(rounds))
}

pub(crate) fn getpoolinfo(ctx: &Arc<Context>, input: &Value) -> Result<Value, RpcError> {
    let ledger = ledger(ctx)?;
    params(input, 0, 0)?;
    let audit = ledger.audit_tail(20).map_err(|error| failure(&error))?;
    Ok(json!({"reward_model": "PPLNS", "external_signer": true,
        "window_work": ledger.config().window_work.to_string(),
        "share_count": ledger.share_count().map_err(|error| failure(&error))?,
        "audit_tail": audit.iter().map(|record| json!({"sequence": record.seq,
            "kind": match record.kind {
                pool_ledger::AuditKind::SharesPruned => "shares_pruned",
                pool_ledger::AuditKind::RoundRecorded => "round_recorded",
                pool_ledger::AuditKind::RewardFixed => "reward_fixed",
                pool_ledger::AuditKind::RoundMatured => "round_matured",
                pool_ledger::AuditKind::RoundOrphaned => "round_orphaned",
                pool_ledger::AuditKind::RoundRevived => "round_revived",
                pool_ledger::AuditKind::PayoutScriptSet => "payout_script_set",
                pool_ledger::AuditKind::BatchPrepared => "batch_prepared",
                pool_ledger::AuditKind::BatchSigned => "batch_signed",
                pool_ledger::AuditKind::BatchBroadcast => "batch_broadcast",
                pool_ledger::AuditKind::BatchConfirmed => "batch_confirmed",
                pool_ledger::AuditKind::BatchReverted => "batch_reverted",
                pool_ledger::AuditKind::BatchCancelled => "batch_cancelled",
                pool_ledger::AuditKind::BatchFailed => "batch_failed",
            }, "subject": record.subject,
            "hash": pool_ledger::to_hex(&record.hash), "hash2": pool_ledger::to_hex(&record.hash2),
            "values": record.values, "chain": pool_ledger::to_hex(&record.chain)})).collect::<Vec<_>>() }))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestOperator(Ledger);
    impl crate::context::PoolOperator for TestOperator {
        fn ledger(&self) -> &Ledger {
            &self.0
        }
        fn payout_policy(&self) -> PayoutPolicy {
            PayoutPolicy {
                min_payout_sat: 546,
                max_outputs: 10,
            }
        }
    }

    #[test]
    fn enabled_handlers_use_the_real_durable_ledger() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let store = Arc::new(bitcoin_rs_storage::FjallStore::open(dir.path())?);
        let ledger = Ledger::create(store, pool_ledger::PoolConfig::new(100, vec![0x51]))?;
        let context = Arc::new(Context::from_handles(crate::context::ContextHandles {
            pool: crate::context::PoolHandles {
                operator: Some(Arc::new(TestOperator(ledger))),
            },
            ..crate::context::ContextHandles::default()
        }));
        let registered = registerpoolaccount(&context, &json!([7, "51"]))?;
        assert_eq!(registered["script_pubkey"].as_str(), Some("51"));
        let balance = getpoolbalances(&context, &json!([7]))?;
        assert_eq!(balance["available_sat"].as_u64(), Some(0));
        assert_eq!(balance["script_pubkey"].as_str(), Some("51"));
        assert!(registerpoolaccount(&context, &json!([7, "6a"])).is_err());
        assert!(
            preparepayoutbatch(&context, &json!([pool_ledger::to_hex(&[1; 32]), 545, 10])).is_err()
        );
        assert!(
            preparepayoutbatch(&context, &json!([pool_ledger::to_hex(&[1; 32]), 546, 11])).is_err()
        );
        let empty = preparepayoutbatch(&context, &json!([pool_ledger::to_hex(&[1; 32]), 546, 10]))?;
        assert!(empty.is_null());
        let rounds = getpoolrounds(&context, &json!([1, 10]))?;
        assert_eq!(rounds.as_array().map(sonic_rs::Array::len), Some(0));
        let info = getpoolinfo(&context, &json!([]))?;
        assert_eq!(info["external_signer"].as_bool(), Some(true));
        assert_eq!(
            info["audit_tail"].as_array().map(sonic_rs::Array::len),
            Some(1)
        );
        let unknown = json!([pool_ledger::to_hex(&[2; 32])]);
        assert!(getpayoutbatch(&context, &unknown)?.is_null());
        assert!(getpayoutrequest(&context, &unknown).is_err());
        assert!(
            cancelpayoutbatch(
                &context,
                &json!([pool_ledger::to_hex(&[2; 32]), "never_handed_to_signer"])
            )
            .is_err()
        );
        let receipt = PayoutReceipt {
            batch_id: [2; 32],
            txid: [3; 32],
            raw_tx: vec![0],
        };
        assert!(
            recordpayoutreceipt(&context, &json!([pool_ledger::to_hex(&receipt.encode()?)]))
                .is_err()
        );
        assert_eq!(
            getpoolbalances(&context, &json!([7]))?["reserved_sat"].as_u64(),
            Some(0)
        );
        Ok(())
    }

    struct FundedChain;
    impl pool_ledger::ChainView for FundedChain {
        fn tip_height(&self) -> Result<u32, pool_ledger::ChainViewError> {
            Ok(200)
        }
        fn block_location(
            &self,
            hash: &Hash32,
            _: u32,
        ) -> Result<pool_ledger::BlockLocation, pool_ledger::ChainViewError> {
            Ok(if *hash == [4; 32] {
                pool_ledger::BlockLocation::Canonical { height: 100 }
            } else {
                pool_ledger::BlockLocation::Unknown
            })
        }
        fn coinbase_of(
            &self,
            _: &Hash32,
        ) -> Result<Option<pool_ledger::ObservedCoinbase>, pool_ledger::ChainViewError> {
            Ok(Some(pool_ledger::ObservedCoinbase {
                txid: [5; 32],
                outputs: vec![pool_ledger::TxOut {
                    value_sat: 10_000,
                    script_pubkey: vec![0x51],
                }],
            }))
        }
        fn tx_status(
            &self,
            _: &Hash32,
        ) -> Result<pool_ledger::TxStatus, pool_ledger::ChainViewError> {
            Ok(pool_ledger::TxStatus::Unknown)
        }
        fn confirmed_spender(
            &self,
            _: &pool_ledger::OutPoint,
        ) -> Result<Option<pool_ledger::ConfirmedSpend>, pool_ledger::ChainViewError> {
            Ok(None)
        }
    }

    // Same legacy transaction fixture structure as the ledger suite: one
    // non-null input, empty scriptSig, one exact payout output. No keys or
    // signature-validity claim: the ledger validates payout shape and txid.
    fn legacy_payout_raw_tx() -> Vec<u8> {
        let mut raw = 2i32.to_le_bytes().to_vec();
        raw.push(1);
        raw.extend_from_slice(&[9; 32]);
        raw.extend_from_slice(&0u32.to_le_bytes());
        raw.push(0);
        raw.extend_from_slice(&0xffff_fffdu32.to_le_bytes());
        raw.push(1);
        raw.extend_from_slice(&10_000u64.to_le_bytes());
        raw.extend_from_slice(&[1, 0x51]);
        raw.extend_from_slice(&0u32.to_le_bytes());
        raw
    }

    #[test]
    fn funded_external_payout_round_trip_preserves_reservations_on_rejection()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let store = Arc::new(bitcoin_rs_storage::FjallStore::open(dir.path())?);
        let ledger = Ledger::create(store, pool_ledger::PoolConfig::new(100, vec![0x51]))?;
        ledger.record_found_block(&pool_ledger::BlockFound {
            share: pool_ledger::ShareCredit {
                header_hash: [4; 32],
                job: 1,
                account: MinerId(7),
                extranonce: vec![1],
                nonce: 1,
                work: 100,
            },
            height: 100,
            coinbase_txid: [5; 32],
            claimed_coinbase_value_sat: 10_000,
        })?;
        ledger.reconcile_rounds(&FundedChain)?;
        let context = Arc::new(Context::from_handles(crate::context::ContextHandles {
            pool: crate::context::PoolHandles {
                operator: Some(Arc::new(TestOperator(ledger))),
            },
            ..crate::context::ContextHandles::default()
        }));
        registerpoolaccount(&context, &json!([7, "51"]))?;
        assert_eq!(
            getpoolbalances(&context, &json!([7]))?["available_sat"].as_u64(),
            Some(10_000)
        );
        let prepared =
            preparepayoutbatch(&context, &json!([pool_ledger::to_hex(&[8; 32]), 546, 10]))?;
        let request_hex = prepared["request"].as_str().ok_or("missing BRPR")?;
        let request = pool_ledger::PayoutRequest::decode(&bytes(&json!(request_hex), 100_000)?)?;
        assert_eq!(request.outputs.len(), 1);
        assert_eq!(request.outputs[0].amount_sat, 10_000);
        let batch_id = pool_ledger::to_hex(&request.batch_id);
        assert_eq!(
            getpayoutrequest(&context, &json!([batch_id]))?["request"].as_str(),
            Some(request_hex)
        );
        let reserved = getpoolbalances(&context, &json!([7]))?;
        assert_eq!(reserved["available_sat"].as_u64(), Some(0));
        assert_eq!(reserved["reserved_sat"].as_u64(), Some(10_000));

        let raw = legacy_payout_raw_tx();
        let mut receipt = PayoutReceipt {
            batch_id: request.batch_id,
            txid: [0; 32],
            raw_tx: raw.clone(),
        };
        let before_rejection = getpayoutbatch(&context, &json!([batch_id]))?;
        let rejected =
            recordpayoutreceipt(&context, &json!([pool_ledger::to_hex(&receipt.encode()?)]));
        let error = match rejected {
            Err(error) => error,
            Ok(_) => panic!("mismatched txid must be rejected"),
        };
        assert_eq!(error.code(), -8);
        assert_eq!(error.to_string(), "receipt refused: TxidMismatch");
        assert_eq!(
            getpayoutbatch(&context, &json!([batch_id]))?,
            before_rejection
        );
        assert_eq!(getpoolbalances(&context, &json!([7]))?, reserved);
        assert_eq!(
            getpayoutbatch(&context, &json!([batch_id]))?["state"].as_str(),
            Some("prepared")
        );
        receipt.txid = pool_ledger::sha256d(&raw);
        let accepted =
            recordpayoutreceipt(&context, &json!([pool_ledger::to_hex(&receipt.encode()?)]))?;
        assert_eq!(accepted["state"].as_str(), Some("externally_signed"));
        assert_eq!(getpoolbalances(&context, &json!([7]))?, reserved);
        let refused = cancelpayoutbatch(&context, &json!([batch_id, "signer_revoked"]));
        let error = match refused {
            Err(error) => error,
            Ok(_) => panic!("signed batch must not cancel"),
        };
        assert_eq!(error.code(), -8);
        assert_eq!(
            error.to_string(),
            format!("batch {batch_id} in state ExternallySigned cannot cancel")
        );
        assert_eq!(getpayoutbatch(&context, &json!([batch_id]))?, accepted);
        assert_eq!(
            getpayoutbatch(&context, &json!([batch_id]))?["state"].as_str(),
            Some("externally_signed")
        );
        assert_eq!(getpoolbalances(&context, &json!([7]))?, reserved);
        assert_eq!(
            recordpayoutreceipt(&context, &json!([pool_ledger::to_hex(&receipt.encode()?)]))?,
            accepted
        );
        Ok(())
    }

    #[test]
    fn disabled_pool_never_returns_fabricated_success() {
        let context = Arc::new(Context::new());
        let input = json!([]);
        for handler in [
            registerpoolaccount,
            preparepayoutbatch,
            getpayoutrequest,
            recordpayoutreceipt,
            getpayoutbatch,
            cancelpayoutbatch,
            getpoolbalances,
            getpoolrounds,
            getpoolinfo,
        ] {
            assert!(matches!(
                handler(&context, &input),
                Err(RpcError::MethodDisabled(_))
            ));
        }
    }

    #[test]
    fn hexadecimal_payload_is_strict_and_bounded() {
        assert_eq!(bytes(&json!("00aAfF"), 3).ok(), Some(vec![0, 170, 255]));
        for input in [json!("0"), json!("gg"), json!("0000"), json!(12)] {
            assert!(bytes(&input, 1).is_err());
        }
        assert!(hash(&json!("00")).is_err());
    }

    #[test]
    fn rejects_named_extra_and_negative_parameters() {
        assert!(params(&json!({"account": 1}), 1, 1).is_err());
        assert!(params(&json!([1, 2]), 1, 1).is_err());
        assert!(number(&json!(-1)).is_err());
        assert!(number(&json!(1.5)).is_err());
    }

    #[test]
    fn external_receipt_hex_preserves_canonical_brpt_and_rejects_trailing_bytes() {
        let receipt = PayoutReceipt {
            batch_id: [1; 32],
            txid: [2; 32],
            raw_tx: vec![3, 4],
        };
        let Ok(encoded) = receipt.encode() else {
            panic!("bounded receipt must encode");
        };
        assert_eq!(&encoded[..5], b"BRPT\x01");
        let encoded_hex = json!(pool_ledger::to_hex(&encoded));
        let Ok(decoded_hex) = bytes(&encoded_hex, pool_ledger::MAX_RAW_TX_BYTES + 128) else {
            panic!("canonical hex must decode");
        };
        assert_eq!(PayoutReceipt::decode(&decoded_hex).ok(), Some(receipt));
        let mut trailing = decoded_hex;
        trailing.push(0);
        assert!(PayoutReceipt::decode(&trailing).is_err());
    }

    #[test]
    fn receipt_uses_the_ledger_codec_not_raw_transaction_hex() {
        assert!(PayoutReceipt::decode(&[1, 0, 0, 0]).is_err());
    }
}
