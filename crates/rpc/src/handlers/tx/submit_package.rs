//! submitpackage wire boundary; admission and all mutations stay in mempool.

use super::*;
use bitcoin_rs_mempool::{PackageSubmission, PackageTxResult};

pub(crate) fn submitpackage(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let bound =
        crate::handlers::bind_named_params(params, &["package", "maxfeerate", "maxburnamount"])?;
    let params = bound.as_ref();
    crate::handlers::ensure_at_most_params(params, 3)?;
    let args = params_array(params)?;
    let raws = args
        .first()
        .and_then(|value| value.as_array())
        .ok_or_else(|| RpcError::InvalidType("package must be an array".to_owned()))?;
    if raws.is_empty() || raws.len() > bitcoin_rs_mempool::standardness::MAX_PACKAGE_COUNT {
        return Err(RpcError::InvalidParameter(
            "Array must contain between 1 and 25 transactions.".to_owned(),
        ));
    }
    let max_rate = optional_max_feerate(params, 1)?;
    let max_burn = args
        .get(2)
        .filter(|value| !value.is_null())
        .map(parse_btc_amount)
        .transpose()?
        .unwrap_or(0);
    if max_burn > Amount::MAX_MONEY.to_sat() {
        return Err(RpcError::InvalidParameter(
            "maxburnamount is out of range".to_owned(),
        ));
    }
    let mut txs = Vec::with_capacity(raws.len());
    for raw in raws {
        let raw = raw
            .as_str()
            .ok_or_else(|| RpcError::InvalidType("raw transaction must be a string".to_owned()))?;
        let tx = decode_tx(
            raw,
            "TX decode failed. Make sure the tx has at least one input.".to_owned(),
        )?;
        for output in &tx.outputs {
            let script = output.script_pubkey.as_bytes();
            // Core's burn guard is per output, not a sum. HasValidOps is
            // already owned by the script crate, including malformed pushes.
            if (script.len() > bitcoin_rs_script::MAX_SCRIPT_SIZE
                || bitcoin_rs_script::is_op_return(script)
                || !bitcoin_rs_script::has_valid_ops(script))
                && output.value.to_sat() > max_burn
            {
                return Err(RpcError::TxVerifyError(
                    "Unspendable output exceeds maximum configured by user (maxburnamount)"
                        .to_owned(),
                ));
            }
        }
        txs.push(tx);
    }
    let facts = ctx
        .mempool
        .gateway
        .submit_rpc_package(
            &txs,
            max_rate,
            unix_time_secs(),
            &ctx.chain.admission_chain(),
        )
        .map_err(|error| match error {
            SubmitError::Policy(AcceptanceRejectReason::PackageTopology) => {
                RpcError::TxVerifyError(
                    "package topology disallowed. not child-with-parents or parents depend on each other."
                        .to_owned(),
                )
            }
            SubmitError::Policy(AcceptanceRejectReason::PackageUnsupported) => {
                RpcError::TxVerifyError(error.to_string())
            }
            other => submit_error_to_rpc_error(other),
        })?;
    render_submission(&txs, facts)
}

fn package_error(error: SubmitError) -> String {
    match error {
        SubmitError::Policy(AcceptanceRejectReason::MissingInputs) => {
            "bad-txns-inputs-missingorspent".to_owned()
        }
        SubmitError::Policy(AcceptanceRejectReason::MaxFeeExceeded) => {
            "max feerate exceeded".to_owned()
        }
        SubmitError::Policy(reason) => reject_reason_to_frozen_string(reason),
        other => other.to_string(),
    }
}

fn render_submission(txs: &[Tx], facts: PackageSubmission) -> Result<Value, RpcError> {
    let failed = facts.tx_results.iter().any(|row| {
        matches!(
            row,
            PackageTxResult::Rejected(_) | PackageTxResult::Unvalidated
        )
    });
    let message = match facts.package_error {
        Some(AcceptanceRejectReason::MinRelayFeeNotMet) => "transaction failed".to_owned(),
        Some(AcceptanceRejectReason::MissingEphemeralSpends) => "unspent-dust".to_owned(),
        Some(reason) => reason.to_string(),
        None if failed => "transaction failed".to_owned(),
        None => "success".to_owned(),
    };
    let mut rows = std::collections::BTreeMap::new();
    for (tx, row) in txs.iter().zip(facts.tx_results) {
        let mut value = v31::SubmitPackageTxResult {
            txid: tx.txid().to_string(),
            other_wtxid: None,
            vsize: None,
            fees: None,
            error: None,
        };
        match row {
            PackageTxResult::Accepted {
                vsize,
                base_fee,
                effective_fee_rate,
                effective_includes,
            } => {
                value.vsize = Some(i64::from(vsize));
                value.fees = Some(v31::SubmitPackageTxResultFees {
                    base_fee: sat_to_btc(base_fee),
                    effective_fee_rate: effective_fee_rate.map(sat_to_btc),
                    effective_includes: effective_fee_rate
                        .map(|_| effective_includes.iter().map(ToString::to_string).collect()),
                });
            }
            PackageTxResult::DifferentWitness(other) => value.other_wtxid = Some(other.to_string()),
            PackageTxResult::Rejected(error) => value.error = Some(package_error(error)),
            PackageTxResult::Unvalidated => value.error = Some("package-not-validated".to_owned()),
        }
        rows.insert(tx.wtxid().to_string(), value);
    }
    typed_to_sonic_omitting_nulls(&v31::SubmitPackage {
        package_msg: message,
        tx_results: rows,
        replaced_transactions: Vec::new(),
    })
}
