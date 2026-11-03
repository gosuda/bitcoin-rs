use bitcoin_rs_mempool::SubmitError;

use crate::context::TxQueryError;
use crate::rest::{Response, bad_request, internal_error, not_found, service_unavailable};

pub(super) fn query_limit(query: &str, name: &str) -> Option<usize> {
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key == name).then(|| value.parse().ok()).flatten()
    })
}

pub(super) fn query_error(e: TxQueryError) -> Response {
    match e {
        TxQueryError::Unavailable(
            bitcoin_rs_index::TxUnavailableCause::ScriptHashLimitExceeded { .. },
        ) => Response {
            status: 422,
            reason: "Unprocessable Entity",
            content_type: "text/plain",
            body: e.to_string().into_bytes(),
        },
        TxQueryError::Retry | TxQueryError::Unavailable(_) => service_unavailable(e.to_string()),
        TxQueryError::Storage(_) => internal_error(e.to_string()),
    }
}

pub(super) fn admission_error(error: SubmitError) -> Response {
    match error {
        SubmitError::Policy(reason) => {
            dispatch_error(crate::handlers::tx::reject_reason_to_rpc_error(reason))
        }
        SubmitError::Consensus => bad_request(error.to_string()),
        SubmitError::RetryExhausted => service_unavailable(format!("internal error: {error}")),
    }
}

pub(super) fn dispatch_error(e: crate::RpcError) -> Response {
    match e {
        crate::RpcError::NotFound(_) => not_found(),
        crate::RpcError::InvalidParams(_)
        | crate::RpcError::InvalidType(_)
        | crate::RpcError::Deserialization(_)
        | crate::RpcError::TxRejected(_)
        | crate::RpcError::TxVerifyError(_) => bad_request(e.to_string()),
        crate::RpcError::Parse(_)
        | crate::RpcError::InvalidRequest(_)
        | crate::RpcError::TopLevelParse(_)
        | crate::RpcError::MethodNotFound(_)
        | crate::RpcError::MethodDisabled(_)
        | crate::RpcError::InvalidParameter(_)
        | crate::RpcError::ScanInProgress(_)
        | crate::RpcError::InvalidAddressOrKey(_)
        | crate::RpcError::ClientNotConnected(_)
        | crate::RpcError::ClientInInitialDownload(_)
        | crate::RpcError::Misc(_)
        | crate::RpcError::CoreInternal(_)
        | crate::RpcError::Internal(_) => service_unavailable(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::admission_error;
    use bitcoin_rs_mempool::SubmitError;

    #[test]
    fn script_work_limits_are_explicit_but_unavailable_indexes_remain_503() {
        use bitcoin_rs_index::{TxQueryError, TxUnavailableCause};
        let response = super::query_error(TxQueryError::Unavailable(
            TxUnavailableCause::ScriptHashLimitExceeded { limit: 25_000 },
        ));
        assert_eq!(response.status, 422);
        assert!(
            String::from_utf8_lossy(&response.body)
                .contains("scripthash limit exceeded (25000 entries)")
        );
        assert_eq!(super::query_error(TxQueryError::Retry).status, 503);
        assert_eq!(
            super::query_error(TxQueryError::Unavailable(
                TxUnavailableCause::BodyReadBudgetExhausted
            ))
            .status,
            503
        );
    }

    #[test]
    fn admission_consensus_and_retry_failures_preserve_the_http_dialect() {
        let consensus = admission_error(SubmitError::Consensus);
        assert_eq!(consensus.status, 400);
        assert_eq!(consensus.body, b"consensus-verification-failed");
        let retry = admission_error(SubmitError::RetryExhausted);
        assert_eq!(retry.status, 503);
        assert_eq!(retry.body, b"internal error: admission retry exhausted: chain or mempool changed during submission");
    }

    #[test]
    fn dispatch_error_maps_internal_variants_to_service_unavailable() {
        let response = super::dispatch_error(crate::RpcError::Parse("bad input".into()));
        assert_eq!(response.status, 503);
        let nf = super::dispatch_error(crate::RpcError::NotFound("missing"));
        assert_eq!(nf.status, 404);
    }
}
