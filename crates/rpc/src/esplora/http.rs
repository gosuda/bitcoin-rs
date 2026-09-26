//! HTTP response mapping for the Esplora surfaces.
//!
//! Esplora-specific policy lives here: query-limit parsing and the mapping
//! from transaction-query and RPC failures onto HTTP statuses. The response
//! shapes themselves come from [`crate::rest`], the one owner of response
//! construction for the crate.

use crate::context::TxQueryError;
use crate::rest::{
    bad_request_owned, internal_error_owned, not_found, service_unavailable_owned, Response,
};

pub(super) fn query_limit(query: &str, name: &str) -> Option<usize> {
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key == name).then(|| value.parse().ok()).flatten()
    })
}

pub(super) fn query_error(e: TxQueryError) -> Response {
    match e {
        TxQueryError::Retry | TxQueryError::Unavailable(_) => {
            service_unavailable_owned(e.to_string())
        }
        TxQueryError::Storage(_) => internal_error_owned(e.to_string()),
    }
}

pub(super) fn dispatch_error(e: crate::RpcError) -> Response {
    match e {
        crate::RpcError::NotFound(_) => not_found(),
        // 400: the request is the problem, and re-sending it unchanged will not
        // help. That covers a malformed request and a refused transaction
        // alike -- `service_unavailable` is 503, which tells a broadcaster to
        // retry, and the one thing a rejected transaction will not do is
        // succeed on a retry. Esplora answers `POST /tx` with 400 and the
        // reject reason, and a wallet reads that as "fix the transaction"
        // rather than "come back later".
        //
        // `TxRejected` is what policy or consensus refused; `TxVerifyError` a
        // guard the caller configured themselves. Neither improves with time.
        crate::RpcError::InvalidParams(_)
        | crate::RpcError::InvalidType(_)
        | crate::RpcError::Deserialization(_)
        | crate::RpcError::TxRejected(_)
        | crate::RpcError::TxVerifyError(_) => bad_request_owned(e.to_string()),
        _ => service_unavailable_owned(e.to_string()),
    }
}
