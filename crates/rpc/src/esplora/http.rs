//! HTTP response helpers for the Esplora surfaces.

use crate::context::TxQueryError;
use crate::rest::Response;

pub(super) fn query_limit(query: &str, name: &str) -> Option<usize> {
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key == name).then(|| value.parse().ok()).flatten()
    })
}

pub(super) fn query_error(e: TxQueryError) -> Response {
    match e {
        TxQueryError::Retry | TxQueryError::Unavailable(_) => unavailable(&e.to_string()),
        TxQueryError::Storage(_) => internal(&e.to_string()),
    }
}

pub(super) fn dispatch_error(e: crate::RpcError) -> Response {
    match e {
        crate::RpcError::NotFound(_) => not_found(),
        // 400: the request is the problem, and re-sending it unchanged will not
        // help. That covers a malformed request and a refused transaction
        // alike -- `unavailable` is 503, which tells a broadcaster to retry,
        // and the one thing a rejected transaction will not do is succeed on a
        // retry. Esplora answers `POST /tx` with 400 and the reject reason, and
        // a wallet reads that as "fix the transaction" rather than "come back
        // later".
        //
        // `TxRejected` is what policy or consensus refused; `TxVerifyError` a
        // guard the caller configured themselves. Neither improves with time.
        crate::RpcError::InvalidParams(_)
        | crate::RpcError::InvalidType(_)
        | crate::RpcError::Deserialization(_)
        | crate::RpcError::TxRejected(_)
        | crate::RpcError::TxVerifyError(_) => bad(&e.to_string()),
        _ => unavailable(&e.to_string()),
    }
}

pub(super) fn json_response(v: impl serde::Serialize) -> Response {
    sonic_rs::to_string(&v).map_or_else(
        |_| internal("failed to serialize response"),
        |b| Response {
            status: 200,
            reason: "OK",
            content_type: "application/json",
            body: b.into_bytes(),
        },
    )
}

pub(super) fn text(b: String) -> Response {
    Response {
        status: 200,
        reason: "OK",
        content_type: "text/plain",
        body: b.into_bytes(),
    }
}

pub(super) fn bad(m: &str) -> Response {
    Response {
        status: 400,
        reason: "Bad Request",
        content_type: "text/plain",
        body: m.as_bytes().to_vec(),
    }
}

pub(super) fn not_found() -> Response {
    Response {
        status: 404,
        reason: "Not Found",
        content_type: "text/plain",
        body: b"not found".to_vec(),
    }
}

pub(super) fn unavailable(m: &str) -> Response {
    Response {
        status: 503,
        reason: "Service Unavailable",
        content_type: "text/plain",
        body: m.as_bytes().to_vec(),
    }
}

pub(super) fn internal(m: &str) -> Response {
    Response {
        status: 500,
        reason: "Internal Server Error",
        content_type: "text/plain",
        body: m.as_bytes().to_vec(),
    }
}
