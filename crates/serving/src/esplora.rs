#![expect(
    clippy::as_conversions,
    clippy::cast_precision_loss,
    clippy::needless_borrow,
    clippy::significant_drop_in_scrutinee
)]

pub(crate) mod admission;
mod backend;
mod http;
mod model;
mod projection;
mod public;

use crate::context::Context;
use crate::handlers::Handler;
use crate::rest::Response;

use self::projection::Projection;
pub const DEFAULT_MAX_QUERIES: std::num::NonZeroUsize =
    std::num::NonZeroUsize::MIN.saturating_add(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Surface {
    Public,
    Backend,
}

#[must_use]
pub fn route(handler: &Handler, surface: Surface, path: &str, query: &str) -> Response {
    let ctx = handler.context();
    let _permit = if admission::is_expensive(path) {
        match ctx.esplora_admission.try_acquire() {
            Some(permit) => Some(permit),
            None => {
                return crate::rest::service_unavailable("expensive Esplora query limit reached");
            }
        }
    } else {
        None
    };
    if needs_tip_fence(path) {
        let projection = Projection::new(&ctx);
        let chain_view = projection.capture_chain_view();
        #[cfg(test)]
        crate::esplora::tests::gate_route_for_tests();
        let response = dispatch_get(handler, &ctx, surface, path, query);
        if response.status == 400 || response.status == 404 {
            return response;
        }
        match projection.ensure_chain_view(chain_view.as_ref()) {
            Ok(()) => response,
            Err(response) => response,
        }
    } else {
        dispatch_get(handler, &ctx, surface, path, query)
    }
}

fn dispatch_get(
    handler: &Handler,
    ctx: &Context,
    surface: Surface,
    path: &str,
    query: &str,
) -> Response {
    if surface == Surface::Backend {
        if let Some(response) = backend::get(handler, ctx, path, query) {
            return response;
        }
    }
    public::get(ctx, path)
}
#[must_use]
pub(crate) fn route_post(handler: &Handler, surface: Surface, path: &str, body: &[u8]) -> Response {
    if surface == Surface::Backend {
        if let Some(response) = backend_post(handler, path, body) {
            return response;
        }
    }
    public::post(handler, path, body)
}
fn backend_post(handler: &Handler, path: &str, body: &[u8]) -> Option<Response> {
    if !needs_tip_fence(path) {
        return backend::post(handler, path, body);
    }
    let ctx = handler.context();
    let projection = Projection::new(&ctx);
    let chain_view = projection.capture_chain_view();
    #[cfg(test)]
    crate::esplora::tests::gate_route_for_tests();
    let response = backend::post(handler, path, body)?;
    if response.status == 400 || response.status == 404 {
        return Some(response);
    }
    match projection.ensure_chain_view(chain_view.as_ref()) {
        Ok(()) => Some(response),
        Err(unavailable) => Some(unavailable),
    }
}

#[must_use]
pub fn namespace(path: &str) -> Option<(Surface, &str)> {
    strip_dir(path, "/api")
        .map(|rest| (Surface::Public, rest))
        .or_else(|| strip_dir(path, "/esplora").map(|rest| (Surface::Backend, rest)))
}

fn needs_tip_fence(path: &str) -> bool {
    let parts: Vec<_> = path.trim_matches('/').split('/').collect();
    !matches!(
        parts.as_slice(),
        ["blocks", ..]
            | ["block", ..]
            | ["block-height", ..]
            | ["tx", _, "merkleblock-proof" | "merkle-proof"]
            | ["tx", _]
            | ["tx", _, "hex" | "raw" | "status" | "outspends"]
            | ["tx", _, "outspend", _]
            | ["address" | "scripthash", _, "txs", "summary"]
            | ["address" | "scripthash", _, "txs", "chain", ..]
            | ["address-prefix", ..]
            | ["internal", "block", _, "txs"]
            | ["mempool", ..]
            | ["fee-estimates"]
            | ["address" | "scripthash", _, "txs", "mempool"]
            | ["internal", "mempool", "txs", ..]
    )
}

fn strip_dir<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = path.strip_prefix(prefix)?;
    if rest.is_empty() {
        Some("/")
    } else if rest.starts_with('/') {
        Some(rest)
    } else {
        None
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests;
