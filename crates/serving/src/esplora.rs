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
    if is_historical_block_read(path) {
        return dispatch_get(handler, &ctx, surface, path, query);
    }
    let projection = Projection::new(&ctx);
    let chain_view = projection.capture_chain_view();
    let response = dispatch_get(handler, &ctx, surface, path, query);
    match projection.ensure_chain_view(chain_view.as_ref()) {
        Ok(()) => response,
        Err(response) => response,
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
        let ctx = handler.context();
        let projection = Projection::new(&ctx);
        let chain_view = projection.capture_chain_view();
        if let Some(response) = backend::post(handler, path, body) {
            return match projection.ensure_chain_view(chain_view.as_ref()) {
                Ok(()) => response,
                Err(response) => response,
            };
        }
    }
    public::post(handler, path, body)
}

#[must_use]
pub fn namespace(path: &str) -> Option<(Surface, &str)> {
    strip_dir(path, "/api")
        .map(|rest| (Surface::Public, rest))
        .or_else(|| strip_dir(path, "/esplora").map(|rest| (Surface::Backend, rest)))
}

fn is_historical_block_read(path: &str) -> bool {
    let parts: Vec<_> = path.trim_matches('/').split('/').collect();
    matches!(
        parts.as_slice(),
        ["block", _]
            | ["block", _, "header" | "raw" | "txids"]
            | ["block", _, "txs"]
            | ["block", _, "txs", _]
            | ["block", _, "txid", _]
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
