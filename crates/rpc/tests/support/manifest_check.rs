//! Authority check against the const `MANIFEST`.

use bitcoin_rs_rpc::manifest::{Entry, SurfaceKind};

use super::fixture::Fixture;

#[must_use]
pub(crate) fn is_shipped_rpc_method(method: &str, manifest: &[Entry]) -> bool {
    manifest
        .iter()
        .any(|entry| entry.kind == SurfaceKind::Rpc && entry.name == method && entry.shipped())
}

pub(crate) fn check_fixture_methods(
    fixture: &Fixture,
    manifest: &[Entry],
    kind: SurfaceKind,
) -> Result<(), String> {
    for method in &fixture.request.methods {
        let declared = manifest
            .iter()
            .find(|entry| entry.kind == kind && entry.name == method);
        match (fixture.request.expect_methods_in_manifest, declared) {
            (true, Some(entry)) if entry.shipped() => {}
            (true, Some(entry)) => {
                return Err(format!(
                    "method {method:?} is declared in the manifest but not shipped \
                     (status {:?}, since {:?})",
                    entry.status, entry.since
                ));
            }
            (true, None) => {
                return Err(format!(
                    "fixture expects {method:?} to be a declared manifest method, but no row \
                     names it"
                ));
            }
            (false, Some(_)) => {
                return Err(format!(
                    "fixture expects {method:?} to be absent from the manifest, but a row \
                     names it; the unknown-method case must stay unknown"
                ));
            }
            (false, None) => {}
        }
    }
    Ok(())
}
