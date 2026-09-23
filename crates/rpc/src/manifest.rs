//! Machine-readable compatibility manifest for every external surface this
//! node exposes, declared against Bitcoin Core 31.x.
//!
//! [`MANIFEST`] is the single source of truth for the dispatcher: a JSON-RPC
//! method answers only when a non-`Unimplemented` RPC row carries its name,
//! so the manifest cannot drift from what actually dispatches. The coverage
//! gate (`crates/rpc/tests/manifest_coverage.rs`) proves the other
//! direction — it asserts set equality between the dispatcher's live
//! registry and the shipped rows in both directions — and regenerates
//! `docs/rpc-reference.md` from this table.
//!
//! Row semantics:
//! - `status`: [`Status::Supported`] is differentially verified against the
//!   pinned reference (no rows qualify yet; the
//!   `[reference].differential_harness` flag gates the claim);
//!   [`Status::Deviation`] ships with a recorded difference (the `notes`
//!   field cites the source file carrying it);
//!   [`Status::ImplementedUnverified`] ships but nothing has compared it to
//!   the pinned reference; [`Status::Extension`] has no Core counterpart;
//!   [`Status::Disabled`] is reserved for parameter-level refusals with a
//!   stable error (zero genuine rows); [`Status::Unimplemented`] is Core
//!   surface this node does not expose.
//! - `feature`: cargo feature that must be active for the surface to exist
//!   (empty for always-compiled surfaces).
//! - `core_version`: the Core contract version the row is declared against.
//! - `since`: the bitcoin-rs version whose surface the row describes;
//!   `pending` marks rows whose implementation lands in a later change.
//!
//! The `Unimplemented` JSON-RPC set was audited against Bitcoin Core v31.0
//! source command tables (`src/rpc/*.cpp`, `src/wallet/rpc/*.cpp`,
//! `src/rest.cpp` `StartREST`, `src/zmq/zmqpublishnotifier.cpp`) — the same
//! registrations Core's `help` output prints. Hidden test/administration
//! commands (`echo*`, `setmocktime`, `mockscheduler`, `addconnection`,
//! `addpeeraddress`, `sendmsgtopeer`, `getrawaddrman`,
//! `syncwithvalidationinterfacequeue`, `generate` (removed in Core),
//! `generatetodescriptor`, `getorphantxs`, `getmempoolfeeratediagram`) are
//! intentionally absent from the table.

use std::format;
use std::string::String;

/// Transport kind of a manifest row.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum SurfaceKind {
    /// JSON-RPC method dispatched by [`crate::handlers::Handler`].
    Rpc,
    /// Core-registered REST route prefix under `/rest/`.
    Rest,
    /// ZMQ PUB notification topic.
    Zmq,
}

impl SurfaceKind {
    /// Lower-case label used in the generated reference.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Rpc => "json-rpc",
            Self::Rest => "rest",
            Self::Zmq => "zmq",
        }
    }

    /// Section heading used in the generated reference.
    #[must_use]
    pub const fn heading(self) -> &'static str {
        match self {
            Self::Rpc => "JSON-RPC methods",
            Self::Rest => "REST endpoints",
            Self::Zmq => "ZMQ topics",
        }
    }
}

/// Compatibility status of one surface.
///
/// Declaration order is also the section order of the generated reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum Status {
    /// Implemented and differentially verified against the pinned
    /// reference. Nothing qualifies while
    /// `[reference].differential_harness` is false; the coverage gate
    /// rejects the claim.
    Supported,
    /// Shipped with a recorded difference from Core; notes cite the source.
    Deviation,
    /// Shipped; nothing has compared it to the pinned reference.
    ImplementedUnverified,
    /// bitcoin-rs-specific surface with no Core counterpart.
    Extension,
    /// Shipped surface refused at the parameter level with a stable error.
    /// Reserved; zero genuine rows carry it today.
    Disabled,
    /// Core surface this node does not expose.
    Unimplemented,
}

impl Status {
    /// PRE: `self` is one of the six Status variants.
    /// POST: returns the exact label used in the generated reference legend,
    ///   section headings, and footer.
    /// INVARIANT: labels are unique and match the legend order.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Supported => "Supported",
            Self::Deviation => "Deviation",
            Self::ImplementedUnverified => "Implemented (unverified)",
            Self::Extension => "Extension",
            Self::Disabled => "Disabled",
            Self::Unimplemented => "Unimplemented",
        }
    }
}

/// One declared surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Entry {
    /// JSON-RPC method name, REST route prefix (`/rest/...`), or ZMQ topic.
    pub name: &'static str,
    /// Transport the surface is spoken over.
    pub kind: SurfaceKind,
    /// Compatibility with the Core contract.
    pub status: Status,
    /// Cargo feature that must be active; empty for always-compiled rows.
    pub feature: &'static str,
    /// Core contract version the row is declared against.
    pub core_version: &'static str,
    /// Deviation/extension rationale, citing the source file when the surface
    /// differs from Core.
    pub notes: &'static str,
    /// bitcoin-rs version whose surface the row describes; `pending` marks
    /// not-yet-landed rows.
    pub since: &'static str,
}

impl Entry {
    /// True when the surface exists in this build: its feature is compiled
    /// in, its status is not `Unimplemented`, and it is not a `pending`
    /// contract-only row. Mirrors registration.
    #[must_use]
    pub fn shipped(self) -> bool {
        self.status != Status::Unimplemented
            && self.since != "pending"
            && feature_active(self.feature)
    }
}

/// Core contract version every row is declared against.
pub const CORE_VERSION: &str = "31.x";

/// No-wallet policy note shared by every wallet-class row; the crate refuses
/// to hold private key material (see `crates/rpc/src/lib.rs`).
pub(crate) const NO_WALLET: &str =
    "No wallet: this process holds no private-key material (crates/rpc/src/lib.rs).";

/// Every external surface, declared against Core 31.x.
///
/// Projection of the single [`crate::registry::REGISTRY`] table: each row's
/// compat metadata without the dispatch arm. The registry is the source of
/// truth; this const exists so existing consumers that take `&[Entry]`
/// compile unmodified.
pub use crate::registry::MANIFEST;

/// True when `name` answers a dispatch for `kind` in this build.
///
/// Projects from [`crate::registry::REGISTRY`], so a row and its dispatch
/// arm cannot disagree about registrability.
#[must_use]
pub fn is_registered(kind: SurfaceKind, name: &str) -> bool {
    crate::registry::REGISTRY
        .iter()
        .any(|row| row.entry.kind == kind && row.entry.name == name && row.entry.shipped())
}

/// Rows of one transport kind, in table order.
///
/// Projects from [`crate::registry::REGISTRY`], yielding the [`Entry`] view
/// of each row.
pub fn entries_of_kind(kind: SurfaceKind) -> impl Iterator<Item = &'static Entry> {
    crate::registry::REGISTRY
        .iter()
        .filter(move |row| row.entry.kind == kind)
        .map(|row| &row.entry)
}

fn feature_active(feature: &str) -> bool {
    match feature {
        "" => true,
        "zmq" => cfg!(feature = "zmq"),
        // An unknown feature name can never be active here; the coverage test
        // rejects such a row outright.
        _ => false,
    }
}

/// Renders `docs/rpc-reference.md` deterministically from [`crate::registry::REGISTRY`].
///
/// The output is a pure function of the table: fixed section order, fixed row
/// order, and a counts footer, so a one-row change always changes the bytes
/// and fails the drift test.
#[must_use]
pub fn render_reference() -> String {
    let mut out = String::new();
    out.push_str("# External API Compatibility Reference\n\n");
    out.push_str("<!-- GENERATED FILE - do not edit by hand.\n");
    out.push_str("     Source of truth: REGISTRY in crates/rpc/src/registry.rs.\n");
    out.push_str(
        "     Regenerate: REGEN_RPC_REFERENCE=1 cargo test -p bitcoin-rs-rpc --test manifest_coverage -- --ignored regenerate_reference\n",
    );
    out.push_str(
        "     The generated_reference_matches_checked_in test fails when this file drifts. -->\n\n",
    );
    out.push_str("Surface contract of bitcoin-rs against Bitcoin Core ");
    out.push_str(CORE_VERSION);
    out.push_str(".\n\n");
    out.push_str("- **Supported** - implemented and differentially verified against the pinned reference. Nothing qualifies while `[reference].differential_harness` is false.\n");
    out.push_str("- **Deviation** - shipped with a recorded difference from Core; notes cite the source file.\n");
    out.push_str("- **Implemented (unverified)** - shipped; nothing has compared it to the pinned reference.\n");
    out.push_str("- **Extension** - bitcoin-rs-specific surface with no Core counterpart.\n");
    out.push_str("- **Disabled** - shipped surface refused at the parameter level with a stable error. Reserved; no row carries it today.\n");
    out.push_str("- **Unimplemented** - Core surface this node does not expose: JSON-RPC answers `method not found`, REST answers 404.\n\n");
    out.push_str("`since` is the bitcoin-rs version whose surface a row describes; `pending` marks a row whose implementation lands in a later change. Rows naming a cargo feature exist only when that feature is compiled.\n\n");
    out.push_str("Unimplemented-set derivation: audited against the Bitcoin Core v31.0 source command tables (src/rpc/*.cpp, src/wallet/rpc/*.cpp, src/rest.cpp StartREST, src/zmq/zmqpublishnotifier.cpp) - the same registrations Core's `help` output prints. Hidden test/administration commands are intentionally absent.\n");
    for kind in [SurfaceKind::Rpc, SurfaceKind::Rest, SurfaceKind::Zmq] {
        let mut printed_heading = false;
        for status in [
            Status::Supported,
            Status::Deviation,
            Status::ImplementedUnverified,
            Status::Extension,
            Status::Disabled,
            Status::Unimplemented,
        ] {
            let rows: Vec<&Entry> = entries_of_kind(kind)
                .filter(|entry| entry.status == status)
                .collect();
            if rows.is_empty() {
                continue;
            }
            if !printed_heading {
                out.push_str("\n## ");
                out.push_str(kind.heading());
                out.push('\n');
                printed_heading = true;
            }
            out.push_str("\n### ");
            out.push_str(status.label());
            out.push_str("\n\n");
            out.push_str("| surface | since | notes |\n");
            out.push_str("|---|---|---|\n");
            for entry in rows {
                out.push_str("| `");
                out.push_str(entry.name);
                out.push_str("` | ");
                out.push_str(entry.since);
                out.push_str(" | ");
                out.push_str(entry.notes);
                out.push_str(" |\n");
            }
        }
    }
    out.push_str("\nRow counts: ");
    for (index, status) in [
        Status::Supported,
        Status::Deviation,
        Status::ImplementedUnverified,
        Status::Extension,
        Status::Disabled,
        Status::Unimplemented,
    ]
    .into_iter()
    .enumerate()
    {
        if index > 0 {
            out.push_str(", ");
        }
        let count = crate::registry::REGISTRY
            .iter()
            .filter(|row| row.entry.status == status)
            .count();
        out.push_str(&format!("{} {count}", status.label()));
    }
    let total = crate::registry::REGISTRY.len();
    out.push_str(&format!(" - total {total}.\n"));
    out
}
