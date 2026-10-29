//! Machine-readable compatibility manifest for every external surface this
//! node exposes, declared against Bitcoin Core 31.x.

use std::format;
use std::string::String;

/// Transport kind of a manifest row.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum SurfaceKind {
    Rpc,
    Rest,
    Zmq,
}

impl SurfaceKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Rpc => "json-rpc",
            Self::Rest => "rest",
            Self::Zmq => "zmq",
        }
    }

    #[must_use]
    const fn heading(self) -> &'static str {
        match self {
            Self::Rpc => "JSON-RPC methods",
            Self::Rest => "REST endpoints",
            Self::Zmq => "ZMQ topics",
        }
    }
}

/// Compatibility status of one surface against the pinned Bitcoin Core reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum Status {
    Supported,
    Deviation,
    ImplementedUnverified,
    Extension,
    Disabled,
    /// Not exposed: JSON-RPC answers `-32601`, REST answers 404.
    Unimplemented,
}

impl Status {
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

    #[must_use]
    const fn legend(self) -> &'static str {
        match self {
            Self::Supported => {
                "differentially verified against the pinned Bitcoin Core reference; requires `reference.differential_harness` in `crates/rpc/core-compat.toml`."
            }
            Self::Deviation => {
                "shipped with a recorded difference from Core; notes cite the source file."
            }
            Self::ImplementedUnverified => "shipped; not compared against the pinned reference.",
            Self::Extension => "bitcoin-rs-specific surface with no Core counterpart.",
            Self::Disabled => "reserved for parameter-level refusal with a stable error.",
            Self::Unimplemented => {
                "Core surface this node does not expose: JSON-RPC answers `method not found`, REST answers 404."
            }
        }
    }
}

/// The compatibility manifest source, embedded so it cannot drift.
pub const MANIFEST_TOML: &str = include_str!("../core-compat.toml");

#[derive(Clone, Copy, Debug)]
pub struct Entry {
    /// JSON-RPC method name, REST route prefix (`/rest/...`), or ZMQ topic.
    pub name: &'static str,
    pub kind: SurfaceKind,
    pub status: Status,
    /// Cargo feature that must be active; empty for always-compiled rows.
    pub feature: &'static str,
    pub core_version: &'static str,
    /// Deviation/extension rationale, citing the source file when the surface
    /// differs from Core.
    pub notes: &'static str,
    /// bitcoin-rs version whose surface the row describes; `pending` marks
    /// not-yet-landed rows.
    pub since: &'static str,
}

impl Entry {
    #[must_use]
    pub fn shipped(self) -> bool {
        self.status != Status::Unimplemented
            && self.since != "pending"
            && feature_active(self.feature)
    }
}

/// Core contract version every row is declared against.
pub(crate) const CORE_VERSION: &str = "31.x";

pub(crate) const NO_WALLET: &str =
    "No wallet: this process holds no private-key material (crates/rpc/src/lib.rs).";

pub use crate::registry::MANIFEST;

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
        "pool" => cfg!(feature = "pool"),
        "silent-payments" => cfg!(feature = "silent-payments"),
        _ => false,
    }
}

const SECTIONS: [Status; 6] = [
    Status::Supported,
    Status::Deviation,
    Status::ImplementedUnverified,
    Status::Extension,
    Status::Disabled,
    Status::Unimplemented,
];

#[must_use]
pub fn render_reference() -> String {
    let mut out = String::new();
    out.push_str("# External API Compatibility Reference\n\n");
    out.push_str("<!-- GENERATED FILE - do not edit by hand.\n");
    out.push_str("     Source of truth: REGISTRY in crates/rpc/src/registry.rs.\n");
    out.push_str(
        "     Regenerate: REGEN_RPC_REFERENCE=1 cargo test -p bitcoin-rs-rpc --test suite manifest_coverage::regenerate_reference -- --ignored\n",
    );
    out.push_str(
        "     The generated_reference_matches_checked_in test fails when this file drifts. -->\n\n",
    );
    out.push_str("Surface contract of bitcoin-rs against Bitcoin Core ");
    out.push_str(CORE_VERSION);
    out.push_str(".\n\n");
    for status in SECTIONS {
        out.push_str("- **");
        out.push_str(status.label());
        out.push_str("** - ");
        out.push_str(status.legend());
        out.push('\n');
    }
    out.push('\n');
    out.push_str("`since` is the bitcoin-rs version whose surface a row describes; `pending` marks a row whose implementation lands in a later change. Rows naming a cargo feature exist only when that feature is compiled.\n\n");
    out.push_str("Unimplemented-set derivation: audited against the Bitcoin Core v31.0 source command tables (src/rpc/*.cpp, src/wallet/rpc/*.cpp, src/rest.cpp StartREST, src/zmq/zmqpublishnotifier.cpp) - the same registrations Core's `help` output prints. Hidden test/administration commands are intentionally absent.\n");
    for kind in [SurfaceKind::Rpc, SurfaceKind::Rest, SurfaceKind::Zmq] {
        let mut printed_heading = false;
        for status in SECTIONS {
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
    for (index, status) in SECTIONS.into_iter().enumerate() {
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
