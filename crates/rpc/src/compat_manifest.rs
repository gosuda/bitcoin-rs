//! The Bitcoin Core compatibility manifest, and the checks that keep it true.
//!
//! `docs/api/core-compat.toml` is the machine-readable inventory #78 asks for:
//! every RPC method, REST route and ZMQ topic this node exposes, with the
//! status it is claimed at.
//!
//! A manifest nobody checks is a document that rots, and a rotted compatibility
//! contract is worse than none — a client reads it, believes it, and finds out
//! at runtime. So the file is embedded at compile time and cross-checked
//! against the things it describes: the dispatcher, the REST router, the ZMQ
//! topic table, and `Cargo.lock`. Adding a method without an entry fails the
//! suite; so does an entry for a method that does not dispatch; so does bumping
//! the kernel crate without revisiting the pinned Core revision.
//!
//! The manifest is deliberately allowed to say *less* than the surface does
//! for REST and ZMQ. For RPC it must name every method the dispatcher answers
//! and no others, because the header claims "anything absent is
//! `not_implemented`" and that claim is tested.
//!
//! `Status::Disabled` is kept in the vocabulary for parameter-level refusals
//! (e.g. `deriveaddresses` refuses ranged descriptors with a stable
//! `MethodDisabled` error). No whole method is disabled: methods this node
//! does not expose are absent from the manifest and answer `-32601`.
//!
//! Reference identity parsing and custody validation are owned by
//! `bin/bitcoin-rs/tests/support/reference_set.rs`.

/// The manifest source, embedded so it cannot drift from the binary.
pub const MANIFEST_TOML: &str = include_str!("../../../docs/api/core-compat.toml");

/// Status a manifest entry is claimed at.
///
/// Ordered by decreasing confidence. The distinction that matters is between
/// [`Self::Supported`] and [`Self::ImplementedUnverified`]: #78 names "treating
/// a Core method name as proof of behavioral compatibility" as a non-goal, so
/// the vocabulary carries a state for "implemented, and nothing has checked it"
/// rather than folding that into "supported".
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    /// Implemented and differentially verified against the pinned reference.
    Supported,
    /// Implemented, with a stated difference from the pinned reference.
    Deviation,
    /// Implemented; nothing has compared it to the reference.
    ImplementedUnverified,
    /// bitcoin-rs-specific surface with no Core counterpart.
    Extension,
    /// Refused by product policy at the parameter level, with a stable error.
    Disabled,
    /// Not dispatched; answers `-32601`.
    NotImplemented,
}

impl Status {
    /// Parses a manifest status string.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "supported" => Some(Self::Supported),
            "deviation" => Some(Self::Deviation),
            "implemented_unverified" => Some(Self::ImplementedUnverified),
            "extension" => Some(Self::Extension),
            "disabled" => Some(Self::Disabled),
            "not_implemented" => Some(Self::NotImplemented),
            _ => None,
        }
    }
}
