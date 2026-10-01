//! Bitcoin Core P2P compatibility inventory.
//!
//! This module owns the decoded command set and the pinned Core reference.
//! The decoder in [`crate::wire`] types exactly the names in [`COMMANDS`].
//! Handshake fields, the reject-or-ignore matrix, and the deviation ledger
//! live in `docs/policies/p2p-compatibility.md`.

/// Bitcoin Core release every P2P compatibility claim is made against.
pub const PINNED_CORE_VERSION: &str = "31.1";

/// Commands `decode_payload` types. Order matches the decoder match.
///
/// `decode_payload` will not type a command absent from this table, so an
/// extra match arm cannot invent inventory. Adding a command updates this
/// table, the decoder, [`crate::Message`], and the policy §5 table in the
/// same change-set. A name without a decoder arm is caught by
/// `listed_commands_type_and_core_untyped_commands_stay_unknown`, which decodes
/// a frame for every entry here and fails on `Message::Unknown`.
pub const COMMANDS: &[&str] = &[
    "version",
    "verack",
    "addr",
    "inv",
    "getdata",
    "notfound",
    "getblocks",
    "getheaders",
    "mempool",
    "tx",
    "block",
    "headers",
    "sendheaders",
    "getaddr",
    "ping",
    "pong",
    "merkleblock",
    "filterload",
    "filteradd",
    "filterclear",
    "getcfilters",
    "cfilter",
    "getcfheaders",
    "cfheaders",
    "getcfcheckpt",
    "cfcheckpt",
    "sendcmpct",
    "cmpctblock",
    "getblocktxn",
    "blocktxn",
    "reject",
    "alert",
    "feefilter",
    "wtxidrelay",
    "addrv2",
    "sendaddrv2",
];

/// Bitcoin Core 31.1 commands this node does not type.
///
/// Decoded as [`crate::Message::Unknown`]. `sendtxrcncl` (BIP330) is the one
/// Core 31 command missing from [`COMMANDS`]; see the deviation ledger.
pub const CORE_UNTYPED_COMMANDS: &[&str] = &["sendtxrcncl"];

/// Reports whether `name` is a typed command.
#[must_use]
pub fn is_typed_command(name: &str) -> bool {
    COMMANDS.contains(&name)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{COMMANDS, CORE_UNTYPED_COMMANDS};

    /// The properties the table must hold for the code that reads it:
    /// [`super::is_typed_command`] resolves a name to one row, and every name
    /// is spelled
    /// as peers send it — lowercase ASCII fitting the 12-byte v1 command field
    /// the framer copies it into. A name that differs from the wire spelling
    /// decodes every real peer's message as `Message::Unknown`.
    #[test]
    fn every_command_name_is_unique_and_fits_the_v1_field() {
        let names: BTreeSet<&str> = COMMANDS.iter().copied().collect();
        assert_eq!(names.len(), COMMANDS.len(), "command names must be unique");
        for name in COMMANDS
            .iter()
            .chain(CORE_UNTYPED_COMMANDS.iter())
            .copied()
        {
            assert!(
                !name.is_empty() && name.len() <= 12,
                "{name} does not fit the 12-byte v1 command field"
            );
            assert!(
                name.bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit()),
                "{name} is not spelled as peers send it: lowercase ASCII"
            );
        }
        for name in CORE_UNTYPED_COMMANDS {
            assert!(
                !names.contains(name),
                "{name} is typed; it belongs in COMMANDS or not in CORE_UNTYPED_COMMANDS"
            );
        }
    }
}
