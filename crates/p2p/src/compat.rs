//! Bitcoin Core P2P compatibility inventory.
//!
//! This module owns the decoded command set and the pinned Core reference.
//! The decoder in [`crate::wire`] types exactly the names in [`COMMANDS`].
//! Handshake fields, the reject-or-ignore matrix, and the deviation ledger
//! live in `docs/policies/p2p-compatibility.md`.

/// Bitcoin Core release every P2P compatibility claim is made against.
pub const PINNED_CORE_VERSION: &str = "31.1";

/// How a decoded command is treated once the peer is ready.
///
/// Vocabulary matches `docs/policies/p2p-compatibility.md` §5.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CommandStatus {
    /// Sent and processed during the version/verack handshake.
    Negotiated,
    /// Answered with protocol data.
    Served,
    /// Decoded and forwarded into the node. No protocol response.
    Sink,
    /// Decoded and FSM-accepted. No response.
    Ignored,
    /// Decoded for corpus or legacy tolerance only. Never sent.
    Legacy,
}

/// One command the v1 decoder types rather than wrapping as [`crate::Message::Unknown`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Command {
    /// Wire command name (NUL-padded to 12 bytes on the envelope).
    pub name: &'static str,
    /// Ready-peer treatment.
    pub status: CommandStatus,
}

/// Commands `decode_payload` types. Order matches the decoder match.
///
/// Adding a command updates this table, the decoder, [`crate::Message`], and
/// the policy §5 table in the same change-set.
pub const COMMANDS: &[Command] = &[
    Command {
        name: "version",
        status: CommandStatus::Negotiated,
    },
    Command {
        name: "verack",
        status: CommandStatus::Negotiated,
    },
    Command {
        name: "addr",
        status: CommandStatus::Ignored,
    },
    Command {
        name: "inv",
        status: CommandStatus::Served,
    },
    Command {
        name: "getdata",
        status: CommandStatus::Served,
    },
    Command {
        name: "notfound",
        status: CommandStatus::Ignored,
    },
    Command {
        name: "getblocks",
        status: CommandStatus::Ignored,
    },
    Command {
        name: "getheaders",
        status: CommandStatus::Served,
    },
    Command {
        name: "mempool",
        status: CommandStatus::Ignored,
    },
    Command {
        name: "tx",
        status: CommandStatus::Sink,
    },
    Command {
        name: "block",
        status: CommandStatus::Sink,
    },
    Command {
        name: "headers",
        status: CommandStatus::Sink,
    },
    Command {
        name: "sendheaders",
        status: CommandStatus::Negotiated,
    },
    Command {
        name: "getaddr",
        status: CommandStatus::Ignored,
    },
    Command {
        name: "ping",
        status: CommandStatus::Served,
    },
    Command {
        name: "pong",
        status: CommandStatus::Ignored,
    },
    Command {
        name: "merkleblock",
        status: CommandStatus::Ignored,
    },
    Command {
        name: "filterload",
        status: CommandStatus::Ignored,
    },
    Command {
        name: "filteradd",
        status: CommandStatus::Ignored,
    },
    Command {
        name: "filterclear",
        status: CommandStatus::Ignored,
    },
    Command {
        name: "getcfilters",
        status: CommandStatus::Ignored,
    },
    Command {
        name: "cfilter",
        status: CommandStatus::Ignored,
    },
    Command {
        name: "getcfheaders",
        status: CommandStatus::Ignored,
    },
    Command {
        name: "cfheaders",
        status: CommandStatus::Ignored,
    },
    Command {
        name: "getcfcheckpt",
        status: CommandStatus::Ignored,
    },
    Command {
        name: "cfcheckpt",
        status: CommandStatus::Ignored,
    },
    Command {
        name: "sendcmpct",
        status: CommandStatus::Ignored,
    },
    Command {
        name: "cmpctblock",
        status: CommandStatus::Ignored,
    },
    Command {
        name: "getblocktxn",
        status: CommandStatus::Ignored,
    },
    Command {
        name: "blocktxn",
        status: CommandStatus::Ignored,
    },
    Command {
        name: "reject",
        status: CommandStatus::Legacy,
    },
    Command {
        name: "alert",
        status: CommandStatus::Legacy,
    },
    Command {
        name: "feefilter",
        status: CommandStatus::Ignored,
    },
    Command {
        name: "wtxidrelay",
        status: CommandStatus::Negotiated,
    },
    Command {
        name: "addrv2",
        status: CommandStatus::Ignored,
    },
    Command {
        name: "sendaddrv2",
        status: CommandStatus::Negotiated,
    },
];

/// Bitcoin Core 31.1 commands this node does not type.
///
/// Decoded as [`crate::Message::Unknown`]. `sendtxrcncl` (BIP330) is the one
/// Core 31 command missing from [`COMMANDS`]; see the deviation ledger.
pub const CORE_UNTYPED_COMMANDS: &[&str] = &["sendtxrcncl"];

/// Looks up a typed command by its wire name.
#[must_use]
pub fn command(name: &str) -> Option<&'static Command> {
    COMMANDS.iter().find(|entry| entry.name == name)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{COMMANDS, CORE_UNTYPED_COMMANDS, CommandStatus, PINNED_CORE_VERSION};

    #[test]
    fn inventory_is_unique_and_complete() {
        assert_eq!(COMMANDS.len(), 36, "decoder types 36 commands");
        let names: BTreeSet<&str> = COMMANDS.iter().map(|entry| entry.name).collect();
        assert_eq!(names.len(), COMMANDS.len(), "command names must be unique");
        for name in CORE_UNTYPED_COMMANDS {
            assert!(
                !names.contains(name),
                "{name} is typed; it belongs in COMMANDS or not in CORE_UNTYPED_COMMANDS"
            );
            assert!(
                name.len() <= 12,
                "{name} exceeds the 12-byte v1 command field"
            );
        }
        for entry in COMMANDS {
            assert!(
                !entry.name.is_empty() && entry.name.len() <= 12,
                "{} is not a v1 command name",
                entry.name
            );
            assert!(
                entry
                    .name
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit()),
                "{} is not a lowercase command name",
                entry.name
            );
        }
        assert_eq!(PINNED_CORE_VERSION, "31.1");
        let statuses: BTreeSet<CommandStatus> = COMMANDS.iter().map(|entry| entry.status).collect();
        assert!(statuses.contains(&CommandStatus::Negotiated));
        assert!(statuses.contains(&CommandStatus::Served));
        assert!(statuses.contains(&CommandStatus::Sink));
        assert!(statuses.contains(&CommandStatus::Ignored));
        assert!(statuses.contains(&CommandStatus::Legacy));
    }
}
