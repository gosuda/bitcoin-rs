//! Bitcoin Core P2P compatibility inventory.

pub const PINNED_CORE_VERSION: &str = "31.1";

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
    "feature",
    "sendpackages",
    "ancpkginfo",
    "getpkgtxns",
    "pkgtxns",
    "staletip",
];

pub const CORE_UNTYPED_COMMANDS: &[&str] = &["sendtxrcncl"];

#[must_use]
pub(crate) fn is_typed_command(name: &str) -> bool {
    COMMANDS.contains(&name)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{COMMANDS, CORE_UNTYPED_COMMANDS};

    #[test]
    fn every_command_name_is_unique_and_fits_the_v1_field() {
        let names: BTreeSet<&str> = COMMANDS.iter().copied().collect();
        assert_eq!(names.len(), COMMANDS.len(), "command names must be unique");
        for name in COMMANDS.iter().chain(CORE_UNTYPED_COMMANDS.iter()) {
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

    #[test]
    fn feature_command_is_typed() {
        assert!(super::is_typed_command(crate::feature::FEATURE_COMMAND));
        assert!(super::is_typed_command("feature"));
    }
}
