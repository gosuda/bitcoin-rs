//! BIP324 message types: a one-byte ID for the commands the BIP assigns, or a
//! zero byte followed by the 12-byte command field of the v1 header.

use bitcoin::p2p::message::CommandString;
use bytes::Bytes;

use crate::wire::read_command;

/// Commands with a one-byte ID, indexed by that ID. Index 0 introduces the
/// 13-byte long form; IDs past the table are undefined.
const SHORT_IDS: [&str; 38] = [
    "",
    "addr",
    "block",
    "blocktxn",
    "cmpctblock",
    "feefilter",
    "filteradd",
    "filterclear",
    "filterload",
    "getblocks",
    "getblocktxn",
    "getdata",
    "getheaders",
    "headers",
    "inv",
    "mempool",
    "merkleblock",
    "notfound",
    "ping",
    "pong",
    "sendcmpct",
    "tx",
    "getcfilters",
    "cfilter",
    "getcfheaders",
    "cfheaders",
    "getcfcheckpt",
    "cfcheckpt",
    "addrv2",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    crate::feature::FEATURE_COMMAND,
];

/// First byte of the long form.
const LONG_FORM: u8 = 0;

/// Bytes of the command field that follows [`LONG_FORM`].
const COMMAND_LEN: usize = 12;

pub(crate) fn encode(command: &CommandString, payload: &[u8]) -> Vec<u8> {
    let name = command.as_ref();
    let short_id = SHORT_IDS
        .iter()
        .skip(1)
        .position(|known| !known.is_empty() && *known == name)
        .and_then(|index| u8::try_from(index + 1).ok());
    let mut contents = Vec::with_capacity(1 + COMMAND_LEN + payload.len());
    if let Some(id) = short_id {
        contents.push(id);
    } else {
        let mut field = [0u8; COMMAND_LEN];
        let len = name.len().min(COMMAND_LEN);
        field[..len].copy_from_slice(&name.as_bytes()[..len]);
        contents.push(LONG_FORM);
        contents.extend_from_slice(&field);
    }
    contents.extend_from_slice(payload);
    contents
}

/// Splits packet contents into their command and payload, or `None` when the
/// type is empty, undefined, or malformed. BIP324 peers drop such a message
/// and keep the connection.
pub(crate) fn decode(contents: &Bytes) -> Option<(String, Bytes)> {
    let first = *contents.first()?;
    if first == LONG_FORM {
        let field = contents.get(1..=COMMAND_LEN)?;
        let command = read_command(field)
            .ok()
            .filter(|command| !command.is_empty())?;
        return Some((command, contents.slice(1 + COMMAND_LEN..)));
    }
    let command = SHORT_IDS
        .get(usize::from(first))
        .copied()
        .filter(|command| !command.is_empty())?;
    Some((command.to_owned(), contents.slice(1..)))
}

#[cfg(test)]
mod tests {
    use bitcoin::p2p::message::CommandString;
    use bytes::Bytes;

    use super::{COMMAND_LEN, LONG_FORM, SHORT_IDS, decode, encode};

    fn command(name: &str) -> CommandString {
        name.parse()
            .unwrap_or_else(|_| panic!("valid command {name}"))
    }

    #[test]
    fn every_assigned_command_uses_its_one_byte_id() {
        for (id, name) in SHORT_IDS.iter().enumerate().skip(1) {
            if name.is_empty() {
                continue;
            }
            let contents = encode(&command(name), b"payload");
            assert_eq!(usize::from(contents[0]), id, "{name}");
            assert_eq!(&contents[1..], b"payload");
            let decoded = decode(&Bytes::from(contents));
            assert_eq!(
                decoded,
                Some(((*name).to_owned(), Bytes::from_static(b"payload")))
            );
        }
    }

    #[test]
    fn undefined_sparse_ids_yield_none() {
        for id in 29..=36 {
            assert_eq!(decode(&Bytes::from(vec![id, 1, 2])), None, "sparse id {id}");
        }
    }

    #[test]
    fn feature_short_id_37_maps_correctly() {
        let contents = encode(&command("feature"), b"payload");
        assert_eq!(contents[0], 37);
        assert_eq!(&contents[1..], b"payload");
        let decoded = decode(&Bytes::from(contents));
        assert_eq!(
            decoded,
            Some(("feature".to_owned(), Bytes::from_static(b"payload")))
        );

        let mut long = vec![LONG_FORM];
        long.extend_from_slice(b"feature\0\0\0\0\0");
        long.extend_from_slice(b"payload");
        assert_eq!(
            decode(&Bytes::from(long)),
            Some(("feature".to_owned(), Bytes::from_static(b"payload")))
        );
    }

    #[test]
    fn unassigned_commands_use_the_long_form() {
        for name in [
            "version",
            "verack",
            "wtxidrelay",
            "sendaddrv2",
            "sendheaders",
        ] {
            let contents = encode(&command(name), b"x");
            assert_eq!(contents[0], LONG_FORM);
            assert_eq!(contents.len(), 1 + COMMAND_LEN + 1);
            assert_eq!(
                decode(&Bytes::from(contents)),
                Some((name.to_owned(), Bytes::from_static(b"x")))
            );
        }
    }

    #[test]
    fn assigned_commands_decode_from_either_encoding() {
        let mut long = vec![LONG_FORM];
        long.extend_from_slice(b"ping\0\0\0\0\0\0\0\0");
        long.extend_from_slice(&7u64.to_le_bytes());
        let short = encode(&command("ping"), &7u64.to_le_bytes());
        assert_eq!(decode(&Bytes::from(long)), decode(&Bytes::from(short)));
    }

    #[test]
    fn empty_undefined_and_malformed_types_are_dropped() {
        assert_eq!(decode(&Bytes::new()), None);
        for id in 29..=36 {
            assert_eq!(decode(&Bytes::from(vec![id, 1, 2])), None, "sparse id {id}");
        }
        for id in u8::try_from(SHORT_IDS.len()).unwrap_or(u8::MAX)..=u8::MAX {
            assert_eq!(decode(&Bytes::from(vec![id, 1, 2])), None, "id {id}");
        }
        assert_eq!(decode(&Bytes::from_static(b"\0ping")), None);
        assert_eq!(decode(&Bytes::from_static(b"\0ping\0\0\0\0\0\0\0x")), None);
        assert_eq!(decode(&Bytes::from(vec![0u8; 1 + COMMAND_LEN + 4])), None);
    }
}
