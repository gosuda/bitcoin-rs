// CONTRACT: `crates/mining/README.md` owns the node-facing BIP22/BIP23
// long-poll identity contract; `docs/contracts/external-api.md#API-11` owns
// the corresponding `getblocktemplate` long-poll surface.
use super::GenerationKey;
use super::parse_long_poll_id;
use crate::template::TemplateId;
use bitcoin_rs_primitives::Hash256;

#[test]
fn long_poll_round_trips_template_id() {
    let tip = Hash256::from_le_bytes(&[0x11; 32]);
    let key = GenerationKey {
        tip_hash: tip,
        mempool_sequence: 7,
    };
    let id = key.template_id();
    let Some(parsed) = parse_long_poll_id(id.as_str()) else {
        panic!("generated long-poll id did not parse");
    };
    assert_eq!(parsed, key);
    assert_eq!(TemplateId::new(&tip, 7).as_str(), id.as_str());
}

#[test]
fn long_poll_rejects_non_ascii_split_boundary_without_panicking() {
    // API-11 requires malformed longpollids, including invalid UTF-8 split
    // boundaries, to be rejected without panicking. 63 ASCII bytes followed
    // by a two-byte UTF-8 scalar makes byte 64 an invalid character boundary.
    let malformed = format!("{}é", "0".repeat(63));
    assert_eq!(malformed.len(), 65);
    assert!(parse_long_poll_id(&malformed).is_none());
}
