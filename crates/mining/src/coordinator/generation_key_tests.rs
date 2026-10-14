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

/// `é` is two bytes, so the 64-char prefix lands mid-codepoint: the slice
/// boundary must be non-ASCII, not just non-UTF8-safe.
#[test]
fn long_poll_rejects_non_ascii_split_boundary_without_panicking() {
    let malformed = format!("{}é", "0".repeat(63));
    assert_eq!(malformed.len(), 65);
    assert!(parse_long_poll_id(&malformed).is_none());
}
