use super::format::*;

// PRJ-08
#[test]
fn posting_holds_reference_and_flags_only() {
    let gen_id = 1u64;
    let script_id = 42u32;
    let chunk = 0u32;
    let key = encode_script_post_key(gen_id, script_id, chunk);

    assert_eq!(key.len(), SCRIPT_POST_KEY_LEN);
    assert_eq!(key.len(), 16);
    assert!(key.len() < 32);

    let items = vec![
        PostingItem {
            delta_ordinal: 10,
            flags: POSTING_FLAG_FUNDING,
        },
        PostingItem {
            delta_ordinal: 5,
            flags: POSTING_FLAG_SPENDING,
        },
    ];

    let encoded = encode_posting_items(&items);
    let Some(decoded) = decode_posting_items(&encoded) else {
        panic!("posting decode failed");
    };
    assert_eq!(decoded, items);

    for item in decoded {
        assert!(item.flags == POSTING_FLAG_FUNDING || item.flags == POSTING_FLAG_SPENDING);
    }
}
