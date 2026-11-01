#![no_main]

use std::io::Cursor;

use bitcoin_rs_p2p::sam::{
    check_hello, destination_identity_len, i2p_base64_decode, parse_fields, require_ok,
};
use bitcoin_rs_p2p::socks::{
    parse_auth_reply, parse_connect_reply, parse_isolated_greeting, parse_no_auth_greeting,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() >= 2 {
        let pair = [data[0], data[1]];
        let _ = parse_isolated_greeting(pair);
        let _ = parse_no_auth_greeting(pair);
        let _ = parse_auth_reply(pair);
    }

    let mut cursor = Cursor::new(data);
    let _ = parse_connect_reply(&mut cursor);

    let _ = destination_identity_len(data);

    if let Ok(text) = std::str::from_utf8(data) {
        let _ = i2p_base64_decode(text);
        let _ = check_hello(text);
        let _ = parse_fields(text, "HELLO REPLY");
        let _ = parse_fields(text, "SESSION STATUS");
        let _ = parse_fields(text, "STREAM STATUS");
        let _ = parse_fields(text, "DEST REPLY");
        let _ = require_ok(text, "SESSION STATUS");
        let _ = require_ok(text, "STREAM STATUS");
    }
});
