#![no_main]

use std::io::Cursor;

use bitcoin_rs_wire::DialFailure;
use bitcoin_rs_wire::sam::{
    check_hello, destination_identity_len, i2p_base64_decode, parse_fields, require_ok,
};
use bitcoin_rs_wire::socks::{
    parse_auth_reply, parse_connect_reply, parse_isolated_greeting, parse_no_auth_greeting,
};
use libfuzzer_sys::fuzz_target;

fn socks5_connect(atyp: u8, bound: &[u8], port: [u8; 2]) -> Vec<u8> {
    let mut reply = vec![0x05, 0x00, 0x00, atyp];
    reply.extend_from_slice(bound);
    reply.extend_from_slice(&port);
    reply
}

fn destination(cert_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0u8; 384];
    bytes.push(cert_type);
    bytes.extend_from_slice(
        &u16::try_from(payload.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    bytes.extend_from_slice(payload);
    bytes
}

fn socks_vectors() {
    assert!(matches!(parse_no_auth_greeting([0x05, 0x00]), Ok(0x00)));
    assert!(matches!(
        parse_isolated_greeting([0x05, 0x02]),
        Ok(0x02)
    ));
    assert!(matches!(
        parse_no_auth_greeting([0x05, 0x02]),
        Err(DialFailure::Transport(_))
    ));
    assert!(matches!(
        parse_isolated_greeting([0x05, 0x00]),
        Err(DialFailure::Transport(_))
    ));
    assert!(matches!(
        parse_isolated_greeting([0x04, 0x02]),
        Err(DialFailure::Transport(_))
    ));
    assert!(parse_auth_reply([0x01, 0x00]).is_ok());
    assert!(matches!(
        parse_auth_reply([0x01, 0x01]),
        Err(DialFailure::Transport(_))
    ));

    let ipv4 = socks5_connect(0x01, &[127, 0, 0, 1], [0x1f, 0x90]);
    assert!(parse_connect_reply(&mut Cursor::new(ipv4)).is_ok());
    let ipv6 = socks5_connect(0x04, &[0u8; 16], [0, 80]);
    assert!(parse_connect_reply(&mut Cursor::new(ipv6)).is_ok());
    let mut domain_bound = vec![11u8];
    domain_bound.extend_from_slice(b"example.com");
    let domain = socks5_connect(0x03, &domain_bound, [0x01, 0xbb]);
    assert!(parse_connect_reply(&mut Cursor::new(domain)).is_ok());

    let refused = [0x05, 0x05, 0x00, 0x01];
    assert!(matches!(
        parse_connect_reply(&mut Cursor::new(refused)),
        Err(DialFailure::PeerUnreachable(_))
    ));
    let denied = [0x05, 0x02, 0x00, 0x01];
    assert!(matches!(
        parse_connect_reply(&mut Cursor::new(denied)),
        Err(DialFailure::Transport(_))
    ));
    let wrong_version = [0x04, 0x00, 0x00, 0x01];
    assert!(matches!(
        parse_connect_reply(&mut Cursor::new(wrong_version)),
        Err(DialFailure::Transport(_))
    ));
    let reserved = [0x05, 0x00, 0x01, 0x01];
    assert!(matches!(
        parse_connect_reply(&mut Cursor::new(reserved)),
        Err(DialFailure::Transport(_))
    ));
    let unknown_atyp = [0x05, 0x00, 0x00, 0x02];
    assert!(matches!(
        parse_connect_reply(&mut Cursor::new(unknown_atyp)),
        Err(DialFailure::Transport(_))
    ));
    let truncated = [0x05, 0x00, 0x00, 0x01, 127, 0, 0];
    assert!(parse_connect_reply(&mut Cursor::new(truncated)).is_err());
    let empty: [u8; 0] = [];
    assert!(parse_connect_reply(&mut Cursor::new(empty)).is_err());
}

fn sam_vectors() {
    let hello = "HELLO REPLY RESULT=OK VERSION=3.3";
    assert!(check_hello(hello).is_ok());
    let fields = parse_fields(hello, "HELLO REPLY");
    assert!(
        matches!(&fields, Ok(fields) if fields.len() == 2
            && fields.iter().any(|(key, value)| key == "RESULT" && value == "OK")
            && fields.iter().any(|(key, value)| key == "VERSION" && value == "3.3"))
    );
    assert!(matches!(
        parse_fields("HELLO REPLY", "HELLO REPLY"),
        Ok(fields) if fields.is_empty()
    ));

    let quoted = "SESSION STATUS RESULT=OK DESTINATION=\"abc def\"";
    assert!(matches!(
        parse_fields(quoted, "SESSION STATUS"),
        Ok(fields) if fields.iter().any(|(key, value)| key == "DESTINATION" && value == "abc def")
    ));
    assert!(parse_fields("SESSION STATUS RESULT=OK RESULT=OK", "SESSION STATUS").is_err());
    assert!(parse_fields("SESSION STATUS RESULT", "SESSION STATUS").is_err());
    assert!(parse_fields("SESSION STATUS =OK", "SESSION STATUS").is_err());
    assert!(parse_fields("SESSION STATUS RESULT=", "SESSION STATUS").is_err());
    assert!(parse_fields("SESSION STATUS RESULT=\"abc", "SESSION STATUS").is_err());
    assert!(parse_fields("SESSION STATUSX RESULT=OK", "SESSION STATUS").is_err());
    assert!(parse_fields("OTHER REPLY RESULT=OK", "SESSION STATUS").is_err());
    assert!(require_ok(hello, "HELLO REPLY").is_ok());
    assert!(require_ok("STREAM STATUS RESULT=CANT_REACH_PEER", "STREAM STATUS").is_err());
    assert!(require_ok("STREAM STATUS RESULT=OK", "STREAM STATUS").is_ok());
    assert!(check_hello("HELLO REPLY RESULT=NOVERSION VERSION=3.3").is_err());
}

fn base64_vectors() {
    assert_eq!(i2p_base64_decode("aGVsbG8="), Some(b"hello".to_vec()));
    assert_eq!(i2p_base64_decode("aGVsbG8"), Some(b"hello".to_vec()));
    assert_eq!(i2p_base64_decode("aGVsbG8h"), Some(b"hello!".to_vec()));
    assert_eq!(i2p_base64_decode(""), None);
    assert_eq!(i2p_base64_decode("a"), None);
    assert_eq!(i2p_base64_decode("===="), None);
    assert_eq!(i2p_base64_decode("aGVsbG8=="), None);
    assert_eq!(i2p_base64_decode("aGVsbG8=x"), None);
    assert_eq!(i2p_base64_decode("aGVs bG8="), None);
    assert_eq!(i2p_base64_decode("aGVsbG8!"), None);
    assert_eq!(i2p_base64_decode("aGVsbG9"), None);
}

fn destination_vectors() {
    assert_eq!(destination_identity_len(&[0u8; 386]), None);
    assert_eq!(destination_identity_len(&destination(0, &[])), Some(387));
    assert!(matches!(
        destination_identity_len(&destination(2, &[])),
        Some(387)
    ));
    assert_eq!(destination_identity_len(&destination(2, &[1])), None);
    assert_eq!(destination_identity_len(&destination(0, &[1])), None);
    assert_eq!(destination_identity_len(&destination(3, &[0u8; 39])), None);
    assert!(destination_identity_len(&destination(1, &[0u8; 12])).is_some());
    let mut truncated = destination(1, &[0u8; 12]);
    truncated.truncate(390);
    assert_eq!(destination_identity_len(&truncated), None);
}

fuzz_target!(|data: &[u8]| {
    socks_vectors();
    sam_vectors();
    base64_vectors();
    destination_vectors();

    if data.len() >= 2 {
        let pair = [data[0], data[1]];
        let _ = parse_isolated_greeting(pair);
        let _ = parse_no_auth_greeting(pair);
        let _ = parse_auth_reply(pair);
    }

    let mut cursor = Cursor::new(data);
    let _ = parse_connect_reply(&mut cursor);

    let reported = destination_identity_len(data);
    if let Some(total) = reported {
        assert!(total <= data.len(), "a destination length must fit its input");
        assert!(total >= 387, "a destination must carry both public keys and a cert");
    }

    if let Ok(text) = std::str::from_utf8(data) {
        let decoded = i2p_base64_decode(text);
        if let Some(bytes) = &decoded {
            assert!(
                bytes.len() <= text.len(),
                "base64 decoding must not expand its input"
            );
        }
        let _ = check_hello(text);
        let _ = parse_fields(text, "HELLO REPLY");
        let _ = parse_fields(text, "SESSION STATUS");
        let _ = parse_fields(text, "STREAM STATUS");
        let _ = parse_fields(text, "DEST REPLY");
        let _ = require_ok(text, "SESSION STATUS");
        let _ = require_ok(text, "STREAM STATUS");
    }

    let mut reply = socks5_connect(
        data.first().copied().unwrap_or_default() % 5,
        data,
        [data.get(1).copied().unwrap_or(0), data.get(2).copied().unwrap_or(0)],
    );
    reply[1] = data.get(3).copied().unwrap_or_default() % 9;
    let _ = parse_connect_reply(&mut Cursor::new(reply));
});
