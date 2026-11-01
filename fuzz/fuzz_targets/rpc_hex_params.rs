#![no_main]

use std::str::FromStr as _;

use bitcoin::hex::{DisplayHex as _, FromHex as _};
use libfuzzer_sys::fuzz_target;

fn check_hex(s: &str) {
    if let Ok(bytes) = Vec::<u8>::from_hex(s) {
        let formatted = bytes.to_lower_hex_string();
        let re_parsed = Vec::<u8>::from_hex(&formatted);
        assert_eq!(
            Ok(&bytes),
            re_parsed.as_ref(),
            "hex parse-then-format must roundtrip"
        );
        assert!(
            formatted
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "formatted hex must be lowercase canonical"
        );
    }
}

fn check_txid(s: &str) {
    if let Ok(txid) = bitcoin_rs_primitives::Txid::from_str(s) {
        let formatted = txid.to_string();
        let re_parsed = bitcoin_rs_primitives::Txid::from_str(&formatted);
        assert_eq!(Ok(txid), re_parsed, "txid parse-then-format must roundtrip");
        assert!(
            formatted
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "formatted txid must be lowercase canonical"
        );
    }
}

fn check_blockhash(s: &str) {
    if let Ok(hash) = bitcoin_rs_primitives::BlockHash::from_str(s) {
        let formatted = hash.to_string();
        let re_parsed = bitcoin_rs_primitives::BlockHash::from_str(&formatted);
        assert_eq!(
            Ok(hash),
            re_parsed,
            "blockhash parse-then-format must roundtrip"
        );
        assert!(
            formatted
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "formatted blockhash must be lowercase canonical"
        );
    }
}

fn check_scripthash(s: &str) {
    if let Ok(raw) = <[u8; 32]>::from_hex(s) {
        let hash = bitcoin_rs_index::ScriptHash::from_byte_array(raw);
        let formatted = hash.to_byte_array().to_lower_hex_string();
        let re_parsed = <[u8; 32]>::from_hex(&formatted);
        assert_eq!(
            Ok(raw),
            re_parsed,
            "scripthash parse-then-format must roundtrip"
        );
        assert!(
            formatted
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "formatted scripthash must be lowercase canonical"
        );
    }
}

fn check_address(s: &str) {
    if let Ok(addr) = bitcoin::Address::from_str(s) {
        let addr = addr.assume_checked();
        let formatted = addr.to_string();
        let re_parsed = bitcoin::Address::from_str(&formatted);
        assert!(
            re_parsed.is_ok(),
            "formatted address must be re-parseable: {formatted}"
        );
        if let Ok(re_addr) = re_parsed {
            assert_eq!(
                addr,
                re_addr.assume_checked(),
                "address parse-then-format must roundtrip"
            );
        }
    }
}

fn check_descriptor(s: &str) {
    let secp = bitcoin::secp256k1::Secp256k1::signing_only();
    if let Ok((desc, _)) =
        miniscript::Descriptor::<miniscript::DescriptorPublicKey>::parse_descriptor(&secp, s)
    {
        let formatted = desc.to_string();
        let re_parsed = miniscript::Descriptor::<miniscript::DescriptorPublicKey>::parse_descriptor(
            &secp, &formatted,
        );
        assert!(
            re_parsed.is_ok(),
            "formatted descriptor must be re-parseable: {formatted}"
        );
        if let Ok((re_desc, _)) = re_parsed {
            assert_eq!(desc, re_desc, "descriptor re-parse must equal parsed");
        }
    }
}

fn check_numeric(s: &str) {
    if let Ok(val) = s.parse::<u64>() {
        let formatted = val.to_string();
        let re_parsed = formatted.parse::<u64>();
        assert_eq!(Ok(val), re_parsed, "u64 parse-then-format must roundtrip");
    }
    if let Ok(val) = s.parse::<i64>() {
        let formatted = val.to_string();
        let re_parsed = formatted.parse::<i64>();
        assert_eq!(Ok(val), re_parsed, "i64 parse-then-format must roundtrip");
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(s) = core::str::from_utf8(data) else {
        return;
    };

    check_hex(s);
    check_txid(s);
    check_blockhash(s);
    check_scripthash(s);
    check_address(s);
    check_descriptor(s);
    check_numeric(s);
});
