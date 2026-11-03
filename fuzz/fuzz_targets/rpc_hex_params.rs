#![no_main]

use std::str::FromStr;

use bitcoin::hex::{DisplayHex as _, FromHex as _};
use libfuzzer_sys::fuzz_target;

fn is_lower_hex(text: &str) -> bool {
    text.chars()
        .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

fn check_format_roundtrip<T>(s: &str, what: &str)
where
    T: FromStr + std::fmt::Display + std::fmt::Debug + PartialEq,
    T::Err: std::fmt::Debug + PartialEq,
{
    if let Ok(value) = T::from_str(s) {
        let formatted = value.to_string();
        assert_eq!(
            Ok(&value),
            T::from_str(&formatted).as_ref(),
            "{what} parse-then-format must roundtrip"
        );
    }
}

fn check_lower_hex_format<T>(s: &str, what: &str)
where
    T: FromStr + std::fmt::Display + std::fmt::Debug + PartialEq,
    T::Err: std::fmt::Debug + PartialEq,
{
    if let Ok(value) = T::from_str(s) {
        let formatted = value.to_string();
        assert_eq!(
            Ok(&value),
            T::from_str(&formatted).as_ref(),
            "{what} parse-then-format must roundtrip"
        );
        assert!(
            is_lower_hex(&formatted),
            "formatted {what} must be lowercase canonical"
        );
    }
}

fn check_hex(s: &str) {
    if let Ok(bytes) = Vec::<u8>::from_hex(s) {
        let formatted = bytes.to_lower_hex_string();
        assert_eq!(
            Ok(&bytes),
            Vec::<u8>::from_hex(&formatted).as_ref(),
            "hex parse-then-format must roundtrip"
        );
        assert!(
            is_lower_hex(&formatted),
            "formatted hex must be lowercase canonical"
        );
    }
}

fn check_scripthash(s: &str) {
    if let Ok(raw) = <[u8; 32]>::from_hex(s) {
        let hash = bitcoin_rs_index::ScriptHash::from_byte_array(raw);
        let formatted = hash.to_byte_array().to_lower_hex_string();
        assert_eq!(
            Ok(raw),
            <[u8; 32]>::from_hex(&formatted),
            "scripthash parse-then-format must roundtrip"
        );
        assert!(
            is_lower_hex(&formatted),
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

fuzz_target!(|data: &[u8]| {
    let Ok(s) = core::str::from_utf8(data) else {
        return;
    };

    check_hex(s);
    check_lower_hex_format::<bitcoin_rs_primitives::Txid>(s, "txid");
    check_lower_hex_format::<bitcoin_rs_primitives::BlockHash>(s, "blockhash");
    check_scripthash(s);
    check_address(s);
    check_descriptor(s);
    check_format_roundtrip::<u64>(s, "u64");
    check_format_roundtrip::<i64>(s, "i64");
});
