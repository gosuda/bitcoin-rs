use alloc::sync::Arc;

use super::*;

const ADDRESS: &str = "1111111111111111111114oLvT2";

#[test]
fn getdescriptorinfo_emits_8_char_bech32_checksum() {
    let ctx = Arc::new(Context::new());
    let result = getdescriptorinfo(&ctx, &json!(["addr(1111111111111111111114oLvT2)"]))
        .unwrap_or_else(|err| panic!("getdescriptorinfo failed: {err}"));
    let Some(checksum) = result.get("checksum").and_then(|v| v.as_str()) else {
        panic!("checksum missing: {result:?}");
    };
    assert_eq!(checksum.len(), 8, "checksum must be 8 chars: {checksum}");
    for ch in checksum.chars() {
        assert!(
            BIP380_CHECKSUM_CHARSET.iter().any(|b| char::from(*b) == ch),
            "checksum char {ch} not in bech32 charset"
        );
    }
}

#[test]
fn the_checksum_matches_the_bip380_vector() {
    const DESCRIPTOR: &str = "raw(deadbeef)";
    const CHECKSUM: &str = "89f8spxm";

    let ctx = Arc::new(Context::new());
    let result = getdescriptorinfo(&ctx, &json!([DESCRIPTOR]))
        .unwrap_or_else(|err| panic!("getdescriptorinfo failed: {err}"));
    assert_eq!(
        result.get("checksum").and_then(JsonValueTrait::as_str),
        Some(CHECKSUM)
    );

    let with_checksum = getdescriptorinfo(&ctx, &json!([format!("{DESCRIPTOR}#{CHECKSUM}")]))
        .unwrap_or_else(|err| panic!("a correct checksum must be accepted: {err}"));
    assert_eq!(
        with_checksum
            .get("checksum")
            .and_then(JsonValueTrait::as_str),
        Some(CHECKSUM)
    );
}

#[test]
fn a_checksum_that_does_not_match_is_refused() {
    let ctx = Arc::new(Context::new());

    for (input, expected) in [
        (format!("addr({ADDRESS})#qqqqqqqq"), "does not match"),
        (
            format!("addr({ADDRESS})#short"),
            "Expected 8 character checksum",
        ),
        (
            format!("addr({ADDRESS})#aaaaaaaa#bbbbbbbb"),
            "Multiple '#' symbols",
        ),
    ] {
        let error = getdescriptorinfo(&ctx, &json!([input.clone()]))
            .err()
            .unwrap_or_else(|| panic!("`{input}` must be refused"));
        assert_eq!(error.code(), RpcError::CORE_NOT_FOUND, "for `{input}`");
        assert!(
            error.to_string().contains(expected),
            "`{input}` must say why: got {error}"
        );
    }
}

#[test]
fn getdescriptorinfo_does_not_require_a_checksum() {
    let ctx = Arc::new(Context::new());
    let result = getdescriptorinfo(&ctx, &json!([format!("addr({ADDRESS})")]))
        .unwrap_or_else(|err| panic!("a bare descriptor must be analysed: {err}"));
    let Some(canonical) = result.get("descriptor").and_then(JsonValueTrait::as_str) else {
        panic!("descriptor missing: {result:?}");
    };
    assert!(
        canonical.starts_with(&format!("addr({ADDRESS})#")),
        "the canonical form carries its own checksum: {canonical}"
    );
}

#[test]
fn the_canonical_descriptor_carries_its_own_checksum() {
    let ctx = Arc::new(Context::new());
    let result = getdescriptorinfo(&ctx, &json!([format!("addr({ADDRESS})")]))
        .unwrap_or_else(|err| panic!("getdescriptorinfo failed: {err}"));

    let Some(canonical) = result.get("descriptor").and_then(JsonValueTrait::as_str) else {
        panic!("descriptor missing: {result:?}");
    };
    let Some((body, sum)) = canonical.rsplit_once('#') else {
        panic!("the canonical form must carry a checksum: {canonical}");
    };
    assert_eq!(body, format!("addr({ADDRESS})"));
    assert_eq!(sum.len(), 8);

    let derived = deriveaddresses(&ctx, &json!([canonical]))
        .unwrap_or_else(|err| panic!("the canonical form must be usable as-is: {err}"));
    assert_eq!(derived, json!([ADDRESS]));
}

#[test]
fn an_address_descriptor_is_not_solvable() {
    let ctx = Arc::new(Context::new());
    let result = getdescriptorinfo(&ctx, &json!([format!("addr({ADDRESS})")]))
        .unwrap_or_else(|err| panic!("getdescriptorinfo failed: {err}"));

    assert_eq!(
        result.get("issolvable").and_then(JsonValueTrait::as_bool),
        Some(false)
    );
    assert_eq!(
        result.get("isrange").and_then(JsonValueTrait::as_bool),
        Some(false)
    );
}

#[test]
fn a_key_descriptor_is_solvable() {
    let ctx = Arc::new(Context::new());
    let descriptor = "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)";
    let result = getdescriptorinfo(&ctx, &json!([descriptor]))
        .unwrap_or_else(|err| panic!("getdescriptorinfo failed: {err}"));

    assert_eq!(
        result.get("issolvable").and_then(JsonValueTrait::as_bool),
        Some(true)
    );
    assert_eq!(
        result
            .get("hasprivatekeys")
            .and_then(JsonValueTrait::as_bool),
        Some(false),
        "a public key is not a private one"
    );
}

#[test]
fn a_private_key_is_reported_and_not_echoed_back() {
    let ctx = Arc::new(Context::new());
    let xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
    let with_key = format!("wpkh({xprv}/0/0)");
    let result = getdescriptorinfo(&ctx, &json!([with_key]))
        .unwrap_or_else(|err| panic!("getdescriptorinfo failed: {err}"));

    assert_eq!(
        result
            .get("hasprivatekeys")
            .and_then(JsonValueTrait::as_bool),
        Some(true)
    );
    let Some(canonical) = result.get("descriptor").and_then(JsonValueTrait::as_str) else {
        panic!("descriptor missing: {result:?}");
    };
    assert!(
        !canonical.contains(xprv),
        "the private key must not come back out: {canonical}"
    );
    assert!(
        canonical.contains("xpub"),
        "the canonical form carries the public key: {canonical}"
    );
}

#[test]
fn a_descriptor_that_does_not_parse_is_refused() {
    let ctx = Arc::new(Context::new());
    let error = getdescriptorinfo(&ctx, &json!(["addr(x)"]))
        .err()
        .unwrap_or_else(|| panic!("addr(x) is not an address"));
    assert_eq!(error.code(), RpcError::CORE_NOT_FOUND, "{error:?}");
}

#[test]
fn combo_is_canonicalized_and_private_keys_are_redacted() {
    let ctx = Arc::new(Context::new());
    let key = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
    let result = getdescriptorinfo(&ctx, &json!([format!("combo({key})")]))
        .unwrap_or_else(|err| panic!("getdescriptorinfo failed: {err}"));
    assert!(
        result
            .get("descriptor")
            .and_then(JsonValueTrait::as_str)
            .is_some_and(|descriptor| descriptor.starts_with(&format!("combo({key})#")))
    );
    assert_eq!(
        result
            .get("hasprivatekeys")
            .and_then(JsonValueTrait::as_bool),
        Some(false)
    );
    assert_eq!(
        result.get("issolvable").and_then(JsonValueTrait::as_bool),
        Some(true)
    );
    assert_eq!(
        result.get("isrange").and_then(JsonValueTrait::as_bool),
        Some(false)
    );
    assert!(
        result.get("multipath_expansion").is_none(),
        "single-path combo must omit multipath_expansion: {result:?}"
    );

    let xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
    let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
    let private = getdescriptorinfo(&ctx, &json!([format!("combo({xprv}/0/0)")]))
        .unwrap_or_else(|err| panic!("combo with an xprv must parse: {err}"));
    assert_eq!(
        private
            .get("hasprivatekeys")
            .and_then(JsonValueTrait::as_bool),
        Some(true)
    );
    let Some(canonical) = private.get("descriptor").and_then(JsonValueTrait::as_str) else {
        panic!("descriptor missing: {private:?}");
    };
    assert!(
        !canonical.contains(xprv),
        "the private key must not come back out: {canonical}"
    );
    assert!(
        canonical.starts_with(&format!("combo({xpub}/0/0)#")),
        "the canonical form is the public combo: {canonical}"
    );
}

#[test]
fn checksummed_combo_is_analysed() {
    let ctx = Arc::new(Context::new());
    let key = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
    let bare = format!("combo({key})");
    let checksum =
        descriptor_checksum(&bare).unwrap_or_else(|| panic!("{bare} must have a checksum"));

    let with = getdescriptorinfo(&ctx, &json!([format!("{bare}#{checksum}")]))
        .unwrap_or_else(|err| panic!("checksummed combo must analyse: {err}"));
    let without = getdescriptorinfo(&ctx, &json!([bare]))
        .unwrap_or_else(|err| panic!("bare combo must analyse: {err}"));
    assert_eq!(without, with);
}

#[test]
fn combo_multipath_is_expanded() {
    let ctx = Arc::new(Context::new());
    let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
    let result = getdescriptorinfo(&ctx, &json!([format!("combo({xpub}/<0;1>/*)")]))
        .unwrap_or_else(|err| panic!("multipath combo must parse: {err}"));
    let Some(canonical) = result.get("descriptor").and_then(JsonValueTrait::as_str) else {
        panic!("descriptor missing: {result:?}");
    };
    assert!(
        canonical.starts_with(&format!("combo({xpub}/0/*)#")),
        "the first expansion is canonical: {canonical}"
    );
    let Some(expansions) = result.get("multipath_expansion").and_then(Value::as_array) else {
        panic!("multipath combo must report expansions: {result:?}");
    };
    assert_eq!(expansions.len(), 2, "{result:?}");
    let Some(first) = expansions.first().and_then(JsonValueTrait::as_str) else {
        panic!("first expansion missing: {result:?}");
    };
    let Some(second) = expansions.get(1).and_then(JsonValueTrait::as_str) else {
        panic!("second expansion missing: {result:?}");
    };
    assert_eq!(first, canonical);
    assert!(
        second.starts_with(&format!("combo({xpub}/1/*)#")),
        "second path in specifier order: {second}"
    );
    assert_eq!(
        result.get("isrange").and_then(JsonValueTrait::as_bool),
        Some(true)
    );
}

#[test]
fn combo_rejects_a_wif_from_another_network() {
    let ctx = Arc::new(Context::new());
    let wif = testnet_compressed_wif();
    let error = getdescriptorinfo(&ctx, &json!([format!("combo({wif})")]))
        .err()
        .unwrap_or_else(|| panic!("a testnet WIF must not analyse on mainnet"));
    assert_eq!(error.code(), RpcError::CORE_NOT_FOUND);
    assert!(
        error.to_string().contains("test network"),
        "the refusal must say which network the key is for: {error}"
    );
}

#[test]
fn combo_rejects_a_testnet_extended_key_on_mainnet() {
    let ctx = Arc::new(Context::new());
    let tpub = "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B";
    let error = getdescriptorinfo(&ctx, &json!([format!("combo({tpub}/0/*)")]))
        .err()
        .unwrap_or_else(|| panic!("a testnet xpub must not analyse on mainnet"));
    assert_eq!(error.code(), RpcError::CORE_NOT_FOUND);
    assert!(error.to_string().contains("test network"), "got {error}");
}

fn testnet_compressed_wif() -> String {
    let secret = bitcoin::secp256k1::SecretKey::from_slice(&[
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,
    ])
    .unwrap_or_else(|err| panic!("secret 1 is valid: {err}"));
    bitcoin::PrivateKey {
        compressed: true,
        network: bitcoin::NetworkKind::Test,
        inner: secret,
    }
    .to_string()
}
