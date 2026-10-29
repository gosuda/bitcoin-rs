use alloc::sync::Arc;

use super::*;

const ADDRESS: &str = "1111111111111111111114oLvT2";

fn checksummed(descriptor: &str) -> String {
    let Some(checksum) = descriptor_checksum(descriptor) else {
        panic!("the fixture descriptor `{descriptor}` must have a checksum");
    };
    format!("{descriptor}#{checksum}")
}

#[test]
fn an_address_descriptor_derives_its_own_address() {
    let ctx = Arc::new(Context::new());
    let result = deriveaddresses(&ctx, &json!([checksummed(&format!("addr({ADDRESS})"))]))
        .unwrap_or_else(|err| panic!("deriveaddresses failed: {err}"));

    assert_eq!(result, json!([ADDRESS]));
}

#[test]
fn a_range_too_large_to_serve_is_refused_before_any_work() {
    let ctx = Arc::new(Context::new());
    let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
    let descriptor = checksummed(&format!("wpkh({xpub}/0/*)"));

    let started = std::time::Instant::now();
    for (range, expected) in [
        (json!([0, 4_294_967_295_u64]), "End of range is too high"),
        (json!([0, 2_147_483_648_u64]), "End of range is too high"),
        (json!([0, 2_147_483_647_u64]), "Range is too large"),
        (json!([0, 1_000_000]), "Range is too large"),
        (json!(1_000_000), "Range is too large"),
    ] {
        let error = deriveaddresses(&ctx, &json!([descriptor.clone(), range.clone()]))
            .err()
            .unwrap_or_else(|| panic!("{range:?} must be refused"));
        assert_eq!(
            error.code(),
            RpcError::CORE_INVALID_PARAMETER,
            "for {range:?}"
        );
        assert!(
            error.to_string().contains(expected),
            "for {range:?}: {error}"
        );
    }
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "the refusals must happen before the derivation, not after it"
    );

    let ok = deriveaddresses(&ctx, &json!([descriptor, [10, 12]]))
        .unwrap_or_else(|err| panic!("a modest range must still work: {err}"));
    assert_eq!(ok.as_array().map(sonic_rs::Array::len), Some(3));
}

#[test]
fn a_testnet_key_does_not_derive_mainnet_addresses() {
    let ctx = Arc::new(Context::new());
    let tpub = "tpubD6NzVbkrYhZ4XgiXtGrdW5XDAPFCL9h7we1vwNCpn8tGbBcgfVYjXyhWo4E1xkh56hjod1RhGjxbaTLV3X4FyWuejifB9jusQ46QzG87VKp";
    let descriptor = checksummed(&format!("wpkh({tpub}/0/*)"));

    let error = deriveaddresses(&ctx, &json!([descriptor, [0, 1]]))
        .err()
        .unwrap_or_else(|| panic!("a testnet key must not derive mainnet addresses"));
    assert_eq!(error.code(), RpcError::CORE_NOT_FOUND);
    assert!(
        error.to_string().contains("test network"),
        "the refusal must say which network the key is for: {error}"
    );
}

#[test]
fn deriveaddresses_requires_a_checksum() {
    let ctx = Arc::new(Context::new());

    let error = deriveaddresses(&ctx, &json!([format!("addr({ADDRESS})")]))
        .err()
        .unwrap_or_else(|| panic!("a descriptor with no checksum must be refused"));
    assert_eq!(error.code(), RpcError::CORE_NOT_FOUND);
    assert!(
        error.to_string().contains("Missing checksum"),
        "got {error}"
    );

    let accepted = deriveaddresses(&ctx, &json!([checksummed(&format!("addr({ADDRESS})"))]))
        .unwrap_or_else(|err| panic!("the same descriptor with a checksum: {err}"));
    assert_eq!(accepted, json!([ADDRESS]));
}

#[test]
fn a_key_descriptor_derives_an_address() {
    let ctx = Arc::new(Context::new());
    let descriptor =
        checksummed("wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)");
    let result = deriveaddresses(&ctx, &json!([descriptor]))
        .unwrap_or_else(|err| panic!("deriveaddresses failed: {err}"));

    let Some(addresses) = result.as_array() else {
        panic!("expected an array: {result:?}");
    };
    assert_eq!(addresses.len(), 1);
    let Some(address) = addresses.first().and_then(JsonValueTrait::as_str) else {
        panic!("expected a string: {result:?}");
    };
    assert!(
        address.starts_with("bc1q"),
        "a mainnet v0 segwit address: {address}"
    );
}

#[test]
fn a_ranged_descriptor_derives_one_address_per_index() {
    let ctx = Arc::new(Context::new());
    let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
    let descriptor = checksummed(&format!("wpkh({xpub}/0/*)"));
    let result = deriveaddresses(&ctx, &json!([descriptor, [0, 2]]))
        .unwrap_or_else(|err| panic!("deriveaddresses failed: {err}"));

    let Some(addresses) = result.as_array() else {
        panic!("expected an array: {result:?}");
    };
    assert_eq!(addresses.len(), 3, "0, 1 and 2: {result:?}");
    let distinct: std::collections::BTreeSet<&str> = addresses
        .iter()
        .filter_map(JsonValueTrait::as_str)
        .collect();
    assert_eq!(
        distinct.len(),
        3,
        "each index is its own address: {result:?}"
    );
}

#[test]
fn the_range_argument_must_match_the_descriptor() {
    let ctx = Arc::new(Context::new());
    let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

    let missing = deriveaddresses(&ctx, &json!([checksummed(&format!("wpkh({xpub}/0/*)"))]))
        .err()
        .unwrap_or_else(|| panic!("a ranged descriptor needs a range"));
    assert_eq!(missing.code(), RpcError::CORE_INVALID_PARAMETER);

    let fixed_key =
        checksummed("wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)");
    for fixed in [fixed_key, checksummed(&format!("addr({ADDRESS})"))] {
        let unwanted = deriveaddresses(&ctx, &json!([fixed.clone(), [0, 2]]))
            .err()
            .unwrap_or_else(|| panic!("a fixed descriptor takes no range: {fixed}"));
        assert_eq!(
            unwanted.code(),
            RpcError::CORE_INVALID_PARAMETER,
            "for {fixed}"
        );
    }
}

#[test]
fn combo_derives_core_regtest_addresses() {
    let mut ctx = Context::new();
    ctx.chain.chain_network = bitcoin_rs_primitives::Network::Regtest;
    let ctx = Arc::new(ctx);
    let tprv = "tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK";
    let result = deriveaddresses(&ctx, &json!([checksummed(&format!("combo({tprv}/1/1/0)"))]))
        .unwrap_or_else(|err| panic!("combo must derive: {err}"));
    assert_eq!(
        result,
        json!([
            "mtfUoUax9L4tzXARpw1oTGxWyoogp52KhJ",
            "bcrt1qjqmxmkpmxt80xz4y3746zgt0q3u3ferr34acd5",
            "2NDvEwGfpEqJWfybzpKPHF2XH3jwoQV3D7x"
        ])
    );
}

#[test]
fn combo_uncompressed_derives_only_p2pkh() {
    let ctx = Arc::new(Context::new());
    let key = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
    let combo = deriveaddresses(&ctx, &json!([checksummed(&format!("combo({key})"))]))
        .unwrap_or_else(|err| panic!("uncompressed combo must derive: {err}"));
    let pkh = deriveaddresses(&ctx, &json!([checksummed(&format!("pkh({key})"))]))
        .unwrap_or_else(|err| panic!("pkh of the same key: {err}"));
    assert_eq!(combo, pkh);
    assert_eq!(combo.as_array().map(sonic_rs::Array::len), Some(1));
}

#[test]
fn combo_compressed_derives_the_bip384_address_set() {
    let ctx = Arc::new(Context::new());
    let key = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    let combo = deriveaddresses(&ctx, &json!([checksummed(&format!("combo({key})"))]))
        .unwrap_or_else(|err| panic!("compressed combo must derive: {err}"));
    let pkh = deriveaddresses(&ctx, &json!([checksummed(&format!("pkh({key})"))]))
        .unwrap_or_else(|err| panic!("pkh: {err}"));
    let wpkh = deriveaddresses(&ctx, &json!([checksummed(&format!("wpkh({key})"))]))
        .unwrap_or_else(|err| panic!("wpkh: {err}"));
    let sh_wpkh = deriveaddresses(&ctx, &json!([checksummed(&format!("sh(wpkh({key}))"))]))
        .unwrap_or_else(|err| panic!("sh(wpkh): {err}"));
    let expected = json!([
        pkh.as_array()
            .and_then(|arr| arr.first())
            .cloned()
            .unwrap_or_else(|| panic!("pkh address")),
        wpkh.as_array()
            .and_then(|arr| arr.first())
            .cloned()
            .unwrap_or_else(|| panic!("wpkh address")),
        sh_wpkh
            .as_array()
            .and_then(|arr| arr.first())
            .cloned()
            .unwrap_or_else(|| panic!("sh(wpkh) address")),
    ]);
    assert_eq!(combo, expected);
}

#[test]
fn combo_range_must_match_and_derives_one_set_per_index() {
    let ctx = Arc::new(Context::new());
    let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
    let ranged = checksummed(&format!("combo({xpub}/0/*)"));
    let missing = deriveaddresses(&ctx, &json!([ranged]))
        .err()
        .unwrap_or_else(|| panic!("a ranged combo needs a range"));
    assert_eq!(missing.code(), RpcError::CORE_INVALID_PARAMETER);

    let fixed =
        checksummed("combo(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)");
    let unwanted = deriveaddresses(&ctx, &json!([fixed, [0, 1]]))
        .err()
        .unwrap_or_else(|| panic!("a fixed combo takes no range"));
    assert_eq!(unwanted.code(), RpcError::CORE_INVALID_PARAMETER);

    let derived = deriveaddresses(&ctx, &json!([ranged, [0, 1]]))
        .unwrap_or_else(|err| panic!("ranged combo must derive: {err}"));
    let Some(addresses) = derived.as_array() else {
        panic!("expected a flat array: {derived:?}");
    };
    assert_eq!(addresses.len(), 6, "3 addresses × 2 indices: {derived:?}");
    let distinct: std::collections::BTreeSet<&str> = addresses
        .iter()
        .filter_map(JsonValueTrait::as_str)
        .collect();
    assert_eq!(
        distinct.len(),
        6,
        "each script and index is distinct: {derived:?}"
    );
}

#[test]
fn combo_does_not_derive_from_a_testnet_wif_on_mainnet() {
    let ctx = Arc::new(Context::new());
    let secret = bitcoin::secp256k1::SecretKey::from_slice(&[
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,
    ])
    .unwrap_or_else(|err| panic!("secret 1 is valid: {err}"));
    let wif = bitcoin::PrivateKey {
        compressed: true,
        network: bitcoin::NetworkKind::Test,
        inner: secret,
    }
    .to_string();
    let error = deriveaddresses(&ctx, &json!([checksummed(&format!("combo({wif})"))]))
        .err()
        .unwrap_or_else(|| panic!("a testnet WIF must not derive on mainnet"));
    assert_eq!(error.code(), RpcError::CORE_NOT_FOUND);
    assert!(error.to_string().contains("test network"), "got {error}");
}
