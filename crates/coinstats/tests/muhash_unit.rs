//! `MuHash3072` unit tests.
use bitcoin_rs_coinstats::MuHash3072;

const IDENTITY: [u8; 384] = {
    let mut bytes = [0_u8; 384];
    bytes[383] = 1;
    bytes
};

const HELLO_MUHASH: [u8; 384] = hex_384(
    "1a3d6ed31c98e21c99ef030208244720f8dbcdd28854389255031e9ffb5f6a60\
     0689dee672161b98848c8b1afc104819cd6cd7c7cee3df9d84fd5fc2007ba3ed\
     62cd1db4a01baf88d5fd25715c0ff09c41220988a8324d8eb8e46a51870c96c\
     d582e9541fecadf5861a4505323e03ccb0efdc910c1cdec49e02fbe2091f81\
     9df2edf619b7ced051f5a6fba688ad4909da5e79db27202d379eefc7a2a01\
     655d4c622f8d7748d5a69dcf8959ec4d2c371cd9fde3172bcf69980a3d9\
     c02a0f14dfa041992299fe8d3dbbd095055188dc44943a9b9bf9a48f15b72\
     0e10989e35332ff65450b24747efc46996974a499494e4463cd1af2ba02896\
     a4cc9377f2dc63bc49366b4d2ec2f5e139602f8bbfbb0ade7cdcde6e8b\
     128e95d3d40eccea452134818d8602e1909eb052cad138ea4237632261e5f3\
     84ae9cdc5f081d93f826e20e557249b944f0b653ae8ac0977f917b34a4c0\
     c51798b70b12cf5d0e63004b0fd010d0d7e7450047ef2c3f945e98387cf\
     163fcbbcd305fe34ef44491e73a6df582",
);

#[test]
fn empty_muhash_finalizes_to_identity_element() {
    assert_eq!(MuHash3072::new().finalize(), IDENTITY);
}

#[test]
fn single_insert_matches_known_answer() {
    let mut muhash = MuHash3072::new();
    muhash.insert(b"hello");

    assert_eq!(muhash.finalize(), HELLO_MUHASH);
}

#[test]
fn insert_order_is_commutative() {
    let mut left = MuHash3072::new();
    left.insert(b"alpha");
    left.insert(b"beta");

    let mut right = MuHash3072::new();
    right.insert(b"beta");
    right.insert(b"alpha");

    assert_eq!(left.finalize(), right.finalize());
}

#[test]
fn insert_then_remove_collapses_to_identity() {
    let mut muhash = MuHash3072::new();
    muhash.insert(b"spent output");
    muhash.remove(b"spent output");

    assert_eq!(muhash.finalize(), IDENTITY);
}

const fn hex_384(hex: &str) -> [u8; 384] {
    let bytes = hex.as_bytes();
    let mut out = [0_u8; 384];
    let mut in_idx = 0;
    let mut out_idx = 0;
    while in_idx < bytes.len() {
        let hi = bytes[in_idx];
        if hi == b' ' || hi == b'\n' || hi == b'\t' {
            in_idx += 1;
            continue;
        }
        let lo = bytes[in_idx + 1];
        out[out_idx] = (hex_nibble(hi) << 4) | hex_nibble(lo);
        out_idx += 1;
        in_idx += 2;
    }
    out
}

const fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => 0,
    }
}
