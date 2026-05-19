//! Source guard for the wallet private-key ban.
#[test]
fn wallet_src_contains_no_private_key_surface() {
    let sources = [
        include_str!("../src/lib.rs"),
        include_str!("../src/descriptor.rs"),
        include_str!("../src/watcher.rs"),
        include_str!("../src/psbt.rs"),
        include_str!("../src/coin_selection.rs"),
        include_str!("../src/fee_bump.rs"),
        include_str!("../src/signer_iface.rs"),
        include_str!("../src/finalize.rs"),
    ];
    for source in sources {
        assert!(!source.contains("SecretKey"));
        assert!(!source.contains("secp256k1::Secret"));
        assert!(!source.to_ascii_lowercase().contains("seckey"));
    }
}
