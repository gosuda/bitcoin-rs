//! Source guard for the wallet no-custody rules.
//!
//! The wallet crate stores no secret material of any kind. The only secret it
//! may touch is caller-supplied keys, and those are confined to the signer
//! interface as call-scoped parameters.
#[test]
fn wallet_src_stores_no_private_key_surface() {
    let sources: [(&str, &str); 8] = [
        ("lib.rs", include_str!("../src/lib.rs")),
        ("descriptor.rs", include_str!("../src/descriptor.rs")),
        ("watcher.rs", include_str!("../src/watcher.rs")),
        ("psbt.rs", include_str!("../src/psbt.rs")),
        (
            "coin_selection.rs",
            include_str!("../src/coin_selection.rs"),
        ),
        ("fee_bump.rs", include_str!("../src/fee_bump.rs")),
        ("signer_iface.rs", include_str!("../src/signer_iface.rs")),
        ("finalize.rs", include_str!("../src/finalize.rs")),
    ];
    for (name, source) in sources {
        assert!(
            !source.contains("SecretKey"),
            "{name} handles raw secret keys"
        );
        assert!(
            !source.contains("secp256k1::Secret"),
            "{name} references raw secret keys"
        );
        assert!(
            !source.to_ascii_lowercase().contains("seckey"),
            "{name} handles secret keys"
        );
    }
    // Caller keys exist only as parameters of the transient signing call in
    // the signer interface; no other source may mention them, and no source
    // may keep one in a field.
    for (name, source) in sources {
        if name != "signer_iface.rs" {
            assert!(
                !source.contains("PrivateKey"),
                "{name} handles caller keys outside the signer interface"
            );
        } else {
            assert!(
                !source.contains(": PrivateKey"),
                "signer_iface.rs must not store caller keys in state"
            );
        }
    }
}
