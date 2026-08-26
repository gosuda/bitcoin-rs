//! Descriptor parser, analysis, import, and watch-only scan coverage.
#![allow(clippy::expect_used)]

use std::collections::HashSet;

use bitcoin::hashes::Hash as _;
use bitcoin::{Network, OutPoint, Txid};
use bitcoin_rs_wallet::{Descriptor, WalletError, Watcher};

#[path = "fixtures/test_signer.rs"]
mod test_signer;

#[test]
fn parser_accepts_task14_descriptor_forms() -> Result<(), Box<dyn std::error::Error>> {
    let signer = test_signer::TestSigner::new()?;
    let public_key = signer.public_key();
    for descriptor in [
        format!("pkh({public_key})"),
        format!("wpkh({public_key})"),
        format!("sh(wpkh({public_key}))"),
        format!("tr({public_key})"),
        format!("wsh(multi(1,{public_key}))"),
        format!("tr({public_key},multi_a(1,{public_key}))"),
    ] {
        Descriptor::parse(&descriptor)?;
    }
    Ok(())
}

#[test]
fn info_reports_range_solvability_and_checksum() -> Result<(), Box<dyn std::error::Error>> {
    let signer = test_signer::TestSigner::new()?;
    let public_key = signer.public_key();
    let xpub = signer.bip32_xpub();

    let info = Descriptor::info(&format!("wpkh({public_key})"))?;
    assert!(!info.is_range);
    assert!(!info.has_private_keys);
    assert!(info.is_solvable);
    assert!(info.descriptor.ends_with(&format!("#{}", info.checksum)));

    // The canonical form, checksum included, reparses to the same descriptor.
    let canonical = Descriptor::parse(&info.descriptor)?;
    assert_eq!(
        canonical,
        Descriptor::parse(&format!("wpkh({public_key})"))?
    );

    // A supplied checksum that does not match is rejected.
    assert!(
        Descriptor::parse(&format!("wpkh({public_key})#00000000")).is_err(),
        "bad checksums must be rejected"
    );

    let ranged = Descriptor::info(&format!("wpkh({xpub}/0/*)"))?;
    assert!(ranged.is_range);
    assert!(!ranged.has_private_keys);
    assert_eq!(ranged.multipath_expansion.len(), 1);

    Ok(())
}

#[test]
fn private_descriptor_material_is_analyzed_but_never_imported()
-> Result<(), Box<dyn std::error::Error>> {
    let signer = test_signer::TestSigner::new()?;
    let wif = signer.caller_key().to_wif();
    let secret_descriptor = format!("wpkh({wif})");

    let info = Descriptor::info(&secret_descriptor)?;
    assert!(info.has_private_keys);
    assert!(!info.descriptor.contains(&wif), "analysis must be public");

    assert!(matches!(
        Descriptor::parse(&secret_descriptor),
        Err(WalletError::PrivateDescriptor)
    ));

    let mut watcher = Watcher::new(Vec::new());
    assert!(matches!(
        watcher.import_descriptor(&secret_descriptor),
        Err(WalletError::PrivateDescriptor)
    ));
    assert!(
        watcher.descriptors.is_empty(),
        "rejected import must not mutate watcher state"
    );
    assert!(
        watcher.imports.is_empty(),
        "rejected import must not retain metadata"
    );

    Ok(())
}

#[test]
fn multipath_descriptors_expand_for_import_but_not_single_parse()
-> Result<(), Box<dyn std::error::Error>> {
    let signer = test_signer::TestSigner::new()?;
    let xpub = signer.bip32_xpub();
    let text = format!("wpkh({xpub}/<0;1>/*)");

    let expanded = Descriptor::parse_all(&text)?;
    assert_eq!(expanded.len(), 2);
    assert!(matches!(
        Descriptor::parse(&text),
        Err(WalletError::Descriptor(message)) if !message.is_empty()
    ));

    let info = Descriptor::info(&text)?;
    assert_eq!(info.multipath_expansion.len(), 2);

    Ok(())
}

#[test]
#[allow(clippy::reversed_empty_ranges)]
fn derive_addresses_enforces_descriptor_range_rules() -> Result<(), Box<dyn std::error::Error>> {
    let signer = test_signer::TestSigner::new()?;
    let public_key = signer.public_key();
    let xpub = signer.bip32_xpub();

    let ranged = Descriptor::parse(&format!("wpkh({xpub}/0/*)"))?;
    let addresses = ranged.derive_addresses(Network::Regtest, 0..=5)?;
    assert_eq!(addresses.len(), 6);
    let distinct: HashSet<_> = addresses.iter().collect();
    assert_eq!(distinct.len(), addresses.len());
    assert!(ranged.derive_addresses(Network::Regtest, 5..=0).is_err());

    let fixed = Descriptor::parse(&format!("wpkh({public_key})"))?;
    assert_eq!(fixed.derive_addresses(Network::Regtest, 0..=0)?.len(), 1);
    assert!(
        fixed.derive_addresses(Network::Regtest, 0..=1).is_err(),
        "unranged descriptors reject nonzero ranges"
    );

    Ok(())
}

#[test]
fn hardened_derivation_material_is_analyzed_but_rejected_on_import()
-> Result<(), Box<dyn std::error::Error>> {
    let signer = test_signer::TestSigner::new()?;
    let xpub = signer.bip32_xpub();
    for rejected in [format!("wpkh({xpub}/0/*')"), format!("wpkh({xpub}/0h/1/*)")] {
        // Analysis still reports the descriptor.
        let info = Descriptor::info(&rejected)?;
        assert!(!info.descriptor.is_empty());
        // Watch-only import refuses material that needs private derivation.
        assert!(Descriptor::parse(&rejected).is_err());
    }
    Ok(())
}

#[test]
fn watcher_imports_public_descriptors_and_scans_derivation_ranges()
-> Result<(), Box<dyn std::error::Error>> {
    let signer = test_signer::TestSigner::new()?;
    let public_key = signer.public_key();
    let xpub = signer.bip32_xpub();
    let mut watcher = Watcher::new(Vec::new());

    let single = watcher.import_descriptor(&format!("wpkh({public_key})"))?;
    assert_eq!(single, [0]);
    assert_eq!(watcher.imports.len(), 1);
    assert!(watcher.imports[0].descriptor.contains("wpkh("));
    assert!(
        !watcher.imports[0].descriptor.contains('['),
        "no origin private material"
    );
    let branches = watcher.import_descriptor(&format!("wpkh({xpub}/<0;1>/*)"))?;
    assert_eq!(branches, [1, 2]);
    assert_eq!(watcher.imports.len(), 3);
    assert!(watcher.imports.iter().all(|import| import.label.is_none()));

    // Unranged descriptors scan only the zero range.
    assert_eq!(watcher.script_hash_scan_prefixes(0, 0..=0)?.len(), 1);
    assert!(watcher.script_hash_scan_prefixes(0, 0..=1).is_err());

    // Ranged descriptors cover every index with distinct prefixes.
    let prefixes = watcher.script_hash_scan_prefixes(1, 0..=4)?;
    assert_eq!(prefixes.len(), 5);
    let distinct: HashSet<_> = prefixes.iter().collect();
    assert_eq!(distinct.len(), 5);
    assert_eq!(prefixes[0], watcher.script_hash_scan_prefix(1)?);

    assert!(watcher.script_hash_scan_prefixes(9, 0..=0).is_err());

    // Scanned outpoints are recorded per derived address.
    let address = watcher.derive_address(1, Network::Regtest, 3)?;
    let outpoint = OutPoint {
        txid: Txid::from_byte_array([3_u8; 32]),
        vout: 1,
    };
    watcher.record_utxo(address.clone(), outpoint, bitcoin::Amount::from_sat(50_000));
    assert_eq!(watcher.utxos_for(&address), [outpoint]);
    assert_eq!(
        watcher.utxo_value(&outpoint),
        Some(bitcoin::Amount::from_sat(50_000))
    );

    Ok(())
}

#[test]
fn addr_descriptors_support_info_and_derive() -> Result<(), Box<dyn std::error::Error>> {
    let text = "addr(1111111111111111111114oLvT2)";
    let info = Descriptor::info(text)?;
    assert!(!info.is_range);
    assert!(!info.is_solvable);
    assert!(!info.has_private_keys);
    assert!(info.descriptor.starts_with("addr("));
    assert!(info.descriptor.ends_with(&format!("#{}", info.checksum)));

    let parsed = Descriptor::parse(text)?;
    let addresses = parsed.derive_addresses(Network::Bitcoin, 0..=0)?;
    assert_eq!(addresses.len(), 1);
    assert_eq!(addresses[0].to_string(), "1111111111111111111114oLvT2");
    assert!(parsed.derive_addresses(Network::Bitcoin, 0..=1).is_err());

    assert!(
        Descriptor::parse("addr(1111111111111111111114oLvT2)#00000000").is_err(),
        "bad addr checksums must be rejected"
    );
    Ok(())
}

#[test]
fn watcher_omits_unknown_utxo_values() -> Result<(), Box<dyn std::error::Error>> {
    let signer = test_signer::TestSigner::new()?;
    let public_key = signer.public_key();
    let mut watcher = Watcher::new(Vec::new());
    watcher.import_descriptor(&format!("wpkh({public_key})"))?;
    let address = watcher.derive_address(0, Network::Regtest, 0)?;
    let outpoint = OutPoint {
        txid: Txid::from_byte_array([4_u8; 32]),
        vout: 0,
    };
    watcher.record_outpoint(address.clone(), outpoint);
    assert_eq!(watcher.utxos_for(&address), [outpoint]);
    assert_eq!(watcher.utxo_value(&outpoint), None);
    Ok(())
}

#[test]
fn encode_state_round_trips_imports_and_omits_utxos() -> Result<(), Box<dyn std::error::Error>> {
    let signer = test_signer::TestSigner::new()?;
    let public_key = signer.public_key();
    let mut watcher = Watcher::new(Vec::new());
    watcher.import_descriptor(&format!("wpkh({public_key})"))?;
    let address = watcher.derive_address(0, Network::Regtest, 0)?;
    let outpoint = OutPoint {
        txid: Txid::from_byte_array([9_u8; 32]),
        vout: 0,
    };
    watcher.record_utxo(address.clone(), outpoint, bitcoin::Amount::from_sat(12_345));
    let encoded = watcher.encode_state()?;
    assert!(
        !encoded.windows(6).any(|w| w == b"utxos" || w == b"value"),
        "utxo cache must not be persisted"
    );
    let restored = Watcher::decode_state(&encoded)?;
    assert_eq!(restored.imports.len(), watcher.imports.len());
    assert_eq!(restored.descriptors.len(), watcher.descriptors.len());
    assert!(restored.utxos_for(&address).is_empty());
    assert!(restored.utxo_value(&outpoint).is_none());
    Ok(())
}

#[test]
fn decode_state_rejects_unknown_version() {
    let payload = br#"{"version":99,"imports":[]}"#;
    let err = Watcher::decode_state(payload).expect_err("unknown version");
    match err {
        WalletError::State(message) => assert!(message.contains("version")),
        other => panic!("expected state error, got {other}"),
    }
}
