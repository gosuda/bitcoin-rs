use super::{ChainTxData, Network};
use crate::Hash256;

const NETWORKS: [Network; 5] = [
    Network::Mainnet,
    Network::Testnet3,
    Network::Testnet4,
    Network::Signet,
    Network::Regtest,
];

#[test]
fn bip16_p2sh_exceptions_are_isolated_to_their_core_networks() -> Result<(), crate::HashError> {
    for (owner, hex) in [
        (
            Network::Mainnet,
            "00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22",
        ),
        (
            Network::Testnet3,
            "00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105",
        ),
    ] {
        let exception = Hash256::from_str_be(hex)?;
        for network in NETWORKS {
            assert_eq!(
                network.is_bip16_p2sh_exception(exception),
                network == owner,
                "{network:?}: {hex}"
            );
            for ordinary in [network.genesis_block_hash(), Hash256::default()] {
                assert!(
                    !network.is_bip16_p2sh_exception(ordinary),
                    "{network:?}: {ordinary}"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn mainnet_constants_match_core_chainparams() -> Result<(), crate::HashError> {
    assert_eq!(Network::Mainnet.magic(), [0xf9, 0xbe, 0xb4, 0xd9]);
    assert_eq!(Network::Mainnet.default_p2p_port(), 8333);
    assert_eq!(Network::Mainnet.default_rpc_port(), 8332);
    assert!(
        Network::Mainnet
            .dns_seeds()
            .contains(&"seed.bitcoin.sipa.be.")
    );
    assert_eq!(
        Network::Mainnet.genesis_block_hash(),
        Hash256::from_str_be("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")?
    );
    Ok(())
}

#[test]
fn non_mainnet_constants_match_core_chainparams() {
    assert_eq!(Network::Testnet3.magic(), [0x0b, 0x11, 0x09, 0x07]);
    assert_eq!(Network::Testnet4.magic(), [0x1c, 0x16, 0x3f, 0x28]);
    assert_eq!(Network::Signet.magic(), [0x0a, 0x03, 0xcf, 0x40]);
    assert_eq!(Network::Regtest.magic(), [0xfa, 0xbf, 0xb5, 0xda]);
    assert_eq!(Network::Regtest.retarget_interval(), 144);
}

#[test]
fn identity_name_is_distinct_from_core_testnet_alias() {
    assert_eq!(Network::Mainnet.identity_name(), "mainnet");
    assert_eq!(Network::Testnet3.identity_name(), "testnet3");
    assert_eq!(Network::Testnet4.identity_name(), "testnet4");
    assert_eq!(Network::Signet.identity_name(), "signet");
    assert_eq!(Network::Regtest.identity_name(), "regtest");
}

#[test]
fn pow_difficulty_parameters_match_core_chainparams() {
    for (network, timespan, min_difficulty, no_retarget, bip94) in [
        (Network::Mainnet, 14 * 24 * 60 * 60, false, false, false),
        (Network::Testnet3, 14 * 24 * 60 * 60, true, false, false),
        (Network::Testnet4, 14 * 24 * 60 * 60, true, false, true),
        (Network::Signet, 14 * 24 * 60 * 60, false, false, false),
        (Network::Regtest, 24 * 60 * 60, true, true, false),
    ] {
        assert_eq!(network.target_spacing_seconds(), 600, "{network:?}");
        assert_eq!(network.target_timespan_seconds(), timespan, "{network:?}");
        assert_eq!(
            network.allow_min_difficulty_blocks(),
            min_difficulty,
            "{network:?}"
        );
        assert_eq!(network.pow_no_retargeting(), no_retarget, "{network:?}");
        assert_eq!(network.enforce_bip94(), bip94, "{network:?}");
    }
}

#[test]
fn bip34_activation_metadata_matches_network_defaults() {
    assert!(!Network::Mainnet.is_bip34_active(227_930));
    assert!(Network::Mainnet.is_bip34_active(227_931));
    assert!(!Network::Regtest.is_bip34_active(499));
    assert!(Network::Regtest.is_bip34_active(500));
    assert!(!Network::Testnet3.is_bip34_active(21_110));
    assert!(Network::Testnet3.is_bip34_active(21_111));
    assert_eq!(
        Network::Mainnet
            .bip34_activation_hash()
            .map(Hash256::to_string_be),
        Some("000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8".to_owned())
    );
    assert_eq!(
        Network::Testnet3
            .bip34_activation_hash()
            .map(Hash256::to_string_be),
        Some("0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8".to_owned())
    );
    assert_eq!(Network::Regtest.bip34_activation_hash(), None);
}

#[test]
fn softfork_activations_match_core_chainparams() {
    type Activation = fn(Network, u32) -> bool;
    let activations: [(&str, Activation, [u32; 5]); 5] = [
        (
            "BIP65",
            Network::is_bip65_active,
            [388_381, 581_885, 1, 1, 1_351],
        ),
        (
            "BIP66",
            Network::is_bip66_active,
            [363_725, 330_776, 1, 1, 1_251],
        ),
        ("CSV", Network::is_csv_active, [419_328, 770_112, 1, 1, 432]),
        (
            "Segwit",
            Network::is_segwit_active,
            [481_824, 834_624, 0, 0, 0],
        ),
        (
            "Taproot",
            Network::is_taproot_active,
            [709_632, 2_017_256, 0, 0, 0],
        ),
    ];
    for (rule, is_active, heights) in activations {
        for (network, activation) in NETWORKS.into_iter().zip(heights) {
            if activation > 0 {
                assert!(!is_active(network, activation - 1), "{network:?}: {rule}");
            }
            assert!(is_active(network, activation), "{network:?}: {rule}");
        }
    }
}
#[test]
fn every_network_carries_chain_tx_data() {
    for network in [
        Network::Mainnet,
        Network::Testnet3,
        Network::Testnet4,
        Network::Signet,
        Network::Regtest,
    ] {
        let ChainTxData {
            time,
            tx_count,
            tx_rate,
        } = network.chain_tx_data();
        assert!(tx_rate > 0.0, "{network:?} needs a non-zero rate");
        if matches!(network, Network::Regtest) {
            assert_eq!((time, tx_count), (0, 0));
        } else {
            assert!(time > 0 && tx_count > 0, "{network:?}");
        }
    }
}

#[test]
fn mainnet_assume_utxo_data_matches_pinned_core() -> Result<(), crate::HashError> {
    let expected_mainnet = [
        (
            840_000,
            "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5",
            "a2a5521b1b5ab65f67818e5e8eccabb7171a517f9e2382208f77687310768f96",
            991_032_194,
        ),
        (
            880_000,
            "000000000000000000010b17283c3c400507969a9c2afd1dcf2082ec5cca2880",
            "dbd190983eaf433ef7c15f78a278ae42c00ef52e0fd2a54953782175fbadcea9",
            1_145_604_538,
        ),
        (
            910_000,
            "0000000000000000000108970acb9522ffd516eae17acddcb1bd16469194a821",
            "4daf8a17b4902498c5787966a2b51c613acdab5df5db73f196fa59a4da2f1568",
            1_226_586_151,
        ),
        (
            935_000,
            "0000000000000000000147034958af1652b2b91bba607beacc5e72a56f0fb5ee",
            "e4b90ef9eae834f56c4b64d2d50143cee10ad87994c614d7d04125e2a6025050",
            1_305_397_408,
        ),
        (
            965_000,
            "00000000000000000001595977e6000ce56129f5c9b4073e31ccc30b90b97da9",
            "4a8d794337118c0c615b574f817c7306c687584a537184b8d233df42bf477ec2",
            1_429_611_231,
        ),
    ];
    assert_eq!(
        Network::Mainnet
            .assume_utxo_data()
            .iter()
            .map(|data| data.height)
            .collect::<Vec<_>>(),
        expected_mainnet.map(|(height, _, _, _)| height)
    );
    for (height, block_hash, commitment, chain_tx_count) in expected_mainnet {
        let Some(data) = Network::Mainnet.assume_utxo_for_height(height) else {
            panic!("mainnet AssumeUTXO base {height} missing");
        };
        let expected_hash = Hash256::from_str_be(block_hash)?;
        assert_eq!(data.height, height);
        assert_eq!(data.block_hash.to_string(), block_hash);
        assert_eq!(data.hash_serialized.to_string(), commitment);
        assert_eq!(data.chain_tx_count, chain_tx_count);
        assert_eq!(
            Network::Mainnet.assume_utxo_for_hash(expected_hash),
            Some(data)
        );
        for network in NETWORKS
            .into_iter()
            .filter(|network| *network != Network::Mainnet)
        {
            assert_eq!(network.assume_utxo_for_height(height), None, "{network:?}");
            assert_eq!(
                network.assume_utxo_for_hash(expected_hash),
                None,
                "{network:?}"
            );
        }
    }

    Ok(())
}

#[test]
fn assume_utxo_data_round_trips_expected_values() {
    let Some(testnet4_90k) = Network::Testnet4.assume_utxo_for_height(90_000) else {
        panic!("90k missing");
    };
    assert_eq!(
        testnet4_90k.block_hash.to_string(),
        "0000000002ebe8bcda020e0dd6ccfbdfac531d2f6a81457191b99fc2df2dbe3b"
    );
    assert_eq!(
        testnet4_90k.hash_serialized.to_string(),
        "784fb5e98241de66fdd429f4392155c9e7db5c017148e66e8fdbc95746f8b9b5"
    );
    assert_eq!(testnet4_90k.chain_tx_count, 11_347_043);

    let Some(regtest_110) = Network::Regtest.assume_utxo_for_height(110) else {
        panic!("110 missing");
    };
    assert_eq!(
        regtest_110.block_hash.to_string(),
        "135eec25a6fb277884e5824e7aa7d052c4868161c99a5122170b5266f86c273d"
    );
    assert_eq!(
        regtest_110.hash_serialized.to_string(),
        "86e9a1205b418b16dde3a18a78c730e30137e28466bda5dbf6b33ab8fc05447c"
    );
    assert_eq!(regtest_110.chain_tx_count, 111);

    let Some(regtest_200) = Network::Regtest.assume_utxo_for_height(200) else {
        panic!("200 missing");
    };
    assert_eq!(
        regtest_200.block_hash.to_string(),
        "385901ccbd69dff6bbd00065d01fb8a9e464dede7cfe0372443884f9b1dcf6b9"
    );
    assert_eq!(
        regtest_200.hash_serialized.to_string(),
        "17dcc016d188d16068907cdeb38b75691a118d43053b8cd6a25969419381d13a"
    );
    assert_eq!(regtest_200.chain_tx_count, 201);

    assert_eq!(Network::Testnet3.assume_utxo_data(), &[]);
    assert_eq!(Network::Signet.assume_utxo_data(), &[]);
    assert_eq!(Network::Mainnet.assume_utxo_for_height(12345), None);
}

#[test]
fn assume_utxo_lookups_reject_unpinned_bases() {
    for height in [
        0,
        839_999,
        840_001,
        879_999,
        880_001,
        909_999,
        910_001,
        934_999,
        935_001,
        964_999,
        965_001,
        u32::MAX,
    ] {
        assert_eq!(
            Network::Mainnet.assume_utxo_for_height(height),
            None,
            "{height}"
        );
    }
    for block_hash in [
        Hash256::from_le_bytes(&[0; 32]),
        Network::Mainnet.genesis_block_hash(),
    ] {
        assert_eq!(Network::Mainnet.assume_utxo_for_hash(block_hash), None);
    }
}
