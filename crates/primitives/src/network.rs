use ruint::Uint;

use crate::Hash256;

/// A supported Bitcoin network.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Network {
    /// Bitcoin mainnet.
    Mainnet,
    /// Bitcoin public testnet version 3.
    Testnet3,
    /// Bitcoin public testnet version 4.
    Testnet4,
    /// Bitcoin default signet.
    Signet,
    /// Local regression-test network.
    Regtest,
}

impl Network {
    /// Returns the four P2P message-start bytes in wire order.
    #[must_use]
    pub const fn magic(self) -> [u8; 4] {
        match self {
            Self::Mainnet => [0xf9, 0xbe, 0xb4, 0xd9],
            Self::Testnet3 => [0x0b, 0x11, 0x09, 0x07],
            Self::Testnet4 => [0x1c, 0x16, 0x3f, 0x28],
            Self::Signet => [0x0a, 0x03, 0xcf, 0x40],
            Self::Regtest => [0xfa, 0xbf, 0xb5, 0xda],
        }
    }

    /// Returns the default P2P port.
    #[must_use]
    pub const fn default_p2p_port(self) -> u16 {
        match self {
            Self::Mainnet => 8333,
            Self::Testnet3 => 18333,
            Self::Testnet4 => 48333,
            Self::Signet => 38333,
            Self::Regtest => 18444,
        }
    }

    /// Returns the network's BIP34 coinbase-height activation height.
    ///
    /// Per Bitcoin Core's `chainparams.cpp` for fixed public networks:
    /// - Mainnet activates at height 227,931
    /// - Testnet3 activates at height 21,111
    /// - Testnet4 / Signet activate at height 1
    /// - This crate's deterministic regtest default activates at height 500.
    #[must_use]
    pub const fn bip34_activation_height(self) -> u32 {
        match self {
            Self::Mainnet => 227_931,
            Self::Testnet3 => 21_111,
            Self::Testnet4 | Self::Signet => 1,
            Self::Regtest => 500,
        }
    }

    /// Returns the fixed BIP34 activation block hash when Core uses one to prove
    /// that BIP34 implies BIP30 on a known chain.
    #[must_use]
    pub const fn bip34_activation_hash(self) -> Option<Hash256> {
        match self {
            Self::Mainnet => Some(Hash256::from_le_bytes(&[
                0xb8, 0x08, 0x08, 0x9c, 0x75, 0x6a, 0xdd, 0x15, 0x91, 0xb1, 0xd1, 0x7b, 0xab, 0x44,
                0xbb, 0xa3, 0xfe, 0xd9, 0xe0, 0x2f, 0x94, 0x2a, 0xb4, 0x89, 0x4b, 0x02, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ])),
            Self::Testnet3 => Some(Hash256::from_le_bytes(&[
                0xf8, 0x8e, 0xcd, 0x99, 0x12, 0xd0, 0x0d, 0x3f, 0x5c, 0x2a, 0x8e, 0x0f, 0x50, 0x41,
                0x7d, 0x3e, 0x41, 0x5c, 0x75, 0xb3, 0xab, 0xe5, 0x84, 0x34, 0x6d, 0xa9, 0xb3, 0x23,
                0x00, 0x00, 0x00, 0x00,
            ])),
            Self::Testnet4 | Self::Signet | Self::Regtest => None,
        }
    }

    /// Returns `true` when BIP34 coinbase-height encoding is enforced at `height`.
    #[must_use]
    pub const fn is_bip34_active(self, height: u32) -> bool {
        height >= self.bip34_activation_height()
    }

    /// Returns `true` when BIP65 (`OP_CHECKLOCKTIMEVERIFY`) is enforced at `height`.
    ///
    /// Per Bitcoin Core's `chainparams.cpp`:
    /// - Mainnet activates at height 388,381
    /// - Testnet3 activates at height 581,885
    /// - Testnet4 / Signet activate at height 1
    /// - Regtest activates at height 1,351
    #[must_use]
    pub const fn is_bip65_active(self, height: u32) -> bool {
        let activation = match self {
            Self::Mainnet => 388_381,
            Self::Testnet3 => 581_885,
            Self::Testnet4 | Self::Signet => 1,
            Self::Regtest => 1_351,
        };
        height >= activation
    }

    /// Returns `true` when BIP66 (strict DER signatures) is enforced at `height`.
    #[must_use]
    pub const fn is_bip66_active(self, height: u32) -> bool {
        let activation = match self {
            Self::Mainnet => 363_725,
            Self::Testnet3 => 330_776,
            Self::Testnet4 | Self::Signet => 1,
            Self::Regtest => 1_251,
        };
        height >= activation
    }

    /// Returns `true` when CSV (BIP68/112/113 relative locktime + MTP) is enforced at `height`.
    #[must_use]
    pub const fn is_csv_active(self, height: u32) -> bool {
        let activation = match self {
            Self::Mainnet => 419_328,
            Self::Testnet3 => 770_112,
            Self::Testnet4 | Self::Signet => 1,
            Self::Regtest => 432,
        };
        height >= activation
    }

    /// Returns `true` when Segwit (BIP141/143/147) is enforced at `height`.
    #[must_use]
    pub const fn is_segwit_active(self, height: u32) -> bool {
        let activation = match self {
            Self::Mainnet => 481_824,
            Self::Testnet3 => 834_624,
            Self::Testnet4 | Self::Signet | Self::Regtest => 0,
        };
        height >= activation
    }

    /// Returns `true` when Taproot (BIP341/342) is enforced at `height`.
    #[must_use]
    pub const fn is_taproot_active(self, height: u32) -> bool {
        let activation = match self {
            Self::Mainnet => 709_632,
            Self::Testnet3 => 2_017_256,
            Self::Testnet4 | Self::Signet | Self::Regtest => 0,
        };
        height >= activation
    }

    /// Returns the default JSON-RPC port used by Bitcoin Core.
    #[must_use]
    pub const fn default_rpc_port(self) -> u16 {
        match self {
            Self::Mainnet => 8332,
            Self::Testnet3 => 18332,
            Self::Testnet4 => 48332,
            Self::Signet => 38332,
            Self::Regtest => 18443,
        }
    }

    /// Returns DNS seeds from Bitcoin Core chain parameters.
    #[must_use]
    pub const fn dns_seeds(self) -> &'static [&'static str] {
        match self {
            Self::Mainnet => &[
                "seed.bitcoin.sipa.be.",
                "dnsseed.bluematt.me.",
                "seed.bitcoin.jonasschnelli.ch.",
                "seed.btc.petertodd.net.",
                "seed.bitcoin.sprovoost.nl.",
                "dnsseed.emzy.de.",
                "seed.bitcoin.wiz.biz.",
                "seed.mainnet.achownodes.xyz.",
            ],
            Self::Testnet3 => &[
                "testnet-seed.bitcoin.jonasschnelli.ch.",
                "seed.tbtc.petertodd.net.",
                "seed.testnet.bitcoin.sprovoost.nl.",
                "testnet-seed.bluematt.me.",
                "seed.testnet.achownodes.xyz.",
            ],
            Self::Testnet4 => &[
                "seed.testnet4.bitcoin.sprovoost.nl.",
                "seed.testnet4.wiz.biz.",
            ],
            Self::Signet => &[
                "seed.signet.bitcoin.sprovoost.nl.",
                "seed.signet.achownodes.xyz.",
            ],
            Self::Regtest => &["dummySeed.invalid."],
        }
    }

    /// Returns the proof-of-work limit target.
    #[must_use]
    pub const fn max_target(self) -> Uint<256, 4> {
        match self {
            Self::Signet => Uint::from_be_bytes([
                0x00, 0x00, 0x03, 0x77, 0xae, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ]),
            Self::Regtest => Uint::from_be_bytes([
                0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff,
            ]),
            Self::Mainnet | Self::Testnet3 | Self::Testnet4 => Uint::from_be_bytes([
                0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff,
            ]),
        }
    }

    /// Returns the main retarget interval in blocks.
    #[must_use]
    pub const fn retarget_interval(self) -> u32 {
        match self {
            Self::Regtest => 144,
            Self::Mainnet | Self::Testnet3 | Self::Testnet4 | Self::Signet => 2016,
        }
    }

    /// Returns the proof-of-work target spacing in seconds.
    #[must_use]
    pub const fn target_spacing_seconds(self) -> u32 {
        10 * 60
    }

    /// Returns the proof-of-work retarget timespan in seconds.
    #[must_use]
    pub const fn target_timespan_seconds(self) -> u32 {
        self.retarget_interval()
            .saturating_mul(self.target_spacing_seconds())
    }

    /// Returns whether non-retarget blocks may use the test-network minimum-difficulty rule.
    #[must_use]
    pub const fn allow_min_difficulty_blocks(self) -> bool {
        match self {
            Self::Testnet3 | Self::Testnet4 | Self::Regtest => true,
            Self::Mainnet | Self::Signet => false,
        }
    }

    /// Returns whether retarget heights keep the previous difficulty unchanged.
    #[must_use]
    pub const fn pow_no_retargeting(self) -> bool {
        match self {
            Self::Regtest => true,
            Self::Mainnet | Self::Testnet3 | Self::Testnet4 | Self::Signet => false,
        }
    }

    /// Returns whether retargeting uses the first block of the period as the base difficulty.
    #[must_use]
    pub const fn enforce_bip94(self) -> bool {
        match self {
            Self::Testnet4 => true,
            Self::Mainnet | Self::Testnet3 | Self::Signet | Self::Regtest => false,
        }
    }

    /// Returns the genesis block hash.
    #[must_use]
    pub fn genesis_block_hash(self) -> Hash256 {
        let hex = match self {
            Self::Mainnet => "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
            Self::Testnet3 => "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
            Self::Testnet4 => "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043",
            Self::Signet => "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6",
            Self::Regtest => "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
        };
        match Hash256::from_str_be(hex) {
            Ok(hash) => hash,
            Err(error) => panic!("invalid compiled-in genesis hash: {error}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Network;
    use crate::Hash256;

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
            Hash256::from_str_be(
                "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
            )?
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
    fn pow_difficulty_parameters_match_core_chainparams() {
        for network in [
            Network::Mainnet,
            Network::Testnet3,
            Network::Testnet4,
            Network::Signet,
            Network::Regtest,
        ] {
            assert_eq!(network.target_spacing_seconds(), 600);
        }

        assert_eq!(
            Network::Mainnet.target_timespan_seconds(),
            14 * 24 * 60 * 60
        );
        assert_eq!(
            Network::Testnet3.target_timespan_seconds(),
            14 * 24 * 60 * 60
        );
        assert_eq!(
            Network::Testnet4.target_timespan_seconds(),
            14 * 24 * 60 * 60
        );
        assert_eq!(Network::Signet.target_timespan_seconds(), 14 * 24 * 60 * 60);
        assert_eq!(Network::Regtest.target_timespan_seconds(), 24 * 60 * 60);

        assert!(!Network::Mainnet.allow_min_difficulty_blocks());
        assert!(Network::Testnet3.allow_min_difficulty_blocks());
        assert!(Network::Testnet4.allow_min_difficulty_blocks());
        assert!(!Network::Signet.allow_min_difficulty_blocks());
        assert!(Network::Regtest.allow_min_difficulty_blocks());

        assert!(!Network::Mainnet.pow_no_retargeting());
        assert!(!Network::Testnet3.pow_no_retargeting());
        assert!(!Network::Testnet4.pow_no_retargeting());
        assert!(!Network::Signet.pow_no_retargeting());
        assert!(Network::Regtest.pow_no_retargeting());

        assert!(!Network::Mainnet.enforce_bip94());
        assert!(!Network::Testnet3.enforce_bip94());
        assert!(Network::Testnet4.enforce_bip94());
        assert!(!Network::Signet.enforce_bip94());
        assert!(!Network::Regtest.enforce_bip94());
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
        fn assert_activation(
            is_active: impl Fn(Network, u32) -> bool,
            network: Network,
            activation: u32,
        ) {
            if activation == 0 {
                assert!(is_active(network, 0));
            } else {
                assert!(!is_active(network, activation - 1));
                assert!(is_active(network, activation));
            }
        }

        // BIP65
        assert_activation(Network::is_bip65_active, Network::Mainnet, 388_381);
        assert_activation(Network::is_bip65_active, Network::Testnet3, 581_885);
        assert_activation(Network::is_bip65_active, Network::Testnet4, 1);
        assert_activation(Network::is_bip65_active, Network::Signet, 1);
        assert_activation(Network::is_bip65_active, Network::Regtest, 1_351);

        // BIP66
        assert_activation(Network::is_bip66_active, Network::Mainnet, 363_725);
        assert_activation(Network::is_bip66_active, Network::Testnet3, 330_776);
        assert_activation(Network::is_bip66_active, Network::Testnet4, 1);
        assert_activation(Network::is_bip66_active, Network::Signet, 1);
        assert_activation(Network::is_bip66_active, Network::Regtest, 1_251);

        // CSV
        assert_activation(Network::is_csv_active, Network::Mainnet, 419_328);
        assert_activation(Network::is_csv_active, Network::Testnet3, 770_112);
        assert_activation(Network::is_csv_active, Network::Testnet4, 1);
        assert_activation(Network::is_csv_active, Network::Signet, 1);
        assert_activation(Network::is_csv_active, Network::Regtest, 432);

        // Segwit
        assert_activation(Network::is_segwit_active, Network::Mainnet, 481_824);
        assert_activation(Network::is_segwit_active, Network::Testnet3, 834_624);
        assert_activation(Network::is_segwit_active, Network::Testnet4, 0);
        assert_activation(Network::is_segwit_active, Network::Signet, 0);
        assert_activation(Network::is_segwit_active, Network::Regtest, 0);

        // Taproot
        assert_activation(Network::is_taproot_active, Network::Mainnet, 709_632);
        assert_activation(Network::is_taproot_active, Network::Testnet3, 2_017_256);
        assert_activation(Network::is_taproot_active, Network::Testnet4, 0);
        assert_activation(Network::is_taproot_active, Network::Signet, 0);
        assert_activation(Network::is_taproot_active, Network::Regtest, 0);
    }
}
