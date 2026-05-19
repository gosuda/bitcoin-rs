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

    /// Returns `true` when BIP34 coinbase-height encoding is enforced at `height`.
    ///
    /// Per Bitcoin Core's `chainparams.cpp`:
    /// - Mainnet activates at height 227,835
    /// - Testnet3 activates at height 21,111
    /// - Testnet4 / Signet activate at height 1
    /// - Regtest activates at height 500
    #[must_use]
    pub const fn is_bip34_active(self, height: u32) -> bool {
        let activation = match self {
            Self::Mainnet => 227_835,
            Self::Testnet3 => 21_111,
            Self::Testnet4 | Self::Signet => 1,
            Self::Regtest => 500,
        };
        height >= activation
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
    fn bip34_activation_heights_match_core_chainparams() {
        assert!(!Network::Mainnet.is_bip34_active(227_834));
        assert!(Network::Mainnet.is_bip34_active(227_835));
        assert!(!Network::Regtest.is_bip34_active(499));
        assert!(Network::Regtest.is_bip34_active(500));
        assert!(!Network::Testnet3.is_bip34_active(21_110));
        assert!(Network::Testnet3.is_bip34_active(21_111));
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
