use ruint::Uint;

use crate::Hash256;

/// A dated observation of the chain's cumulative transaction count, plus the
/// rate transactions have arrived since — Bitcoin Core's `ChainTxData`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ChainTxData {
    pub time: u64,
    pub tx_count: u64,
    pub tx_rate: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeadersSyncParams {
    pub commitment_period: u32,
    pub redownload_buffer_size: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssumeUtxoData {
    pub height: u32,
    pub block_hash: Hash256,
    pub hash_serialized: Hash256,
    pub chain_tx_count: u64,
}

const MAINNET_MINIMUM_CHAIN_WORK: [u8; 32] =
    decode_compiled_hex("0000000000000000000000000000000000000001128750f82f4c366153a3a030");

const TESTNET3_MINIMUM_CHAIN_WORK: [u8; 32] =
    decode_compiled_hex("0000000000000000000000000000000000000000000017dde1c649f3708d14b6");

const TESTNET4_MINIMUM_CHAIN_WORK: [u8; 32] =
    decode_compiled_hex("0000000000000000000000000000000000000000000009a0fe15d0177d086304");

const SIGNET_MINIMUM_CHAIN_WORK: [u8; 32] =
    decode_compiled_hex("00000000000000000000000000000000000000000000000000000b463ea0a4b8");

const BIP16_EXCEPTION_MAINNET: Hash256 = Hash256::from_le_bytes(&[
    0x22, 0x9c, 0x4f, 0xac, 0x88, 0xba, 0xb1, 0x94, 0xeb, 0x08, 0xf1, 0xa5, 0x28, 0xcc, 0x30, 0x8d,
    0xed, 0x23, 0x97, 0xf4, 0xf4, 0xeb, 0x6e, 0x75, 0xdc, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]);

const BIP16_EXCEPTION_TESTNET3: Hash256 = Hash256::from_le_bytes(&[
    0x05, 0xb1, 0x32, 0xa4, 0xf7, 0x4a, 0x87, 0x99, 0xa5, 0x7a, 0x42, 0x02, 0xd0, 0xee, 0xb0, 0x96,
    0x12, 0xcc, 0x08, 0xd2, 0x95, 0x40, 0x1f, 0x00, 0x7c, 0x45, 0x30, 0xdd, 0x00, 0x00, 0x00, 0x00,
]);

const MAINNET_ASSUME_VALID_HEIGHT: u32 = 938_343;

const MAINNET_ASSUME_VALID_HASH: Hash256 = Hash256::from_le_bytes(&[
    0xac, 0xa5, 0x1b, 0xd5, 0xfa, 0x4b, 0x09, 0x8e, 0x47, 0x7c, 0x17, 0x1d, 0xdc, 0xdc, 0xd8, 0x94,
    0x91, 0x4d, 0xd7, 0xd6, 0xeb, 0xcc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet3,
    Testnet4,
    Signet,
    Regtest,
}

impl Network {
    #[must_use]
    pub const fn identity_name(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet3 => "testnet3",
            Self::Testnet4 => "testnet4",
            Self::Signet => "signet",
            Self::Regtest => "regtest",
        }
    }

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

    #[must_use]
    pub const fn bip34_activation_height(self) -> u32 {
        match self {
            Self::Mainnet => 227_931,
            Self::Testnet3 => 21_111,
            Self::Testnet4 | Self::Signet => 1,
            Self::Regtest => 500,
        }
    }

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

    #[must_use]
    pub const fn is_bip34_active(self, height: u32) -> bool {
        height >= self.bip34_activation_height()
    }

    #[must_use]
    pub const fn is_bip65_active(self, height: u32) -> bool {
        height >= self.bip65_activation_height()
    }

    #[must_use]
    pub const fn bip65_activation_height(self) -> u32 {
        match self {
            Self::Mainnet => 388_381,
            Self::Testnet3 => 581_885,
            Self::Testnet4 | Self::Signet => 1,
            Self::Regtest => 1_351,
        }
    }

    #[must_use]
    pub const fn is_bip66_active(self, height: u32) -> bool {
        height >= self.bip66_activation_height()
    }

    #[must_use]
    pub const fn bip66_activation_height(self) -> u32 {
        match self {
            Self::Mainnet => 363_725,
            Self::Testnet3 => 330_776,
            Self::Testnet4 | Self::Signet => 1,
            Self::Regtest => 1_251,
        }
    }

    #[must_use]
    pub const fn is_csv_active(self, height: u32) -> bool {
        height >= self.csv_activation_height()
    }

    #[must_use]
    pub const fn csv_activation_height(self) -> u32 {
        match self {
            Self::Mainnet => 419_328,
            Self::Testnet3 => 770_112,
            Self::Testnet4 | Self::Signet => 1,
            Self::Regtest => 432,
        }
    }

    #[must_use]
    pub const fn is_segwit_active(self, height: u32) -> bool {
        height >= self.segwit_activation_height()
    }

    #[must_use]
    pub const fn segwit_activation_height(self) -> u32 {
        match self {
            Self::Mainnet => 481_824,
            Self::Testnet3 => 834_624,
            Self::Testnet4 | Self::Signet | Self::Regtest => 0,
        }
    }

    #[must_use]
    pub const fn is_taproot_active(self, height: u32) -> bool {
        height >= self.taproot_activation_height()
    }

    #[must_use]
    pub const fn taproot_activation_height(self) -> u32 {
        match self {
            Self::Mainnet => 709_632,
            Self::Testnet3 => 2_017_256,
            Self::Testnet4 | Self::Signet | Self::Regtest => 0,
        }
    }

    #[must_use]
    pub fn is_bip16_p2sh_exception(self, block_hash: Hash256) -> bool {
        match self {
            Self::Mainnet => block_hash == BIP16_EXCEPTION_MAINNET,
            Self::Testnet3 => block_hash == BIP16_EXCEPTION_TESTNET3,
            _ => false,
        }
    }

    #[must_use]
    pub const fn assume_valid_anchor(self) -> Option<(u32, Hash256)> {
        match self {
            Self::Mainnet => Some((MAINNET_ASSUME_VALID_HEIGHT, MAINNET_ASSUME_VALID_HASH)),
            Self::Testnet3 | Self::Testnet4 | Self::Signet | Self::Regtest => None,
        }
    }

    #[must_use]
    pub const fn assume_utxo_data(self) -> &'static [AssumeUtxoData] {
        match self {
            Self::Mainnet => &MAINNET_ASSUME_UTXO,
            Self::Testnet4 => &TESTNET4_ASSUME_UTXO,
            Self::Regtest => &REGTEST_ASSUME_UTXO,
            Self::Testnet3 | Self::Signet => &[],
        }
    }

    #[must_use]
    pub fn assume_utxo_for_height(self, height: u32) -> Option<&'static AssumeUtxoData> {
        self.assume_utxo_data().iter().find(|d| d.height == height)
    }

    #[must_use]
    pub fn assume_utxo_for_hash(self, block_hash: Hash256) -> Option<&'static AssumeUtxoData> {
        self.assume_utxo_data()
            .iter()
            .find(|d| d.block_hash == block_hash)
    }

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

    #[must_use]
    pub const fn retarget_interval(self) -> u32 {
        match self {
            Self::Regtest => 144,
            Self::Mainnet | Self::Testnet3 | Self::Testnet4 | Self::Signet => 2016,
        }
    }

    #[must_use]
    pub const fn subsidy_halving_interval(self) -> u32 {
        match self {
            Self::Regtest => 150,
            Self::Mainnet | Self::Testnet3 | Self::Testnet4 | Self::Signet => 210_000,
        }
    }

    #[must_use]
    pub const fn target_spacing_seconds(self) -> u32 {
        10 * 60
    }

    #[must_use]
    pub const fn chain_tx_data(self) -> ChainTxData {
        match self {
            Self::Mainnet => ChainTxData {
                time: 1_772_055_173,
                tx_count: 1_315_805_869,
                tx_rate: 5.401_110_064_961_22,
            },
            Self::Testnet3 => ChainTxData {
                time: 1_772_051_651,
                tx_count: 536_108_416,
                tx_rate: 0.026_914_790_162_571_17,
            },
            Self::Testnet4 => ChainTxData {
                time: 1_772_013_387,
                tx_count: 14_191_421,
                tx_rate: 0.018_485_795_795_284_12,
            },
            Self::Signet => ChainTxData {
                time: 1_772_055_248,
                tx_count: 28_676_833,
                tx_rate: 0.067_366_234_363_389_29,
            },
            Self::Regtest => ChainTxData {
                time: 0,
                tx_count: 0,
                tx_rate: 0.001,
            },
        }
    }
    #[must_use]
    pub const fn minimum_chain_work(self) -> [u8; 32] {
        match self {
            Self::Mainnet => MAINNET_MINIMUM_CHAIN_WORK,
            Self::Testnet3 => TESTNET3_MINIMUM_CHAIN_WORK,
            Self::Testnet4 => TESTNET4_MINIMUM_CHAIN_WORK,
            Self::Signet => SIGNET_MINIMUM_CHAIN_WORK,
            Self::Regtest => [0_u8; 32],
        }
    }

    #[must_use]
    pub const fn headers_sync_params(self) -> HeadersSyncParams {
        match self {
            Self::Mainnet => HeadersSyncParams {
                commitment_period: 649,
                redownload_buffer_size: 15_400,
            },
            Self::Testnet3 => HeadersSyncParams {
                commitment_period: 682,
                redownload_buffer_size: 14_613,
            },
            Self::Testnet4 => HeadersSyncParams {
                commitment_period: 616,
                redownload_buffer_size: 16_199,
            },
            Self::Signet => HeadersSyncParams {
                commitment_period: 629,
                redownload_buffer_size: 15_885,
            },
            Self::Regtest => HeadersSyncParams {
                commitment_period: 275,
                redownload_buffer_size: 7_017,
            },
        }
    }

    #[must_use]
    pub const fn target_timespan_seconds(self) -> u32 {
        self.retarget_interval()
            .saturating_mul(self.target_spacing_seconds())
    }

    #[must_use]
    pub const fn allow_min_difficulty_blocks(self) -> bool {
        match self {
            Self::Testnet3 | Self::Testnet4 | Self::Regtest => true,
            Self::Mainnet | Self::Signet => false,
        }
    }

    #[must_use]
    pub const fn pow_no_retargeting(self) -> bool {
        match self {
            Self::Regtest => true,
            Self::Mainnet | Self::Testnet3 | Self::Testnet4 | Self::Signet => false,
        }
    }

    #[must_use]
    pub const fn enforce_bip94(self) -> bool {
        match self {
            Self::Testnet4 => true,
            Self::Mainnet | Self::Testnet3 | Self::Signet | Self::Regtest => false,
        }
    }

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

    #[must_use]
    pub const fn signet_challenge(self) -> Option<&'static [u8]> {
        match self {
            Self::Signet => Some(SIGNET_DEFAULT_CHALLENGE),
            Self::Mainnet | Self::Testnet3 | Self::Testnet4 | Self::Regtest => None,
        }
    }

    #[must_use]
    pub fn genesis_block(self) -> crate::Block {
        let bytes: &[u8] = match self {
            Self::Mainnet => &MAINNET_GENESIS,
            Self::Testnet3 => &TESTNET3_GENESIS,
            Self::Testnet4 => &TESTNET4_GENESIS,
            Self::Signet => &SIGNET_GENESIS,
            Self::Regtest => &REGTEST_GENESIS,
        };
        let block = crate::deserialize::<crate::Block>(bytes)
            .unwrap_or_else(|error| panic!("compiled-in genesis must decode: {error}"));
        debug_assert_eq!(
            crate::Hash256::from_le_bytes(block.block_hash().as_bytes()),
            self.genesis_block_hash(),
            "compiled-in genesis bytes must hash to the compiled-in genesis hash"
        );
        block
    }
}

/// Core's default signet challenge (`OP_1 <pubkey> <pubkey> OP_2 OP_CHECKMULTISIG`,
/// `src/signet.h`).
const SIGNET_DEFAULT_CHALLENGE: &[u8] = &[
    0x51, 0x21, 0x03, 0xad, 0x5e, 0x0e, 0xda, 0xd1, 0x8c, 0xb1, 0xf0, 0xfc, 0x0d, 0x28, 0xa3, 0xd4,
    0xf1, 0xf3, 0xe4, 0x45, 0x64, 0x03, 0x37, 0x48, 0x9a, 0xbb, 0x10, 0x40, 0x4f, 0x2d, 0x1e, 0x08,
    0x6b, 0xe4, 0x30, 0x21, 0x03, 0x59, 0xef, 0x50, 0x21, 0x96, 0x4f, 0xe2, 0x2d, 0x6f, 0x8e, 0x05,
    0xb2, 0x46, 0x3c, 0x95, 0x40, 0xce, 0x96, 0x88, 0x3f, 0xe3, 0xb2, 0x78, 0x76, 0x0f, 0x04, 0x8f,
    0x51, 0x89, 0xf2, 0xe6, 0xc4, 0x52, 0xae,
];

const TESTNET3_GENESIS_HEX: &str = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae180101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";
const MAINNET_GENESIS_HEX: &str = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";

const TESTNET4_GENESIS_HEX: &str = "0100000000000000000000000000000000000000000000000000000000000000000000004e7b2b9128fe0291db0693af2ae418b767e657cd407e80cb1434221eaea7a07a046f3566ffff001dbb0c78170101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff5504ffff001d01044c4c30332f4d61792f323032342030303030303030303030303030303030303030303165626435386332343439373062336161396437383362623030313031316662653865613865393865303065ffffffff0100f2052a010000002321000000000000000000000000000000000000000000000000000000000000000000ac00000000";

const SIGNET_GENESIS_HEX: &str = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a008f4d5fae77031e8ad222030101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";

const REGTEST_GENESIS_HEX: &str = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff7f20020000000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";

const fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("compiled-in hex constant is hex"),
    }
}

const fn decode_compiled_hex<const N: usize>(hex: &str) -> [u8; N] {
    let bytes = hex.as_bytes();
    assert!(bytes.len() == N * 2, "compiled-in hex length matches array");
    let mut out = [0_u8; N];
    let mut index = 0;
    while index < N {
        out[index] = (hex_nibble(bytes[index * 2]) << 4) | hex_nibble(bytes[index * 2 + 1]);
        index += 1;
    }
    out
}

const MAINNET_GENESIS: [u8; 285] = decode_compiled_hex(MAINNET_GENESIS_HEX);
const TESTNET3_GENESIS: [u8; 285] = decode_compiled_hex(TESTNET3_GENESIS_HEX);
const TESTNET4_GENESIS: [u8; 261] = decode_compiled_hex(TESTNET4_GENESIS_HEX);
const SIGNET_GENESIS: [u8; 285] = decode_compiled_hex(SIGNET_GENESIS_HEX);
const REGTEST_GENESIS: [u8; 285] = decode_compiled_hex(REGTEST_GENESIS_HEX);

const fn decode_compiled_hash_be(hex: &str) -> Hash256 {
    let bytes = hex.as_bytes();
    assert!(
        bytes.len() == 64,
        "compiled-in hash hex must be 64 characters"
    );
    let mut out = [0_u8; 32];
    let mut index = 0;
    while index < 32 {
        let hi = hex_nibble(bytes[index * 2]);
        let lo = hex_nibble(bytes[index * 2 + 1]);
        out[31 - index] = (hi << 4) | lo;
        index += 1;
    }
    Hash256::from_le_bytes(&out)
}

const MAINNET_ASSUME_UTXO: [AssumeUtxoData; 5] = [
    AssumeUtxoData {
        height: 840_000,
        block_hash: decode_compiled_hash_be(
            "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5",
        ),
        hash_serialized: decode_compiled_hash_be(
            "a2a5521b1b5ab65f67818e5e8eccabb7171a517f9e2382208f77687310768f96",
        ),
        chain_tx_count: 991_032_194,
    },
    AssumeUtxoData {
        height: 880_000,
        block_hash: decode_compiled_hash_be(
            "000000000000000000010b17283c3c400507969a9c2afd1dcf2082ec5cca2880",
        ),
        hash_serialized: decode_compiled_hash_be(
            "dbd190983eaf433ef7c15f78a278ae42c00ef52e0fd2a54953782175fbadcea9",
        ),
        chain_tx_count: 1_145_604_538,
    },
    AssumeUtxoData {
        height: 910_000,
        block_hash: decode_compiled_hash_be(
            "0000000000000000000108970acb9522ffd516eae17acddcb1bd16469194a821",
        ),
        hash_serialized: decode_compiled_hash_be(
            "4daf8a17b4902498c5787966a2b51c613acdab5df5db73f196fa59a4da2f1568",
        ),
        chain_tx_count: 1_226_586_151,
    },
    AssumeUtxoData {
        height: 935_000,
        block_hash: decode_compiled_hash_be(
            "0000000000000000000147034958af1652b2b91bba607beacc5e72a56f0fb5ee",
        ),
        hash_serialized: decode_compiled_hash_be(
            "e4b90ef9eae834f56c4b64d2d50143cee10ad87994c614d7d04125e2a6025050",
        ),
        chain_tx_count: 1_305_397_408,
    },
    AssumeUtxoData {
        height: 965_000,
        block_hash: decode_compiled_hash_be(
            "00000000000000000001595977e6000ce56129f5c9b4073e31ccc30b90b97da9",
        ),
        hash_serialized: decode_compiled_hash_be(
            "4a8d794337118c0c615b574f817c7306c687584a537184b8d233df42bf477ec2",
        ),
        chain_tx_count: 1_429_611_231,
    },
];

const TESTNET4_ASSUME_UTXO: [AssumeUtxoData; 1] = [AssumeUtxoData {
    height: 90_000,
    block_hash: decode_compiled_hash_be(
        "0000000002ebe8bcda020e0dd6ccfbdfac531d2f6a81457191b99fc2df2dbe3b",
    ),
    hash_serialized: decode_compiled_hash_be(
        "784fb5e98241de66fdd429f4392155c9e7db5c017148e66e8fdbc95746f8b9b5",
    ),
    chain_tx_count: 11_347_043,
}];

const REGTEST_ASSUME_UTXO: [AssumeUtxoData; 2] = [
    AssumeUtxoData {
        height: 110,
        block_hash: decode_compiled_hash_be(
            "135eec25a6fb277884e5824e7aa7d052c4868161c99a5122170b5266f86c273d",
        ),
        hash_serialized: decode_compiled_hash_be(
            "86e9a1205b418b16dde3a18a78c730e30137e28466bda5dbf6b33ab8fc05447c",
        ),
        chain_tx_count: 111,
    },
    AssumeUtxoData {
        height: 200,
        block_hash: decode_compiled_hash_be(
            "385901ccbd69dff6bbd00065d01fb8a9e464dede7cfe0372443884f9b1dcf6b9",
        ),
        hash_serialized: decode_compiled_hash_be(
            "17dcc016d188d16068907cdeb38b75691a118d43053b8cd6a25969419381d13a",
        ),
        chain_tx_count: 201,
    },
];

#[cfg(test)]
mod tests {
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
}

#[cfg(test)]
mod chain_params_tests {
    use super::{Network, decode_compiled_hex};

    fn to_hex(bytes: [u8; 32]) -> String {
        let mut out = String::with_capacity(64);
        for byte in bytes {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    #[test]
    fn decode_compiled_hex_places_the_first_character_in_the_high_bit_of_byte_zero() {
        let parsed: [u8; 32] =
            decode_compiled_hex("8000000000000000000000000000000000000000000000000000000000000001");
        assert_eq!(
            parsed[0], 0x80,
            "the leading nibble is the most significant"
        );
        assert_eq!(
            parsed[31], 0x01,
            "the trailing nibble is the least significant"
        );
        assert!(parsed[1..31].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn minimum_chain_work_round_trips_to_the_hex_bitcoin_core_ships() {
        let expected = [
            (
                Network::Mainnet,
                "0000000000000000000000000000000000000001128750f82f4c366153a3a030",
            ),
            (
                Network::Testnet3,
                "0000000000000000000000000000000000000000000017dde1c649f3708d14b6",
            ),
            (
                Network::Testnet4,
                "0000000000000000000000000000000000000000000009a0fe15d0177d086304",
            ),
            (
                Network::Signet,
                "00000000000000000000000000000000000000000000000000000b463ea0a4b8",
            ),
            (
                Network::Regtest,
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
        ];
        for (network, hex) in expected {
            assert_eq!(to_hex(network.minimum_chain_work()), hex, "{network:?}");
        }
    }

    #[test]
    fn minimum_chain_work_compares_as_a_number_when_compared_as_bytes() {
        let smaller: [u8; 32] =
            decode_compiled_hex("00000000000000000000000000000000000000000000000000000000000000ff");
        let larger: [u8; 32] =
            decode_compiled_hex("0000000000000000000000000000000000000000000000000000000000000100");
        assert!(smaller < larger);
        assert!(Network::Regtest.minimum_chain_work() < Network::Signet.minimum_chain_work());
        assert!(Network::Signet.minimum_chain_work() < Network::Mainnet.minimum_chain_work());
    }
}
