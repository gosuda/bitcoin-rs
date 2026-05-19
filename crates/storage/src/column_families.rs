/// Logical storage column families.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ColumnFamily {
    /// Confirmed transaction index rows.
    TxConfirmed = 0,
    /// Mempool transaction index rows.
    TxMempool = 1,
    /// Block header rows.
    BlockHeaders = 2,
    /// Transaction funding rows.
    Funding = 3,
    /// Transaction spending rows.
    Spending = 4,
    /// BIP157/158 compact filter rows.
    Filters = 5,
    /// BIP157/158 filter-header rows.
    FilterHeaders = 6,
    /// Coinstats index rows.
    Coinstats = 7,
    /// Block-tree node rows.
    BlockTree = 8,
    /// UTXO snapshot metadata rows.
    UtxoMeta = 9,
}

impl ColumnFamily {
    /// All supported column families, in stable on-disk order.
    pub const ALL: &'static [Self] = &[
        Self::TxConfirmed,
        Self::TxMempool,
        Self::BlockHeaders,
        Self::Funding,
        Self::Spending,
        Self::Filters,
        Self::FilterHeaders,
        Self::Coinstats,
        Self::BlockTree,
        Self::UtxoMeta,
    ];

    /// Stable backend column-family/table name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::TxConfirmed => "tx_confirmed",
            Self::TxMempool => "tx_mempool",
            Self::BlockHeaders => "block_headers",
            Self::Funding => "funding",
            Self::Spending => "spending",
            Self::Filters => "filters",
            Self::FilterHeaders => "filter_headers",
            Self::Coinstats => "coinstats",
            Self::BlockTree => "block_tree",
            Self::UtxoMeta => "utxo_meta",
        }
    }

    /// Alias for [`Self::name`].
    pub const fn as_str(self) -> &'static str {
        self.name()
    }

    /// Converts the stable one-byte representation to a column family.
    pub const fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::TxConfirmed),
            1 => Some(Self::TxMempool),
            2 => Some(Self::BlockHeaders),
            3 => Some(Self::Funding),
            4 => Some(Self::Spending),
            5 => Some(Self::Filters),
            6 => Some(Self::FilterHeaders),
            7 => Some(Self::Coinstats),
            8 => Some(Self::BlockTree),
            9 => Some(Self::UtxoMeta),
            _ => None,
        }
    }

    /// Stable zero-based index for arrays keyed by column family.
    pub const fn index(self) -> usize {
        match self {
            Self::TxConfirmed => 0,
            Self::TxMempool => 1,
            Self::BlockHeaders => 2,
            Self::Funding => 3,
            Self::Spending => 4,
            Self::Filters => 5,
            Self::FilterHeaders => 6,
            Self::Coinstats => 7,
            Self::BlockTree => 8,
            Self::UtxoMeta => 9,
        }
    }
}
