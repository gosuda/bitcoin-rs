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
    /// Coinstats index rows.
    Coinstats = 5,
    /// Block-tree node rows.
    BlockTree = 6,
    /// UTXO snapshot metadata rows.
    UtxoMeta = 7,
    /// Serialized block body rows.
    BlockBodies = 8,
    /// Per-block UTXO undo records, needed to disconnect a block during a reorg.
    UndoData = 9,
    /// Live script-index rows: `script-prefix || outpoint` for currently
    /// unspent outputs (#225). Appended after every existing discriminant so
    /// the addition is additive -- renumbering these is a breaking change
    /// (`docs/policies/db-migration.md` 3.1).
    ScriptLive = 10,
}

impl ColumnFamily {
    /// All supported column families, in stable on-disk order.
    pub const ALL: &'static [Self] = &[
        Self::TxConfirmed,
        Self::TxMempool,
        Self::BlockHeaders,
        Self::Funding,
        Self::Spending,
        Self::Coinstats,
        Self::BlockTree,
        Self::UtxoMeta,
        Self::BlockBodies,
        Self::UndoData,
        Self::ScriptLive,
    ];

    /// Stable backend column-family/table name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::TxConfirmed => "tx_confirmed",
            Self::TxMempool => "tx_mempool",
            Self::BlockHeaders => "block_headers",
            Self::Funding => "funding",
            Self::Spending => "spending",
            Self::Coinstats => "coinstats",
            Self::BlockTree => "block_tree",
            Self::UtxoMeta => "utxo_meta",
            Self::BlockBodies => "block_bodies",
            Self::UndoData => "undo_data",
            Self::ScriptLive => "script_live",
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
            5 => Some(Self::Coinstats),
            6 => Some(Self::BlockTree),
            7 => Some(Self::UtxoMeta),
            8 => Some(Self::BlockBodies),
            9 => Some(Self::UndoData),
            10 => Some(Self::ScriptLive),
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
            Self::Coinstats => 5,
            Self::BlockTree => 6,
            Self::UtxoMeta => 7,
            Self::BlockBodies => 8,
            Self::UndoData => 9,
            Self::ScriptLive => 10,
        }
    }
}
