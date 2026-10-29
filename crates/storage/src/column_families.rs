/// Logical storage column families.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ColumnFamily {
    TxConfirmed = 0,
    TxMempool = 1,
    BlockHeaders = 2,
    Funding = 3,
    Spending = 4,
    Coinstats = 5,
    BlockTree = 6,
    UtxoMeta = 7,
    BlockBodies = 8,
    UndoData = 9,
    /// Live script-index rows: `script-prefix || outpoint` for currently
    /// unspent outputs.
    ScriptLive = 10,
    /// Grouped transaction-level live coin records: one row per
    /// transaction with live outputs, keyed by the full 256-bit txid and
    /// valued by the lossless canonical v5 record payload.
    CoinRecords = 11,
    /// Durable pool-ledger rows: one byte-keyed keyspace holding the
    /// ledger revision sentinel and its tagged logical tables.
    PoolLedger = 12,
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
        Self::CoinRecords,
        Self::PoolLedger,
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
            Self::CoinRecords => "coin_records",
            Self::PoolLedger => "pool_ledger",
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
            Self::CoinRecords => 11,
            Self::PoolLedger => 12,
        }
    }
}
