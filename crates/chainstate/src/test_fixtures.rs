use std::sync::Arc;

use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::{BlockTree, ChainTxCount, TipSnapshot};
use bitcoin_rs_primitives::{Amount, Hash256, Network, OutPoint, TxOut, Txid};
use bitcoin_rs_storage::StorageError;
use bitcoin_rs_storage::block_body::BlockBodyStore;
use bitcoin_rs_storage::chainstate_journal::Coin;
use bitcoin_rs_utxo::UtxoSet;
use bitcoin_rs_utxo::stats::{CoinStats, CoinStatsListener};
use hashbrown::HashMap;
use parking_lot::{Mutex, RwLock};

use crate::{ApplyError, Chainstate, TipStagedHook};

pub(crate) fn journal_coin(marker: u8, height: u32, value: u64) -> Coin {
    Coin {
        outpoint: OutPoint::new(Txid(Hash256::from_le_bytes(&[marker; 32])), 0),
        txout: TxOut {
            value: Amount::from_sat(value),
            script_pubkey: vec![0x51].into(),
        },
        height,
        coinbase: true,
    }
}

pub(crate) fn handles(network: Network, utxo: Arc<UtxoSet>) -> Chainstate {
    Chainstate::new(
        network,
        Arc::new(ArcSwapOption::empty()),
        Arc::new(ArcSwapOption::empty()),
        Arc::new(RwLock::new(BlockTree::new())),
        utxo,
        Arc::new(CoinStatsListener::new(CoinStats::default())),
        Arc::new(crate::events::ChainEventPublisher::detached(0)),
    )
}

pub(crate) fn seed_genesis(handles: &Chainstate) -> Result<TipSnapshot, ApplyError> {
    let genesis = Network::Regtest.genesis_block();
    let tip = crate::connect::applied_header_tip(
        handles,
        Hash256::from(genesis.block_hash()),
        &genesis,
        0,
    )?;
    let tip = TipSnapshot {
        chain_tx_count: ChainTxCount::established(1),
        ..tip
    };
    handles.applied_tip.store(Some(Arc::new(tip.clone())));
    Ok(tip)
}

pub(crate) struct StagedFire {
    pub(crate) staged_hash: Hash256,
    pub(crate) staged_height: u32,
    pub(crate) block_hash: Hash256,
    pub(crate) published: Option<(Hash256, u32)>,
}

pub(crate) fn staging_recorder(
    chain: &Chainstate,
    fires: &Arc<Mutex<Vec<StagedFire>>>,
) -> TipStagedHook {
    let fires = Arc::clone(fires);
    let chain = chain.clone();
    Arc::new(move |staged, block| {
        let published = chain
            .applied_tip_snapshot()
            .map(|tip| (tip.hash, tip.height));
        fires.lock().push(StagedFire {
            staged_hash: staged.hash,
            staged_height: staged.height,
            block_hash: Hash256::from(block.block_hash()),
            published,
        });
    })
}

#[derive(Default)]
pub(crate) struct MemoryBodies {
    bodies: RwLock<HashMap<(u32, Hash256), Vec<u8>>>,
}

impl BlockBodyStore for MemoryBodies {
    fn load_block_body_bounded(
        &self,
        height: u32,
        hash: Hash256,
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>, bitcoin_rs_storage::BoundedReadError> {
        self.bodies
            .read()
            .get(&(height, hash))
            .map(|body| {
                if body.len() > max_bytes {
                    Err(bitcoin_rs_storage::BoundedReadError::Limit {
                        size: body.len(),
                        limit: max_bytes,
                    })
                } else {
                    Ok(body.clone())
                }
            })
            .transpose()
    }

    fn persist_block_body(
        &self,
        height: u32,
        hash: Hash256,
        body: &[u8],
    ) -> Result<(), StorageError> {
        self.bodies.write().insert((height, hash), body.to_vec());
        Ok(())
    }

    fn load_block_body(&self, height: u32, hash: Hash256) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.bodies.read().get(&(height, hash)).cloned())
    }

    fn sync(&self) -> Result<(), StorageError> {
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum TestError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Var(#[from] std::env::VarError),
    #[error(transparent)]
    TryFromInt(#[from] std::num::TryFromIntError),
    #[error(transparent)]
    ParseInt(#[from] std::num::ParseIntError),
    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),
    #[error(transparent)]
    Storage(#[from] bitcoin_rs_storage::StorageError),
    #[error(transparent)]
    BoundedRead(#[from] bitcoin_rs_storage::BoundedReadError),
    #[error(transparent)]
    CheckpointLoad(#[from] bitcoin_rs_storage::checkpoint::CheckpointLoadError),
    #[error(transparent)]
    JournalWriter(#[from] bitcoin_rs_storage::chainstate_journal::JournalWriterError),
    #[error(transparent)]
    JournalReplay(#[from] bitcoin_rs_storage::chainstate_journal::JournalReplayError),
    #[error(transparent)]
    HistoryUnavailable(#[from] bitcoin_rs_storage::pruning::HistoryUnavailable),
    #[error(transparent)]
    Chain(#[from] bitcoin_rs_chain::ChainError),
    #[error(transparent)]
    RegtestFixture(#[from] bitcoin_rs_chain::regtest_fixture::RegtestFixtureError),
    #[error(transparent)]
    Consensus(#[from] bitcoin_rs_consensus::ConsensusError),
    #[error(transparent)]
    Utxo(#[from] bitcoin_rs_utxo::UtxoError),
    #[error(transparent)]
    BlockSpends(#[from] bitcoin_rs_utxo::contract::BlockSpendsError),
    #[error(transparent)]
    UndoLoad(#[from] bitcoin_rs_utxo::contract::UndoLoadError),
    #[error(transparent)]
    BlockChange(#[from] bitcoin_rs_utxo::contract::BlockChangeError),
    #[error(transparent)]
    Snapshot(#[from] bitcoin_rs_utxo::core_snapshot::SnapshotError),
    #[error(transparent)]
    StateVerify(#[from] bitcoin_rs_utxo::core_snapshot::StateVerifyError),
    #[error(transparent)]
    RawSeed(#[from] bitcoin_rs_utxo::snapshot::RawSeedError<std::convert::Infallible>),
    #[error(transparent)]
    Apply(#[from] crate::ApplyError),
    #[error(transparent)]
    Disconnect(#[from] crate::DisconnectError),
    #[error(transparent)]
    AssumeUtxo(#[from] crate::assumeutxo::AssumeUtxoError),
    #[error(transparent)]
    Checkpoint(#[from] crate::CheckpointError),
    #[error(transparent)]
    HeaderCheckpoint(#[from] crate::checkpoint::headers::HeaderCheckpointError),
    #[error(transparent)]
    HeaderAdmission(#[from] crate::HeaderAdmissionError),
    #[error(transparent)]
    CheckpointSetup(#[from] crate::CheckpointSetupError),
    #[error(transparent)]
    DataDir(#[from] crate::events::DataDirError),
    #[error(transparent)]
    SnapshotArchive(#[from] crate::SnapshotArchiveError),
    #[error(transparent)]
    BodyDecode(#[from] crate::verify::BodyDecodeError),
    #[error(transparent)]
    Verify(#[from] crate::verify::VerifyError),
    #[error(transparent)]
    Recovery(#[from] crate::recovery::RecoveryError),
    #[error(transparent)]
    Reorg(#[from] crate::reorg::ReorgError),
    #[error(transparent)]
    WindowApply(Box<crate::WindowApplyError>),
    #[error(transparent)]
    Sonic(#[from] sonic_rs::Error),
    #[error(transparent)]
    RecvTimeout(#[from] std::sync::mpsc::RecvTimeoutError),
    #[error("regrind {what} block: {source}")]
    Regrind {
        what: &'static str,
        #[source]
        source: bitcoin_rs_chain::regtest_fixture::RegtestFixtureError,
    },
    #[error("hook already installed: {0}")]
    HookAlreadyInstalled(&'static str),
    #[error("missing: {0}")]
    Missing(&'static str),
    #[error(transparent)]
    Decode(#[from] bitcoin_rs_primitives::DecodeError),
    #[error("exhausted: {0}")]
    Exhausted(&'static str),
    #[error("worker panicked: {0}")]
    WorkerPanicked(&'static str),
    #[error("blocked past the deadline: {0}")]
    Blocked(&'static str),
    #[error("unexpected success: {0}")]
    UnexpectedSuccess(&'static str),
}

pub(crate) type TestResult<T = ()> = Result<T, TestError>;
impl From<crate::WindowApplyError> for TestError {
    fn from(error: crate::WindowApplyError) -> Self {
        Self::WindowApply(Box::new(error))
    }
}
