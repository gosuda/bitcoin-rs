use std::sync::Arc;

use crate::chain::{BlockTree, ChainTxCount, TipSnapshot};
use arc_swap::ArcSwapOption;
use bitcoin_rs_consensus::primitives::{
    Amount, Block, BlockImage, Hash256, LockTime, Network, OutPoint, Sequence, Tx, TxIn, TxOut,
    Witness,
};
use bitcoin_rs_storage::utxo::UtxoSet;
use bitcoin_rs_storage::utxo::stats::{CoinStats, CoinStatsListener};
use parking_lot::{Mutex, RwLock};

use crate::{ApplyError, Chainstate, TipStagedHook};

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

pub(crate) fn handles_with_store<S: bitcoin_rs_storage::KvStore>(
    network: Network,
    utxo: Arc<UtxoSet>,
    store: Arc<S>,
) -> Chainstate {
    let dyn_store: Arc<dyn bitcoin_rs_storage::KvStore> = store.clone();
    let coins = Arc::new(bitcoin_rs_storage::CoinStore::open(
        Arc::clone(&dyn_store),
        64 * 1024 * 1024,
    ));
    let durable_head = Arc::new(bitcoin_rs_storage::KvDurableHeadStore::new(Arc::clone(
        &store,
    )));
    let undo_store = Arc::new(bitcoin_rs_storage::KvUndoStore::new(Arc::clone(&dyn_store)));
    let commit_authority = Arc::new(bitcoin_rs_storage::CommitAuthority::new(
        Arc::clone(&dyn_store),
        Arc::clone(&coins),
    ));
    let retention = Arc::new(bitcoin_rs_storage::RetentionRegistry::new());
    Chainstate::from_parts(crate::ChainstateParts {
        network,
        block_tree: BlockTree::new(),
        restored_applied_tip: None,
        utxo,
        coin_stats: Arc::new(CoinStatsListener::new(CoinStats::default())),
        chain_events: Arc::new(crate::events::ChainEventPublisher::detached(0)),
        block_body_store: None,
        undo_store,
        durable_head,
        coins,
        commit_authority,
        chain_transition: crate::chain::TransitionDomain::new().authority(),
        assume_valid_height: 0,
        validation_mode: crate::ValidationMode::AssumeValid,
        validation_engine: bitcoin_rs_consensus::ValidationEngine::Native,
        script_cache: None,
        capture_rawtx: false,
        capture_block_bytes: false,
        retention: bitcoin_rs_storage::MandatoryRetention::new(Arc::clone(&retention)),
        history: bitcoin_rs_storage::pruning::HistoryAccess::new(
            retention,
            bitcoin_rs_storage::pruning::RetentionBudget::from_blocks(
                bitcoin_rs_consensus::primitives::chain_constants::CORE_REORG_SAFETY_MARGIN,
            ),
        ),
        role: crate::ChainstateRole::Ordinary,
    })
}

pub(crate) fn seed_genesis(handles: &Chainstate) -> Result<TipSnapshot, ApplyError> {
    let genesis = Network::Regtest.genesis_block();
    let tip = crate::connect::applied_header_tip(
        handles,
        Hash256::from(genesis.block_hash()),
        &BlockImage::from_local(genesis),
        0,
    )?;
    let tip = TipSnapshot {
        chain_tx_count: ChainTxCount::established(1),
        ..tip
    };
    handles.applied_tip.store(Some(Arc::new(tip.clone())));
    Ok(tip)
}

pub(crate) fn seed_durable_head(
    chain: &Chainstate,
    next: bitcoin_rs_storage::DurableHead,
) -> TestResult {
    <Chainstate>::commit_authority(chain)
        .commit_prefix(bitcoin_rs_storage::AcceptedPrefix {
            expected_head: None,
            next_head: next,
            undo_rows: Vec::new(),
            body_rows: Vec::new(),
            attestation: None,
            coin_delta: bitcoin_rs_storage::WindowDelta::default(),
        })
        .map_err(|error| {
            TestError::Storage(bitcoin_rs_storage::StorageError::backend(error.to_string()))
        })?;
    Ok(())
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
    HistoryUnavailable(#[from] bitcoin_rs_storage::pruning::HistoryUnavailable),
    #[error(transparent)]
    Chain(#[from] crate::chain::ChainError),
    #[error(transparent)]
    RegtestFixture(#[from] crate::chain::regtest_fixture::RegtestFixtureError),
    #[error(transparent)]
    Consensus(#[from] bitcoin_rs_consensus::ConsensusError),
    #[error(transparent)]
    Utxo(#[from] bitcoin_rs_storage::utxo::UtxoError),
    #[error(transparent)]
    BlockSpends(#[from] bitcoin_rs_storage::utxo::contract::BlockSpendsError),
    #[error(transparent)]
    UndoLoad(#[from] bitcoin_rs_storage::utxo::contract::UndoLoadError),
    #[error(transparent)]
    BlockChange(#[from] bitcoin_rs_storage::utxo::contract::BlockChangeError),
    #[error(transparent)]
    Snapshot(#[from] bitcoin_rs_storage::utxo::core_snapshot::SnapshotError),
    #[error(transparent)]
    StateVerify(#[from] bitcoin_rs_storage::utxo::core_snapshot::StateVerifyError),
    #[error(transparent)]
    RawSeed(#[from] bitcoin_rs_storage::utxo::snapshot::RawSeedError<std::convert::Infallible>),
    #[error(transparent)]
    Apply(#[from] crate::ApplyError),
    #[error(transparent)]
    Disconnect(#[from] crate::DisconnectError),
    #[error(transparent)]
    Fuzz(#[from] crate::fuzzing::FuzzError),
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
        source: crate::chain::regtest_fixture::RegtestFixtureError,
    },
    #[error("hook already installed: {0}")]
    HookAlreadyInstalled(&'static str),
    #[error("missing: {0}")]
    Missing(&'static str),
    #[error(transparent)]
    Decode(#[from] bitcoin_rs_consensus::primitives::DecodeError),
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
impl From<&'static str> for TestError {
    fn from(error: &'static str) -> Self {
        Self::Missing(error)
    }
}

pub(crate) type CoinScan = Vec<(Vec<u8>, Vec<u8>)>;

pub(crate) fn coin_scan(chain: &Chainstate) -> Result<CoinScan, TestError> {
    let store = chain.commit_authority.store();
    store
        .iter_prefix(bitcoin_rs_storage::ColumnFamily::Coins, &[])?
        .collect::<Result<Vec<_>, _>>()
        .map_err(TestError::Storage)
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum CorpusSpend {
    MatureCoinbase { height: u32 },
    EarlierBlock { block: usize, tx: usize },
    SameBlock { tx: usize },
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct CorpusSpendPlan {
    pub spend: CorpusSpend,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct CorpusBlockPlan {
    pub spends: Vec<CorpusSpendPlan>,
}

pub(crate) struct Corpus {
    pub prefix: Vec<Block>,
    pub blocks: Vec<Block>,
}

pub(crate) const CORPUS_MATURITY_BLOCKS: u32 = 100;

const CORPUS_SPEND_VALUE: u64 = 5_000_000_000;

impl Corpus {
    pub(crate) fn build(plans: &[CorpusBlockPlan]) -> TestResult<Self> {
        let genesis = Network::Regtest.genesis_block();
        let mut parent = genesis.block_hash();
        let mut funded: Vec<Block> = Vec::new();
        for height in 1..=CORPUS_MATURITY_BLOCKS {
            let block = crate::chain::regtest_fixture::mined_regtest_child_at(parent, height)?;
            parent = block.block_hash();
            funded.push(block);
        }
        let mut generated: Vec<Block> = Vec::new();
        for (offset, plan) in plans.iter().enumerate() {
            let height = CORPUS_MATURITY_BLOCKS
                + u32::try_from(offset)?
                    .checked_add(1)
                    .ok_or(TestError::Missing("corpus height overflow"))?;
            let mut block = crate::chain::regtest_fixture::mined_regtest_child_at(parent, height)?;
            let mut created: Vec<Tx> = Vec::new();
            for spend in &plan.spends {
                let previous_output = match spend.spend {
                    CorpusSpend::MatureCoinbase { height } => {
                        let index = usize::try_from(height)?
                            .checked_sub(1)
                            .ok_or(TestError::Missing("mature coinbase height"))?;
                        let coinbase = funded
                            .get(index)
                            .ok_or(TestError::Missing("mature coinbase block"))?;
                        OutPoint::new(coinbase.txs[0].txid(), 0)
                    }
                    CorpusSpend::EarlierBlock { block: index, tx } => {
                        let earlier = generated
                            .get(index)
                            .ok_or(TestError::Missing("earlier corpus block"))?;
                        let transaction = earlier
                            .txs
                            .get(tx + 1)
                            .ok_or(TestError::Missing("earlier corpus transaction"))?;
                        OutPoint::new(transaction.txid(), 0)
                    }
                    CorpusSpend::SameBlock { tx } => {
                        let transaction = created
                            .get(tx)
                            .ok_or(TestError::Missing("same-block transaction"))?;
                        OutPoint::new(transaction.txid(), 0)
                    }
                };
                created.push(corpus_spend_tx(previous_output));
            }
            block.txs.extend(created);
            block.header.merkle_root = crate::chain::regtest_fixture::merkle_root(&block.txs)
                .ok_or(TestError::Missing("corpus merkle root"))?;
            crate::chain::regtest_fixture::mine_block_to_declared_target(&mut block)?;
            parent = block.block_hash();
            generated.push(block);
        }
        Ok(Self {
            prefix: funded,
            blocks: generated,
        })
    }

    pub(crate) fn payloads(&self) -> Vec<BlockImage> {
        self.blocks
            .iter()
            .map(|block| BlockImage::from_local(block.clone()))
            .collect()
    }
}

fn corpus_spend_tx(previous_output: OutPoint) -> Tx {
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output,
            script_sig: vec![bitcoin_rs_consensus::script::opcode::OP_PUSHNUM_1].into(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(CORPUS_SPEND_VALUE),
            script_pubkey: vec![bitcoin_rs_consensus::script::opcode::OP_PUSHNUM_1].into(),
        }],
        lock_time: LockTime::ZERO,
    }
}
