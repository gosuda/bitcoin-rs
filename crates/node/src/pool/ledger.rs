use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use bitcoin_rs_chainstate::Chainstate;
use bitcoin_rs_index::{DerivedIndexQuery, ScriptIndexQuery};
use bitcoin_rs_mempool::MempoolReader;
use bitcoin_rs_primitives::encode::deserialize;
use bitcoin_rs_primitives::{Block, Hash256, OutPoint as NodeOutPoint, Txid};
use bitcoin_rs_storage::block_body::BlockBodyStore;
use bitcoin_rs_stratum::{
    AcceptedShare, AccountResolver, AuthDenied, BlockReceipt, FoundBlock, LedgerUnavailable,
    Password, RecordOutcome, ShareLedger, WorkerIdentity,
};
use pool_ledger::{
    BlockFound as LedgerBlockFound, BlockLocation, ChainView, ChainViewError, ConfirmedSpend,
    Ledger, MinerId, ObservedCoinbase, ShareCredit, ShareReceipt, TxOut, TxStatus,
    work_from_le_bytes,
};

/// Node-backed observation of the fully applied chain.
///
/// Header-chain state is deliberately not used: headers may lead block validation.
pub(crate) struct NodeChainView {
    chainstate: Arc<Chainstate>,
    bodies: Arc<dyn BlockBodyStore>,
    stable: bitcoin_rs_chain::StableRead,
    mempool: MempoolReader,
    transactions: Option<Arc<dyn DerivedIndexQuery>>,
    scripts: Option<Arc<dyn ScriptIndexQuery>>,
}

impl NodeChainView {
    pub(crate) fn new(
        chainstate: Arc<Chainstate>,
        stable: bitcoin_rs_chain::StableRead,
        mempool: MempoolReader,
        transactions: Option<Arc<dyn DerivedIndexQuery>>,
        scripts: Option<Arc<dyn ScriptIndexQuery>>,
    ) -> Result<Self, ChainViewError> {
        let bodies = chainstate
            .block_body_store_handle()
            .ok_or_else(|| ChainViewError("running node has no block body store".to_owned()))?;
        Ok(Self {
            chainstate,
            bodies,
            stable,
            mempool,
            transactions,
            scripts,
        })
    }

    fn with_observation<T>(&self, observe: impl FnOnce() -> T) -> T {
        let _stable = self.stable.lock();
        observe()
    }

    fn load_block(&self, height: u32, hash: Hash256) -> Result<Block, ChainViewError> {
        let bytes = self
            .bodies
            .load_block_body(height, hash)
            .map_err(|error| ChainViewError(error.to_string()))?
            .ok_or_else(|| ChainViewError("canonical block body is unavailable".to_owned()))?;
        let block = deserialize::<Block>(&bytes)
            .map_err(|error| ChainViewError(format!("stored block body is corrupt: {error}")))?;
        if Hash256::from(block.block_hash()) != hash {
            return Err(ChainViewError(
                "stored block body has the wrong hash".to_owned(),
            ));
        }
        Ok(block)
    }
}

struct RawChainView<'a>(&'a NodeChainView);

impl core::ops::Deref for RawChainView<'_> {
    type Target = NodeChainView;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl ChainView for RawChainView<'_> {
    fn tip_height(&self) -> Result<u32, ChainViewError> {
        self.chainstate
            .applied_tip_snapshot()
            .map(|tip| tip.height)
            .ok_or_else(|| ChainViewError("applied chain tip is unavailable".to_owned()))
    }

    fn block_location(
        &self,
        block_hash: &[u8; 32],
        _claimed_height: u32,
    ) -> Result<BlockLocation, ChainViewError> {
        let hash = Hash256::from_le_bytes(block_hash);
        let Some(tip) = self.chainstate.applied_tip_snapshot() else {
            return Ok(BlockLocation::Unknown);
        };
        let tree = self.chainstate.block_tree_reader();
        let tree = tree.read();
        let Some(candidate) = tree.node_by_hash(hash) else {
            return Ok(BlockLocation::Unknown);
        };
        let canonical = tree
            .node_at_height_from(tip.tip_id, candidate.height)
            .and_then(|id| tree.node(id).ok())
            .is_some_and(|node| node.hash == hash);
        if canonical {
            Ok(BlockLocation::Canonical {
                height: candidate.height,
            })
        } else {
            Ok(BlockLocation::Side)
        }
    }

    fn coinbase_of(
        &self,
        block_hash: &[u8; 32],
    ) -> Result<Option<ObservedCoinbase>, ChainViewError> {
        let hash = Hash256::from_le_bytes(block_hash);
        let height = {
            let Some(tip) = self.chainstate.applied_tip_snapshot() else {
                return Ok(None);
            };
            let tree = self.chainstate.block_tree_reader();
            let tree = tree.read();
            let Some(node) = tree.node_by_hash(hash) else {
                return Ok(None);
            };
            let height = node.height;
            let canonical = tree
                .node_at_height_from(tip.tip_id, height)
                .and_then(|id| tree.node(id).ok())
                .is_some_and(|active| active.hash == hash);
            if !canonical {
                return Ok(None);
            }
            height
        };
        let Some(bytes) = self
            .bodies
            .load_block_body(height, hash)
            .map_err(|error| ChainViewError(error.to_string()))?
        else {
            return Ok(None);
        };
        let block = deserialize::<Block>(&bytes)
            .map_err(|error| ChainViewError(format!("stored block body is corrupt: {error}")))?;
        if Hash256::from(block.block_hash()) != hash {
            return Err(ChainViewError(
                "stored block body has the wrong hash".to_owned(),
            ));
        }
        let coinbase = block
            .txs
            .first()
            .filter(|transaction| transaction.is_coinbase())
            .ok_or_else(|| ChainViewError("stored block has no valid coinbase".to_owned()))?;
        Ok(Some(ObservedCoinbase {
            txid: Hash256::from(coinbase.txid()).to_le_bytes(),
            outputs: coinbase
                .outputs
                .iter()
                .map(|output| TxOut {
                    value_sat: output.value.to_sat(),
                    script_pubkey: output.script_pubkey.as_bytes().to_vec(),
                })
                .collect(),
        }))
    }

    fn tx_status(&self, txid: &[u8; 32]) -> Result<TxStatus, ChainViewError> {
        let txid = Txid::from(Hash256::from_le_bytes(txid));
        let Some(transactions) = self.transactions.as_ref() else {
            return if self.mempool.read().contains_txid(&txid) {
                Ok(TxStatus::InMempool)
            } else {
                Err(ChainViewError(
                    "payout transaction observation requires txindex".to_owned(),
                ))
            };
        };
        if let Some(height) = transactions
            .transaction_height(&txid)
            .map_err(|error| ChainViewError(error.to_string()))?
        {
            let Some(tip) = self.chainstate.applied_tip_snapshot() else {
                return Err(ChainViewError(
                    "applied chain tip is unavailable".to_owned(),
                ));
            };
            let tree = self.chainstate.block_tree_reader();
            let tree = tree.read();
            let block_hash = tree
                .node_at_height_from(tip.tip_id, height)
                .and_then(|id| tree.node(id).ok())
                .map(|node| node.hash)
                .ok_or_else(|| {
                    ChainViewError(
                        "transaction index height is not on the applied chain".to_owned(),
                    )
                })?;
            drop(tree);
            let block = self.load_block(height, block_hash)?;
            if !block
                .txs
                .iter()
                .any(|transaction| transaction.txid() == txid)
            {
                return Err(ChainViewError(
                    "transaction index entry is absent from the canonical block".to_owned(),
                ));
            }
            return Ok(TxStatus::Confirmed {
                block_hash: block_hash.to_le_bytes(),
                height,
            });
        }
        if self.mempool.read().contains_txid(&txid) {
            Ok(TxStatus::InMempool)
        } else {
            Ok(TxStatus::Unknown)
        }
    }

    fn confirmed_spender(
        &self,
        outpoint: &pool_ledger::OutPoint,
    ) -> Result<Option<ConfirmedSpend>, ChainViewError> {
        let node_outpoint = NodeOutPoint::new(
            Txid::from(Hash256::from_le_bytes(&outpoint.txid)),
            outpoint.vout,
        );
        let scripts = self.scripts.as_ref().ok_or_else(|| {
            ChainViewError("payout spend observation requires script index".to_owned())
        })?;
        let Some(spend) = scripts
            .spender(node_outpoint)
            .map_err(|error| ChainViewError(error.to_string()))?
        else {
            return Ok(None);
        };
        let Some(tip) = self.chainstate.applied_tip_snapshot() else {
            return Err(ChainViewError(
                "applied chain tip is unavailable".to_owned(),
            ));
        };
        let tree = self.chainstate.block_tree_reader();
        let tree = tree.read();
        let block_hash = tree
            .node_at_height_from(tip.tip_id, spend.height)
            .and_then(|id| tree.node(id).ok())
            .map(|node| node.hash)
            .ok_or_else(|| {
                ChainViewError("spend index height is not on the applied chain".to_owned())
            })?;
        drop(tree);
        let block = self.load_block(spend.height, block_hash)?;
        let spends_exact_outpoint = block.txs.iter().any(|transaction| {
            transaction.txid() == spend.txid
                && transaction
                    .inputs
                    .iter()
                    .any(|input| input.previous_output == node_outpoint)
        });
        if !spends_exact_outpoint {
            return Err(ChainViewError(
                "spend index entry is absent from the canonical block".to_owned(),
            ));
        }
        Ok(Some(ConfirmedSpend {
            spender_txid: Hash256::from(spend.txid).to_le_bytes(),
            block_hash: block_hash.to_le_bytes(),
            height: spend.height,
        }))
    }
}

const MAX_PENDING_BLOCK_RECORDS: usize = 8;
const MAX_BLOCK_RECORD_BYTES: usize = 4_000_000;
const MAX_PENDING_BLOCK_BYTES: usize = MAX_PENDING_BLOCK_RECORDS * MAX_BLOCK_RECORD_BYTES;

struct PendingBlockRecord {
    hash: bitcoin_rs_primitives::BlockHash,
    block: LedgerBlockFound,
    bytes: usize,
}

#[derive(Default)]
struct PendingBlockRecords {
    reserved: usize,
    bytes: usize,
    queue: VecDeque<PendingBlockRecord>,
}

/// Result of consuming a pre-submission durable-record reservation.
pub(crate) enum BlockRecordOutcome {
    /// The found-block round is durably visible and protocol success may be sent.
    Durable,
    /// The host retained the block for retry; the socket must not send success.
    Queued,
    /// The block cannot be represented by the ledger; close without success.
    Unrecordable,
}

/// Capacity reserved before node submission so a failed ledger write survives socket exit.
pub(crate) struct BlockRecordPermit {
    host: Arc<LedgerHost>,
    bytes: usize,
    armed: bool,
}

impl BlockRecordPermit {
    pub(crate) fn record_or_enqueue(
        mut self,
        account: MinerId,
        block: &FoundBlock,
        submission: &Result<BlockReceipt, bitcoin_rs_mining::MiningControlError>,
    ) -> BlockRecordOutcome {
        let host = Arc::clone(&self.host);
        self.armed = false;
        let recorded_directly = host
            .record_submitted_block(account, block, submission)
            .is_ok();
        if recorded_directly || matches!(host.found_block_recorded(block.share.hash), Ok(true)) {
            host.release_block_reservation(self.bytes);
            return BlockRecordOutcome::Durable;
        }
        let hash = block.share.hash;
        let Some(ledger_block) = ledger_block(host.run_epoch, account, block).ok() else {
            host.release_block_reservation(self.bytes);
            return BlockRecordOutcome::Unrecordable;
        };
        let mut pending = host
            .pending_blocks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        debug_assert!(pending.reserved <= MAX_PENDING_BLOCK_RECORDS);
        pending.queue.push_back(PendingBlockRecord {
            hash,
            block: ledger_block,
            bytes: self.bytes,
        });
        BlockRecordOutcome::Queued
    }
}

impl Drop for BlockRecordPermit {
    fn drop(&mut self) {
        if self.armed {
            self.host.release_block_reservation(self.bytes);
        }
    }
}

impl ChainView for NodeChainView {
    fn tip_height(&self) -> Result<u32, ChainViewError> {
        self.with_observation(|| RawChainView(self).tip_height())
    }

    fn block_location(
        &self,
        block_hash: &[u8; 32],
        claimed_height: u32,
    ) -> Result<BlockLocation, ChainViewError> {
        self.with_observation(|| RawChainView(self).block_location(block_hash, claimed_height))
    }

    fn coinbase_of(
        &self,
        block_hash: &[u8; 32],
    ) -> Result<Option<ObservedCoinbase>, ChainViewError> {
        self.with_observation(|| RawChainView(self).coinbase_of(block_hash))
    }

    fn tx_status(&self, txid: &[u8; 32]) -> Result<TxStatus, ChainViewError> {
        self.with_observation(|| RawChainView(self).tx_status(txid))
    }

    fn confirmed_spender(
        &self,
        outpoint: &pool_ledger::OutPoint,
    ) -> Result<Option<ConfirmedSpend>, ChainViewError> {
        self.with_observation(|| RawChainView(self).confirmed_spender(outpoint))
    }
}

/// Shared durable accounting adapter for SV1, SV2, and operator RPC.
pub(crate) struct LedgerHost {
    ledger: Arc<Ledger>,
    run_epoch: u32,
    payout_policy: pool_ledger::PayoutPolicy,
    pending_blocks: Mutex<PendingBlockRecords>,
}

impl LedgerHost {
    pub(crate) fn new(
        ledger: Arc<Ledger>,
        run_epoch: u32,
        payout_policy: pool_ledger::PayoutPolicy,
    ) -> Self {
        Self {
            ledger,
            run_epoch,
            payout_policy,
            pending_blocks: Mutex::new(PendingBlockRecords::default()),
        }
    }

    /// Reserves one fixed-capacity found-record slot before protocol feed/validation.
    ///
    /// The permit must be dropped for non-block events. Failed writes retain only the
    /// compact [`LedgerBlockFound`] projection, not block transactions or serialized bytes.
    pub(crate) fn try_reserve_block_slot(self: &Arc<Self>) -> Option<BlockRecordPermit> {
        let block_bytes = MAX_BLOCK_RECORD_BYTES;
        let mut pending = self
            .pending_blocks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if pending.reserved == MAX_PENDING_BLOCK_RECORDS
            || block_bytes > MAX_PENDING_BLOCK_BYTES.saturating_sub(pending.bytes)
        {
            return None;
        }
        pending.reserved += 1;
        pending.bytes += block_bytes;
        Some(BlockRecordPermit {
            host: Arc::clone(self),
            bytes: block_bytes,
            armed: true,
        })
    }

    fn release_block_reservation(&self, bytes: usize) {
        let mut pending = self
            .pending_blocks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        pending.reserved = pending.reserved.saturating_sub(1);
        pending.bytes = pending.bytes.saturating_sub(bytes);
    }

    pub(crate) fn pending_block_records(&self) -> usize {
        self.pending_blocks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .queue
            .len()
    }

    pub(crate) fn drain_one_block_record(&self) -> Result<bool, pool_ledger::LedgerError> {
        let pending_record = {
            let mut pending = self
                .pending_blocks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            pending.queue.pop_front()
        };
        let Some(record) = pending_record else {
            return Ok(false);
        };
        let result = match self.found_block_recorded(record.hash) {
            Ok(true) => Ok(()),
            Ok(false) => self.ledger.record_found_block(&record.block).map(|_| ()),
            Err(error) => Err(error),
        };
        let mut pending = self
            .pending_blocks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match result {
            Ok(()) => {
                pending.bytes = pending.bytes.saturating_sub(record.bytes);
                pending.reserved = pending.reserved.saturating_sub(1);
                Ok(true)
            }
            Err(error) => {
                pending.queue.push_front(record);
                Err(error)
            }
        }
    }

    /// Resolves a decimal account id only when its payout script was explicitly registered.
    pub(crate) fn account(&self, login: &str) -> Option<MinerId> {
        let (account, worker) = login
            .split_once('.')
            .map_or((login, None), |(account, worker)| (account, Some(worker)));
        if worker.is_some_and(|worker| worker.is_empty() || worker.contains('.')) {
            return None;
        }
        let miner = MinerId(account.parse().ok()?);
        self.ledger
            .payout_script(miner)
            .ok()
            .flatten()
            .map(|_| miner)
    }

    pub(crate) fn reconcile(&self, chain: &NodeChainView) -> Result<(), pool_ledger::LedgerError> {
        let queue_error = loop {
            match self.drain_one_block_record() {
                Ok(true) => {}
                Ok(false) => break None,
                Err(error) => break Some(error),
            }
        };
        chain.with_observation(|| {
            let observation = RawChainView(chain);
            self.ledger.reconcile_rounds(&observation)?;
            self.ledger.reconcile_payouts(&observation)
        })?;
        match queue_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    pub(crate) fn record_accepted_share(
        &self,
        account: MinerId,
        share: &AcceptedShare,
    ) -> Result<RecordOutcome, LedgerUnavailable> {
        let credit = share_credit(self.run_epoch, account, share)?;
        self.ledger
            .record_share(&credit)
            .map(|receipt| match receipt {
                ShareReceipt::Credited { .. } => RecordOutcome::Recorded,
                ShareReceipt::Duplicate { .. } => RecordOutcome::AlreadyRecorded,
            })
            .map_err(|_| LedgerUnavailable)
    }

    /// Records a found block after any submission result.
    ///
    /// Submission status is not accounting evidence: the round remains Pending until
    /// authoritative chain reconciliation observes the exact block hash and coinbase.
    pub(crate) fn record_submitted_block(
        &self,
        account: MinerId,
        block: &FoundBlock,
        _receipt: &Result<BlockReceipt, bitcoin_rs_mining::MiningControlError>,
    ) -> Result<(), LedgerUnavailable> {
        self.record_found_block(account, block)
    }

    pub(crate) fn found_block_recorded(
        &self,
        hash: bitcoin_rs_primitives::BlockHash,
    ) -> Result<bool, pool_ledger::LedgerError> {
        self.ledger
            .round_for_block(&Hash256::from(hash).to_le_bytes())
            .map(|round| round.is_some())
    }

    pub(crate) fn record_found_block(
        &self,
        account: MinerId,
        block: &FoundBlock,
    ) -> Result<(), LedgerUnavailable> {
        let found = ledger_block(self.run_epoch, account, block)?;
        self.ledger
            .record_found_block(&found)
            .map(|_| ())
            .map_err(|_| LedgerUnavailable)
    }
}

fn ledger_block(
    run_epoch: u32,
    account: MinerId,
    block: &FoundBlock,
) -> Result<LedgerBlockFound, LedgerUnavailable> {
    Ok(LedgerBlockFound {
        share: share_credit(run_epoch, account, &block.share)?,
        height: block.share.height,
        coinbase_txid: Hash256::from(block.coinbase_txid).to_le_bytes(),
        claimed_coinbase_value_sat: block.coinbase_value,
    })
}

fn share_credit(
    run_epoch: u32,
    account: MinerId,
    share: &AcceptedShare,
) -> Result<ShareCredit, LedgerUnavailable> {
    let work = work_from_le_bytes(share.work.to_le_bytes()).map_err(|_| LedgerUnavailable)?;
    Ok(ShareCredit {
        header_hash: Hash256::from(share.hash).to_le_bytes(),
        job: (u64::from(run_epoch) << 32) | u64::from(share.job.get()),
        account,
        extranonce: share.extranonce.clone(),
        nonce: share.header.nonce,
        work,
    })
}

/// Public mining identity routing, not a withdrawal-authentication boundary.
///
/// A login is a decimal [`MinerId`] optionally followed by `.rig`, and resolves only
/// after the account's payout script was explicitly registered through authenticated
/// management RPC. The SV1 password is intentionally ignored: miners cannot create or
/// mutate accounts, payout scripts, payout requests, or signed receipts through this
/// adapter. There is consequently no unreachable in-memory password registration API.
impl AccountResolver for LedgerHost {
    fn resolve(&self, login: &str, _password: &Password) -> Result<WorkerIdentity, AuthDenied> {
        let (account, worker) = login
            .split_once('.')
            .map_or((login, "default"), |(account, worker)| (account, worker));
        if worker.is_empty() || self.account(login).is_none() {
            return Err(AuthDenied);
        }
        Ok(WorkerIdentity {
            account: account.to_owned(),
            worker: worker.to_owned(),
        })
    }
}

impl ShareLedger for LedgerHost {
    fn record_share(
        &self,
        worker: &WorkerIdentity,
        share: &AcceptedShare,
    ) -> Result<RecordOutcome, LedgerUnavailable> {
        let account = self.account(&worker.account).ok_or(LedgerUnavailable)?;
        self.record_accepted_share(account, share)
    }

    fn record_block(
        &self,
        worker: &WorkerIdentity,
        block: &FoundBlock,
        submission: &Result<BlockReceipt, bitcoin_rs_mining::MiningControlError>,
    ) -> Result<(), LedgerUnavailable> {
        let account = self.account(&worker.account).ok_or(LedgerUnavailable)?;
        self.record_submitted_block(account, block, submission)
    }
}

impl bitcoin_rs_rpc::context::PoolOperator for LedgerHost {
    fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    fn payout_policy(&self) -> pool_ledger::PayoutPolicy {
        self.payout_policy
    }
}
