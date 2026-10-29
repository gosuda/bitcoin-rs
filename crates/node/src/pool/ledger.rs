use std::collections::VecDeque;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU8, Ordering},
};

use bitcoin_rs_chainstate::Chainstate;
use bitcoin_rs_index::{DerivedIndexQuery, ScriptIndexQuery};
use bitcoin_rs_mempool::MempoolReader;
use bitcoin_rs_mining::pool::ledger as pool_ledger;
use bitcoin_rs_mining::pool::ledger::{
    BlockFound as LedgerBlockFound, BlockLocation, ChainView, ChainViewError, ConfirmedSpend,
    Ledger, MinerId, ObservedCoinbase, ShareCredit, ShareReceipt, TxOut, TxStatus,
    work_from_le_bytes,
};
use bitcoin_rs_mining::pool::stratum::sv1::{AccountResolver, AuthDenied, Password};
use bitcoin_rs_mining::pool::{
    AcceptedShare, BlockReceipt, BlockStatus, FoundBlock, LedgerUnavailable, RecordOutcome,
    ShareLedger, WorkerIdentity,
};
use bitcoin_rs_primitives::encode::deserialize;
use bitcoin_rs_primitives::{Block, Hash256, OutPoint as NodeOutPoint, Txid};
use bitcoin_rs_storage::block_body::BlockBodyStore;

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

    fn tip_generation(&self) -> Option<Arc<bitcoin_rs_chain::TipSnapshot>> {
        self.chainstate.applied_tip_snapshot()
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

const RECOVERY_QUEUED_ALIVE: u8 = 0;
const RECOVERY_QUEUED_GONE: u8 = 1;
const RECOVERY_WAITER_OWNS: u8 = 2;
const RECOVERY_RELEASED: u8 = 3;

#[derive(Clone)]
struct PendingBlockRecord {
    hash: bitcoin_rs_primitives::BlockHash,
    block: LedgerBlockFound,
    bytes: usize,
    recovery: Option<Arc<AtomicU8>>,
    token: Arc<()>,
}

#[derive(Default)]
struct PendingBlockRecords {
    reserved: usize,
    bytes: usize,
    queue: VecDeque<PendingBlockRecord>,
}

pub(crate) struct QueuedRecoveryHold {
    host: Arc<LedgerHost>,
    state: Arc<AtomicU8>,
}

impl Drop for QueuedRecoveryHold {
    fn drop(&mut self) {
        if self
            .state
            .compare_exchange(
                RECOVERY_QUEUED_ALIVE,
                RECOVERY_QUEUED_GONE,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok()
        {
            return;
        }
        if self
            .state
            .compare_exchange(
                RECOVERY_WAITER_OWNS,
                RECOVERY_RELEASED,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok()
        {
            let mut pending = self
                .host
                .pending_blocks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            pending.reserved = pending.reserved.saturating_sub(1);
            pending.bytes = pending.bytes.saturating_sub(MAX_BLOCK_RECORD_BYTES);
        }
    }
}

pub(crate) enum DeferredCharge {
    Permit(BlockRecordPermit),
    Queued(QueuedRecoveryHold),
}

pub(crate) enum BlockRecordOutcome {
    Durable,
    Queued,
    Unrecordable,
}

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
    ) -> (BlockRecordOutcome, Option<DeferredCharge>) {
        let host = Arc::clone(&self.host);
        self.armed = false;
        let bytes = self.bytes;
        let undetermined =
            matches!(submission, Ok(receipt) if receipt.status() == BlockStatus::Undetermined);
        let queued_defers = matches!(
            submission,
            Ok(receipt) if matches!(
                receipt.status(),
                BlockStatus::Applied | BlockStatus::Undetermined
            )
        );
        let recorded_directly = host
            .record_submitted_block(account, block, submission)
            .is_ok();
        if recorded_directly || matches!(host.found_block_recorded(block.share.hash), Ok(true)) {
            if undetermined {
                let permit = BlockRecordPermit {
                    host,
                    bytes,
                    armed: true,
                };
                return (
                    BlockRecordOutcome::Durable,
                    Some(DeferredCharge::Permit(permit)),
                );
            }
            host.release_block_reservation(bytes);
            return (BlockRecordOutcome::Durable, None);
        }
        let hash = block.share.hash;
        let Some(ledger_block) = ledger_block(host.run_epoch, account, block).ok() else {
            host.release_block_reservation(bytes);
            return (BlockRecordOutcome::Unrecordable, None);
        };
        if queued_defers {
            let state = Arc::new(AtomicU8::new(RECOVERY_QUEUED_ALIVE));
            {
                let mut pending = host
                    .pending_blocks
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                debug_assert!(pending.reserved <= MAX_PENDING_BLOCK_RECORDS);
                pending.queue.push_back(PendingBlockRecord {
                    hash,
                    block: ledger_block,
                    bytes,
                    recovery: Some(Arc::clone(&state)),
                    token: Arc::new(()),
                });
            }
            let hold = QueuedRecoveryHold { host, state };
            return (
                BlockRecordOutcome::Queued,
                Some(DeferredCharge::Queued(hold)),
            );
        }
        {
            let mut pending = host
                .pending_blocks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            debug_assert!(pending.reserved <= MAX_PENDING_BLOCK_RECORDS);
            pending.queue.push_back(PendingBlockRecord {
                hash,
                block: ledger_block,
                bytes,
                recovery: None,
                token: Arc::new(()),
            });
        }
        (BlockRecordOutcome::Queued, None)
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

fn tip_unchanged(
    before: &Option<Arc<bitcoin_rs_chain::TipSnapshot>>,
    after: &Option<Arc<bitcoin_rs_chain::TipSnapshot>>,
) -> bool {
    match (before, after) {
        (None, None) => true,
        (Some(first), Some(second)) => Arc::ptr_eq(first, second),
        (None, Some(_)) | (Some(_), None) => false,
    }
}

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
        let peeked = {
            let pending = self
                .pending_blocks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            pending.queue.front().cloned()
        };
        let Some(record) = peeked else {
            return Ok(false);
        };
        let result = match self.found_block_recorded(record.hash) {
            Ok(true) => Ok(()),
            Ok(false) => self.ledger.record_found_block(&record.block).map(|_| ()),
            Err(error) => Err(error),
        };
        if result.is_err() {
            return result.map(|()| true);
        }
        let mut pending = self
            .pending_blocks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let front_matches = pending.queue.front().is_some_and(|front| {
            front.hash == record.hash && Arc::ptr_eq(&front.token, &record.token)
        });
        if !front_matches {
            return Ok(true);
        }
        if let Some(state) = record.recovery.as_ref() {
            if state
                .compare_exchange(
                    RECOVERY_QUEUED_ALIVE,
                    RECOVERY_WAITER_OWNS,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                )
                .is_ok()
            {
                pending.queue.pop_front();
                return Ok(true);
            }
            if state
                .compare_exchange(
                    RECOVERY_QUEUED_GONE,
                    RECOVERY_RELEASED,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                )
                .is_ok()
            {
                let popped = pending.queue.pop_front();
                debug_assert!(popped.is_some_and(|entry| entry.hash == record.hash));
                pending.bytes = pending.bytes.saturating_sub(record.bytes);
                pending.reserved = pending.reserved.saturating_sub(1);
                return Ok(true);
            }
            return Err(pool_ledger::LedgerError::Invariant(
                "block recovery state already decided".into(),
            ));
        }
        let popped = pending.queue.pop_front();
        debug_assert!(popped.is_some_and(|entry| entry.hash == record.hash));
        pending.bytes = pending.bytes.saturating_sub(record.bytes);
        pending.reserved = pending.reserved.saturating_sub(1);
        Ok(true)
    }

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
        let mut round_after: Option<u64> = None;
        let mut payout_after: Option<u64> = None;
        let mut attempts = 0;
        let reconcile_result = loop {
            let before = chain.tip_generation();
            let observation = RawChainView(chain);
            let aborted = || !tip_unchanged(&before, &chain.tip_generation());
            let result: Result<(bool, bool, Option<u64>, Option<u64>), pool_ledger::LedgerError> =
                (|| {
                    let (_, round_more, round_next) = self.ledger.reconcile_rounds_checked_limit(
                        &observation,
                        &aborted,
                        pool_ledger::RECONCILE_ROUND_BATCH_LIMIT,
                        round_after,
                    )?;
                    let (_, payout_more, payout_next) =
                        self.ledger.reconcile_payouts_checked_limit(
                            &observation,
                            &aborted,
                            pool_ledger::RECONCILE_PAYOUT_BATCH_LIMIT,
                            payout_after,
                        )?;
                    Ok((round_more, payout_more, round_next, payout_next))
                })();
            let after = chain.tip_generation();
            match result {
                Ok((false, false, _, _)) if tip_unchanged(&before, &after) => break Ok(()),
                Ok((round_more, payout_more, round_next, payout_next))
                    if tip_unchanged(&before, &after) =>
                {
                    round_after = round_next;
                    payout_after = payout_next;
                    if !round_more && !payout_more {
                        break Ok(());
                    }
                }
                Ok(_) => {
                    attempts += 1;
                    if attempts >= 2 {
                        break Ok(());
                    }
                }
                Err(error) => {
                    attempts += 1;
                    if attempts >= 2 || tip_unchanged(&before, &after) {
                        break Err(error);
                    }
                }
            }
        };
        reconcile_result?;
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
        match self.ledger.record_share(&credit) {
            Ok(receipt) => Ok(match receipt {
                ShareReceipt::Credited { .. } => RecordOutcome::Recorded,
                ShareReceipt::Duplicate { .. } => RecordOutcome::AlreadyRecorded,
            }),
            Err(error) if error.is_permanent_share_conflict() => Ok(RecordOutcome::Rejected),
            Err(_) => Err(LedgerUnavailable),
        }
    }

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
        version: share.header.version,
        ntime: share.header.time,
        work,
    })
}

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
        let credit = share_credit(self.run_epoch, account, share)?;
        match self.ledger.record_share(&credit) {
            Ok(receipt) => Ok(match receipt {
                ShareReceipt::Credited { .. } => RecordOutcome::Recorded,
                ShareReceipt::Duplicate { .. } => RecordOutcome::AlreadyRecorded,
            }),
            Err(error) if error.is_permanent_share_conflict() => Ok(RecordOutcome::Rejected),
            Err(_) => Err(LedgerUnavailable),
        }
    }

    fn record_block(
        &self,
        worker: &WorkerIdentity,
        block: &FoundBlock,
        _submission: &Result<BlockReceipt, bitcoin_rs_mining::MiningControlError>,
    ) -> Result<(), LedgerUnavailable> {
        let account = self.account(&worker.account).ok_or(LedgerUnavailable)?;
        let found = ledger_block(self.run_epoch, account, block)?;
        match self.ledger.record_found_block(&found) {
            Ok(_) => Ok(()),
            Err(error) if error.is_permanent_share_conflict() => Ok(()),
            Err(_) => Err(LedgerUnavailable),
        }
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
