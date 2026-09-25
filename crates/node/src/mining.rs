//! Node-owned mining control facade.
//!
//! Header admission and proposal/submission projection over the authoritative
//! chainstate. Candidate lifecycle lives in `bitcoin_rs_mining`.

use crate::chain_effects::ChainFollowers;
use alloc::sync::Arc;
use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::BlockTree;
use bitcoin_rs_chain::ChainError;
use bitcoin_rs_chain::NodeStatus;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_chain::accept_headers;
use bitcoin_rs_chain::current_unix_seconds;
use bitcoin_rs_chain::signalling_deployments;
use bitcoin_rs_chainstate::ApplyError;
use bitcoin_rs_chainstate::Chainstate;
use bitcoin_rs_chainstate::bytes_are_block;
use bitcoin_rs_mempool::Mempool;
use bitcoin_rs_mempool::MempoolMiningSnapshot;
use bitcoin_rs_mining::AppliedTipSource;
use bitcoin_rs_mining::AvailableMiningRule;
use bitcoin_rs_mining::BlockTemplateMode;
use bitcoin_rs_mining::BlockTemplateRequest;
use bitcoin_rs_mining::BlockTemplateResult;
use bitcoin_rs_mining::BlockValidationResult;
use bitcoin_rs_mining::ChainContextSource;
use bitcoin_rs_mining::GenerateRequest;
use bitcoin_rs_mining::GenerateSelection;
use bitcoin_rs_mining::GeneratedBlock;
use bitcoin_rs_mining::MempoolSequenceWake;
use bitcoin_rs_mining::MempoolSnapshotSource;
use bitcoin_rs_mining::MiningChainContext;
use bitcoin_rs_mining::MiningControl;
use bitcoin_rs_mining::MiningControlError;
pub use bitcoin_rs_mining::MiningGenerationSignal;
use bitcoin_rs_mining::MiningInfo;
use bitcoin_rs_mining::MiningRule;
use bitcoin_rs_mining::MiningService;
use bitcoin_rs_mining::header_reject_reason;
use bitcoin_rs_mining::snapshot_for_selection;
use bitcoin_rs_mining::solve_block;
use bitcoin_rs_mining::update_uncommitted_block_structures;
use bitcoin_rs_primitives::Block;
use bitcoin_rs_primitives::CompactTarget;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::Header;
use bitcoin_rs_primitives::Network;
use bitcoin_rs_primitives::consensus_bytes;
use compact_str::CompactString;
use parking_lot::RwLock;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

/// Production mining coordinator owned by the node process.
pub struct MiningCoordinator {
    chainstate: Arc<Chainstate>,
    followers: ChainFollowers,
    shutdown: Arc<AtomicBool>,
    service: MiningService,
}

impl MiningCoordinator {
    /// Builds a coordinator over the shared applied-chain and mempool handles.
    #[must_use]
    pub fn new(
        mempool: Arc<RwLock<Mempool>>,
        chainstate: Arc<Chainstate>,
        followers: ChainFollowers,
        coinbase_script: Vec<u8>,
    ) -> Self {
        let network = chainstate.network();
        let applied_tip = chainstate.applied_tip_handle();
        let block_tree = chainstate.block_tree_handle();
        let shutdown = chainstate.shutdown_handle();
        let service = MiningService::new(
            network,
            Arc::new(AppliedTipAdapter {
                tip: Arc::clone(&applied_tip),
            }),
            Arc::new(MempoolAdapter { mempool }),
            Arc::new(ChainContextAdapter {
                block_tree: Arc::clone(&block_tree),
                network,
            }),
            coinbase_script,
            Arc::clone(&shutdown),
        );
        Self {
            chainstate,
            followers,
            shutdown,
            service,
        }
    }

    /// Reduces shutdown latency after the caller sets the shared shutdown flag.
    ///
    /// Correctness does not depend on this notification: every wait is bounded
    /// and rechecks the shutdown predicate.
    pub fn notify_shutdown(&self) {
        self.service.notify_shutdown();
    }

    fn propose(&self, block: &Block) -> Result<BlockValidationResult, MiningControlError> {
        // Core GBT proposal looks the hash up before TestBlockValidity.
        if let Some(known) = self.known_block_result(block.block_hash().into()) {
            return Ok(known);
        }
        match self.chainstate.validate_block(block) {
            Ok(()) => Ok(BlockValidationResult::Accepted),
            Err(error) => map_apply_error(error),
        }
    }

    /// Core `LookupBlockIndex` / BIP22 proposal vocabulary.
    ///
    /// A node on the applied chain has had its body connected (Core
    /// `BLOCK_VALID_SCRIPTS`). `Invalid` is `BLOCK_FAILED_VALID`. Any other
    /// tree entry, including a header-only `Active` tip, is still
    /// inconclusive — `NodeStatus::Active` is the header chain, not scripts.
    fn known_block_result(&self, block_hash: Hash256) -> Option<BlockValidationResult> {
        let tree = self.chainstate.block_tree().read();
        let node_id = tree.lookup(block_hash)?;
        let node = tree.node(node_id).ok()?;
        if node.status == NodeStatus::Invalid {
            return Some(BlockValidationResult::DuplicateInvalid);
        }
        let on_applied = self
            .chainstate
            .applied_tip()
            .load_full()
            .is_some_and(|tip| tree.node_at_height_from(tip.tip_id, node.height) == Some(node_id));
        if on_applied || node.chain_tx_count.get().is_some() {
            return Some(BlockValidationResult::Duplicate);
        }
        Some(BlockValidationResult::DuplicateInconclusive)
    }

    /// Core `submitblock` fills the coinbase reserved nonce when the block
    /// already has a BIP141 commitment but no coinbase witness. Proposal skips this.
    fn fill_uncommitted_witness(&self, block: &mut Block) -> bool {
        let tree = self.chainstate.block_tree().read();
        let Some(prev_id) = tree.lookup(block.header.prev_blockhash.into()) else {
            return false;
        };
        let Ok(prev) = tree.node(prev_id) else {
            return false;
        };
        let height = prev.height.saturating_add(1);
        let segwit_active = self.chainstate.network().is_segwit_active(height);
        drop(tree);
        let witness_len = block
            .txs
            .first()
            .and_then(|tx| tx.inputs.first())
            .map(|input| input.witness.len());
        update_uncommitted_block_structures(block, segwit_active);
        witness_len
            != block
                .txs
                .first()
                .and_then(|tx| tx.inputs.first())
                .map(|input| input.witness.len())
    }

    fn submit(
        &self,
        block: &Block,
        serialized: Option<bytes::Bytes>,
    ) -> Result<BlockValidationResult, MiningControlError> {
        let block_hash: Hash256 = block.block_hash().into();
        // Duplicate classification and apply observe the same serialized chain state.
        // Reserve a generation only after ruling out an already accepted body.
        let lock = match self.chainstate.lock_transition() {
            Ok(lock) => lock,
            Err(error) => return map_apply_error(error),
        };
        // Core v31 `submitblock` dropped the index pre-check. `ProcessNewBlock`
        // returns `duplicate` only when the block was already accepted
        // (`!new_block && accepted`). A header-only tree entry must still
        // receive the body so `submitheader` then `submitblock` works.
        if matches!(
            self.known_block_result(block_hash),
            Some(BlockValidationResult::Duplicate)
        ) {
            return Ok(BlockValidationResult::Duplicate);
        }

        let mempool_change = match self.followers.begin_mempool_change() {
            Ok(change) => change,
            Err(error) => return map_apply_error(error),
        };
        let transition = lock.into_transition();
        match transition.connect(block, serialized) {
            Ok(outcome) => {
                self.followers.on_connect(block, &outcome);
                let tip = outcome.tip;
                let Some(visible) = self.chainstate.applied_tip().load_full() else {
                    self.chainstate.fail_closed_for_recovery();
                    return Err(MiningControlError::Failed(CompactString::from(
                        "applied tip missing after accepted submission",
                    )));
                };
                if visible.hash != tip.hash {
                    self.chainstate.fail_closed_for_recovery();
                    return Err(MiningControlError::Failed(CompactString::from(
                        "applied tip was not published before submit_block returned",
                    )));
                }
                if let Err(error) = crate::chain_effects::ChainFollowers::finish_transition(
                    &self.chainstate,
                    transition,
                    mempool_change,
                ) {
                    return Err(MiningControlError::Failed(CompactString::from(
                        error.to_string(),
                    )));
                }
                Ok(BlockValidationResult::Accepted)
            }
            Err(error) => {
                if bitcoin_rs_chainstate::classify_apply_error(&error)
                    == bitcoin_rs_chainstate::WindowApplyDisposition::Fatal
                {
                } else if let Err(finish_error) =
                    crate::chain_effects::ChainFollowers::finish_transition(
                        &self.chainstate,
                        transition,
                        mempool_change,
                    )
                {
                    return Err(MiningControlError::Failed(CompactString::from(
                        finish_error.to_string(),
                    )));
                }
                map_apply_error(error)
            }
        }
    }
}

/// Serves the lifecycle the applied-tip snapshot the node publishes.
struct AppliedTipAdapter {
    tip: Arc<ArcSwapOption<TipSnapshot>>,
}

impl AppliedTipSource for AppliedTipAdapter {
    fn applied_tip(&self) -> Option<TipSnapshot> {
        self.tip.load_full().map(|snapshot| (*snapshot).clone())
    }
}

/// Serves mempool reads for candidate assembly, one read lock per call.
struct MempoolAdapter {
    mempool: Arc<RwLock<Mempool>>,
}

impl MempoolSnapshotSource for MempoolAdapter {
    fn current_sequence(&self) -> u64 {
        self.mempool.read().sequence_number()
    }

    fn mining_snapshot_at(&self, expected_sequence: u64) -> Option<MempoolMiningSnapshot> {
        let mempool = self.mempool.read();
        if mempool.sequence_number() != expected_sequence {
            return None;
        }
        Some(mempool.mining_snapshot())
    }

    fn pooled_transaction_count(&self) -> u64 {
        u64::try_from(self.mempool.read().len()).unwrap_or(u64::MAX)
    }

    fn selection_snapshot(
        &self,
        selection: &GenerateSelection,
    ) -> Result<MempoolMiningSnapshot, MiningControlError> {
        let mempool = self.mempool.read();
        snapshot_for_selection(&mempool, selection)
    }

    fn min_relay_fee_sat_per_kvb(&self) -> u64 {
        self.mempool.read().min_relay_fee_sat_per_kvb()
    }
}

/// Resolves applied-tree facts for the lifecycle.
struct ChainContextAdapter {
    block_tree: Arc<RwLock<BlockTree>>,
    network: Network,
}

impl ChainContextSource for ChainContextAdapter {
    fn resolve_mining_context(
        &self,
        tip: &TipSnapshot,
        candidate_time: u32,
    ) -> Result<MiningChainContext, ChainError> {
        MiningChainContext::resolve(
            &self.block_tree.read(),
            self.network,
            tip.tip_id,
            candidate_time,
        )
    }

    fn tip_bits(&self, tip: &TipSnapshot) -> Result<CompactTarget, ChainError> {
        self.block_tree
            .read()
            .node(tip.tip_id)
            .map(|node| node.header.bits)
    }

    fn signalling_rules(&self, tip: &TipSnapshot, height: u32) -> Vec<AvailableMiningRule> {
        signalling_deployments(&self.block_tree.read(), self.network, tip.tip_id, height)
            .into_iter()
            .map(|deployment| AvailableMiningRule {
                rule: MiningRule::new(deployment.name),
                bit: deployment.bit,
            })
            .collect()
    }
}

impl MempoolSequenceWake for MiningCoordinator {
    fn publish_generation_from(&self, sequence: u64) {
        self.service.publish_generation_from(sequence);
    }
}

impl MiningControl for MiningCoordinator {
    fn get_block_template(
        &self,
        request: BlockTemplateRequest,
    ) -> Result<BlockTemplateResult, MiningControlError> {
        match request.mode {
            BlockTemplateMode::Proposal(block) => {
                Ok(BlockTemplateResult::Proposal(self.propose(&block)?))
            }
            BlockTemplateMode::Template => Ok(BlockTemplateResult::Template(
                self.service
                    .get_block_template(request.long_poll_id.as_deref())?,
            )),
        }
    }

    fn mining_info(&self) -> Result<MiningInfo, MiningControlError> {
        let tip = self.chainstate.applied_tip().load_full();
        let network_hashes_per_second = {
            let tree = self.chainstate.block_tree().read();
            tip.as_ref().map_or(0.0, |tip| {
                bitcoin_rs_mining::estimate_network_hashps(
                    &tree,
                    Some(tip.tip_id),
                    120,
                    self.chainstate.network(),
                )
            })
        };
        let warnings = Vec::new();
        self.service
            .mining_info(network_hashes_per_second, warnings, tip.as_deref())
    }

    fn network_hash_ps(&self, lookup: i64, height: i64) -> Result<f64, MiningControlError> {
        let tree = self.chainstate.block_tree().read();
        let tip = self.chainstate.applied_tip().load_full();
        bitcoin_rs_mining::network_hash_ps(
            &tree,
            tip.as_deref(),
            lookup,
            height,
            self.chainstate.network(),
        )
    }

    fn submit_block(&self, mut block: Block) -> Result<BlockValidationResult, MiningControlError> {
        self.fill_uncommitted_witness(&mut block);
        self.submit(&block, None)
    }

    fn submit_block_with_bytes(
        &self,
        mut block: Block,
        raw: Vec<u8>,
    ) -> Result<BlockValidationResult, MiningControlError> {
        if !bytes_are_block(&raw, &block) {
            return Err(MiningControlError::Rejected(CompactString::from(
                "submitted bytes are not the serialization of the submitted block",
            )));
        }
        let filled = self.fill_uncommitted_witness(&mut block);
        let serialized = if filled {
            bytes::Bytes::from(consensus_bytes(&block))
        } else {
            bytes::Bytes::from(raw)
        };
        self.submit(&block, Some(serialized))
    }

    /// Admits `header` through [`accept_headers`], the same gate inbound P2P uses.
    fn submit_header(&self, header: Header) -> Result<(), MiningControlError> {
        let _transition = self.chainstate.lock_transition().map_err(|error| {
            MiningControlError::Unavailable(CompactString::from(error.to_string()))
        })?;
        let mut tree = self.chainstate.block_tree().write();
        accept_headers(
            &mut tree,
            std::slice::from_ref(&header),
            self.chainstate.network(),
            current_unix_seconds(),
        )
        .map(|_| ())
        .map_err(header_reject_reason)
    }

    fn publish_generation(&self) {
        self.service.publish_generation();
    }

    /// Assemble, solve, and optionally persist `request.count` blocks (`API-05`).
    ///
    /// `generateblock` (`GenerateSelection::Ordered`) runs Core's
    /// `TestBlockValidity` before the nonce search (`API-30`).
    /// `generatetoaddress` (`Mempool`) does not. Each submitted block is
    /// applied and dispatched to [`ChainFollowers`] under one chain transition
    /// before the next iteration (`ARCH-07`). Failure after *N* accepted submissions
    /// leaves those *N* blocks durable at the applied tip. `submit = false`
    /// dry-validates through [`Chainstate::validate_block`] and does not persist.
    /// The result vector grows one block at a time, so `count` cannot force a
    /// large allocation up front. Callers own retry after inspecting the tip.
    /// [`MiningControlError::InvalidRequest`] is not retriable without changing
    /// the request. Operational failures require checking node state before retrying;
    /// a failed durable commit requires recovery.
    fn generate(
        &self,
        request: GenerateRequest,
    ) -> Result<Vec<GeneratedBlock>, MiningControlError> {
        if request.count == 0 {
            return Ok(Vec::new());
        }
        if !request.submit && request.count != 1 {
            return Err(MiningControlError::InvalidRequest(CompactString::from(
                "submit=false requires nblocks=1",
            )));
        }
        let mut generated = Vec::new();
        for _ in 0..request.count {
            if self.shutdown.load(Ordering::Acquire) {
                return Err(MiningControlError::Unavailable(CompactString::from(
                    "node is shutting down",
                )));
            }
            let candidate = self
                .service
                .assemble_fresh(&request.payout, &request.selection)?;
            let mut block = candidate.into_unsolved_block();
            if matches!(request.selection, GenerateSelection::Ordered(_)) {
                // CONTRACT: docs/contracts/external-api.md#API-30
                self.chainstate
                    .validate_block(&block)
                    .map_err(|error| test_block_validity_error(&error))?;
            }
            solve_block(&mut block, request.max_tries).map_err(|error| {
                MiningControlError::Failed(CompactString::from(error.to_string()))
            })?;
            if request.submit {
                match self.submit(&block, None)? {
                    BlockValidationResult::Accepted => {}
                    other => {
                        return Err(MiningControlError::Failed(CompactString::from(format!(
                            "generated block was not accepted: {other:?}"
                        ))));
                    }
                }
            } else {
                let validation = self.propose(&block)?;
                if validation != BlockValidationResult::Accepted {
                    return Err(MiningControlError::Failed(CompactString::from(format!(
                        "generated block failed validation: {validation:?}"
                    ))));
                }
            }
            generated.push(GeneratedBlock {
                hash: block.block_hash(),
                hex: bitcoin_rs_storage::checkpoint::hex_encode(&consensus_bytes(&block)),
            });
        }
        Ok(generated)
    }
}

fn map_apply_error(error: ApplyError) -> Result<BlockValidationResult, MiningControlError> {
    match error {
        ApplyError::Shutdown | ApplyError::JournalBackpressure(_) => {
            Ok(BlockValidationResult::Inconclusive)
        }
        ApplyError::ConcurrentChainChange => Err(MiningControlError::Unavailable(
            CompactString::from(error.to_string()),
        )),
        // The generation counter cannot recover in-process; only a restart
        // reserves another coordinated mutation.
        ApplyError::ChainChangeGenerationOverflow => Err(MiningControlError::Failed(
            CompactString::from(error.to_string()),
        )),
        other => bip22_reject_reason(&other).map(BlockValidationResult::Rejected),
    }
}

/// Core `JSONRPCError(RPC_VERIFY_ERROR, "TestBlockValidity failed: %s")`.
///
/// Runtime failures remain operational, without a `TestBlockValidity` prefix.
/// CONTRACT: docs/contracts/external-api.md#API-30
fn test_block_validity_error(error: &ApplyError) -> MiningControlError {
    match bip22_reject_reason(error) {
        Ok(reason) => MiningControlError::Rejected(CompactString::from(format!(
            "TestBlockValidity failed: {reason}"
        ))),
        Err(error) => error,
    }
}

/// Core `GetRejectReason` strings used by `BIP22ValidationResult`.
fn bip22_reject_reason(error: &ApplyError) -> Result<CompactString, MiningControlError> {
    let reason = match error {
        ApplyError::ProofOfWork { .. } => CompactString::from("high-hash"),
        ApplyError::PrevHashMismatch { .. } => CompactString::from("inconclusive-not-best-prevblk"),
        ApplyError::TargetAboveLimit | ApplyError::NbitsNonRetargetMismatch { .. } => {
            CompactString::from("bad-diffbits")
        }
        ApplyError::BlockOutputsExceedInputs | ApplyError::BlockValueOverflow => {
            CompactString::from("bad-cb-amount")
        }
        ApplyError::UndoPrevoutMissing { .. } => {
            CompactString::from("bad-txns-inputs-missingorspent")
        }
        ApplyError::Consensus(_)
            if bitcoin_rs_chainstate::classify_apply_error(error)
                == bitcoin_rs_chainstate::WindowApplyDisposition::Operational =>
        {
            return Err(MiningControlError::Failed(CompactString::from(
                error.to_string(),
            )));
        }
        ApplyError::Consensus(consensus) => bitcoin_rs_mining::consensus_reject_reason(consensus),
        ApplyError::Chain(
            chain @ (ChainError::MissingParent { .. }
            | ChainError::NonContinuousHeader { .. }
            | ChainError::ZeroTarget { .. }
            | ChainError::TargetExceedsLimit { .. }
            | ChainError::InvalidPow { .. }
            | ChainError::NbitsMismatch { .. }
            | ChainError::TimestampTooEarly { .. }
            | ChainError::TimestampTooFarAhead { .. }
            | ChainError::BadVersion { .. }
            | ChainError::TimewarpAttack { .. }
            | ChainError::InvalidParent { .. }),
        ) => bitcoin_rs_mining::chain_reject_reason(chain),
        ApplyError::Shutdown
        | ApplyError::JournalBackpressure(_)
        | ApplyError::ConcurrentChainChange => {
            return Err(MiningControlError::Unavailable(CompactString::from(
                error.to_string(),
            )));
        }
        ApplyError::HeightOverflow(_)
        | ApplyError::ChainChangeGenerationOverflow
        | ApplyError::Chain(
            ChainError::NodeIdOverflow { .. }
            | ChainError::UnknownNode { .. }
            | ChainError::DuplicateHeader { .. }
            | ChainError::ChainworkOverflow { .. }
            | ChainError::HeightOverflow { .. }
            | ChainError::NoCommonAncestor { .. },
        )
        | ApplyError::UtxoCommit(_)
        | ApplyError::BlockBodyPersistence(_)
        | ApplyError::UndoPersistence(_)
        | ApplyError::UndoLoad(_)
        | ApplyError::DisconnectNotTip { .. }
        | ApplyError::DisconnectBodyMismatch { .. }
        | ApplyError::DurableHeadCommit(_)
        | ApplyError::DurableHeadLineage { .. }
        | ApplyError::DisconnectOffDurableHead { .. }
        | ApplyError::DurableHeadGapUnrecoverable { .. }
        | ApplyError::RecoveryPublication(_)
        | ApplyError::CoinStatsRewind(_) => {
            return Err(MiningControlError::Failed(CompactString::from(
                error.to_string(),
            )));
        }
    };
    Ok(reason)
}

#[cfg(test)]
#[path = "../tests/unit/mining/apply_error_tests.rs"]
mod apply_error_tests;
