use crate::chain_effects::{ChainFollowers, ConnectMutationError};
use alloc::sync::Arc;
use bitcoin_rs_chain::ApplyError;
use bitcoin_rs_chain::Chainstate;
use bitcoin_rs_chain::chain::ChainError;
use bitcoin_rs_chain::chain::NodeStatus;
use bitcoin_rs_chain::chain::StableRead;
use bitcoin_rs_chain::chain::TipSnapshot;
use bitcoin_rs_chain::chain::signalling_deployments;
use bitcoin_rs_chain::chain::{BlockTreeReader, TipReader};
use bitcoin_rs_mempool::MempoolMiningSnapshot;
use bitcoin_rs_mempool::MempoolReader;
use bitcoin_rs_mempool::MutationResult;
pub mod coordinator;
pub use coordinator::*;

use bitcoin_rs_consensus::primitives::Block;
use bitcoin_rs_consensus::primitives::BlockImage;
use bitcoin_rs_consensus::primitives::CompactTarget;
use bitcoin_rs_consensus::primitives::Hash256;
use bitcoin_rs_consensus::primitives::Header;
use bitcoin_rs_consensus::primitives::Network;
use bitcoin_rs_wire::mining::AppliedTipSource;
use bitcoin_rs_wire::mining::AvailableMiningRule;
use bitcoin_rs_wire::mining::BlockTemplateMode;
use bitcoin_rs_wire::mining::BlockTemplateRequest;
use bitcoin_rs_wire::mining::BlockTemplateResult;
use bitcoin_rs_wire::mining::BlockValidationResult;
use bitcoin_rs_wire::mining::Candidate;
use bitcoin_rs_wire::mining::CandidateContext;
use bitcoin_rs_wire::mining::ChainContextSource;
use bitcoin_rs_wire::mining::CoinbaseBudget;
use bitcoin_rs_wire::mining::CoinbaseReserve;
use bitcoin_rs_wire::mining::GenerateRequest;
use bitcoin_rs_wire::mining::GenerateSelection;
use bitcoin_rs_wire::mining::GenerateTx;
use bitcoin_rs_wire::mining::GeneratedBlock;
use bitcoin_rs_wire::mining::MempoolSequenceWake;
use bitcoin_rs_wire::mining::MempoolSnapshotSource;
use bitcoin_rs_wire::mining::MiningChainContext;
use bitcoin_rs_wire::mining::MiningControl;
use bitcoin_rs_wire::mining::MiningControlError;
pub use bitcoin_rs_wire::mining::MiningGenerationSignal;
use bitcoin_rs_wire::mining::MiningInfo;
use bitcoin_rs_wire::mining::MiningRule;
use bitcoin_rs_wire::mining::PreparedTemplateBody;
use bitcoin_rs_wire::mining::SelectedBody;
use bitcoin_rs_wire::mining::header_reject_reason;
use bitcoin_rs_wire::mining::image_needs_witness_reserved_value;
use bitcoin_rs_wire::mining::select_template_body;
use bitcoin_rs_wire::mining::select_template_body_after;
use bitcoin_rs_wire::mining::solve_block_with_budget;
use bitcoin_rs_wire::mining::update_uncommitted_block_structures;
use compact_str::CompactString;

pub struct MiningCoordinator {
    chainstate: Arc<Chainstate>,
    block_tree: BlockTreeReader,
    followers: ChainFollowers,
    shutdown: bitcoin_rs_consensus::latch::LatchReader,
    service: MiningService,
}

impl MiningCoordinator {
    #[must_use]
    pub fn new(
        mempool: MempoolReader,
        chainstate: Arc<Chainstate>,
        stable: StableRead,
        followers: ChainFollowers,
        coinbase_script: Vec<u8>,
        coinbase_reserve: CoinbaseReserve,
    ) -> Self {
        let network = chainstate.network();
        let applied_tip = chainstate.applied_tip_reader();
        let block_tree = chainstate.block_tree_reader();
        let shutdown = chainstate.shutdown_reader();
        let service = MiningService::new(
            network,
            Arc::new(AppliedTipAdapter {
                tip: applied_tip,
                epoch: followers.epoch(),
            }),
            Arc::new(MempoolAdapter {
                mempool,
                chainstate: Arc::clone(&chainstate),
                stable,
            }),
            Arc::new(ChainContextAdapter {
                block_tree,
                network,
                chainstate: Arc::clone(&chainstate),
            }),
            coinbase_script,
            coinbase_reserve,
            shutdown.clone(),
        );
        let block_tree = chainstate.block_tree_reader();
        Self {
            chainstate,
            block_tree,
            followers,
            shutdown,
            service,
        }
    }

    #[cfg(feature = "test-seam")]
    #[must_use]
    pub fn parked_long_poll_waiters(&self) -> usize {
        self.service.parked_long_poll_waiters()
    }

    #[cfg(any(test, feature = "test-seam"))]
    pub fn wait_for_prepared_candidate(
        &self,
        tip_hash: Hash256,
        timeout: core::time::Duration,
    ) -> Option<Arc<Candidate>> {
        self.service.wait_for_prepared_candidate(tip_hash, timeout)
    }

    fn propose(&self, payload: &BlockImage) -> Result<BlockValidationResult, MiningControlError> {
        if let Some(known) = self.known_block_result(payload.block_hash().into()) {
            return Ok(known);
        }
        match self.chainstate.validate_block(payload) {
            Ok(()) => Ok(BlockValidationResult::Accepted),
            Err(error) => map_apply_error(error),
        }
    }

    #[expect(
        clippy::expect_used,
        reason = "tree.node cannot fail after successful tree.lookup under the same read guard"
    )]
    fn known_block_result(&self, block_hash: Hash256) -> Option<BlockValidationResult> {
        let tree = self.block_tree.read();
        let node_id = tree.lookup(block_hash)?;
        let node = tree
            .node(node_id)
            .expect("node exists for looked-up id under block_tree read guard");
        if node.status == NodeStatus::Invalid {
            return Some(BlockValidationResult::DuplicateInvalid);
        }
        let on_applied = self
            .chainstate
            .applied_tip_snapshot()
            .is_some_and(|tip| tree.node_at_height_from(tip.tip_id, node.height) == Some(node_id));
        if on_applied || node.chain_tx_count.get().is_some() {
            return Some(BlockValidationResult::Duplicate);
        }
        Some(BlockValidationResult::DuplicateInconclusive)
    }

    fn fill_uncommitted_witness(&self, block: &mut Block) -> bool {
        let tree = self.block_tree.read();
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
        payload: &BlockImage,
        generation: Option<coordinator::GenerationKey>,
    ) -> Result<BlockValidationResult, MiningControlError> {
        let block_hash: Hash256 = payload.block_hash().into();
        let lock = match self.chainstate.lock_transition() {
            Ok(lock) => lock,
            Err(error) => return map_apply_error(error),
        };
        if generation.is_none()
            && matches!(
                self.known_block_result(block_hash),
                Some(BlockValidationResult::Duplicate)
            )
        {
            return Ok(BlockValidationResult::Duplicate);
        }

        let mempool_change = match self.followers.begin_mempool_change() {
            Ok(change) => change,
            Err(error) => return map_apply_error(error),
        };
        let transition = lock.into_transition();
        if generation.is_some_and(|key| self.service.live_generation_key() != key) {
            if let Err(error) =
                ChainFollowers::finish_transition(&self.chainstate, transition, mempool_change)
            {
                return map_apply_error(error);
            }
            return Err(coordinator::generation_race());
        }
        match self.followers.apply_connect_in_transition(
            &self.chainstate,
            transition,
            mempool_change,
            payload,
        ) {
            Ok(_) => Ok(BlockValidationResult::Accepted),
            Err(ConnectMutationError::CommittedButSettlementFailed { outcome, source }) => {
                tracing::error!(
                    committed = %outcome.hash,
                    %source,
                    "submitblock committed but node settlement failed; retry is forbidden"
                );
                Ok(BlockValidationResult::Accepted)
            }
            Err(ConnectMutationError::CommittedButMempoolSettlementRefused { outcome, source }) => {
                tracing::error!(
                    committed = %outcome.hash,
                    %source,
                    "submitblock committed but mempool settlement was refused; retry is forbidden"
                );
                Ok(BlockValidationResult::Accepted)
            }
            Err(ConnectMutationError::NotCommitted(error)) => map_apply_error(error),
        }
    }
}

struct AppliedTipAdapter {
    tip: TipReader,
    epoch: crate::chain_effects::EpochCell,
}

impl AppliedTipSource for AppliedTipAdapter {
    fn applied_tip(&self) -> Option<TipSnapshot> {
        self.tip.load_full().map(|snapshot| (*snapshot).clone())
    }

    fn applied_epoch(&self) -> Option<bitcoin_rs_chain::chain::AppliedEpoch> {
        self.epoch.current().or_else(|| {
            self.applied_tip()
                .map(|tip| bitcoin_rs_chain::chain::AppliedEpoch::new(tip, 0))
        })
    }
}

struct MempoolAdapter {
    mempool: MempoolReader,
    chainstate: Arc<Chainstate>,
    stable: StableRead,
}

impl MempoolSnapshotSource for MempoolAdapter {
    fn current_revisions(&self) -> (u64, u64) {
        let mempool = self.mempool.read();
        (
            mempool.sequence_number(),
            mempool.fee_delta_sequence_number(),
        )
    }

    fn settled_generation(&self) -> (u64, u64, u64) {
        let mempool = self.mempool.read();
        (
            mempool.settled_at_commit(),
            mempool.sequence_number(),
            mempool.fee_delta_sequence_number(),
        )
    }

    fn select_template(
        &self,
        expected_sequences: Option<(u64, u64)>,
        context: &CandidateContext,
        payout: &[u8],
        budget: Option<CoinbaseBudget>,
    ) -> Result<Option<SelectedBody>, MiningControlError> {
        let pool = self.mempool.read();
        if expected_sequences.is_some_and(|(sequence, fee_delta_sequence)| {
            pool.sequence_number() != sequence
                || pool.fee_delta_sequence_number() != fee_delta_sequence
        }) {
            return Ok(None);
        }
        select_template_body(&pool, context, payout, budget)
            .map(Some)
            .map_err(|error| MiningControlError::Failed(CompactString::from(error.to_string())))
    }

    fn select_template_after(
        &self,
        block: &bitcoin_rs_consensus::primitives::BlockImage,
        context: &CandidateContext,
        payout: &[u8],
    ) -> Result<PreparedTemplateBody, MiningControlError> {
        let pool = self.mempool.read();
        let source_sequences = (pool.sequence_number(), pool.fee_delta_sequence_number());
        let facts = bitcoin_rs_mempool::TransitionFacts::from_block(block);
        let plan = pool.plan_block_removals(&facts);
        let body = select_template_body_after(&pool, &plan, context, payout)
            .map_err(|error| MiningControlError::Failed(CompactString::from(error.to_string())))?;
        let removals = plan
            .removals
            .iter()
            .filter_map(|(id, reason)| pool.entry(*id).map(|entry| (entry.txid, *reason)))
            .collect();
        Ok(PreparedTemplateBody {
            body,
            source_sequences,
            removals,
        })
    }

    fn pooled_transaction_count(&self) -> u64 {
        u64::try_from(self.mempool.read().len()).unwrap_or(u64::MAX)
    }

    fn selection_snapshot(
        &self,
        selection: &GenerateSelection,
        context: &CandidateContext,
    ) -> Result<Arc<MempoolMiningSnapshot>, MiningControlError> {
        if !matches!(selection, GenerateSelection::Ordered(items) if items.iter().any(|item| matches!(item, GenerateTx::Raw(_))))
        {
            return snapshot_for_selection(
                self.mempool.read().mining_snapshot(),
                selection,
                &[],
                context.segwit_active,
            );
        }
        let (snapshot, prevouts) = {
            let _guard = self.stable.lock();
            if self
                .chainstate
                .applied_tip_snapshot()
                .is_none_or(|tip| tip.hash != context.previous_block_hash)
            {
                return Err(MiningControlError::Unavailable(CompactString::from(
                    "applied tip changed during generate selection",
                )));
            }
            let snapshot = self.mempool.read().mining_snapshot();
            let mut prevouts = hashbrown::HashMap::new();
            if let GenerateSelection::Ordered(items) = selection {
                for item in items {
                    if let GenerateTx::Raw(tx) = item {
                        for input in &tx.inputs {
                            let outpoint = input.previous_output;
                            if let hashbrown::hash_map::Entry::Vacant(slot) =
                                prevouts.entry(outpoint)
                                && let Some(coin) =
                                    self.chainstate.utxo_reader().get_entry(&outpoint).map_err(
                                        |error| {
                                            MiningControlError::Failed(CompactString::from(
                                                error.to_string(),
                                            ))
                                        },
                                    )?
                            {
                                slot.insert(coin.txout);
                            }
                        }
                    }
                }
            }
            (snapshot, prevouts.into_iter().collect::<Vec<_>>())
        };
        snapshot_for_selection(snapshot, selection, &prevouts, context.segwit_active)
    }

    fn min_relay_fee_sat_per_kvb(&self) -> u64 {
        self.mempool.read().min_relay_fee_sat_per_kvb()
    }
}

struct ChainContextAdapter {
    block_tree: BlockTreeReader,
    network: Network,
    chainstate: Arc<Chainstate>,
}

impl ChainContextSource for ChainContextAdapter {
    fn validate_candidate(&self, candidate: &Candidate) -> Result<(), MiningControlError> {
        let block = candidate
            .into_unsolved_block()
            .map_err(|error| MiningControlError::Failed(CompactString::from(error.to_string())))?;
        self.chainstate
            .validate_block(&BlockImage::from_local(block))
            .map_err(|error| test_block_validity_error(&error))
    }

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

    fn stage_tip(&self, tip: &TipSnapshot, block: &BlockImage) {
        self.service.stage_tip(tip, block);
    }

    fn publish_block_generation(&self, tip_hash: Hash256, removals: &MutationResult) {
        self.service.publish_block_generation(tip_hash, removals);
    }
}

impl MiningControl for MiningCoordinator {
    fn get_block_template(
        &self,
        request: BlockTemplateRequest,
    ) -> Result<BlockTemplateResult, MiningControlError> {
        match request.mode {
            BlockTemplateMode::Proposal(block) => {
                let payload = BlockImage::from_local(block);
                Ok(BlockTemplateResult::Proposal(self.propose(&payload)?))
            }
            BlockTemplateMode::Template => Ok(BlockTemplateResult::Template(
                self.service
                    .get_block_template(request.long_poll_id.as_deref(), request.coinbase_budget)?,
            )),
        }
    }

    fn mining_info(&self) -> Result<MiningInfo, MiningControlError> {
        let tip = self.chainstate.applied_tip_snapshot();
        let network_hashes_per_second = {
            let tree = self.block_tree.read();
            tip.as_ref().map_or(0.0, |tip| {
                bitcoin_rs_wire::mining::estimate_network_hashps(
                    &tree,
                    tip.tip_id,
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
        let tree = self.block_tree.read();
        let tip = self.chainstate.applied_tip_snapshot();
        bitcoin_rs_wire::mining::network_hash_ps(
            &tree,
            tip.as_deref(),
            lookup,
            height,
            self.chainstate.network(),
        )
    }

    #[expect(
        clippy::expect_used,
        reason = "tree.node cannot fail after successful tree.lookup under the same read guard"
    )]
    fn submit_block(
        &self,
        payload: BlockImage,
    ) -> Result<BlockValidationResult, MiningControlError> {
        let segwit_active = {
            let tree = self.block_tree.read();
            tree.lookup(payload.header().prev_blockhash.into())
                .map(|prev_id| {
                    tree.node(prev_id)
                        .expect("node exists for looked-up id under block_tree read guard")
                })
                .map(|prev| {
                    self.chainstate
                        .network()
                        .is_segwit_active(prev.height.saturating_add(1))
                })
        };
        if image_needs_witness_reserved_value(&payload, segwit_active == Some(true)) {
            let mut trial = payload.materialize();
            if self.fill_uncommitted_witness(&mut trial) {
                let filled = BlockImage::from_local(trial);
                return self.submit(&filled, None);
            }
        }
        self.submit(&payload, None)
    }

    fn submit_header(&self, header: Header) -> Result<(), MiningControlError> {
        {
            let tree = self.block_tree.read();
            let hash = header.compute_hash().into();
            let is_genesis_root =
                tree.is_empty() && hash == self.chainstate.network().genesis_block_hash();
            if !is_genesis_root
                && tree.lookup(hash).is_none()
                && tree.lookup(header.prev_blockhash.into()).is_none()
            {
                return Err(header_reject_reason(ChainError::MissingParent {
                    prev_hash: header.prev_blockhash.into(),
                }));
            }
        }
        match self.chainstate.admit_headers(std::slice::from_ref(&header)) {
            Ok(_) => Ok(()),
            Err(bitcoin_rs_chain::HeaderAdmissionError::Rejected(error)) => {
                Err(header_reject_reason(error))
            }
            Err(bitcoin_rs_chain::HeaderAdmissionError::Refused(error)) => Err(
                MiningControlError::Unavailable(CompactString::from(error.to_string())),
            ),
        }
    }

    fn publish_generation(&self) {
        self.service.publish_generation();
    }

    fn publish_fee_delta_generation(&self, fee_delta_sequence: u64) {
        self.service
            .publish_fee_delta_generation(fee_delta_sequence);
    }

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
        'blocks: for _ in 0..request.count {
            let mut remaining = request.max_tries;
            for _ in 0..coordinator::CANDIDATE_GENERATION_RETRIES {
                if self.shutdown.is_triggered() {
                    return Err(MiningControlError::Unavailable(CompactString::from(
                        "node is shutting down",
                    )));
                }
                let generation = matches!(request.selection, GenerateSelection::Mempool)
                    .then(|| self.service.live_generation_key());
                let assembled = match generation {
                    Some(generation) => self
                        .service
                        .assemble_fresh_for_generation(generation, &request.payout),
                    None => self
                        .service
                        .assemble_fresh(&request.payout, &request.selection),
                };
                if generation.is_some_and(|key| self.service.live_generation_key() != key) {
                    continue;
                }
                let candidate = match assembled {
                    Err(error) if generation.is_some() && error.is_template_generation_race() => {
                        continue;
                    }
                    result => result?,
                };
                let mut block = candidate.into_unsolved_block().map_err(|error| {
                    MiningControlError::Failed(CompactString::from(error.to_string()))
                })?;
                if matches!(request.selection, GenerateSelection::Ordered(_)) {
                    let payload = BlockImage::from_local(block);
                    self.chainstate
                        .validate_block(&payload)
                        .map_err(|error| test_block_validity_error(&error))?;
                    block = payload.into_block();
                }
                if generation.is_some_and(|key| self.service.live_generation_key() != key) {
                    continue;
                }
                let solved = solve_block_with_budget(&mut block, &mut remaining);
                if generation.is_some_and(|key| self.service.live_generation_key() != key) {
                    continue;
                }
                solved.map_err(|error| {
                    let error = match error {
                        bitcoin_rs_wire::mining::MiningError::Unsolved { .. } => {
                            bitcoin_rs_wire::mining::MiningError::Unsolved {
                                tries: request.max_tries - remaining,
                            }
                        }
                        other => other,
                    };
                    MiningControlError::Failed(CompactString::from(error.to_string()))
                })?;
                let hash = block.block_hash();
                let payload = BlockImage::from_local(block);
                let hex = bitcoin_rs_consensus::primitives::hex::hex_encode(payload.bytes());
                if generation.is_some_and(|key| self.service.live_generation_key() != key) {
                    continue;
                }
                if request.submit {
                    match self.submit(&payload, generation) {
                        Ok(BlockValidationResult::Accepted) => {}
                        Err(error)
                            if generation.is_some() && error.is_template_generation_race() =>
                        {
                            continue;
                        }
                        result => {
                            let other = result?;
                            return Err(MiningControlError::Failed(CompactString::from(format!(
                                "generated block was not accepted: {other:?}"
                            ))));
                        }
                    }
                } else {
                    let validation = self.propose(&payload);
                    if generation.is_some_and(|key| self.service.live_generation_key() != key) {
                        continue;
                    }
                    let validation = validation?;
                    if validation != BlockValidationResult::Accepted {
                        return Err(MiningControlError::Failed(CompactString::from(format!(
                            "generated block failed validation: {validation:?}"
                        ))));
                    }
                }
                generated.push(GeneratedBlock { hash, hex });
                continue 'blocks;
            }
            return Err(coordinator::generation_race());
        }
        Ok(generated)
    }
}

fn map_apply_error(error: ApplyError) -> Result<BlockValidationResult, MiningControlError> {
    match error {
        ApplyError::Shutdown => Ok(BlockValidationResult::Inconclusive),
        ApplyError::ConcurrentChainChange => Err(MiningControlError::Unavailable(
            CompactString::from(error.to_string()),
        )),
        ApplyError::ChainChangeGenerationOverflow => Err(MiningControlError::Failed(
            CompactString::from(error.to_string()),
        )),
        other => bip22_reject_reason(&other).map(BlockValidationResult::Rejected),
    }
}

fn test_block_validity_error(error: &ApplyError) -> MiningControlError {
    match bip22_reject_reason(error) {
        Ok(reason) => MiningControlError::Rejected(CompactString::from(format!(
            "TestBlockValidity failed: {reason}"
        ))),
        Err(error) => error,
    }
}

fn bip22_reject_reason(error: &ApplyError) -> Result<CompactString, MiningControlError> {
    let reason = match error {
        ApplyError::ProofOfWork { .. } => CompactString::from("high-hash"),
        ApplyError::PrevHashMismatch { .. } => {
            CompactString::from(bitcoin_rs_wire::mining::STALE_PARENT_REASON)
        }
        ApplyError::BlockOutputsExceedInputs | ApplyError::BlockValueOverflow => {
            CompactString::from("bad-cb-amount")
        }
        ApplyError::UndoPrevoutMissing { .. } => {
            CompactString::from("bad-txns-inputs-missingorspent")
        }
        ApplyError::Consensus(_)
            if bitcoin_rs_chain::classify_apply_error(error)
                == bitcoin_rs_chain::WindowApplyDisposition::Operational =>
        {
            return Err(MiningControlError::Failed(CompactString::from(
                error.to_string(),
            )));
        }
        ApplyError::Consensus(consensus) => {
            bitcoin_rs_wire::mining::consensus_reject_reason(consensus)
        }
        ApplyError::Chain(
            chain @ (ChainError::MissingParent { .. }
            | ChainError::InvalidParent { .. }
            | ChainError::KnownInvalidHeader { .. }
            | ChainError::NonContinuousHeader { .. }
            | ChainError::ZeroTarget { .. }
            | ChainError::TargetExceedsLimit { .. }
            | ChainError::TargetBitsOverflow { .. }
            | ChainError::InvalidPow { .. }
            | ChainError::NbitsMismatch { .. }
            | ChainError::TimestampTooEarly { .. }
            | ChainError::TimestampTooFarAhead { .. }
            | ChainError::BadVersion { .. }
            | ChainError::TimewarpAttack { .. }),
        ) => bitcoin_rs_wire::mining::chain_reject_reason(chain),
        ApplyError::Shutdown
        | ApplyError::ConcurrentChainChange
        | ApplyError::StagedBudgetExhausted => {
            return Err(MiningControlError::Unavailable(CompactString::from(
                error.to_string(),
            )));
        }
        ApplyError::HeightOverflow(_)
        | ApplyError::VoutOverflow { .. }
        | ApplyError::TxidCountMismatch { .. }
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
        | ApplyError::WindowWorkspaceIncomplete { .. }
        | ApplyError::RecoveryPublication(_)
        | ApplyError::RecoveryCoinStats(_)
        | ApplyError::CoinStoreRead(_)
        | ApplyError::CoinStatsRewind(_)
        | ApplyError::DisconnectBelowSnapshotBase { .. }
        | ApplyError::PruneDuringHistoricalValidation { .. }
        | ApplyError::ConnectPastHistoricalTarget { .. }
        | ApplyError::HistoricalTargetHashMismatch { .. } => {
            return Err(MiningControlError::Failed(CompactString::from(
                error.to_string(),
            )));
        }
    };
    Ok(reason)
}

#[cfg(test)]
mod tests {
    use super::{map_apply_error, test_block_validity_error};
    use bitcoin_rs_chain::ApplyError;
    use bitcoin_rs_chain::chain::ChainError;
    use bitcoin_rs_chain::chain::NodeId;
    use bitcoin_rs_consensus::ConsensusError;
    use bitcoin_rs_consensus::header_rules::ChainWork;
    use bitcoin_rs_consensus::primitives::Hash256;
    use bitcoin_rs_consensus::primitives::Txid;
    use bitcoin_rs_wire::mining::BlockValidationResult;
    use bitcoin_rs_wire::mining::MiningControlError;
    use compact_str::CompactString;

    // API-30, MPS-03, SYNC-05
    #[test]
    fn fresh_submission_rechecks_generation_under_transition_and_reopens_admission()
    -> Result<(), crate::test_support::TestError> {
        use bitcoin_rs_consensus::primitives::{BlockImage, Network};
        use bitcoin_rs_wire::mining::{
            CoinbaseReserve, GenerateRequest, GenerateSelection, MiningControl, solve_block,
        };

        let directory = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(Network::Regtest);
        config.data_dir = directory.path().join("node");
        config.p2p.listen.clear();
        let state = crate::state::NodeState::open(config, None)?;
        state.apply_block(&BlockImage::from_local(Network::Regtest.genesis_block()))?;
        let mining = super::MiningCoordinator::new(
            state.mempool_reader(),
            state.chainstate(),
            state.stable_read(),
            state.chain_followers(),
            vec![0x51],
            CoinbaseReserve::default(),
        );
        let generation = mining.service.live_generation_key();
        let mut stale = mining
            .service
            .assemble_fresh_for_generation(generation, &[0x51])?
            .into_unsolved_block()?;
        solve_block(&mut stale, GenerateRequest::DEFAULT_MAX_TRIES)?;
        let stale = BlockImage::from_local(stale);
        let request = || GenerateRequest {
            payout: vec![0x52],
            count: 1,
            max_tries: GenerateRequest::DEFAULT_MAX_TRIES,
            selection: GenerateSelection::Mempool,
            submit: true,
        };
        mining.generate(request())?;
        let committed = state.chainstate().applied_tip_snapshot();
        let before_gate = state
            .mempool_gateway()
            .stable_generation()
            .ok_or(crate::test_support::TestError::Missing("open admission"))?;
        assert!(matches!(
            mining.submit(&stale, Some(generation)),
            Err(error) if error.is_template_generation_race()
        ));
        assert_eq!(
            state
                .chainstate()
                .applied_tip_snapshot()
                .map(|tip| tip.hash),
            committed.map(|tip| tip.hash)
        );
        assert_eq!(
            state.mempool_gateway().stable_generation(),
            Some(before_gate + 2)
        );
        assert_eq!(mining.generate(request())?.len(), 1);
        assert_eq!(
            state
                .chainstate()
                .applied_tip_snapshot()
                .map(|tip| tip.height),
            Some(2)
        );
        Ok(())
    }

    // API-11, API-30, SYNC-05
    #[test]
    fn fresh_submission_observes_fee_changes_while_waiting_for_admission()
    -> Result<(), crate::test_support::TestError> {
        use bitcoin_rs_consensus::primitives::{BlockImage, Network};
        use bitcoin_rs_wire::mining::{CoinbaseReserve, GenerateRequest, solve_block};
        use std::{sync::mpsc, time::Duration};

        let directory = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(Network::Regtest);
        config.data_dir = directory.path().join("node");
        config.p2p.listen.clear();
        let state = crate::state::NodeState::open(config, None)?;
        state.apply_block(&BlockImage::from_local(Network::Regtest.genesis_block()))?;
        let mining = super::MiningCoordinator::new(
            state.mempool_reader(),
            state.chainstate(),
            state.stable_read(),
            state.chain_followers(),
            vec![0x51],
            CoinbaseReserve::default(),
        );
        let generation = mining.service.live_generation_key();
        let mut candidate = mining
            .service
            .assemble_fresh_for_generation(generation, &[0x51])?
            .into_unsolved_block()?;
        solve_block(&mut candidate, GenerateRequest::DEFAULT_MAX_TRIES)?;
        let payload = BlockImage::from_local(candidate);
        let gateway = state.mempool_gateway();
        let before_gate = gateway
            .stable_generation()
            .ok_or(crate::test_support::TestError::Missing("open admission"))?;
        let before_tip = state
            .chainstate()
            .applied_tip_snapshot()
            .map(|tip| tip.hash);
        let result = std::thread::scope(|scope| {
            let mut pool = gateway.pool().write();
            let (entered_tx, entered_rx) = mpsc::channel();
            let (locked_tx, locked_rx) = mpsc::channel();
            let (resume_tx, resume_rx) = mpsc::channel();
            gateway.install_begin_chain_change_probes(
                entered_tx,
                locked_tx,
                resume_rx,
                Box::new(|| true),
            );
            let submitted = scope.spawn(|| mining.submit(&payload, Some(generation)));
            entered_rx.recv_timeout(Duration::from_secs(10))?;
            assert_eq!(gateway.stable_generation(), Some(before_gate));
            pool.prioritise(Txid::from(Hash256::from_le_bytes(&[92; 32])), 900)?;
            drop(pool);
            assert!(locked_rx.recv_timeout(Duration::from_secs(10))?);
            resume_tx.send(()).map_err(|_| {
                crate::test_support::TestError::ChannelSend("resume chain admission")
            })?;
            submitted.join().map_err(|_| {
                crate::test_support::TestError::ExpectationFailed("submission thread panicked")
            })
        })?;
        assert!(matches!(result, Err(error) if error.is_template_generation_race()));
        assert_eq!(
            state
                .chainstate()
                .applied_tip_snapshot()
                .map(|tip| tip.hash),
            before_tip
        );
        assert_eq!(gateway.stable_generation(), Some(before_gate + 2));
        let fresh = mining.service.live_generation_key();
        assert_ne!(fresh, generation);
        assert!(
            mining
                .service
                .assemble_fresh_for_generation(fresh, &[0x51])
                .is_ok()
        );
        Ok(())
    }

    // API-11, API-30, MPS-03, SYNC-05
    #[test]
    fn fresh_submission_commits_after_fee_changes_past_generation_check()
    -> Result<(), crate::test_support::TestError> {
        use bitcoin_rs_consensus::primitives::{BlockImage, Network};
        use bitcoin_rs_wire::mining::{CoinbaseReserve, GenerateRequest, solve_block};
        use std::{
            sync::{Arc, mpsc},
            time::Duration,
        };

        let directory = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(Network::Regtest);
        config.data_dir = directory.path().join("node");
        config.p2p.listen.clear();
        let state = crate::state::NodeState::open(config, None)?;
        state.apply_block(&BlockImage::from_local(Network::Regtest.genesis_block()))?;
        let chain = state.chainstate();
        let gateway = state.mempool_gateway();
        let durable = state.durable_head();
        let mining = super::MiningCoordinator::new(
            state.mempool_reader(),
            Arc::clone(&chain),
            state.stable_read(),
            state.chain_followers(),
            vec![0x51],
            CoinbaseReserve::default(),
        );
        let generation = mining.service.live_generation_key();
        let mut candidate = mining
            .service
            .assemble_fresh_for_generation(generation, &[0x51])?
            .into_unsolved_block()?;
        solve_block(&mut candidate, GenerateRequest::DEFAULT_MAX_TRIES)?;
        let payload = BlockImage::from_local(candidate);
        let expected_hash = Hash256::from(payload.block_hash());
        let before_head = durable
            .load()?
            .ok_or(crate::test_support::TestError::Missing("committed genesis"))?;
        let before_hash = before_head.tip;
        let before_pool = gateway.read().settled_generation();
        let before_gate = gateway
            .stable_generation()
            .ok_or(crate::test_support::TestError::Missing("open admission"))?;
        let prioritised = Txid::from(Hash256::from_le_bytes(&[93; 32]));
        let hook_gateway = Arc::clone(&gateway);
        let hook_durable = Arc::clone(&durable);
        let applied = chain.applied_tip_reader();
        let (edited_tx, edited_rx) = mpsc::channel();
        chain
            .set_pow_valid_block(Arc::new(move |_block, hash, height| {
                assert_eq!((hash, height), (expected_hash, 1));
                assert_eq!(hook_gateway.stable_generation(), None);
                assert_eq!(applied.load_full().map(|tip| tip.hash), Some(before_hash));
                let head = hook_durable.load();
                let edit = hook_gateway.prioritise(prioritised, 900);
                let changed_pool = hook_gateway.read().settled_generation();
                assert!(edited_tx.send((head, edit, changed_pool)).is_ok());
            }))
            .map_err(|_| {
                crate::test_support::TestError::ExpectationFailed("pow-valid hook installs once")
            })?;

        assert_eq!(
            mining.submit(&payload, Some(generation))?,
            BlockValidationResult::Accepted
        );
        let (hook_head, edit, changed_pool) = edited_rx.recv_timeout(Duration::from_secs(10))?;
        edit?;
        assert_eq!(
            hook_head?.map(|head| (head.tip, head.commit_id)),
            Some((before_head.tip, before_head.commit_id))
        );
        assert_eq!(
            changed_pool,
            (before_pool.0, before_pool.1, before_pool.2 + 1)
        );
        let committed = durable
            .load()?
            .ok_or(crate::test_support::TestError::Missing(
                "committed generated block",
            ))?;
        assert_eq!(
            (committed.tip, committed.height, committed.commit_id),
            (expected_hash, 1, before_head.commit_id + 1)
        );
        assert_eq!(
            chain
                .applied_tip_snapshot()
                .map(|tip| (tip.hash, tip.height)),
            Some((expected_hash, 1))
        );
        let settled = gateway.read().settled_generation();
        assert_eq!(settled.0, committed.commit_id);
        assert_eq!(settled.2, changed_pool.2);
        assert!(matches!(
            gateway.prioritised_transactions().as_slice(),
            [entry] if entry.txid == prioritised && entry.fee_delta == 900
        ));
        assert_eq!(gateway.stable_generation(), Some(before_gate + 2));
        assert!(!chain.is_closed_for_recovery());
        Ok(())
    }

    // API-11, API-30, SYNC-05
    #[test]
    fn templates_reject_missing_inputs_without_mutating_chainstate()
    -> Result<(), crate::test_support::TestError> {
        use bitcoin_rs_consensus::primitives::{
            Amount, BlockImage, LockTime, Network, OutPoint, Sequence, Tx, TxIn, TxOut, Witness,
        };
        use bitcoin_rs_mempool::MempoolEntry;
        use bitcoin_rs_wire::mining::{
            BlockTemplateMode, BlockTemplateRequest, CoinbaseBudget, CoinbaseReserve,
            GenerateRequest, GenerateSelection, MiningControl,
        };
        use std::sync::Arc;

        let directory = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(Network::Regtest);
        config.data_dir = directory.path().join("node");
        config.p2p.listen.clear();
        let state = crate::state::NodeState::open(config, None)?;
        let _ = state.apply_block(&BlockImage::from_local(Network::Regtest.genesis_block()))?;
        let mining = super::MiningCoordinator::new(
            state.mempool_reader(),
            state.chainstate(),
            state.stable_read(),
            state.chain_followers(),
            vec![0x51],
            CoinbaseReserve::default(),
        );
        let request = |coinbase_budget| BlockTemplateRequest {
            mode: BlockTemplateMode::Template,
            capabilities: Vec::new(),
            rules: Vec::new(),
            long_poll_id: None,
            coinbase_budget,
        };
        mining.generate(GenerateRequest {
            payout: vec![0x51],
            count: 1,
            max_tries: GenerateRequest::DEFAULT_MAX_TRIES,
            selection: GenerateSelection::Ordered(Vec::new()),
            submit: true,
        })?;
        assert_eq!(
            state
                .chainstate()
                .utxo_reader()
                .with_stable_view(|view| view.len())?,
            1
        );
        mining.get_block_template(request(None))?;
        let missing = Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid::from(Hash256::from_le_bytes(&[1; 32])), 0),
                script_sig: Vec::new().into(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: vec![0x51].into(),
            }],
            lock_time: LockTime::ZERO,
        };
        let txid = missing.txid();
        let vsize = u32::try_from(missing.vsize())?;
        state.mempool().write().insert_entry(MempoolEntry::new(
            Arc::new(missing),
            vsize,
            10_000,
            0,
            0,
            0,
        ))?;
        state.mempool().write().prioritise(txid, 200)?;
        mining.publish_generation();
        let capture_state = || -> Result<_, crate::test_support::TestError> {
            let chain = state.chainstate();
            let tip = chain
                .applied_tip_snapshot()
                .map(|tip| (tip.hash, tip.height, tip.chainwork, tip.chain_tx_count));
            let coins = chain.utxo_reader().with_stable_view(|view| {
                let mut coins = std::collections::HashMap::new();
                view.for_each_all(|outpoint, bytes| {
                    coins.insert(*outpoint, bytes.to_vec());
                });
                coins
            })?;
            let coin_stats = chain.coin_stats_handle().snapshot();
            let pool_handle = state.mempool();
            let pool = pool_handle.read();
            let entries = pool
                .iter_entries()
                .map(|entry| {
                    (
                        entry.txid,
                        (
                            Arc::clone(&entry.tx),
                            entry.wtxid,
                            (entry.vsize, entry.bip141_vsize, entry.size, entry.weight),
                            (entry.fee, entry.fee_rate, entry.fee_delta),
                            (
                                entry.ancestor_size,
                                entry.ancestor_fee,
                                entry.ancestor_fee_delta,
                            ),
                            (
                                entry.descendant_size,
                                entry.descendant_fee,
                                entry.descendant_fee_delta,
                            ),
                            (entry.time, entry.height, entry.sigop_cost),
                            (
                                entry.unbroadcast,
                                entry.broadcast_pending,
                                entry.broadcast_done,
                                entry.broadcast_marks,
                            ),
                        ),
                    )
                })
                .collect::<std::collections::BTreeMap<_, _>>();
            let priorities = pool.prioritised_transactions();
            Ok((
                tip,
                coins,
                coin_stats,
                entries,
                priorities,
                pool.stats(),
                pool.sequence_number(),
                pool.fee_delta_sequence_number(),
                pool.settled_at_commit(),
            ))
        };
        for budget in [
            None,
            Some(CoinbaseBudget {
                additional_size: 1_000,
                additional_sigops: 100,
            }),
        ] {
            let before = capture_state()?;
            assert!(matches!(
                mining.get_block_template(request(budget)),
                Err(MiningControlError::Rejected(reason))
                    if reason == "TestBlockValidity failed: bad-txns-inputs-missingorspent"
            ));
            assert_eq!(capture_state()?, before);
        }
        let before = capture_state()?;
        assert!(matches!(
            mining.generate(GenerateRequest {
                payout: vec![0x51],
                count: 1,
                max_tries: 0,
                selection: GenerateSelection::Mempool,
                submit: false,
            }),
            Err(MiningControlError::Rejected(reason))
                if reason == "TestBlockValidity failed: bad-txns-inputs-missingorspent"
        ));
        assert_eq!(capture_state()?, before);
        state.mempool().write().clear();
        mining.publish_generation();
        mining.get_block_template(request(None))?;
        Ok(())
    }

    #[test]
    fn operational_failures_are_not_block_rejections() {
        fn failures() -> Vec<ApplyError> {
            use bitcoin_rs_storage::StorageError;
            vec![
                ApplyError::PruneDuringHistoricalValidation { base_height: 110 },
                ApplyError::DisconnectBelowSnapshotBase {
                    height: 110,
                    base_height: 110,
                },
                ApplyError::ConnectPastHistoricalTarget {
                    height: 111,
                    base_height: 110,
                },
                ApplyError::HistoricalTargetHashMismatch {
                    base_height: 110,
                    expected: Hash256::default(),
                    found: Hash256::from_le_bytes(&[1; 32]),
                },
                ApplyError::UtxoCommit(bitcoin_rs_storage::utxo::UtxoError::CorruptRecord),
                ApplyError::BlockBodyPersistence(StorageError::InvalidOperation(
                    "body write failed",
                )),
                ApplyError::UndoPersistence(StorageError::InvalidOperation("undo write failed")),
                ApplyError::DurableHeadCommit(StorageError::InvalidOperation("head write failed")),
                ApplyError::DurableHeadLineage {
                    head: Hash256::default(),
                    prev: Hash256::from_le_bytes(&[1; 32]),
                },
                ApplyError::WindowWorkspaceIncomplete {
                    staged: 2,
                    covered: 1,
                },
                ApplyError::RecoveryCoinStats(Box::new(
                    bitcoin_rs_chain::recovery::RecoveryError::Storage(
                        StorageError::InvalidOperation("recovery coin statistics read failed"),
                    ),
                )),
                ApplyError::CoinStoreRead(StorageError::InvalidOperation("coin read failed")),
                ApplyError::Consensus(ConsensusError::Kernel("verifier unavailable".to_owned())),
                ApplyError::Consensus(ConsensusError::PrevoutMatrixSize {
                    expected: 1,
                    actual: 0,
                }),
            ]
        }

        for error in failures() {
            let result = map_apply_error(error);
            assert!(
                matches!(result, Err(MiningControlError::Failed(_))),
                "operational failure became a block verdict: {result:?}"
            );
        }
        for error in failures() {
            let result = test_block_validity_error(&error);
            assert!(
                matches!(result, MiningControlError::Failed(_)),
                "generateblock hid an operational error: {result:?}"
            );
        }
    }

    fn rejected(error: ApplyError) -> CompactString {
        match map_apply_error(error) {
            Ok(BlockValidationResult::Rejected(reason)) => reason,
            other => panic!("expected rejected, got {other:?}"),
        }
    }

    // API-30
    #[test]
    fn generateblock_validity_wraps_bip22_reason() {
        let error = test_block_validity_error(&ApplyError::UndoPrevoutMissing {
            txid: Txid::from(Hash256::from_le_bytes(&[0x11; 32])),
            vout: 0,
        });
        match error {
            MiningControlError::Rejected(reason) => {
                assert_eq!(
                    reason.as_str(),
                    "TestBlockValidity failed: bad-txns-inputs-missingorspent"
                );
            }
            other => panic!("expected rejected, got {other:?}"),
        }
    }

    #[test]
    fn generateblock_validity_keeps_shutdown_operational() {
        assert!(matches!(
            test_block_validity_error(&ApplyError::Shutdown),
            MiningControlError::Unavailable(_)
        ));
    }

    #[test]
    fn apply_errors_delegate_consensus_and_chain_reasons() {
        assert_eq!(
            rejected(ApplyError::Consensus(ConsensusError::MissingCoinbase)),
            "bad-cb-missing"
        );
        assert_eq!(
            rejected(ApplyError::Consensus(ConsensusError::SixtyFourByteMutation)),
            "bad-cb-missing"
        );
        assert_eq!(
            rejected(ApplyError::Chain(ChainError::InvalidPow {
                hash: Hash256::default(),
                target: ChainWork::ZERO,
            })),
            "high-hash"
        );
        assert_eq!(
            rejected(ApplyError::Chain(ChainError::TargetBitsOverflow {
                bits: 0x2300_0001,
            })),
            "high-hash"
        );
        assert_eq!(
            rejected(ApplyError::Chain(ChainError::KnownInvalidHeader {
                hash: Hash256::default(),
            })),
            "duplicate-invalid"
        );
        assert_eq!(
            rejected(ApplyError::Chain(ChainError::BadVersion {
                version: 1,
                required: 2,
                height: 500,
            })),
            "bad-version(0x00000001)"
        );
        assert_eq!(
            rejected(ApplyError::Chain(ChainError::TimewarpAttack {
                height: 2016,
                timestamp: 1,
                minimum: 601,
            })),
            "time-timewarp-attack"
        );
        assert_eq!(
            rejected(ApplyError::Chain(ChainError::InvalidParent {
                parent: NodeId::new(3),
            })),
            "bad-prevblk"
        );
    }

    #[test]
    fn generation_overflow_is_terminal_unavailability_is_transient() {
        assert!(
            matches!(
                map_apply_error(ApplyError::ChainChangeGenerationOverflow),
                Err(MiningControlError::Failed(_))
            ),
            "a generation overflow requires restart, not a retry hint"
        );
        assert!(matches!(
            test_block_validity_error(&ApplyError::ChainChangeGenerationOverflow),
            MiningControlError::Failed(_)
        ));
        assert!(
            matches!(
                map_apply_error(ApplyError::ConcurrentChainChange),
                Err(MiningControlError::Unavailable(_))
            ),
            "an in-flight chain change is a transient refusal"
        );
    }
}
