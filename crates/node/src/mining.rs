use crate::chain_effects::{ChainFollowers, ConnectMutationError};
use alloc::sync::Arc;
use bitcoin_rs_chain::ChainError;
use bitcoin_rs_chain::NodeStatus;
use bitcoin_rs_chain::StableRead;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_chain::signalling_deployments;
use bitcoin_rs_chain::{BlockTreeReader, TipReader};
use bitcoin_rs_chainstate::ApplyError;
use bitcoin_rs_chainstate::Chainstate;
use bitcoin_rs_mempool::MempoolMiningSnapshot;
use bitcoin_rs_mempool::MempoolReader;
use bitcoin_rs_mempool::MutationResult;
use bitcoin_rs_mining::AppliedTipSource;
use bitcoin_rs_mining::AvailableMiningRule;
use bitcoin_rs_mining::BlockTemplateMode;
use bitcoin_rs_mining::BlockTemplateRequest;
use bitcoin_rs_mining::BlockTemplateResult;
use bitcoin_rs_mining::BlockValidationResult;
#[cfg(any(test, feature = "test-seam"))]
use bitcoin_rs_mining::Candidate;
use bitcoin_rs_mining::CandidateContext;
use bitcoin_rs_mining::ChainContextSource;
use bitcoin_rs_mining::CoinbaseBudget;
use bitcoin_rs_mining::GenerateRequest;
use bitcoin_rs_mining::GenerateSelection;
use bitcoin_rs_mining::GenerateTx;
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
use bitcoin_rs_mining::PreparedTemplateBody;
use bitcoin_rs_mining::SelectedBody;
use bitcoin_rs_mining::header_reject_reason;
use bitcoin_rs_mining::needs_witness_reserved_value;
use bitcoin_rs_mining::select_template_body;
use bitcoin_rs_mining::select_template_body_after;
use bitcoin_rs_mining::snapshot_for_selection;
use bitcoin_rs_mining::solve_block;
use bitcoin_rs_mining::update_uncommitted_block_structures;
use bitcoin_rs_primitives::Block;
use bitcoin_rs_primitives::BlockPayload;
use bitcoin_rs_primitives::CompactTarget;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::Header;
use bitcoin_rs_primitives::Network;
use compact_str::CompactString;

pub struct MiningCoordinator {
    chainstate: Arc<Chainstate>,
    block_tree: BlockTreeReader,
    followers: ChainFollowers,
    shutdown: bitcoin_rs_chain::LatchReader,
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
    ) -> Self {
        let network = chainstate.network();
        let applied_tip = chainstate.applied_tip_reader();
        let block_tree = chainstate.block_tree_reader();
        let shutdown = chainstate.shutdown_reader();
        let service = MiningService::new(
            network,
            Arc::new(AppliedTipAdapter { tip: applied_tip }),
            Arc::new(MempoolAdapter {
                mempool,
                chainstate: Arc::clone(&chainstate),
                stable,
            }),
            Arc::new(ChainContextAdapter {
                block_tree,
                network,
            }),
            coinbase_script,
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

    fn propose(&self, payload: &BlockPayload) -> Result<BlockValidationResult, MiningControlError> {
        if let Some(known) = self.known_block_result(payload.block().block_hash().into()) {
            return Ok(known);
        }
        match self.chainstate.validate_block(payload) {
            Ok(()) => Ok(BlockValidationResult::Accepted),
            Err(error) => map_apply_error(error),
        }
    }

    fn known_block_result(&self, block_hash: Hash256) -> Option<BlockValidationResult> {
        let tree = self.block_tree.read();
        let node_id = tree.lookup(block_hash)?;
        let node = tree.node(node_id).ok()?;
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

    fn submit(&self, payload: &BlockPayload) -> Result<BlockValidationResult, MiningControlError> {
        let block_hash: Hash256 = payload.block().block_hash().into();
        let lock = match self.chainstate.lock_transition() {
            Ok(lock) => lock,
            Err(error) => return map_apply_error(error),
        };
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
            Err(ConnectMutationError::NotCommitted(error)) => map_apply_error(error),
        }
    }
}

struct AppliedTipAdapter {
    tip: TipReader,
}

impl AppliedTipSource for AppliedTipAdapter {
    fn applied_tip(&self) -> Option<TipSnapshot> {
        self.tip.load_full().map(|snapshot| (*snapshot).clone())
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
        block: &Block,
        context: &CandidateContext,
        payout: &[u8],
    ) -> Result<PreparedTemplateBody, MiningControlError> {
        let pool = self.mempool.read();
        let source_sequences = (pool.sequence_number(), pool.fee_delta_sequence_number());
        let plan = pool.plan_block_removals(block);
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
    ) -> Result<MempoolMiningSnapshot, MiningControlError> {
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
                                && let Some(output) = self
                                    .chainstate
                                    .utxo_reader()
                                    .get_entry(&outpoint)
                                    .map(|coin| coin.txout)
                            {
                                slot.insert(output);
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

    fn stage_tip(&self, tip: &TipSnapshot, block: &Block) {
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
                let payload = BlockPayload::from_local(block);
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
                bitcoin_rs_mining::estimate_network_hashps(
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
        bitcoin_rs_mining::network_hash_ps(
            &tree,
            tip.as_deref(),
            lookup,
            height,
            self.chainstate.network(),
        )
    }

    fn submit_block(
        &self,
        payload: BlockPayload,
    ) -> Result<BlockValidationResult, MiningControlError> {
        let segwit_active = {
            let tree = self.block_tree.read();
            tree.lookup(payload.block().header.prev_blockhash.into())
                .and_then(|prev_id| tree.node(prev_id).ok())
                .map(|prev| {
                    self.chainstate
                        .network()
                        .is_segwit_active(prev.height.saturating_add(1))
                })
        };
        if segwit_active.is_some_and(|active| needs_witness_reserved_value(payload.block(), active))
        {
            let mut trial = payload.block().clone();
            if self.fill_uncommitted_witness(&mut trial) {
                let filled = BlockPayload::from_local(trial);
                return self.submit(&filled);
            }
        }
        self.submit(&payload)
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
            Err(bitcoin_rs_chainstate::HeaderAdmissionError::Rejected(error)) => {
                Err(header_reject_reason(error))
            }
            Err(bitcoin_rs_chainstate::HeaderAdmissionError::Refused(error)) => Err(
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
        for _ in 0..request.count {
            if self.shutdown.is_triggered() {
                return Err(MiningControlError::Unavailable(CompactString::from(
                    "node is shutting down",
                )));
            }
            let candidate = self
                .service
                .assemble_fresh(&request.payout, &request.selection)?;
            let mut block = candidate.into_unsolved_block().map_err(|error| {
                MiningControlError::Failed(CompactString::from(error.to_string()))
            })?;
            if matches!(request.selection, GenerateSelection::Ordered(_)) {
                let payload = BlockPayload::from_local(block);
                self.chainstate
                    .validate_block(&payload)
                    .map_err(|error| test_block_validity_error(&error))?;
                block = payload.into_block();
            }
            solve_block(&mut block, request.max_tries).map_err(|error| {
                MiningControlError::Failed(CompactString::from(error.to_string()))
            })?;
            let hash = block.block_hash();
            if request.submit {
                let payload = BlockPayload::from_local(block);
                let hex = bitcoin_rs_primitives::encode::hex_encode(payload.bytes());
                match self.submit(&payload)? {
                    BlockValidationResult::Accepted => {}
                    other => {
                        return Err(MiningControlError::Failed(CompactString::from(format!(
                            "generated block was not accepted: {other:?}"
                        ))));
                    }
                }
                generated.push(GeneratedBlock { hash, hex });
            } else {
                let payload = BlockPayload::from_local(block);
                let validation = self.propose(&payload)?;
                if validation != BlockValidationResult::Accepted {
                    return Err(MiningControlError::Failed(CompactString::from(format!(
                        "generated block failed validation: {validation:?}"
                    ))));
                }
                let hex = bitcoin_rs_primitives::encode::hex_encode(payload.bytes());
                generated.push(GeneratedBlock { hash, hex });
            }
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
            CompactString::from(bitcoin_rs_mining::STALE_PARENT_REASON)
        }
        ApplyError::TargetAboveLimit => CompactString::from("bad-diffbits"),
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
            | ChainError::InvalidParent { .. }
            | ChainError::KnownInvalidHeader { .. }
            | ChainError::NonContinuousHeader { .. }
            | ChainError::ZeroTarget { .. }
            | ChainError::TargetExceedsLimit { .. }
            | ChainError::InvalidPow { .. }
            | ChainError::NbitsMismatch { .. }
            | ChainError::TimestampTooEarly { .. }
            | ChainError::TimestampTooFarAhead { .. }
            | ChainError::BadVersion { .. }
            | ChainError::TimewarpAttack { .. }),
        ) => bitcoin_rs_mining::chain_reject_reason(chain),
        ApplyError::Shutdown
        | ApplyError::JournalBackpressure(_)
        | ApplyError::ConcurrentChainChange => {
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
        | ApplyError::RecoveryPublication(_)
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
mod tests;
