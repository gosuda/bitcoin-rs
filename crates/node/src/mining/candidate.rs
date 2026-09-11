//! Candidate construction, single-flight assembly, and bounded template caching.

use super::CANDIDATE_GENERATION_RETRIES;
use super::GENERATION_RACE;
use super::GenerationKey;
use super::InFlight;
use super::LONG_POLL_SLICE;
use super::MAX_BLOCK_SIZE;
use super::MAX_BLOCK_WEIGHT;
use super::MiningCoordinator;
use super::control::signet_info;
use super::hex_encode;
use alloc::sync::Arc;
use bitcoin_rs_mempool::Mempool;
use bitcoin_rs_mempool::MempoolMiningSnapshot;
use bitcoin_rs_mempool::SnapshotEntry;
use bitcoin_rs_mining::AvailableMiningRule;
use bitcoin_rs_mining::BlockTemplate;
use bitcoin_rs_mining::BlockValidationResult;
use bitcoin_rs_mining::Candidate;
use bitcoin_rs_mining::CandidateContext;
use bitcoin_rs_mining::GenerateRequest;
use bitcoin_rs_mining::GenerateSelection;
use bitcoin_rs_mining::GenerateTx;
use bitcoin_rs_mining::GeneratedBlock;
use bitcoin_rs_mining::LastCandidateInfo;
use bitcoin_rs_mining::MiningCapability;
use bitcoin_rs_mining::MiningChainContext;
use bitcoin_rs_mining::MiningControlError;
use bitcoin_rs_mining::MiningRule;
use bitcoin_rs_mining::TemplateMutation;
use bitcoin_rs_mining::assemble_candidate;
use bitcoin_rs_mining::assemble_ordered_candidate;
use bitcoin_rs_primitives::Network;
use bitcoin_rs_primitives::Tx;
use bitcoin_rs_primitives::consensus_bytes;
use compact_str::CompactString;
use hashbrown::HashMap;
use std::sync::atomic::Ordering;

impl MiningCoordinator {
    pub(super) fn live_candidate(&self) -> Result<Arc<Candidate>, MiningControlError> {
        let mut last_race = None;
        for attempt in 0..CANDIDATE_GENERATION_RETRIES {
            if self.shutdown.load(Ordering::Acquire) {
                return Err(MiningControlError::Unavailable(CompactString::from(
                    "node is shutting down",
                )));
            }
            let key = {
                let mut state = self.state.lock();
                self.ensure_published(&mut state)
            };
            match self.candidate_for_key(key) {
                Ok(candidate) => {
                    if self.live_generation_key() == key {
                        return Ok(candidate);
                    }
                    last_race = Some(generation_race());
                }
                Err(error) if is_generation_race(&error) => last_race = Some(error),
                Err(error) => return Err(error),
            }
            let _ = attempt;
        }
        Err(last_race.unwrap_or_else(generation_race))
    }

    pub(super) fn candidate_for_key(
        &self,
        key: GenerationKey,
    ) -> Result<Arc<Candidate>, MiningControlError> {
        let template_id = key.template_id();
        let mut state = self.state.lock();
        if let Some(cached) = state.cache_get(&template_id) {
            return Ok(cached);
        }

        loop {
            if self.shutdown.load(Ordering::Acquire) {
                return Err(MiningControlError::Unavailable(CompactString::from(
                    "node is shutting down",
                )));
            }
            let Some(flight) = state.in_flight.as_ref() else {
                break;
            };
            if flight.key != key {
                break;
            }
            if let Some(result) = flight.result.clone() {
                return result;
            }
            let _ = self.wake.wait_for(&mut state, LONG_POLL_SLICE);
        }
        if let Some(cached) = state.cache_get(&template_id) {
            return Ok(cached);
        }

        state.in_flight = Some(InFlight { key, result: None });
        drop(state);

        let assembled = self.assemble_for_key(key);
        let mut state = self.state.lock();
        let returned = match &assembled {
            Ok(candidate) => {
                let live = self.live_generation_key();
                if live == key {
                    state.cache_insert(template_id, Arc::clone(candidate));
                    state.last_candidate = Some(LastCandidateInfo {
                        weight: candidate.weight,
                        transactions: u64::try_from(candidate.transactions.len())
                            .unwrap_or(u64::MAX)
                            .saturating_add(1),
                    });
                    state.published = Some(key);
                    Ok(Arc::clone(candidate))
                } else {
                    Err(generation_race())
                }
            }
            Err(error) => Err(error.clone()),
        };
        if let Some(flight) = state.in_flight.as_mut()
            && flight.key == key
        {
            flight.result = Some(returned.clone());
        }
        self.wake.notify_all();
        if state
            .in_flight
            .as_ref()
            .is_some_and(|flight| flight.key == key && flight.result.is_some())
        {
            state.in_flight = None;
        }
        returned
    }

    pub(super) fn assemble_for_key(
        &self,
        key: GenerationKey,
    ) -> Result<Arc<Candidate>, MiningControlError> {
        let tip = self.applied_tip.load_full().ok_or_else(|| {
            MiningControlError::Unavailable(CompactString::from("applied tip is not available"))
        })?;
        if tip.hash != key.tip_hash {
            return Err(generation_race());
        }
        let snapshot = {
            let mempool = self.mempool.read();
            if mempool.sequence_number() != key.mempool_sequence {
                return Err(generation_race());
            }
            mempool.mining_snapshot()
        };
        let current_time = Self::current_time_secs().max(1);
        let chain = {
            let tree = self.block_tree.read();
            MiningChainContext::resolve(&tree, self.network, tip.tip_id, current_time).map_err(
                |error| MiningControlError::Failed(CompactString::from(error.to_string())),
            )?
        };
        let context = CandidateContext {
            previous_block_hash: chain.previous_block_hash,
            height: chain.height,
            version: chain.version,
            bits: chain.bits,
            min_time: chain.min_time,
            current_time: current_time.max(chain.min_time),
            locktime_cutoff: chain.locktime_cutoff(current_time.max(chain.min_time)),
            network: self.network,
            csv_active: chain.csv_active,
            segwit_active: chain.segwit_active,
            max_weight: MAX_BLOCK_WEIGHT,
            max_size: MAX_BLOCK_SIZE,
            max_sigops: u64::from(bitcoin_rs_consensus::MAX_BLOCK_SIGOPS_COST),
        };
        let candidate = assemble_candidate(&context, &snapshot, &self.coinbase_script)
            .map_err(|error| MiningControlError::Failed(CompactString::from(error.to_string())))?;
        if candidate.template_id != key.template_id() {
            return Err(MiningControlError::Failed(CompactString::from(
                "assembled candidate template id does not match generation key",
            )));
        }
        Ok(Arc::new(candidate))
    }

    pub(super) fn assemble_fresh(
        &self,
        payout: &[u8],
        selection: &GenerateSelection,
    ) -> Result<Candidate, MiningControlError> {
        let tip = self.applied_tip.load_full().ok_or_else(|| {
            MiningControlError::Unavailable(CompactString::from("applied tip is not available"))
        })?;
        let snapshot = {
            let mempool = self.mempool.read();
            snapshot_for_selection(&mempool, selection)?
        };
        let current_time = Self::current_time_secs().max(1);
        let chain = {
            let tree = self.block_tree.read();
            MiningChainContext::resolve(&tree, self.network, tip.tip_id, current_time).map_err(
                |error| MiningControlError::Failed(CompactString::from(error.to_string())),
            )?
        };
        let context = CandidateContext {
            previous_block_hash: chain.previous_block_hash,
            height: chain.height,
            version: chain.version,
            bits: chain.bits,
            min_time: chain.min_time,
            current_time: current_time.max(chain.min_time),
            locktime_cutoff: chain.locktime_cutoff(current_time.max(chain.min_time)),
            network: self.network,
            csv_active: chain.csv_active,
            segwit_active: chain.segwit_active,
            max_weight: MAX_BLOCK_WEIGHT,
            max_size: MAX_BLOCK_SIZE,
            max_sigops: u64::from(bitcoin_rs_consensus::MAX_BLOCK_SIGOPS_COST),
        };
        match selection {
            GenerateSelection::Mempool => assemble_candidate(&context, &snapshot, payout),
            GenerateSelection::Ordered(_) => {
                assemble_ordered_candidate(&context, &snapshot, payout)
            }
        }
        .map_err(|error| MiningControlError::Failed(CompactString::from(error.to_string())))
    }

    /// Assemble, solve, and optionally persist `request.count` blocks (`API-05`).
    ///
    /// Each submitted block is applied through `apply::apply_block` before the
    /// next iteration; that is the commit point (`ARCH-07`). Failure after *N*
    /// accepted submissions leaves those *N* blocks durable at the applied tip.
    /// `submit = false` dry-validates through `apply::validate_block` and does
    /// not persist. The result vector grows one block at a time, so `count` cannot
    /// force a large allocation up front. Callers own retry after inspecting the
    /// tip. [`MiningControlError::InvalidRequest`] is not retriable without
    /// changing the request; `Unavailable` and `Failed` may be retried.
    pub(super) fn generate_blocks(
        &self,
        request: &GenerateRequest,
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
            let candidate = self.assemble_fresh(&request.payout, &request.selection)?;
            let block = candidate.solve(request.max_tries).map_err(|error| {
                MiningControlError::Failed(CompactString::from(error.to_string()))
            })?;
            if request.submit {
                match self.submit(&block)? {
                    BlockValidationResult::Accepted => {}
                    other => {
                        return Err(MiningControlError::Failed(CompactString::from(format!(
                            "generated block was not accepted: {other:?}"
                        ))));
                    }
                }
            } else {
                let validation = self.propose(&block);
                if validation != BlockValidationResult::Accepted {
                    return Err(MiningControlError::Failed(CompactString::from(format!(
                        "generated block failed validation: {validation:?}"
                    ))));
                }
            }
            generated.push(GeneratedBlock {
                hash: block.block_hash(),
                hex: hex_encode(&consensus_bytes(&block)),
            });
        }
        Ok(generated)
    }

    pub(super) fn template_from_candidate(
        network: Network,
        candidate: Arc<Candidate>,
        submit_old: Option<bool>,
        version_bits_available: Vec<AvailableMiningRule>,
        version_bits_required: u32,
    ) -> BlockTemplate {
        let mut rules = Vec::new();
        if candidate.segwit_active {
            rules.push(MiningRule::new("segwit"));
        }
        if candidate.csv_active {
            rules.push(MiningRule::new("csv"));
        }
        if network.is_taproot_active(candidate.height) {
            rules.push(MiningRule::new("taproot"));
        }
        let signet = signet_info(network);
        if signet.is_some() {
            rules.push(MiningRule::new("signet"));
        }
        BlockTemplate {
            candidate,
            rules,
            version_bits_available,
            version_bits_required,
            capabilities: vec![
                MiningCapability::new("proposal"),
                MiningCapability::new("longpoll"),
            ],
            mutable: vec![
                TemplateMutation::Time,
                TemplateMutation::Transactions,
                TemplateMutation::PreviousBlock,
            ],
            submit_old,
            signet,
        }
    }

    pub(super) fn version_bits_for(
        &self,
        candidate: &Candidate,
    ) -> (Vec<AvailableMiningRule>, u32) {
        let Some(tip) = self.applied_tip.load_full() else {
            return (Vec::new(), 0);
        };
        if tip.hash != candidate.previous_block_hash {
            return (Vec::new(), 0);
        }
        let tree = self.block_tree.read();
        let signalling = bitcoin_rs_chain::signalling_deployments(
            &tree,
            self.network,
            tip.tip_id,
            candidate.height,
        );
        let mut required = 0_u32;
        let available = signalling
            .into_iter()
            .map(|deployment| {
                if deployment.locked_in {
                    required |= 1_u32 << u32::from(deployment.bit);
                }
                AvailableMiningRule {
                    rule: MiningRule::new(deployment.name),
                    bit: deployment.bit,
                }
            })
            .collect();
        (available, required)
    }
}

pub(super) fn snapshot_for_selection(
    mempool: &Mempool,
    selection: &GenerateSelection,
) -> Result<MempoolMiningSnapshot, MiningControlError> {
    match selection {
        GenerateSelection::Mempool => Ok(mempool.mining_snapshot()),
        GenerateSelection::Ordered(items) => {
            let full = mempool.mining_snapshot();
            let mut by_txid = HashMap::with_capacity(full.entries.len());
            for (index, entry) in full.entries.iter().enumerate() {
                let position = u32::try_from(index).unwrap_or(u32::MAX);
                by_txid.insert(entry.txid, position);
            }
            let mut selected = Vec::with_capacity(items.len());
            let mut old_to_new = HashMap::with_capacity(items.len());
            for item in items {
                match item {
                    GenerateTx::Mempool(txid) => {
                        let Some(&old) = by_txid.get(txid) else {
                            return Err(MiningControlError::InvalidRequest(CompactString::from(
                                "transaction not in mempool",
                            )));
                        };
                        let new_index = u32::try_from(selected.len()).unwrap_or(u32::MAX);
                        old_to_new.insert(old, new_index);
                        let old_usize = usize::try_from(old).unwrap_or(usize::MAX);
                        selected.push(full.entries[old_usize].clone());
                    }
                    GenerateTx::Raw(tx) => selected.push(snapshot_entry_from_raw(tx)),
                }
            }
            for entry in &mut selected {
                entry.ancestors.retain_mut(|ancestor| {
                    if let Some(&new_index) = old_to_new.get(ancestor) {
                        *ancestor = new_index;
                        true
                    } else {
                        false
                    }
                });
            }
            Ok(MempoolMiningSnapshot {
                sequence: full.sequence,
                entries: selected,
            })
        }
    }
}

pub(super) fn snapshot_entry_from_raw(tx: &Tx) -> SnapshotEntry {
    let tx = Arc::new(tx.clone());
    let vsize = u32::try_from(tx.vsize()).unwrap_or(u32::MAX);
    let size = u32::try_from(tx.total_size()).unwrap_or(u32::MAX);
    SnapshotEntry {
        txid: tx.txid(),
        wtxid: tx.wtxid(),
        vsize,
        bip141_vsize: vsize,
        size,
        weight: tx.weight(),
        sigop_cost: bitcoin_rs_script::count_tx_legacy(&tx),
        fee: 0,
        fee_delta: 0,
        time: 0,
        height: 0,
        ancestor_size: u64::from(vsize),
        ancestor_fee: 0,
        ancestor_fee_delta: 0,
        ancestors: Vec::new(),
        tx,
    }
}

pub(super) fn generation_race() -> MiningControlError {
    MiningControlError::Unavailable(CompactString::from(GENERATION_RACE))
}

pub(super) fn is_generation_race(error: &MiningControlError) -> bool {
    matches!(error, MiningControlError::Unavailable(message) if message.as_str() == GENERATION_RACE)
}
