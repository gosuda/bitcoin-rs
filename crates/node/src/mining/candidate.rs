//! Candidate construction, single-flight assembly, and bounded template caching.

use super::CANDIDATE_GENERATION_RETRIES;
use super::GenerationKey;
use super::InFlight;
use super::LONG_POLL_SLICE;
use super::MAX_BLOCK_SIZE;
use super::MAX_BLOCK_WEIGHT;
use super::MiningCoordinator;
use super::generation_race;
use super::hex_encode;
use super::is_generation_race;
use super::snapshot_for_selection;
use super::submission::test_block_validity_error;
use alloc::sync::Arc;
use bitcoin_rs_mining::AvailableMiningRule;
use bitcoin_rs_mining::BlockValidationResult;
use bitcoin_rs_mining::Candidate;
use bitcoin_rs_mining::CandidateContext;
use bitcoin_rs_mining::GenerateRequest;
use bitcoin_rs_mining::GenerateSelection;
use bitcoin_rs_mining::GeneratedBlock;
use bitcoin_rs_mining::LastCandidateInfo;
use bitcoin_rs_mining::MiningChainContext;
use bitcoin_rs_mining::MiningControlError;
use bitcoin_rs_mining::MiningRule;
use bitcoin_rs_mining::assemble_candidate;
use bitcoin_rs_mining::assemble_ordered_candidate;
use bitcoin_rs_mining::solve_block;
use bitcoin_rs_primitives::Block;
use bitcoin_rs_primitives::consensus_bytes;
use compact_str::CompactString;
use std::sync::atomic::Ordering;

/// Clears an abandoned single-flight slot if candidate assembly unwinds.
///
/// Release/quickstart builds abort on panic, but test, development, and other
/// unwind-enabled profiles must not leave same-key callers blocked behind a
/// permanently in-flight generation.
struct InFlightAssemblyGuard<'a> {
    coordinator: &'a MiningCoordinator,
    key: GenerationKey,
    id: u64,
    armed: bool,
}

impl Drop for InFlightAssemblyGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut state = self.coordinator.state.lock();
        if state
            .in_flight
            .as_ref()
            .is_some_and(|flight| flight.key == self.key && flight.id == self.id)
        {
            state.in_flight = None;
            drop(state);
            self.coordinator.wake.notify_all();
        }
    }
}

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

        state.next_flight_id = state.next_flight_id.wrapping_add(1);
        let flight_id = state.next_flight_id;
        state.in_flight = Some(InFlight {
            key,
            id: flight_id,
            result: None,
        });
        drop(state);
        let mut flight_guard = InFlightAssemblyGuard {
            coordinator: self,
            key,
            id: flight_id,
            armed: true,
        };

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
            && flight.id == flight_id
        {
            flight.result = Some(returned.clone());
        }
        self.wake.notify_all();
        if state.in_flight.as_ref().is_some_and(|flight| {
            flight.key == key && flight.id == flight_id && flight.result.is_some()
        }) {
            state.in_flight = None;
        }
        flight_guard.armed = false;
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
    /// `generateblock` (`GenerateSelection::Ordered`) runs Core's
    /// `TestBlockValidity` before the nonce search (`API-30`).
    /// `generatetoaddress` (`Mempool`) does not. Each submitted block is
    /// applied through `apply::apply_block` before the next iteration; that
    /// is the commit point (`ARCH-07`). Failure after *N* accepted submissions
    /// leaves those *N* blocks durable at the applied tip. `submit = false`
    /// dry-validates through `apply::validate_block` and does not persist.
    /// The result vector grows one block at a time, so `count` cannot force a
    /// large allocation up front. Callers own retry after inspecting the tip.
    /// [`MiningControlError::InvalidRequest`] is not retriable without changing
    /// the request; `Unavailable` and `Failed` may be retried.
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
            let mut block = candidate.into_unsolved_block();
            if matches!(request.selection, GenerateSelection::Ordered(_)) {
                // CONTRACT: docs/contracts/external-api.md#API-30
                self.test_generateblock_validity(&block)?;
            }
            solve_block(&mut block, request.max_tries).map_err(|error| {
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

    /// Core `generateblock` `TestBlockValidity` before `GenerateBlock`.
    ///
    /// `ApplyIntent::Propose` already skips hash-meets-target. This path does
    /// not use [`Self::propose`], which owns GBT `LookupBlockIndex` duplicate
    /// vocabulary (`API-18`).
    /// CONTRACT: docs/contracts/external-api.md#API-30
    fn test_generateblock_validity(&self, block: &Block) -> Result<(), MiningControlError> {
        match self.apply_handles.validate_block(block) {
            Ok(()) => Ok(()),
            Err(error) => Err(test_block_validity_error(error)),
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
        let available = signalling
            .into_iter()
            .map(|deployment| AvailableMiningRule {
                rule: MiningRule::new(deployment.name),
                bit: deployment.bit,
            })
            .collect();
        // Core v31 `getblocktemplate` hardcodes `vbrequired` to 0.
        (available, 0)
    }
}
