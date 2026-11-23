use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Weak};

use arc_swap::ArcSwapOption;
use bitcoin_rs_consensus::header_rules::ChainWork;
use bitcoin_rs_consensus::primitives::{Hash256, Header};
use parking_lot::{Mutex, RwLock};

use crate::chain::header_sync::{
    HeaderCandidate, HeaderCandidateBudget, HeaderCandidateError, HeaderValidationMode,
    MAX_FUTURE_TIME_SECONDS, PreparedHeader, VerifiedHeaderTarget, current_unix_seconds,
    prepare_header,
};
use crate::chain::{BlockTree, ChainError, NodeId, NodeStatus, TipSnapshot};
use crate::{ApplyError, Chainstate, ChainstateRole};

pub(crate) const HEADER_SIDE_CACHE_LIMIT: usize = 65_536;
pub(crate) const RECLAIM_PER_ADMISSION: usize = 4_000;
const MAX_HEADER_OPERATIONS: usize = 4;

#[derive(Debug)]
pub struct HeaderAdmissionOutcome {
    pub accepted: usize,
    pub announced_tip: Option<Hash256>,
    pub active_height: Option<i32>,
    pub demoted_tip: Option<Hash256>,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum HeaderResourceError {
    #[error("header retention requires a validated winning candidate from {anchor}")]
    CandidateRequired { anchor: Hash256 },
    #[error("header retention is reclaiming a completed or cancelled branch")]
    Reclaiming,
    #[error("required header ancestry exceeds the resident index domain")]
    CapacityOverflow,
}

#[derive(Debug, thiserror::Error)]
pub enum HeaderAdmissionError {
    #[error("header admission refused: {0}")]
    Refused(#[source] ApplyError),
    #[error(transparent)]
    Rejected(#[from] ChainError),
    #[error(transparent)]
    Resource(#[from] HeaderResourceError),
    #[error(transparent)]
    Candidate(#[from] HeaderCandidateError),
}

#[derive(Default)]
struct PendingApplied {
    scopes: usize,
    hash: Option<Hash256>,
}

pub(crate) struct HeaderRoleRetention {
    applied: Arc<ArcSwapOption<TipSnapshot>>,
    role: Arc<RwLock<ChainstateRole>>,
    pending: Mutex<PendingApplied>,
}

impl HeaderRoleRetention {
    pub(crate) fn begin_application(self: &Arc<Self>) -> PendingHeaderApplication {
        let mut pending = self.pending.lock();
        assert!(pending.scopes < usize::MAX);
        pending.scopes += 1;
        PendingHeaderApplication(Arc::clone(self))
    }

    pub(crate) fn stage(&self, hash: Hash256) {
        let mut pending = self.pending.lock();
        assert!(pending.scopes > 0);
        pending.hash = Some(hash);
    }

    pub(crate) fn published(&self, hash: Hash256) {
        let mut pending = self.pending.lock();
        if pending.hash == Some(hash) { pending.hash = None; }
    }
}

pub(crate) struct PendingHeaderApplication(Arc<HeaderRoleRetention>);

impl Drop for PendingHeaderApplication {
    fn drop(&mut self) {
        let mut pending = self.0.pending.lock();
        assert!(pending.scopes > 0);
        pending.scopes -= 1;
        if pending.scopes == 0 { pending.hash = None; }
    }
}

#[derive(Clone, Copy)]
struct ActiveReplay {
    candidate: u64,
    target: VerifiedHeaderTarget,
    prefix: Hash256,
}

#[derive(Default)]
struct RequiredAncestry {
    roots: Vec<NodeId>,
    count: usize,
}

#[derive(Default)]
struct RetentionPins {
    roles: Vec<Weak<HeaderRoleRetention>>,
    operations: usize,
    transient: BTreeMap<Hash256, usize>,
    replay: Option<ActiveReplay>,
    ancestry: RequiredAncestry,
}

pub(crate) struct HeaderRetention {
    candidates: Arc<HeaderCandidateBudget>,
    operator_invalid: Arc<RwLock<BTreeSet<Hash256>>>,
    pins: Mutex<RetentionPins>,
    #[cfg(any(test, feature = "test-seam"))]
    side_limit: std::sync::atomic::AtomicUsize,
}

impl Default for HeaderRetention {
    fn default() -> Self {
        let operator_invalid = Arc::new(RwLock::default());
        Self {
            candidates: Arc::new(HeaderCandidateBudget::new(Arc::clone(&operator_invalid))),
            operator_invalid,
            pins: Mutex::default(),
            #[cfg(any(test, feature = "test-seam"))]
            side_limit: std::sync::atomic::AtomicUsize::new(HEADER_SIDE_CACHE_LIMIT),
        }
    }
}

struct RetentionPlan {
    protected: Vec<NodeId>,
    ordinary_limit: usize,
    replay: Option<ActiveReplay>,
}

impl HeaderRetention {
    pub(crate) fn register_role(&self, applied: Arc<ArcSwapOption<TipSnapshot>>, role: Arc<RwLock<ChainstateRole>>) -> Arc<HeaderRoleRetention> {
        let mut pins = self.pins.lock();
        pins.roles.retain(|role| role.strong_count() != 0);
        assert!(pins.roles.len() < 2);
        let role = Arc::new(HeaderRoleRetention { applied, role, pending: Mutex::default() });
        pins.roles.push(Arc::downgrade(&role));
        role
    }

    fn side_limit(&self) -> usize {
        #[cfg(any(test, feature = "test-seam"))]
        { self.side_limit.load(std::sync::atomic::Ordering::Relaxed) }
        #[cfg(not(any(test, feature = "test-seam")))]
        { HEADER_SIDE_CACHE_LIMIT }
    }

    pub(crate) fn remember_operator_invalidation(&self, hash: Hash256) {
        self.operator_invalid.write().insert(hash);
        self.candidates.cancel_all();
    }

    pub(crate) fn cancel_candidates(&self) {
        self.candidates.cancel_all();
    }

    pub(crate) fn restore_operator_verdicts(&self, tree: &mut BlockTree) -> Result<(), ChainError> {
        for hash in self.operator_invalid.read().iter().copied() {
            if let Some(root) = tree.lookup(hash) { tree.invalidate_subtree(root)?; }
        }
        self.candidates.cancel_all();
        let mut pins = self.pins.lock();
        assert_eq!(pins.operations, 0);
        pins.replay = None;
        pins.ancestry = RequiredAncestry::default();
        for role in pins.roles.iter().filter_map(Weak::upgrade) {
            let mut pending = role.pending.lock();
            assert_eq!(pending.scopes, 0);
            pending.hash = None;
        }
        Ok(())
    }

    pub(crate) fn pin_operation(self: &Arc<Self>, tree: &BlockTree, roots: &[NodeId]) -> Result<HeaderRetentionLease, ApplyError> {
        assert!(roots.len() <= 3);
        let mut hashes = roots.iter().map(|id| tree.node(*id).map(|node| node.hash)).collect::<Result<Vec<_>, _>>()?;
        hashes.sort_unstable();
        hashes.dedup();
        let mut pins = self.pins.lock();
        if pins.operations == MAX_HEADER_OPERATIONS { return Err(ApplyError::ConcurrentChainChange); }
        pins.operations += 1;
        for hash in &hashes { *pins.transient.entry(*hash).or_default() += 1; }
        Ok(HeaderRetentionLease { owner: Arc::clone(self), hashes })
    }

    fn plan(&self, tree: &BlockTree) -> Result<RetentionPlan, HeaderAdmissionError> {
        let mut pins = self.pins.lock();
        if pins.replay.is_some_and(|replay| self.candidates.active_replay() != Some(replay.candidate)) {
            pins.replay = None;
        }
        let best = tree.tip_id();
        let mut roots = Vec::new();
        for role in pins.roles.iter().filter_map(Weak::upgrade) {
            let pending = role.pending.lock();
            if let Some(applied) = role.applied.load_full() { roots.push(retained_id(tree, applied.hash)?); }
            if let Some(hash) = pending.hash { roots.push(retained_id(tree, hash)?); }
            match *role.role.read() {
                ChainstateRole::Ordinary => {},
                ChainstateRole::AssumedActive { base_hash, .. } | ChainstateRole::Historical { base_hash, .. } => {
                    roots.push(retained_id(tree, base_hash)?);
                }
            }
        }
        for hash in pins.transient.keys() { roots.push(retained_id(tree, *hash)?); }
        roots.extend(self.operator_invalid.read().iter().filter_map(|hash| tree.lookup(*hash)));
        roots.sort_unstable();
        roots.dedup();
        let mut required_roots = Vec::with_capacity(roots.len() + usize::from(best.is_some()));
        if let Some(best) = best { required_roots.push(best); }
        for root in roots {
            let node = tree.node(root)?;
            if best.is_none_or(|best| tree.node_at_height_from(best, node.height) != Some(root)) {
                required_roots.push(root);
            }
        }
        let required = pins.ancestry.count(tree, &required_roots)?;
        let ordinary_limit = required.checked_add(self.side_limit()).ok_or(HeaderResourceError::CapacityOverflow)?;
        required_roots.extend(self.candidates.anchors().into_iter().flatten().filter_map(|hash| tree.lookup(hash)));
        if let Some(replay) = pins.replay { required_roots.push(retained_id(tree, replay.prefix)?); }
        Ok(RetentionPlan { protected: required_roots, ordinary_limit, replay: pins.replay })
    }

    pub(crate) fn check_operator_header(&self, header: &Header) -> Result<(), ChainError> {
        let invalid = self.operator_invalid.read();
        if invalid.is_empty() { return Ok(()); }
        let hash = Hash256::from(header.compute_hash());
        if invalid.contains(&hash) { return Err(ChainError::KnownInvalidHeader { hash }); }
        if invalid.contains(&header.prev_blockhash.0) {
            return Err(ChainError::KnownInvalidHeader { hash: header.prev_blockhash.0 });
        }
        Ok(())
    }
}

impl RequiredAncestry {
    fn count(&mut self, tree: &BlockTree, roots: &[NodeId]) -> Result<usize, HeaderAdmissionError> {
        if self.roots == roots { return Ok(self.count); }
        if roots.len() == self.roots.len()
            && let (Some(best), Some(previous)) = (roots.first(), self.roots.first())
            && roots[1..] == self.roots[1..]
            && tree.node(*best)?.parent == Some(*previous)
            && self.roots.iter().all(|root| root < best)
        {
            self.count = self.count.checked_add(1).ok_or(HeaderResourceError::CapacityOverflow)?;
            self.roots.copy_from_slice(roots);
            return Ok(self.count);
        }
        let mut count = 0_u64;
        for (index, id) in roots.iter().enumerate() {
            let height = tree.node(*id)?.height;
            let added = if index == 0 { u64::from(height) + 1 } else {
                let mut shared_height = 0;
                for previous in &roots[..index] {
                    let common = tree.find_common_ancestor(*id, *previous).ok_or(ChainError::UnknownNode { id: *id })?;
                    shared_height = shared_height.max(tree.node(common)?.height);
                }
                u64::from(height - shared_height)
            };
            count = count.checked_add(added).ok_or(HeaderResourceError::CapacityOverflow)?;
        }
        self.count = usize::try_from(count).map_err(|_| HeaderResourceError::CapacityOverflow)?;
        self.roots.clear();
        self.roots.extend_from_slice(roots);
        Ok(self.count)
    }
}

pub(crate) struct HeaderRetentionLease {
    owner: Arc<HeaderRetention>,
    hashes: Vec<Hash256>,
}

impl Drop for HeaderRetentionLease {
    #[expect(clippy::expect_used, reason = "an active operation retains each of its registered roots")]
    fn drop(&mut self) {
        let mut pins = self.owner.pins.lock();
        assert!(pins.operations > 0);
        pins.operations -= 1;
        for hash in &self.hashes {
            let count = pins.transient.get_mut(hash).expect("operation owns its header pin");
            assert!(*count > 0);
            *count -= 1;
            if *count == 0 { pins.transient.remove(hash); }
        }
    }
}

fn retained_id(tree: &BlockTree, hash: Hash256) -> Result<NodeId, ChainError> {
    tree.lookup(hash).ok_or(ChainError::MissingParent { prev_hash: hash })
}

impl Chainstate {
    pub fn admit_headers(&self, headers: &[Header]) -> Result<HeaderAdmissionOutcome, HeaderAdmissionError> {
        let _transition = self.lock_transition().map_err(HeaderAdmissionError::Refused)?;
        let mut tree = self.block_tree.write();
        let mut removals = RECLAIM_PER_ADMISSION;
        let result = self.admit_headers_retained(&mut tree, headers, None, &mut removals);
        self.assume_valid_gate.evaluate(&tree);
        result
    }

    fn insert_retained_header(
        &self,
        tree: &mut BlockTree,
        header: &Header,
        replay: Option<(u64, VerifiedHeaderTarget)>,
        removals: &mut usize,
        now: u32,
    ) -> Result<(NodeId, Option<Hash256>), HeaderAdmissionError> {
        self.header_retention.check_operator_header(header)?;
        let prepared = prepare_header(tree, header, self.network, now, HeaderValidationMode::LiveAdmission)?;
        if let PreparedHeader::New(validated) = &prepared {
            let lower_limit = tree.tip().map_or(Some(0), |tip| usize::try_from(tip.height).ok().and_then(|height| height.checked_add(1)))
                .and_then(|count| count.checked_add(self.header_retention.side_limit()));
            if replay.is_some() || lower_limit.is_none_or(|limit| tree.len() >= limit) {
                let mut plan = self.header_retention.plan(tree)?;
                let extra = match replay {
                    Some((id, target)) if plan.replay.is_some_and(|active| active.candidate == id && active.target == target) => {
                        usize::try_from(target.tip.height - target.anchor.height).map_err(|_| HeaderResourceError::CapacityOverflow)?
                    }
                    Some(_) => return Err(HeaderCandidateError::WrongChainstate.into()),
                    None => 0,
                };
                let limit = plan.ordinary_limit.checked_add(extra).ok_or(HeaderResourceError::CapacityOverflow)?;
                let wins = tree.tip().is_none_or(|tip| validated.chainwork() > tip.chainwork);
                let room = if wins { limit } else { limit.saturating_sub(1) };
                if let Some(parent) = validated.parent() { plan.protected.push(parent); }
                *removals -= tree.reclaim_leaves(&plan.protected, room, *removals)?;
                if tree.len() > room {
                    if tree.len() > limit { return Err(HeaderResourceError::Reclaiming.into()); }
                    let anchor = validated.parent().map(|id| tree.node(id).map(|node| node.hash)).transpose()?.ok_or(HeaderResourceError::Reclaiming)?;
                    return Err(HeaderResourceError::CandidateRequired { anchor }.into());
                }
            }
        }
        let inserted = prepared.insert(tree)?;
        Ok((inserted.id, inserted.demoted_tip))
    }

    #[expect(clippy::expect_used, reason = "only the active authenticated replay can update its prefix")]
    pub(crate) fn admit_headers_retained(
        &self,
        tree: &mut BlockTree,
        headers: &[Header],
        replay: Option<(u64, VerifiedHeaderTarget)>,
        removals: &mut usize,
    ) -> Result<HeaderAdmissionOutcome, HeaderAdmissionError> {
        let now = current_unix_seconds();
        let mut outcome = HeaderAdmissionOutcome { accepted: 0, announced_tip: None, active_height: None, demoted_tip: None };
        for header in headers {
            let (id, demoted) = match self.insert_retained_header(tree, header, replay, removals, now) {
                Ok(inserted) => inserted,
                Err(HeaderAdmissionError::Resource(HeaderResourceError::Reclaiming)) if replay.is_some() && outcome.accepted > 0 => break,
                Err(error) => return Err(error),
            };
            let hash = tree.node(id)?.hash;
            outcome.accepted += 1;
            outcome.announced_tip = Some(hash);
            outcome.demoted_tip = outcome.demoted_tip.or(demoted);
            if let Some((candidate, _)) = replay {
                let mut pins = self.header_retention.pins.lock();
                let active = pins.replay.as_mut().expect("authenticated replay owns its retention allowance");
                assert_eq!(active.candidate, candidate);
                active.prefix = hash;
            }
        }
        outcome.active_height = tree.tip().zip(outcome.announced_tip)
            .and_then(|(tip, hash)| tree.active_height_of(tip.tip_id, hash))
            .and_then(|height| i32::try_from(height).ok());
        Ok(outcome)
    }

    pub fn begin_header_candidate(&self, anchor: Hash256, minimum_work: ChainWork) -> Result<HeaderCandidate, HeaderAdmissionError> {
        let _transition = self.lock_transition().map_err(HeaderAdmissionError::Refused)?;
        let mut tree = self.block_tree.write();
        let mut plan = self.header_retention.plan(&tree)?;
        let parent = tree.lookup(anchor).ok_or(HeaderCandidateError::AnchorUnavailable { anchor })?;
        plan.protected.push(parent);
        tree.reclaim_leaves(&plan.protected, plan.ordinary_limit, RECLAIM_PER_ADMISSION)?;
        if tree.len() > plan.ordinary_limit { return Err(HeaderResourceError::Reclaiming.into()); }
        let best = tree.tip().ok_or(HeaderCandidateError::AnchorUnavailable { anchor })?;
        let required = best.chainwork.checked_add(ChainWork::from(1_u32)).ok_or(ChainError::ChainworkOverflow { hash: best.hash })?
            .max(minimum_work).max(ChainWork::from_be_bytes(self.network.minimum_chain_work()));
        Ok(HeaderCandidate::new(Arc::clone(&self.header_retention.candidates), &tree, parent, self.network, required)?)
    }

    #[expect(clippy::expect_used, reason = "the successful replay acquisition establishes its protected prefix")]
    pub fn admit_verified_headers(&self, candidate: &mut HeaderCandidate, maximum: usize) -> Result<HeaderAdmissionOutcome, HeaderAdmissionError> {
        let _transition = self.lock_transition().map_err(HeaderAdmissionError::Refused)?;
        let mut tree = self.block_tree.write();
        let result = (|| {
            if candidate.is_cancelled() { return Err(HeaderCandidateError::Cancelled.into()); }
            candidate.acquire_replay(&self.header_retention.candidates)?;
            let batch = candidate.verified_batch(maximum)?;
            let target = batch.target;
            let anchor = tree.lookup(target.anchor.hash).ok_or(HeaderCandidateError::AnchorUnavailable { anchor: target.anchor.hash })?;
            let node = tree.node(anchor)?;
            if node.status == NodeStatus::Invalid || node.height != target.anchor.height || node.chainwork != target.anchor.chainwork {
                return Err(HeaderCandidateError::AnchorUnavailable { anchor: target.anchor.hash }.into());
            }
            if tree.tip().is_none_or(|tip| target.tip.chainwork <= tip.chainwork) {
                return Err(HeaderCandidateError::TargetSuperseded.into());
            }
            let allowed_time = current_unix_seconds().saturating_add(MAX_FUTURE_TIME_SECONDS);
            if target.max_time > allowed_time {
                return Err(HeaderCandidateError::ClockChanged { maximum_time: target.max_time, allowed_time }.into());
            }
            let mut removals = RECLAIM_PER_ADMISSION;
            let plan = self.header_retention.plan(&tree)?;
            if plan.replay.is_none() {
                removals -= tree.reclaim_leaves(&plan.protected, plan.ordinary_limit, removals)?;
                if tree.len() > plan.ordinary_limit { return Err(HeaderResourceError::Reclaiming.into()); }
                self.header_retention.pins.lock().replay = Some(ActiveReplay { candidate: batch.candidate_id, target, prefix: target.anchor.hash });
            }
            let active = self.header_retention.pins.lock().replay.expect("acquired replay owns its prefix");
            assert_eq!(active.candidate, batch.candidate_id);
            if batch.headers.first().is_none_or(|header| header.prev_blockhash.0 != active.prefix) {
                return Err(HeaderCandidateError::TargetMismatch.into());
            }
            let outcome = self.admit_headers_retained(&mut tree, batch.headers, Some((batch.candidate_id, target)), &mut removals)?;
            candidate.acknowledge(outcome.accepted)?;
            Ok(outcome)
        })();
        self.assume_valid_gate.evaluate(&tree);
        let retry = matches!(&result, Err(HeaderAdmissionError::Candidate(HeaderCandidateError::Busy | HeaderCandidateError::NoVerifiedBatch)) | Err(HeaderAdmissionError::Resource(HeaderResourceError::Reclaiming)));
        if result.is_err() && !retry { candidate.finalize(); }
        result
    }

    pub fn maintain_header_retention(&self) -> Result<usize, HeaderAdmissionError> {
        let _transition = self.lock_transition().map_err(HeaderAdmissionError::Refused)?;
        let mut tree = self.block_tree.write();
        let plan = self.header_retention.plan(&tree)?;
        Ok(tree.reclaim_leaves(&plan.protected, plan.ordinary_limit, RECLAIM_PER_ADMISSION)?)
    }

    #[cfg(any(test, feature = "test-seam"))]
    pub fn set_header_side_cache_limit(&self, limit: usize) {
        assert!(limit > 0 && limit <= HEADER_SIDE_CACHE_LIMIT);
        self.header_retention.side_limit.store(limit, std::sync::atomic::Ordering::Relaxed);
    }
}
