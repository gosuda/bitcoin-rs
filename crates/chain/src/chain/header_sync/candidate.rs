use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

use bitcoin_rs_consensus::header_rules::{BlockHeader, ChainWork};
use bitcoin_rs_consensus::primitives::{Hash256, Network};
use parking_lot::{Mutex, RwLock};
use sha2::{Digest, Sha256};

use crate::chain::{BlockTree, ChainError, NodeId};

use super::context::{HeaderContextError, HeaderValidationContext};
use super::{HeaderValidationMode, current_unix_seconds};

pub(crate) const MAX_HEADER_CANDIDATES: usize = 4;
pub(crate) const HEADER_COMMITMENT_CHUNK: usize = 65_536;
pub(crate) const MAX_HEADER_CANDIDATE_BATCH: usize = 2_000;
const MAX_COMMITMENTS: usize = 65_536;
const LOCATOR_LIMIT: usize = 32;
const COMMITMENT_DOMAIN: &[u8] = b"bitcoin-rs/header-candidate/v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderCandidatePhase {
    Verifying,
    Redownloading,
    Finished,
}

#[derive(Debug, thiserror::Error)]
pub enum HeaderCandidateError {
    #[error("all header verification slots are in use")]
    Busy,
    #[error("header candidate identity space is exhausted")]
    IdentityExhausted,
    #[error("header candidate belongs to another chainstate")]
    WrongChainstate,
    #[error("header candidate was cancelled by its chainstate")]
    Cancelled,
    #[error("header candidate has finished")]
    Finished,
    #[error("header candidate input has {actual} headers, limit is {limit}")]
    BatchTooLarge { actual: usize, limit: usize },
    #[error("header candidate needs its authenticated prefix admitted before more input")]
    PendingAdmission,
    #[error("header candidate work {actual} does not reach {required}")]
    InsufficientWork { actual: ChainWork, required: ChainWork },
    #[error("header candidate exceeded its height-domain commitment bound")]
    CommitmentLimit,
    #[error("header redownload differs from authenticated chunk {chunk}")]
    CommitmentMismatch { chunk: usize },
    #[error("header redownload ended at height {actual}, target is {target}")]
    IncompleteRedownload { actual: u32, target: u32 },
    #[error("header redownload does not match its validated target")]
    TargetMismatch,
    #[error("header replay anchor {anchor} is no longer retained; request its ancestry again")]
    AnchorUnavailable { anchor: Hash256 },
    #[error("header replay target no longer exceeds the best header work")]
    TargetSuperseded,
    #[error("candidate timestamp {maximum_time} exceeds the current admission limit {allowed_time}")]
    ClockChanged { maximum_time: u32, allowed_time: u32 },
    #[error("header replay has no authenticated batch ready")]
    NoVerifiedBatch,
    #[error(transparent)]
    Validation(#[from] HeaderContextError),
    #[error(transparent)]
    Chain(#[from] ChainError),
}

struct CandidateSlot {
    anchor: Hash256,
    cancelled: bool,
}

#[derive(Default)]
struct CandidateBudgetState {
    next_id: u64,
    slots: BTreeMap<u64, CandidateSlot>,
    waiting: VecDeque<u64>,
    replay: Option<u64>,
}

#[derive(Default)]
pub(crate) struct HeaderCandidateBudget {
    state: Mutex<CandidateBudgetState>,
    operator_invalid: Arc<RwLock<BTreeSet<Hash256>>>,
}

impl HeaderCandidateBudget {
    pub(crate) fn new(operator_invalid: Arc<RwLock<BTreeSet<Hash256>>>) -> Self {
        Self { state: Mutex::default(), operator_invalid }
    }

    fn reserve(self: &Arc<Self>, anchor: Hash256) -> Result<CandidateReservation, HeaderCandidateError> {
        let mut state = self.state.lock();
        if state.slots.len() == MAX_HEADER_CANDIDATES { return Err(HeaderCandidateError::Busy); }
        let id = state.next_id.checked_add(1).ok_or(HeaderCandidateError::IdentityExhausted)?;
        state.next_id = id;
        state.slots.insert(id, CandidateSlot { anchor, cancelled: false });
        Ok(CandidateReservation { id, budget: Arc::clone(self) })
    }

    pub(crate) fn cancel_all(&self) {
        let mut state = self.state.lock();
        for slot in state.slots.values_mut() { slot.cancelled = true; }
        state.waiting.clear();
        state.replay = None;
    }

    pub(crate) fn active_replay(&self) -> Option<u64> { self.state.lock().replay }

    pub(crate) fn anchors(&self) -> [Option<Hash256>; MAX_HEADER_CANDIDATES] {
        let mut anchors = [None; MAX_HEADER_CANDIDATES];
        let state = self.state.lock();
        for (position, slot) in state.slots.values().filter(|slot| !slot.cancelled).enumerate() {
            anchors[position] = Some(slot.anchor);
        }
        anchors
    }
}

struct CandidateReservation {
    id: u64,
    budget: Arc<HeaderCandidateBudget>,
}

impl CandidateReservation {
    fn is_cancelled(&self) -> bool {
        self.budget.state.lock().slots.get(&self.id).is_none_or(|slot| slot.cancelled)
    }

    fn ready(&self) -> Result<(), HeaderCandidateError> {
        let mut state = self.budget.state.lock();
        if state.slots.get(&self.id).is_none_or(|slot| slot.cancelled) {
            return Err(HeaderCandidateError::Cancelled);
        }
        assert!(!state.waiting.contains(&self.id));
        state.waiting.push_back(self.id);
        Ok(())
    }

    fn acquire_replay(&self) -> Result<(), HeaderCandidateError> {
        let mut state = self.budget.state.lock();
        if state.slots.get(&self.id).is_none_or(|slot| slot.cancelled) {
            return Err(HeaderCandidateError::Cancelled);
        }
        if state.replay == Some(self.id) { return Ok(()); }
        if state.replay.is_some() || state.waiting.front() != Some(&self.id) {
            return Err(HeaderCandidateError::Busy);
        }
        state.waiting.pop_front();
        state.replay = Some(self.id);
        Ok(())
    }
}

impl Drop for CandidateReservation {
    fn drop(&mut self) {
        let mut state = self.budget.state.lock();
        assert!(state.slots.remove(&self.id).is_some());
        state.waiting.retain(|id| *id != self.id);
        if state.replay == Some(self.id) { state.replay = None; }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HeaderCandidatePoint {
    pub(crate) height: u32,
    pub(crate) hash: Hash256,
    pub(crate) chainwork: ChainWork,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedHeaderTarget {
    pub(crate) anchor: HeaderCandidatePoint,
    pub(crate) tip: HeaderCandidatePoint,
    pub(crate) max_time: u32,
}

struct Verification {
    context: HeaderValidationContext,
    commitments: Vec<[u8; 32]>,
    chunk: Sha256,
    chunk_len: usize,
    max_time: u32,
}

struct Redownload {
    target: VerifiedHeaderTarget,
    commitments: Vec<[u8; 32]>,
    next_commitment: usize,
    headers: Vec<BlockHeader>,
    authenticated: usize,
    admitted: usize,
    received_height: u32,
    received_hash: Hash256,
}

enum CandidateState {
    Verifying(Verification),
    Redownloading(Redownload),
    Finished { height: u32, hash: Hash256 },
}

pub struct HeaderCandidate {
    reservation: Option<CandidateReservation>,
    anchor: HeaderCandidatePoint,
    locator: Vec<Hash256>,
    required_work: ChainWork,
    state: CandidateState,
}

pub(crate) struct VerifiedHeaderBatch<'a> {
    pub(crate) candidate_id: u64,
    pub(crate) target: VerifiedHeaderTarget,
    pub(crate) headers: &'a [BlockHeader],
}

impl HeaderCandidate {
    pub(crate) fn new(budget: Arc<HeaderCandidateBudget>, tree: &BlockTree, parent: NodeId, network: Network, required_work: ChainWork) -> Result<Self, HeaderCandidateError> {
        let context = HeaderValidationContext::from_tree(tree, parent, network)?;
        let anchor = HeaderCandidatePoint { height: context.height(), hash: context.hash(), chainwork: context.chainwork() };
        assert!(required_work > anchor.chainwork);
        let reservation = budget.reserve(anchor.hash)?;
        let max_time = context.header().time;
        Ok(Self {
            reservation: Some(reservation),
            anchor,
            locator: tree.block_locator(parent, LOCATOR_LIMIT),
            required_work,
            state: CandidateState::Verifying(Verification {
                context,
                commitments: Vec::with_capacity(MAX_COMMITMENTS),
                chunk: chunk_hasher(anchor.hash, 0),
                chunk_len: 0,
                max_time,
            }),
        })
    }

    #[must_use]
    pub fn phase(&self) -> HeaderCandidatePhase {
        match self.state {
            CandidateState::Verifying(_) => HeaderCandidatePhase::Verifying,
            CandidateState::Redownloading(_) => HeaderCandidatePhase::Redownloading,
            CandidateState::Finished { .. } => HeaderCandidatePhase::Finished,
        }
    }

    #[must_use]
    pub fn height(&self) -> u32 {
        match &self.state {
            CandidateState::Verifying(state) => state.context.height(),
            CandidateState::Redownloading(state) => state.received_height,
            CandidateState::Finished { height, .. } => *height,
        }
    }

    fn last_hash(&self) -> Hash256 {
        match &self.state {
            CandidateState::Verifying(state) => state.context.hash(),
            CandidateState::Redownloading(state) => state.received_hash,
            CandidateState::Finished { hash, .. } => *hash,
        }
    }

    #[must_use]
    pub fn locator(&self) -> Vec<Hash256> {
        let last = self.last_hash();
        let mut locator = Vec::with_capacity(LOCATOR_LIMIT);
        locator.push(last);
        for hash in &self.locator {
            if *hash != last && locator.len() < LOCATOR_LIMIT { locator.push(*hash); }
        }
        locator
    }

    #[must_use]
    pub fn has_verified_headers(&self) -> bool {
        matches!(&self.state, CandidateState::Redownloading(state) if state.authenticated > state.admitted)
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.reservation.as_ref().is_some_and(CandidateReservation::is_cancelled)
    }

    pub fn receive(&mut self, headers: &[BlockHeader], full_message: bool) -> Result<usize, HeaderCandidateError> {
        self.receive_at(headers, full_message, current_unix_seconds())
    }

    fn receive_at(&mut self, headers: &[BlockHeader], full_message: bool, now: u32) -> Result<usize, HeaderCandidateError> {
        if self.is_cancelled() {
            self.finalize();
            return Err(HeaderCandidateError::Cancelled);
        }
        if headers.len() > MAX_HEADER_CANDIDATE_BATCH {
            self.finalize();
            return Err(HeaderCandidateError::BatchTooLarge { actual: headers.len(), limit: MAX_HEADER_CANDIDATE_BATCH });
        }
        if self.has_verified_headers() { return Err(HeaderCandidateError::PendingAdmission); }
        let height = self.height();
        let hash = self.last_hash();
        let state = core::mem::replace(&mut self.state, CandidateState::Finished { height, hash });
        let result = match state {
            CandidateState::Verifying(mut state) => {
                let reservation = self.reservation.as_ref().ok_or(HeaderCandidateError::Finished)?;
                let verdicts = reservation.budget.operator_invalid.read();
                verify_headers(&mut state, headers, self.anchor.hash, now, &verdicts)
                    .and_then(|()| self.after_verification(state, headers.len(), full_message))
            }
            CandidateState::Redownloading(mut state) => {
                receive_redownload(&mut state, headers, full_message)
                    .map(|consumed| (CandidateState::Redownloading(state), consumed))
            }
            CandidateState::Finished { .. } => Err(HeaderCandidateError::Finished),
        };
        match result {
            Ok((state, consumed)) => { self.state = state; Ok(consumed) }
            Err(error) => { self.reservation.take(); Err(error) }
        }
    }

    fn after_verification(&self, mut state: Verification, consumed: usize, full_message: bool) -> Result<(CandidateState, usize), HeaderCandidateError> {
        if state.context.chainwork() < self.required_work {
            if !full_message {
                return Err(HeaderCandidateError::InsufficientWork { actual: state.context.chainwork(), required: self.required_work });
            }
            return Ok((CandidateState::Verifying(state), consumed));
        }
        if state.chunk_len != 0 { finish_chunk(&mut state, self.anchor.hash)?; }
        let target = VerifiedHeaderTarget {
            anchor: self.anchor,
            tip: HeaderCandidatePoint { height: state.context.height(), hash: state.context.hash(), chainwork: state.context.chainwork() },
            max_time: state.max_time,
        };
        self.reservation.as_ref().ok_or(HeaderCandidateError::Finished)?.ready()?;
        Ok((CandidateState::Redownloading(Redownload {
            target,
            commitments: state.commitments,
            next_commitment: 0,
            headers: Vec::with_capacity(HEADER_COMMITMENT_CHUNK + MAX_HEADER_CANDIDATE_BATCH),
            authenticated: 0,
            admitted: 0,
            received_height: target.anchor.height,
            received_hash: target.anchor.hash,
        }), consumed))
    }

    pub(crate) fn acquire_replay(&self, budget: &Arc<HeaderCandidateBudget>) -> Result<(), HeaderCandidateError> {
        let reservation = self.reservation.as_ref().ok_or(HeaderCandidateError::Finished)?;
        if !Arc::ptr_eq(&reservation.budget, budget) { return Err(HeaderCandidateError::WrongChainstate); }
        if !self.has_verified_headers() { return Err(HeaderCandidateError::NoVerifiedBatch); }
        reservation.acquire_replay()
    }

    pub(crate) fn verified_batch(&self, maximum: usize) -> Result<VerifiedHeaderBatch<'_>, HeaderCandidateError> {
        let reservation = self.reservation.as_ref().ok_or(HeaderCandidateError::Finished)?;
        if reservation.is_cancelled() { return Err(HeaderCandidateError::Cancelled); }
        let CandidateState::Redownloading(state) = &self.state else { return Err(HeaderCandidateError::NoVerifiedBatch); };
        let count = (state.authenticated - state.admitted).min(maximum).min(MAX_HEADER_CANDIDATE_BATCH);
        if count == 0 { return Err(HeaderCandidateError::NoVerifiedBatch); }
        Ok(VerifiedHeaderBatch { candidate_id: reservation.id, target: state.target, headers: &state.headers[state.admitted..state.admitted + count] })
    }

    pub(crate) fn acknowledge(&mut self, admitted: usize) -> Result<(), HeaderCandidateError> {
        let CandidateState::Redownloading(state) = &mut self.state else { return Err(HeaderCandidateError::NoVerifiedBatch); };
        assert!(admitted > 0 && admitted <= state.authenticated - state.admitted);
        state.admitted += admitted;
        if state.admitted != state.authenticated { return Ok(()); }
        state.headers.drain(..state.authenticated);
        state.authenticated = 0;
        state.admitted = 0;
        state.next_commitment += 1;
        if state.received_height == state.target.tip.height && state.headers.is_empty() {
            self.finalize();
            return Ok(());
        }
        if let Err(error) = authenticate_chunk(state) {
            self.finalize();
            return Err(error);
        }
        Ok(())
    }

    pub fn finalize(&mut self) {
        let height = self.height();
        let hash = self.last_hash();
        self.state = CandidateState::Finished { height, hash };
        self.reservation.take();
    }
}

impl Drop for HeaderCandidate {
    fn drop(&mut self) { self.finalize(); }
}

#[expect(clippy::expect_used, reason = "chunk counts are bounded by the u32 height domain")]
fn chunk_hasher(anchor: Hash256, index: usize) -> Sha256 {
    let mut chunk = Sha256::new();
    chunk.update(COMMITMENT_DOMAIN);
    chunk.update(anchor.as_byte_array());
    chunk.update(u64::try_from(index).expect("chunk index fits u64").to_le_bytes());
    chunk
}

#[expect(clippy::expect_used, reason = "the commitment chunk contains at most 65536 headers")]
fn finish_chunk(state: &mut Verification, anchor: Hash256) -> Result<(), HeaderCandidateError> {
    if state.commitments.len() == MAX_COMMITMENTS { return Err(HeaderCandidateError::CommitmentLimit); }
    let next = state.commitments.len() + 1;
    let mut chunk = core::mem::replace(&mut state.chunk, chunk_hasher(anchor, next));
    chunk.update(u64::try_from(state.chunk_len).expect("chunk length fits u64").to_le_bytes());
    state.commitments.push(chunk.finalize().into());
    state.chunk_len = 0;
    Ok(())
}

fn verify_headers(state: &mut Verification, headers: &[BlockHeader], anchor: Hash256, now: u32, operator_invalid: &BTreeSet<Hash256>) -> Result<(), HeaderCandidateError> {
    for header in headers {
        let hash = Hash256::from(header.compute_hash());
        if operator_invalid.contains(&hash) { return Err(ChainError::KnownInvalidHeader { hash }.into()); }
        state.context.accept_header(header, now, HeaderValidationMode::LiveAdmission)?;
        state.max_time = state.max_time.max(header.time);
        state.chunk.update(header.to_bytes());
        state.chunk_len += 1;
        if state.chunk_len == HEADER_COMMITMENT_CHUNK { finish_chunk(state, anchor)?; }
    }
    Ok(())
}

fn receive_redownload(state: &mut Redownload, headers: &[BlockHeader], full_message: bool) -> Result<usize, HeaderCandidateError> {
    let mut consumed = 0;
    for header in headers {
        if state.received_height == state.target.tip.height { break; }
        if header.prev_blockhash.0 != state.received_hash {
            return Err(ChainError::NonContinuousHeader { expected_prev: state.received_hash, actual_prev: header.prev_blockhash.0 }.into());
        }
        state.received_height += 1;
        state.received_hash = Hash256::from(header.compute_hash());
        assert!(state.headers.len() < HEADER_COMMITMENT_CHUNK + MAX_HEADER_CANDIDATE_BATCH);
        state.headers.push(*header);
        consumed += 1;
    }
    if state.received_height == state.target.tip.height && state.received_hash != state.target.tip.hash {
        return Err(HeaderCandidateError::TargetMismatch);
    }
    if !full_message && state.received_height != state.target.tip.height {
        return Err(HeaderCandidateError::IncompleteRedownload { actual: state.received_height, target: state.target.tip.height });
    }
    authenticate_chunk(state)?;
    Ok(consumed)
}

#[expect(clippy::expect_used, reason = "the verified target bounds every chunk in the u32 height domain")]
fn authenticate_chunk(state: &mut Redownload) -> Result<(), HeaderCandidateError> {
    if state.authenticated != 0 { return Ok(()); }
    let total = usize::try_from(state.target.tip.height - state.target.anchor.height).expect("u32 height fits usize");
    let done = state.next_commitment.checked_mul(HEADER_COMMITMENT_CHUNK).expect("completed chunks fit usize");
    let count = (total - done).min(HEADER_COMMITMENT_CHUNK);
    assert!(count > 0);
    if state.headers.len() < count { return Ok(()); }
    let mut chunk = chunk_hasher(state.target.anchor.hash, state.next_commitment);
    for header in &state.headers[..count] { chunk.update(header.to_bytes()); }
    chunk.update(u64::try_from(count).expect("chunk length fits u64").to_le_bytes());
    let digest: [u8; 32] = chunk.finalize().into();
    if state.commitments.get(state.next_commitment) != Some(&digest) {
        return Err(HeaderCandidateError::CommitmentMismatch { chunk: state.next_commitment });
    }
    state.authenticated = count;
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{NodeStatus, accept_headers, block_work, regtest_fixture};

    #[derive(Debug, thiserror::Error)]
    enum TestError {
        #[error(transparent)]
        Candidate(#[from] HeaderCandidateError),
        #[error(transparent)]
        Chain(#[from] ChainError),
        #[error(transparent)]
        Fixture(#[from] regtest_fixture::RegtestFixtureError),
        #[error(transparent)]
        Integer(#[from] core::num::TryFromIntError),
    }

    fn fixture(count: usize, marker: u8) -> Result<(BlockTree, NodeId, Vec<BlockHeader>), TestError> {
        let genesis = Network::Regtest.genesis_block().header;
        let mut tree = BlockTree::new();
        let root = tree.insert_header(genesis, NodeStatus::HeaderValid)?;
        let mut parent = genesis.compute_hash();
        let mut headers = Vec::with_capacity(count);
        for height in 1..=count {
            let mut header = regtest_fixture::mined_regtest_header(parent, u32::try_from(height)?)?;
            header.merkle_root = Hash256::from_le_bytes(&[marker; 32]);
            header.nonce = 0;
            regtest_fixture::mine_header_to_declared_target(&mut header)?;
            parent = header.compute_hash();
            headers.push(header);
        }
        Ok((tree, root, headers))
    }

    fn candidate(tree: &BlockTree, root: NodeId, budget: &Arc<HeaderCandidateBudget>, count: usize) -> Result<HeaderCandidate, TestError> {
        let required = tree.node(root)?.chainwork + block_work(&tree.node(root)?.header) * ChainWork::from(u64::try_from(count)?);
        Ok(HeaderCandidate::new(Arc::clone(budget), tree, root, Network::Regtest, required)?)
    }

    fn verify(candidate: &mut HeaderCandidate, headers: &[BlockHeader]) -> Result<(), HeaderCandidateError> {
        for page in headers.chunks(MAX_HEADER_CANDIDATE_BATCH) {
            candidate.receive_at(page, page.len() == MAX_HEADER_CANDIDATE_BATCH, u32::MAX)?;
        }
        assert_eq!(candidate.phase(), HeaderCandidatePhase::Redownloading);
        Ok(())
    }

    // P2P-10
    #[test]
    fn late_contextual_failure_with_valid_pow_never_releases_a_prefix() -> Result<(), TestError> {
        let count = HEADER_COMMITMENT_CHUNK + 1;
        let (tree, root, mut headers) = fixture(count, 1)?;
        let last = &mut headers[count - 1];
        last.time = Network::Regtest.genesis_block().header.time;
        last.nonce = 0;
        regtest_fixture::mine_header_to_declared_target(last)?;
        for header in &headers {
            super::super::validate_pow(header, Hash256::from(header.compute_hash()), Network::Regtest)?;
        }
        let budget = Arc::new(HeaderCandidateBudget::default());
        let mut candidate = candidate(&tree, root, &budget, count)?;
        let mut failure = None;
        for page in headers.chunks(MAX_HEADER_CANDIDATE_BATCH) {
            match candidate.receive_at(page, page.len() == MAX_HEADER_CANDIDATE_BATCH, u32::MAX) {
                Ok(_) => assert!(!candidate.has_verified_headers()),
                Err(error) => { failure = Some(error); break; }
            }
        }
        assert!(matches!(failure, Some(HeaderCandidateError::Validation(HeaderContextError::Chain(ChainError::TimestampTooEarly { .. })))));
        assert_eq!(tree.len(), 1);
        assert_eq!(candidate.phase(), HeaderCandidatePhase::Finished);
        assert!(budget.state.lock().slots.is_empty());
        Ok(())
    }

    // P2P-10, SYNC-03
    #[test]
    fn authenticated_redownload_admits_bounded_slices_across_a_chunk_boundary() -> Result<(), TestError> {
        let count = HEADER_COMMITMENT_CHUNK + 7;
        let (mut tree, root, headers) = fixture(count, 2)?;
        let budget = Arc::new(HeaderCandidateBudget::default());
        let mut candidate = candidate(&tree, root, &budget, count)?;
        verify(&mut candidate, &headers)?;
        assert_eq!(tree.len(), 1);
        let mut admitted = 0;
        for page in headers.chunks(MAX_HEADER_CANDIDATE_BATCH) {
            candidate.receive_at(page, page.len() == MAX_HEADER_CANDIDATE_BATCH, u32::MAX)?;
            if let CandidateState::Redownloading(state) = &candidate.state {
                assert!(state.headers.len() <= HEADER_COMMITMENT_CHUNK + MAX_HEADER_CANDIDATE_BATCH);
                assert!(state.commitments.len() <= MAX_COMMITMENTS);
            }
            while candidate.has_verified_headers() {
                candidate.acquire_replay(&budget)?;
                let batch = candidate.verified_batch(usize::MAX)?;
                assert!(batch.headers.len() <= MAX_HEADER_CANDIDATE_BATCH);
                let accepted = accept_headers(&mut tree, batch.headers, Network::Regtest, u32::MAX, HeaderValidationMode::LiveAdmission)?.ids.len();
                admitted += accepted;
                candidate.acknowledge(accepted)?;
            }
        }
        assert_eq!(admitted, count);
        assert_eq!(tree.tip().map(|tip| tip.hash), headers.last().map(|header| Hash256::from(header.compute_hash())));
        assert_eq!(candidate.phase(), HeaderCandidatePhase::Finished);
        assert!(budget.state.lock().slots.is_empty());
        assert_eq!(budget.active_replay(), None);
        Ok(())
    }

    // P2P-10
    #[test]
    fn an_uncommitted_chunk_cannot_release_a_valid_replacement_branch() -> Result<(), TestError> {
        let count = HEADER_COMMITMENT_CHUNK + 1;
        let (tree, root, headers) = fixture(count, 3)?;
        let (_, _, alternate) = fixture(HEADER_COMMITMENT_CHUNK, 4)?;
        let budget = Arc::new(HeaderCandidateBudget::default());
        let mut candidate = candidate(&tree, root, &budget, count)?;
        verify(&mut candidate, &headers)?;
        let mut failure = None;
        for page in alternate.chunks(MAX_HEADER_CANDIDATE_BATCH) {
            match candidate.receive_at(page, true, u32::MAX) {
                Ok(_) => assert!(!candidate.has_verified_headers()),
                Err(error) => { failure = Some(error); break; }
            }
        }
        assert!(matches!(failure, Some(HeaderCandidateError::CommitmentMismatch { chunk: 0 })));
        assert_eq!(tree.len(), 1);
        assert!(budget.state.lock().slots.is_empty());
        Ok(())
    }

    // SYNC-03, SYNC-04
    #[test]
    fn cancellation_keeps_old_reservations_charged_until_release() -> Result<(), TestError> {
        let (tree, root, headers) = fixture(1, 5)?;
        let budget = Arc::new(HeaderCandidateBudget::default());
        let mut candidates = Vec::new();
        for _ in 0..MAX_HEADER_CANDIDATES {
            let mut next = candidate(&tree, root, &budget, 1)?;
            verify(&mut next, &headers)?;
            next.receive_at(&headers, false, u32::MAX)?;
            candidates.push(next);
        }
        candidates[0].acquire_replay(&budget)?;
        assert!(matches!(candidates[1].acquire_replay(&budget), Err(HeaderCandidateError::Busy)));
        budget.cancel_all();
        assert_eq!(budget.active_replay(), None);
        assert!(budget.anchors().iter().all(Option::is_none));
        assert!(candidates.iter().all(HeaderCandidate::is_cancelled));
        assert!(matches!(candidate(&tree, root, &budget, 1), Err(TestError::Candidate(HeaderCandidateError::Busy))));
        assert!(matches!(candidates[0].receive_at(&[], false, u32::MAX), Err(HeaderCandidateError::Cancelled)));
        let replacement = candidate(&tree, root, &budget, 1)?;
        assert_eq!(budget.state.lock().slots.len(), MAX_HEADER_CANDIDATES);
        drop(candidates);
        assert_eq!(budget.state.lock().slots.len(), 1);
        drop(replacement);
        assert!(budget.state.lock().slots.is_empty());
        Ok(())
    }

    // SYNC-03, SYNC-04
    #[test]
    fn replay_ownership_is_fifo_and_cancellation_releases_the_next_owner() -> Result<(), TestError> {
        let (tree, root, headers) = fixture(1, 6)?;
        let budget = Arc::new(HeaderCandidateBudget::default());
        let mut first = candidate(&tree, root, &budget, 1)?;
        let mut second = candidate(&tree, root, &budget, 1)?;
        for candidate in [&mut first, &mut second] {
            verify(candidate, &headers)?;
            candidate.receive_at(&headers, false, u32::MAX)?;
        }
        assert!(matches!(second.acquire_replay(&budget), Err(HeaderCandidateError::Busy)));
        first.acquire_replay(&budget)?;
        first.finalize();
        second.acquire_replay(&budget)?;
        second.finalize();
        assert!(budget.state.lock().slots.is_empty());
        Ok(())
    }

    // SYNC-03, SYNC-04
    #[test]
    fn input_limits_and_short_redownload_release_the_reservation() -> Result<(), TestError> {
        let (tree, root, headers) = fixture(2, 7)?;
        let budget = Arc::new(HeaderCandidateBudget::default());
        let mut short = candidate(&tree, root, &budget, 2)?;
        verify(&mut short, &headers)?;
        assert!(matches!(short.receive_at(&headers[..1], false, u32::MAX), Err(HeaderCandidateError::IncompleteRedownload { actual: 1, target: 2 })));
        assert!(budget.state.lock().slots.is_empty());
        let mut oversized = candidate(&tree, root, &budget, 2)?;
        let large = vec![headers[0]; MAX_HEADER_CANDIDATE_BATCH + 1];
        assert!(matches!(oversized.receive_at(&large, true, u32::MAX), Err(HeaderCandidateError::BatchTooLarge { .. })));
        assert!(budget.state.lock().slots.is_empty());
        Ok(())
    }
}
