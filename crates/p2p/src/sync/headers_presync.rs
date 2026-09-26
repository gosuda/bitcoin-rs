//! Core's download-twice header presync state: the anti-memory-DoS gate that
//! keeps an unverified, low-work header chain out of the block tree.
//!
//! A peer that has not demonstrated at least the network's minimum chain work
//! must be synchronized twice. The first pass (PRESYNC) validates each header
//! minimally — continuity, proof of work, permitted difficulty transition, and
//! cumulative work — and retains only one salted commitment bit per
//! [`HeadersSyncParams::commitment_period`] headers. Once the cumulative work
//! crosses the minimum, the second pass (REDOWNLOAD) replays the same chain
//! from the fork point, checks every commitment at its salted offset, and
//! releases headers to the caller only from behind the bounded redownload
//! buffer. Only that released output may reach
//! [`SyncChain::admit_headers`](super::chain::SyncChain::admit_headers).
//!
//! Core authority: `bitcoin-core/src/headerssync.h:57-100` (the design),
//! `:103-149` (state and constructor), and
//! `bitcoin-core/src/headerssync.cpp:72-149` (phase processing),
//! `:150-218` (presync validation and the work transition),
//! `:219-305` (redownload commitment checks and buffering), and
//! `:306-326` (the locator switch).

use std::collections::VecDeque;

use bitcoin_rs_chain::{
    ChainWork, block_work, current_unix_seconds, permitted_difficulty_transition, validate_pow,
};
use bitcoin_rs_primitives::{CompactTarget, Hash256, Header, HeadersSyncParams, Network};
use sha2::{Digest as _, Sha256};

/// Cumulative proof of work, ordered like Core's `arith_uint256` chainwork.
type Work = ChainWork;

/// Core's `MAX_FUTURE_BLOCK_TIME` (`bitcoin-core/src/consensus/params.h`), the
/// drift the honest-chain length estimate allows on top of the median-time-past
/// bound (`bitcoin-core/src/headerssync.cpp:33-49`).
const MAX_FUTURE_BLOCK_TIME_SECONDS: u64 = 2 * 60 * 60;

/// The phase of one peer's download-twice sync.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeadersSyncPhase {
    /// Collecting salted commitments; nothing is releasable.
    Presync,
    /// Replaying the chain and verifying commitments; releases buffered
    /// headers once enough commitments stand behind them.
    Redownload,
    /// Finished: temporary storage is released and the state is spent.
    Final,
}

/// The fork point a peer's header chain builds from, resolved against the
/// block tree by the caller before any state exists.
///
/// PRE: the anchor names a header this node already holds in its tree.
/// POST: (no mutation — this is an input record).
/// INVARIANT: `locator` is the tree locator for the anchor as observed at
///   resolution time, so the state can issue continuation requests without
///   ever reading the tree.
#[derive(Clone, Debug)]
pub struct HeaderAnchor {
    /// The network whose difficulty rules the chain is validated against.
    pub network: Network,
    /// Height of the anchor.
    pub height: u32,
    /// Hash of the anchor.
    pub hash: Hash256,
    /// The anchor header itself: redownload reads its bits as the previous
    /// difficulty when its buffer is empty.
    pub header: Header,
    /// Cumulative chain work through the anchor.
    pub chain_work: Work,
    /// Median time past at the anchor, bounding the honest-chain length
    /// estimate behind `max_commitments`.
    pub median_time_past: u32,
    /// Tree locator for the anchor, appended after the sync cursor in every
    /// continuation request.
    pub locator: Vec<Hash256>,
}

/// One batch's outcome from [`HeadersSyncState::process`].
#[derive(Clone, Debug)]
pub struct HeaderSyncResult {
    /// Headers the caller may admit now: empty during PRESYNC, and during
    /// REDOWNLOAD only headers whose commitments are verified and whose
    /// buffer depth has been retired.
    pub ready_headers: Vec<Header>,
    /// Whether the caller should request the next batch from this peer with
    /// [`HeadersSyncState::next_locator`].
    pub request_more: bool,
    /// The phase after this batch.
    pub phase: HeadersSyncPhase,
}

/// A typed failure that ends one peer's download-twice sync.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeaderSyncError {
    /// The batch did not connect to the sync cursor. Core treats this as
    /// benign — the peer may have reorged — and gives up on the sync
    /// (`bitcoin-core/src/headerssync.cpp:155-163`).
    NonContinuous {
        /// Phase that observed the break.
        phase: HeadersSyncPhase,
        /// Height where continuity broke.
        height: u32,
    },
    /// A difficulty transition the network does not permit at this height
    /// (`bitcoin-core/src/headerssync.cpp:186-195`).
    DifficultyTransition {
        /// Phase that observed the transition.
        phase: HeadersSyncPhase,
        /// Height of the offending header.
        height: u32,
    },
    /// A header whose hash does not meet its own declared target.
    InvalidPow {
        /// Phase that observed the header.
        phase: HeadersSyncPhase,
        /// Height of the offending header.
        height: u32,
        /// Hash of the offending header.
        hash: Hash256,
    },
    /// Redownload produced a header whose commitment bit differs from the one
    /// PRESYNC stored — the peer served a different chain the second time
    /// (`bitcoin-core/src/headerssync.cpp:281-293`).
    CommitmentMismatch {
        /// Height where the bits diverged.
        height: u32,
    },
    /// Redownload reached a commitment height with no stored commitment left
    /// to check (`bitcoin-core/src/headerssync.cpp:275-280`).
    CommitmentOverrun {
        /// Height that overran the commitment deque.
        height: u32,
    },
    /// PRESYNC exceeded the honest-chain length bound on stored commitments,
    /// so continuing would spend the memory the mechanism exists to bound
    /// (`bitcoin-core/src/headerssync.cpp:197-206`).
    MaxCommitments {
        /// Height that exceeded the bound.
        height: u32,
    },
    /// `process` was called on a spent state; a caller bookkeeping bug.
    Finalized,
}

impl HeaderSyncError {
    /// Whether this failure is the peer's, not the network's.
    ///
    /// PRE: none.
    /// POST: return true for every failure except a lost continuity, which
    ///   Core documents as possibly benign (`headerssync.cpp:155-163`).
    /// INVARIANT: a commitment divergence is always the peer's: PRESYNC and
    ///   REDOWNLOAD saw the same salted hasher, so only the sender can make
    ///   the two passes disagree.
    pub(crate) const fn is_peer_fault(&self) -> bool {
        !matches!(self, Self::NonContinuous { .. })
    }
}

impl core::fmt::Display for HeaderSyncError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NonContinuous { phase, height } => {
                write!(
                    f,
                    "headers batch broke continuity at height {height:?} ({phase:?})"
                )
            }
            Self::DifficultyTransition { phase, height } => {
                write!(
                    f,
                    "impermitted difficulty transition at height {height:?} ({phase:?})"
                )
            }
            Self::InvalidPow {
                phase,
                height,
                hash,
            } => {
                write!(
                    f,
                    "header {hash} at height {height:?} misses its target ({phase:?})"
                )
            }
            Self::CommitmentMismatch { height } => {
                write!(f, "redownload commitment mismatch at height {height}")
            }
            Self::CommitmentOverrun { height } => {
                write!(f, "redownload overran commitments at height {height}")
            }
            Self::MaxCommitments { height } => {
                write!(
                    f,
                    "presync exceeded its commitment bound at height {height}"
                )
            }
            Self::Finalized => f.write_str("header sync state already finalized"),
        }
    }
}

impl std::error::Error for HeaderSyncError {}

/// A compressed header: every field but `prev_blockhash`, which the redownload
/// buffer reconstructs from its predecessor
/// (`bitcoin-core/src/headerssync.h:29-52`).
#[derive(Clone, Copy, Debug)]
struct CompressedHeader {
    version: i32,
    merkle_root: Hash256,
    time: u32,
    bits: CompactTarget,
    nonce: u32,
}

impl CompressedHeader {
    const fn compress(header: &Header) -> Self {
        Self {
            version: header.version,
            merkle_root: header.merkle_root,
            time: header.time,
            bits: header.bits,
            nonce: header.nonce,
        }
    }

    fn expand(self, prev_blockhash: Hash256) -> Header {
        Header {
            version: self.version,
            prev_blockhash: prev_blockhash.into(),
            merkle_root: self.merkle_root,
            time: self.time,
            bits: self.bits,
            nonce: self.nonce,
        }
    }
}

/// One peer's download-twice header sync (`headerssync.h:103-149`).
///
/// INVARIANT: no method on this type inserts into the block tree. Headers
/// leave only through [`HeaderSyncResult::ready_headers`], and only the
/// caller's committed-phase branch may admit them.
pub struct HeadersSyncState {
    phase: HeadersSyncPhase,
    chain_start: HeaderAnchor,
    params: HeadersSyncParams,
    minimum_work: Work,
    /// The secret offset on heights for commitment bits
    /// (`headerssync.cpp:24`, `headerssync.h:186-190`).
    commit_offset: u32,
    /// Salted key material for the commitment hash; generated once per state
    /// and never reused after `FINAL` (`headerssync.h:211-212`).
    salt: [u8; 16],
    /// Cumulative work over the PRESYNC pass, starting at the anchor's.
    current_work: Work,
    /// Height of the last PRESYNC header (starts at the anchor's).
    current_height: u32,
    /// Hash of the last PRESYNC header (starts at the anchor's).
    last_header_hash: Hash256,
    /// Bits of the last PRESYNC header (starts at the anchor's).
    last_header_bits: u32,
    /// One-bit commitments created during PRESYNC, consumed during REDOWNLOAD.
    commitments: VecDeque<bool>,
    /// Bound on [`Self::commitments`] from the honest-chain length estimate
    /// (`headerssync.cpp:33-49`).
    max_commitments: u64,
    /// The bounded second-pass buffer (`headerssync.h:231-233`).
    redownloaded: VecDeque<CompressedHeader>,
    redownload_last_height: u32,
    redownload_last_hash: Hash256,
    /// Bits of the last stored redownload header. The buffer can drain
    /// below it, so the difficulty check reads this rather than the
    /// buffer's tail — which would wrongly fall back to the anchor's bits
    /// after a release emptied the buffer mid-retarget.
    redownload_last_bits: CompactTarget,
    redownload_first_prev_hash: Hash256,
    redownload_work: Work,
    /// Set once the redownloaded chain itself crosses the minimum work: the
    /// target is reached and the whole buffer may drain
    /// (`headerssync.h:244-249`).
    process_all_remaining_headers: bool,
}

impl HeadersSyncState {
    /// Starts one peer's download-twice sync from a known fork point.
    ///
    /// PRE: `chain_start` names a header this node already holds, and
    ///   `params.commitment_period > 0`.
    /// POST: returns a fresh PRESYNC state whose permanent storage is empty;
    ///   `salt` keys the commitment hash and `params` size the commitment
    ///   period and the redownload buffer.
    /// INVARIANT: no method on this type inserts into the block tree.
    pub fn new(
        chain_start: HeaderAnchor,
        minimum_work: Work,
        params: HeadersSyncParams,
        salt: [u8; 16],
    ) -> Self {
        debug_assert!(
            params.commitment_period > 0,
            "commitment period must be nonzero"
        );
        let period = u64::from(params.commitment_period);
        // Core draws the commitment offset from a fast RNG
        // (`headerssync.cpp:24`); deriving it from the state's own salt keeps
        // one random input per sync and stays reproducible under test.
        let commit_offset = u64::from_le_bytes(salt[..8].try_into().unwrap_or([0; 8])) % period;
        // Estimate how long an honest chain could be right now: the fastest
        // rate the median-time-past rule allows (6 blocks per second) times
        // the seconds from the anchor's MTP to now plus the future-block
        // bound (`headerssync.cpp:33-49`). A clock behind the anchor clamps
        // the estimate to the bound alone, which is the safe direction: the
        // sync aborts rather than the memory bound growing unbounded.
        let seconds_since_start =
            u64::from(current_unix_seconds().saturating_sub(chain_start.median_time_past))
                .saturating_add(MAX_FUTURE_BLOCK_TIME_SECONDS);
        let max_commitments = 6_u64.saturating_mul(seconds_since_start) / period;
        let last_header_bits = chain_start.header.bits.to_consensus();
        Self {
            phase: HeadersSyncPhase::Presync,
            current_work: chain_start.chain_work,
            current_height: chain_start.height,
            last_header_hash: chain_start.hash,
            last_header_bits,
            commitments: VecDeque::new(),
            max_commitments,
            redownloaded: VecDeque::new(),
            redownload_last_height: chain_start.height,
            redownload_last_hash: chain_start.hash,
            redownload_last_bits: chain_start.header.bits,
            redownload_first_prev_hash: chain_start.hash,
            redownload_work: chain_start.chain_work,
            process_all_remaining_headers: false,
            commit_offset: u32::try_from(commit_offset).unwrap_or(0),
            chain_start,
            params,
            minimum_work,
            salt,
        }
    }

    /// Processes one received batch (`headerssync.cpp:72-149`).
    ///
    /// PRE: `headers` is non-empty; continuity is enforced here per
    ///   header, not assumed from the sender; `full_message` says whether
    ///   the batch filled the wire's maximum headers page.
    /// POST: PRESYNC releases nothing; REDOWNLOAD releases only ordered,
    ///   commitment-verified headers whose buffer depth has been retired. A
    ///   returned `request_more` means the caller should continue this sync
    ///   with [`Self::next_locator`]; a `Final` phase means the sync is over
    ///   and the state is spent.
    /// INVARIANT: returned headers are continuous, commitment-checked, and
    ///   may be admitted only by the caller's committed-phase branch.
    pub fn process(
        &mut self,
        headers: &[Header],
        full_message: bool,
    ) -> Result<HeaderSyncResult, HeaderSyncError> {
        if headers.is_empty() {
            // The route admits empty batches itself; a defensive no-op keeps
            // the sync alive rather than spending it.
            return Ok(HeaderSyncResult {
                ready_headers: Vec::new(),
                request_more: true,
                phase: self.phase,
            });
        }
        if self.phase == HeadersSyncPhase::Final {
            return Err(HeaderSyncError::Finalized);
        }
        let outcome = if self.phase == HeadersSyncPhase::Presync {
            self.process_presync(headers, full_message)
        } else {
            self.process_redownload(headers, full_message)
        };
        // Core finalizes whenever a run will not continue
        // (`headerssync.cpp:146`): a failure or a stopped download frees the
        // temporary state in the same step that reports it.
        let result = match outcome {
            Ok(result) => result,
            Err(error) => {
                self.finalize();
                return Err(error);
            }
        };
        if result.phase == HeadersSyncPhase::Final || !result.request_more {
            self.finalize();
        }
        Ok(HeaderSyncResult {
            phase: self.phase,
            ..result
        })
    }

    /// The PRESYNC pass: minimal validation and salted commitments
    /// (`headerssync.cpp:150-218`).
    ///
    /// PRE: `headers` is non-empty (the caller guards the empty batch).
    /// POST: every header passed [`Self::validate_presync_header`] —
    ///   which enforces continuity for each header, not just the first —
    ///   or the first failing header's error.
    /// INVARIANT: the crossing check runs only after the whole batch
    ///   validated, so a batch that breaks continuity mid-way never sums
    ///   its disconnected branch work into the REDOWNLOAD decision.
    fn process_presync(
        &mut self,
        headers: &[Header],
        full_message: bool,
    ) -> Result<HeaderSyncResult, HeaderSyncError> {
        for header in headers {
            self.validate_presync_header(header)?;
        }
        if self.current_work >= self.minimum_work {
            self.begin_redownload();
        }
        let request_more = full_message || self.phase == HeadersSyncPhase::Redownload;
        Ok(HeaderSyncResult {
            ready_headers: Vec::new(),
            request_more,
            phase: self.phase,
        })
    }

    /// Validates and commits one PRESYNC header (`headerssync.cpp:172-218`).
    ///
    /// PRE: `header` chains onto the running cursor — its
    ///   `prev_blockhash` equals the hash the cursor holds. Whole-batch
    ///   continuity lives here, as Core's `CheckHeadersAreContinuous`
    ///   keeps it out of the caller's loop
    ///   (`net_processing.cpp:2915-2924`).
    /// POST: the header passed continuity, the permitted difficulty
    ///   transition, proof of work, and the commitment bound, and the
    ///   cursor advanced onto it; or the failing check's error with the
    ///   cursor untouched.
    /// INVARIANT: a rejected header leaves no trace: work, bits, height,
    ///   and the cursor are exactly their pre-call values.
    fn validate_presync_header(&mut self, header: &Header) -> Result<(), HeaderSyncError> {
        let height = self.current_height.saturating_add(1);
        if Hash256::from(header.prev_blockhash) != self.last_header_hash {
            return Err(HeaderSyncError::NonContinuous {
                phase: HeadersSyncPhase::Presync,
                height,
            });
        }
        let bits = header.bits.to_consensus();
        if !permitted_difficulty_transition(
            self.chain_start.network,
            height,
            CompactTarget::from_consensus(self.last_header_bits),
            header.bits,
        ) {
            return Err(HeaderSyncError::DifficultyTransition {
                phase: HeadersSyncPhase::Presync,
                height,
            });
        }
        let hash = Hash256::from(header.compute_hash());
        if validate_pow(header, hash, self.chain_start.network).is_err() {
            return Err(HeaderSyncError::InvalidPow {
                phase: HeadersSyncPhase::Presync,
                height,
                hash,
            });
        }
        if height % self.params.commitment_period == self.commit_offset {
            self.commitments.push_back(self.commitment_bit(hash));
            if u64::try_from(self.commitments.len()).unwrap_or(u64::MAX) > self.max_commitments {
                return Err(HeaderSyncError::MaxCommitments { height });
            }
        }
        self.current_work = self.current_work.saturating_add(block_work(header));
        self.last_header_hash = hash;
        self.last_header_bits = bits;
        self.current_height = height;
        Ok(())
    }

    /// Transitions to REDOWNLOAD at the anchor: replay the same chain from
    /// the fork point with the commitments PRESYNC collected
    /// (`headerssync.cpp:207-216`).
    fn begin_redownload(&mut self) {
        self.redownloaded.clear();
        self.redownload_last_height = self.chain_start.height;
        self.redownload_last_hash = self.chain_start.hash;
        self.redownload_first_prev_hash = self.chain_start.hash;
        self.redownload_work = self.chain_start.chain_work;
        self.process_all_remaining_headers = false;
        self.phase = HeadersSyncPhase::Redownload;
    }

    /// The REDOWNLOAD pass: commitment verification and the bounded buffer
    /// (`headerssync.cpp:219-305`).
    fn process_redownload(
        &mut self,
        headers: &[Header],
        full_message: bool,
    ) -> Result<HeaderSyncResult, HeaderSyncError> {
        for header in headers {
            self.store_redownloaded_header(header)?;
        }
        let ready_headers = self.pop_ready_headers();
        let complete = self.redownloaded.is_empty() && self.process_all_remaining_headers;
        if complete {
            return Ok(HeaderSyncResult {
                ready_headers,
                request_more: false,
                phase: HeadersSyncPhase::Final,
            });
        }
        if !full_message {
            // The peer declined to serve the full chain a second time:
            // release whatever the buffer retired and end the sync
            // (`headerssync.cpp:130-138`).
            return Ok(HeaderSyncResult {
                ready_headers,
                request_more: false,
                phase: HeadersSyncPhase::Final,
            });
        }
        Ok(HeaderSyncResult {
            ready_headers,
            request_more: true,
            phase: self.phase,
        })
    }

    /// Validates one redownloaded header and buffers it
    /// (`headerssync.cpp:220-299`).
    fn store_redownloaded_header(&mut self, header: &Header) -> Result<(), HeaderSyncError> {
        let height = self.redownload_last_height.saturating_add(1);
        let hash = Hash256::from(header.compute_hash());
        if Hash256::from(header.prev_blockhash) != self.redownload_last_hash {
            return Err(HeaderSyncError::NonContinuous {
                phase: HeadersSyncPhase::Redownload,
                height,
            });
        }
        let previous_bits = self.redownload_last_bits;
        if !permitted_difficulty_transition(
            self.chain_start.network,
            height,
            previous_bits,
            header.bits,
        ) {
            return Err(HeaderSyncError::DifficultyTransition {
                phase: HeadersSyncPhase::Redownload,
                height,
            });
        }
        if validate_pow(header, hash, self.chain_start.network).is_err() {
            return Err(HeaderSyncError::InvalidPow {
                phase: HeadersSyncPhase::Redownload,
                height,
                hash,
            });
        }
        self.redownload_work = self.redownload_work.saturating_add(block_work(header));
        if self.redownload_work >= self.minimum_work {
            self.process_all_remaining_headers = true;
        }
        if !self.process_all_remaining_headers
            && height % self.params.commitment_period == self.commit_offset
        {
            let Some(expected) = self.commitments.pop_front() else {
                return Err(HeaderSyncError::CommitmentOverrun { height });
            };
            if self.commitment_bit(hash) != expected {
                return Err(HeaderSyncError::CommitmentMismatch { height });
            }
        }
        self.redownloaded
            .push_back(CompressedHeader::compress(header));
        self.redownload_last_height = height;
        self.redownload_last_hash = hash;
        self.redownload_last_bits = header.bits;
        Ok(())
    }

    /// Returns a released prefix to the buffer when the admission path
    /// refused it, so the next release emits it again rather than losing a
    /// verified span.
    ///
    /// PRE: `headers` are exactly the most recently popped prefix, in
    ///   order, and the state is still in REDOWNLOAD (not finalized).
    /// POST: the buffer's front is that prefix again and
    ///   `redownload_first_prev_hash` points at its first header's parent.
    pub(crate) fn requeue_released(&mut self, headers: &[Header]) {
        let Some(first) = headers.first() else {
            return;
        };
        self.redownload_first_prev_hash = Hash256::from(first.prev_blockhash);
        for header in headers.iter().rev() {
            self.redownloaded
                .push_front(CompressedHeader::compress(header));
        }
    }

    /// Releases headers the verified commitments cover
    /// (`headerssync.cpp:231-249`): everything past the buffer bound, and
    /// once the redownloaded chain itself crosses the minimum work,
    /// everything left.
    fn pop_ready_headers(&mut self) -> Vec<Header> {
        let mut ready = Vec::new();
        let release_all = self.process_all_remaining_headers;
        while self.redownloaded.len() > self.params.redownload_buffer_size || release_all {
            let Some(compressed) = self.redownloaded.pop_front() else {
                break;
            };
            let header = compressed.expand(self.redownload_first_prev_hash);
            self.redownload_first_prev_hash = Hash256::from(header.compute_hash());
            ready.push(header);
        }
        ready
    }

    /// The locator to continue this sync with (`headerssync.cpp:306-326`).
    ///
    /// PRE: the state is not `Final`.
    /// POST: returns the sync cursor for the current phase — the last
    ///   PRESYNC header or the last buffered REDOWNLOAD header — followed by
    ///   the anchor's known fork locator.
    /// INVARIANT: locator progress is monotonic within a phase: the cursor is
    ///   the deepest header this sync has accepted.
    #[must_use]
    pub fn next_locator(&self) -> Vec<Hash256> {
        if self.phase == HeadersSyncPhase::Final {
            return Vec::new();
        }
        let cursor = if self.phase == HeadersSyncPhase::Presync {
            self.last_header_hash
        } else {
            self.redownload_last_hash
        };
        let mut locator = Vec::with_capacity(self.chain_start.locator.len() + 1);
        locator.push(cursor);
        locator.extend(self.chain_start.locator.iter().copied());
        locator
    }

    /// The height this sync has reached, for request bookkeeping and logs.
    ///
    /// PRE: none.
    /// POST: returns the cursor height of the live phase, or the anchor
    ///   height once spent.
    #[must_use]
    pub(crate) const fn sync_height(&self) -> u32 {
        match self.phase {
            HeadersSyncPhase::Presync => self.current_height,
            HeadersSyncPhase::Redownload => self.redownload_last_height,
            HeadersSyncPhase::Final => self.chain_start.height,
        }
    }

    /// The live phase, for tests and logs.
    #[must_use]
    #[cfg(test)]
    pub(crate) const fn phase(&self) -> HeadersSyncPhase {
        self.phase
    }

    /// Releases all temporary state and spends the sync (`headerssync.cpp:52-66`).
    ///
    /// PRE: none (idempotent).
    /// POST: the state is `Final`, every commitment and buffered header is
    ///   dropped, and the salt is never reused: the caller must discard this
    ///   state and construct a fresh one for any later sync.
    /// INVARIANT: no temporary header remains retained after finalization.
    pub fn finalize(&mut self) {
        if self.phase == HeadersSyncPhase::Final {
            return;
        }
        self.commitments.clear();
        self.redownloaded.clear();
        self.redownload_last_hash = Hash256::default();
        self.redownload_first_prev_hash = Hash256::default();
        self.process_all_remaining_headers = false;
        self.current_height = 0;
        self.phase = HeadersSyncPhase::Final;
    }

    /// The salted one-bit commitment for one header hash
    /// (`headerssync.h:211-216`: a salted hasher reduced to its low bit).
    pub(crate) fn commitment_bit(&self, hash: Hash256) -> bool {
        let mut digest = Sha256::new();
        digest.update(self.salt);
        digest.update(hash.as_byte_array());
        digest.finalize()[0] & 1 == 1
    }

    /// The first height at or above `from` whose header carries a salted
    /// commitment, for tests that must substitute exactly one of those.
    #[must_use]
    #[cfg(test)]
    pub(crate) const fn first_commitment_height(&self, from: u32) -> u32 {
        let period = self.params.commitment_period;
        let offset = self.commit_offset;
        let remainder = from % period;
        if remainder <= offset {
            from + (offset - remainder)
        } else {
            from + (period - remainder + offset)
        }
    }
}
