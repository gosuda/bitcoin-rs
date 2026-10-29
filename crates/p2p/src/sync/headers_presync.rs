//! Core's download-twice header presync state: the anti-memory-DoS gate that
//! keeps an unverified, low-work header chain out of the block tree.

use std::collections::VecDeque;

use bitcoin_rs_chain::{
    ChainWork, block_work, current_unix_seconds, permitted_difficulty_transition, validate_pow,
};
use bitcoin_rs_primitives::{CompactTarget, Hash256, Header, HeadersSyncParams, Network};
use sha2::{Digest as _, Sha256};

type Work = ChainWork;

const MAX_FUTURE_BLOCK_TIME_SECONDS: u64 = 2 * 60 * 60;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeadersSyncPhase {
    Presync,
    Redownload,
    Final,
}

#[derive(Clone, Debug)]
pub struct HeaderAnchor {
    pub network: Network,
    pub height: u32,
    pub hash: Hash256,
    pub header: Header,
    pub chain_work: Work,
    pub median_time_past: u32,
    pub locator: Vec<Hash256>,
}

#[derive(Clone, Debug)]
pub struct HeaderSyncResult {
    pub ready_headers: Vec<Header>,
    pub request_more: bool,
    pub phase: HeadersSyncPhase,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeaderSyncError {
    NonContinuous {
        phase: HeadersSyncPhase,
        height: u32,
    },
    DifficultyTransition {
        phase: HeadersSyncPhase,
        height: u32,
    },
    InvalidPow {
        phase: HeadersSyncPhase,
        height: u32,
        hash: Hash256,
    },
    CommitmentMismatch {
        height: u32,
    },
    CommitmentOverrun {
        height: u32,
    },
    MaxCommitments {
        height: u32,
    },
    Finalized,
}

impl HeaderSyncError {
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

/// A FIFO of the one-bit commitments a PRESYNC pass leaves for the REDOWNLOAD check
/// (`headerssync.h` keeps the same bits), packed 64 per word.
///
/// A mainnet pass can retain millions of commitments — see the honest-chain estimate in
/// [`HeadersSyncState::new`] — so one byte apiece would make every open sync state a
/// memory-amplification surface per connection.
#[derive(Default)]
struct CommitmentBits {
    words: VecDeque<u64>,
    live: u64,
    head: u8,
}

impl CommitmentBits {
    fn push_back(&mut self, bit: bool) {
        let tail = u64::from(self.head).saturating_add(self.live);
        let word = usize::try_from(tail / 64).unwrap_or(usize::MAX);
        if word >= self.words.len() {
            self.words.push_back(0);
        }
        if bit {
            self.words[word] |= 1_u64 << (tail % 64);
        }
        self.live += 1;
    }

    fn pop_front(&mut self) -> Option<bool> {
        if self.live == 0 {
            return None;
        }
        let bit = self.words[0] & (1_u64 << self.head) != 0;
        self.live -= 1;
        self.head += 1;
        if self.head == 64 {
            self.words.pop_front();
            self.head = 0;
        }
        Some(bit)
    }

    fn live_bits(&self) -> u64 {
        self.live
    }

    fn clear(&mut self) {
        self.words.clear();
        self.live = 0;
        self.head = 0;
    }
}

/// INVARIANT: no method on this type inserts into the block tree. Headers
/// leave only through [`HeaderSyncResult::ready_headers`], and only the
/// caller's committed-phase branch may admit them.
pub struct HeadersSyncState {
    phase: HeadersSyncPhase,
    chain_start: HeaderAnchor,
    params: HeadersSyncParams,
    minimum_work: Work,
    commit_offset: u32,
    salt: [u8; 16],
    current_work: Work,
    current_height: u32,
    last_header_hash: Hash256,
    last_header_bits: u32,
    commitments: CommitmentBits,
    max_commitments: u64,
    redownloaded: VecDeque<CompressedHeader>,
    redownload_last_height: u32,
    redownload_last_hash: Hash256,
    redownload_last_bits: CompactTarget,
    redownload_first_prev_hash: Hash256,
    redownload_work: Work,
    process_all_remaining_headers: bool,
    final_height: u32,
}

impl HeadersSyncState {
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
        let commit_offset = u64::from_le_bytes(salt[..8].try_into().unwrap_or([0; 8])) % period;
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
            commitments: CommitmentBits::default(),
            max_commitments,
            redownloaded: VecDeque::new(),
            redownload_last_height: chain_start.height,
            redownload_last_hash: chain_start.hash,
            redownload_last_bits: chain_start.header.bits,
            redownload_first_prev_hash: chain_start.hash,
            redownload_work: chain_start.chain_work,
            process_all_remaining_headers: false,
            commit_offset: u32::try_from(commit_offset).unwrap_or(0),
            final_height: chain_start.height,
            chain_start,
            params,
            minimum_work,
            salt,
        }
    }

    pub fn process(
        &mut self,
        headers: &[Header],
        full_message: bool,
    ) -> Result<HeaderSyncResult, HeaderSyncError> {
        if headers.is_empty() {
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
            if self.commitments.live_bits() > self.max_commitments {
                return Err(HeaderSyncError::MaxCommitments { height });
            }
        }
        self.current_work = self.current_work.saturating_add(block_work(header));
        self.last_header_hash = hash;
        self.last_header_bits = bits;
        self.current_height = height;
        Ok(())
    }

    fn begin_redownload(&mut self) {
        self.redownloaded.clear();
        self.redownload_last_height = self.chain_start.height;
        self.redownload_last_hash = self.chain_start.hash;
        self.redownload_first_prev_hash = self.chain_start.hash;
        self.redownload_work = self.chain_start.chain_work;
        self.process_all_remaining_headers = false;
        self.phase = HeadersSyncPhase::Redownload;
    }

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

    #[must_use]
    pub(crate) fn next_locator(&self) -> Vec<Hash256> {
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

    #[must_use]
    pub(crate) const fn sync_height(&self) -> u32 {
        match self.phase {
            HeadersSyncPhase::Presync => self.current_height,
            HeadersSyncPhase::Redownload => self.redownload_last_height,
            HeadersSyncPhase::Final => self.final_height,
        }
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) const fn phase(&self) -> HeadersSyncPhase {
        self.phase
    }

    pub fn finalize(&mut self) {
        if self.phase == HeadersSyncPhase::Final {
            return;
        }
        self.commitments.clear();
        self.redownloaded.clear();
        self.redownload_last_hash = Hash256::default();
        self.redownload_first_prev_hash = Hash256::default();
        self.process_all_remaining_headers = false;
        self.final_height = self.sync_height();
        self.current_height = 0;
        self.phase = HeadersSyncPhase::Final;
    }

    pub(super) fn commitment_bit(&self, hash: Hash256) -> bool {
        let mut digest = Sha256::new();
        digest.update(self.salt);
        digest.update(hash.as_byte_array());
        digest.finalize()[0] & 1 == 1
    }

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
