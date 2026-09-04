use std::collections::BTreeMap;
use std::sync::Arc;

use bitcoin_rs_chain::compact_is_met_by;
use bitcoin_rs_mempool::MempoolMiningSnapshot;
use bitcoin_rs_primitives::{
    Block, BlockHash, Hash256, Header, Network, Tx, Txid, Wtxid, encode::double_sha256,
};

use crate::MiningError;
use crate::coinbase::{WITNESS_RESERVED_VALUE, build_coinbase};
use crate::policy::{modified_fee, select_packages};

/// Chain and limit facts required to assemble one candidate.
///
/// Callers derive these from the C1 mining context plus configured block limits.
/// The mining crate never takes node locks or re-derives consensus state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateContext {
    /// Parent tip hash in consensus little-endian storage order.
    pub previous_block_hash: Hash256,
    /// Height the candidate would have.
    pub height: u32,
    /// Versionbits candidate version.
    pub version: i32,
    /// Compact target the candidate header must carry (`nBits`).
    pub bits: u32,
    /// Earliest legal timestamp (previous MTP + 1).
    pub min_time: u32,
    /// Candidate header time used for the template clock.
    pub current_time: u32,
    /// BIP113 locktime cutoff already resolved by the caller.
    pub locktime_cutoff: u32,
    /// Network whose subsidy schedule applies.
    pub network: Network,
    /// Whether CSV (BIP68/112/113) is active at `height`.
    pub csv_active: bool,
    /// Whether BIP141 is active at `height`.
    pub segwit_active: bool,
    /// Maximum candidate block weight, including the coinbase.
    pub max_weight: u64,
    /// Maximum serialized block size, including the coinbase.
    pub max_size: u64,
    /// Maximum sigop cost, including the coinbase reservation.
    pub max_sigops: u64,
}

/// Deterministic generation identity for a captured tip and mempool sequence.
///
/// Matches Bitcoin Core's `longpollid` encoding: tip hash as big-endian hex
/// concatenated with the decimal mempool sequence.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct TemplateId(String);

impl TemplateId {
    /// Builds the identity for `previous_block_hash` and `mempool_sequence`.
    #[must_use]
    pub fn new(previous_block_hash: &Hash256, mempool_sequence: u64) -> Self {
        Self(format!(
            "{}{mempool_sequence}",
            previous_block_hash.to_string_be()
        ))
    }

    /// Returns the opaque identity string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for TemplateId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl core::fmt::Display for TemplateId {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One non-coinbase transaction selected into a candidate.
#[derive(Clone, Debug)]
pub struct CandidateTransaction {
    /// Transaction payload shared with the mempool snapshot.
    pub tx: Arc<Tx>,
    /// Transaction id.
    pub txid: Txid,
    /// Witness transaction id.
    pub wtxid: Wtxid,
    /// Actual fee in satoshis.
    pub fee: u64,
    /// Signed mining-only fee overlay.
    pub fee_delta: i64,
    /// Modified fee (`fee + fee_delta`) used for ranking overlays.
    pub modified_fee: i128,
    /// Consensus sigop cost.
    pub sigop_cost: u32,
    /// Consensus transaction weight.
    pub weight: u64,
    /// Consensus serialization size including witness.
    pub size: u32,
    /// One-based indexes of in-candidate ancestors.
    pub depends: Vec<u32>,
}

/// Transport-neutral assembled block candidate.
#[derive(Clone, Debug)]
pub struct Candidate {
    /// Generation identity for this tip and mempool sequence.
    pub template_id: TemplateId,
    /// Parent tip hash.
    pub previous_block_hash: Hash256,
    /// Candidate height.
    pub height: u32,
    /// Candidate version.
    pub version: i32,
    /// Compact target bits.
    pub bits: u32,
    /// Minimum legal timestamp.
    pub min_time: u32,
    /// Candidate creation time.
    pub current_time: u32,
    /// Whether CSV (BIP68/112/113) is active at this candidate's height.
    pub csv_active: bool,
    /// Whether BIP141 is active at this candidate's height.
    pub segwit_active: bool,
    /// Configured weight limit.
    pub max_weight: u64,
    /// Configured serialized-size limit.
    pub max_size: u64,
    /// Configured sigop-cost limit.
    pub max_sigops: u64,
    /// Mempool sequence captured with the snapshot.
    pub mempool_sequence: u64,
    /// Fully constructed coinbase, including the witness commitment when active.
    pub coinbase: Tx,
    /// Coinbase output value: subsidy plus actual selected fees.
    pub coinbase_value: u64,
    /// Sum of actual fees from selected non-coinbase transactions.
    pub fees: u64,
    /// Total block weight including the coinbase.
    pub weight: u64,
    /// Total serialized size including the coinbase.
    pub size: u64,
    /// Total sigop cost including the coinbase.
    pub sigop_cost: u64,
    /// Selected non-coinbase transactions in topological order.
    pub transactions: Vec<CandidateTransaction>,
    /// Witness merkle root over `[0, wtxid_1, …]` when `SegWit` is active.
    pub witness_merkle_root: Option<Hash256>,
    /// Reserved value committed in the coinbase witness.
    pub witness_reserved_value: Option<[u8; 32]>,
    /// `SHA256D(witness_merkle_root || witness_reserved_value)` commitment hash.
    pub witness_commitment: Option<Hash256>,
}

impl Candidate {
    /// Builds the unsolved block this candidate describes.
    ///
    /// Coinbase is first, then the selected transactions in topological order.
    /// The header carries the candidate version, parent, merkle root, time,
    /// and compact target with a zero nonce.
    #[must_use]
    pub fn into_unsolved_block(&self) -> Block {
        let mut txs = Vec::with_capacity(self.transactions.len().saturating_add(1));
        txs.push(self.coinbase.clone());
        txs.extend(self.transactions.iter().map(|tx| (*tx.tx).clone()));
        let merkle_root = merkle_root_from_txids(txs.iter().map(Tx::txid));
        Block {
            header: Header {
                version: self.version,
                prev_blockhash: BlockHash::from(self.previous_block_hash),
                merkle_root,
                time: self.current_time.max(self.min_time),
                bits: self.bits,
                nonce: 0,
            },
            txs,
        }
    }

    /// Assembles the unsolved block and searches nonces until the compact
    /// target is met or `max_tries` is exhausted.
    pub fn solve(&self, max_tries: u64) -> Result<Block, MiningError> {
        let mut block = self.into_unsolved_block();
        solve_block(&mut block, max_tries)?;
        Ok(block)
    }
}

/// Searches `block.header.nonce` until the compact target is met.
pub fn solve_block(block: &mut Block, max_tries: u64) -> Result<(), MiningError> {
    for _ in 0..max_tries {
        let hash = Hash256::from(block.header.compute_hash());
        if compact_is_met_by(block.header.bits, hash) {
            return Ok(());
        }
        block.header.nonce = block.header.nonce.wrapping_add(1);
    }
    Err(MiningError::Unsolved { tries: max_tries })
}

/// Assembles one transport-neutral candidate from a chain context and snapshot.
///
/// Selection is package-atomic, topologically ordered, final under
/// `context.locktime_cutoff`, and bounded by weight, serialized size, and
/// sigop cost. Modified fees rank packages; actual fees fund the coinbase.
pub fn assemble_candidate(
    context: &CandidateContext,
    snapshot: &MempoolMiningSnapshot,
    payout: &[u8],
) -> Result<Candidate, MiningError> {
    let reservation = coinbase_reservation(context, payout)?;
    let (ordered, fees, weight, size, sigops) = select_packages(
        context,
        snapshot,
        reservation.weight,
        reservation.size,
        reservation.sigops,
    )?;
    let body = SelectedBody {
        ordered,
        fees,
        weight,
        size,
        sigops,
    };
    finish_candidate(context, snapshot, payout, &body, reservation)
}

/// Assembles a candidate whose non-coinbase body is `snapshot.entries` in order.
///
/// Used by `generateblock`: the listed transactions are the block, not a
/// package-selected subset. Resource overflows fail rather than skip.
pub fn assemble_ordered_candidate(
    context: &CandidateContext,
    snapshot: &MempoolMiningSnapshot,
    payout: &[u8],
) -> Result<Candidate, MiningError> {
    let reservation = coinbase_reservation(context, payout)?;
    let body = exact_order(context, snapshot, reservation)?;
    finish_candidate(context, snapshot, payout, &body, reservation)
}

#[derive(Clone, Copy)]
struct CoinbaseReservation {
    weight: u64,
    size: u64,
    sigops: u64,
}

struct SelectedBody {
    ordered: Vec<usize>,
    fees: u64,
    weight: u64,
    size: u64,
    sigops: u64,
}

fn coinbase_reservation(
    context: &CandidateContext,
    payout: &[u8],
) -> Result<CoinbaseReservation, MiningError> {
    let dummy_commitment = Hash256::from_le_bytes(&[0_u8; 32]);
    let reservation = build_coinbase(
        context.height,
        context.network.subsidy_halving_interval(),
        0,
        payout.to_vec(),
        context.segwit_active.then_some(&dummy_commitment),
    )?;
    let size = u64::try_from(reservation.total_size()).map_err(|_| {
        MiningError::CandidateScalarOverflow {
            field: "coinbase size",
        }
    })?;
    Ok(CoinbaseReservation {
        weight: reservation.weight(),
        size,
        sigops: u64::from(bitcoin_rs_script::count_tx_legacy(&reservation)),
    })
}

fn exact_order(
    context: &CandidateContext,
    snapshot: &MempoolMiningSnapshot,
    reservation: CoinbaseReservation,
) -> Result<SelectedBody, MiningError> {
    if reservation.weight > context.max_weight {
        return Err(MiningError::CapacityExhausted { field: "weight" });
    }
    if reservation.size > context.max_size {
        return Err(MiningError::CapacityExhausted { field: "size" });
    }
    if reservation.sigops > context.max_sigops {
        return Err(MiningError::CapacityExhausted { field: "sigops" });
    }

    // Core's generateblock does not pay fees for explicitly ordered transactions.
      let fees = 0_u64;
    let mut weight = 0_u64;
    let mut size = 0_u64;
    let mut sigops = 0_u64;
    for entry in &snapshot.entries {
        fees = fees
            .checked_add(entry.fee)
            .ok_or(MiningError::FeeOverflow)?;
        weight = weight
            .checked_add(entry.weight)
            .ok_or(MiningError::CandidateScalarOverflow { field: "weight" })?;
        size = size
            .checked_add(u64::from(entry.size))
            .ok_or(MiningError::CandidateScalarOverflow { field: "size" })?;
        sigops = sigops.checked_add(u64::from(entry.sigop_cost)).ok_or(
            MiningError::CandidateScalarOverflow {
                field: "sigop cost",
            },
        )?;
    }
    if reservation.weight.saturating_add(weight) > context.max_weight {
        return Err(MiningError::CapacityExhausted { field: "weight" });
    }
    if reservation.size.saturating_add(size) > context.max_size {
        return Err(MiningError::CapacityExhausted { field: "size" });
    }
    if reservation.sigops.saturating_add(sigops) > context.max_sigops {
        return Err(MiningError::CapacityExhausted { field: "sigops" });
    }
    Ok(SelectedBody {
        ordered: (0..snapshot.entries.len()).collect(),
        fees,
        weight,
        size,
        sigops,
    })
}

fn finish_candidate(
    context: &CandidateContext,
    snapshot: &MempoolMiningSnapshot,
    payout: &[u8],
    body: &SelectedBody,
    reservation: CoinbaseReservation,
) -> Result<Candidate, MiningError> {
    let (witness_merkle_root, witness_reserved_value, witness_commitment) = if context.segwit_active
    {
        let root = witness_merkle_root(snapshot, &body.ordered)?;
        let commitment = witness_commitment_hash(&root, &WITNESS_RESERVED_VALUE);
        (Some(root), Some(WITNESS_RESERVED_VALUE), Some(commitment))
    } else {
        (None, None, None)
    };

    let coinbase = build_coinbase(
        context.height,
        context.network.subsidy_halving_interval(),
        body.fees,
        payout.to_vec(),
        witness_commitment.as_ref(),
    )?;
    let coinbase_value = coinbase
        .outputs
        .first()
        .map(|output| output.value)
        .ok_or(MiningError::CoinbaseValueOverflow)?;
    // Fees change a fixed-width amount and the witness commitment replaces a
    // fixed-width hash, so the reservation and final coinbase have the same
    // weight, serialized size, and sigop cost.

    let transactions = candidate_transactions(snapshot, &body.ordered)?;

    let weight = reservation
        .weight
        .checked_add(body.weight)
        .ok_or(MiningError::CandidateScalarOverflow { field: "weight" })?;
    let size = reservation
        .size
        .checked_add(body.size)
        .ok_or(MiningError::CandidateScalarOverflow { field: "size" })?;
    let sigop_cost = reservation.sigops.checked_add(body.sigops).ok_or(
        MiningError::CandidateScalarOverflow {
            field: "sigop cost",
        },
    )?;

    Ok(Candidate {
        template_id: TemplateId::new(&context.previous_block_hash, snapshot.sequence),
        previous_block_hash: context.previous_block_hash,
        height: context.height,
        version: context.version,
        bits: context.bits,
        min_time: context.min_time,
        current_time: context.current_time,
        csv_active: context.csv_active,
        segwit_active: context.segwit_active,
        max_weight: context.max_weight,
        max_size: context.max_size,
        max_sigops: context.max_sigops,
        mempool_sequence: snapshot.sequence,
        coinbase,
        coinbase_value,
        fees: body.fees,
        weight,
        size,
        sigop_cost,
        transactions,
        witness_merkle_root,
        witness_reserved_value,
        witness_commitment,
    })
}

fn candidate_transactions(
    snapshot: &MempoolMiningSnapshot,
    ordered: &[usize],
) -> Result<Vec<CandidateTransaction>, MiningError> {
    let mut tx_positions = BTreeMap::<Txid, u32>::new();
    for (offset, &index) in ordered.iter().enumerate() {
        let position = u32::try_from(offset.saturating_add(1)).map_err(|_| {
            MiningError::CandidateScalarOverflow {
                field: "transaction index",
            }
        })?;
        tx_positions.insert(snapshot.entries[index].txid, position);
    }

    let mut transactions = Vec::with_capacity(ordered.len());
    for &index in ordered {
        let entry = &snapshot.entries[index];
        transactions.push(CandidateTransaction {
            tx: Arc::clone(&entry.tx),
            txid: entry.txid,
            wtxid: entry.wtxid,
            fee: entry.fee,
            fee_delta: entry.fee_delta,
            modified_fee: modified_fee(entry),
            sigop_cost: entry.sigop_cost,
            weight: entry.weight,
            size: entry.size,
            depends: depends(&entry.tx, &tx_positions),
        });
    }
    Ok(transactions)
}

fn depends(tx: &Tx, tx_positions: &BTreeMap<Txid, u32>) -> Vec<u32> {
    let mut depends = tx
        .inputs
        .iter()
        .filter_map(|input| tx_positions.get(&input.previous_output.txid).copied())
        .collect::<Vec<_>>();
    depends.sort_unstable();
    depends.dedup();
    depends
}

/// BIP141 witness merkle root: pairwise `SHA256d` fold duplicating the last leaf
/// on odd levels. The coinbase contributes the all-zero wtxid leaf.
fn witness_merkle_root(
    snapshot: &MempoolMiningSnapshot,
    ordered: &[usize],
) -> Result<Hash256, MiningError> {
    let mut leaves = Vec::with_capacity(ordered.len().saturating_add(1));
    // BIP141: the coinbase wtxid leaf is the all-zero hash, not the real wtxid.
    leaves.push([0_u8; 32]);
    for &index in ordered {
        leaves.push(*snapshot.entries[index].wtxid.as_bytes());
    }
    merkle_root_from_leaves(leaves)
}

fn merkle_root_from_txids(txids: impl IntoIterator<Item = Txid>) -> Hash256 {
    let leaves = txids
        .into_iter()
        .map(|txid| *txid.as_bytes())
        .collect::<Vec<_>>();
    merkle_root_from_leaves(leaves).unwrap_or_else(|_| Hash256::from_le_bytes(&[0_u8; 32]))
}

fn merkle_root_from_leaves(mut leaves: Vec<[u8; 32]>) -> Result<Hash256, MiningError> {
    if leaves.is_empty() {
        return Err(MiningError::CandidateScalarOverflow {
            field: "merkle root",
        });
    }

    while leaves.len() > 1 {
        let original_len = leaves.len();
        let mut next = Vec::with_capacity(original_len.div_ceil(2));
        for pos in 0..original_len.div_ceil(2) {
            let left = leaves[2 * pos];
            let right = leaves[(2 * pos + 1).min(original_len - 1)];
            let mut pair = [0_u8; 64];
            pair[..32].copy_from_slice(&left);
            pair[32..].copy_from_slice(&right);
            next.push(*double_sha256(&pair).as_byte_array());
        }
        leaves = next;
    }

    Ok(Hash256::from_le_bytes(&leaves[0]))
}

fn witness_commitment_hash(witness_merkle_root: &Hash256, reserved: &[u8; 32]) -> Hash256 {
    let mut pair = [0_u8; 64];
    pair[..32].copy_from_slice(witness_merkle_root.as_byte_array());
    pair[32..].copy_from_slice(reserved);
    double_sha256(&pair)
}
