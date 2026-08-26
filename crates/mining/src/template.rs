use std::collections::BTreeMap;
use std::sync::Arc;

use bitcoin::hashes::{Hash as _, HashEngine as _, sha256d};
use bitcoin::{ScriptBuf, Transaction, Txid, Wtxid};
use bitcoin_rs_mempool::MempoolMiningSnapshot;
use bitcoin_rs_primitives::{Hash256, Network};

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
    pub tx: Arc<Transaction>,
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
    pub coinbase: Transaction,
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

/// Assembles one transport-neutral candidate from a chain context and snapshot.
///
/// Selection is package-atomic, topologically ordered, final under
/// `context.locktime_cutoff`, and bounded by weight, serialized size, and
/// sigop cost. Modified fees rank packages; actual fees fund the coinbase.
pub fn assemble_candidate(
    context: &CandidateContext,
    snapshot: &MempoolMiningSnapshot,
    payout: &ScriptBuf,
) -> Result<Candidate, MiningError> {
    let dummy_commitment = Hash256::from_le_bytes(&[0_u8; 32]);
    let reservation = build_coinbase(
        context.height,
        context.network.subsidy_halving_interval(),
        0,
        payout.clone(),
        context.segwit_active.then_some(&dummy_commitment),
    )?;
    let reserved_weight = reservation.weight().to_wu();
    let reserved_size = u64::try_from(reservation.total_size()).map_err(|_| {
        MiningError::CandidateScalarOverflow {
            field: "coinbase size",
        }
    })?;
    let reserved_sigops = u64::try_from(reservation.total_sigop_cost(|_| None)).map_err(|_| {
        MiningError::CandidateScalarOverflow {
            field: "coinbase sigops",
        }
    })?;

    let (ordered, fees, selected_weight, selected_size, selected_sigops) = select_packages(
        context,
        snapshot,
        reserved_weight,
        reserved_size,
        reserved_sigops,
    )?;

    let (witness_merkle_root, witness_reserved_value, witness_commitment) = if context.segwit_active
    {
        let root = witness_merkle_root(snapshot, &ordered)?;
        let commitment = witness_commitment_hash(&root, &WITNESS_RESERVED_VALUE);
        (Some(root), Some(WITNESS_RESERVED_VALUE), Some(commitment))
    } else {
        (None, None, None)
    };

    let coinbase = build_coinbase(
        context.height,
        context.network.subsidy_halving_interval(),
        fees,
        payout.clone(),
        witness_commitment.as_ref(),
    )?;
    let coinbase_value = coinbase
        .output
        .first()
        .map(|output| output.value.to_sat())
        .ok_or(MiningError::CoinbaseValueOverflow)?;
    // Fees change a fixed-width amount and the witness commitment replaces a
    // fixed-width hash, so the reservation and final coinbase have the same
    // weight, serialized size, and sigop cost.

    let transactions = candidate_transactions(snapshot, &ordered)?;

    let weight = reserved_weight
        .checked_add(selected_weight)
        .ok_or(MiningError::CandidateScalarOverflow { field: "weight" })?;
    let size = reserved_size
        .checked_add(selected_size)
        .ok_or(MiningError::CandidateScalarOverflow { field: "size" })?;
    let sigop_cost = reserved_sigops.checked_add(selected_sigops).ok_or(
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
        fees,
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

fn depends(tx: &Transaction, tx_positions: &BTreeMap<Txid, u32>) -> Vec<u32> {
    let mut depends = tx
        .input
        .iter()
        .filter_map(|input| tx_positions.get(&input.previous_output.txid).copied())
        .collect::<Vec<_>>();
    depends.sort_unstable();
    depends.dedup();
    depends
}

fn witness_merkle_root(
    snapshot: &MempoolMiningSnapshot,
    ordered: &[usize],
) -> Result<Hash256, MiningError> {
    let mut leaves = Vec::with_capacity(ordered.len().saturating_add(1));
    // BIP141: the coinbase wtxid leaf is the all-zero hash, not the real wtxid.
    leaves.push(Wtxid::all_zeros());
    for &index in ordered {
        leaves.push(snapshot.entries[index].wtxid);
    }
    let root = bitcoin::merkle_tree::calculate_root(leaves.into_iter()).ok_or(
        MiningError::CandidateScalarOverflow {
            field: "witness merkle root",
        },
    )?;
    Ok(Hash256::from_le_bytes(root.as_byte_array()))
}

fn witness_commitment_hash(witness_merkle_root: &Hash256, reserved: &[u8; 32]) -> Hash256 {
    let mut engine = sha256d::Hash::engine();
    engine.input(witness_merkle_root.as_byte_array());
    engine.input(reserved);
    let hash = sha256d::Hash::from_engine(engine);
    Hash256::from_le_bytes(hash.as_byte_array())
}
