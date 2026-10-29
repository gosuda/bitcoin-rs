use std::sync::Arc;

use bitcoin_rs_chain::compact_is_met_by;
use bitcoin_rs_consensus::{compute_merkle_root, transaction_sigop_cost};
use bitcoin_rs_mempool::{BlockRemovalPlan, Mempool, MempoolMiningSnapshot};
use bitcoin_rs_primitives::{
    Block, BlockHash, CompactTarget, Hash256, Header, Network, Tx, Txid, Wtxid,
    encode::{consensus_bytes, double_sha256, hex_encode},
    varint,
};
use bitcoin_rs_script::VerifyFlags;
use hashbrown::HashMap;

use crate::MiningError;
use crate::coinbase::{WITNESS_RESERVED_VALUE, build_coinbase};
use crate::policy::select_packages;

/// Chain and limit facts required to assemble one candidate.
#[derive(Clone, Debug)]
pub struct CandidateContext {
    pub previous_block_hash: Hash256,
    pub height: u32,
    pub version: i32,
    pub bits: CompactTarget,
    pub min_time: u32,
    pub current_time: u32,
    pub locktime_cutoff: u32,
    pub staged_parent_mtp: u32,
    pub network: Network,
    pub csv_active: bool,
    pub segwit_active: bool,
    pub max_weight: u64,
    pub max_size: u64,
    pub max_sigops: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct CoinbaseBudget {
    pub additional_size: u32,
    pub additional_sigops: u16,
}

impl CoinbaseBudget {
    /// Consensus limit on a coinbase scriptSig length (`bad-cb-length`).
    pub const MAX_SCRIPT_SIG_LEN: usize = 100;
    pub const MIN_SCRIPT_SIG_LEN: usize = 2;
    pub(crate) fn split_qualifier(id: &str) -> Option<(&str, Option<Self>)> {
        let Some((ordinary, qualifier)) = id.split_once('@') else {
            return Some((id, None));
        };
        let (size, sigops) = qualifier.strip_prefix("cb")?.split_once('.')?;
        let budget = Self {
            additional_size: canonical_decimal(size)?,
            additional_sigops: canonical_decimal(sigops)?,
        };
        Some((ordinary, Some(budget)))
    }
}

fn canonical_decimal<T: std::str::FromStr>(text: &str) -> Option<T> {
    let canonical = match text.as_bytes() {
        [b'0'] => true,
        [b'1'..=b'9', rest @ ..] => rest.iter().all(u8::is_ascii_digit),
        _ => false,
    };
    if canonical { text.parse().ok() } else { None }
}

/// Deterministic generation identity for a tip, membership and fee revision.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct TemplateId(String);

impl TemplateId {
    #[must_use]
    pub fn new(previous_block_hash: &Hash256, mempool_sequence: u64) -> Self {
        Self::with_fee_revision(previous_block_hash, mempool_sequence, 0)
    }

    #[must_use]
    pub fn with_fee_revision(
        previous_block_hash: &Hash256,
        mempool_sequence: u64,
        fee_delta_sequence: u64,
    ) -> Self {
        let mut id = format!("{}{mempool_sequence}", previous_block_hash.to_string_be());
        if fee_delta_sequence != 0 {
            use std::fmt::Write as _;
            let _ = write!(id, ":{fee_delta_sequence}");
        }
        Self(id)
    }

    #[must_use]
    pub(crate) fn qualified(mut self, budget: Option<CoinbaseBudget>) -> Self {
        if let Some(budget) = budget {
            use std::fmt::Write as _;
            let _ = write!(
                self.0,
                "@cb{}.{}",
                budget.additional_size, budget.additional_sigops
            );
        }
        self
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug)]
pub struct CandidateTransaction {
    pub tx: Arc<Tx>,
    pub txid: Txid,
    pub wtxid: Wtxid,
    pub fee: u64,
    pub sigop_cost: u32,
    pub weight: u64,
    pub depends: Vec<u32>,
    pub data_hex: String,
}

#[derive(Debug)]
pub struct Candidate {
    pub template_id: TemplateId,
    pub previous_block_hash: Hash256,
    pub height: u32,
    pub version: i32,
    pub bits: CompactTarget,
    pub min_time: u32,
    pub current_time: u32,
    pub csv_active: bool,
    pub segwit_active: bool,
    pub max_weight: u64,
    pub max_size: u64,
    pub max_sigops: u64,
    pub mempool_sequence: u64,
    pub coinbase: Tx,
    pub coinbase_value: u64,
    pub weight: u64,
    pub transactions: Vec<CandidateTransaction>,
    pub witness_commitment: Option<Hash256>,
}

impl Candidate {
    pub fn into_unsolved_block(&self) -> Result<Block, MiningError> {
        let mut txs = Vec::with_capacity(self.transactions.len().saturating_add(1));
        txs.push(self.coinbase.clone());
        txs.extend(self.transactions.iter().map(|tx| (*tx.tx).clone()));
        let mut leaves = core::iter::once(self.coinbase.txid())
            .chain(self.transactions.iter().map(|tx| tx.tx.txid()))
            .map(|txid| *txid.as_bytes())
            .collect::<Vec<_>>();
        let merkle_root = merkle_root_from_leaves(&mut leaves)?;
        Ok(Block {
            header: Header {
                version: self.version,
                prev_blockhash: BlockHash::from(self.previous_block_hash),
                merkle_root,
                time: self.current_time.max(self.min_time),
                bits: self.bits,
                nonce: 0,
            },
            txs,
        })
    }

    pub fn admits(&self, budget: CoinbaseBudget) -> Result<(), MiningError> {
        self.block_costs()?
            .checked_add(coinbase_growth(&self.coinbase, budget)?)?
            .check(self.max_weight, self.max_size, self.max_sigops)
    }

    fn block_costs(&self) -> Result<FixedReservation, MiningError> {
        let mut size = checked_sum(
            widen(Header::LEN),
            transaction_count_size(self.transactions.len())?,
            "size",
        )?;
        size = checked_sum(size, widen(self.coinbase.total_size()), "size")?;
        let mut sigops = u64::from(transaction_sigop_cost(
            &self.coinbase,
            &[],
            VerifyFlags::NONE,
        ));
        for transaction in &self.transactions {
            size = checked_sum(size, widen(transaction.tx.total_size()), "size")?;
            sigops = checked_sum(sigops, u64::from(transaction.sigop_cost), "sigop cost")?;
        }
        Ok(FixedReservation {
            weight: self.weight,
            size,
            sigops,
        })
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

pub fn assemble_candidate(
    context: &CandidateContext,
    pool: &Mempool,
    payout: &[u8],
) -> Result<Candidate, MiningError> {
    let body = select_template_body(pool, context, payout, None)?;
    finish_candidate(context, &body, payout)
}

/// [`MiningError::CapacityExhausted`] names the dimension in which the header,
/// coinbase, and any budgeted growth already exceed the context's limit, before
/// any transaction is considered.
pub fn select_template_body(
    pool: &Mempool,
    context: &CandidateContext,
    payout: &[u8],
    budget: Option<CoinbaseBudget>,
) -> Result<SelectedBody, MiningError> {
    let reservation = reserve(context, payout, budget)?;
    let sequences = (pool.sequence_number(), pool.fee_delta_sequence_number());
    let body = select_packages(
        context,
        pool,
        pool.chunks_by_feerate(),
        sequences,
        reservation,
    )?;
    Ok(body)
}

/// Selects the template body as if `plan` had applied, without mutating the pool.
pub fn select_template_body_after(
    pool: &Mempool,
    plan: &BlockRemovalPlan,
    context: &CandidateContext,
    payout: &[u8],
) -> Result<SelectedBody, MiningError> {
    let reservation = reserve(context, payout, None)?;
    let projected = pool.chunks_after(plan);
    let removals =
        u64::try_from(plan.removals.len()).map_err(|_| MiningError::CandidateScalarOverflow {
            field: "transaction count",
        })?;
    let sequences = (
        pool.sequence_number().wrapping_add(removals),
        pool.fee_delta_sequence_number()
            .wrapping_add(plan.fee_deltas_cleared),
    );
    select_packages(context, pool, projected.iter(), sequences, reservation)
}

/// Assembles a candidate whose non-coinbase body is `snapshot.entries` in order.
pub fn assemble_ordered_candidate(
    context: &CandidateContext,
    snapshot: &MempoolMiningSnapshot,
    payout: &[u8],
) -> Result<Candidate, MiningError> {
    let reservation = reserve(context, payout, None)?.fixed;
    let body = exact_order(context, snapshot, reservation)?;
    finish_candidate(context, &body, payout)
}

/// Weight, serialized size, and sigop cost of one part of a block. The fixed
/// block header and coinbase are reserved before selecting the body.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FixedReservation {
    pub(crate) weight: u64,
    pub(crate) size: u64,
    pub(crate) sigops: u64,
}

impl FixedReservation {
    pub(crate) const ZERO: Self = Self {
        weight: 0,
        size: 0,
        sigops: 0,
    };

    pub(crate) fn checked_add(self, other: Self) -> Result<Self, MiningError> {
        Ok(Self {
            weight: checked_sum(self.weight, other.weight, "weight")?,
            size: checked_sum(self.size, other.size, "size")?,
            sigops: checked_sum(self.sigops, other.sigops, "sigop cost")?,
        })
    }

    pub(crate) fn check(
        self,
        max_weight: u64,
        max_size: u64,
        max_sigops: u64,
    ) -> Result<(), MiningError> {
        if self.weight > max_weight {
            return Err(MiningError::CapacityExhausted { field: "weight" });
        }
        if self.size > max_size {
            return Err(MiningError::CapacityExhausted { field: "size" });
        }
        if self.sigops > max_sigops {
            return Err(MiningError::CapacityExhausted { field: "sigops" });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Reservation {
    pub(crate) fixed: FixedReservation,
    pub(crate) growth: FixedReservation,
    pub(crate) budget: Option<CoinbaseBudget>,
}

#[derive(Debug)]
pub struct SelectedTx {
    pub tx: Arc<Tx>,
    pub txid: Txid,
    pub wtxid: Wtxid,
    pub fee: u64,
    pub sigop_cost: u32,
    pub weight: u64,
}

/// Dependency-closed body selected under the pool read guard.
#[derive(Debug)]
pub struct SelectedBody {
    pub sequence: u64,
    pub fee_delta_sequence: u64,
    pub transactions: Vec<SelectedTx>,
    pub fees: u64,
    pub weight: u64,
    pub(crate) reservation: FixedReservation,
    pub(crate) budget: Option<CoinbaseBudget>,
}

fn checked_sum(left: u64, right: u64, field: &'static str) -> Result<u64, MiningError> {
    left.checked_add(right)
        .ok_or(MiningError::CandidateScalarOverflow { field })
}

fn widen(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

pub(crate) fn transaction_count_size(body_count: usize) -> Result<u64, MiningError> {
    let overflow = MiningError::CandidateScalarOverflow {
        field: "transaction count",
    };
    let count = u64::try_from(body_count)
        .ok()
        .and_then(|count| count.checked_add(1))
        .ok_or(overflow)?;
    Ok(u64::try_from(varint::encoded_len(count)).unwrap_or(u64::MAX))
}

fn reserve(
    context: &CandidateContext,
    payout: &[u8],
    budget: Option<CoinbaseBudget>,
) -> Result<Reservation, MiningError> {
    let dummy_commitment = Hash256::from_le_bytes(&[0_u8; 32]);
    let reservation = build_coinbase(
        context.height,
        context.network.subsidy_halving_interval(),
        0,
        payout,
        context.segwit_active.then_some(&dummy_commitment),
    )?;
    let size = u64::try_from(reservation.total_size()).map_err(|_| {
        MiningError::CandidateScalarOverflow {
            field: "coinbase size",
        }
    })?;
    let header_size = u64::try_from(Header::LEN).unwrap_or(u64::MAX);
    let fixed = FixedReservation {
        weight: reservation
            .weight()
            .checked_add(header_size * 4)
            .ok_or(MiningError::CandidateScalarOverflow { field: "weight" })?,
        size: size
            .checked_add(header_size)
            .ok_or(MiningError::CandidateScalarOverflow { field: "size" })?,
        sigops: u64::from(transaction_sigop_cost(&reservation, &[], VerifyFlags::NONE)),
    };
    let growth = budget
        .map(|budget| coinbase_growth(&reservation, budget))
        .transpose()?
        .unwrap_or(FixedReservation::ZERO);
    Ok(Reservation {
        fixed,
        growth,
        budget,
    })
}

const MIN_TXOUT_SIZE: u32 = 9;

fn coinbase_growth(coinbase: &Tx, budget: CoinbaseBudget) -> Result<FixedReservation, MiningError> {
    let script_sig_len = coinbase
        .inputs
        .first()
        .map_or(0, |input| input.script_sig.len());
    let script_growth = widen(CoinbaseBudget::MAX_SCRIPT_SIG_LEN.saturating_sub(script_sig_len));
    let outputs = widen(coinbase.outputs.len());
    let added_outputs = u64::from(budget.additional_size / MIN_TXOUT_SIZE);
    let count_growth = widen(
        varint::encoded_len(outputs.saturating_add(added_outputs)) - varint::encoded_len(outputs),
    );
    let size = checked_sum(
        checked_sum(u64::from(budget.additional_size), script_growth, "size")?,
        count_growth,
        "size",
    )?;
    let weight = size
        .checked_mul(4)
        .ok_or(MiningError::CandidateScalarOverflow { field: "weight" })?;
    Ok(FixedReservation {
        weight,
        size,
        sigops: checked_sum(
            script_growth * 80,
            u64::from(budget.additional_sigops),
            "sigops",
        )?,
    })
}

fn exact_order(
    context: &CandidateContext,
    snapshot: &MempoolMiningSnapshot,
    reservation: FixedReservation,
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

    let mut size = transaction_count_size(snapshot.entries.len())?;
    let mut weight = size * 4;
    let mut sigops = 0_u64;
    for entry in &snapshot.entries {
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
    let total_weight = reservation
        .weight
        .checked_add(weight)
        .ok_or(MiningError::CandidateScalarOverflow { field: "weight" })?;
    let total_size = reservation
        .size
        .checked_add(size)
        .ok_or(MiningError::CandidateScalarOverflow { field: "size" })?;
    if total_weight > context.max_weight {
        return Err(MiningError::CapacityExhausted { field: "weight" });
    }
    if total_size > context.max_size {
        return Err(MiningError::CapacityExhausted { field: "size" });
    }
    if reservation.sigops.saturating_add(sigops) > context.max_sigops {
        return Err(MiningError::CapacityExhausted { field: "sigops" });
    }
    let transactions = snapshot
        .entries
        .iter()
        .map(|entry| SelectedTx {
            tx: Arc::clone(&entry.tx),
            txid: entry.txid,
            wtxid: entry.wtxid,
            fee: entry.fee,
            sigop_cost: entry.sigop_cost,
            weight: entry.weight,
        })
        .collect();
    Ok(SelectedBody {
        sequence: snapshot.sequence,
        fee_delta_sequence: snapshot.fee_delta_sequence,
        transactions,
        fees: 0,
        weight,
        reservation,
        budget: None,
    })
}

pub(crate) fn finish_candidate(
    context: &CandidateContext,
    body: &SelectedBody,
    payout: &[u8],
) -> Result<Candidate, MiningError> {
    let witness_commitment = if context.segwit_active {
        let root = witness_merkle_root(&body.transactions)?;
        Some(witness_commitment_hash(&root, &WITNESS_RESERVED_VALUE))
    } else {
        None
    };

    let coinbase = build_coinbase(
        context.height,
        context.network.subsidy_halving_interval(),
        body.fees,
        payout,
        witness_commitment.as_ref(),
    )?;
    let coinbase_value = coinbase.outputs[0].value.to_sat();

    let transactions = candidate_transactions(&body.transactions)?;

    let weight = body
        .reservation
        .weight
        .checked_add(body.weight)
        .ok_or(MiningError::CandidateScalarOverflow { field: "weight" })?;

    Ok(Candidate {
        template_id: TemplateId::with_fee_revision(
            &context.previous_block_hash,
            body.sequence,
            body.fee_delta_sequence,
        )
        .qualified(body.budget),
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
        mempool_sequence: body.sequence,
        coinbase,
        coinbase_value,
        weight,
        transactions,
        witness_commitment,
    })
}

fn candidate_transactions(
    selected: &[SelectedTx],
) -> Result<Vec<CandidateTransaction>, MiningError> {
    let mut tx_positions = HashMap::<Txid, u32>::with_capacity(selected.len());
    for (offset, entry) in selected.iter().enumerate() {
        let position = u32::try_from(offset.saturating_add(1)).map_err(|_| {
            MiningError::CandidateScalarOverflow {
                field: "transaction index",
            }
        })?;
        tx_positions.insert(entry.txid, position);
    }

    let mut transactions = Vec::with_capacity(selected.len());
    for entry in selected {
        let data_hex = hex_encode(&consensus_bytes(entry.tx.as_ref()));
        transactions.push(CandidateTransaction {
            tx: Arc::clone(&entry.tx),
            txid: entry.txid,
            wtxid: entry.wtxid,
            fee: entry.fee,
            sigop_cost: entry.sigop_cost,
            weight: entry.weight,
            depends: depends(&entry.tx, &tx_positions),
            data_hex,
        });
    }
    Ok(transactions)
}

fn depends(tx: &Tx, tx_positions: &HashMap<Txid, u32>) -> Vec<u32> {
    let mut depends = tx
        .inputs
        .iter()
        .filter_map(|input| tx_positions.get(&input.previous_output.txid).copied())
        .collect::<Vec<_>>();
    depends.sort_unstable();
    depends.dedup();
    depends
}

/// BIP141 witness merkle root. The coinbase contributes the all-zero wtxid leaf.
fn witness_merkle_root(selected: &[SelectedTx]) -> Result<Hash256, MiningError> {
    let mut leaves = Vec::with_capacity(selected.len().saturating_add(1));
    leaves.push([0_u8; 32]);
    for entry in selected {
        leaves.push(*entry.wtxid.as_bytes());
    }
    merkle_root_from_leaves(&mut leaves)
}

fn merkle_root_from_leaves(leaves: &mut Vec<[u8; 32]>) -> Result<Hash256, MiningError> {
    compute_merkle_root(leaves)
        .map(|bytes| Hash256::from_le_bytes(&bytes))
        .ok_or(MiningError::CandidateScalarOverflow {
            field: "merkle root",
        })
}

fn witness_commitment_hash(witness_merkle_root: &Hash256, reserved: &[u8; 32]) -> Hash256 {
    let mut pair = [0_u8; 64];
    pair[..32].copy_from_slice(witness_merkle_root.as_byte_array());
    pair[32..].copy_from_slice(reserved);
    double_sha256(&pair)
}

#[cfg(test)]
mod tests;
