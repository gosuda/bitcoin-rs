use std::collections::HashSet;
use std::sync::Arc;

use bitcoin_rs_consensus::is_final_tx;
use bitcoin_rs_mempool::{ChunkView, EntryId, Mempool, MempoolEntry};
use bitcoin_rs_primitives::Tx;

use crate::MiningError;
use crate::template::{
    CandidateContext, FixedReservation, Reservation, SelectedBody, SelectedTx,
    transaction_count_size,
};

/// Core `DEFAULT_BLOCK_MIN_TX_FEE` (`policy.h`): the lowest rate a template
/// chunk or chunk prefix may pay, in satoshis per kvB of rounded virtual size.
/// Fixed, with no configuration key.
const BLOCK_MIN_TX_FEE_SAT_PER_KVB: i128 = 1;

#[derive(Clone, Copy, Default)]
struct PackageTotals {
    fee: u64,
    weight: u64,
    size: u64,
    sigop_cost: u64,
    modified_fee: i128,
    charged_weight: u64,
}

impl PackageTotals {
    fn of_chunk(chunk: &ChunkView<'_>) -> Result<Self, MiningError> {
        chunk
            .entries()
            .try_fold(Self::default(), |totals, (_, entry)| totals.plus(entry))
    }

    fn plus(self, entry: &MempoolEntry) -> Result<Self, MiningError> {
        Ok(Self {
            fee: self
                .fee
                .checked_add(entry.fee)
                .ok_or(MiningError::FeeOverflow)?,
            weight: self
                .weight
                .checked_add(entry.weight)
                .ok_or(MiningError::CandidateScalarOverflow { field: "weight" })?,
            size: self
                .size
                .checked_add(u64::from(entry.size))
                .ok_or(MiningError::CandidateScalarOverflow { field: "size" })?,
            sigop_cost: self
                .sigop_cost
                .checked_add(u64::from(entry.sigop_cost))
                .ok_or(MiningError::CandidateScalarOverflow {
                    field: "sigop cost",
                })?,
            modified_fee: self.modified_fee.checked_add(entry.modified_fee()).ok_or(
                MiningError::CandidateScalarOverflow {
                    field: "modified fee",
                },
            )?,
            charged_weight: self
                .charged_weight
                .checked_add(entry.policy_weight())
                .ok_or(MiningError::CandidateScalarOverflow {
                    field: "charged weight",
                })?,
        })
    }

    fn minus(self, entry: &MempoolEntry) -> Self {
        Self {
            fee: self.fee - entry.fee,
            weight: self.weight - entry.weight,
            size: self.size - u64::from(entry.size),
            sigop_cost: self.sigop_cost - u64::from(entry.sigop_cost),
            modified_fee: self.modified_fee - entry.modified_fee(),
            charged_weight: self.charged_weight - entry.policy_weight(),
        }
    }
}

/// Whether a chunk or chunk prefix pays the block minimum fee.
/// Core `ToFeePerVSize` rounds the summed charged weight up to whole vbytes
fn meets_block_min_fee_rate(modified_fee: i128, charged_weight: u64) -> Result<bool, MiningError> {
    let rate = modified_fee
        .checked_mul(1_000)
        .and_then(|scaled| scaled.checked_div_euclid(i128::from(charged_weight.div_ceil(4))))
        .ok_or(MiningError::CandidateScalarOverflow { field: "fee rate" })?;
    Ok(rate >= BLOCK_MIN_TX_FEE_SAT_PER_KVB)
}

#[derive(Clone, Copy)]
struct BodyUsage {
    weight: u64,
    size: u64,
    sigops: u64,
    fees: u64,
}

impl BodyUsage {
    fn claim_fees(self, totals: &PackageTotals) -> Result<Self, MiningError> {
        let fees = self
            .fees
            .checked_add(totals.fee)
            .ok_or(MiningError::FeeOverflow)?;
        Ok(Self { fees, ..self })
    }
}

struct SkippedChunk<'pool> {
    chunk: ChunkView<'pool>,
    totals: PackageTotals,
}

struct Selection {
    usage: BodyUsage,
    selected: HashSet<EntryId>,
    ordered: Vec<SelectedTx>,
}

impl Selection {
    fn is_full(&self, context: &CandidateContext) -> bool {
        (context.max_weight > 0 && self.usage.weight >= context.max_weight)
            || (context.max_size > 0 && self.usage.size >= context.max_size)
    }

    fn grown_by(
        &self,
        context: &CandidateContext,
        members: usize,
        totals: &PackageTotals,
    ) -> Result<Option<BodyUsage>, MiningError> {
        let count = self.ordered.len();
        let next_count =
            count
                .checked_add(members)
                .ok_or(MiningError::CandidateScalarOverflow {
                    field: "transaction count",
                })?;
        let count_growth = transaction_count_size(next_count)? - transaction_count_size(count)?;
        let Some(weight) = self
            .usage
            .weight
            .checked_add(totals.weight)
            .and_then(|weight| weight.checked_add(count_growth * 4))
        else {
            return Ok(None);
        };
        let Some(size) = self
            .usage
            .size
            .checked_add(totals.size)
            .and_then(|size| size.checked_add(count_growth))
        else {
            return Ok(None);
        };
        let Some(sigops) = self.usage.sigops.checked_add(totals.sigop_cost) else {
            return Ok(None);
        };
        if weight > context.max_weight || size > context.max_size || sigops > context.max_sigops {
            return Ok(None);
        }
        Ok(Some(BodyUsage {
            weight,
            size,
            sigops,
            fees: self.usage.fees,
        }))
    }

    fn append(&mut self, chunk: &ChunkView<'_>, len: usize, usage: BodyUsage) {
        for (member, entry) in chunk.entries().take(len) {
            self.selected.insert(member);
            self.ordered.push(SelectedTx {
                tx: Arc::clone(&entry.tx),
                txid: entry.txid,
                wtxid: entry.wtxid,
                fee: entry.fee,
                sigop_cost: entry.sigop_cost,
                weight: entry.weight,
            });
        }
        self.usage = usage;
    }

    fn parents_selected(&self, chunk: &ChunkView<'_>) -> bool {
        chunk.members.iter().all(|&member| {
            chunk
                .parents_of(member)
                .all(|parent| self.selected.contains(&parent) || chunk.members.contains(&parent))
        })
    }

    fn tail_candidate<'pool>(
        &self,
        context: &CandidateContext,
        pool: &Mempool,
        chunk: ChunkView<'pool>,
        totals: PackageTotals,
    ) -> Result<Option<SkippedChunk<'pool>>, MiningError> {
        let [first, _, ..] = chunk.members else {
            return Ok(None);
        };
        let first = PackageTotals::default().plus(pool.chunk_member(*first))?;
        let fits = self.grown_by(context, 1, &first)?.is_some();
        Ok(fits.then_some(SkippedChunk { chunk, totals }))
    }

    fn walk<'view>(
        &mut self,
        context: &CandidateContext,
        pool: &Mempool,
        chunks: impl Iterator<Item = ChunkView<'view>>,
    ) -> Result<Vec<SkippedChunk<'view>>, MiningError> {
        let mut skipped = Vec::new();
        for chunk in chunks {
            if self.is_full(context) {
                break;
            }
            if !meets_block_min_fee_rate(chunk.modified_fee, chunk.charged_weight)? {
                break;
            }
            if !self.parents_selected(&chunk) {
                continue;
            }
            let totals = PackageTotals::of_chunk(&chunk)?;
            if !chunk_is_final(context, pool, &chunk) {
                continue;
            }
            let Some(usage) = self.grown_by(context, chunk.len(), &totals)? else {
                skipped.extend(self.tail_candidate(context, pool, chunk, totals)?);
                continue;
            };
            let usage = usage.claim_fees(&totals)?;
            self.append(&chunk, chunk.len(), usage);
        }
        Ok(skipped)
    }

    fn longest_prefix(
        &self,
        context: &CandidateContext,
        pool: &Mempool,
        chunk: &ChunkView<'_>,
        totals: PackageTotals,
    ) -> Result<Option<(usize, BodyUsage)>, MiningError> {
        let mut prefix = totals;
        for (index, &last) in chunk.members.iter().enumerate().rev() {
            let len = index + 1;
            if let Some(usage) = self.grown_by(context, len, &prefix)?
                && meets_block_min_fee_rate(prefix.modified_fee, prefix.charged_weight)?
            {
                return Ok(Some((len, usage.claim_fees(&prefix)?)));
            }
            prefix = prefix.minus(pool.chunk_member(last));
        }
        Ok(None)
    }

    fn fill_tail(
        &mut self,
        context: &CandidateContext,
        pool: &Mempool,
        skipped: Vec<SkippedChunk<'_>>,
    ) -> Result<(), MiningError> {
        for SkippedChunk { chunk, totals } in skipped {
            if self.is_full(context) {
                break;
            }
            let Some((len, usage)) = self.longest_prefix(context, pool, &chunk, totals)? else {
                continue;
            };
            self.append(&chunk, len, usage);
        }
        Ok(())
    }
}

/// Selects dependency-closed packages under the candidate's resource limits.
pub(crate) fn select_packages<'a>(
    context: &CandidateContext,
    pool: &Mempool,
    chunks: impl Iterator<Item = ChunkView<'a>>,
    sequences: (u64, u64),
    reservation: Reservation,
) -> Result<SelectedBody, MiningError> {
    let count_size = transaction_count_size(0)?;
    let empty_count = FixedReservation {
        weight: count_size * 4,
        size: count_size,
        sigops: 0,
    };
    let start = reservation
        .fixed
        .checked_add(empty_count)?
        .checked_add(reservation.growth)?;
    start.check(context.max_weight, context.max_size, context.max_sigops)?;

    let mut selection = Selection {
        usage: BodyUsage {
            weight: start.weight,
            size: start.size,
            sigops: start.sigops,
            fees: 0,
        },
        selected: HashSet::new(),
        ordered: Vec::new(),
    };
    let skipped = selection.walk(context, pool, chunks)?;
    selection.fill_tail(context, pool, skipped)?;

    let held_back = reservation
        .fixed
        .weight
        .saturating_add(reservation.growth.weight);
    Ok(SelectedBody {
        sequence: sequences.0,
        fee_delta_sequence: sequences.1,
        transactions: selection.ordered,
        fees: selection.usage.fees,
        weight: selection.usage.weight.saturating_sub(held_back),
        reservation: reservation.fixed,
        budget: reservation.budget,
    })
}

fn chunk_is_final(context: &CandidateContext, pool: &Mempool, chunk: &ChunkView<'_>) -> bool {
    chunk.entries().all(|(member, entry)| {
        is_final_tx(&entry.tx, context.height, context.locktime_cutoff)
            && member_sequence_locks_final(context, pool, chunk, member, &entry.tx)
    })
}

fn member_sequence_locks_final(
    context: &CandidateContext,
    pool: &Mempool,
    chunk: &ChunkView<'_>,
    member: EntryId,
    tx: &Tx,
) -> bool {
    if !context.csv_active {
        return true;
    }
    if tx.version < 2 {
        return true;
    }
    tx.inputs.iter().all(|input| {
        let prev = &input.previous_output.txid;
        let Some(parent) = pool.entry_id_by_txid(prev) else {
            return true;
        };
        if chunk.is_staged_confirmed(parent) {
            return bitcoin_rs_consensus::bip68::sequence_lock_satisfied(
                tx.version,
                input.sequence.to_consensus(),
                context.height.saturating_sub(1),
                context.staged_parent_mtp,
                context.height,
                context.locktime_cutoff,
            );
        }
        let required = chunk
            .parents_of(member)
            .any(|parent| pool.chunk_member(parent).txid == *prev);
        if !required {
            return true;
        }
        bitcoin_rs_consensus::bip68::sequence_lock_satisfied(
            tx.version,
            input.sequence.to_consensus(),
            context.height,
            context.locktime_cutoff,
            context.height,
            context.locktime_cutoff,
        )
    })
}
