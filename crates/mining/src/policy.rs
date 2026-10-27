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

/// Exact sums over the first members of one chunk: the whole chunk, or a
/// prefix of its linearization.
///
/// Every field is a plain sum over the members counted, so removing the last
/// member with [`PackageTotals::minus`] yields the sums of the shorter prefix
/// without revisiting the others. Rounding to vbytes belongs to the rate test
/// alone: `charged_weight` stays exact, because summing per-entry vbytes can
/// overstate the block's rounded size (two 41 WU members round to 11 vB each,
/// 22 vB, while the pair rounds to `ceil(82 / 4)` = 21 vB).
#[derive(Clone, Copy, Default)]
struct PackageTotals {
    /// Actual fees: what the coinbase may claim.
    fee: u64,
    /// Consensus weights.
    weight: u64,
    /// Serialized sizes.
    size: u64,
    /// Sigop costs.
    sigop_cost: u64,
    /// Modified fees: actual fees plus signed overlays. Feerate input only.
    modified_fee: i128,
    /// Policy-charged weights, summed exactly before any rounding.
    charged_weight: u64,
}

impl PackageTotals {
    /// Sums every member of `chunk`.
    fn of_chunk(chunk: &ChunkView<'_>) -> Result<Self, MiningError> {
        chunk
            .entries()
            .try_fold(Self::default(), |totals, (_, entry)| totals.plus(entry))
    }

    /// Adds one entry. Overflow is an error, never a saturated total.
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

    /// Removes an entry that [`Self::plus`] added. The sums are exact, so no
    /// field can underflow.
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
///
/// Core `ToFeePerVSize` rounds the summed charged weight up to whole vbytes
/// once; the rate is `floor(modified_fee * 1000 / vsize)` in sat/kvB, floored
/// toward negative infinity so a negative aggregate is never read as zero. A
/// zero vsize has no rate and fails like an overflow instead of falling back
/// to a made-up denominator.
fn meets_block_min_fee_rate(modified_fee: i128, charged_weight: u64) -> Result<bool, MiningError> {
    let rate = modified_fee
        .checked_mul(1_000)
        .and_then(|scaled| scaled.checked_div_euclid(i128::from(charged_weight.div_ceil(4))))
        .ok_or(MiningError::CandidateScalarOverflow { field: "fee rate" })?;
    Ok(rate >= BLOCK_MIN_TX_FEE_SAT_PER_KVB)
}

/// Running totals of the body under construction, reservation included.
#[derive(Clone, Copy)]
struct BodyUsage {
    weight: u64,
    size: u64,
    sigops: u64,
    /// Sum of actual fees of the selected transactions.
    fees: u64,
}

impl BodyUsage {
    /// Claims the actual fees of the package this usage was grown for.
    fn claim_fees(self, totals: &PackageTotals) -> Result<Self, MiningError> {
        let fees = self
            .fees
            .checked_add(totals.fee)
            .ok_or(MiningError::FeeOverflow)?;
        Ok(Self { fees, ..self })
    }
}

/// A chunk the main walk passed over for lack of room, kept for the tail pass.
///
/// Recorded only when the chunk cleared the fee floor, every in-pool parent
/// outside it was already selected, every member is final, and at least its
/// first member would still fit. Selected transactions only grow, so any
/// prefix of a recorded chunk stays dependency-closed and final, and a chunk
/// whose first member did not fit then cannot gain room later.
struct SkippedChunk<'pool> {
    chunk: ChunkView<'pool>,
    /// Sums of the whole chunk, computed once by the main walk.
    totals: PackageTotals,
}

/// The body under construction.
///
/// `selected` holds exactly the entry ids of `ordered`. Both only grow, and
/// each append is a dependency-closed whole chunk or chunk prefix, so every
/// parent precedes its child and `usage` never rolls back.
struct Selection {
    usage: BodyUsage,
    selected: HashSet<EntryId>,
    ordered: Vec<SelectedTx>,
}

impl Selection {
    /// Whether the block already reached its weight or size limit. A zero
    /// limit means the context sets none.
    fn is_full(&self, context: &CandidateContext) -> bool {
        (context.max_weight > 0 && self.usage.weight >= context.max_weight)
            || (context.max_size > 0 && self.usage.size >= context.max_size)
    }

    /// Usage after appending `members` transactions summing to `totals`, or
    /// `None` when weight, serialized size, or sigop cost would pass the
    /// context's limit. Fees are not claimed here.
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

    /// Appends the first `len` members of `chunk` in linearization order and
    /// adopts `usage`, which already accounts for them.
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

    /// Whether every in-pool parent of `chunk` that sits outside it is already
    /// selected. A skipped parent chunk therefore makes dependent later chunks
    /// unavailable.
    fn parents_selected(&self, chunk: &ChunkView<'_>) -> bool {
        chunk.members.iter().all(|&member| {
            chunk
                .parents_of(member)
                .all(|parent| self.selected.contains(&parent) || chunk.members.contains(&parent))
        })
    }

    /// The record of a chunk that did not fit whole, or `None` when no prefix
    /// of it can ever fit: a one-member chunk has no shorter prefix, and a
    /// first member that does not fit now never will, because selection only
    /// grows.
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

    /// Walks the caller's chunks from the highest feerate. Returns the chunks it
    /// skipped for weight, serialized size, or sigop cost, in index order.
    fn walk<'view>(
        &mut self,
        context: &CandidateContext,
        pool: &Mempool,
        chunks: impl Iterator<Item = ChunkView<'view>>,
    ) -> Result<Vec<SkippedChunk<'view>>, MiningError> {
        let mut skipped = Vec::new();
        // The caller yields chunks in descending feerate order, each a
        // linearization: every ancestor precedes its child. A selected chunk's
        // own ancestors are therefore already selected whenever its direct
        // parents are, so checking direct parents keeps the body
        // ancestor-closed without a transitive walk.
        for chunk in chunks {
            if self.is_full(context) {
                break;
            }
            // Chunks come in decreasing feerate, so everything after the first
            // chunk below the block minimum pays less as well (Core `addChunks`).
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

    /// The longest linearization prefix of `chunk` that fits and whose
    /// aggregate rate meets the block minimum, with the usage after appending
    /// it. The prefix may be the whole chunk. Prefix sums are the chunk's sums
    /// trimmed from the end one member at a time, so a chunk costs one pass
    /// over its members.
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

    /// Fills the room the main walk left with prefixes of the chunks it
    /// skipped, in index order. The pass only appends, so total fees never
    /// fall.
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
///
/// The main walk follows the caller's dependency-closed fee chunks from the
/// highest feerate while the caller holds the pool read guard. It stops at
/// the first chunk whose aggregate rate, `floor(modified_fee * 1000 /
/// ceil(charged_weight / 4))`, is below `BLOCK_MIN_TX_FEE_SAT_PER_KVB`. The
/// rate belongs to the chunk, not to each transaction: descendants' fees can
/// lift a low-fee or negative-fee parent over the minimum, and a chunk that
/// pays less than it is never selected, whatever its actual fees. A chunk that
/// is not final, whose parents outside it are not all selected, or that would
/// overflow weight, serialized size, or sigop cost is skipped atomically; later
/// chunks may still fit.
///
/// A tail pass then fills the room left with prefixes of the chunks skipped
/// for weight, serialized size, or sigop cost. Each chunk, in index order,
/// contributes its longest linearization prefix that fits and whose aggregate
/// rate meets the same minimum. A chunk skipped for finality, or one whose
/// outside parents were not selected, contributes nothing. Only the selected
/// transactions are copied out of the pool. Returned body weight includes the
/// block transaction count; the reservation covers the header and coinbase.
///
/// `chunks` is either the live [`Mempool::chunks_by_feerate`] walk or a
/// [`ProjectedChunks::iter`](bitcoin_rs_mempool::ProjectedChunks::iter) walk;
/// both share every fee-floor, finality, dependency, resource, and topological
/// rule here. `sequences` is the generation the body was read at: the live
/// sequences for the live walk, or the predicted post-removal sequences for a
/// projection. The projection owner must outlive the borrowed iteration.
///
/// `reservation.growth` is the room a budgeted consumer's coinbase may add. It
/// starts the running totals beside the header, coinbase, and empty count, so
/// the walk and the tail pass see one set of limits and choose a body that
/// leaves it. The block's own weight never includes it: the returned body
/// weight and `reservation.fixed` describe only what the block contains. An
/// empty block that cannot hold the growth is refused before any chunk is read.
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
            // Confirmed on chain: its locks settled at confirmation.
            return true;
        };
        if chunk.is_staged_confirmed(parent) {
            // The staged block confirms the parent one height below the
            // candidate, so a positive height lock still binds: it is
            // evaluated at the staged confirmation height, not skipped, and
            // not evaluated as if the parent confirmed with the candidate.
            // The predecessor MTP rides the confirmation context, and the
            // candidate cutoff stays the fail-closed block MTP.
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
