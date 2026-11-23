use std::sync::Arc;

use bitcoin_rs_chain::chain::compact_is_met_by;
use bitcoin_rs_consensus::primitives::{
    Block, BlockHash, CompactTarget, Hash256, Header, Network, Tx, Txid, Wtxid,
    encode::{consensus_bytes, double_sha256},
    hex::hex_encode,
    varint,
};
use bitcoin_rs_consensus::script::VerifyFlags;
use bitcoin_rs_consensus::{compute_merkle_root, transaction_sigop_cost};
use bitcoin_rs_mempool::{BlockRemovalPlan, Mempool, MempoolMiningSnapshot};
use hashbrown::HashMap;

use crate::mining::MiningError;
use crate::mining::coinbase::{WITNESS_RESERVED_VALUE, build_coinbase};
use crate::mining::policy::select_packages;

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
    pub const MAX_SCRIPT_SIG_LEN: usize = 100;
    pub const MIN_SCRIPT_SIG_LEN: usize = 2;
    pub fn split_qualifier(id: &str) -> Option<(&str, Option<Self>)> {
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
    pub fn qualified(mut self, budget: Option<CoinbaseBudget>) -> Self {
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

pub fn assemble_ordered_candidate(
    context: &CandidateContext,
    snapshot: &MempoolMiningSnapshot,
    payout: &[u8],
) -> Result<Candidate, MiningError> {
    let reservation = reserve(context, payout, None)?.fixed;
    let body = exact_order(context, snapshot, reservation)?;
    finish_candidate(context, &body, payout)
}

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

pub fn finish_candidate(
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
mod tests {
    use super::*;
    use bitcoin_rs_consensus::primitives::{
        Amount, LockTime, OutPoint, Script, Sequence, TxIn, TxOut,
    };
    use bitcoin_rs_mempool::{MempoolEntry, MempoolLimits};

    use crate::mining::test_error::TestError;

    type TestResult = Result<(), TestError>;

    const PAYOUT: &[u8] = &[0x51];

    #[derive(Clone, Copy)]
    struct Limits {
        weight: u64,
        size: u64,
        sigops: u64,
    }

    const GENEROUS: Limits = Limits {
        weight: 4_000_000,
        size: 4_000_000,
        sigops: 80_000,
    };

    const BUDGET: CoinbaseBudget = CoinbaseBudget {
        additional_size: 1_000,
        additional_sigops: 7,
    };

    fn context(segwit_active: bool, limits: Limits) -> CandidateContext {
        CandidateContext {
            previous_block_hash: Hash256::from_le_bytes(&[0x11; 32]),
            height: 100,
            version: 0x2000_0000,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            min_time: 1,
            current_time: 2,
            locktime_cutoff: 1,
            staged_parent_mtp: 1,
            network: Network::Regtest,
            csv_active: true,
            segwit_active,
            max_weight: limits.weight,
            max_size: limits.size,
            max_sigops: limits.sigops,
        }
    }

    fn witnessed_tx(label: u8) -> Tx {
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid::from(Hash256::from_le_bytes(&[label; 32])), 0),
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: vec![vec![label; 200]].into(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: vec![0x51].into(),
            }],
        }
    }

    fn pool_with_tx(sigop_cost: u32) -> Result<Mempool, TestError> {
        let mut pool = Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            ..MempoolLimits::default()
        });
        let tx = witnessed_tx(1);
        let vsize = u32::try_from(tx.vsize())?;
        pool.insert_entry(MempoolEntry::new(
            Arc::new(tx),
            vsize,
            10_000,
            0,
            0,
            sigop_cost,
        ))?;
        Ok(pool)
    }


    // API-11
    #[test]
    fn ordinary_templates_reserve_external_coinbase_sigops() -> TestResult {
        let mut pool = Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            ..MempoolLimits::default()
        });
        for label in 1..=5 {
            let tx = witnessed_tx(label);
            let vsize = u32::try_from(tx.vsize())?;
            pool.insert_entry(MempoolEntry::new(
                Arc::new(tx),
                vsize,
                10_000,
                0,
                0,
                16_000,
            ))?;
        }
        let candidate = assemble(
            &context(
                true,
                Limits {
                    sigops: 80_000,
                    ..GENEROUS
                },
            ),
            &pool,
            None,
        )?;
        assert_eq!(candidate.transactions.len(), 4);
        assert!(used(&candidate)?.2 + 400 <= 80_000);
        Ok(())
    }

    // API-11
    #[test]
    fn ordinary_templates_reserve_external_coinbase_weight() -> TestResult {
        let candidate = assemble(
            &context(
                true,
                Limits {
                    weight: 8_000,
                    ..GENEROUS
                },
            ),
            &pool_with_tx(0)?,
            None,
        )?;
        assert!(candidate.transactions.is_empty());
        Ok(())
    }

    fn assemble(
        context: &CandidateContext,
        pool: &Mempool,
        budget: Option<CoinbaseBudget>,
    ) -> Result<Candidate, MiningError> {
        let body = select_template_body(pool, context, PAYOUT, budget)?;
        finish_candidate(context, &body, PAYOUT)
    }

    fn lock_child(parent: Txid, vout: u32, version: u32, sequence: u32) -> Tx {
        Tx {
            version,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(parent, vout),
                script_sig: Script::new(),
                sequence: Sequence::from_consensus(sequence),
                witness: vec![vec![0x51; 10]].into(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(900),
                script_pubkey: vec![0x51].into(),
            }],
        }
    }

    fn insert_staged(pool: &mut Mempool, tx: Tx) -> Txid {
        let txid = tx.txid();
        let vsize = u32::try_from(tx.vsize()).unwrap_or_else(|_| panic!("fixture vsize fits"));
        pool.insert_entry(MempoolEntry::new(Arc::new(tx), vsize, 10_000, 0, 0, 0))
            .unwrap_or_else(|error| panic!("fixture insert stages: {error:?}"));
        txid
    }

    const TIME_FLAG: u32 = 1 << 22;

    #[test]
    fn projected_staged_parent_locks_evaluate_at_the_staged_height() -> TestResult {
        let mut pool = Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            ..MempoolLimits::default()
        });
        let parent = Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid::from(Hash256::from_le_bytes(&[0x77; 32])), 0),
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: vec![vec![0x51; 10]].into(),
            }],
            outputs: (0..4)
                .map(|_| TxOut {
                    value: Amount::from_sat(1_000),
                    script_pubkey: vec![0x51].into(),
                })
                .collect(),
        };
        let parent_txid = insert_staged(&mut pool, parent.clone());
        let height_met = insert_staged(&mut pool, lock_child(parent_txid, 0, 2, 1));
        let _height_unmet = insert_staged(&mut pool, lock_child(parent_txid, 1, 2, 2));
        let unsigned = insert_staged(&mut pool, lock_child(parent_txid, 2, 1, 2));
        let timed = insert_staged(&mut pool, lock_child(parent_txid, 3, 2, TIME_FLAG | 1));

        let block = Block {
            header: Header::default(),
            txs: vec![parent],
        };
        let plan = pool.plan_block_removals(&bitcoin_rs_mempool::TransitionFacts::from_block(
            &bitcoin_rs_consensus::primitives::BlockImage::from_local(block.clone()),
        ));
        assert_eq!(plan.removals.len(), 1, "only the parent stages");

        let base = context(true, GENEROUS);
        let selected = select_template_body_after(&pool, &plan, &base, PAYOUT)?;
        let body: Vec<Txid> = selected.transactions.iter().map(|tx| tx.txid).collect();
        assert_eq!(body.len(), 2, "only two children survive: {body:?}");
        assert!(body.contains(&height_met), "the met height lock selects");
        assert!(body.contains(&unsigned), "the unsigned child selects");

        let met_time = CandidateContext {
            locktime_cutoff: 1_512,
            staged_parent_mtp: 1_000,
            ..base
        };
        let selected = select_template_body_after(&pool, &plan, &met_time, PAYOUT)?;
        assert!(
            selected.transactions.iter().any(|tx| tx.txid == timed),
            "a time lock met by the staged predecessor MTP selects"
        );
        let unmet_time = CandidateContext {
            locktime_cutoff: 1_511,
            staged_parent_mtp: 1_000,
            ..base
        };
        let selected = select_template_body_after(&pool, &plan, &unmet_time, PAYOUT)?;
        assert!(
            selected.transactions.iter().all(|tx| tx.txid != timed),
            "a time lock unmet by the staged predecessor MTP refuses"
        );
        Ok(())
    }

    fn used(candidate: &Candidate) -> Result<(u64, u64, u64), TestError> {
        let block = candidate.into_unsolved_block()?;
        let sigops = u64::from(transaction_sigop_cost(
            &candidate.coinbase,
            &[],
            VerifyFlags::NONE,
        )) + candidate
            .transactions
            .iter()
            .map(|tx| u64::from(tx.sigop_cost))
            .sum::<u64>();
        Ok((block.weight(), u64::try_from(block.total_size())?, sigops))
    }

    fn growth_size(candidate: &Candidate, budget: CoinbaseBudget) -> Result<u64, TestError> {
        let script_sig = candidate.coinbase.inputs[0].script_sig.len();
        Ok(u64::from(budget.additional_size) + u64::try_from(100 - script_sig)?)
    }

    #[test]
    fn growth_binds_each_dimension_exactly_and_the_selector_drops_what_no_longer_fits() -> TestResult
    {
        for segwit_active in [true, false] {
            let pool = pool_with_tx(50)?;
            let plain = assemble(&context(segwit_active, GENEROUS), &pool, None)?;
            assert_eq!(plain.transactions.len(), 1);
            let (weight, size, sigops) = used(&plain)?;
            assert_eq!(weight, plain.weight);
            let growth = growth_size(&plain, BUDGET)?;
            let cases = [
                (
                    "weight",
                    Limits {
                        weight: weight + 4 * growth,
                        ..GENEROUS
                    },
                ),
                (
                    "size",
                    Limits {
                        size: size + growth,
                        ..GENEROUS
                    },
                ),
                (
                    "sigops",
                    Limits {
                        sigops: sigops
                            + u64::from(BUDGET.additional_sigops)
                            + u64::try_from(100 - plain.coinbase.inputs[0].script_sig.len())? * 80,
                        ..GENEROUS
                    },
                ),
            ];
            for (field, exact) in cases {
                let fit = assemble(&context(segwit_active, exact), &pool, Some(BUDGET))?;
                assert_eq!(fit.transactions.len(), 1, "{field}");
                fit.admits(BUDGET)?;
                assert_eq!(
                    fit.weight, plain.weight,
                    "{field}: the block never contains the growth"
                );
                let tight = match field {
                    "weight" => Limits {
                        weight: exact.weight - 1,
                        ..exact
                    },
                    "size" => Limits {
                        size: exact.size - 1,
                        ..exact
                    },
                    _ => Limits {
                        sigops: exact.sigops - 1,
                        ..exact
                    },
                };
                let tight = context(segwit_active, tight);
                let ordinary = assemble(&tight, &pool, None)?;
                assert_eq!(ordinary.transactions.len(), 1, "{field}");
                assert!(
                    matches!(
                        ordinary.admits(BUDGET),
                        Err(MiningError::CapacityExhausted { field: refused }) if refused == field
                    ),
                    "{field}"
                );
                let selected = assemble(&tight, &pool, Some(BUDGET))?;
                assert!(selected.transactions.is_empty(), "{field}");
                selected.admits(BUDGET)?;
            }
        }
        Ok(())
    }

    fn pool_coinbase(candidate: &Candidate, extra: Vec<TxOut>) -> Tx {
        let mut coinbase = candidate.coinbase.clone();
        let mut script = coinbase.inputs[0].script_sig.as_bytes().to_vec();
        script.resize(100, 0xae);
        coinbase.inputs[0].script_sig = script.into();
        coinbase.outputs.extend(extra);
        coinbase
    }

    fn outputs_of(count: usize, serialized: usize, sigop: bool) -> Vec<TxOut> {
        (0..count)
            .map(|index| {
                let mut script = vec![0x51_u8; serialized - 9];
                if sigop && index == 0 {
                    script[0] = 0xac;
                }
                TxOut {
                    value: Amount::from_sat(0),
                    script_pubkey: script.into(),
                }
            })
            .collect()
    }

    #[test]
    fn a_pool_shaped_coinbase_fits_the_derived_envelope_exactly() -> TestResult {
        let cases = [
            (BUDGET, outputs_of(10, 100, true)),
            (
                CoinbaseBudget {
                    additional_size: 251 * 9,
                    additional_sigops: 0,
                },
                outputs_of(251, 9, false),
            ),
        ];
        for segwit_active in [true, false] {
            for (budget, extra) in &cases {
                let pool = pool_with_tx(0)?;
                let plain = assemble(&context(segwit_active, GENEROUS), &pool, None)?;
                let (weight, size, sigops) = used(&plain)?;
                let total_outputs = plain.coinbase.outputs.len() + extra.len();
                let count_growth = if total_outputs >= 253 { 2 } else { 0 };
                let growth = growth_size(&plain, *budget)? + count_growth;
                let exact = Limits {
                    weight: weight + 4 * growth,
                    size: size + growth,
                    sigops: sigops
                        + u64::from(budget.additional_sigops)
                        + u64::try_from(100 - plain.coinbase.inputs[0].script_sig.len())? * 80,
                };
                let fit = assemble(&context(segwit_active, exact), &pool, Some(*budget))?;
                fit.admits(*budget)?;

                let mut block = fit.into_unsolved_block()?;
                block.txs[0] = pool_coinbase(&fit, extra.clone());
                let bytes = consensus_bytes(&block);
                let oracle: bitcoin::Block = bitcoin::consensus::deserialize(&bytes)?;
                assert_eq!(oracle.weight().to_wu(), exact.weight, "weight is exact");
                assert_eq!(
                    u64::try_from(oracle.total_size())?,
                    exact.size,
                    "size is exact"
                );
                let coinbase_sigops = u64::try_from(oracle.txdata[0].total_sigop_cost(|_| None))?;
                let body_sigops = fit
                    .transactions
                    .iter()
                    .map(|tx| u64::from(tx.sigop_cost))
                    .sum::<u64>();
                assert!(coinbase_sigops + body_sigops <= exact.sigops);
            }
        }
        Ok(())
    }

    #[test]
    fn an_infeasible_budget_names_its_first_exhausted_dimension() -> TestResult {
        let pool = pool_with_tx(50)?;
        let empty = Mempool::new(MempoolLimits::default());
        let base = assemble(&context(true, GENEROUS), &empty, None)?;
        let (weight, size, sigops) = used(&base)?;
        let at_base = Limits {
            weight,
            size,
            sigops,
        };
        let nothing = CoinbaseBudget {
            additional_size: 0,
            additional_sigops: 0,
        };
        let one_sigop = CoinbaseBudget {
            additional_size: 0,
            additional_sigops: 1,
        };
        assert!(select_template_body(&pool, &context(true, at_base), PAYOUT, None).is_ok());
        let cases = [
            ("weight", at_base, nothing),
            (
                "size",
                Limits {
                    weight: 4_000_000,
                    ..at_base
                },
                nothing,
            ),
            (
                "sigops",
                Limits {
                    weight: 4_000_000,
                    size: 4_000_000,
                    ..at_base
                },
                one_sigop,
            ),
        ];
        for (field, limits, budget) in cases {
            let limited = context(true, limits);
            let refused = select_template_body(&pool, &limited, PAYOUT, Some(budget));
            assert!(
                matches!(
                    &refused,
                    Err(MiningError::CapacityExhausted { field: actual }) if *actual == field
                ),
                "{field}: {refused:?}"
            );
            let ordinary = assemble(&limited, &pool, None)?;
            assert!(ordinary.transactions.is_empty(), "{field}");
            assert!(
                matches!(
                    ordinary.admits(budget),
                    Err(MiningError::CapacityExhausted { field: actual }) if actual == field
                ),
                "{field}"
            );
        }
        let huge = CoinbaseBudget {
            additional_size: u32::MAX,
            additional_sigops: u16::MAX,
        };
        assert!(matches!(
            select_template_body(&pool, &context(true, GENEROUS), PAYOUT, Some(huge)),
            Err(MiningError::CapacityExhausted { field: "weight" })
        ));
        assert!(matches!(
            base.admits(huge),
            Err(MiningError::CapacityExhausted { field: "weight" })
        ));
        Ok(())
    }

    #[test]
    fn ordinary_identity_is_unchanged_and_the_qualifier_parses_strictly() {
        let previous = Hash256::from_le_bytes(&[0x22; 32]);
        for fee_revision in [0, 3] {
            let ordinary = TemplateId::with_fee_revision(&previous, 7, fee_revision);
            assert_eq!(ordinary.clone().qualified(None), ordinary);
            assert_eq!(
                CoinbaseBudget::split_qualifier(ordinary.as_str()),
                Some((ordinary.as_str(), None))
            );
            let qualified = ordinary.clone().qualified(Some(BUDGET));
            assert_ne!(qualified, ordinary);
            assert!(qualified.as_str().starts_with(ordinary.as_str()));
            assert_eq!(
                CoinbaseBudget::split_qualifier(qualified.as_str()),
                Some((ordinary.as_str(), Some(BUDGET)))
            );
            let zero = CoinbaseBudget {
                additional_size: 0,
                additional_sigops: 0,
            };
            assert_ne!(ordinary.clone().qualified(Some(zero)), ordinary);
        }
        let extremes = CoinbaseBudget {
            additional_size: u32::MAX,
            additional_sigops: u16::MAX,
        };
        let id = TemplateId::new(&previous, 1).qualified(Some(extremes));
        let split = CoinbaseBudget::split_qualifier(id.as_str());
        assert_eq!(split.map(|(_, budget)| budget), Some(Some(extremes)));
        for malformed in [
            "x@cb",
            "x@cb1",
            "x@cb1.",
            "x@cb.1",
            "x@cb01.1",
            "x@cb1.01",
            "x@cb+1.1",
            "x@cb1.1 ",
            "x@cb4294967296.1",
            "x@cb1.65536",
            "x@cb1.1@cb2.2",
            "x@CB1.1",
            "x@",
        ] {
            assert!(
                CoinbaseBudget::split_qualifier(malformed).is_none(),
                "must reject {malformed}"
            );
        }
    }
}
