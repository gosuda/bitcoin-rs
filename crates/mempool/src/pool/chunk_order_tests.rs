#![expect(clippy::expect_used)]

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cmp::Ordering;

use bitcoin_rs_primitives::{
    Amount, Block, Hash256, Header, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid,
    Witness,
};
use hashbrown::{HashMap, HashSet};
use proptest::prelude::*;

use super::{BlockRemovalPlan, Mempool};
use crate::fee_diagram::FeeWeight;
use crate::mutation::{MutationOutcome, RemovalReason};
use crate::{
    EntryId, FeeDiagramError, MempoolEntry, MempoolError, MempoolLimits, ReplacementCandidate,
};

fn label_outputs(label: u64) -> u32 {
    u32::try_from(label % 3).map_or(1, |residue| residue + 1)
}

impl Mempool {
    pub(super) fn oracle_chunk_order(&self) -> Result<Vec<Vec<Txid>>, FeeDiagramError> {
        struct OracleChunk {
            fee: i128,
            weight: u64,
            prefix: u64,
            max_txid: Txid,
            txids: Vec<Txid>,
        }
        let mut members: Vec<(EntryId, &MempoolEntry)> = self
            .entries
            .iter()
            .filter_map(|(index, entry)| {
                let id = EntryId::try_from(index).ok()?;
                Some((id, entry))
            })
            .collect();
        members.sort_by_key(|(_, entry)| entry.txid);
        if members.is_empty() {
            return Ok(Vec::new());
        }
        let positions: HashMap<EntryId, usize> = members
            .iter()
            .enumerate()
            .map(|(position, (id, _))| (*id, position))
            .collect();
        let fees: Vec<FeeWeight> = members
            .iter()
            .map(|(_, entry)| FeeWeight {
                fee: entry.modified_fee(),
                weight: u32::try_from(entry.policy_weight()).unwrap_or(u32::MAX),
            })
            .collect();
        let parents: Vec<Vec<usize>> = members
            .iter()
            .map(|(_, entry)| {
                let mut parents: Vec<usize> = entry
                    .tx
                    .inputs
                    .iter()
                    .filter_map(|input| {
                        let parent = self.entry_id_by_txid(&input.previous_output.txid)?;
                        positions.get(&parent).copied()
                    })
                    .collect();
                parents.sort_unstable();
                parents.dedup();
                parents
            })
            .collect();
        let mut all = Vec::new();
        for group in crate::fee_diagram::components(&parents)? {
            let local_fees: Vec<FeeWeight> = group.iter().map(|&i| fees[i]).collect();
            let local_parents: Vec<Vec<usize>> = group
                .iter()
                .map(|&i| {
                    parents[i]
                        .iter()
                        .map(|parent| {
                            group
                                .binary_search(parent)
                                .map_err(|_| FeeDiagramError::Dependencies)
                        })
                        .collect::<Result<Vec<_>, _>>()
                })
                .collect::<Result<Vec<_>, _>>()?;
            let mut prefix = 0_u64;
            let mut rate: Option<FeeWeight> = None;
            for chunk in crate::fee_diagram::linearize(&local_fees, &local_parents)? {
                let total = chunk.total;
                prefix = match rate {
                    Some(current) if current.rate_cmp(total) == Ordering::Equal => {
                        prefix.saturating_add(u64::from(total.weight))
                    }
                    _ => u64::from(total.weight),
                };
                rate = Some(total);
                let txids: Vec<Txid> = chunk
                    .members
                    .iter()
                    .map(|&local| members[group[local]].1.txid)
                    .collect();
                let max_txid = txids.iter().copied().max().unwrap_or_default();
                all.push(OracleChunk {
                    fee: total.fee,
                    weight: u64::from(total.weight),
                    prefix,
                    max_txid,
                    txids,
                });
            }
        }
        all.sort_by(|left, right| {
            (right.fee * i128::from(left.weight))
                .cmp(&(left.fee * i128::from(right.weight)))
                .then_with(|| left.prefix.cmp(&right.prefix))
                .then_with(|| left.max_txid.cmp(&right.max_txid))
        });
        Ok(all.into_iter().map(|chunk| chunk.txids).collect())
    }

    pub(super) fn chunk_order(&self) -> Vec<Vec<Txid>> {
        self.chunks_by_feerate()
            .map(|chunk| chunk.txids.to_vec())
            .collect()
    }

    pub(super) fn assert_index_matches_oracle(&self, stage: &str) {
        let maintained = self.chunk_order();
        let oracle = self
            .oracle_chunk_order()
            .expect("the oracle re-solves the admitted graph");
        assert_eq!(maintained, oracle, "chunk order diverged after {stage}");
        self.assert_index_invariants();
    }

    fn assert_index_invariants(&self) {
        let mut seen = HashSet::new();
        let mut flattened: Vec<EntryId> = Vec::new();
        let mut previous: Option<(i128, u64)> = None;
        for chunk in self.chunks_by_feerate() {
            assert!(!chunk.is_empty(), "the index holds an empty chunk");
            let mut fee = 0_i128;
            let mut weight = 0_u64;
            for (id, entry) in chunk.entries() {
                assert!(seen.insert(id), "an entry sits in two chunks");
                fee = fee.saturating_add(entry.modified_fee());
                weight = weight.saturating_add(entry.policy_weight());
            }
            assert_eq!(fee, chunk.modified_fee, "chunk fee drifted");
            assert_eq!(weight, chunk.charged_weight, "chunk weight drifted");
            flattened.extend(chunk.members.iter().copied());
            if let Some((previous_fee, previous_weight)) = previous {
                assert!(
                    chunk.modified_fee * i128::from(previous_weight)
                        <= previous_fee * i128::from(chunk.charged_weight),
                    "feerates increase along the index"
                );
            }
            previous = Some((chunk.modified_fee, chunk.charged_weight));
        }
        assert_eq!(seen.len(), self.len(), "the index drops live entries");
        let positions: HashMap<EntryId, usize> = flattened
            .iter()
            .enumerate()
            .map(|(position, &id)| (id, position))
            .collect();
        for chunk in self.chunks_by_feerate() {
            for &member in chunk.members {
                for parent in chunk.parents_of(member) {
                    assert!(
                        positions[&parent] < positions[&member],
                        "a parent sorts after its child"
                    );
                }
            }
        }
    }
}

fn order_tx(label: u64, spends: &[(Txid, u32)], outputs: u32, sequence: Sequence) -> Tx {
    let mut seed = [0xC1_u8; 32];
    seed[..8].copy_from_slice(&label.to_le_bytes());
    let inputs = if spends.is_empty() {
        alloc::vec![TxIn {
            previous_output: OutPoint::new(Txid::from(Hash256::from_le_bytes(&seed)), 0),
            script_sig: Script::new(),
            sequence,
            witness: Witness::new(),
        }]
    } else {
        spends
            .iter()
            .map(|&(txid, vout)| TxIn {
                previous_output: OutPoint::new(txid, vout),
                script_sig: Script::new(),
                sequence,
                witness: Witness::new(),
            })
            .collect()
    };
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs,
        outputs: (0..outputs.max(1))
            .map(|index| TxOut {
                value: Amount::from_sat(5_000 + ((label + u64::from(index)) % 9_000)),
                script_pubkey: Script::from(vec![0x51]),
            })
            .collect(),
    }
}

fn order_fee(label: u64) -> u64 {
    1_000 + (label.wrapping_mul(2_654_435_761) % 20_000)
}

fn order_pool() -> Mempool {
    Mempool::new(MempoolLimits {
        min_relay_fee_sat_per_kvb: 0,
        ..MempoolLimits::default()
    })
}

fn insert_ordered(
    pool: &mut Mempool,
    label: u64,
    spends: &[(Txid, u32)],
    outputs: u32,
    fee: u64,
) -> Txid {
    let tx = order_tx(label, spends, outputs, Sequence::MAX);
    let txid = tx.txid();
    pool.insert_entry(MempoolEntry::new(Arc::new(tx), 200, fee, label, 1, 0))
        .expect("fixture insert must apply");
    txid
}

#[test]
fn single_insertion_indexes_one_chunk() {
    let mut pool = order_pool();
    let txid = insert_ordered(&mut pool, 7, &[], 1, order_fee(7));
    assert_eq!(pool.chunk_order(), alloc::vec![alloc::vec![txid]]);
    assert_eq!(pool.derived.chunks.len(), 1);
    pool.assert_index_matches_oracle("a single insertion");
}

#[test]
fn equal_rate_parent_sorts_before_its_child() -> Result<(), MempoolError> {
    let mut pool = order_pool();
    let parent = order_tx(1, &[], 1, Sequence::MAX);
    let parent_txid = parent.txid();
    let mut parent_entry = MempoolEntry::new(Arc::new(parent), 200, 2_000, 1, 1, 0);
    parent_entry.weight = 800;
    pool.insert_entry(parent_entry)?;
    let child = order_tx(2, &[(parent_txid, 0)], 1, Sequence::MAX);
    let child_txid = child.txid();
    let mut child_entry = MempoolEntry::new(Arc::new(child), 100, 1_000, 2, 1, 0);
    child_entry.weight = 400;
    pool.insert_entry(child_entry)?;
    let oracle = pool.oracle_chunk_order()?;
    assert_eq!(
        oracle.len(),
        2,
        "the solver keeps the equal-rate pair split"
    );
    assert_eq!(
        pool.chunk_order(),
        alloc::vec![alloc::vec![parent_txid], alloc::vec![child_txid]]
    );
    pool.assert_index_matches_oracle("an equal-rate pair");
    Ok(())
}

#[test]
fn distinct_output_indices_link_by_vout() {
    let mut pool = order_pool();
    let parent_txid = insert_ordered(&mut pool, 1, &[], 3, order_fee(1));
    insert_ordered(&mut pool, 2, &[(parent_txid, 1)], 1, order_fee(2));
    insert_ordered(&mut pool, 3, &[(parent_txid, 2)], 1, order_fee(3));
    insert_ordered(&mut pool, 4, &[(parent_txid, 9)], 1, order_fee(4));
    assert_eq!(pool.len(), 4);
    pool.assert_index_matches_oracle("distinct vout links");
}

#[test]
fn negative_prioritise_keeps_the_cluster_indexed() {
    let mut pool = order_pool();
    let first = insert_ordered(&mut pool, 1, &[], 1, 5_000);
    let second = insert_ordered(&mut pool, 2, &[], 1, 6_000);
    pool.prioritise(first, -15_000)
        .expect("negative overlay applies");
    let order = pool.chunk_order();
    assert_eq!(order.len(), 2);
    assert_eq!(order[0], alloc::vec![second]);
    assert_eq!(order[1], alloc::vec![first]);
    pool.assert_index_matches_oracle("a negative overlay");
}

#[test]
fn remove_for_block_confirms_and_conflicts() -> Result<(), MempoolError> {
    let mut pool = order_pool();
    let parent = order_tx(1, &[], 1, Sequence::MAX);
    let parent_txid = parent.txid();
    pool.insert_entry(MempoolEntry::new(
        Arc::new(parent),
        200,
        order_fee(1),
        1,
        1,
        0,
    ))?;
    let child = order_tx(2, &[(parent_txid, 0)], 1, Sequence::MAX);
    let child_txid = child.txid();
    pool.insert_entry(MempoolEntry::new(
        Arc::new(child),
        200,
        order_fee(2),
        2,
        1,
        0,
    ))?;
    let other = order_tx(3, &[], 1, Sequence::MAX);
    let other_out = OutPoint::new(other.txid(), 0);
    pool.insert_entry(MempoolEntry::new(
        Arc::new(other),
        200,
        order_fee(3),
        3,
        1,
        0,
    ))?;
    let rival_parent = order_tx(4, &[(other_out.txid, other_out.vout)], 1, Sequence::MAX);
    let rival_parent_txid = rival_parent.txid();
    pool.insert_entry(MempoolEntry::new(
        Arc::new(rival_parent),
        200,
        order_fee(4),
        4,
        1,
        0,
    ))?;
    let rival_child = order_tx(5, &[(rival_parent_txid, 0)], 1, Sequence::MAX);
    let rival_child_txid = rival_child.txid();
    pool.insert_entry(MempoolEntry::new(
        Arc::new(rival_child),
        200,
        order_fee(5),
        5,
        1,
        0,
    ))?;

    let confirmed = order_tx(1, &[], 1, Sequence::MAX);
    let included = pool.remove_for_block(&[&confirmed], &[parent_txid], 3, 5);
    assert!(pool.contains_txid(&child_txid));
    assert!(!pool.contains_txid(&parent_txid));
    assert!(
        included
            .changes
            .iter()
            .any(|change| change.outcome == MutationOutcome::Removed(RemovalReason::BlockInclusion))
    );
    pool.assert_index_matches_oracle("a block inclusion");

    let conflict = order_tx(6, &[(other_out.txid, other_out.vout)], 1, Sequence::MAX);
    let conflict_txid = conflict.txid();
    let swept = pool.remove_for_block(&[&conflict], &[conflict_txid], 3, 6);
    assert!(!pool.contains_txid(&rival_child_txid));
    assert_eq!(pool.len(), 2);
    assert!(
        swept
            .changes
            .iter()
            .all(|change| change.outcome == MutationOutcome::Removed(RemovalReason::Conflict))
    );
    pool.assert_index_matches_oracle("a block conflict");
    Ok(())
}

#[test]
fn rbf_replacement_keeps_the_index_current() -> Result<(), MempoolError> {
    let mut pool = order_pool();
    let funding = OutPoint::new(Txid::from(Hash256::from_le_bytes(&[0x11; 32])), 0);
    let original = order_tx(
        1,
        &[(funding.txid, funding.vout)],
        1,
        Sequence::ENABLE_RBF_NO_LOCKTIME,
    );
    let original_txid = original.txid();
    pool.insert_entry(MempoolEntry::new(Arc::new(original), 1_000, 2_000, 1, 7, 0))?;
    let child = order_tx(2, &[(original_txid, 0)], 1, Sequence::MAX);
    let child_txid = child.txid();
    pool.insert_entry(MempoolEntry::new(Arc::new(child), 200, 1_000, 2, 7, 0))?;

    let winner = order_tx(
        11,
        &[(funding.txid, funding.vout)],
        1,
        Sequence::ENABLE_RBF_NO_LOCKTIME,
    );
    let winner_txid = winner.txid();
    pool.replace_transaction(
        &ReplacementCandidate::new(Arc::new(winner), 1_000, 4_000, 1).with_sigop_cost(4),
        10,
        1,
    )
    .map_err(crate::RbfError::into_pool_error)?;
    assert!(pool.contains_txid(&winner_txid));
    assert!(!pool.contains_txid(&original_txid));
    assert!(!pool.contains_txid(&child_txid));
    pool.assert_index_matches_oracle("a replacement");
    Ok(())
}

#[test]
fn merge_two_clusters_via_bridge_tx() {
    let mut pool = order_pool();
    let first = insert_ordered(&mut pool, 1, &[], 1, order_fee(1));
    let second = insert_ordered(&mut pool, 2, &[], 1, order_fee(2));
    assert_eq!(pool.derived.chunks.len(), 2);
    insert_ordered(&mut pool, 3, &[(first, 0), (second, 0)], 1, order_fee(3));
    assert_eq!(pool.len(), 3);
    assert_eq!(
        pool.derived.chunks.len(),
        1,
        "the bridge joins both clusters into one component"
    );
    pool.assert_index_matches_oracle("a cluster merge");
}

#[test]
fn a_full_cluster_keeps_its_exact_order_through_mutations() {
    let mut pool = order_pool();
    let mut spine: Vec<Txid> = Vec::new();
    let mut leaves: Vec<Txid> = Vec::new();
    for step in 0_u64..32 {
        let spends: Vec<(Txid, u32)> = spine.last().map(|&txid| (txid, 0)).into_iter().collect();
        let node = insert_ordered(&mut pool, step + 1, &spends, 2, order_fee(step + 1));
        spine.push(node);
        leaves.push(insert_ordered(
            &mut pool,
            step + 101,
            &[(node, 1)],
            1,
            order_fee(step + 101),
        ));
    }
    assert_eq!(pool.len(), 64);
    assert_eq!(pool.derived.chunks.len(), 1, "one component holds all 64");
    pool.assert_index_matches_oracle("a full cluster");

    let overflow = order_tx(900, &[(spine[31], 0)], 1, Sequence::MAX);
    assert!(
        pool.insert_entry(MempoolEntry::new(
            Arc::new(overflow),
            200,
            50_000,
            900,
            1,
            0
        ))
        .is_err(),
        "the cluster count limit refuses a 65th member"
    );
    assert_eq!(pool.len(), 64);
    pool.assert_index_matches_oracle("a refused 65th member");

    pool.prioritise(spine[0], 500_000)
        .expect("positive overlay applies");
    pool.assert_index_matches_oracle("a root overlay");
    pool.prioritise(leaves[10], -1_000_000)
        .expect("negative overlay applies");
    pool.assert_index_matches_oracle("a leaf overlay");

    let confirmed = order_tx(1, &[], 2, Sequence::MAX);
    pool.remove_for_block(&[&confirmed], &[spine[0]], 3, 133);
    assert_eq!(pool.len(), 63);
    assert_eq!(
        pool.derived.chunks.len(),
        2,
        "confirming the root splits its first leaf from the rest"
    );
    pool.assert_index_matches_oracle("the root confirmation");
}

proptest! {
    #[test]
    fn maintained_chunk_order_matches_the_from_scratch_solver(
        actions in prop::collection::vec(
            (
                0_u64..48,
                prop::option::of(0_u64..48),
                prop::option::of(0_u64..48),
                0_usize..5,
                1_u32..4,
                0_u32..4,
                0_u8..10,
            ),
            1..32,
        ),
    ) {
        let mut pool = order_pool();
        let mut inserted: HashMap<u64, Txid> = HashMap::new();
        let mut actions = actions;
        actions.insert(0, (1, Some(0), None, 3, 1, 0, 0));
        actions.insert(0, (0, None, None, 3, 1, 0, 0));
        for (label, parent_a, parent_b, fee_class, outputs, vout, op) in actions {
            let fees = [order_fee(label), 100, 50_000, 150_000, 1_000];
            let fee = fees[fee_class];
            let mut spends = Vec::new();
            for parent_label in [parent_a, parent_b].into_iter().flatten() {
                let Some(parent_txid) = inserted.get(&parent_label) else {
                    continue;
                };
                if spends.iter().all(|&(txid, _)| txid != *parent_txid) {
                    let slots = label_outputs(parent_label);
                    spends.push((*parent_txid, vout % slots));
                }
            }
            for parent_label in [parent_a, parent_b].into_iter().flatten() {
                if let Some(parent_txid) = inserted.get(&parent_label) {
                    assert!(
                        spends.iter().any(|&(txid, _)| txid == *parent_txid),
                        "tracked resident parent {parent_label} must link into label {label}"
                    );
                }
            }
            let resident = inserted.get(&label).copied();
            match op {
                0..=4 => {
                    let tx = order_tx(label, &spends, outputs, Sequence::ENABLE_RBF_NO_LOCKTIME);
                    let txid = tx.txid();
                    let admitted = pool
                        .insert_entry(MempoolEntry::new(Arc::new(tx), 200, fee, label, 1, 0))
                        .is_ok();
                    if admitted {
                        assert!(pool.contains_txid(&txid));
                        inserted.insert(label, txid);
                        if !spends.is_empty() {
                            let child = pool.entry_id_by_txid(&txid);
                            for &(parent_txid, _) in &spends {
                                assert_eq!(
                                    child.and_then(|id| pool.component_id(id)),
                                    pool.entry_id_by_txid(&parent_txid)
                                        .and_then(|id| pool.component_id(id)),
                                    "admitted spends must join the parent component"
                                );
                            }
                        }
                    }
                }
                5..=6 => {
                    if let Some(txid) = resident
                        && let Some(id) = pool.entry_id_by_txid(&txid)
                    {
                        let mut changes = Vec::new();
                        pool.remove_entries_with_reasons(
                            &[(id, RemovalReason::BlockInclusion)],
                            &mut changes,
                        );
                        assert!(!pool.contains_txid(&txid), "the targeted resident must leave");
                    }
                }
                7 => {
                    if let Some(txid) = resident {
                        let deltas = [-15_000, -1_000, -100, 100, 1_000, 15_000];
                        assert!(
                            pool.prioritise(txid, deltas[fee_class % deltas.len()]).is_ok(),
                            "an overlay on a resident applies"
                        );
                    }
                }
                8 => {
                    if let Some(txid) = resident
                        && let Some(entry) = pool.entry_by_txid(&txid)
                    {
                        let confirmed = entry.tx.clone();
                        let time = entry.time;
                        let _ = pool.remove_for_block(&[confirmed.as_ref()], &[txid], 2, time);
                        assert!(!pool.contains_txid(&txid), "a confirmed resident must leave");
                    }
                }
                _ => {
                    if let Some(txid) = resident
                        && let Some(entry) = pool.entry_by_txid(&txid)
                    {
                        let held: Vec<(Txid, u32)> = entry
                            .tx
                            .inputs
                            .iter()
                            .map(|input| (input.previous_output.txid, input.previous_output.vout))
                            .collect();
                        let winner = order_tx(
                            label + 1_000,
                            &held,
                            outputs,
                            Sequence::ENABLE_RBF_NO_LOCKTIME,
                        );
                        let replaced = pool
                            .replace_transaction(
                                &ReplacementCandidate::new(
                                    Arc::new(winner),
                                    200,
                                    fee.saturating_add(50_000),
                                    0,
                                ),
                                label,
                                1,
                            )
                            .map_err(crate::RbfError::into_pool_error);
                        if replaced.is_ok() {
                            assert!(!pool.contains_txid(&txid), "a replaced resident must leave");
                        }
                    }
                }
            }
            inserted.retain(|_, txid| pool.contains_txid(txid));
            pool.assert_index_matches_oracle("one random mutation");
        }
        pool.clear();
        pool.assert_index_matches_oracle("clear");
    }
}

fn test_block(txs: Vec<Tx>) -> Block {
    Block {
        header: Header::default(),
        txs,
    }
}

fn coinbase_stub(label: u64) -> Tx {
    order_tx(label, &[], 1, Sequence::MAX)
}

fn assert_plan_unique(plan: &BlockRemovalPlan) {
    let mut seen = HashSet::new();
    for (id, _) in &plan.removals {
        assert!(seen.insert(*id), "removal plan repeats entry {id}");
    }
}

fn projected_facts(pool: &Mempool, plan: &BlockRemovalPlan) -> Vec<(Vec<Txid>, i128, u64)> {
    pool.chunks_after(plan)
        .iter()
        .map(|chunk| {
            (
                chunk.txids.to_vec(),
                chunk.modified_fee,
                chunk.charged_weight,
            )
        })
        .collect()
}

fn live_facts(pool: &Mempool) -> Vec<(Vec<Txid>, i128, u64)> {
    pool.chunks_by_feerate()
        .map(|chunk| {
            (
                chunk.txids.to_vec(),
                chunk.modified_fee,
                chunk.charged_weight,
            )
        })
        .collect()
}

fn apply_block(pool: &mut Mempool, block: &Block) {
    let refs: Vec<&Tx> = block.txs.iter().collect();
    let ids = block.txids();
    let _ = pool.remove_for_block(&refs, &ids, 3, 5);
}

fn twin_pools(build: impl Fn(&mut Mempool)) -> (Mempool, Mempool) {
    let mut first = order_pool();
    let mut second = order_pool();
    build(&mut first);
    build(&mut second);
    first.assert_index_matches_oracle("twin first");
    second.assert_index_matches_oracle("twin second");
    (first, second)
}

fn assert_projection_matches_real(first: &Mempool, second: &mut Mempool, block: &Block) {
    let before_len = first.len();
    let before_sequence = first.sequence_number();
    let before_fee_sequence = first.fee_delta_sequence_number();
    let before_live = live_facts(first);
    let plan = first.plan_block_removals(block);
    assert_plan_unique(&plan);
    let projected = projected_facts(first, &plan);
    assert_eq!(first.len(), before_len, "projection mutated membership");
    assert_eq!(
        first.sequence_number(),
        before_sequence,
        "projection moved the membership sequence"
    );
    assert_eq!(
        first.fee_delta_sequence_number(),
        before_fee_sequence,
        "projection moved the fee sequence"
    );
    assert_eq!(
        live_facts(first),
        before_live,
        "projection reordered the live index"
    );
    apply_block(second, block);
    let actual: Vec<(Vec<Txid>, i128, u64)> = second
        .chunks_by_feerate()
        .map(|chunk| {
            (
                chunk.txids.to_vec(),
                chunk.modified_fee,
                chunk.charged_weight,
            )
        })
        .collect();
    assert_eq!(
        projected.len(),
        actual.len(),
        "projected chunk count diverged"
    );
    for (index, (projected_chunk, actual_chunk)) in projected.iter().zip(&actual).enumerate() {
        assert_eq!(
            projected_chunk.0, actual_chunk.0,
            "projected members diverged at chunk {index}"
        );
        assert_eq!(
            projected_chunk.1, actual_chunk.1,
            "projected modified fee diverged at chunk {index}"
        );
        assert_eq!(
            projected_chunk.2, actual_chunk.2,
            "projected charged weight diverged at chunk {index}"
        );
    }
    second.assert_index_matches_oracle("real removal after projection");
}

#[test]
fn projected_long_touched_run_still_yields_the_untouched_tail() {
    const PAIRS: u64 = 32;
    let (first, mut second) = twin_pools(|pool| {
        for pair in 0..PAIRS {
            let parent = 2 * pair + 1;
            let child = 2 * pair + 2;
            let parent_txid = insert_ordered(pool, parent, &[], 1, 100);
            insert_ordered(pool, child, &[(parent_txid, 0)], 1, 50_000);
        }
        insert_ordered(pool, 1_000, &[], 1, 100);
    });
    let mut block_txs = alloc::vec![coinbase_stub(999_990)];
    for pair in 0..PAIRS {
        block_txs.push(order_tx(2 * pair + 1, &[], 1, Sequence::MAX));
    }
    let block = test_block(block_txs);
    let plan = first.plan_block_removals(&block);
    assert_eq!(
        plan.removals.len(),
        usize::try_from(PAIRS).expect("pair count fits"),
        "every parent confirms"
    );
    assert_projection_matches_real(&first, &mut second, &block);
}

#[test]
fn projected_empty_plan_matches_live_order() {
    let (first, mut second) = twin_pools(|pool| {
        insert_ordered(pool, 1, &[], 1, order_fee(1));
        insert_ordered(pool, 2, &[], 1, order_fee(2));
    });
    let block = test_block(alloc::vec![coinbase_stub(999_991)]);
    let plan = first.plan_block_removals(&block);
    assert!(plan.removals.is_empty(), "empty block must plan nothing");
    assert_eq!(plan.fee_deltas_cleared, 0);
    assert_projection_matches_real(&first, &mut second, &block);
}

#[test]
fn projected_surviving_child_treats_confirmed_parent_as_selected() {
    let (first, mut second) = twin_pools(|pool| {
        insert_ordered(pool, 1, &[], 1, order_fee(1));
        let parent = order_tx(1, &[], 1, Sequence::MAX).txid();
        insert_ordered(pool, 2, &[(parent, 0)], 1, order_fee(2));
    });
    let parent_tx = order_tx(1, &[], 1, Sequence::MAX);
    let parent_txid = parent_tx.txid();
    let parent_id = first.entry_id_by_txid(&parent_txid).expect("parent pooled");
    let child_txid = order_tx(2, &[(parent_txid, 0)], 1, Sequence::MAX).txid();
    let child_id = first.entry_id_by_txid(&child_txid).expect("child pooled");
    let block = test_block(alloc::vec![coinbase_stub(999_992), parent_tx]);
    let plan = first.plan_block_removals(&block);
    assert_plan_unique(&plan);
    assert_eq!(
        plan.removals,
        alloc::vec![(parent_id, RemovalReason::BlockInclusion)]
    );
    let projected = first.chunks_after(&plan);
    let mut child_chunk = None;
    for chunk in projected.iter() {
        if chunk.members.contains(&child_id) {
            child_chunk = Some(chunk);
        }
    }
    let child_chunk = child_chunk.expect("surviving child stays projected");
    assert!(
        child_chunk.parents_of(child_id).next().is_none(),
        "confirmed parent must filter out of projected parents"
    );
    assert!(
        !first.parents_of(child_id).is_empty(),
        "live parents keep the confirmed edge"
    );
    assert_projection_matches_real(&first, &mut second, &block);
    assert!(second.contains_txid(&child_txid));
    assert!(!second.contains_txid(&parent_txid));
}

#[test]
fn projected_splitting_bridge_yields_independent_pieces() {
    let build = |pool: &mut Mempool| {
        insert_ordered(pool, 1, &[], 2, order_fee(1));
        let parent = order_tx(1, &[], 2, Sequence::MAX).txid();
        insert_ordered(pool, 2, &[(parent, 0)], 1, order_fee(2));
        insert_ordered(pool, 3, &[(parent, 1)], 1, order_fee(3));
    };
    let (first, mut second) = twin_pools(build);
    let parent_tx = order_tx(1, &[], 2, Sequence::MAX);
    let block = test_block(alloc::vec![coinbase_stub(999_993), parent_tx]);
    let plan = first.plan_block_removals(&block);
    assert_plan_unique(&plan);
    assert_eq!(plan.removals.len(), 1);
    let projected = projected_facts(&first, &plan);
    assert_eq!(projected.len(), 2, "split children project as two chunks");
    for (txids, _, _) in &projected {
        assert_eq!(txids.len(), 1, "split pieces never merge into one chunk");
    }
    assert_projection_matches_real(&first, &mut second, &block);
}

#[test]
fn projected_equal_rate_prefix_preserved() -> Result<(), MempoolError> {
    let build = |pool: &mut Mempool| -> Result<(), MempoolError> {
        let parent = order_tx(1, &[], 1, Sequence::MAX);
        let parent_txid = parent.txid();
        let mut parent_entry = MempoolEntry::new(Arc::new(parent), 200, 2_000, 1, 1, 0);
        parent_entry.weight = 800;
        pool.insert_entry(parent_entry)?;
        let child = order_tx(2, &[(parent_txid, 0)], 1, Sequence::MAX);
        let mut child_entry = MempoolEntry::new(Arc::new(child), 100, 1_000, 2, 1, 0);
        child_entry.weight = 400;
        pool.insert_entry(child_entry)?;
        insert_ordered(pool, 3, &[], 1, order_fee(3));
        Ok(())
    };
    let mut first = order_pool();
    let mut second = order_pool();
    build(&mut first)?;
    build(&mut second)?;
    let unrelated = order_tx(3, &[], 1, Sequence::MAX);
    let block = test_block(alloc::vec![coinbase_stub(999_994), unrelated]);
    let plan = first.plan_block_removals(&block);
    assert_plan_unique(&plan);
    assert_eq!(plan.removals.len(), 1);
    let projected = first.chunks_after(&plan);
    let mut order: Vec<Txid> = Vec::new();
    for chunk in projected.iter() {
        order.extend(chunk.txids.iter().copied());
    }
    let parent_txid = order_tx(1, &[], 1, Sequence::MAX).txid();
    let child_txid = order_tx(2, &[(parent_txid, 0)], 1, Sequence::MAX).txid();
    let parent_pos = order.iter().position(|txid| *txid == parent_txid);
    let child_pos = order.iter().position(|txid| *txid == child_txid);
    assert!(
        parent_pos.is_some_and(|parent| child_pos.is_some_and(|child| parent < child)),
        "equal-rate parent must precede its child in projection"
    );
    assert_projection_matches_real(&first, &mut second, &block);
    Ok(())
}

#[test]
fn projected_conflicts_and_descendants_match_real() -> Result<(), MempoolError> {
    let build = |pool: &mut Mempool| -> Result<OutPoint, MempoolError> {
        let other = order_tx(10, &[], 1, Sequence::MAX);
        let funding = OutPoint::new(other.txid(), 0);
        pool.insert_entry(MempoolEntry::new(
            Arc::new(other),
            200,
            order_fee(10),
            10,
            1,
            0,
        ))?;
        let rival = order_tx(11, &[(funding.txid, funding.vout)], 1, Sequence::MAX);
        let rival_txid = rival.txid();
        pool.insert_entry(MempoolEntry::new(
            Arc::new(rival),
            200,
            order_fee(11),
            11,
            1,
            0,
        ))?;
        let rival_child = order_tx(12, &[(rival_txid, 0)], 1, Sequence::MAX);
        pool.insert_entry(MempoolEntry::new(
            Arc::new(rival_child),
            200,
            order_fee(12),
            12,
            1,
            0,
        ))?;
        insert_ordered(pool, 20, &[], 1, order_fee(20));
        Ok(funding)
    };
    let mut first = order_pool();
    let mut second = order_pool();
    let other_out = build(&mut first)?;
    build(&mut second)?;
    let funding_txid = order_tx(10, &[], 1, Sequence::MAX).txid();
    let rival_txid = order_tx(11, &[(other_out.txid, other_out.vout)], 1, Sequence::MAX).txid();
    let rival_child_txid = order_tx(12, &[(rival_txid, 0)], 1, Sequence::MAX).txid();
    let singleton_txid = order_tx(20, &[], 1, Sequence::MAX).txid();
    let rival_id = first.entry_id_by_txid(&rival_txid).expect("rival pooled");
    let rival_child_id = first
        .entry_id_by_txid(&rival_child_txid)
        .expect("rival child pooled");
    let conflict = order_tx(30, &[(other_out.txid, other_out.vout)], 1, Sequence::MAX);
    let block = test_block(alloc::vec![coinbase_stub(999_995), conflict]);
    let plan = first.plan_block_removals(&block);
    assert_plan_unique(&plan);
    let mut expected = alloc::vec![
        (rival_id, RemovalReason::Conflict),
        (rival_child_id, RemovalReason::Conflict),
    ];
    expected.sort_unstable_by_key(|(id, _)| *id);
    assert_eq!(
        plan.removals, expected,
        "block spending 10:0 removes exactly the rival and its child as conflicts"
    );
    assert_projection_matches_real(&first, &mut second, &block);
    assert!(
        second.contains_txid(&funding_txid),
        "conflict sweep keeps the funding entry"
    );
    assert!(
        second.contains_txid(&singleton_txid),
        "conflict sweep keeps the unrelated singleton"
    );
    assert!(!second.contains_txid(&rival_txid));
    assert!(!second.contains_txid(&rival_child_txid));
    assert_eq!(second.len(), 2);
    Ok(())
}

#[test]
fn projected_prioritised_fees_and_cleared_overlays_match_real() {
    let mut first = order_pool();
    let mut second = order_pool();
    for pool in [&mut first, &mut second] {
        insert_ordered(&mut *pool, 1, &[], 1, 5_000);
        insert_ordered(&mut *pool, 2, &[], 1, 6_000);
        insert_ordered(&mut *pool, 3, &[], 1, 7_000);
    }
    let first_txid = order_tx(1, &[], 1, Sequence::MAX).txid();
    let second_txid = order_tx(2, &[], 1, Sequence::MAX).txid();
    for pool in [&mut first, &mut second] {
        pool.prioritise(first_txid, 50_000)
            .expect("positive overlay applies");
        pool.prioritise(second_txid, -4_000)
            .expect("negative overlay applies");
    }
    let confirmed = order_tx(1, &[], 1, Sequence::MAX);
    let block = test_block(alloc::vec![coinbase_stub(999_996), confirmed]);
    let plan = first.plan_block_removals(&block);
    assert_plan_unique(&plan);
    assert_eq!(
        plan.fee_deltas_cleared, 1,
        "only the confirmed overlay clears"
    );
    let projected = projected_facts(&first, &plan);
    assert_eq!(projected.len(), 2);
    assert_projection_matches_real(&first, &mut second, &block);
    assert_eq!(
        second.fee_delta_sequence_number(),
        first.fee_delta_sequence_number().wrapping_add(1)
    );
}

proptest! {
    #[test]
    fn projected_chunks_match_real_remove_for_block(
        actions in prop::collection::vec(
            (
                0_u64..16,
                prop::option::of(0_u64..16),
                0_usize..3,
                1_u32..3,
                0_u32..3,
            ),
            1..24,
        ),
        overlay_picks in prop::collection::vec((0_u64..16, 0_usize..5), 0..4),
        block_picks in prop::collection::vec((0_u64..16, 0_u8..2), 0..6),
    ) {
        const DELTAS: [i64; 5] = [-15_000, -1_000, 100, 1_000, 15_000];
        let mut actions = actions;
        actions.insert(0, (1, Some(0), 0, 1, 0));
        actions.insert(0, (0, None, 0, 2, 0));
        let build = |pool: &mut Mempool| {
            let mut inserted: HashMap<u64, (Txid, u32)> = HashMap::new();
            for (label, parent, fee_class, outputs, vout) in &actions {
                let fees = [order_fee(*label), 100, 50_000];
                let fee = fees[*fee_class % fees.len()];
                let mut spends = Vec::new();
                let intended_parent = if let Some(parent_label) = parent
                    && let Some(&(parent_txid, slots)) = inserted.get(parent_label)
                {
                    spends.push((parent_txid, vout % slots));
                    Some(parent_txid)
                } else {
                    None
                };
                let tx = order_tx(*label, &spends, *outputs, Sequence::MAX);
                let txid = tx.txid();
                if pool
                    .insert_entry(MempoolEntry::new(Arc::new(tx), 200, fee, *label, 1, 0))
                    .is_ok()
                {
                    inserted.insert(*label, (txid, *outputs));
                    if let Some(parent_txid) = intended_parent {
                        let child_id = pool.entry_id_by_txid(&txid);
                        let parent_id = pool.entry_id_by_txid(&parent_txid);
                        assert!(
                            child_id.is_some() && parent_id.is_some(),
                            "the child and its tracked parent must both be resident"
                        );
                        assert!(
                            child_id.zip(parent_id).is_some_and(|(child, parent)| {
                                pool.parents_of(child).contains(&parent)
                            }),
                            "label {label} must link to its tracked resident parent"
                        );
                    }
                }
            }
        };
        let (mut first, mut second) = twin_pools(build);
        let pooled_for_overlays = first.iter_txids();
        for (label, delta_idx) in &overlay_picks {
            let target = if pooled_for_overlays.is_empty() {
                order_tx(*label, &[], 1, Sequence::MAX).txid()
            } else {
                let at = usize::try_from(*label).expect("label fits usize") % pooled_for_overlays.len();
                pooled_for_overlays[at]
            };
            let delta = DELTAS[*delta_idx % DELTAS.len()];
            let _ = first.prioritise(target, delta);
            let _ = second.prioritise(target, delta);
        }
        let pooled = first.iter_txids();
        let mut block_txs = alloc::vec![coinbase_stub(999_997)];
        for (index, (label, kind)) in block_picks.iter().enumerate() {
            if pooled.is_empty() {
                block_txs.push(order_tx(*label, &[], 1, Sequence::MAX));
                continue;
            }
            let at = usize::try_from(*label).expect("label fits usize") % pooled.len();
            let victim = pooled[at];
            if *kind == 0 {
                if let Some(tx) = first.transaction_by_txid(&victim) {
                    block_txs.push(tx.as_ref().clone());
                }
            } else if let Some(entry) = first.entry_by_txid(&victim) {
                if let Some(input) = entry.tx.inputs.first() {
                    let out = input.previous_output;
                    let step = u64::try_from(index).expect("index fits u64");
                    let fresh = label.wrapping_mul(32).wrapping_add(step).wrapping_add(1_000);
                    block_txs.push(order_tx(fresh, &[(out.txid, out.vout)], 1, Sequence::MAX));
                }
            }
        }
        let block = test_block(block_txs);
        let mut id_of: HashMap<Txid, EntryId> = HashMap::new();
        for txid in first.iter_txids() {
            if let Some(id) = first.entry_id_by_txid(&txid) {
                id_of.insert(txid, id);
            }
        }
        let mut planned: HashSet<EntryId> = HashSet::new();
        let mut expected: Vec<(EntryId, RemovalReason)> = Vec::new();
        for tx in &block.txs {
            if let Some(&id) = id_of.get(&tx.txid()) {
                if planned.insert(id) {
                    expected.push((id, RemovalReason::BlockInclusion));
                }
            }
            let mut direct = Vec::new();
            for entry in first.iter_entries() {
                let Some(&eid) = id_of.get(&entry.txid) else {
                    continue;
                };
                if planned.contains(&eid) {
                    continue;
                }
                let mut hits = false;
                for binput in &tx.inputs {
                    for einput in &entry.tx.inputs {
                        if einput.previous_output == binput.previous_output {
                            hits = true;
                            break;
                        }
                    }
                    if hits {
                        break;
                    }
                }
                if hits {
                    direct.push(eid);
                }
            }
            direct.sort_unstable();
            direct.dedup();
            for root in direct {
                if planned.contains(&root) {
                    continue;
                }
                let mut seen_local: HashSet<EntryId> = HashSet::new();
                seen_local.insert(root);
                let mut subtree = alloc::vec![root];
                let mut stack = alloc::vec![root];
                while let Some(current) = stack.pop() {
                    for child_txid in first.spender_txids(current) {
                        let Some(&child) = id_of.get(&child_txid) else {
                            continue;
                        };
                        if planned.contains(&child) {
                            continue;
                        }
                        if seen_local.insert(child) {
                            subtree.push(child);
                            stack.push(child);
                        }
                    }
                }
                subtree.sort_unstable();
                for id in subtree {
                    if planned.insert(id) {
                        expected.push((id, RemovalReason::Conflict));
                    }
                }
            }
        }
        let overlay_set: HashSet<Txid> = first
            .prioritised_transactions()
            .into_iter()
            .map(|row| row.txid)
            .collect();
        let mut seen_block: HashSet<Txid> = HashSet::new();
        let mut expected_cleared = 0_u64;
        for tx in &block.txs {
            let txid = tx.txid();
            if seen_block.insert(txid) && overlay_set.contains(&txid) {
                expected_cleared += 1;
            }
        }
        let plan = first.plan_block_removals(&block);
        assert_plan_unique(&plan);
        assert_eq!(
            plan.fee_deltas_cleared, expected_cleared,
            "cleared-overlay count diverged from the overlay set"
        );
        assert_eq!(
            plan.removals, expected,
            "planned set and reasons diverged from the input-descendant oracle"
        );
        assert_projection_matches_real(&first, &mut second, &block);
    }
}
