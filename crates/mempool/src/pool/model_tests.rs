use alloc::sync::Arc;
use alloc::vec::Vec;

use bitcoin_rs_consensus::primitives::{
    Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid,
};
use hashbrown::{HashMap, HashSet};
use proptest::prelude::*;

use super::{EntryId, Mempool, MempoolEntry, MempoolLimits};
use crate::ReplacementCandidate;
use crate::mutation::MutationOutcome;
use crate::policy::MEMPOOL_EXPIRY_SECS;

const FEE_TIERS: [u64; 6] = [0, 500, 1_000, 10_000, 100_000, 1_000_000];
const VSIZE_TIERS: [u32; 5] = [100, 200, 400, 1_000, 2_000];

fn model_tx(nonce: u32, inputs: &[OutPoint], outputs_count: u32) -> Tx {
    let out_count = outputs_count.max(1);
    Tx {
        version: 2,
        lock_time: LockTime::from_consensus(nonce),
        inputs: inputs
            .iter()
            .map(|previous_output| TxIn {
                previous_output: *previous_output,
                script_sig: Script::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin_rs_consensus::primitives::Witness::new(),
            })
            .collect(),
        outputs: (0..out_count)
            .map(|vout| {
                let vout_u8 = u8::try_from(vout % 256).unwrap_or(0);
                TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: Script::from_bytes(alloc::vec![0x51, 0x20, vout_u8]),
                }
            })
            .collect(),
    }
}

#[derive(Clone, Debug)]
struct NaiveEntry {
    tx: Arc<Tx>,
    vsize: u32,
    fee: u64,
    time: u64,
}

#[derive(Default)]
struct NaiveMempool {
    entries: HashMap<Txid, NaiveEntry>,
    spends: HashMap<OutPoint, HashSet<Txid>>,
}

impl NaiveMempool {
    fn contains_txid(&self, txid: &Txid) -> bool {
        self.entries.contains_key(txid)
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn children_of(&self, txid: &Txid) -> HashSet<Txid> {
        let mut children = HashSet::new();
        for (child_txid, entry) in &self.entries {
            for input in &entry.tx.inputs {
                if input.previous_output.txid == *txid {
                    children.insert(*child_txid);
                }
            }
        }
        children
    }

    fn ancestors_of(&self, txid: &Txid) -> HashSet<Txid> {
        let mut ancestors = HashSet::new();
        let mut stack = alloc::vec![*txid];
        while let Some(current) = stack.pop() {
            let Some(entry) = self.entries.get(&current) else {
                continue;
            };
            for input in &entry.tx.inputs {
                let parent = input.previous_output.txid;
                if self.entries.contains_key(&parent) && ancestors.insert(parent) {
                    stack.push(parent);
                }
            }
        }
        ancestors
    }

    fn collect_descendants(&self, root: &Txid) -> HashSet<Txid> {
        let mut descendants = HashSet::new();
        let mut stack = alloc::vec![*root];
        descendants.insert(*root);
        while let Some(current) = stack.pop() {
            for child in self.children_of(&current) {
                if descendants.insert(child) {
                    stack.push(child);
                }
            }
        }
        descendants
    }

    fn insert(&mut self, tx: Arc<Tx>, vsize: u32, fee: u64, time: u64) {
        let txid = tx.txid();
        for input in &tx.inputs {
            self.spends
                .entry(input.previous_output)
                .or_default()
                .insert(txid);
        }
        self.entries.insert(
            txid,
            NaiveEntry {
                tx,
                vsize,
                fee,
                time,
            },
        );
    }

    fn remove(&mut self, txid: &Txid) -> Option<NaiveEntry> {
        let entry = self.entries.remove(txid)?;
        for input in &entry.tx.inputs {
            if let Some(set) = self.spends.get_mut(&input.previous_output) {
                set.remove(txid);
                if set.is_empty() {
                    self.spends.remove(&input.previous_output);
                }
            }
        }
        Some(entry)
    }

    fn remove_all(&mut self, txids: &HashSet<Txid>) {
        for txid in txids {
            self.remove(txid);
        }
    }

    fn conflicts_for(&self, tx: &Tx) -> HashSet<Txid> {
        let mut conflicts = HashSet::new();
        for input in &tx.inputs {
            if let Some(residents) = self.spends.get(&input.previous_output) {
                for &resident in residents {
                    if resident != tx.txid() {
                        conflicts.insert(resident);
                    }
                }
            }
        }
        conflicts
    }

    fn all_conflicts_and_descendants(&self, direct: &HashSet<Txid>) -> HashSet<Txid> {
        let mut all = HashSet::new();
        for conflict in direct {
            for desc in self.collect_descendants(conflict) {
                all.insert(desc);
            }
        }
        all
    }
    fn evaluate_bip125_replacement(
        &self,
        candidate: &Tx,
        candidate_fee: u64,
        candidate_vsize: u32,
    ) -> Option<HashSet<Txid>> {
        let direct = self.conflicts_for(candidate);
        if direct.is_empty() {
            return None;
        }
        let victims = self.all_conflicts_and_descendants(&direct);
        if victims.len() > 100 {
            return None;
        }
        for input in &candidate.inputs {
            if victims.contains(&input.previous_output.txid) {
                return None;
            }
        }
        let victims_fee: u64 = victims
            .iter()
            .filter_map(|t| self.entries.get(t))
            .map(|e| e.fee)
            .sum();
        let min_relay_bump = u64::from(candidate_vsize);
        let min_required = victims_fee.saturating_add(min_relay_bump);
        if candidate_fee <= victims_fee || candidate_fee < min_required {
            return None;
        }
        let victims_vsize: u64 = victims
            .iter()
            .filter_map(|t| self.entries.get(t))
            .map(|e| u64::from(e.vsize))
            .sum();
        if u128::from(candidate_fee) * u128::from(victims_vsize.max(1))
            <= u128::from(victims_fee) * u128::from(candidate_vsize)
        {
            return None;
        }
        Some(victims)
    }

    fn plan_block_removals(&self, block_txs: &[Tx], block_txids: &[Txid]) -> HashSet<Txid> {
        let mut to_remove = HashSet::new();
        for txid in block_txids {
            if self.entries.contains_key(txid) {
                to_remove.insert(*txid);
            }
        }
        for btx in block_txs {
            let conflicts = self.conflicts_for(btx);
            for conf in conflicts {
                if !to_remove.contains(&conf) {
                    to_remove.extend(self.collect_descendants(&conf));
                }
            }
        }
        to_remove
    }

    fn plan_expiry(&self, current_time: u64) -> HashSet<Txid> {
        let cutoff = current_time.saturating_sub(MEMPOOL_EXPIRY_SECS);
        let expired_roots: HashSet<Txid> = self
            .entries
            .iter()
            .filter(|(_, e)| e.time < cutoff)
            .map(|(t, _)| *t)
            .collect();
        self.all_conflicts_and_descendants(&expired_roots)
    }
}

fn assert_ancestor_descendant_invariants(pool: &Mempool) {
    for (index, entry) in pool.entries.iter() {
        let id = EntryId::try_from(index).expect("id fits u32");

        let mut ancestors: HashSet<EntryId> = HashSet::new();
        let mut queue = alloc::vec![id];
        while let Some(current) = queue.pop() {
            if let Some(links) = pool.links(current) {
                for &parent in &links.parents {
                    if ancestors.insert(parent) {
                        queue.push(parent);
                    }
                }
            }
        }
        let expected_anc_count =
            u32::try_from(ancestors.len().saturating_add(1)).unwrap_or(u32::MAX);
        let mut expected_anc_size = u64::from(entry.vsize);
        let mut expected_anc_fee = entry.fee;
        let mut expected_anc_fee_delta = i128::from(entry.fee_delta);
        for &parent_id in &ancestors {
            if let Some(parent) = pool.entry(parent_id) {
                expected_anc_size = expected_anc_size.saturating_add(u64::from(parent.vsize));
                expected_anc_fee = expected_anc_fee.saturating_add(parent.fee);
                expected_anc_fee_delta =
                    expected_anc_fee_delta.saturating_add(i128::from(parent.fee_delta));
            }
        }
        assert_eq!(pool.ancestor_count_inclusive(id), expected_anc_count);
        assert_eq!(entry.ancestor_size, expected_anc_size);
        assert_eq!(entry.ancestor_fee, expected_anc_fee);
        assert_eq!(entry.ancestor_fee_delta, expected_anc_fee_delta);

        let mut descendants: HashSet<EntryId> = HashSet::new();
        let mut queue = alloc::vec![id];
        while let Some(current) = queue.pop() {
            if let Some(links) = pool.links(current) {
                for &child in &links.children {
                    if descendants.insert(child) {
                        queue.push(child);
                    }
                }
            }
        }
        let expected_desc_count =
            u32::try_from(descendants.len().saturating_add(1)).unwrap_or(u32::MAX);
        let mut expected_desc_size = u64::from(entry.vsize);
        let mut expected_desc_fee = entry.fee;
        let mut expected_desc_fee_delta = i128::from(entry.fee_delta);
        for &child_id in &descendants {
            if let Some(child) = pool.entry(child_id) {
                expected_desc_size = expected_desc_size.saturating_add(u64::from(child.vsize));
                expected_desc_fee = expected_desc_fee.saturating_add(child.fee);
                expected_desc_fee_delta =
                    expected_desc_fee_delta.saturating_add(i128::from(child.fee_delta));
            }
        }
        assert_eq!(pool.descendant_count_inclusive(id), expected_desc_count);
        assert_eq!(entry.descendant_size, expected_desc_size);
        assert_eq!(entry.descendant_fee, expected_desc_fee);
        assert_eq!(entry.descendant_fee_delta, expected_desc_fee_delta);
    }
}

fn assert_accounting_invariants(pool: &Mempool) {
    let mut sum_vsize = 0_u64;
    let mut sum_fees = 0_u64;
    let mut count = 0_usize;
    for (_index, entry) in pool.entries.iter() {
        sum_vsize = sum_vsize.saturating_add(u64::from(entry.vsize));
        sum_fees = sum_fees.saturating_add(entry.fee);
        count = count.saturating_add(1);
        assert_eq!(
            crate::accounting::charged_weight(entry.weight, entry.vsize, entry.sigop_cost),
            entry.policy_weight()
        );
    }
    assert_eq!(pool.total_vsize(), sum_vsize);
    assert_eq!(pool.stats().bytes, sum_vsize);
    assert_eq!(pool.aggregate_fees(), sum_fees);
    assert_eq!(pool.stats().total_fee, sum_fees);
    assert_eq!(pool.len(), count);
    assert_eq!(pool.stats().txs, u64::try_from(count).unwrap_or(u64::MAX));
    assert_eq!(pool.dynamic_memory_usage(), pool.recount_memory_usage());
}

fn assert_edge_invariants(pool: &Mempool) {
    for (index, entry) in pool.entries.iter() {
        let id = EntryId::try_from(index).expect("id fits u32");
        let links = pool.links(id).expect("live entry links");

        for &parent in &links.parents {
            assert!(pool.entry(parent).is_some());
            let parent_links = pool.links(parent).expect("parent links");
            assert!(parent_links.children.contains(&id));
        }
        for &child in &links.children {
            assert!(pool.entry(child).is_some());
            let child_links = pool.links(child).expect("child links");
            assert!(child_links.parents.contains(&id));
        }
        for input in &entry.tx.inputs {
            if let Some(parent_id) = pool.entry_id_by_txid(&input.previous_output.txid) {
                assert!(links.parents.contains(&parent_id));
            }
        }
    }
}

fn assert_pool_matches_model(pool: &Mempool, naive: &NaiveMempool) {
    assert_eq!(pool.len(), naive.len());
    for (txid, entry) in &naive.entries {
        let pooled = pool.entry_by_txid(txid).expect("pooled entry");
        assert_eq!(pooled.fee, entry.fee);
        assert_eq!(pooled.vsize, entry.vsize);
        assert_eq!(pooled.time, entry.time);
    }
    for (_index, entry) in pool.entries.iter() {
        assert!(naive.contains_txid(&entry.txid));
    }
}
#[derive(Clone, Copy, Debug)]
struct AddParams {
    nonce: u32,
    fee_tier: usize,
    vsize_tier: usize,
    outputs_count: u32,
}

struct ModelDriver {
    pool: Mempool,
    naive: NaiveMempool,
    reorg_stash: Vec<Arc<Tx>>,
    current_time: u64,
    height: u32,
    root_counter: u32,
}

impl ModelDriver {
    fn new() -> Self {
        Self {
            pool: Mempool::new(MempoolLimits {
                max_total_bytes: 0,
                min_relay_fee_sat_per_kvb: 0,
                cluster_count: 64,
                ..MempoolLimits::default()
            }),
            naive: NaiveMempool::default(),
            reorg_stash: Vec::new(),
            current_time: 1_700_000_000,
            height: 800_000,
            root_counter: 0,
        }
    }

    fn apply_add(&mut self, params: AddParams, parent_picks: &[usize]) {
        let pooled = self.pool.iter_txids();
        let mut inputs = Vec::new();
        if !pooled.is_empty() && !parent_picks.is_empty() {
            for &pick in parent_picks {
                let parent_txid = pooled[pick % pooled.len()];
                if let Some(entry) = self.naive.entries.get(&parent_txid) {
                    let vout = u32::try_from(pick % entry.tx.outputs.len().max(1)).unwrap_or(0);
                    let point = OutPoint::new(parent_txid, vout);
                    if !inputs.contains(&point) && !self.naive.spends.contains_key(&point) {
                        inputs.push(point);
                    }
                }
            }
        }
        if inputs.is_empty() {
            let mut seed = [0xA5_u8; 32];
            let root_id = self.root_counter;
            self.root_counter = self.root_counter.wrapping_add(1);
            seed[..4].copy_from_slice(&root_id.to_le_bytes());
            inputs.push(OutPoint::new(Txid::from(Hash256::from_le_bytes(&seed)), 0));
        }
        let tx = Arc::new(model_tx(params.nonce, &inputs, params.outputs_count));
        let fee = FEE_TIERS[params.fee_tier % FEE_TIERS.len()];
        let vsize = VSIZE_TIERS[params.vsize_tier % VSIZE_TIERS.len()];
        let entry = MempoolEntry::new(
            Arc::clone(&tx),
            vsize,
            fee,
            self.current_time,
            self.height,
            0,
        );
        if self.naive.contains_txid(&tx.txid()) {
            return;
        }
        match self.pool.insert_entry(entry) {
            Ok(_) => self.naive.insert(tx, vsize, fee, self.current_time),
            Err(error) => panic!(
                "model predicts acceptance for a fresh insertion that spends only unspent outpoints, but the pool refused: {error:?}"
            ),
        }
    }
    fn apply_replace(&mut self, nonce: u32, victim_pick: usize, fee_bump: u64, shortfall: bool) {
        let pooled = self.pool.iter_txids();
        if pooled.is_empty() {
            return;
        }
        let victim_txid = pooled[victim_pick % pooled.len()];
        let Some(victim) = self.naive.entries.get(&victim_txid) else {
            return;
        };
        let Some(first_in) = victim.tx.inputs.first() else {
            return;
        };
        let conflict_outpoint = first_in.previous_output;
        let candidate = Arc::new(model_tx(nonce, &[conflict_outpoint], 2));
        let direct = self.naive.conflicts_for(&candidate);
        let victims = self.naive.all_conflicts_and_descendants(&direct);
        let victims_fee: u64 = victims
            .iter()
            .filter_map(|t| self.naive.entries.get(t))
            .map(|e| e.fee)
            .sum();
        let victims_vsize: u64 = victims
            .iter()
            .filter_map(|t| self.naive.entries.get(t))
            .map(|e| u64::from(e.vsize))
            .sum();
        let rate_fee = victims_fee
            .saturating_mul(200)
            .checked_div(victims_vsize.max(1))
            .unwrap_or(0);
        let fee = if shortfall {
            victims_fee / 2
        } else {
            victims_fee
                .max(rate_fee)
                .saturating_add(10_000)
                .saturating_add(fee_bump)
        };
        if self.naive.contains_txid(&candidate.txid()) {
            return;
        }
        let expected = self.naive.evaluate_bip125_replacement(&candidate, fee, 200);
        let repl = ReplacementCandidate::new(Arc::clone(&candidate), 200, fee, 0);
        let outcome = self
            .pool
            .replace_transaction(&repl, self.current_time, self.height);
        let Some(victims) = expected else {
            assert!(
                outcome.is_err(),
                "model predicts a BIP125 rejection, but the pool accepted the replacement"
            );
            return;
        };
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(crate::rbf::RbfError::InsufficientFeerateDiagram) => return,
            Err(error) => {
                panic!(
                    "model predicts a BIP125-valid replacement, but the pool refused: {error:?}"
                );
            }
        };
        let mut pool_removed = HashSet::new();
        for change in outcome.changes {
            if let MutationOutcome::Removed(_) = change.outcome {
                pool_removed.insert(Txid(change.txid));
            }
        }
        assert_eq!(
            pool_removed, victims,
            "pool removed set must equal BIP125 victims"
        );
        self.naive.remove_all(&victims);
        self.naive.insert(candidate, 200, fee, self.current_time);
    }

    fn apply_remove_for_block(
        &mut self,
        block_picks: &[usize],
        conflict_pick: Option<usize>,
        nonce: u32,
    ) {
        let pooled = self.pool.iter_txids();
        if pooled.is_empty() {
            return;
        }
        let mut block_spent_inputs: HashSet<OutPoint> = HashSet::new();
        let mut mined: HashSet<Txid> = HashSet::new();
        let mut block_txs = Vec::new();
        for &pick in block_picks {
            let txid = pooled[pick % pooled.len()];
            for ancestor in self.naive.ancestors_of(&txid) {
                mined.insert(ancestor);
            }
            mined.insert(txid);
        }
        let mut mined: Vec<Txid> = mined.into_iter().collect();
        mined.sort_unstable_by_key(|txid| {
            let depth = self.naive.ancestors_of(txid).len();
            (depth, *txid)
        });
        for txid in &mined {
            if let Some(entry) = self.naive.entries.get(txid) {
                let tx = entry.tx.as_ref().clone();
                if tx
                    .inputs
                    .iter()
                    .any(|i| block_spent_inputs.contains(&i.previous_output))
                {
                    continue;
                }
                for input in &tx.inputs {
                    block_spent_inputs.insert(input.previous_output);
                }
                block_txs.push(tx);
            }
        }
        if let Some(cpick) = conflict_pick
            && let Some(entry) = self.naive.entries.get(&pooled[cpick % pooled.len()])
            && let Some(in0) = entry.tx.inputs.first()
            && !block_spent_inputs.contains(&in0.previous_output)
        {
            block_spent_inputs.insert(in0.previous_output);
            let mut conf_tx = model_tx(nonce, &[in0.previous_output], 1);
            conf_tx.version = 1;
            block_txs.push(conf_tx);
        }
        if block_txs.is_empty() {
            return;
        }
        let block_refs: Vec<&Tx> = block_txs.iter().collect();
        let block_id_list: Vec<Txid> = block_txs.iter().map(Tx::txid).collect();
        let expected_removals = self.naive.plan_block_removals(&block_txs, &block_id_list);
        let outcome = self.pool.remove_for_block(
            &crate::settlement::TransitionFacts::from_txs(&block_refs),
            self.height.saturating_add(1),
            self.current_time,
        );
        let mut pool_removed = HashSet::new();
        for change in outcome.changes {
            if let MutationOutcome::Removed(_) = change.outcome {
                pool_removed.insert(Txid(change.txid));
            }
        }
        assert_eq!(
            pool_removed, expected_removals,
            "pool removals must match naive model block removals"
        );
        for tid in &expected_removals {
            if let Some(entry) = self.naive.remove(tid) {
                self.reorg_stash.push(entry.tx);
            }
        }
    }

    fn apply_evict(&mut self, keep_percent: u8) {
        if self.pool.is_empty() {
            return;
        }
        let pct = u64::from(keep_percent.clamp(10, 90));
        let target = self.pool.dynamic_memory_usage().saturating_mul(pct) / 100;
        if let Ok(changes) = crate::eviction::evict_lowest_fee_packages(&mut self.pool, target) {
            for change in changes {
                let txid = Txid(change.txid);
                self.naive.remove(&txid);
            }
        }
    }

    fn apply_expire(&mut self, hours_elapsed: u32) {
        self.current_time = self
            .current_time
            .saturating_add(u64::from(hours_elapsed) * 3600);
        let expected_expired = self.naive.plan_expiry(self.current_time);
        let outcome = self.pool.expire(self.current_time);
        let mut pool_expired = HashSet::new();
        for change in outcome.changes {
            if let MutationOutcome::Removed(_) = change.outcome {
                pool_expired.insert(Txid(change.txid));
            }
        }
        assert_eq!(
            pool_expired, expected_expired,
            "pool expired set must match naive model expiry"
        );
        self.naive.remove_all(&expected_expired);
    }

    fn apply_reorg_readd(&mut self, count: usize) {
        let mut readded = 0_usize;
        let mut remaining = Vec::new();
        for tx in self.reorg_stash.drain(..) {
            let can_readd = readded < count
                && tx
                    .inputs
                    .iter()
                    .all(|i| !self.naive.spends.contains_key(&i.previous_output));
            if can_readd {
                let entry = MempoolEntry::new(
                    Arc::clone(&tx),
                    200,
                    10_000,
                    self.current_time,
                    self.height,
                    0,
                );
                match self.pool.insert_entry(entry) {
                    Ok(_) => {}
                    Err(error) => panic!(
                        "model predicts acceptance for the reorg re-add, but the pool refused: {error:?}"
                    ),
                }
                self.naive.insert(tx, 200, 10_000, self.current_time);
                readded = readded.saturating_add(1);
                continue;
            }
            remaining.push(tx);
        }
        self.reorg_stash = remaining;
    }

    fn assert_invariants(&self) {
        assert_ancestor_descendant_invariants(&self.pool);
        self.pool.assert_index_matches_oracle("model command step");
        assert_accounting_invariants(&self.pool);
        assert_edge_invariants(&self.pool);
        assert_pool_matches_model(&self.pool, &self.naive);
    }
}

#[derive(Clone, Debug)]
enum ModelOp {
    Add {
        params: AddParams,
        parent_picks: Vec<usize>,
        time_offset: u64,
    },
    Replace {
        nonce: u32,
        victim_pick: usize,
        fee_bump: u64,
        shortfall: bool,
        time_offset: u64,
    },
    RemoveForBlock {
        block_picks: Vec<usize>,
        conflict_pick: Option<usize>,
        nonce: u32,
        time_offset: u64,
    },
    Evict {
        keep_percent: u8,
    },
    Expire {
        hours_elapsed: u32,
    },
    ReorgReAdd {
        count: usize,
    },
}

fn arb_model_op() -> impl Strategy<Value = ModelOp> {
    prop_oneof![
        3 => (
            any::<u32>(),
            prop::collection::vec(0_usize..16, 0..3),
            0_usize..6,
            0_usize..5,
            1_u32..4,
            0_u64..100,
        ).prop_map(|(nonce, parent_picks, fee_tier, vsize_tier, outputs_count, time_offset)| {
            ModelOp::Add {
                params: AddParams {
                    nonce,
                    fee_tier,
                    vsize_tier,
                    outputs_count,
                },
                parent_picks,
                time_offset,
            }
        }),
        1 => (
            any::<u32>(),
            0_usize..16,
            0_u64..50_000,
            any::<bool>(),
            0_u64..100,
        ).prop_map(|(nonce, victim_pick, fee_bump, shortfall, time_offset)| {
            ModelOp::Replace {
                nonce,
                victim_pick,
                fee_bump,
                shortfall,
                time_offset,
            }
        }),
        1 => (
            prop::collection::vec(0_usize..16, 1..4),
            prop::option::of(0_usize..16),
            any::<u32>(),
            0_u64..100,
        ).prop_map(|(block_picks, conflict_pick, nonce, time_offset)| {
            ModelOp::RemoveForBlock {
                block_picks,
                conflict_pick,
                nonce,
                time_offset,
            }
        }),
        1 => (10_u8..90).prop_map(|keep_percent| ModelOp::Evict { keep_percent }),
        1 => (1_u32..400).prop_map(|hours_elapsed| ModelOp::Expire { hours_elapsed }),
        1 => (1_usize..4).prop_map(|count| ModelOp::ReorgReAdd { count }),
    ]
}

fn proptest_cases(default: u32) -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: proptest_cases(256),
        ..ProptestConfig::default()
    })]
    // POL-03, POL-05, MPL-02
    #[test]
    fn mempool_model_command_sequence_preserves_all_invariants(
        ops in prop::collection::vec(arb_model_op(), 1..32)
    ) {
        let mut driver = ModelDriver::new();

        for op in ops {
            match op {
                ModelOp::Add {
                    params,
                    parent_picks,
                    time_offset,
                } => {
                    driver.current_time = driver.current_time.saturating_add(time_offset);
                    driver.apply_add(params, &parent_picks);
                }
                ModelOp::Replace {
                    nonce,
                    victim_pick,
                    fee_bump,
                    shortfall,
                    time_offset,
                } => {
                    driver.current_time = driver.current_time.saturating_add(time_offset);
                    driver.apply_replace(nonce, victim_pick, fee_bump, shortfall);
                }
                ModelOp::RemoveForBlock {
                    block_picks,
                    conflict_pick,
                    nonce,
                    time_offset,
                } => {
                    driver.current_time = driver.current_time.saturating_add(time_offset);
                    driver.apply_remove_for_block(&block_picks, conflict_pick, nonce);
                }
                ModelOp::Evict { keep_percent } => {
                    driver.apply_evict(keep_percent);
                }
                ModelOp::Expire { hours_elapsed } => {
                    driver.apply_expire(hours_elapsed);
                }
                ModelOp::ReorgReAdd { count } => {
                    driver.apply_reorg_readd(count);
                }
            }

            driver.assert_invariants();
        }
    }
}
