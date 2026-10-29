use super::*;
use crate::template::{SelectedBody, select_template_body, select_template_body_after};
use bitcoin_rs_chain::{BlockTree, ChainTxCount, NodeStatus};
use bitcoin_rs_mempool::{Mempool, MempoolEntry, MempoolLimits};
use bitcoin_rs_primitives::{Block, Sequence, TxIn, Txid, Witness};
use compact_str::CompactString;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::sync::mpsc::{Sender, channel};
use std::thread;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

pub(super) struct Sources {
    tree: BlockTree,
    pub(super) tip: TipSnapshot,
    pub(super) pool: Mutex<Mempool>,
    wait_probe: Mutex<Option<(usize, Sender<()>)>>,
    pub(super) ordinary_walks: AtomicUsize,
    pub(super) budgeted_walks: AtomicUsize,
}

impl AppliedTipSource for Sources {
    fn applied_tip(&self) -> Option<TipSnapshot> {
        Some(self.tip.clone())
    }
}

impl ChainContextSource for Sources {
    fn resolve_mining_context(
        &self,
        tip: &TipSnapshot,
        time: u32,
    ) -> Result<MiningChainContext, ChainError> {
        MiningChainContext::resolve(&self.tree, Network::Regtest, tip.tip_id, time)
    }
    fn tip_bits(&self, tip: &TipSnapshot) -> Result<CompactTarget, ChainError> {
        Ok(self.tree.node(tip.tip_id)?.header.bits)
    }
    fn signalling_rules(&self, _: &TipSnapshot, _: u32) -> Vec<AvailableMiningRule> {
        Vec::new()
    }
}

impl MempoolSnapshotSource for Sources {
    fn current_revisions(&self) -> (u64, u64) {
        let mut probe = self.wait_probe.lock();
        if let Some((remaining, signal)) = probe.as_mut() {
            *remaining -= 1;
            if *remaining == 0 {
                let _ = signal.send(());
                *probe = None;
            }
        }
        let pool = self.pool.lock();
        (pool.sequence_number(), pool.fee_delta_sequence_number())
    }
    fn select_template(
        &self,
        expected_sequences: Option<(u64, u64)>,
        context: &CandidateContext,
        payout: &[u8],
        budget: Option<CoinbaseBudget>,
    ) -> Result<Option<SelectedBody>, MiningControlError> {
        let pool = self.pool.lock();
        if expected_sequences.is_some_and(|(sequence, fee_revision)| {
            pool.sequence_number() != sequence || pool.fee_delta_sequence_number() != fee_revision
        }) {
            return Ok(None);
        }
        let walks = if budget.is_some() {
            &self.budgeted_walks
        } else {
            &self.ordinary_walks
        };
        walks.fetch_add(1, Ordering::SeqCst);
        select_template_body(&pool, context, payout, budget)
            .map(Some)
            .map_err(|error| MiningControlError::Failed(CompactString::from(error.to_string())))
    }
    fn select_template_after(
        &self,
        block: &Block,
        context: &CandidateContext,
        payout: &[u8],
    ) -> Result<PreparedTemplateBody, MiningControlError> {
        let pool = self.pool.lock();
        let source_sequences = (pool.sequence_number(), pool.fee_delta_sequence_number());
        let plan = pool.plan_block_removals(block);
        let body = select_template_body_after(&pool, &plan, context, payout)
            .map_err(|error| MiningControlError::Failed(CompactString::from(error.to_string())))?;
        let removals = plan
            .removals
            .iter()
            .filter_map(|(id, reason)| pool.entry(*id).map(|entry| (entry.txid, *reason)))
            .collect();
        Ok(PreparedTemplateBody {
            body,
            source_sequences,
            removals,
        })
    }
    fn selection_snapshot(
        &self,
        selection: &GenerateSelection,
        context: &CandidateContext,
    ) -> Result<MempoolMiningSnapshot, MiningControlError> {
        snapshot_for_selection(
            self.pool.lock().mining_snapshot(),
            selection,
            &[],
            context.segwit_active,
        )
    }
    fn pooled_transaction_count(&self) -> u64 {
        u64::try_from(self.pool.lock().len()).unwrap_or(u64::MAX)
    }
    fn min_relay_fee_sat_per_kvb(&self) -> u64 {
        self.pool.lock().min_relay_fee_sat_per_kvb()
    }
}

pub(super) fn service_over(pool: Mempool) -> TestResult<(Arc<Sources>, Arc<MiningService>)> {
    let mut tree = BlockTree::new();
    let genesis = Network::Regtest.genesis_block();
    let tip_id = tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
    let node = tree.node(tip_id)?;
    let tip = TipSnapshot {
        tip_id,
        height: node.height,
        hash: node.hash,
        chainwork: node.chainwork,
        chain_tx_count: ChainTxCount::established(1),
    };
    let source = Arc::new(Sources {
        tree,
        tip,
        pool: Mutex::new(pool),
        wait_probe: Mutex::new(None),
        ordinary_walks: AtomicUsize::new(0),
        budgeted_walks: AtomicUsize::new(0),
    });
    let service = Arc::new(MiningService::new(
        Network::Regtest,
        source.clone(),
        source.clone(),
        source.clone(),
        vec![0x51],
        Arc::new(AtomicBool::new(false)),
    ));
    Ok((source, service))
}

fn fixture() -> TestResult<(Arc<Sources>, Arc<MiningService>, Txid)> {
    let mut pool = Mempool::new(MempoolLimits::default());
    let mut low = Txid::default();
    for (label, fee) in [(1_u8, 1_000), (2, 10_000)] {
        let tx = Arc::new(Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Hash256::from_le_bytes(&[label; 32]).into(), 0),
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: vec![0x51].into(),
            }],
        });
        if label == 1 {
            low = tx.txid();
        }
        pool.insert_entry(MempoolEntry::new(tx, 100, fee, 1, 0, 0))?;
    }
    let (source, service) = service_over(pool)?;
    Ok((source, service, low))
}

#[test]
fn prioritisation_rebuilds_cached_order_and_wakes_a_waiting_long_poll() -> TestResult {
    let (source, service, low) = fixture()?;
    let first = service.get_block_template(None, None)?.candidate;
    assert_ne!(first.transactions[0].txid, low);
    assert!(Arc::ptr_eq(
        &first,
        &service.get_block_template(None, None)?.candidate
    ));
    let original = source.current_revisions();
    let legacy_id = TemplateId::new(&source.tip.hash, original.0);
    assert_eq!(first.template_id, legacy_id);

    let (entered_tx, entered_rx) = channel();
    *source.wait_probe.lock() = Some((2, entered_tx));
    let (done_tx, done_rx) = channel();
    let waiting = Arc::clone(&service);
    let poll = thread::spawn(move || {
        let _ = done_tx.send(waiting.get_block_template(Some(legacy_id.as_str()), None));
    });
    entered_rx.recv_timeout(Duration::from_secs(2))?;
    drop(service.state.lock());
    assert!(done_rx.try_recv().is_err());
    source.pool.lock().prioritise(low, 100_000)?;
    assert_eq!(source.current_revisions(), (original.0, original.1 + 1));
    service.publish_generation();
    let next = done_rx.recv_timeout(Duration::from_millis(500))??.candidate;
    poll.join().map_err(|_| "long-poll worker panicked")?;
    assert_eq!(next.transactions[0].txid, low);
    assert_ne!(next.template_id, first.template_id);
    assert!(!Arc::ptr_eq(&first, &next));
    assert!(Arc::ptr_eq(
        &next,
        &service.get_block_template(None, None)?.candidate
    ));
    Ok(())
}

#[test]
fn stale_fee_snapshot_cannot_populate_the_candidate_cache() -> TestResult {
    let (source, service, low) = fixture()?;
    let stale = service.live_generation_key();
    source.pool.lock().prioritise(low, 100_000)?;
    assert!(matches!(
        service.candidate_for_key(stale),
        Err(MiningControlError::Unavailable(_))
    ));
    assert!(
        service
            .state
            .lock()
            .cache_get(&CandidateKey::ordinary(stale))
            .is_none()
    );
    let full = source.pool.lock().mining_snapshot();
    let ordered = snapshot_for_selection(
        full.clone(),
        &GenerateSelection::Ordered(Vec::new()),
        &[],
        true,
    )?;
    assert_eq!(
        (ordered.sequence, ordered.fee_delta_sequence),
        (full.sequence, full.fee_delta_sequence)
    );
    assert_eq!(
        service
            .get_block_template(None, None)?
            .candidate
            .transactions[0]
            .txid,
        low
    );
    Ok(())
}
