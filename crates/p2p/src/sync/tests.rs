use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use arc_swap::ArcSwapOption;
// Wire seam: byte-array access on the retained bitcoin:: wire hash types.
use bitcoin::hashes::Hash;
use bitcoin_rs_chain::{BlockTree, NodeId, NodeStatus, TipSnapshot};
use bitcoin_rs_primitives::encode::double_sha256;
use bitcoin_rs_primitives::{
    Block, BlockHash, Hash256, Header, Network, OutPoint, Tx, TxIn, TxOut, Txid, consensus_bytes,
};
use crossbeam_channel::unbounded;
use hashbrown::HashMap;
use metrics::Counter;
use metrics::CounterFn;
use metrics::Gauge;
use metrics::GaugeFn;
use metrics::Histogram;
use metrics::HistogramFn;
use metrics::Key;
use metrics::KeyName;
use metrics::Metadata;
use metrics::Recorder;
use metrics::SharedString;
use metrics::Unit;
use parking_lot::Mutex;
use parking_lot::RwLock;

use super::chain::{
    BranchSwitchError, HeaderAdmission, SyncChain, SyncChainError, WindowCommitDisposition,
    WindowCommitError,
};
use super::receive::unrequested_body_admissible;
use super::{BlockSync, Inventory};
use crate::{InboundHeaders, Message, PeerInfo, PeerLease, PeerSource, PeerTable, StagedBlock};

/// One-shot scripted branch switch: `connected` hashes are reported as
/// committed (applied tip advanced, `connected_body` fired) before `error`
/// is returned, mirroring a connect walk that stopped partway.
struct ScriptedBranchSwitch {
    connected: Vec<Hash256>,
    error: BranchSwitchError,
}

/// Applied-chain stub for executor tests: real [`BlockTree`] header admission
/// and block-at-a-time applied-tip advance, with one-shot scripted commit and
/// branch-switch failures. Body classification mirrors node's apply
/// classifier: a second coinbase-shaped transaction is a permanent
/// `ExtraCoinbase` invalidity, while a body that fails the header binding
/// (txid merkle root or witness commitment) is `BodyMutated`.
pub(crate) struct TestChain {
    network: Network,
    block_tree: Arc<RwLock<BlockTree>>,
    chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
    applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    scripted_commit_failure: Mutex<Option<(Hash256, WindowCommitDisposition)>>,
    scripted_branch_switch: Mutex<Option<ScriptedBranchSwitch>>,
}

impl TestChain {
    pub(crate) fn new(
        chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
        applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
        block_tree: Arc<RwLock<BlockTree>>,
    ) -> Self {
        Self {
            network: Network::Regtest,
            block_tree,
            chain_tip,
            applied_tip,
            scripted_commit_failure: Mutex::new(None),
            scripted_branch_switch: Mutex::new(None),
        }
    }
}

impl TestChain {
    /// Binding check over an already-held tree guard — the same
    /// `softfork_state` parent derivation node applies before delegating to
    /// the consensus binding check.
    fn body_binding(&self, tree: &BlockTree, block: &Block) -> Result<(), SyncChainError> {
        let hash = Hash256::from_le_bytes(block.block_hash().as_bytes());
        let segwit_active = tree
            .lookup(hash)
            .and_then(|node_id| tree.node(node_id).ok())
            .is_none_or(|node| {
                bitcoin_rs_chain::softfork_state(tree, self.network, node.parent, node.height)
                    .segwit_active
            });
        bitcoin_rs_consensus::check_block_body_binding(block, segwit_active)
            .map_err(|error| -> SyncChainError { Box::new(error) })
    }
}

impl SyncChain for TestChain {
    fn network(&self) -> Network {
        self.network
    }

    fn block_tree(&self) -> parking_lot::RwLockReadGuard<'_, BlockTree> {
        self.block_tree.read()
    }

    fn chain_tip(&self) -> Option<Arc<TipSnapshot>> {
        self.chain_tip.load_full()
    }

    fn applied_tip(&self) -> Option<Arc<TipSnapshot>> {
        self.applied_tip.load_full()
    }

    fn block_tree_mut(&self) -> parking_lot::RwLockWriteGuard<'_, BlockTree> {
        self.block_tree.write()
    }

    fn set_tips(&self, applied: TipSnapshot, header: TipSnapshot) {
        self.applied_tip.store(Some(Arc::new(applied)));
        self.chain_tip.store(Some(Arc::new(header)));
    }

    fn bootstrap_genesis(&self) {
        if self.applied_tip.load_full().is_some() {
            return;
        }
        let genesis = self.network.genesis_block();
        let hash = Hash256::from_le_bytes(genesis.block_hash().as_bytes());
        let tree = self.block_tree.read();
        let Some(id) = tree.lookup(hash) else {
            return;
        };
        let Ok(node) = tree.node(id) else {
            return;
        };
        let snapshot = Arc::new(TipSnapshot {
            tip_id: id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
        });
        self.applied_tip.store(Some(Arc::clone(&snapshot)));
        if self.chain_tip.load_full().is_none() {
            self.chain_tip.store(Some(snapshot));
        }
    }

    fn admit_headers(&self, headers: &[Header]) -> HeaderAdmission {
        let mut tree = self.block_tree.write();
        match bitcoin_rs_chain::accept_headers(
            &mut tree,
            headers,
            self.network,
            bitcoin_rs_chain::current_unix_seconds(),
        ) {
            Ok(node_ids) => {
                let announced_tip = node_ids
                    .last()
                    .and_then(|id| tree.node(*id).ok())
                    .map(|node| node.hash);
                let active_height = tree
                    .tip()
                    .zip(announced_tip)
                    .and_then(|(active_tip, hash)| {
                        tree.active_height_of(active_tip.tip_id, hash)
                            .and_then(|height| i32::try_from(height).ok())
                    });
                HeaderAdmission::Accepted {
                    accepted: node_ids.len(),
                    announced_tip,
                    active_height,
                }
            }
            // Header validation rejected the fixture batch.
            Err(error) => HeaderAdmission::Rejected(error),
        }
    }

    fn check_body_binding(&self, block: &Block) -> Result<(), SyncChainError> {
        let tree = self.block_tree.read();
        self.body_binding(&tree, block)
    }

    fn window_len(&self, serialized_sizes: &mut dyn Iterator<Item = usize>) -> usize {
        const MAX_BLOCKS: usize = 1024;
        const MAX_BYTES: usize = 64 << 20;
        let mut count = 0_usize;
        let mut bytes = 0_usize;
        for size in serialized_sizes {
            if count == MAX_BLOCKS {
                break;
            }
            let next = bytes.saturating_add(size);
            if count > 0 && next > MAX_BYTES {
                break;
            }
            bytes = next;
            count += 1;
        }
        count
    }

    fn commit_window(
        &self,
        blocks: &[&Block],
        _bodies: &[bytes::Bytes],
    ) -> Result<usize, WindowCommitError> {
        let mut tree = self.block_tree.write();
        let mut applied = 0_usize;
        for block in blocks {
            let hash = Hash256::from_le_bytes(block.block_hash().as_bytes());
            let scripted = *self.scripted_commit_failure.lock();
            let failure = match scripted {
                Some((fail_hash, _)) if fail_hash == hash => {
                    self.scripted_commit_failure.lock().take()
                }
                _ => None,
            };
            if let Some((_, disposition)) = failure {
                // The test explicitly scripted this block to fail once.
                return Err(WindowCommitError {
                    applied,
                    disposition,
                    invalidated: Box::default(),
                    source: Box::new(std::io::Error::other("scripted commit failure")),
                });
            }
            let Some(node_id) = tree.lookup(hash) else {
                // The staged body has no corresponding header-tree node.
                return Err(WindowCommitError {
                    applied,
                    disposition: WindowCommitDisposition::Operational,
                    invalidated: Box::default(),
                    source: Box::new(std::io::Error::other("commit block not in tree")),
                });
            };
            // Mirrors node's apply classifier order: a second coinbase-shaped
            // transaction trips `ExtraCoinbase` before the merkle compare —
            // a permanent invalidity whose subtree is invalidated while the
            // transition is held. Empty bodies are header-chain fixtures.
            let coinbase_shaped = |tx: &Tx| {
                tx.inputs.len() == 1
                    && tx.inputs[0].previous_output.txid == Txid::default()
                    && tx.inputs[0].previous_output.vout == u32::MAX
            };
            if !block.txs.is_empty() && block.txs.iter().skip(1).any(coinbase_shaped) {
                let invalidated = tree
                    .invalidate_subtree(node_id)
                    .map(Vec::into_boxed_slice)
                    .unwrap_or_default();
                return Err(WindowCommitError {
                    applied,
                    disposition: WindowCommitDisposition::Permanent,
                    invalidated,
                    source: Box::new(std::io::Error::other("extra coinbase")),
                });
            }
            // A non-empty body that does not bind to its header is
            // `BodyMutated`: the body is dropped for retry and nothing is
            // invalidated.
            if !block.txs.is_empty() {
                if let Err(source) = self.body_binding(&tree, block) {
                    return Err(WindowCommitError {
                        applied,
                        disposition: WindowCommitDisposition::BodyMutated,
                        invalidated: Box::default(),
                        source,
                    });
                }
            }
            let Ok(node) = tree.node(node_id) else {
                // The looked-up header node disappeared during the fixture run.
                return Err(WindowCommitError {
                    applied,
                    disposition: WindowCommitDisposition::Operational,
                    invalidated: Box::default(),
                    source: Box::new(std::io::Error::other("commit node missing")),
                });
            };
            self.applied_tip.store(Some(Arc::new(TipSnapshot {
                tip_id: node_id,
                height: node.height,
                chainwork: node.chainwork,
                hash: node.hash,
            })));
            applied = applied.saturating_add(1);
        }
        Ok(applied)
    }

    fn switch_to_branch(
        &self,
        _target: NodeId,
        _staged_body: &mut dyn FnMut(Hash256) -> Option<(Block, bytes::Bytes)>,
        connected_body: &mut dyn FnMut(Hash256),
    ) -> Result<(), BranchSwitchError> {
        let scripted = self.scripted_branch_switch.lock().take();
        if let Some(scripted) = scripted {
            for hash in &scripted.connected {
                // Mirror the impl: each committed connect advances the
                // applied tip and fires `connected_body` so the executor
                // retires its download accounting.
                let tip = {
                    let tree = self.block_tree.read();
                    tree.lookup(*hash).and_then(|node_id| {
                        tree.node(node_id).ok().map(|node| {
                            Arc::new(TipSnapshot {
                                tip_id: node_id,
                                height: node.height,
                                chainwork: node.chainwork,
                                hash: node.hash,
                            })
                        })
                    })
                };
                if let Some(tip) = tip {
                    self.applied_tip.store(Some(tip));
                }
                connected_body(*hash);
            }
            if let BranchSwitchError::ConnectFailed {
                hash,
                disposition: WindowCommitDisposition::Permanent,
                ..
            } = &scripted.error
            {
                // Mirror the impl marking the failed block's subtree while
                // the transition is held.
                let mut tree = self.block_tree.write();
                if let Some(node_id) = tree.lookup(*hash) {
                    let _ = tree.invalidate_subtree(node_id);
                }
            }
            return Err(scripted.error);
        }
        // Branch-switch behavior is covered by node-only reorg tests.
        Err(BranchSwitchError::Other(Box::new(std::io::Error::other(
            "test chain does not switch branches",
        ))))
    }
}

/// Script-int encoding used by the regtest fixture coinbases (duplicated
/// rather than depending on `bitcoin-rs-script` from `p2p` tests).
fn push_int(value: i64) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }
    let negative = value < 0;
    let mut magnitude = value.unsigned_abs();
    let mut out = Vec::new();
    while magnitude > 0 {
        out.push(u8::try_from(magnitude & 0xff).unwrap_or_default());
        magnitude >>= 8;
    }
    if let Some(last) = out.last_mut() {
        if *last & 0x80 != 0 {
            out.push(if negative { 0x80 } else { 0 });
        } else if negative {
            *last |= 0x80;
        }
    }
    out.insert(0, u8::try_from(out.len() - 1).unwrap_or_default());
    out
}

fn check_sync_frontier_pair(
    sync: &BlockSync,
    rx: &crossbeam_channel::Receiver<Message>,
    addr: SocketAddr,
    applied: &TipSnapshot,
    target: &TipSnapshot,
) -> Result<(), Box<dyn std::error::Error>> {
    let expected =
        bitcoin_rs_chain::plan_reorg(&sync.chain.block_tree(), applied.tip_id, target.tip_id).ok();
    sync.chain.set_tips(applied.clone(), target.clone());
    assert_eq!(
        sync.outweighed_branch_target(),
        expected
            .as_ref()
            .filter(|plan| !plan.disconnect.is_empty())
            .map(|_| target.tip_id),
        "branch gate differs: {applied:?} -> {target:?}; indexed or parent-walk fixture"
    );
    sync.install_budget(super::default_sync_budget(Network::Regtest));
    let outcome = sync.send_getdata_for_pending_blocks(
        current_source(&sync.peer_table, addr),
        true,
        100,
        &test_frontier(sync),
    );
    let expected_ids = expected
        .as_ref()
        .map(|plan| plan.connect.as_slice())
        .unwrap_or_default();
    if expected_ids.is_empty() {
        assert!(!outcome.sent);
        assert!(rx.try_recv().is_err());
        return Ok(());
    }
    assert!(outcome.sent);
    let Message::GetData(inventory) = rx.try_recv()? else {
        return Err("expected witness getdata".into());
    };
    let requested = witness_block_inventory(inventory)?;
    let tree = sync.chain.block_tree();
    let expected_hashes = expected_ids
        .iter()
        .take(requested.len())
        .map(|id| tree.node(*id).map(|node| BlockHash(node.hash)))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(requested, expected_hashes);
    assert!(!requested.is_empty());
    assert!(rx.try_recv().is_err());
    Ok(())
}

#[test]
fn tick_allows_demoted_peer_when_it_is_the_only_eligible_peer()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(4)?;
    install_budget(
        &sync,
        super::SyncBudget {
            max_pending_blocks: 2,
            max_peer_inflight: 2,
            getdata_batch_limit: 2,
            ..super::default_sync_budget(Network::Regtest)
        }
        .with_pending_timeout_override(Duration::ZERO),
    );
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let rx = connect_peer(&peers, synthetic_peer(addr, 100));

    sync.tick();

    assert_applied_genesis(&applied_tip, &block_tree)?;
    let Message::GetData(first_inventory) = rx.try_recv()? else {
        return Err(std::io::Error::other("expected first getdata").into());
    };
    assert_eq!(witness_block_inventory(first_inventory)?, expected[..2]);
    let headers = rx.try_recv()?;
    if !matches!(headers, Message::GetHeaders(_)) {
        return Err(std::io::Error::other("expected getheaders").into());
    }

    sync.tick();

    let Message::GetData(retry_inventory) = rx.try_recv()? else {
        return Err(std::io::Error::other("expected retry getdata").into());
    };
    assert_eq!(witness_block_inventory(retry_inventory)?, expected[..2]);
    Ok(())
}

/// A purge of one invalidated batch stamps the owner's remaining queue
/// age at a single instant: entries of one batched request share one
/// `requested_at`, so releasing them leaves the queue start at the batch
/// origin instead of re-stamping it once per removed hash.
#[test]
fn purge_of_one_invalidated_batch_keeps_the_owner_queue_start_at_one_instant()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(8)?;
    install_budget(
        &sync,
        super::SyncBudget {
            max_pending_blocks: 4,
            max_peer_inflight: 4,
            getdata_batch_limit: 4,
            ..super::default_sync_budget(Network::Regtest)
        },
    );
    let addr = test_addr(9345, 0)?;
    let rx = connect_peer(&peers, synthetic_peer(addr, 100));

    // One peer takes the whole window: the striped getdata is one batched
    // request, so all four pendings share one request stamp.
    sync.tick();

    assert_applied_genesis(&applied_tip, &block_tree)?;
    let requested = witness_block_inventory(next_getdata(&rx)?)?;
    assert_eq!(requested, expected[..4]);
    let to_hash = |block: &BlockHash| Hash256::from_le_bytes(block.as_bytes());
    let all: Vec<Hash256> = requested.iter().map(to_hash).collect();
    let owner = current_source(&peers, addr);
    let queue_start = |sync: &BlockSync| {
        sync.scheduler
            .lock()
            .window
            .owner_queue_start_for_test(owner)
    };
    let before = queue_start(&sync)
        .unwrap_or_else(|| panic!("the batched request stamps the owner's queue start"));

    // Releasing the first two invalidated hashes leaves the surviving pair
    // owning the queue start at the batch origin.
    sync.purge_invalidated(&all[..2]);
    assert_eq!(
        queue_start(&sync),
        Some(before),
        "one purge must not re-stamp the owner's queue age per removed hash"
    );
    assert_eq!(
        sync.scheduler.lock().window.pending_owner(&all[2]),
        Some(owner)
    );

    // Releasing the rest drops the queue start with the owner's last
    // pending.
    sync.purge_invalidated(&all[2..]);
    assert_eq!(queue_start(&sync), None);
    Ok(())
}

/// Near-tip requests to a compact-relaying peer ride the compact flavor;
/// deep IBD requests and non-relaying peers keep the witness flavor. The
/// download window resolves either answer by hash, unchanged.
///
/// CONTRACT: docs/policies/p2p-compatibility.md#5-message-surface (compact
/// flavor fetch eligibility).
#[test]
fn getdata_uses_compact_flavor_only_for_relaying_peers_near_tip()
-> Result<(), Box<dyn std::error::Error>> {
    let assert_flavor = |inventory: &[Inventory], compact: bool| {
        assert!(!inventory.is_empty());
        for item in inventory {
            if compact {
                assert!(matches!(item, Inventory::CompactBlock(_)), "got {item:?}");
            } else {
                assert!(matches!(item, Inventory::WitnessBlock(_)), "got {item:?}");
            }
        }
    };
    let first_getdata = |rx: &crossbeam_channel::Receiver<Message>| -> Vec<Inventory> {
        loop {
            match rx.try_recv() {
                Ok(Message::GetData(inventory)) => return inventory,
                Ok(_) => continue,
                Err(error) => panic!("expected a getdata batch: {error}"),
            }
        }
    };

    // Relaying peer, whole four-block chain within the near-tip window:
    // every entry asks for the compact flavor.
    let (sync, peers, _block_tree, _applied, _expected) = sync_with_header_chain(4)?;
    install_budget(&sync, super::default_sync_budget(Network::Regtest));
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9_101);
    let mut relaying = synthetic_peer(addr, 100);
    relaying.compact_block_relay = true;
    let rx = connect_peer(&peers, relaying);
    sync.tick();
    assert_flavor(&first_getdata(&rx), true);

    // Same proximity without the published relay preference: witness flavor.
    let (sync, peers, _block_tree, _applied, _expected) = sync_with_header_chain(4)?;
    install_budget(&sync, super::default_sync_budget(Network::Regtest));
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9_102);
    let rx = connect_peer(&peers, synthetic_peer(addr, 100));
    sync.tick();
    assert_flavor(&first_getdata(&rx), false);

    // Relaying peer deep behind the tip (IBD): witness flavor dominates.
    let (sync, peers, _block_tree, _applied, _expected) = sync_with_header_chain(9)?;
    install_budget(
        &sync,
        super::SyncBudget {
            max_pending_blocks: 9,
            max_peer_inflight: 9,
            getdata_batch_limit: 9,
            ..super::default_sync_budget(Network::Regtest)
        },
    );
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9_103);
    let mut relaying = synthetic_peer(addr, 100);
    relaying.compact_block_relay = true;
    let rx = connect_peer(&peers, relaying);
    sync.tick();
    assert_flavor(&first_getdata(&rx), false);
    Ok(())
}

#[test]
fn unsolicited_stale_block_retries_from_resolved_header_height()
-> Result<(), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let block1 = mined_block_with_prev_hash(genesis.block_hash(), 1, vec![coinbase_transaction(1)]);
    let block2 = mined_block_with_prev_hash(block1.block_hash(), 2, vec![coinbase_transaction(2)]);
    let block1_hash = block1.block_hash();
    let expected_hash = block2.block_hash();
    let mut tree = BlockTree::new();
    let genesis_id = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
    let block1_id = tree.insert_node(Some(genesis_id), block1.header, NodeStatus::HeaderValid)?;
    tree.insert_node(Some(block1_id), block2.header, NodeStatus::HeaderValid)?;
    let SyncHarness {
        sync,
        peers,
        block_tree,
        applied_tip,
        inbound_blocks_tx,
        inbound_headers_tx: _inbound_headers_tx,
    } = SyncHarness::new(tree);
    install_budget(
        &sync,
        super::SyncBudget {
            getdata_batch_limit: 2,
            received_timeout: Duration::ZERO,
            ..super::default_sync_budget(Network::Regtest)
        },
    );
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let rx = connect_peer(&peers, synthetic_peer(addr, 100));

    sync.tick();

    assert_applied_genesis(&applied_tip, &block_tree)?;
    let Message::GetData(initial) = rx.try_recv()? else {
        return Err(std::io::Error::other("expected initial getdata").into());
    };
    assert_eq!(
        witness_block_inventory(initial)?,
        std::vec![block1_hash, expected_hash]
    );
    let _headers = rx.try_recv()?;
    apply_fixture_block(&sync, block1)?;
    {
        let hash = Hash256::from(expected_hash);
        let height = {
            let tree = sync.chain.block_tree();
            tree.lookup(hash)
                .and_then(|id| tree.node(id).ok())
                .map(|node| node.height)
        };
        sync.scheduler
            .lock()
            .window
            .requeue_for_retry(&hash, height, Instant::now());
    }

    inbound_blocks_tx.send(crate::InboundBlock::from_decoded(block2))?;
    sync.drain_inbound_blocks();

    assert_eq!(sync.scheduler.lock().stager.received_len(), 0);

    sync.tick();

    let Message::GetData(retry) = rx.try_recv()? else {
        return Err(std::io::Error::other("expected height-2 retry getdata").into());
    };
    assert_eq!(witness_block_inventory(retry)?, std::vec![expected_hash]);
    Ok(())
}

/// A block delivered ahead of its header — the `inv`/compact announcement
/// path fetches bodies directly, so no `headers` batch ever travels —
/// carries the only copy of its header. The drain admits it through the
/// headers seam, so the body applies, and the delivery earns the same
/// demonstrated-tip credit a `headers` announcement would.
#[test]
fn inv_delivered_block_admits_carried_header_and_applies() -> Result<(), Box<dyn std::error::Error>>
{
    let genesis = Network::Regtest.genesis_block();
    let block = mined_block_with_prev_hash(genesis.block_hash(), 1, vec![coinbase_transaction(1)]);
    let block_hash = block.block_hash();
    let mut tree = BlockTree::new();
    tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
    let SyncHarness {
        sync,
        peers,
        block_tree,
        applied_tip,
        inbound_blocks_tx,
        inbound_headers_tx: _inbound_headers_tx,
    } = SyncHarness::new(tree);
    install_budget(&sync, super::default_sync_budget(Network::Regtest));
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let rx = connect_peer(&peers, synthetic_peer(addr, 0));

    sync.tick();
    assert_applied_genesis(&applied_tip, &block_tree)?;
    assert!(
        rx.try_recv().is_err(),
        "nothing to send before any announcement"
    );

    let source = current_source(&peers, addr);
    let serialized = bytes::Bytes::from(consensus_bytes(&block));
    inbound_blocks_tx.send(crate::InboundBlock {
        block,
        serialized,
        source: Some(source),
        forward_credit: None,
    })?;
    sync.tick();

    let applied = applied_tip
        .load_full()
        .ok_or_else(|| std::io::Error::other("missing applied tip"))?;
    assert_eq!(applied.hash, Hash256::from(block_hash));
    assert_eq!(applied.height, 1);
    let best_known = peers
        .sessions()
        .iter()
        .find(|session| session.addr == addr)
        .and_then(|session| session.info.as_ref())
        .map(|info| info.best_known_height)
        .ok_or_else(|| std::io::Error::other("missing peer info"))?;
    assert_eq!(best_known, 1);
    assert_no_getdata(&rx)?;
    Ok(())
}

/// Two blocks delivered child-before-parent in one chunk stage their
/// carried headers and both apply. When the admission pass happens to try
/// the child first it may fire a benign gap-recovery `getheaders` — the
/// staged parent admits in the same drain, so no body re-download may
/// follow.
#[test]
fn out_of_order_delivered_blocks_admit_and_apply() -> Result<(), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let block1 = mined_block_with_prev_hash(genesis.block_hash(), 1, vec![coinbase_transaction(1)]);
    let block2 = mined_block_with_prev_hash(block1.block_hash(), 2, vec![coinbase_transaction(2)]);
    let mut tree = BlockTree::new();
    tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
    let SyncHarness {
        sync,
        peers,
        block_tree,
        applied_tip,
        inbound_blocks_tx,
        inbound_headers_tx: _inbound_headers_tx,
    } = SyncHarness::new(tree);
    install_budget(&sync, super::default_sync_budget(Network::Regtest));
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let rx = connect_peer(&peers, eligible_peer(addr, 0));
    let source = current_source(&peers, addr);

    sync.tick();
    assert_applied_genesis(&applied_tip, &block_tree)?;

    for block in [block2, block1] {
        let serialized = bytes::Bytes::from(consensus_bytes(&block));
        inbound_blocks_tx.send(crate::InboundBlock {
            block,
            serialized,
            source: Some(source),
            forward_credit: None,
        })?;
    }
    // Whichever order the pass tries the carried headers, the second drain
    // admits whichever waited on the other's parent.
    sync.tick();
    sync.tick();

    let applied = applied_tip
        .load_full()
        .ok_or_else(|| std::io::Error::other("missing applied tip"))?;
    assert_eq!(applied.height, 2);
    for message in std::iter::from_fn(|| rx.try_recv().ok()) {
        assert!(
            matches!(message, Message::GetHeaders(_)),
            "a same-drain admission may only fire a benign getheaders, never a body retry"
        );
    }
    Ok(())
}

/// A delivered block whose carried header refers to an unlearned parent is
/// not a peer fault — the announced chain extends past a gap the deliverer
/// provably covers — so the sync asks it for the headers spanning the gap.
/// Once the ancestors land, the already-staged body applies in place.
#[test]
fn missing_parent_block_delivery_recovers_with_getheaders() -> Result<(), Box<dyn std::error::Error>>
{
    let genesis = Network::Regtest.genesis_block();
    let block1 = mined_block_with_prev_hash(genesis.block_hash(), 1, vec![coinbase_transaction(1)]);
    let block2 = mined_block_with_prev_hash(block1.block_hash(), 2, vec![coinbase_transaction(2)]);
    let mut tree = BlockTree::new();
    tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
    let SyncHarness {
        sync,
        peers,
        block_tree,
        applied_tip,
        inbound_blocks_tx,
        inbound_headers_tx,
    } = SyncHarness::new(tree);
    install_budget(&sync, super::default_sync_budget(Network::Regtest));
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let rx = connect_peer(&peers, eligible_peer(addr, 0));
    let source = current_source(&peers, addr);

    sync.tick();
    assert_applied_genesis(&applied_tip, &block_tree)?;

    // The height-2 body arrives first; its carried header's parent is the
    // unlearned height-1 header — a chain gap, not a peer fault.
    let serialized = bytes::Bytes::from(consensus_bytes(&block2));
    inbound_blocks_tx.send(crate::InboundBlock {
        block: block2.clone(),
        serialized,
        source: Some(source),
        forward_credit: None,
    })?;
    sync.tick();
    let Message::GetHeaders(_) = rx.try_recv()? else {
        return Err(std::io::Error::other("expected recovery getheaders").into());
    };
    assert!(
        block_tree
            .read()
            .lookup(Hash256::from(block2.block_hash()))
            .is_none(),
        "unattachable header must not be admitted"
    );

    // The reply covers the gap; the still-missing parent body is fetched
    // through the ordinary window path.
    inbound_headers_tx.send(InboundHeaders {
        headers: vec![block1.header, block2.header],
        source: Some(source),
        wire_response: true,
        body_fetch_owned: false,
    })?;
    sync.tick();
    assert_eq!(
        witness_block_inventory(next_getdata(&rx)?)?,
        std::vec![block1.block_hash()]
    );
    assert_eq!(
        {
            let hash = Hash256::from(block2.block_hash());
            let tree = sync.chain.block_tree();
            tree.lookup(hash)
                .and_then(|id| tree.node(id).ok())
                .map(|node| node.height)
        },
        Some(2),
        "header admission must reconcile the staged child's height"
    );

    // Delivering the parent applies both: the staged child body commits
    // right behind it (the second tick drains past the requested-prefix
    // apply window that capped the first).
    let serialized = bytes::Bytes::from(consensus_bytes(&block1));
    inbound_blocks_tx.send(crate::InboundBlock {
        block: block1,
        serialized,
        source: Some(source),
        forward_credit: None,
    })?;
    sync.tick();
    sync.tick();
    let applied = applied_tip
        .load_full()
        .ok_or_else(|| std::io::Error::other("missing applied tip"))?;
    assert_eq!(applied.hash, Hash256::from(block2.block_hash()));
    assert_eq!(applied.height, 2);
    Ok(())
}

/// Cross-tick regression for the bounded prefix-race-before-fanout
/// handoff: a probe created below the threshold must defer fanout when the
/// eligible count reaches the threshold on a following tick while the
/// probe is still fresh, then fanout must engage once the injected time
/// crosses the `stall_timeout_initial` deadline. Exercises the real
/// `tick()` / `configure_request_mode` / `set_fanout_eligible_peers`
/// path for probe creation and the deferral, then injects a future
/// `Instant` (the only available time seam, since `tick()` reads
/// `Instant::now()`) to cross the deadline. This is the exact cross-tick
/// boundary test; the direct window-boundary test lives in
/// `window::tests::fanout_cancels_prefix_probe_without_rearming_it`. No
/// sleeps, no network.
#[test]
fn tick_fanout_deferred_for_fresh_probe_engages_at_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    // A 16-block chain: the deep single-peer window takes all 16 while
    // the one-shot probe sends the first 8 (PREFIX_PROBE_BLOCK_LIMIT), so
    // the probe getdata is distinguishable from the deep getdata.
    let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(16)?;
    install_budget(&sync, super::default_sync_budget(Network::Regtest));

    // Two eligible peers: below the 8-peer fanout threshold. The owner
    // (highest) takes the deep window; the alternate is the probe racer.
    let owner_addr = test_addr(9401, 0)?;
    let alternate_addr = test_addr(9401, 1)?;
    let owner_rx = connect_peer(&peers, eligible_peer(owner_addr, 201));
    let alternate_rx = connect_peer(&peers, eligible_peer(alternate_addr, 200));

    // Tick 1: below the threshold, a prefix probe is created. The owner
    // receives the deep getdata (all 16) and the alternate receives the
    // one-shot probe getdata (the first 8).
    sync.tick();
    assert_applied_genesis(&applied_tip, &block_tree)?;
    assert_eq!(
        witness_block_inventory(next_getdata(&owner_rx)?)?,
        expected,
        "the deep owner must receive the full window"
    );
    assert_eq!(
        witness_block_inventory(next_getdata(&alternate_rx)?)?,
        expected[..8],
        "the alternate must receive the one-shot probe prefix"
    );
    assert!(
        !sync.scheduler.lock().window.fanout_active(),
        "below the threshold fanout must stay off"
    );

    // Reach the fanout threshold on the following tick: add six more
    // eligible peers (eight total) and tick again. The probe is still
    // fresh (age well under stall_timeout_initial = 2s), so the bounded
    // deferral holds fanout off and the probe survives the transition.
    for idx in 2..super::MIN_PEERS_FOR_FANOUT {
        connect_peer(&peers, eligible_peer(test_addr(9401, idx)?, 200));
    }
    sync.tick();
    assert!(
        !sync.scheduler.lock().window.fanout_active(),
        "a fresh prefix probe must defer the threshold-crossing tick"
    );

    // Cross the injected time deadline measured from the active probe's
    // stored `started_at`. The cross-tick path cannot control the
    // `Instant::now()` used when the probe is created, so read it back and
    // add exactly `stall_timeout_initial`. Then assert the planned
    // duration equals the budget before engaging fanout.
    let mut scheduler = sync.scheduler.lock();
    let window = &mut scheduler.window;
    let started_at = window
        .active_prefix_probe_started_at()
        .ok_or_else(|| std::io::Error::other("probe must remain active after deferral"))?;
    let budget = super::default_sync_budget(Network::Regtest);
    let planned_duration = budget.stall_timeout_initial;
    let deadline = started_at + planned_duration;
    assert_eq!(
        deadline - started_at,
        planned_duration,
        "planned deadline must be exactly stall_timeout_initial after probe start"
    );
    window.set_fanout_eligible_peers(super::MIN_PEERS_FOR_FANOUT, deadline);
    assert!(
        window.fanout_active(),
        "fanout must engage at the stall_timeout_initial deadline"
    );
    assert!(
        window.prefix_probe_plan().is_none(),
        "no probe plan may remain once fanout engages"
    );
    Ok(())
}

/// Seven eligible peers plus one ineligible candidate: were the
/// ineligible peer counted, fan-out (many shallow getdatas) would engage;
/// instead the window collapses to one deep single-peer batch. When the
/// ineligible peer is the highest candidate (`serves_fallback`), it also
/// pins that the fallback still uses it — the pre-fan-out shipped
/// behavior (an inbound-only node must still sync).
fn assert_fallback_with_ineligible_candidate(
    ineligible: PeerInfo,
    serves_fallback: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, block_tree, applied_tip, expected) =
        sync_with_header_chain(u32::try_from(super::PENDING_BUDGET)?)?;
    let ineligible_rx = connect_peer(&peers, ineligible);
    let mut rxs = Vec::new();
    for idx in 0..super::MIN_PEERS_FOR_FANOUT - 1 {
        let addr = test_addr(9230, idx)?;
        rxs.push(connect_peer(
            &peers,
            eligible_peer(addr, 300 - i32::try_from(idx)?),
        ));
    }

    sync.tick();

    assert_applied_genesis(&applied_tip, &block_tree)?;
    let deep_rx = if serves_fallback {
        &ineligible_rx
    } else {
        &rxs[0]
    };
    let Message::GetData(inventory) = deep_rx.try_recv()? else {
        return Err(std::io::Error::other("expected one deep fallback getdata").into());
    };
    assert_eq!(witness_block_inventory(inventory)?, expected);
    if !serves_fallback {
        assert!(
            ineligible_rx.try_recv().is_err(),
            "ineligible peer must receive nothing"
        );
    }
    for rx in &rxs[usize::from(!serves_fallback)..] {
        assert_eq!(witness_block_inventory(next_getdata(rx)?)?, expected[..8]);
    }
    Ok(())
}

#[test]
fn stalled_frontier_peer_disconnected_after_adaptive_timeout_and_stripe_requeued()
-> Result<(), Box<dyn std::error::Error>> {
    // R8 core scenario and the terminator for the U6 wedge's bounded
    // cycle (and the first-audit ADV-2 shape: the staller is the
    // highest-advertising peer, holding the front on claimed height it
    // never serves). The 1-minute pending timeout can never fire inside
    // this test, so the staller disconnect is the ONLY recovery path.
    let budget = super::SyncBudget {
        stall_timeout_initial: Duration::from_millis(100),
        ..wedge_budget(Duration::from_mins(1))
    };
    let (sync, peers, expected, rxs, _blocks_tx) = staged_count_wedge(budget)?;
    let staller = test_addr(9320, 0)?;

    // Cold-start disarm: the wedge fixture never advances the window
    // front, so the cadence EWMA would stay unseeded and conviction
    // would defer to the 60s pending-timeout fallback (the cold-start
    // suppression, pinned at the window level). Seed it at 50ms — the
    // decay floor stays max(2x50ms, 100ms) = the injected initial
    // threshold — so this test keeps pinning the adaptive-timeout fire.
    sync.scheduler
        .lock()
        .window
        .seed_front_cadence_for_test(50, Instant::now());

    // Tick 2: the wedge forms (staged 14 + pending 2 at the count
    // budget) and the stall episode starts on the front-stripe owner.
    sync.tick();
    {
        let scheduler = sync.scheduler.lock();
        assert_eq!(scheduler.stager.received_len(), 14);
        assert_eq!(scheduler.window.pending_len(), 2);
        assert_eq!(
            scheduler.window.stalling_peer().map(|(addr, _)| addr),
            Some(staller),
            "the front-stripe owner must be the observed staller"
        );
    }

    // Past the adaptive threshold: the staller is disconnected, its
    // front stripe re-queues, and a healthy peer is asked for it in the
    // same tick — with the staged set intact (no prune involvement).
    std::thread::sleep(Duration::from_millis(150));
    sync.tick();

    assert!(
        !peers.is_connected(staller),
        "staller's outbound lease must be revoked"
    );
    assert!(
        sync.scheduler
            .lock()
            .window
            .peer_in_staller_cooldown(staller, Instant::now()),
        "disconnected staller must enter the cooldown"
    );
    assert_no_getdata(&rxs[0])?;
    let mut rerequested = Vec::new();
    for rx in &rxs[1..] {
        while let Ok(message) = rx.try_recv() {
            if let Message::GetData(inventory) = message {
                rerequested.extend(witness_block_inventory(inventory)?);
            }
        }
    }
    assert_eq!(
        rerequested,
        expected[..2],
        "the stalled front stripe must be re-requested from a healthy peer"
    );
    assert_eq!(
        sync.scheduler.lock().stager.received_len(),
        14,
        "staged progress must survive the staller disconnect"
    );
    {
        let scheduler = sync.scheduler.lock();
        let window = &scheduler.window;
        assert_eq!(window.pending_len(), 2);
        for front in &expected[..2] {
            assert!(window.contains_pending(&Hash256::from_le_bytes(front.as_bytes())));
        }
    }
    Ok(())
}

#[test]
fn clean_fast_path_caps_request_at_peer_height() -> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(8)?;
    install_budget(
        &sync,
        super::SyncBudget {
            max_pending_blocks: 4,
            max_peer_inflight: 4,
            getdata_batch_limit: 4,
            ..super::default_sync_budget(Network::Regtest)
        },
    );
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let rx = connect_peer(&peers, synthetic_peer(addr, 2));

    sync.tick();

    assert_applied_genesis(&applied_tip, &block_tree)?;
    let Message::GetData(inventory) = rx.try_recv()? else {
        return Err(std::io::Error::other("expected getdata").into());
    };
    assert_eq!(witness_block_inventory(inventory)?, expected[..2]);
    assert!(rx.try_recv().is_err());

    sync.tick();

    assert!(rx.try_recv().is_err());
    Ok(())
}

struct ExhaustionFixture {
    sync: BlockSync,
    stalled_rx: crossbeam_channel::Receiver<Message>,
    healthy_rx: crossbeam_channel::Receiver<Message>,
    block1_hash: BlockHash,
    block2_hash: BlockHash,
}

fn staging_exhaustion_fixture() -> Result<ExhaustionFixture, Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let block1 = mined_block_with_prev_hash(genesis.block_hash(), 1, vec![coinbase_transaction(1)]);
    let block2 = mined_block_with_prev_hash(block1.block_hash(), 2, vec![coinbase_transaction(2)]);
    let block3 = mined_block_with_prev_hash(block2.block_hash(), 3, vec![coinbase_transaction(3)]);
    let block1_hash = block1.block_hash();
    let block2_hash = block2.block_hash();
    let mut tree = BlockTree::new();
    let genesis_id = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
    let block1_id = tree.insert_node(Some(genesis_id), block1.header, NodeStatus::HeaderValid)?;
    let block2_id = tree.insert_node(Some(block1_id), block2.header, NodeStatus::HeaderValid)?;
    tree.insert_node(Some(block2_id), block3.header, NodeStatus::HeaderValid)?;

    let SyncHarness {
        sync,
        peers,
        block_tree,
        applied_tip,
        inbound_blocks_tx,
        inbound_headers_tx: _inbound_headers_tx,
    } = SyncHarness::new(tree);
    // Staging byte budget that exactly one staged block exhausts.
    install_budget(
        &sync,
        super::SyncBudget {
            max_received_bytes: consensus_bytes(&block2).len(),
            getdata_batch_limit: 2,
            received_timeout: Duration::from_millis(100),
            ..super::default_sync_budget(Network::Regtest)
        }
        .with_pending_timeout_override(Duration::ZERO),
    );
    let stalled_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let healthy_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8334);
    let stalled_rx = connect_peer(&peers, synthetic_peer(stalled_addr, 100));

    sync.tick();

    assert_applied_genesis(&applied_tip, &block_tree)?;
    let Message::GetData(inventory) = stalled_rx.try_recv()? else {
        return Err(std::io::Error::other("expected getdata").into());
    };
    assert_eq!(
        witness_block_inventory(inventory)?,
        std::vec![block1_hash, block2_hash]
    );
    let _headers = stalled_rx.try_recv()?;

    // Deliver only the successor: it stages (waiting on block1, which the
    // stalled peer will never send) and exactly exhausts the staging byte
    // budget, closing the request gate.
    inbound_blocks_tx.send(crate::InboundBlock::from_decoded(block2))?;
    sync.drain_inbound_blocks();
    assert!(!{
        let scheduler = sync.scheduler.lock();
        scheduler.window.has_request_capacity(&scheduler.stager)
    });

    let healthy_rx = connect_peer(&peers, synthetic_peer(healthy_addr, 100));

    Ok(ExhaustionFixture {
        sync,
        stalled_rx,
        healthy_rx,
        block1_hash,
        block2_hash,
    })
}

const DETERMINISTIC_PROXY_BLOCKS: usize = 24;
const DETERMINISTIC_PROXY_TIP_HEIGHT: u32 = 24;
const DETERMINISTIC_PROXY_HEADER_HEIGHT: u32 = 96;

struct DeterministicProxyFixture {
    sync: BlockSync,
    applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    block_tree: Arc<RwLock<BlockTree>>,
    inbound_blocks_tx: crossbeam_channel::Sender<crate::InboundBlock>,
    outbound_rx: crossbeam_channel::Receiver<Message>,
    blocks: Vec<Block>,
}

fn deterministic_proxy_fixture() -> Result<DeterministicProxyFixture, Box<dyn std::error::Error>> {
    let (tree, blocks) = mined_chain(
        DETERMINISTIC_PROXY_TIP_HEIGHT,
        DETERMINISTIC_PROXY_HEADER_HEIGHT - DETERMINISTIC_PROXY_TIP_HEIGHT,
    )?;
    let SyncHarness {
        sync,
        peers,
        block_tree,
        applied_tip,
        inbound_blocks_tx,
        inbound_headers_tx: _inbound_headers_tx,
    } = SyncHarness::new(tree);
    install_budget(
        &sync,
        super::SyncBudget {
            max_pending_blocks: DETERMINISTIC_PROXY_BLOCKS,
            max_pending_bytes: usize::MAX,
            max_received_blocks: DETERMINISTIC_PROXY_BLOCKS,
            max_received_bytes: usize::MAX,
            max_peer_inflight: DETERMINISTIC_PROXY_BLOCKS,
            getdata_batch_limit: DETERMINISTIC_PROXY_BLOCKS,
            ..super::default_sync_budget(Network::Regtest)
        },
    );

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let outbound_rx = connect_peer(&peers, synthetic_peer(addr, 100));

    Ok(DeterministicProxyFixture {
        sync,
        applied_tip,
        block_tree,
        inbound_blocks_tx,
        outbound_rx,
        blocks,
    })
}

struct ApplyCacheFixture {
    sync: BlockSync,
    blocks: Vec<Block>,
    applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
}

/// Builds a regtest chain with `body_height` mined block bodies followed by
/// `header_only` header-only blocks, applies genesis, and returns a fixture
/// whose stager is empty so individual rounds can stage bodies directly and
/// exercise the apply-side cache miss/hit transitions.
fn apply_cache_fixture(
    body_height: u32,
    header_only: u32,
) -> Result<ApplyCacheFixture, Box<dyn std::error::Error>> {
    let (tree, blocks) = mined_chain(body_height, header_only)?;
    let SyncHarness {
        sync,
        block_tree,
        applied_tip,
        inbound_headers_tx: _inbound_headers_tx,
        inbound_blocks_tx: _inbound_blocks_tx,
        ..
    } = SyncHarness::new(tree);
    let chain_tip = block_tree.write().tip_handle();
    // Apply genesis so the applied tip starts at height 0; no block bodies
    // are staged yet, leaving every round below to drive cache state.
    sync.chain.bootstrap_genesis();
    assert_eq!(
        applied_tip.load_full().map(|tip| tip.height),
        Some(0),
        "fixture must apply genesis before staging bodies"
    );

    Ok(ApplyCacheFixture {
        sync,
        blocks,
        applied_tip,
        chain_tip,
    })
}

fn stage_body(sync: &BlockSync, block: &Block) {
    let hash = Hash256::from_le_bytes(block.block_hash().as_bytes());
    let serialized = bytes::Bytes::from(consensus_bytes(block));
    sync.scheduler.lock().stager.insert(
        hash,
        None,
        block.clone(),
        serialized,
        None,
        Instant::now(),
    );
}

fn cache_snapshot(sync: &BlockSync) -> Option<super::ExpectedApplyCache> {
    sync.expected_apply_cache.lock().clone()
}

/// Commit a delivered fixture through the ordinary binding and apply path.
/// Scheduler tests must not fake application by only erasing a window slot.
fn apply_fixture_block(sync: &BlockSync, block: Block) -> Result<(), Box<dyn std::error::Error>> {
    let hash = Hash256::from(block.block_hash());
    sync.buffer_received_block_chunk(
        &mut vec![crate::InboundBlock::from_decoded(block)],
        Some(hash),
    );
    assert_eq!(sync.apply_buffered_blocks(Some(hash)), (1, 0));
    assert_eq!(
        sync.chain.applied_tip().ok_or("missing applied tip")?.hash,
        hash
    );
    Ok(())
}

/// BLK-06/07 follow-up: a Permanent commit failure purges the failed
/// subtree instead of re-queueing it. The failed block heads its own
/// invalidated subtree, so the purge releases it; the unconditional
/// tree-height retry requeue must not run for that disposition, or it
/// rewinds the request cursor onto the invalidated block and the frontier
/// cycles on a block the tree has marked Invalid.
#[test]
fn permanent_rejection_keeps_the_request_cursor_off_the_invalidated_block()
-> Result<(), Box<dyn std::error::Error>> {
    // One valid block, then a two-coinbase body whose header the tree
    // knows: the commit classifier treats the body as a permanent
    // ExtraCoinbase invalidity and invalidates its subtree while the
    // transition is held.
    let (mut tree, mut blocks) = mined_chain(1, 0)?;
    let tip_id = tree.tip_id().ok_or("missing mined tip")?;
    let extra_coinbase = mined_block_with_prev_hash(
        blocks[0].block_hash(),
        2,
        vec![coinbase_transaction(90), coinbase_transaction(91)],
    );
    let extra_id =
        tree.insert_node(Some(tip_id), extra_coinbase.header, NodeStatus::HeaderValid)?;
    let follower = mined_block_with_prev_hash(
        extra_coinbase.block_hash(),
        3,
        vec![coinbase_transaction(92)],
    );
    tree.insert_node(Some(extra_id), follower.header, NodeStatus::HeaderValid)?;
    let SyncHarness {
        sync,
        peers,
        inbound_blocks_tx: _inbound_blocks_tx,
        ..
    } = SyncHarness::new(tree);
    sync.chain.bootstrap_genesis();
    let peer = test_addr(9789, 0)?;
    let _rx = connect_peer(&peers, eligible_peer(peer, 3));
    sync.tick();
    let failing_hash = Hash256::from(extra_coinbase.block_hash());

    // Deliver all three bodies: staging releases each one's pending, so
    // the request cursor sits strictly above the failing height and a
    // rewind onto it would be observable.
    let staged = sync.buffer_received_block_chunk(
        &mut vec![
            crate::InboundBlock::from_decoded(blocks.remove(0)),
            crate::InboundBlock::from_decoded(extra_coinbase),
            crate::InboundBlock::from_decoded(follower),
        ],
        None,
    );
    assert_eq!(staged, 3, "all three delivered bodies must stage");
    let cursor_before = sync.scheduler.lock().window.request_cursor();
    assert!(
        cursor_before > 2,
        "the request frontier must sit above the failing height for the rewind to be observable"
    );

    assert_eq!(sync.apply_buffered_blocks(None), (1, 1));
    assert_eq!(
        sync.scheduler.lock().window.request_cursor(),
        cursor_before,
        "a Permanent rejection must not rewind the request cursor onto the invalidated block"
    );
    assert!(
        !sync.scheduler.lock().stager.contains(&failing_hash),
        "the invalidated block and its descendants must leave the stager"
    );
    Ok(())
}

/// BLK-06/07: an unrequested body stages only when Core's `AcceptBlock`
/// would process it with `fRequested == false` (validation.cpp:4327-4353):
/// on the active branch, with at least the applied tip's work, and at most
/// 288 blocks above the applied tip. Requested bodies are not gated.
#[test]
fn unrequested_body_admission_matches_core_acceptance() -> Result<(), Box<dyn std::error::Error>> {
    let (mut tree, blocks) = mined_chain(300, 0)?;
    let fork_parent = tree
        .lookup(Hash256::from(blocks[4].block_hash()))
        .ok_or("missing height 5")?;
    let fork_body =
        mined_block_with_prev_hash(blocks[4].block_hash(), 606, vec![coinbase_transaction(606)]);
    tree.insert_node(Some(fork_parent), fork_body.header, NodeStatus::HeaderValid)?;
    let applied = {
        let node = tree.node(fork_parent)?;
        TipSnapshot {
            tip_id: fork_parent,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
        }
    };
    let SyncHarness {
        sync,
        applied_tip,
        inbound_headers_tx: _inbound_headers_tx,
        inbound_blocks_tx: _inbound_blocks_tx,
        ..
    } = SyncHarness::new(tree);
    applied_tip.store(Some(Arc::new(applied)));
    let mut blocks = blocks.into_iter();
    let successor = blocks.nth(5).ok_or("missing height 6")?;
    let far_body = blocks.nth(288).ok_or("missing height 295")?;
    let successor_hash = Hash256::from(successor.block_hash());
    let far_hash = Hash256::from(far_body.block_hash());
    let fork_hash = Hash256::from(fork_body.block_hash());
    let mut delivery = vec![
        crate::InboundBlock::from_decoded(successor),
        crate::InboundBlock::from_decoded(far_body),
        crate::InboundBlock::from_decoded(fork_body),
    ];
    sync.buffer_received_block_chunk(&mut delivery, None);

    let scheduler = sync.scheduler.lock();
    assert!(
        scheduler.stager.contains(&successor_hash),
        "an active-branch successor passes every clause"
    );
    assert!(
        !scheduler.stager.contains(&far_hash),
        "a body more than 288 blocks above the applied tip is too far ahead"
    );
    assert!(
        !scheduler.stager.contains(&fork_hash),
        "a body off the active branch is discarded"
    );
    assert_eq!(scheduler.stager.received_len(), 1);
    Ok(())
}

/// Clause coverage the regtest fixture cannot reach: its floor is zero and
/// its candidates all sit above the applied tip, so clauses 2 and 3 never
/// fire. The floor is injected through the gate's parameter — no network
/// identity is faked — and the below-applied candidate isolates clause 2.
#[test]
fn unrequested_body_gate_rejects_below_floor_and_below_applied_work()
-> Result<(), Box<dyn std::error::Error>> {
    fn snapshot(
        tree: &BlockTree,
        hash: Hash256,
    ) -> Result<TipSnapshot, Box<dyn std::error::Error>> {
        let node_id = tree.lookup(hash).ok_or("missing fixture block")?;
        let node = tree.node(node_id)?;
        Ok(TipSnapshot {
            tip_id: node_id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
        })
    }
    let (tree, blocks) = mined_chain(8, 0)?;
    let chain_tip = snapshot(&tree, Hash256::from(blocks[7].block_hash()))?;
    let applied_tip = snapshot(&tree, Hash256::from(blocks[3].block_hash()))?;
    let floor = {
        let node_id = tree
            .lookup(Hash256::from(blocks[7].block_hash()))
            .ok_or("missing tip fixture block")?;
        tree.node(node_id)?.chainwork.to_be_bytes()
    };

    // Clause 3: on the active branch and above the applied tip, but with
    // less work than the injected floor.
    let above_applied = Hash256::from(blocks[5].block_hash());
    assert!(
        !unrequested_body_admissible(
            &tree,
            above_applied,
            Some(&chain_tip),
            Some(&applied_tip),
            floor,
        ),
        "a candidate below the work floor must be rejected even on-branch above the applied tip"
    );
    assert!(
        unrequested_body_admissible(
            &tree,
            above_applied,
            Some(&chain_tip),
            Some(&applied_tip),
            [0; 32],
        ),
        "the same candidate passes with the regtest zero floor, isolating the floor clause"
    );

    // Clause 2: on the active branch with less work than the applied tip.
    let below_applied = Hash256::from(blocks[1].block_hash());
    assert!(
        !unrequested_body_admissible(
            &tree,
            below_applied,
            Some(&chain_tip),
            Some(&applied_tip),
            [0; 32],
        ),
        "a candidate with less work than the applied tip must be rejected"
    );
    Ok(())
}

/// Shared executor wiring; callers keep or drop each sender explicitly.
struct SyncHarness {
    sync: BlockSync,
    peers: Arc<PeerTable>,
    block_tree: Arc<RwLock<BlockTree>>,
    applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    inbound_headers_tx: crossbeam_channel::Sender<InboundHeaders>,
    inbound_blocks_tx: InboundBlockSender,
}

impl SyncHarness {
    fn new(mut tree: BlockTree) -> Self {
        let chain_tip = tree.tip_handle();
        let block_tree = Arc::new(RwLock::new(tree));
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let peers = Arc::new(PeerTable::new());
        let (inbound_headers_tx, inbound_headers_rx) = unbounded();
        let (inbound_blocks_tx, inbound_blocks_rx) = unbounded();
        let chain = Arc::new(TestChain::new(
            chain_tip,
            Arc::clone(&applied_tip),
            Arc::clone(&block_tree),
        ));
        let sync = BlockSync::new(
            chain,
            Arc::clone(&peers),
            Arc::new(Mutex::new(inbound_headers_rx)),
            Arc::new(Mutex::new(inbound_blocks_rx)),
        );
        Self {
            sync,
            peers,
            block_tree,
            applied_tip,
            inbound_headers_tx,
            inbound_blocks_tx,
        }
    }
}

/// Mine real bodies, then extend their header chain without applying anything.
pub(crate) fn mined_chain(
    body_height: u32,
    header_only: u32,
) -> Result<(BlockTree, Vec<Block>), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let mut tree = BlockTree::new();
    let mut tip_id = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
    let mut prev_hash = genesis.block_hash();
    let mut blocks = Vec::with_capacity(usize::try_from(body_height)?);
    for height in 1..=body_height {
        let block =
            mined_block_with_prev_hash(prev_hash, height, vec![coinbase_transaction(height)]);
        tip_id = tree.insert_node(Some(tip_id), block.header, NodeStatus::HeaderValid)?;
        prev_hash = block.block_hash();
        blocks.push(block);
    }
    for height in body_height.saturating_add(1)..=body_height.saturating_add(header_only) {
        let header = test_header(prev_hash, height);
        tip_id = tree.insert_node(Some(tip_id), header, NodeStatus::HeaderValid)?;
        prev_hash = header.compute_hash();
    }
    Ok((tree, blocks))
}

type SyncFixture = (
    BlockSync,
    Arc<PeerTable>,
    Arc<RwLock<BlockTree>>,
    Arc<ArcSwapOption<TipSnapshot>>,
    Vec<BlockHash>,
);

type InboundBlockSender = crossbeam_channel::Sender<crate::InboundBlock>;

fn sync_with_header_chain(height: u32) -> Result<SyncFixture, Box<dyn std::error::Error>> {
    // Dropping the sender mirrors the original fixture: a disconnected
    // inbound-blocks channel that never yields a block.
    let (fixture, _inbound_blocks_tx) = sync_with_header_chain_and_blocks(height)?;
    Ok(fixture)
}

fn sync_with_header_chain_and_blocks(
    height: u32,
) -> Result<(SyncFixture, InboundBlockSender), Box<dyn std::error::Error>> {
    let (tree, blocks) = mined_chain(height, 0)?;
    let expected = blocks.iter().map(Block::block_hash).collect();
    let SyncHarness {
        sync,
        peers,
        block_tree,
        applied_tip,
        inbound_blocks_tx,
        inbound_headers_tx: _inbound_headers_tx,
    } = SyncHarness::new(tree);

    Ok((
        (sync, peers, block_tree, applied_tip, expected),
        inbound_blocks_tx,
    ))
}

type MinedChainFixture = (
    BlockSync,
    Arc<PeerTable>,
    Arc<ArcSwapOption<TipSnapshot>>,
    Vec<Block>,
    InboundBlockSender,
);

/// Like [`sync_with_header_chain_and_blocks`] but with fully applicable
/// mined regtest blocks (coinbase-bearing, PoW-valid), so tests can drive
/// real apply progress through the inbound channel.
fn sync_with_mined_chain(count: u32) -> Result<MinedChainFixture, Box<dyn std::error::Error>> {
    let (tree, blocks) = mined_chain(count, 0)?;
    let SyncHarness {
        sync,
        peers,
        block_tree: _,
        applied_tip,
        inbound_blocks_tx,
        inbound_headers_tx: _inbound_headers_tx,
    } = SyncHarness::new(tree);

    Ok((sync, peers, applied_tip, blocks, inbound_blocks_tx))
}

type WedgeFixture = (
    BlockSync,
    Arc<PeerTable>,
    Vec<BlockHash>,
    Vec<crossbeam_channel::Receiver<Message>>,
    InboundBlockSender,
);

/// The recorded-collapse construction at `install_budget` scale: eight
/// eligible peers stripe a 16-block window at per-peer fan-out cap 2
/// against a 64-block header chain; the front-stripe owner (the highest
/// peer, heights 1-2) stalls while the seven healthy peers deliver
/// heights 3..=16 into the inbound channel. After the caller's next tick
/// drains them, staged (14) + pending (2) sit exactly at the count
/// budget (16) with the apply frontier frozen behind the stall. Byte
/// budgets are unbounded so only count-denominated behavior is exercised.
fn wedge_budget(pending_timeout: Duration) -> super::SyncBudget {
    super::SyncBudget {
        max_pending_blocks: 16,
        max_pending_bytes: usize::MAX,
        max_received_blocks: 16,
        max_received_bytes: usize::MAX,
        max_peer_inflight: 16,
        fanout_peer_inflight: 2,
        min_peers_for_fanout: 8,
        getdata_batch_limit: 16,
        ..super::default_sync_budget(Network::Regtest)
    }
    .with_pending_timeout_override(pending_timeout)
}

fn staged_count_wedge(
    budget: super::SyncBudget,
) -> Result<WedgeFixture, Box<dyn std::error::Error>> {
    let ((sync, peers, block_tree, applied_tip, expected), blocks_tx) =
        sync_with_header_chain_and_blocks(64)?;
    let peer_count = budget.min_peers_for_fanout;
    install_budget(&sync, budget);
    let mut rxs = Vec::new();
    for idx in 0..peer_count {
        let addr = test_addr(9320, idx)?;
        rxs.push(connect_peer(
            &peers,
            eligible_peer(addr, 200 - i32::try_from(idx)?),
        ));
    }

    sync.tick();

    assert_applied_genesis(&applied_tip, &block_tree)?;
    for (idx, rx) in rxs.iter().enumerate() {
        let Message::GetData(inventory) = rx.try_recv()? else {
            return Err(std::io::Error::other("expected a striped getdata per peer").into());
        };
        assert_eq!(
            witness_block_inventory(inventory)?,
            expected[idx * 2..(idx + 1) * 2]
        );
    }
    for height in 3..=16_u32 {
        blocks_tx.send(crate::InboundBlock::from_decoded(header_chain_block(
            &expected, height,
        )?))?;
    }
    Ok((sync, peers, expected, rxs, blocks_tx))
}

/// Returns the next `getdata` inventory from `rx`, skipping header
/// traffic; fails when none is queued.
fn next_getdata(
    rx: &crossbeam_channel::Receiver<Message>,
) -> Result<Vec<Inventory>, Box<dyn std::error::Error>> {
    while let Ok(message) = rx.try_recv() {
        if let Message::GetData(inventory) = message {
            return Ok(inventory);
        }
    }
    Err(std::io::Error::other("expected a queued getdata").into())
}

/// Drains `rx`, failing on any `getdata` while ignoring header traffic.
fn assert_no_getdata(
    rx: &crossbeam_channel::Receiver<Message>,
) -> Result<(), Box<dyn std::error::Error>> {
    while let Ok(message) = rx.try_recv() {
        if matches!(message, Message::GetData(_)) {
            return Err(std::io::Error::other("unexpected getdata").into());
        }
    }
    Ok(())
}

/// Reconstructs the deliverable block body (header-only, empty `txs`)
/// for `height` of a [`sync_with_header_chain`] fixture: the block hash
/// is the header hash, so the delivery matches the fixture's tree node.
fn header_chain_block(
    expected: &[BlockHash],
    height: u32,
) -> Result<Block, Box<dyn std::error::Error>> {
    let index = usize::try_from(height.checked_sub(1).ok_or("height must be >= 1")?)?;
    let prev_blockhash = if index == 0 {
        genesis_header().compute_hash()
    } else {
        expected[index - 1]
    };
    let block =
        mined_block_with_prev_hash(prev_blockhash, height, vec![coinbase_transaction(height)]);
    assert_eq!(
        block.block_hash(),
        expected[index],
        "reconstructed block must hash to the fixture's header-chain node"
    );
    Ok(block)
}

fn install_budget(sync: &BlockSync, budget: super::SyncBudget) {
    sync.install_budget(budget);
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum TestMetric {
    Counter(u64),
    Gauge(f64),
    Histogram { count: u64, sum: f64 },
}

#[derive(Clone, Debug, Default)]
struct TestRecorder {
    values: Arc<Mutex<HashMap<String, TestMetric>>>,
}

impl TestRecorder {
    fn metric_key(key: &Key) -> String {
        key.name().to_owned()
    }

    fn snapshot(&self) -> HashMap<String, TestMetric> {
        self.values.lock().clone()
    }
}

impl Recorder for TestRecorder {
    fn describe_counter(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}

    fn describe_gauge(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}

    fn describe_histogram(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}

    fn register_counter(&self, key: &Key, _metadata: &Metadata<'_>) -> Counter {
        Counter::from_arc(Arc::new(TestCounter {
            key: Self::metric_key(key),
            recorder: self.clone(),
        }))
    }

    fn register_gauge(&self, key: &Key, _metadata: &Metadata<'_>) -> Gauge {
        Gauge::from_arc(Arc::new(TestGauge {
            key: Self::metric_key(key),
            recorder: self.clone(),
        }))
    }

    fn register_histogram(&self, key: &Key, _metadata: &Metadata<'_>) -> Histogram {
        Histogram::from_arc(Arc::new(TestHistogram {
            key: Self::metric_key(key),
            recorder: self.clone(),
        }))
    }
}

struct TestCounter {
    key: String,
    recorder: TestRecorder,
}

impl CounterFn for TestCounter {
    fn increment(&self, value: u64) {
        let mut values = self.recorder.values.lock();
        let entry = values
            .entry(self.key.clone())
            .or_insert(TestMetric::Counter(0));
        if let TestMetric::Counter(current) = entry {
            *current = current.saturating_add(value);
        }
    }

    fn absolute(&self, value: u64) {
        self.recorder
            .values
            .lock()
            .insert(self.key.clone(), TestMetric::Counter(value));
    }
}

struct TestGauge {
    key: String,
    recorder: TestRecorder,
}

impl GaugeFn for TestGauge {
    fn increment(&self, value: f64) {
        let mut values = self.recorder.values.lock();
        let entry = values
            .entry(self.key.clone())
            .or_insert(TestMetric::Gauge(0.0));
        if let TestMetric::Gauge(current) = entry {
            *current += value;
        }
    }

    fn decrement(&self, value: f64) {
        let mut values = self.recorder.values.lock();
        let entry = values
            .entry(self.key.clone())
            .or_insert(TestMetric::Gauge(0.0));
        if let TestMetric::Gauge(current) = entry {
            *current -= value;
        }
    }

    fn set(&self, value: f64) {
        self.recorder
            .values
            .lock()
            .insert(self.key.clone(), TestMetric::Gauge(value));
    }
}

struct TestHistogram {
    key: String,
    recorder: TestRecorder,
}

impl HistogramFn for TestHistogram {
    fn record(&self, value: f64) {
        let mut values = self.recorder.values.lock();
        let entry = values
            .entry(self.key.clone())
            .or_insert(TestMetric::Histogram { count: 0, sum: 0.0 });
        if let TestMetric::Histogram { count, sum } = entry {
            *count = count.saturating_add(1);
            *sum += value;
        }
    }
}

fn assert_gauge(recorder: &TestRecorder, name: &str, expected: usize) {
    let expected = super::metric_count(expected);
    assert_eq!(
        recorder.snapshot().get(name),
        Some(&TestMetric::Gauge(expected)),
        "{name} gauge must match deterministic sync pipeline state",
    );
}

fn assert_metric_absent(recorder: &TestRecorder, name: &str) {
    assert!(
        !recorder.snapshot().contains_key(name),
        "{name} metric should not be recorded"
    );
}

fn assert_histogram(recorder: &TestRecorder, name: &str) {
    match recorder.snapshot().get(name) {
        Some(TestMetric::Histogram { count, sum }) => {
            assert_ne!(
                *count, 0,
                "{name} histogram must record at least one sample"
            );
            assert!(sum.is_finite(), "{name} histogram sum must be finite");
        }
        value => panic!("{name} histogram missing or wrong type: {value:?}"),
    }
}

fn witness_block_inventory(
    inventory: Vec<Inventory>,
) -> Result<Vec<BlockHash>, Box<dyn std::error::Error>> {
    inventory
        .into_iter()
        .map(|item| match item {
            // Wire seam: Inventory payloads stay bitcoin::; convert to native.
            Inventory::WitnessBlock(hash) => {
                Ok(BlockHash(Hash256::from_le_bytes(hash.as_byte_array())))
            }
            _ => Err(std::io::Error::other("expected witness block inventory").into()),
        })
        .collect()
}

/// Regtest genesis timestamp. Fixture headers must advance past it or the
/// median-time-past rule rejects them, since the median is taken over the
/// ancestors actually present in the tree.
const GENESIS_TIME: u32 = 1_296_688_602;

fn test_header(prev_blockhash: BlockHash, height: u32) -> Header {
    use bitcoin_rs_primitives::CompactTarget;
    let mut merkle = [0_u8; 32];
    merkle[..4].copy_from_slice(&height.to_le_bytes());
    let mut header = Header {
        version: 1,
        prev_blockhash,
        merkle_root: Hash256::from_le_bytes(&merkle),
        time: GENESIS_TIME.saturating_add(height),
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce: height,
    };
    // Mine rather than hope: the fixture previously relied on nonce=height
    // happening to satisfy regtest's easy target, so any change to another
    // header field silently broke proof-of-work validation.
    while !pow_met(
        header.bits.to_consensus(),
        Hash256::from(header.compute_hash()),
    ) {
        header.nonce = header.nonce.wrapping_add(1);
    }
    header
}

fn nbits_mismatch_header(prev_blockhash: BlockHash, height: u32) -> Header {
    use bitcoin_rs_primitives::CompactTarget;
    let mut header = test_header(prev_blockhash, height);
    header.bits = CompactTarget::from_consensus(0x207f_fffe);
    for nonce in 0..=u32::MAX {
        header.nonce = nonce;
        if pow_met(
            header.bits.to_consensus(),
            Hash256::from(header.compute_hash()),
        ) {
            return header;
        }
    }
    panic!("exhausted the header nonce space while mining a regtest fixture");
}

fn far_future_header(
    prev_blockhash: BlockHash,
    height: u32,
) -> Result<Header, Box<dyn std::error::Error>> {
    let mut header = test_header(prev_blockhash, height);
    header.time = bitcoin_rs_chain::current_unix_seconds().saturating_add(3 * 60 * 60);
    for nonce in 0..=u32::MAX {
        header.nonce = nonce;
        if pow_met(
            header.bits.to_consensus(),
            Hash256::from(header.compute_hash()),
        ) {
            return Ok(header);
        }
    }
    Err(std::io::Error::other("exhausted future-header nonce space").into())
}

/// Regtest-easy compact-target `PoW` check over the hash as a 256-bit
/// little-endian integer (mirrors `chain::pow::compact_is_met_by` for the
/// >3-exponent, 3-byte-mantissa forms these fixtures mine).
fn pow_met(bits: u32, hash: Hash256) -> bool {
    let exponent = bits >> 24;
    let mantissa = bits & 0x007f_ffff;
    if exponent <= 3 || exponent > 32 || mantissa > 0x00ff_ffff {
        return false;
    }
    let bytes = hash.as_byte_array();
    let lo = usize::try_from(exponent).unwrap_or(32) - 3;
    let window =
        u32::from(bytes[lo]) | u32::from(bytes[lo + 1]) << 8 | u32::from(bytes[lo + 2]) << 16;
    window <= mantissa
        && bytes[usize::try_from(exponent).unwrap_or(32)..]
            .iter()
            .all(|&byte| byte == 0)
}

struct HeaderSyncFixture {
    genesis: Header,
    sync: BlockSync,
    inbound_headers_tx: crossbeam_channel::Sender<InboundHeaders>,
    peers: Arc<PeerTable>,
}

fn header_sync_with_genesis() -> Result<HeaderSyncFixture, Box<dyn std::error::Error>> {
    let mut tree = BlockTree::new();
    let genesis = genesis_header();
    tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
    let SyncHarness {
        sync,
        peers,
        inbound_headers_tx,
        inbound_blocks_tx: _inbound_blocks_tx,
        ..
    } = SyncHarness::new(tree);
    install_budget(
        &sync,
        super::SyncBudget {
            max_pending_blocks: 0,
            ..super::default_sync_budget(Network::Regtest)
        },
    );
    Ok(HeaderSyncFixture {
        genesis,
        sync,
        inbound_headers_tx,
        peers,
    })
}

fn genesis_header() -> Header {
    Network::Regtest.genesis_block().header
}

pub(crate) fn coinbase_transaction(height: u32) -> Tx {
    use bitcoin_rs_primitives::{Amount, LockTime, Script, Sequence, Witness};
    let mut script_sig = push_int(i64::from(height));
    script_sig.extend_from_slice(&push_int(1));
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid::default(), u32::MAX),
            script_sig: Script::from_bytes(script_sig),
            sequence: Sequence::from_consensus(0xffff_ffff),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: Script::new(),
        }],
        lock_time: LockTime::from_consensus(0),
    }
}

fn transaction(seed: u8) -> Tx {
    use bitcoin_rs_primitives::{Amount, LockTime, Script, Sequence, Witness};
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(
                Txid(Hash256::from_le_bytes(&[seed; 32])),
                u32::from(seed),
            ),
            script_sig: Script::new(),
            sequence: Sequence::from_consensus(0xffff_ffff),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: Script::new(),
        }],
        lock_time: LockTime::from_consensus(0),
    }
}

pub(crate) fn mined_block_with_prev_hash(
    prev_blockhash: BlockHash,
    height: u32,
    txdata: Vec<Tx>,
) -> Block {
    use bitcoin_rs_primitives::CompactTarget;
    let mut block = Block {
        header: Header {
            version: 1,
            prev_blockhash,
            merkle_root: Hash256::default(),
            time: GENESIS_TIME.saturating_add(height),
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txs: txdata,
    };
    block.header.merkle_root = merkle_root(&block.txs);
    while !pow_met(
        block.header.bits.to_consensus(),
        Hash256::from(block.block_hash()),
    ) {
        block.header.nonce = block.header.nonce.saturating_add(1);
    }
    block
}

/// Consensus merkle fold: pairwise double-SHA256 over little-endian txid
/// bytes, duplicating the last leaf on odd levels.
#[allow(clippy::expect_used)]
fn merkle_root(txs: &[Tx]) -> Hash256 {
    let mut hashes: Vec<[u8; 32]> = txs.iter().map(|tx| *tx.txid().as_bytes()).collect();
    if hashes.is_empty() {
        return Hash256::default();
    }
    while hashes.len() > 1 {
        if hashes.len() % 2 == 1 {
            let last = hashes.last().expect("odd merkle level has a last leaf");
            hashes.push(*last);
        }
        hashes = hashes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let mut buffer = [0_u8; 64];
                buffer[..32].copy_from_slice(&pair[0]);
                buffer[32..].copy_from_slice(&pair[1]);
                double_sha256(&buffer).to_le_bytes()
            })
            .collect();
    }
    let root = hashes.first().expect("merkle fold reduces to one root");
    Hash256::from_le_bytes(root)
}

fn assert_applied_genesis(
    applied_tip: &Arc<ArcSwapOption<TipSnapshot>>,
    block_tree: &Arc<RwLock<BlockTree>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let genesis_hash = Network::Regtest.genesis_block_hash();
    let tip = applied_tip
        .load_full()
        .ok_or_else(|| std::io::Error::other("missing applied genesis tip"))?;
    assert_eq!(tip.height, 0);
    assert_eq!(tip.hash, genesis_hash);
    assert_eq!(block_tree.read().height_of_hash(genesis_hash), Some(0));
    Ok(())
}

pub(crate) fn current_source(peer_table: &Arc<PeerTable>, addr: SocketAddr) -> PeerSource {
    peer_table.lease(addr).map_or_else(
        || panic!("test peer {addr} must be connected"),
        |lease| lease.source(addr),
    )
}

/// The canonical frontier `tick()` would observe right now.
fn test_frontier(sync: &BlockSync) -> super::ChainFrontier {
    sync.observe_chain_frontier()
}

fn register_info(peer_table: &Arc<PeerTable>, info: PeerInfo) {
    let (tx, _rx) = unbounded::<Message>();
    let lease = PeerLease::new(tx);
    peer_table.register(info.addr, lease.clone());
    peer_table.publish_info(info.addr, &lease, info);
}

fn synthetic_peer(addr: SocketAddr, start_height: i32) -> PeerInfo {
    PeerInfo {
        addr,
        version: 70_016,
        wtxid_relay: false,
        compact_block_relay: false,
        services: 0,
        user_agent: String::from("/test/"),
        start_height,
        best_known_height: start_height,
        conn_time: 0,
        inbound: true,
        addr_bind: addr,
        time_offset: 0,
        counters: std::sync::Arc::new(crate::PeerCounters::default()),
    }
}

pub(crate) fn eligible_peer(addr: SocketAddr, start_height: i32) -> PeerInfo {
    PeerInfo {
        // SERVICE_WITNESS (1 << 3) | NODE_NETWORK (1): native peer flags.
        services: 0b1001,
        inbound: false,
        addr_bind: addr,
        time_offset: 0,
        counters: std::sync::Arc::new(crate::PeerCounters::default()),
        ..synthetic_peer(addr, start_height)
    }
}

pub(crate) fn test_addr(
    base_port: usize,
    idx: usize,
) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    Ok(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        u16::try_from(base_port + idx)?,
    ))
}

pub(crate) fn connect_peer(
    peer_table: &Arc<PeerTable>,
    info: PeerInfo,
) -> crossbeam_channel::Receiver<Message> {
    let (tx, rx) = unbounded::<Message>();
    let lease = PeerLease::new(tx);
    peer_table.register(info.addr, lease.clone());
    peer_table.publish_info(info.addr, &lease, info);
    rx
}

#[cfg(test)]
mod behavior_1;

#[cfg(test)]
mod behavior_2;

#[cfg(test)]
mod behavior_3;

#[cfg(test)]
mod behavior_4;

#[cfg(test)]
mod behavior_5;

#[cfg(test)]
mod behavior_6;

#[cfg(test)]
mod transitions_1;

#[cfg(test)]
mod transitions_2;

#[cfg(test)]
mod transitions_3;

#[cfg(test)]
mod transitions_4;

#[cfg(test)]
mod transitions_5;

#[cfg(test)]
mod transitions_6;

#[cfg(test)]
mod validation_1;

#[cfg(test)]
mod witness_staging_gate;

mod frontier_recovery;

#[cfg(test)]
mod frontier_model;
mod head_sync;

/// A sync loop over an applied chain whose commit fails on command for one
/// hash, with block 2 announced and its body owed to one live connection.
///
/// The fixture is the `SYNC-BR-01` setup: the node has applied block 1, the
/// header tip is block 2, and the body that will fail is attributable to
/// `source`.
struct PunishmentFixture {
    sync: Arc<BlockSync>,
    peers: Arc<PeerTable>,
    chain: Arc<TestChain>,
    blocks_tx: crossbeam_channel::Sender<crate::InboundBlock>,
    block2: Block,
    source: PeerSource,
    /// The announcing connection's outbound queue, kept alive so a send
    /// failure can never masquerade as a disconnect.
    _peer_rx: crossbeam_channel::Receiver<Message>,
}

fn punishment_fixture() -> Result<PunishmentFixture, Box<dyn std::error::Error>> {
    let (mut tree, blocks) = mined_chain(1, 0)?;
    let chain_tip = tree.tip_handle();
    let block_tree = Arc::new(RwLock::new(tree));
    let peers = Arc::new(PeerTable::new());
    let (headers_tx, headers_rx) = unbounded();
    let (blocks_tx, blocks_rx) = unbounded();
    let chain = Arc::new(TestChain::new(
        chain_tip,
        Arc::new(ArcSwapOption::empty()),
        Arc::clone(&block_tree),
    ));
    let chain_handle: Arc<TestChain> = Arc::clone(&chain);
    let chain_ref: Arc<dyn SyncChain> = chain_handle;
    let sync = Arc::new(BlockSync::new(
        chain_ref,
        Arc::clone(&peers),
        Arc::new(Mutex::new(headers_rx)),
        Arc::new(Mutex::new(blocks_rx)),
    ));
    // Apply block 1 so the apply frontier needs block 2's body.
    blocks_tx.send(crate::InboundBlock::from_decoded(blocks[0].clone()))?;
    sync.tick();

    let addr = test_addr(9770, 0)?;
    let peer_rx = connect_peer(&peers, eligible_peer(addr, 2));
    let source = current_source(&peers, addr);
    let block2 =
        mined_block_with_prev_hash(blocks[0].block_hash(), 2, vec![coinbase_transaction(2)]);
    headers_tx.send(InboundHeaders {
        headers: vec![block2.header],
        source: Some(source),
        wire_response: true,
        body_fetch_owned: false,
    })?;
    sync.tick();
    Ok(PunishmentFixture {
        sync,
        peers,
        chain,
        blocks_tx,
        block2,
        source,
        _peer_rx: peer_rx,
    })
}

/// Delivers the fixture's block 2 body from the connection that announced it.
fn deliver_attributed_body(fixture: &PunishmentFixture) -> Result<(), Box<dyn std::error::Error>> {
    let mut inbound = crate::InboundBlock::from_decoded(fixture.block2.clone());
    inbound.source = Some(fixture.source);
    fixture.blocks_tx.send(inbound)?;
    fixture.sync.tick();
    Ok(())
}

/// A body the chain rejects for a permanent consensus reason is the delivering
/// connection's fault: Core disconnects its source
/// (`net_processing.cpp:2031-2068`). At the base of this change the same body
/// purged its subtree and left the connection serving it.
#[test]
fn permanent_consensus_body_disconnects_delivering_source() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = punishment_fixture()?;
    let hash = Hash256::from(fixture.block2.block_hash());
    *fixture.chain.scripted_commit_failure.lock() =
        Some((hash, WindowCommitDisposition::Permanent));

    deliver_attributed_body(&fixture)?;

    assert!(
        !fixture.peers.is_current(fixture.source),
        "the connection that served a consensus-invalid block must be disconnected"
    );
    Ok(())
}

/// The exclusions: a body that does not bind to its header and an operational
/// settlement failure are not the delivering connection's fault, so neither may
/// end the conversation.
#[test]
fn binding_and_operational_failures_do_not_disconnect() -> Result<(), Box<dyn std::error::Error>> {
    for disposition in [
        WindowCommitDisposition::BodyMutated,
        WindowCommitDisposition::Operational,
    ] {
        let fixture = punishment_fixture()?;
        let hash = Hash256::from(fixture.block2.block_hash());
        *fixture.chain.scripted_commit_failure.lock() = Some((hash, disposition));

        deliver_attributed_body(&fixture)?;

        assert!(
            fixture.peers.is_current(fixture.source),
            "a {disposition:?} settlement failure must not disconnect the delivering connection"
        );
    }
    Ok(())
}
