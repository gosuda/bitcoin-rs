"""Apply the reviewed, blob-pinned sync optimization in an isolated checkout."""
from pathlib import Path
import hashlib
import sys

SOURCE = Path('crates/node/src/sync.rs')
EXPECTED = 'b8db70115b4f7d7d1680ed5dac962cf219d75d8b'
data = SOURCE.read_bytes()
assert hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == EXPECTED
text = data.decode()

def replace_once(old, new):
    global text
    assert text.count(old) == 1, f'expected one exact replacement: {old[:100]!r}'
    if '--control' not in sys.argv or old.startswith('    #[test]'):
        text = text.replace(old, new, 1)

replace_once('''        let applied_id = tree.lookup(applied.hash)?;
        let plan = plan_reorg(&tree, applied_id, chain_tip.tip_id).ok()?;
''', '''        let applied_id = tree.lookup(applied.hash)?;
        // Normal IBD extends the applied chain. Its trusted height index proves
        // ancestry without allocating a plan for the entire remaining chain.
        // Keep the parent-walk planner for actual forks and disconnected roots.
        let applied_height = tree.node(applied_id).ok()?.height;
        if tree.node_at_height_from(chain_tip.tip_id, applied_height) == Some(applied_id) {
            return None;
        }
        let plan = plan_reorg(&tree, applied_id, chain_tip.tip_id).ok()?;
''')

replace_once('''        let Ok(plan) = plan_reorg(&tree, applied_id, chain_tip.tip_id) else {
            return GetdataRequestOutcome::default();
        };
        let Some(first_connect) = plan.connect.first() else {
            return GetdataRequestOutcome::default();
        };
        let Ok(first_connect) = tree.node(*first_connect) else {
''', '''        let Ok(applied_node) = tree.node(applied_id) else {
            return GetdataRequestOutcome::default();
        };
        // Only the first connect height is needed by the bounded scheduler.
        // On linear IBD, use the existing ancestry index rather than building
        // and discarding a connect Vec proportional to the full header gap.
        let successor = if tree.node_at_height_from(chain_tip.tip_id, applied_node.height)
            == Some(applied_id)
        {
            applied_node
                .height
                .checked_add(1)
                .and_then(|height| tree.node_at_height_from(chain_tip.tip_id, height))
        } else {
            None
        };
        let first_connect = if let Some(successor) = successor {
            successor
        } else {
            let Ok(plan) = plan_reorg(&tree, applied_id, chain_tip.tip_id) else {
                return GetdataRequestOutcome::default();
            };
            let Some(first_connect) = plan.connect.first().copied() else {
                return GetdataRequestOutcome::default();
            };
            first_connect
        };
        let Ok(first_connect) = tree.node(first_connect) else {
''')

replace_once("""    /// Returns the header tip when the applied chain is not on its branch.
""", """    /// Returns the header tip when the applied chain is not on its branch.
    ///
    /// SYNC-FRONTIER-01: ancestry is identified by node identity, not height
    /// alone. An applied ancestor needs no switch; request selection starts at
    /// the first connect node of the parent-walk plan. The trusted active-height
    /// index may answer linear-sync queries without constructing that plan.
    /// Forks, disconnected roots, and invalidated indices retain parent-walk
    /// semantics. This does not change admission, request budgets, or apply.
""")

TESTS = r'''
    fn check_sync_frontier_pair(
        sync: &BlockSync,
        rx: &crossbeam_channel::Receiver<Message>,
        addr: SocketAddr,
        applied: &TipSnapshot,
        target: &TipSnapshot,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let expected = bitcoin_rs_chain::plan_reorg(
            &sync.handles.block_tree.read(), applied.tip_id, target.tip_id,
        ).ok();
        sync.handles.applied_tip.store(Some(Arc::new(applied.clone())));
        sync.handles.chain_tip.store(Some(Arc::new(target.clone())));
        assert_eq!(
            sync.outweighed_branch_target(),
            expected.as_ref().filter(|plan| !plan.disconnect.is_empty())
                .map(|_| target.tip_id),
            "branch gate differs: {applied:?} -> {target:?}; indexed or parent-walk fixture"
        );
        sync.install_budget(super::default_sync_budget());
        let outcome = sync.send_getdata_for_pending_blocks(
            addr, true, 100, target, applied,
        );
        let expected_ids = expected.as_ref().map(|plan| plan.connect.as_slice())
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
        let requested = inventory.into_iter().map(|item| match item {
            Inventory::WitnessBlock(hash) => Ok(Hash256::from_le_bytes(hash.as_byte_array())),
            _ => Err("expected witness block inventory"),
        }).collect::<Result<Vec<_>, _>>()?;
        let tree = sync.handles.block_tree.read();
        let expected_hashes = expected_ids.iter().take(requested.len())
            .map(|id| tree.node(*id).map(|node| node.hash))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(requested, expected_hashes);
        assert!(!requested.is_empty());
        assert!(rx.try_recv().is_err());
        Ok(())
    }


    // SYNC-FRONTIER-01: the documented contracts of outweighed_branch_target
    // and send_getdata_for_pending_blocks require ancestry, not equal heights.
    // Independent oracle: crates/chain/src/reorg.rs::plan_reorg, unchanged by
    // this optimization. Compare actual emitted hashes, not only batch sizes.
    #[test]
    fn indexed_sync_frontiers_match_parent_plans() -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let root = tree.insert_node(None, genesis_header(), NodeStatus::HeaderValid)?;
        let mut main = vec![root];
        for tag in 1..=12 {
            let parent = *main.last().ok_or("missing main parent")?;
            let header = test_header(BlockHash::from(tree.node(parent)?.hash), tag);
            main.push(tree.insert_node(Some(parent), header, NodeStatus::HeaderValid)?);
        }
        let mut fork = vec![main[2]];
        for tag in 101..=106 {
            let parent = *fork.last().ok_or("missing fork parent")?;
            let header = test_header(BlockHash::from(tree.node(parent)?.hash), tag);
            fork.push(tree.insert_node(Some(parent), header, NodeStatus::HeaderValid)?);
        }
        let foreign_header = test_header(BlockHash::from(Hash256::from_le_bytes(&[0; 32])), 200);
        let foreign = tree.insert_node(None, foreign_header, NodeStatus::HeaderValid)?;
        let endpoints = [root, main[2], main[6], main[12], fork[2], fork[6], foreign];
        let snapshots = endpoints
            .iter()
            .map(|&tip_id| {
                let node = tree.node(tip_id)?;
                Ok(TipSnapshot {
                    tip_id,
                    height: node.height,
                    chainwork: node.chainwork,
                    hash: node.hash,
                })
            })
            .collect::<Result<Vec<_>, bitcoin_rs_chain::ChainError>>()?;
        let chain_tip = tree.tip_handle();
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let block_tree = Arc::new(RwLock::new(tree));
        let peers = Arc::new(PeerTable::new());
        let (_, headers_rx) = unbounded::<InboundHeaders>();
        let (_, blocks_rx) = unbounded::<bitcoin_rs_p2p::InboundBlock>();
        let sync = BlockSync::for_test(
            apply_handles(chain_tip, Arc::clone(&applied_tip), Arc::clone(&block_tree)),
            Arc::clone(&peers),
            Arc::new(Mutex::new(headers_rx)),
            Arc::new(Mutex::new(blocks_rx)),
        );
        let addr = SocketAddr::from(([127, 0, 0, 1], 8_333));
        let rx = connect_peer(&peers, synthetic_peer(addr, 100));

        // Repeat the same matrix after public node_mut invalidates the index,
        // without changing any node. Cached and parent-walk answers must agree.
        for tainted in [false, true] {
            if tainted {
                let mut tree = block_tree.write();
                let _ = tree.node_mut(main[12])?;
            }
            for applied in &snapshots {
                for target in &snapshots {
                    check_sync_frontier_pair(&sync, &rx, addr, applied, target)?;
                }
            }
        }
        Ok(())
    }
'''
# Tests live beside and reuse the existing sync fixture owners.
needle = '    #[test]\n    fn tick_sends_getdata_for_headers_above_applied_tip()'
replace_once(needle, TESTS + '\n' + needle)
SOURCE.write_text(text)
print('PATCH_APPLIED', SOURCE, hashlib.sha256(SOURCE.read_bytes()).hexdigest())
