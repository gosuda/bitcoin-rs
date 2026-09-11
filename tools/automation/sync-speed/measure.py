"""Workbench-only probe: actual private branch gate and actual BlockSync::tick."""
from pathlib import Path
import sys

PROBE = r'''
    #[test]
    #[ignore = "workbench-only paired measurement; not an acceptance test"]
    fn workbench_sync_frontier_measurement() -> Result<(), Box<dyn std::error::Error>> {
        let height = std::env::var("FRONTIER_HEIGHT")?.parse::<u32>()?;
        let mode = std::env::var("FRONTIER_MODE")?;
        let mut tree = BlockTree::new();
        let root = tree.insert_node(None, genesis_header(), NodeStatus::HeaderValid)?;
        let genesis = tree.node(root)?;
        let applied = TipSnapshot {
            tip_id: root, height: 0, chainwork: genesis.chainwork, hash: genesis.hash,
        };
        let mut parent = root;
        for tag in 1..=height {
            let header = test_header(BlockHash::from(tree.node(parent)?.hash), tag);
            parent = tree.insert_node(Some(parent), header, NodeStatus::HeaderValid)?;
        }
        let expected_tip = tree.node(parent)?.hash;
        let chain_tip = tree.tip_handle();
        let applied_tip = Arc::new(ArcSwapOption::empty());
        applied_tip.store(Some(Arc::new(applied)));
        let block_tree = Arc::new(RwLock::new(tree));
        let peers = Arc::new(PeerTable::new());
        let (_, headers_rx) = unbounded::<InboundHeaders>();
        let (_, blocks_rx) = unbounded::<bitcoin_rs_p2p::InboundBlock>();
        let sync = BlockSync::for_test(
            apply_handles(chain_tip, applied_tip, block_tree), Arc::clone(&peers),
            Arc::new(Mutex::new(headers_rx)), Arc::new(Mutex::new(blocks_rx)),
        );
        let addr = SocketAddr::from(([127, 0, 0, 1], 8_333));
        let rx = connect_peer(&peers, synthetic_peer(addr, i32::try_from(height)?));
        // Fill the bounded in-flight window once. Later saturated ticks are a
        // real IBD state, but no network, script throughput or disk speed is measured.
        sync.tick();
        for sample in 0..21 {
            let started = Instant::now();
            for _ in 0..16 {
                if mode == "gate" {
                    assert!(std::hint::black_box(&sync).outweighed_branch_target().is_none());
                } else {
                    std::hint::black_box(&sync).tick();
                }
            }
            println!("SYNC_SAMPLE {{\"mode\":\"{mode}\",\"height\":{height},\"sample\":{sample},\"iterations\":16,\"elapsed_ns\":{}}}", started.elapsed().as_nanos());
        }
        let mut trace = Vec::new();
        let mut requested = 0_usize;
        for message in rx.try_iter() {
            let Message::GetData(inventory) = message else {
                return Err("unexpected non-getdata message in frozen-height probe".into());
            };
            for item in inventory {
                let Inventory::WitnessBlock(hash) = item else {
                    return Err("unexpected inventory kind".into());
                };
                requested += 1;
                trace.extend_from_slice(hash.as_byte_array());
            }
        }
        let final_applied = sync.handles.applied_tip.load_full().ok_or("no applied tip")?;
        let final_headers = sync.handles.chain_tip.load_full().ok_or("no header tip")?;
        assert_eq!(final_applied.height, 0);
        assert_eq!(final_headers.height, height);
        assert_eq!(final_headers.hash, expected_tip);
        assert!(requested > 0);
        trace.extend_from_slice(final_applied.hash.as_byte_array());
        trace.extend_from_slice(final_headers.hash.as_byte_array());
        let digest = bitcoin::hashes::sha256d::Hash::hash(&trace);
        println!("SYNC_RESULT {{\"mode\":\"{mode}\",\"height\":{height},\"requests\":{requested},\"result_hash\":\"{digest}\"}}");
        Ok(())
    }
'''
path = Path('crates/node/src/sync.rs')
s = path.read_text()
needle = '    #[test]\n    fn tick_sends_getdata_for_headers_above_applied_tip()'
assert s.count(needle) == 1
path.write_text(s.replace(needle, PROBE + '\n' + needle, 1))
