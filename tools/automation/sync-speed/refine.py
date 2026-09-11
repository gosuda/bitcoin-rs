"""Refine the source candidate without changing its ancestry contract."""
from pathlib import Path

p = Path('crates/node/src/sync.rs')
s = p.read_text()
start = s.index('        let Ok(applied_node) = tree.node(applied_id) else {', s.index('    fn send_getdata_for_pending_blocks('))
end = s.index('\n        let mut window = self.download_window.lock();', start)
s = s[:start] + '''        let Some(request_start_height) =
            Self::pending_request_start_height(&tree, applied_id, chain_tip.tip_id)
        else {
            return GetdataRequestOutcome::default();
        };
''' + s[end:]
needle = '    fn send_getdata_for_pending_blocks('
helper = '''    /// First connect height under SYNC-FRONTIER-01, without an IBD-sized plan.
    fn pending_request_start_height(
        tree: &BlockTree,
        applied_id: NodeId,
        header_tip_id: NodeId,
    ) -> Option<u32> {
        let applied_height = tree.node(applied_id).ok()?.height;
        if tree.node_at_height_from(header_tip_id, applied_height) == Some(applied_id) {
            let height = applied_height.checked_add(1)?;
            let successor = tree.node_at_height_from(header_tip_id, height)?;
            return Some(tree.node(successor).ok()?.height);
        }
        // Actual forks and disconnected roots retain the parent-walk planner.
        let plan = plan_reorg(tree, applied_id, header_tip_id).ok()?;
        tree.node(*plan.connect.first()?).ok().map(|node| node.height)
    }

'''
assert s.count(needle) == 1
s = s.replace(needle, helper + needle, 1)
p.write_text(s)
