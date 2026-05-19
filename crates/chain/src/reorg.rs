use crate::{ChainError, node::NodeId, tree::BlockTree};

/// Parent-walk plan for switching from one tip to another.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReorgPlan {
    /// Common ancestor shared by both tips.
    pub ancestor: NodeId,
    /// Nodes to disconnect from old tip down toward the ancestor.
    pub disconnect: Vec<NodeId>,
    /// Nodes to connect from ancestor child toward the new tip.
    pub connect: Vec<NodeId>,
}

/// Plans a reorg by walking parent pointers to the common ancestor.
pub fn plan_reorg(
    tree: &BlockTree,
    old_tip: NodeId,
    new_tip: NodeId,
) -> Result<ReorgPlan, ChainError> {
    let mut old_cursor = old_tip;
    let mut new_cursor = new_tip;
    let mut old_height = tree.node(old_cursor)?.height;
    let mut new_height = tree.node(new_cursor)?.height;
    let mut disconnect = Vec::new();
    let mut connect = Vec::new();

    while old_height > new_height {
        disconnect.push(old_cursor);
        old_cursor = parent_or_no_common(tree, old_cursor, old_tip, new_tip)?;
        old_height = tree.node(old_cursor)?.height;
    }

    while new_height > old_height {
        connect.push(new_cursor);
        new_cursor = parent_or_no_common(tree, new_cursor, old_tip, new_tip)?;
        new_height = tree.node(new_cursor)?.height;
    }

    while old_cursor != new_cursor {
        disconnect.push(old_cursor);
        connect.push(new_cursor);
        old_cursor = parent_or_no_common(tree, old_cursor, old_tip, new_tip)?;
        new_cursor = parent_or_no_common(tree, new_cursor, old_tip, new_tip)?;
    }

    connect.reverse();
    Ok(ReorgPlan {
        ancestor: old_cursor,
        disconnect,
        connect,
    })
}

fn parent_or_no_common(
    tree: &BlockTree,
    id: NodeId,
    old_tip: NodeId,
    new_tip: NodeId,
) -> Result<NodeId, ChainError> {
    tree.parent_id(id)?
        .ok_or(ChainError::NoCommonAncestor { old_tip, new_tip })
}
