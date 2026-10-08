use crate::node::NodeId;

enum TrustState {
    Trusted,
    Tainted,
}

pub(super) struct ActiveHeightIndex {
    entries: Vec<NodeId>,
    state: TrustState,
}

impl ActiveHeightIndex {
    pub(super) fn new() -> Self {
        Self {
            entries: Vec::new(),
            state: TrustState::Tainted,
        }
    }

    pub(super) fn is_trusted(&self) -> bool {
        matches!(self.state, TrustState::Trusted)
    }

    pub(super) fn get(&self, height: u32) -> Option<NodeId> {
        let index = usize::try_from(height).ok()?;
        self.entries.get(index).copied()
    }

    pub(super) fn last(&self) -> Option<NodeId> {
        self.entries.last().copied()
    }

    #[cfg(any(test, feature = "test-seam"))]
    pub(super) fn contains_at_height(&self, height: u32, id: NodeId) -> bool {
        self.get(height) == Some(id)
    }

    #[cfg(any(test, feature = "test-seam"))]
    pub(super) fn taint(&mut self) {
        self.state = TrustState::Tainted;
    }

    pub(super) fn clear_tainted(&mut self) {
        self.entries.clear();
        self.state = TrustState::Tainted;
    }

    /// Extends a trusted index by one tip when parent/height preconditions hold.
    ///
    /// Must not promote [`TrustState::Tainted`] to [`TrustState::Trusted`].
    pub(super) fn extend_validated(
        &mut self,
        parent: NodeId,
        tip_height: u32,
        tip: NodeId,
    ) -> bool {
        if self.is_trusted()
            && self.last() == Some(parent)
            && u32::try_from(self.entries.len()).ok() == Some(tip_height)
        {
            self.entries.push(tip);
            true
        } else {
            false
        }
    }

    /// Commits a fully validated rebuild. This is the only Trusted transition.
    pub(super) fn commit_validated_rebuild(&mut self, entries: Vec<NodeId>) {
        self.entries = entries;
        self.state = TrustState::Trusted;
    }
}

#[cfg(test)]
impl ActiveHeightIndex {
    /// Test seam: taints first, then optionally replaces a height slot.
    pub(super) fn replace_slot_for_test(&mut self, height: u32, id: NodeId) -> bool {
        self.taint();
        let Some(index) = usize::try_from(height).ok() else {
            return false;
        };
        if let Some(slot) = self.entries.get_mut(index) {
            *slot = id;
            true
        } else {
            false
        }
    }

    pub(super) fn is_empty_for_test(&self) -> bool {
        self.entries.is_empty()
    }

    pub(super) fn is_tainted_for_test(&self) -> bool {
        matches!(self.state, TrustState::Tainted)
    }
}
