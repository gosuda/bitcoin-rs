//! Bounded retention of recent stale tips for BIP332 relay.

use std::cmp::Reverse;
use std::collections::VecDeque;
use std::sync::Arc;

use bitcoin_rs_chain::{BlockTree, BlockTreeNode, ChainWork, NodeId, NodeStatus, TipSnapshot};
use bitcoin_rs_primitives::Hash256;
use hashbrown::HashMap;
use parking_lot::Mutex;

use super::BlockSync;
use crate::PeerSource;

/// Most stale tips held at once.
pub(crate) const MAX_RETAINED_STALE_TIPS: usize = 64;

/// Most blocks a stale tip may lie behind the active tip and still be relayed
/// (BIP332 `STALETIP_RECENT_WINDOW`).
pub(crate) const STALETIP_RECENT_WINDOW: u32 = 1000;

/// Most previously known stale tips advertised to a peer when relay with it
/// begins (BIP332 `MAX_ADVERTISED_STALETIPS`).
pub(crate) const MAX_ADVERTISED_STALETIPS: usize = 10;

#[derive(Debug)]
struct Retained {
    hash: Hash256,
    work: ChainWork,
    sequence: u64,
    known_by: Vec<PeerSource>,
}

impl Retained {
    fn rank(&self) -> (ChainWork, u64) {
        (self.work, self.sequence)
    }

    fn mark_known(&mut self, peer: PeerSource) {
        if !self.known_by.contains(&peer) {
            self.known_by.push(peer);
        }
    }
}

#[derive(Debug, Default)]
struct Opening {
    floor: u64,
    pending: Vec<Hash256>,
}

#[derive(Debug, Default)]
struct State {
    tips: Vec<Retained>,
    next_sequence: u64,
    opened: HashMap<PeerSource, Opening>,
    heard: VecDeque<(Hash256, PeerSource)>,
}

impl State {
    fn prune(&mut self, tree: &BlockTree) {
        let tip = tree.tip();
        self.tips.retain(|retained| {
            tip.as_deref().is_some_and(|tip| {
                tree.lookup(retained.hash)
                    .is_some_and(|id| stale_fork(tree, tip, id).is_some())
            })
        });
    }

    fn ranked(&self) -> Vec<&Retained> {
        let mut ranked: Vec<&Retained> = self.tips.iter().collect();
        ranked.sort_by_key(|retained| Reverse(retained.rank()));
        ranked
    }

    fn absorb_heard(&mut self, hash: Hash256) {
        let Some(held) = self.tips.iter_mut().find(|held| held.hash == hash) else {
            return;
        };
        self.heard.retain(|&(tip, peer)| {
            if tip == hash {
                held.mark_known(peer);
                false
            } else {
                true
            }
        });
    }
}

fn in_scope(node: &BlockTreeNode, tip: &TipSnapshot) -> bool {
    node.status != NodeStatus::Invalid
        && tip.height.saturating_sub(node.height) <= STALETIP_RECENT_WINDOW
}

fn stale_fork(tree: &BlockTree, tip: &TipSnapshot, id: NodeId) -> Option<NodeId> {
    let node = tree.node(id).ok()?;
    if !in_scope(node, tip) {
        return None;
    }
    let fork = tree.find_common_ancestor(tip.tip_id, id)?;
    (fork != id && fork != tip.tip_id).then_some(fork)
}

fn on_ancestry_of(
    tree: &BlockTree,
    ancestor: NodeId,
    ancestor_height: u32,
    descendant: Hash256,
) -> bool {
    tree.lookup(descendant)
        .and_then(|id| tree.node_at_height_from(id, ancestor_height))
        == Some(ancestor)
}

#[derive(Debug, Default)]
pub struct StaleTipRetainer {
    state: Mutex<State>,
}

impl StaleTipRetainer {
    pub(crate) fn seed(tree: &BlockTree) -> Self {
        let Some(tip) = tree.tip() else {
            return Self::default();
        };
        let mut next_sequence = 0_u64;
        let mut leaves = Vec::new();
        for (sequence, id) in (0_u64..).zip(tree.leaf_node_ids()) {
            next_sequence = sequence.saturating_add(1);
            let Ok(node) = tree.node(id) else {
                continue;
            };
            if in_scope(node, &tip) {
                leaves.push((
                    id,
                    Retained {
                        hash: node.hash,
                        work: node.chainwork,
                        sequence,
                        known_by: Vec::new(),
                    },
                ));
            }
        }
        leaves.sort_by_key(|(_, retained)| Reverse(retained.rank()));

        let mut tips = Vec::with_capacity(leaves.len().min(MAX_RETAINED_STALE_TIPS));
        for (id, retained) in leaves {
            if tips.len() == MAX_RETAINED_STALE_TIPS {
                break;
            }
            if stale_fork(tree, &tip, id).is_some() {
                tips.push(retained);
            }
        }
        Self {
            state: Mutex::new(State {
                tips,
                next_sequence,
                ..State::default()
            }),
        }
    }

    pub(crate) fn learn(&self, tree: &BlockTree, hash: Hash256, from: Option<PeerSource>) -> bool {
        let mut state = self.state.lock();
        state.prune(tree);
        if let Some(held) = state.tips.iter_mut().find(|held| held.hash == hash) {
            if let Some(peer) = from {
                held.mark_known(peer);
            }
            state.absorb_heard(hash);
            return false;
        }

        let (Some(tip), Some(id)) = (tree.tip(), tree.lookup(hash)) else {
            return false;
        };
        let (Some(fork), Ok(node)) = (stale_fork(tree, &tip, id), tree.node(id)) else {
            return false;
        };
        if state
            .tips
            .iter()
            .any(|held| on_ancestry_of(tree, id, node.height, held.hash))
        {
            return false;
        }

        let mut cursor = node.parent;
        for _ in 0..tree.len() {
            let Some(ancestor) = cursor.filter(|&ancestor| ancestor != fork) else {
                break;
            };
            let Ok(ancestor_node) = tree.node(ancestor) else {
                break;
            };
            state.tips.retain(|held| held.hash != ancestor_node.hash);
            cursor = ancestor_node.parent;
        }

        let sequence = state.next_sequence;
        state.next_sequence = sequence.saturating_add(1);
        state.tips.push(Retained {
            hash,
            work: node.chainwork,
            sequence,
            known_by: from.into_iter().collect(),
        });
        if state.tips.len() > MAX_RETAINED_STALE_TIPS {
            let Some(weakest) = state
                .tips
                .iter()
                .enumerate()
                .min_by_key(|(_, held)| held.rank())
                .map(|(index, _)| index)
            else {
                return false;
            };
            if state.tips.swap_remove(weakest).hash == hash {
                return false;
            }
        }
        state.absorb_heard(hash);
        true
    }

    pub(crate) fn note_heard(&self, peer: PeerSource, hash: Hash256) {
        let mut state = self.state.lock();
        if state.heard.contains(&(hash, peer)) {
            return;
        }
        if state.heard.len() == MAX_RETAINED_STALE_TIPS {
            state.heard.pop_front();
        }
        state.heard.push_back((hash, peer));
    }

    pub(crate) fn prune(&self, tree: &BlockTree) {
        self.state.lock().prune(tree);
    }

    pub(crate) fn pending_for(
        &self,
        peer: PeerSource,
        mut relayable: impl FnMut(Hash256) -> bool,
    ) -> Vec<Hash256> {
        let (opening, candidates) = {
            let mut state = self.state.lock();
            let opening = !state.opened.contains_key(&peer);
            if opening {
                let floor = state.next_sequence;
                state.opened.insert(
                    peer,
                    Opening {
                        floor,
                        pending: Vec::new(),
                    },
                );
            }
            let (floor, pending) = state
                .opened
                .get(&peer)
                .map(|slot| (slot.floor, slot.pending.clone()))
                .unwrap_or_default();
            let mut candidates = Vec::new();
            for held in state.ranked() {
                if held.known_by.contains(&peer) {
                    continue;
                }
                if opening || held.sequence >= floor || pending.contains(&held.hash) {
                    candidates.push(held.hash);
                }
            }
            (opening, candidates)
        };
        let mut accepted: Vec<Hash256> = Vec::new();
        let mut seen: Vec<Hash256> = Vec::new();
        for hash in candidates {
            if opening && accepted.len() == MAX_ADVERTISED_STALETIPS {
                break;
            }
            if opening {
                seen.push(hash);
            }
            if relayable(hash) {
                accepted.push(hash);
            }
        }
        {
            let mut state = self.state.lock();
            let offerable = |tips: &[Retained], hash: Hash256| {
                tips.iter()
                    .any(|held| held.hash == hash && !held.known_by.contains(&peer))
            };
            if opening {
                let budget = MAX_ADVERTISED_STALETIPS.saturating_sub(accepted.len());
                let mut selected = Vec::new();
                let mut refused_kept = 0;
                for hash in &seen {
                    if accepted.contains(hash) {
                        if offerable(&state.tips, *hash) {
                            selected.push(*hash);
                        }
                    } else if refused_kept < budget && offerable(&state.tips, *hash) {
                        selected.push(*hash);
                        refused_kept += 1;
                    }
                }
                if let Some(slot) = state.opened.get_mut(&peer) {
                    slot.pending = selected;
                }
            } else {
                let State { tips, opened, .. } = &mut *state;
                if let Some(slot) = opened.get_mut(&peer) {
                    slot.pending.retain(|hash| offerable(tips, *hash));
                }
            }
        }
        accepted
    }

    pub(crate) fn knows(&self, peer: PeerSource, hash: Hash256) -> bool {
        self.state
            .lock()
            .tips
            .iter()
            .any(|held| held.hash == hash && held.known_by.contains(&peer))
    }

    pub(crate) fn mark_known(&self, peer: PeerSource, hash: Hash256) {
        if let Some(held) = self
            .state
            .lock()
            .tips
            .iter_mut()
            .find(|held| held.hash == hash)
        {
            held.mark_known(peer);
        }
    }

    pub(crate) fn forget_peer(&self, peer: PeerSource) {
        let mut state = self.state.lock();
        for held in &mut state.tips {
            held.known_by.retain(|known| *known != peer);
        }
        state.opened.remove(&peer);
        state.heard.retain(|&(_, heard_from)| heard_from != peer);
    }
}

impl BlockSync {
    #[must_use]
    pub fn stale_tips(&self) -> Arc<StaleTipRetainer> {
        Arc::clone(&self.stale_tips)
    }

    pub fn record_demoted_tip(&self, hash: Hash256) -> bool {
        let tree = self.chain.block_tree();
        self.stale_tips.learn(&tree, hash, None)
    }

    pub(super) fn record_admitted_tips(
        &self,
        demoted_tip: Option<Hash256>,
        announced_tip: Option<Hash256>,
        from: Option<PeerSource>,
    ) {
        if demoted_tip.is_none() && announced_tip.is_none() {
            return;
        }
        let tree = self.chain.block_tree();
        if let Some(tip) = demoted_tip {
            self.stale_tips.learn(&tree, tip, None);
        }
        if let Some(tip) = announced_tip {
            self.stale_tips.learn(&tree, tip, from);
        }
    }
}

#[cfg(test)]
mod tests;
