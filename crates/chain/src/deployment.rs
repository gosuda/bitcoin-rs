//! BIP9/softfork lookups over a [`BlockTree`].
//!
//! Consensus owns the state machine and deployment parameters. This module
//! owns the tree walk, the BIP9 cache, and the CSV/Segwit snapshot an apply
//! or mining caller needs at a connect height.

use bitcoin_rs_consensus::bip9::versionbits_block_version;
use bitcoin_rs_consensus::bip30::BIP34_IMPLIES_BIP30_LIMIT;
use bitcoin_rs_consensus::{
    CSV_DEPLOYMENT_ID, DeploymentContext, DeploymentParams, DeploymentState, SEGWIT_DEPLOYMENT_ID,
    SoftforkState, compute_state, deployment_params,
};
use bitcoin_rs_primitives::Network;

use crate::{BlockTree, NodeId};

/// Read-only [`DeploymentContext`] over a [`BlockTree`] rooted at `tip_id`.
struct DeploymentView<'a> {
    tree: &'a BlockTree,
    tip_id: NodeId,
    // Only reporting captures an off-header-chain ancestry; validation keeps
    // its existing direct view. The temporary IDs are not a state cache.
    ancestry: Option<Vec<NodeId>>,
}

impl<'a> DeploymentView<'a> {
    /// Anchors lookups at `tip_id` within `tree`.
    #[must_use]
    const fn new(tree: &'a BlockTree, tip_id: NodeId) -> Self {
        Self {
            tree,
            tip_id,
            ancestry: None,
        }
    }

    fn for_query(
        tree: &'a BlockTree,
        tip_id: NodeId,
        budget: usize,
    ) -> Result<Self, DeploymentQueryError> {
        let node = tree.node(tip_id)?;
        if tree
            .active_node_at_height(node.height)
            .is_some_and(|active| active.hash == node.hash)
        {
            return Ok(Self::new(tree, tip_id));
        }
        let count = usize::try_from(node.height)
            .ok()
            .and_then(|height| height.checked_add(1))
            .filter(|count| *count <= budget)
            .ok_or(DeploymentQueryError::Budget { limit: budget })?;
        let mut ancestry = Vec::with_capacity(count);
        let mut cursor = Some(tip_id);
        for expected in (0..=node.height).rev() {
            let id = cursor.ok_or(DeploymentQueryError::IncompleteAncestry)?;
            let node = tree.node(id)?;
            if node.height != expected {
                return Err(DeploymentQueryError::IncompleteAncestry);
            }
            ancestry.push(id);
            cursor = node.parent;
        }
        Ok(Self {
            tree,
            tip_id,
            ancestry: Some(ancestry),
        })
    }

    fn node_at_height(&self, height: u32) -> Option<NodeId> {
        match &self.ancestry {
            Some(ancestry) => ancestry
                .len()
                .checked_sub(usize::try_from(height).ok()?.checked_add(1)?)
                .and_then(|index| ancestry.get(index))
                .copied(),
            None => self.tree.node_at_height_from(self.tip_id, height),
        }
    }
}

impl DeploymentContext for DeploymentView<'_> {
    fn block_version(&self, height: u32) -> Option<i32> {
        let node_id = self.node_at_height(height)?;
        let node = self.tree.node(node_id).ok()?;
        Some(node.header.version)
    }

    fn median_time_past(&self, height: u32) -> Option<u32> {
        let node_id = self.node_at_height(height)?;
        self.tree.median_time_past_at(node_id)
    }
}

/// CSV/Segwit contextual state for the block that would extend `previous_tip_id`.
#[must_use]
pub fn softfork_state(
    tree: &BlockTree,
    network: Network,
    previous_tip_id: Option<NodeId>,
    height: u32,
) -> SoftforkState {
    SoftforkState {
        csv_active: deployment_active(tree, network, previous_tip_id, height, CSV_DEPLOYMENT_ID)
            .unwrap_or_else(|| network.is_csv_active(height)),
        segwit_active: deployment_active(
            tree,
            network,
            previous_tip_id,
            height,
            SEGWIT_DEPLOYMENT_ID,
        )
        .unwrap_or_else(|| network.is_segwit_active(height)),
    }
}

/// A BIP9 deployment currently in `Started` or `LockedIn` at a candidate height.
#[derive(Debug)]
pub struct SignallingDeployment {
    /// BIP22 rule name (`csv`, `segwit`).
    pub name: &'static str,
    /// Header-version bit assigned to the deployment.
    pub bit: u8,
}

const NAMED_DEPLOYMENTS: [(&str, u32); 2] =
    [("csv", CSV_DEPLOYMENT_ID), ("segwit", SEGWIT_DEPLOYMENT_ID)];

/// Deployments a GBT caller must see in `vbavailable`.
///
/// Only `Started` and `LockedIn` states are signalling. Active and failed
/// deployments are not negotiated as version bits. Core v31 `vbrequired` is
/// always 0 and is not derived from this list.
#[must_use]
pub fn signalling_deployments(
    tree: &BlockTree,
    network: Network,
    previous_tip_id: NodeId,
    height: u32,
) -> Vec<SignallingDeployment> {
    deployment_states(tree, network, previous_tip_id, height)
        .filter_map(|(name, params, state)| match state {
            DeploymentState::Started | DeploymentState::LockedIn => Some(SignallingDeployment {
                name,
                bit: params.bit,
            }),
            DeploymentState::Defined | DeploymentState::Active | DeploymentState::Failed => None,
        })
        .collect()
}

/// Versionbits candidate version at `height`, using the tree's BIP9 cache.
#[must_use]
pub fn candidate_version(
    tree: &BlockTree,
    network: Network,
    previous_tip_id: NodeId,
    height: u32,
) -> i32 {
    versionbits_block_version(
        deployment_states(tree, network, previous_tip_id, height)
            .map(|(_, params, state)| (params.bit, state)),
    )
}

/// Resolves each named deployment's parameters and BIP9 state at `height`,
/// reading through the tree's cache.
fn deployment_states(
    tree: &BlockTree,
    network: Network,
    previous_tip_id: NodeId,
    height: u32,
) -> impl Iterator<Item = (&'static str, DeploymentParams, DeploymentState)> + '_ {
    let ctx = DeploymentView::new(tree, previous_tip_id);
    NAMED_DEPLOYMENTS
        .into_iter()
        .filter_map(move |(name, deployment_id)| {
            let params = deployment_params(network, deployment_id)?;
            let state = cached_deployment_state(tree, &ctx, height, deployment_id, params);
            Some((name, params, state))
        })
}

/// Native activation facts for one deployment at a queried block.
#[derive(Debug)]
pub struct DeploymentStatus {
    /// Consensus deployment name.
    pub name: &'static str,
    /// Fixed activation height, or observed BIP9 activation height.
    pub height: Option<u32>,
    /// Whether the next block enforces the deployment.
    pub active: bool,
    /// Whether the queried block enforces the deployment.
    pub active_at_block: bool,
    /// Historical BIP9 facts when this network uses version-bit activation.
    pub bip9: Option<VersionBitsStatus>,
}

/// BIP9 history projected from the same cache and parameters validation uses.
#[derive(Debug)]
pub struct VersionBitsStatus {
    /// Authoritative deployment parameters.
    pub params: DeploymentParams,
    /// State at the queried block.
    pub state: DeploymentState,
    /// State at its successor.
    pub next: DeploymentState,
    /// First height in the current state.
    pub since: u32,
    /// Chronological signalling in the current window, only while signalling.
    pub signalling: Option<Vec<bool>>,
}

/// Maximum temporary ancestry IDs for an off-header-chain deployment query.
/// Two million IDs occupy at most eight megabytes. Header-chain queries reuse
/// the tree's existing height index and do not allocate this projection.
const MAX_DEPLOYMENT_QUERY_ANCESTORS: usize = 2_000_000;

/// Why native deployment history could not be projected.
#[derive(Debug, thiserror::Error)]
pub enum DeploymentQueryError {
    /// A requested header identity is unavailable.
    #[error(transparent)]
    Chain(#[from] crate::ChainError),
    /// The off-header-chain ancestry exceeds the query's temporary work budget.
    #[error("deployment query exceeds the {limit}-header ancestry budget")]
    Budget {
        /// Maximum ancestors captured by one query.
        limit: usize,
    },
    /// Header ancestry is incomplete or inconsistent.
    #[error("deployment query has incomplete header ancestry")]
    IncompleteAncestry,
}

/// Reads native deployment facts on the named ancestry; no tip is reloaded.
///
/// `None` identifies genesis before the first applied publication. Fixed-height
/// Taproot and native CSV/Segwit BIP9 remain native facts, not Core's newer
/// deployment model. This read never changes validation rules.
pub fn deployment_statuses(
    tree: &BlockTree,
    network: Network,
    block: Option<NodeId>,
) -> Result<Vec<DeploymentStatus>, DeploymentQueryError> {
    let height = block
        .map(|id| tree.node(id).map(|node| node.height))
        .transpose()?
        .unwrap_or(0);
    let next_height = height.saturating_add(1);
    let view = block
        .filter(|_| {
            NAMED_DEPLOYMENTS
                .iter()
                .any(|(_, id)| deployment_params(network, *id).is_some())
        })
        .map(|block| DeploymentView::for_query(tree, block, MAX_DEPLOYMENT_QUERY_ANCESTORS))
        .transpose()?;
    let mut statuses = Vec::with_capacity(6);
    for (name, activation, id) in [
        ("bip34", network.bip34_activation_height(), None),
        ("bip66", network.bip66_activation_height(), None),
        ("bip65", network.bip65_activation_height(), None),
        (
            "csv",
            network.csv_activation_height(),
            Some(CSV_DEPLOYMENT_ID),
        ),
        (
            "segwit",
            network.segwit_activation_height(),
            Some(SEGWIT_DEPLOYMENT_ID),
        ),
        ("taproot", network.taproot_activation_height(), None),
    ] {
        let versionbits =
            id.and_then(|id| deployment_params(network, id).map(|params| (id, params)));
        let Some((id, params)) = versionbits else {
            statuses.push(DeploymentStatus {
                name,
                height: Some(activation),
                active: next_height >= activation,
                active_at_block: height >= activation,
                bip9: None,
            });
            continue;
        };
        let Some(view) = &view else {
            statuses.push(DeploymentStatus {
                name,
                height: None,
                active: false,
                active_at_block: false,
                bip9: Some(VersionBitsStatus {
                    params,
                    state: DeploymentState::Defined,
                    next: DeploymentState::Defined,
                    since: 0,
                    signalling: None,
                }),
            });
            continue;
        };
        let state_at = |height| cached_deployment_state(tree, view, height, id, params);
        let state = state_at(height);
        let next = state_at(next_height);
        // States never return to a previous state. Binary search the first
        // period with this state instead of walking every historical period.
        let mut low = 0;
        let mut high = height / params.period;
        while low < high {
            let mid = low + (high - low) / 2;
            if state_at(mid * params.period) == state {
                high = mid;
            } else {
                low = mid + 1;
            }
        }
        let since = low * params.period;
        let signalling = matches!(state, DeploymentState::Started | DeploymentState::LockedIn)
            .then(|| {
                ((height / params.period) * params.period..=height)
                    .map(|h| view.block_version(h).is_some_and(|v| params.signals(v)))
                    .collect()
            });
        statuses.push(DeploymentStatus {
            name,
            height: if state == DeploymentState::Active {
                Some(since)
            } else {
                (next == DeploymentState::Active).then_some(next_height)
            },
            active: next == DeploymentState::Active,
            active_at_block: state == DeploymentState::Active,
            bip9: Some(VersionBitsStatus {
                params,
                state,
                next,
                since,
                signalling,
            }),
        });
    }
    Ok(statuses)
}

/// Returns whether the BIP30 duplicate-txid scan is required at `height`.
#[must_use]
pub fn bip30_duplicate_scan_required(
    tree: &BlockTree,
    network: Network,
    height: u32,
    previous_tip: Option<NodeId>,
) -> bool {
    if height >= BIP34_IMPLIES_BIP30_LIMIT || !network.is_bip34_active(height) {
        return true;
    }

    let Some(expected_activation_hash) = network.bip34_activation_hash() else {
        return true;
    };
    let Some(previous_tip) = previous_tip else {
        return true;
    };

    let Some(activation_id) =
        tree.node_at_height_from(previous_tip, network.bip34_activation_height())
    else {
        return true;
    };
    let Ok(activation_node) = tree.node(activation_id) else {
        return true;
    };

    activation_node.hash != expected_activation_hash
}

fn deployment_active(
    tree: &BlockTree,
    network: Network,
    previous_tip_id: Option<NodeId>,
    height: u32,
    deployment_id: u32,
) -> Option<bool> {
    let params = deployment_params(network, deployment_id)?;
    let Some(previous_tip_id) = previous_tip_id else {
        return Some(false);
    };
    let ctx = DeploymentView::new(tree, previous_tip_id);
    Some(
        cached_deployment_state(tree, &ctx, height, deployment_id, params)
            == DeploymentState::Active,
    )
}

fn cached_deployment_state(
    tree: &BlockTree,
    ctx: &DeploymentView<'_>,
    height: u32,
    deployment_id: u32,
    params: DeploymentParams,
) -> DeploymentState {
    let period_start = (height / params.period).saturating_mul(params.period);
    if period_start == 0 {
        return compute_state(ctx, height, params);
    }

    let anchor_height = period_start.saturating_sub(1);
    let Some(anchor_node) = ctx.node_at_height(anchor_height) else {
        return compute_state(ctx, height, params);
    };
    if let Some(tag) = tree.cached_bip9_state(anchor_node, deployment_id)
        && let Some(state) = DeploymentState::from_cache_tag(tag)
    {
        return state;
    }

    let state = compute_state(ctx, height, params);
    tree.cache_bip9_state(anchor_node, deployment_id, state.cache_tag());
    state
}

#[cfg(test)]
mod tests {
    use crate::node::NodeStatus;
    use bitcoin_rs_consensus::bip30::BIP34_IMPLIES_BIP30_LIMIT;
    use bitcoin_rs_primitives::{BlockHash, CompactTarget, Hash256, Header, Network};

    use super::softfork_state;
    use crate::BlockTree;

    fn synthetic_header(prev_blockhash: BlockHash, time: u32) -> Header {
        synthetic_header_with_version(prev_blockhash, time, 1)
    }

    fn synthetic_header_with_version(prev_blockhash: BlockHash, time: u32, version: i32) -> Header {
        Header {
            version,
            prev_blockhash,
            merkle_root: Hash256::default(),
            time,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        }
    }

    #[test]
    fn deployment_history_keeps_current_next_since_and_branch_signalling()
    -> Result<(), Box<dyn std::error::Error>> {
        use bitcoin_rs_consensus::DeploymentState::{Active, Defined, LockedIn, Started};
        let mut tree = BlockTree::new();
        let mut ids = Vec::new();
        let mut previous = BlockHash::default();
        for height in 0..=6048 {
            let mut header = synthetic_header_with_version(previous, 1_462_060_800, 0x2000_0001);
            header.nonce = height;
            let id = tree.insert_header(header, NodeStatus::HeaderValid)?;
            previous = tree.node(id)?.hash.into();
            ids.push(id);
        }
        for (height, state, next, since, active_height) in [
            (2015_usize, Defined, Started, 0, None),
            (2016, Started, Started, 2016, None),
            (4031, Started, LockedIn, 2016, None),
            (4032, LockedIn, LockedIn, 4032, None),
            (6047, LockedIn, Active, 4032, Some(6048)),
            (6048, Active, Active, 6048, Some(6048)),
        ] {
            let statuses = super::deployment_statuses(&tree, Network::Mainnet, Some(ids[height]))?;
            let csv = statuses
                .iter()
                .find(|status| status.name == "csv")
                .ok_or("CSV missing")?;
            let bip9 = csv.bip9.as_ref().ok_or("CSV BIP9 missing")?;
            assert_eq!((bip9.state, bip9.next, bip9.since), (state, next, since));
            assert_eq!(csv.height, active_height);
            assert_eq!(csv.active, next == Active);
            if let Some(signals) = &bip9.signalling {
                assert_eq!(signals.len(), height % 2016 + 1);
                assert!(signals.iter().all(|signal| *signal));
            }
        }
        previous = tree.node(ids[2015])?.hash.into();
        let mut fork = ids[2015];
        for height in 2016..=4031 {
            let mut header = synthetic_header_with_version(previous, 1_462_060_800, 0x2000_0000);
            header.nonce = height;
            fork = tree.insert_header(header, NodeStatus::HeaderValid)?;
            previous = tree.node(fork)?.hash.into();
        }
        let indexed = super::DeploymentView::for_query(&tree, fork, 4096)?;
        assert_eq!(indexed.ancestry.as_ref().map(Vec::len), Some(4032));
        assert!(matches!(
            super::DeploymentView::for_query(&tree, fork, 128),
            Err(super::DeploymentQueryError::Budget { limit: 128 })
        ));
        let statuses = super::deployment_statuses(&tree, Network::Mainnet, Some(fork))?;
        let csv = statuses
            .iter()
            .find(|status| status.name == "csv")
            .ok_or("CSV missing")?;
        let bip9 = csv.bip9.as_ref().ok_or("CSV BIP9 missing")?;
        assert_eq!((bip9.state, bip9.next), (Started, Started));
        assert!(
            bip9.signalling
                .as_ref()
                .ok_or("signalling missing")?
                .iter()
                .all(|signal| !signal)
        );
        Ok(())
    }

    fn seed_known_bip34_activation_chain(
        tree: &mut BlockTree,
        network: Network,
    ) -> Result<crate::NodeId, Box<dyn std::error::Error>> {
        let activation_height = network.bip34_activation_height();
        let expected_hash = network
            .bip34_activation_hash()
            .ok_or_else(|| std::io::Error::other("network has no fixed BIP34 activation hash"))?;
        let mut prev_hash = BlockHash::default();
        let mut tip = None;
        let mut activation_id = None;
        for height in 0..=activation_height.saturating_add(1) {
            let header = synthetic_header(prev_hash, height);
            // The activation header must enter the index under its
            // authenticated hash; mutating afterwards would leave the child
            // prev_blockhash and the by_hash key pointing at a discarded hash.
            let node_id = if height == activation_height {
                tree.insert_header_with_hash(header, expected_hash, NodeStatus::HeaderValid)?
            } else {
                tree.insert_header(header, NodeStatus::HeaderValid)?
            };
            if height == activation_height {
                activation_id = Some(node_id);
            }
            prev_hash = BlockHash::from(tree.node(node_id)?.hash);
            tip = Some(node_id);
        }
        activation_id.ok_or_else(|| std::io::Error::other("missing activation node"))?;
        tip.ok_or_else(|| std::io::Error::other("missing previous tip").into())
    }

    #[test]
    fn bip30_skips_duplicate_scan_after_known_bip34_activation()
    -> Result<(), Box<dyn std::error::Error>> {
        let network = Network::Testnet3;
        let height = network
            .bip34_activation_height()
            .checked_add(1)
            .ok_or_else(|| std::io::Error::other("activation height overflow"))?;
        let mut tree = BlockTree::new();
        let previous_tip = seed_known_bip34_activation_chain(&mut tree, network)?;
        // The child of the activation header must commit to the authenticated
        // hash, not to a pre-mutation synthetic hash.
        let expected = network
            .bip34_activation_hash()
            .ok_or_else(|| std::io::Error::other("network has no fixed BIP34 activation hash"))?;
        let child_id = tree
            .node_at_height_from(previous_tip, height)
            .ok_or_else(|| std::io::Error::other("seeded child missing"))?;
        assert_eq!(
            tree.node(child_id)?.header.prev_blockhash,
            BlockHash::from(expected),
            "activation child must point at the authenticated activation hash"
        );
        assert!(
            !super::bip30_duplicate_scan_required(&tree, network, height, Some(previous_tip)),
            "known BIP34 activation must skip the duplicate scan"
        );
        Ok(())
    }

    #[test]
    fn bip30_duplicate_scan_runs_without_known_bip34_activation_hash()
    -> Result<(), Box<dyn std::error::Error>> {
        let network = Network::Regtest;
        let height = network
            .bip34_activation_height()
            .checked_add(1)
            .ok_or_else(|| std::io::Error::other("activation height overflow"))?;

        assert!(super::bip30_duplicate_scan_required(
            &BlockTree::new(),
            network,
            height,
            None,
        ));
        Ok(())
    }

    #[test]
    fn bip30_duplicate_scan_runs_at_core_recheck_limit() {
        assert!(super::bip30_duplicate_scan_required(
            &BlockTree::new(),
            Network::Mainnet,
            BIP34_IMPLIES_BIP30_LIMIT,
            None,
        ));
    }

    #[test]
    fn mainnet_csv_activation_matches_consensus_thresholds()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let tip = append_chain(&mut tree, 6048, 1_462_060_800, |height| {
            if (2016..3932).contains(&height) {
                0x2000_0001
            } else {
                0x2000_0000
            }
        })?;

        let state = softfork_state(&tree, Network::Mainnet, Some(tip), 6048);

        assert!(state.csv_active);
        assert!(!state.segwit_active);
        Ok(())
    }

    #[test]
    fn testnet3_segwit_activation_matches_consensus_thresholds()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let tip = append_chain(&mut tree, 6048, 1_462_060_800, |height| {
            if (2016..3528).contains(&height) {
                0x2000_0002
            } else {
                0x2000_0000
            }
        })?;

        let state = softfork_state(&tree, Network::Testnet3, Some(tip), 6048);

        assert!(!state.csv_active);
        assert!(state.segwit_active);
        Ok(())
    }

    fn append_chain(
        tree: &mut BlockTree,
        len: u32,
        start_time: u32,
        version_at: impl Fn(u32) -> i32,
    ) -> Result<crate::NodeId, Box<dyn std::error::Error>> {
        let mut prev = BlockHash::default();
        let mut tip = None;
        for height in 0..len {
            let header = synthetic_header_with_version(
                prev,
                start_time.saturating_add(height.saturating_mul(600)),
                version_at(height),
            );
            prev = header.compute_hash();
            tip = Some(tree.insert_header(header, NodeStatus::HeaderValid)?);
        }
        let Some(tip) = tip else {
            panic!("synthetic chain length must be non-zero");
        };
        Ok(tip)
    }
}
