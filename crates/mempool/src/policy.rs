use crate::standardness::StandardnessPolicy;

use thiserror::Error;

/// Mempool cluster, replacement, and capacity limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MempoolLimits {
    /// Maximum distinct clusters containing direct replacement conflicts.
    pub max_replacement_clusters: u32,
    /// Maximum total mempool size in vbytes. The selected limit is 300,000,000;
    /// Core limits allocator usage rather than this virtual-size sum.
    /// Set to 0 to disable size-bound eviction.
    pub max_total_bytes: u64,
    /// Minimum relay fee rate in sat/kvB. Transactions with lower `fee_rate` are
    /// not relayed. Selected default: 1000 sat/kvB = 1 sat/vB.
    pub min_relay_fee_sat_per_kvb: u64,
    /// Maximum number of transactions in one cluster, including the candidate.
    ///
    /// A cluster is the set of mempool transactions directly or indirectly
    /// connected to a transaction through spends -- a connected component of
    /// the spend graph, not an ancestor package. Two children of one parent
    /// share a cluster although neither is an ancestor of the other.
    ///
    /// Core's `-limitclustercount`, `DEFAULT_CLUSTER_LIMIT` (`policy.h`).
    pub cluster_count: u32,
    /// Maximum virtual size of one cluster in vbytes, including the candidate.
    ///
    /// Core's `-limitclustersize`, `DEFAULT_CLUSTER_SIZE_LIMIT_KVB * 1000`
    /// (`policy.h`, `kernel/mempool_limits.h`).
    pub cluster_size_vbytes: u64,
}

impl Default for MempoolLimits {
    fn default() -> Self {
        Self {
            max_replacement_clusters: 100,
            max_total_bytes: 300_000_000,
            min_relay_fee_sat_per_kvb: 1_000,
            cluster_count: 64,
            cluster_size_vbytes: 101_000,
        }
    }
}

/// Policy rejection reason for non-consensus mempool limits.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PolicyError {
    /// The caller supplied no positive policy size.
    #[error("invalid transaction virtual size")]
    InvalidVirtualSize,
    /// Fee-policy arithmetic exceeds the supported monetary representation.
    #[error("fee policy arithmetic overflow")]
    FeeArithmetic,
    /// Transaction's `fee_rate` is below the configured min-relay-fee floor.
    #[error("fee rate {tx_rate} sat/kvB below min-relay-fee {min_rate} sat/kvB")]
    BelowMinRelayFee {
        /// The transaction's effective `fee_rate` in sat/kvB.
        tx_rate: u64,
        /// The configured min-relay-fee floor.
        min_rate: u64,
    },
    /// The transaction would join a cluster holding too many transactions.
    #[error("too many transactions in cluster")]
    ClusterCountLimit,
    /// The transaction would join a cluster exceeding the virtual size limit.
    #[error("cluster is too large")]
    ClusterSizeLimit,
}

/// Fee-rate increment the eviction-floor projection and BIP125 rule 4 quote,
/// in sat/kvB. The selected rate is 1,000 sat/kvB; Core 31.1's default is 100.
pub const DEFAULT_INCREMENTAL_RELAY_FEE_SAT_PER_KVB: u64 = 1_000;

/// Typed snapshot of the mempool relay-policy surface the RPC
/// `getmempoolinfo` response projects, built from the policy the pool
/// actually enforces.
///
/// Every field traces to an enforcement site or is a recorded deviation (the
/// `getmempoolinfo` manifest row carries the ledger). The RPC layer consumes
/// this record verbatim and holds no policy literals of its own, so the
/// response cannot disagree with the running pool.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MempoolPolicySnapshot {
    /// Standardness settings admission enforces through `is_standard_tx`:
    /// the dust relay rate and the aggregate nulldata byte budget.
    pub standardness: StandardnessPolicy,
    /// Bare multisig outputs pass `is_standard_tx` (the standardness check
    /// accepts up to 3-key bare multisig and has no opt-out), so the v31
    /// `permitbaremultisig` field reports the enforced `true`.
    pub permit_bare_multisig: bool,
    /// Enforced cluster count bound (`PolicyError::ClusterCountLimit`).
    /// The v31 `limitclustercount` field projects this — the limit admission
    /// actually applies, not the ancestor-package cap.
    pub cluster_count: u32,
    /// Enforced cluster virtual-size bound in vbytes
    /// (`PolicyError::ClusterSizeLimit`). The v31 `limitclustersize` field
    /// projects this.
    pub cluster_size_vbytes: u64,
    /// Fee-rate increment the eviction-floor projection and BIP125 rule 4
    /// (`RbfError::Rule4InsufficientIncrementalFee`) quote, in sat/kvB.
    pub incremental_relay_fee_sat_per_kvb: u64,
    /// Replacements do not require BIP125 signaling, so this is always
    /// `true`. Other replacement policy differences remain under #639.
    pub full_rbf: bool,
    /// The graph owner computes exact optimal chunks for immutable snapshots.
    /// This reports true rather than emulating Core's background SFL state;
    /// that work-budget difference remains in the compatibility manifest.
    pub optimal: bool,
}

impl MempoolPolicySnapshot {
    /// Builds the snapshot from the policy a pool enforces: its configured
    /// [`MempoolLimits`] and the enforced [`StandardnessPolicy`].
    #[must_use]
    pub fn from_enforced(limits: MempoolLimits, standardness: StandardnessPolicy) -> Self {
        Self {
            standardness,
            permit_bare_multisig: true,
            cluster_count: limits.cluster_count,
            cluster_size_vbytes: limits.cluster_size_vbytes,
            incremental_relay_fee_sat_per_kvb: DEFAULT_INCREMENTAL_RELAY_FEE_SAT_PER_KVB,
            full_rbf: true,
            optimal: true,
        }
    }

    /// The v31 `maxdatacarriersize` projection: the enforced aggregate
    /// nulldata byte budget. A disabled nulldata policy permits zero bytes,
    /// so it projects as `0` rather than pretending the default budget is
    /// still in force.
    #[must_use]
    pub fn max_data_carrier_size(&self) -> u64 {
        self.standardness
            .max_datacarrier_bytes
            .map_or(0, |bytes| u64::try_from(bytes).unwrap_or(u64::MAX))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_snapshot_projects_the_enforced_defaults() {
        let snapshot = MempoolPolicySnapshot::from_enforced(
            MempoolLimits::default(),
            StandardnessPolicy::default(),
        );
        assert!(snapshot.permit_bare_multisig);
        assert_eq!(snapshot.max_data_carrier_size(), 83);
        assert_eq!(snapshot.cluster_count, 64);
        assert_eq!(snapshot.cluster_size_vbytes, 101_000);
        assert_eq!(snapshot.incremental_relay_fee_sat_per_kvb, 1_000);
        assert!(snapshot.full_rbf);
        assert!(snapshot.optimal);
    }

    #[test]
    fn configured_limits_flow_into_the_cluster_projections() {
        let snapshot = MempoolPolicySnapshot::from_enforced(
            MempoolLimits {
                cluster_count: 7,
                cluster_size_vbytes: 42_000,
                ..MempoolLimits::default()
            },
            StandardnessPolicy::default(),
        );
        assert_eq!(snapshot.cluster_count, 7);
        assert_eq!(snapshot.cluster_size_vbytes, 42_000);
    }

    #[test]
    fn disabled_nulldata_projects_a_zero_carrier_budget() {
        let snapshot = MempoolPolicySnapshot::from_enforced(
            MempoolLimits::default(),
            StandardnessPolicy {
                max_datacarrier_bytes: None,
                ..StandardnessPolicy::default()
            },
        );
        assert_eq!(snapshot.max_data_carrier_size(), 0);
    }
}
