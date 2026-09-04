use crate::standardness::StandardnessPolicy;

use thiserror::Error;

/// Mempool ancestor, descendant, cluster, and replacement limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MempoolLimits {
    /// Maximum number of transactions in an ancestor package, including the transaction itself.
    pub max_ancestors: u32,
    /// Maximum ancestor package virtual size in vbytes.
    pub max_ancestor_size: u64,
    /// Maximum number of transactions in a descendant package, including the transaction itself.
    pub max_descendants: u32,
    /// Maximum number of transactions a single BIP125 replacement may evict.
    pub max_replacement_evictions: u32,
    /// Maximum total mempool size in vbytes. Default 300 MB (Bitcoin Core default).
    /// Set to 0 to disable size-bound eviction.
    pub max_total_bytes: u64,
    /// Minimum relay fee rate in sat/kvB. Transactions with lower `fee_rate` are
    /// not relayed. Default 1000 sat/kvB = 1 sat/vB (Bitcoin Core default).
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
            max_ancestors: 25,
            max_ancestor_size: 101_000,
            max_descendants: 25,
            max_replacement_evictions: 100,
            max_total_bytes: 300_000_000,
            min_relay_fee_sat_per_kvb: 1_000,
            cluster_count: 64,
            // 101 kvB, the same number `max_ancestor_size` carries. The
            // coincidence is why ancestor limits look like a stand-in for
            // cluster limits and are not one: Core 31 deprecated
            // `-limitancestorcount`/`-limitdescendantcount` and replaced them
            // with these, keeping the old ones only for wallet coin selection.
            cluster_size_vbytes: 101_000,
        }
    }
}

/// Policy rejection reason for non-consensus mempool limits.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PolicyError {
    /// The transaction would exceed the configured ancestor count limit.
    #[error("too many unconfirmed ancestors")]
    TooManyAncestors,
    /// Transaction's `fee_rate` is below the configured min-relay-fee floor.
    #[error("fee rate {tx_rate} sat/kvB below min-relay-fee {min_rate} sat/kvB")]
    BelowMinRelayFee {
        /// The transaction's effective `fee_rate` in sat/kvB.
        tx_rate: u64,
        /// The configured min-relay-fee floor.
        min_rate: u64,
    },
    /// The transaction would exceed the configured ancestor package size limit.
    #[error("ancestor package is too large")]
    AncestorSizeLimit,
    /// The transaction would exceed a configured descendant count limit.
    #[error("too many unconfirmed descendants")]
    TooManyDescendants,
    /// The transaction would join a cluster holding too many transactions.
    #[error("too many transactions in cluster")]
    ClusterCountLimit,
    /// The transaction would join a cluster exceeding the virtual size limit.
    #[error("cluster is too large")]
    ClusterSizeLimit,
}

/// Fee-rate increment the eviction-floor projection and BIP125 rule 4 quote,
/// in sat/kvB. Bitcoin Core's `-incrementalrelayfee` default:
/// 1 000 sat/kvB = 1 sat/vB.
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
    /// BIP125 rule 1 is enforced (`RbfError::Rule1NoOptIn`): a replacement
    /// must signal replaceability, matching Core's default `-fullrbf=false`.
    /// The pool has no full-rbf mode, so this is always `false`.
    pub full_rbf: bool,
    /// The pool rewrites its fee-rate index in the same critical section as
    /// every mutation, so no stale-ordering window exists and the v31
    /// `optimal` field is always `true` — a recorded deviation from Core's
    /// churn-sensitive cluster-linearization flag.
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
            full_rbf: false,
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
        // BIP125 rule 1 (opt-in signaling) is enforced: the pool is not
        // full-rbf, so the projection must not fabricate `true`.
        assert!(!snapshot.full_rbf);
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
