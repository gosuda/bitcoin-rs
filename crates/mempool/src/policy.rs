use crate::standardness::StandardnessPolicy;

use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MempoolLimits {
    /// Maximum distinct clusters containing direct replacement conflicts.
    pub max_replacement_clusters: u32,
    /// Set to 0 to disable size-bound eviction.
    pub max_total_bytes: u64,
    pub min_relay_fee_sat_per_kvb: u64,
    /// Maximum number of transactions in one cluster, including the candidate.
    pub cluster_count: u32,
    /// Maximum virtual size of one cluster in vbytes, including the candidate.
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
    BelowMinRelayFee { tx_rate: u64, min_rate: u64 },
    #[error("too many transactions in cluster")]
    ClusterCountLimit,
    #[error("cluster is too large")]
    ClusterSizeLimit,
}

pub(crate) const DEFAULT_INCREMENTAL_RELAY_FEE_SAT_PER_KVB: u64 = 1_000;
pub(crate) const ROLLING_FEE_HALFLIFE_SECS: u64 = 12 * 60 * 60;

pub(crate) const MEMPOOL_EXPIRY_SECS: u64 = 336 * 60 * 60;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MempoolPolicySnapshot {
    pub standardness: StandardnessPolicy,
    pub permit_bare_multisig: bool,
    pub cluster_count: u32,
    pub cluster_size_vbytes: u64,
    pub incremental_relay_fee_sat_per_kvb: u64,
    /// Replacements do not require BIP125 signaling, so this is always `true`.
    pub full_rbf: bool,
    /// The graph owner computes exact optimal chunks for immutable snapshots.
    pub optimal: bool,
}

impl MempoolPolicySnapshot {
    #[must_use]
    pub(crate) fn from_enforced(limits: MempoolLimits, standardness: StandardnessPolicy) -> Self {
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
    fn enforced_cluster_count_rejects_a_joining_transaction() {
        use alloc::sync::Arc;

        use bitcoin_rs_consensus::ValidationEngine;
        use bitcoin_rs_primitives::{
            Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
        };
        use parking_lot::RwLock;

        use crate::{AdmissionOrigin, Mempool, MempoolEntry, MempoolError, MempoolGateway};

        fn tx_with(inputs: &[OutPoint], outputs: u32, tag: u64) -> Tx {
            Tx {
                version: 2,
                lock_time: LockTime::ZERO,
                inputs: inputs
                    .iter()
                    .map(|previous_output| TxIn {
                        previous_output: *previous_output,
                        script_sig: Script::new(),
                        sequence: Sequence::MAX,
                        witness: Witness::new(),
                    })
                    .collect(),
                outputs: (0..outputs)
                    .map(|vout| TxOut {
                        value: Amount::from_sat(
                            10_000_u64
                                .saturating_add(u64::from(vout))
                                .saturating_add(tag.saturating_mul(1_000)),
                        ),
                        script_pubkey: alloc::vec![0x51].into(),
                    })
                    .collect(),
            }
        }

        let gateway = MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits {
                cluster_count: 2,
                ..MempoolLimits::default()
            }))),
            None,
            ValidationEngine::Native,
            None,
        );
        let admit = |tx: Tx| {
            gateway.insert_entry(
                AdmissionOrigin::Rpc,
                MempoolEntry::new(Arc::new(tx), 100, 10_000, 1, 7, 0),
            )
        };

        let confirmed = OutPoint::new(Txid::from(Hash256::from_le_bytes(&[9_u8; 32])), 0);
        let root = tx_with(&[confirmed], 2, 1);
        let root_txid = root.txid();
        assert!(admit(root).is_ok(), "the root fits in an empty cluster");
        assert!(
            admit(tx_with(&[OutPoint::new(root_txid, 0)], 1, 2)).is_ok(),
            "the first sibling fits a limit of two"
        );

        let refused = admit(tx_with(&[OutPoint::new(root_txid, 1)], 1, 3));
        assert!(
            matches!(
                refused,
                Err(MempoolError::Policy(PolicyError::ClusterCountLimit))
            ),
            "the joining child must be refused on cluster count: {refused:?}"
        );
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
