//! Bounded, cancellable reads of the authoritative UTXO set.
//!
//! The reservation belongs to the set, including across snapshot replacement.
//! No coins or scan state are persisted here. A dropped reservation is idle.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use bitcoin_rs_primitives::{Amount, OutPoint, TxOut};
use parking_lot::Mutex;

use crate::{UtxoCoin, UtxoScan, UtxoSet};

/// Maximum number of distinct script needles in one scan.
pub const MAX_SCAN_SCRIPTS: usize = 1_024;
/// Maximum combined script bytes in one scan.
pub const MAX_SCAN_SCRIPT_BYTES: usize = 1_048_576;
const MAX_VISITED_COINS: usize = 250_000_000;
const MAX_MATCHES: usize = 10_000;
const MAX_MATCH_SCRIPT_BYTES: usize = 8 * 1_048_576;
const MAX_DURATION: Duration = Duration::from_secs(60);
const CHECK_INTERVAL: usize = 256;

/// A scan cannot acquire its reservation or exceeds an explicit work budget.
#[derive(Debug, thiserror::Error)]
pub enum UtxoScanError {
    /// The same authoritative set already has a reserved scan.
    #[error("Scan already in progress, use action \"abort\" or \"status\"")]
    InProgress,
    /// An enforced bound was reached; no complete result is claimed.
    #[error("UTXO scan limit exceeded: {0}")]
    Limit(&'static str),
    /// A caller of the legacy complete-scan API was interrupted.
    #[error("UTXO scan aborted")]
    Aborted,
}

#[derive(Default)]
pub(crate) struct ScanState(Mutex<Option<Progress>>);

struct Progress {
    percent: u8,
    abort: bool,
}

impl ScanState {
    pub(crate) fn reserve(&self) -> Result<(), UtxoScanError> {
        let mut state = self.0.lock();
        if state.is_some() {
            return Err(UtxoScanError::InProgress);
        }
        *state = Some(Progress {
            percent: 0,
            abort: false,
        });
        Ok(())
    }

    pub(crate) fn status(&self) -> Option<u8> {
        self.0.lock().as_ref().map(|progress| progress.percent)
    }

    pub(crate) fn abort(&self) -> bool {
        let mut state = self.0.lock();
        let Some(progress) = state.as_mut() else {
            return false;
        };
        progress.abort = true;
        true
    }
}

/// Exclusive transient reservation for a scan of one authoritative set.
///
/// The caller must also exclude chain transitions while collecting the tip
/// and coins. This guard controls resource use, not chain publication.
pub struct UtxoScanPermit<'a> {
    set: &'a UtxoSet,
    started: Instant,
}

impl<'a> UtxoScanPermit<'a> {
    pub(crate) fn reserve(set: &'a UtxoSet) -> Result<Self, UtxoScanError> {
        set.scan.reserve()?;
        Ok(Self {
            set,
            started: Instant::now(),
        })
    }

    /// Checks abort/shutdown and the total 60-second reservation budget.
    /// The predicate is called without holding the scan-state mutex.
    pub fn cancelled(&self, stopping: impl FnOnce() -> bool) -> Result<bool, UtxoScanError> {
        let abort = self.set.scan.0.lock().as_ref().is_some_and(|p| p.abort);
        if abort || stopping() {
            return Ok(true);
        }
        if self.started.elapsed() >= MAX_DURATION {
            return Err(UtxoScanError::Limit("60 seconds"));
        }
        Ok(false)
    }

    /// Visits a stable view, returning false with partial results on abort.
    ///
    /// Script matching is logarithmic in the bounded needle set. Traversal
    /// stops before exceeding 250 million coins, 10,000 matches or 8 MiB of
    /// matched scripts. Abort/deadline checks occur every 256 coins and between
    /// shards. No write lock or durable mutation is used.
    pub fn scan(
        &self,
        scripts: &BTreeSet<Vec<u8>>,
        stopping: impl Fn() -> bool,
    ) -> Result<(bool, UtxoScan), UtxoScanError> {
        self.scan_bounded(
            scripts,
            stopping,
            MAX_VISITED_COINS,
            MAX_MATCHES,
            MAX_MATCH_SCRIPT_BYTES,
        )
    }

    fn scan_bounded(
        &self,
        scripts: &BTreeSet<Vec<u8>>,
        stopping: impl Fn() -> bool,
        max_coins: usize,
        max_matches: usize,
        max_bytes: usize,
    ) -> Result<(bool, UtxoScan), UtxoScanError> {
        if scripts.len() > MAX_SCAN_SCRIPTS {
            return Err(UtxoScanError::Limit("1024 scripts"));
        }
        if scripts
            .iter()
            .try_fold(0usize, |n, script| n.checked_add(script.len()))
            .is_none_or(|n| n > MAX_SCAN_SCRIPT_BYTES)
        {
            return Err(UtxoScanError::Limit("1 MiB of scripts"));
        }
        let mut scan = UtxoScan::default();
        let view = loop {
            if self.cancelled(&stopping)? {
                return Ok((false, scan));
            }
            if let Some(view) = self.set.try_stable_view(Duration::from_millis(50)) {
                break view;
            }
        };
        let mut script_bytes = 0usize;
        for (index, shard) in self.set.shards.iter().enumerate() {
            if self.cancelled(&stopping)? {
                return Ok((false, scan));
            }
            let complete = shard.with_table(|table| -> Result<bool, UtxoScanError> {
                for record in &table.table {
                    for output in record.outputs() {
                        if scan.txouts.is_multiple_of(CHECK_INTERVAL)
                            && self.cancelled(&stopping)?
                        {
                            return Ok(false);
                        }
                        if scan.txouts == max_coins {
                            return Err(UtxoScanError::Limit("250 million visited coins"));
                        }
                        scan.txouts += 1;
                        if scripts.contains(output.script_pubkey) {
                            if scan.unspents.len() == max_matches {
                                return Err(UtxoScanError::Limit("10000 matched coins"));
                            }
                            script_bytes += output.script_pubkey.len();
                            if script_bytes > max_bytes {
                                return Err(UtxoScanError::Limit("8 MiB of matched scripts"));
                            }
                            scan.unspents.push(UtxoCoin {
                                outpoint: OutPoint::new(record.txid().into(), output.vout),
                                txout: TxOut {
                                    value: Amount::from_sat(output.value),
                                    script_pubkey: output.script_pubkey.to_vec().into(),
                                },
                                coinbase: output.coinbase,
                                height: output.height,
                            });
                        }
                    }
                }
                Ok(true)
            })?;
            if !complete {
                return Ok((false, scan));
            }
            if let Some(progress) = self.set.scan.0.lock().as_mut() {
                progress.percent =
                    u8::try_from((index + 1) * 100 / self.set.shards.len()).unwrap_or(100);
            }
        }
        drop(view);
        Ok((true, scan))
    }
}

impl Drop for UtxoScanPermit<'_> {
    fn drop(&mut self) {
        *self.set.scan.0.lock() = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::UtxoReader;
    use crate::contract::{BlockChanges, UtxoAdd, commit_block_changes};
    use bitcoin_rs_primitives::{Hash256, Txid};
    use std::cell::Cell;
    use std::sync::Arc;

    fn coins(count: u32) -> Arc<UtxoSet> {
        let set = Arc::new(UtxoSet::new());
        let mut changes = BlockChanges::default();
        for i in 0..count {
            let mut bytes = [0u8; 32];
            bytes[1..5].copy_from_slice(&i.to_le_bytes());
            changes.add(UtxoAdd::new(
                OutPoint::new(Txid::from(Hash256::from_le_bytes(&bytes)), 0),
                TxOut {
                    value: Amount::from_sat(7),
                    script_pubkey: vec![0x51].into(),
                },
                false,
                0,
            ));
        }
        commit_block_changes(&set, &changes, &Hash256::default())
            .unwrap_or_else(|error| panic!("fixture coins: {error}"));
        set
    }

    #[test]
    fn reservation_is_shared_and_drop_clears_abort() {
        let reader = UtxoReader::new(coins(1));
        let other = reader.clone();
        assert_eq!(reader.scan_progress(), None);
        assert!(!reader.abort_scan());
        let permit = reader
            .reserve_scan()
            .unwrap_or_else(|error| panic!("reserve: {error}"));
        assert_eq!(other.scan_progress(), Some(0));
        assert!(matches!(
            other.reserve_scan(),
            Err(UtxoScanError::InProgress)
        ));
        assert!(other.abort_scan());
        let (complete, scan) = permit
            .scan(&BTreeSet::new(), || false)
            .unwrap_or_else(|error| panic!("cancel: {error}"));
        assert!(!complete);
        assert_eq!(scan.txouts, 0);
        drop(permit);
        assert_eq!(other.scan_progress(), None);
        let next = other
            .reserve_scan()
            .unwrap_or_else(|error| panic!("new reservation: {error}"));
        assert!(
            !next
                .cancelled(|| false)
                .unwrap_or_else(|error| panic!("clean state: {error}"))
        );
        assert_eq!(
            UtxoReader::new(coins(0)).scan_progress(),
            None,
            "restart has no scan"
        );
    }

    #[test]
    fn snapshot_replacement_does_not_create_a_second_scan_owner() {
        let set = coins(1);
        let reader = UtxoReader::new(Arc::clone(&set));
        let permit = reader
            .reserve_scan()
            .unwrap_or_else(|error| panic!("reserve: {error}"));
        set.replace_from(UtxoSet::new());
        assert_eq!(reader.scan_progress(), Some(0));
        assert!(matches!(
            reader.reserve_scan(),
            Err(UtxoScanError::InProgress)
        ));
        let (complete, scan) = permit
            .scan(&BTreeSet::new(), || false)
            .unwrap_or_else(|error| panic!("new stable coins: {error}"));
        assert!(complete);
        assert_eq!(scan.txouts, 0);
    }

    #[test]
    fn unwind_releases_the_reservation() {
        let reader = UtxoReader::new(coins(1));
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let permit = reader
                .reserve_scan()
                .unwrap_or_else(|error| panic!("reserve: {error}"));
            let _ = permit.scan(&BTreeSet::new(), || panic!("interrupted caller"));
        }));
        assert!(outcome.is_err());
        assert_eq!(reader.scan_progress(), None);
        assert!(!reader.abort_scan());
    }

    #[test]
    fn abort_during_traversal_returns_only_visited_matches() {
        let reader = UtxoReader::new(coins(1_024));
        let permit = reader
            .reserve_scan()
            .unwrap_or_else(|error| panic!("reserve: {error}"));
        let checks = Cell::new(0usize);
        let (complete, scan) = permit
            .scan(&BTreeSet::from([vec![0x51]]), || {
                checks.set(checks.get() + 1);
                checks.get() == 5
            })
            .unwrap_or_else(|error| panic!("bounded cancellation: {error}"));
        assert!(!complete);
        assert_eq!(scan.txouts, 512);
        assert_eq!(scan.unspents.len(), 512);
    }

    #[test]
    fn traversal_match_and_payload_bounds_fail_without_complete_results() {
        let reader = UtxoReader::new(coins(4));
        let permit = reader
            .reserve_scan()
            .unwrap_or_else(|error| panic!("reserve: {error}"));
        let scripts = BTreeSet::from([vec![0x51]]);
        for (coins, matches, bytes) in [(3, 4, 4), (4, 3, 4), (4, 4, 3)] {
            assert!(matches!(
                permit.scan_bounded(&scripts, || false, coins, matches, bytes),
                Err(UtxoScanError::Limit(_))
            ));
        }
        let (complete, scan) = permit
            .scan_bounded(&scripts, || false, 4, 4, 4)
            .unwrap_or_else(|error| panic!("inclusive budget: {error}"));
        assert!(complete);
        assert_eq!(scan.txouts, 4);
        assert_eq!(scan.unspents.len(), 4);
    }

    #[test]
    fn needle_and_deadline_bounds_apply_before_traversal() {
        let reader = UtxoReader::new(coins(1));
        let mut permit = reader
            .reserve_scan()
            .unwrap_or_else(|error| panic!("reserve: {error}"));
        let scripts = (0..=MAX_SCAN_SCRIPTS)
            .map(|n| n.to_le_bytes().to_vec())
            .collect();
        assert!(matches!(
            permit.scan(&scripts, || false),
            Err(UtxoScanError::Limit(_))
        ));
        let scripts = BTreeSet::from([vec![0u8; MAX_SCAN_SCRIPT_BYTES + 1]]);
        assert!(matches!(
            permit.scan(&scripts, || false),
            Err(UtxoScanError::Limit(_))
        ));
        permit.started = Instant::now()
            .checked_sub(MAX_DURATION)
            .unwrap_or_else(|| panic!("monotonic clock has no prior instant"));
        assert!(matches!(
            permit.cancelled(|| false),
            Err(UtxoScanError::Limit(_))
        ));
        assert!(
            permit
                .cancelled(|| true)
                .unwrap_or_else(|error| panic!("shutdown takes precedence: {error}"))
        );
    }
}
