use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use bitcoin_rs_consensus::primitives::{Amount, OutPoint, TxOut};
use parking_lot::Mutex;

use crate::utxo::record::UtxoRecord;
use crate::utxo::{UtxoCoin, UtxoScan, UtxoSet};
use crate::{ColumnFamily, KvSnapshot, StorageError};

pub const MAX_SCAN_SCRIPTS: usize = 1_024;
pub const MAX_SCAN_SCRIPT_BYTES: usize = 1_048_576;
const MAX_VISITED_COINS: usize = 250_000_000;
const MAX_MATCHES: usize = 10_000;
const MAX_MATCH_SCRIPT_BYTES: usize = 8 * 1_048_576;
const MAX_DURATION: Duration = Duration::from_secs(60);
const CHECK_INTERVAL: usize = 256;

#[derive(Debug, thiserror::Error)]
pub enum UtxoScanError {
    #[error("Scan already in progress, use action \"abort\" or \"status\"")]
    InProgress,
    #[error("UTXO scan limit exceeded: {0}")]
    Limit(&'static str),
    #[error("UTXO scan aborted")]
    Aborted,
    #[error("UTXO coin row is unreadable: {0}")]
    Corrupt(String),
}

fn validate_scan_scripts(scripts: &BTreeSet<Vec<u8>>) -> Result<(), UtxoScanError> {
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
    Ok(())
}

fn percent_complete(rows_seen: usize, total_rows: usize) -> u8 {
    let seen = u64::try_from(rows_seen).unwrap_or(u64::MAX);
    let total = u64::try_from(total_rows).unwrap_or(u64::MAX).max(1);
    u8::try_from(seen.saturating_mul(100) / total).unwrap_or(100)
}

fn snapshot_error(error: StorageError) -> UtxoScanError {
    UtxoScanError::Corrupt(error.to_string())
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

    #[must_use]
    pub fn aborted(&self) -> bool {
        self.set
            .scan
            .0
            .lock()
            .as_ref()
            .is_some_and(|progress| progress.abort)
    }

    pub fn cancelled(&self, stopping: impl FnOnce() -> bool) -> Result<bool, UtxoScanError> {
        if self.aborted() || stopping() {
            return Ok(true);
        }
        if self.started.elapsed() >= MAX_DURATION {
            return Err(UtxoScanError::Limit("60 seconds"));
        }
        Ok(false)
    }

    /// Streams one engine snapshot of the `coins` keyspace.
    ///
    /// Rows are decoded one at a time and only matched coins are retained, so
    /// memory stays O(matches), never O(UTXO set). The snapshot is a
    /// point-in-time image: commits landing after it was taken stay invisible,
    /// so the walk agrees with the applied head captured beside it.
    pub fn scan_snapshot(
        &self,
        snapshot: &dyn KvSnapshot,
        scripts: &BTreeSet<Vec<u8>>,
        stopping: impl Fn() -> bool,
    ) -> Result<(bool, UtxoScan), UtxoScanError> {
        self.scan_snapshot_bounded(
            snapshot,
            scripts,
            stopping,
            MAX_VISITED_COINS,
            MAX_MATCHES,
            MAX_MATCH_SCRIPT_BYTES,
        )
    }

    /// Counts the snapshot rows first so progress percentages are exact.
    ///
    /// `None` means the caller aborted or the deadline expired mid-count.
    fn count_coin_rows(
        &self,
        snapshot: &dyn KvSnapshot,
        stopping: &impl Fn() -> bool,
    ) -> Result<Option<usize>, UtxoScanError> {
        let rows = snapshot
            .iter_prefix(ColumnFamily::Coins, &[])
            .map_err(snapshot_error)?;
        let mut total = 0usize;
        for row in rows {
            if total.is_multiple_of(CHECK_INTERVAL) && self.cancelled(stopping)? {
                return Ok(None);
            }
            row.map_err(snapshot_error)?;
            total += 1;
        }
        Ok(Some(total))
    }

    fn scan_snapshot_bounded(
        &self,
        snapshot: &dyn KvSnapshot,
        scripts: &BTreeSet<Vec<u8>>,
        stopping: impl Fn() -> bool,
        max_coins: usize,
        max_matches: usize,
        max_bytes: usize,
    ) -> Result<(bool, UtxoScan), UtxoScanError> {
        validate_scan_scripts(scripts)?;
        let mut scan = UtxoScan::default();
        let Some(total_rows) = self.count_coin_rows(snapshot, &stopping)? else {
            return Ok((false, scan));
        };
        let rows = snapshot
            .iter_prefix(ColumnFamily::Coins, &[])
            .map_err(snapshot_error)?;
        let mut script_bytes = 0usize;
        let mut rows_seen = 0usize;
        if self.cancelled(&stopping)? {
            return Ok((false, scan));
        }
        for row in rows {
            if rows_seen.is_multiple_of(CHECK_INTERVAL) && self.cancelled(&stopping)? {
                return Ok((false, scan));
            }
            let (_key, value) = row.map_err(snapshot_error)?;
            let record = UtxoRecord::from_encoded(value.into_boxed_slice())
                .map_err(|error| UtxoScanError::Corrupt(error.to_string()))?;
            for output in record.outputs() {
                if scan.txouts.is_multiple_of(CHECK_INTERVAL) && self.cancelled(&stopping)? {
                    return Ok((false, scan));
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
            rows_seen += 1;
            if rows_seen.is_multiple_of(CHECK_INTERVAL) {
                let percent = percent_complete(rows_seen, total_rows);
                if let Some(progress) = self.set.scan.0.lock().as_mut() {
                    progress.percent = percent;
                }
            }
        }
        if let Some(progress) = self.set.scan.0.lock().as_mut() {
            progress.percent = 100;
        }
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
    use crate::utxo::UtxoReader;
    use bitcoin_rs_consensus::primitives::Hash256;

    fn fixture_reader(coin_count: u32) -> UtxoReader {
        let reader = UtxoReader::fixture_new();
        let mut changes = crate::utxo::contract::BlockChanges::default();
        for index in 0..coin_count {
            let mut bytes = [0_u8; 32];
            bytes[1..5].copy_from_slice(&index.to_le_bytes());
            let txid = Hash256::from_le_bytes(&bytes);
            changes.add(crate::utxo::contract::UtxoAdd::new(
                OutPoint::new(txid.into(), 0),
                TxOut {
                    value: Amount::from_sat(7),
                    script_pubkey: vec![0x51].into(),
                },
                false,
                0,
            ));
        }
        reader
            .populate_fixture_coins(&changes)
            .unwrap_or_else(|error| panic!("engine coin write: {error}"));
        reader
    }

    fn coin_snapshot(reader: &UtxoReader) -> Box<dyn crate::KvSnapshot + '_> {
        reader
            .scan_coin_snapshot()
            .unwrap_or_else(|error| panic!("snapshot: {error}"))
    }

    #[test]
    fn snapshot_scan_streams_engine_rows_without_resident_image() {
        let reader = UtxoReader::fixture_new();
        let mut changes = crate::utxo::contract::BlockChanges::default();
        let scripts = [vec![0x51], vec![0x6a], vec![0x51]];
        for (index, script) in scripts.iter().enumerate() {
            let index_u8 = match u8::try_from(index) {
                Ok(index) => index,
                Err(error) => panic!("fixture index fits u8: {error}"),
            };
            let index_u64 = u64::try_from(index)
                .unwrap_or_else(|error| panic!("fixture index fits u64: {error}"));
            let txid = Hash256::from_le_bytes(&{
                let mut bytes = [0_u8; 32];
                bytes[1] = index_u8;
                bytes
            });
            changes.add(crate::utxo::contract::UtxoAdd::new(
                OutPoint::new(txid.into(), 0),
                TxOut {
                    value: Amount::from_sat(10 + index_u64),
                    script_pubkey: script.clone().into(),
                },
                false,
                0,
            ));
        }
        reader
            .populate_fixture_coins(&changes)
            .unwrap_or_else(|error| panic!("engine coin write: {error}"));
        let snapshot = coin_snapshot(&reader);
        let resident_insertions =
            crate::utxo::set::PARSED_RECORD_INSERTIONS.with(|count| count.get());
        let permit = reader
            .reserve_scan()
            .unwrap_or_else(|error| panic!("reserve: {error}"));
        let (complete, scan) = permit
            .scan_snapshot(&*snapshot, &BTreeSet::from([vec![0x51]]), || false)
            .unwrap_or_else(|error| panic!("snapshot scan: {error}"));
        assert!(complete);
        assert_eq!(scan.txouts, 3);
        assert_eq!(
            scan.unspents
                .iter()
                .map(|coin| (coin.outpoint.vout, coin.txout.value.to_sat()))
                .collect::<Vec<_>>(),
            vec![(0, 10), (0, 12)]
        );
        assert_eq!(
            crate::utxo::set::PARSED_RECORD_INSERTIONS.with(|count| count.get()),
            resident_insertions,
            "snapshot scan must not materialize the resident coin image"
        );
    }

    #[test]
    fn snapshot_scan_rejects_undecodable_coin_row() {
        let reader = UtxoReader::fixture_new();
        reader
            .fixture_coin_store()
            .store()
            .put(ColumnFamily::Coins, &[7_u8; 32], &[0xff, 0xff])
            .unwrap_or_else(|error| panic!("corrupt row write: {error}"));
        let snapshot = coin_snapshot(&reader);
        let permit = reader
            .reserve_scan()
            .unwrap_or_else(|error| panic!("reserve: {error}"));
        let error = permit
            .scan_snapshot(&*snapshot, &BTreeSet::new(), || false)
            .err()
            .unwrap_or_else(|| panic!("corrupt row must fail the scan"));
        assert!(matches!(error, UtxoScanError::Corrupt(_)), "{error:?}");
    }

    #[test]
    fn snapshot_scan_input_bounds_are_inclusive_and_release_reservations() {
        let reader = fixture_reader(1);
        let snapshot = coin_snapshot(&reader);
        let permit = reader
            .reserve_scan()
            .unwrap_or_else(|error| panic!("reserve: {error}"));
        let mut scripts: BTreeSet<Vec<u8>> = (0..MAX_SCAN_SCRIPTS - 1)
            .map(|n| n.to_le_bytes().to_vec())
            .collect();
        scripts.insert(vec![0x51]);
        let (complete, scan) = permit
            .scan_snapshot(&*snapshot, &scripts, || false)
            .unwrap_or_else(|error| panic!("inclusive bounds: {error}"));
        assert!(complete);
        assert_eq!(scan.txouts, 1);
        assert_eq!(scan.unspents.len(), 1);
        drop(permit);
        assert_eq!(reader.scan_progress(), None);

        scripts.insert(MAX_SCAN_SCRIPTS.to_le_bytes().to_vec());
        let permit = reader
            .reserve_scan()
            .unwrap_or_else(|error| panic!("reserve: {error}"));
        assert!(matches!(
            permit.scan_snapshot(&*snapshot, &scripts, || false),
            Err(UtxoScanError::Limit(_))
        ));
        drop(permit);
        assert_eq!(reader.scan_progress(), None);

        let permit = reader
            .reserve_scan()
            .unwrap_or_else(|error| panic!("reserve: {error}"));
        let exact = vec![0_u8; MAX_SCAN_SCRIPT_BYTES];
        assert!(
            permit
                .scan_snapshot(&*snapshot, &BTreeSet::from([exact]), || false)
                .is_ok()
        );
        drop(permit);
        assert_eq!(reader.scan_progress(), None);

        let permit = reader
            .reserve_scan()
            .unwrap_or_else(|error| panic!("reserve: {error}"));
        assert!(matches!(
            permit.scan_snapshot(
                &*snapshot,
                &BTreeSet::from([vec![0_u8; MAX_SCAN_SCRIPT_BYTES + 1]]),
                || false
            ),
            Err(UtxoScanError::Limit(_))
        ));
        assert!(matches!(
            permit.scan_snapshot(
                &*snapshot,
                &BTreeSet::from([vec![0_u8; MAX_SCAN_SCRIPT_BYTES], vec![1_u8],]),
                || false
            ),
            Err(UtxoScanError::Limit(_))
        ));
        assert_eq!(reader.scan_progress(), Some(0));
        drop(permit);
        assert_eq!(reader.scan_progress(), None);
        let permit = reader
            .reserve_scan()
            .unwrap_or_else(|error| panic!("reserve: {error}"));
        assert!(
            permit
                .scan_snapshot(&*snapshot, &BTreeSet::from([vec![0x51]]), || false)
                .is_ok()
        );
    }

    #[test]
    fn snapshot_scan_observes_abort_and_deadline() {
        let reader = fixture_reader(1);
        let snapshot = coin_snapshot(&reader);
        let permit = reader
            .reserve_scan()
            .unwrap_or_else(|error| panic!("reserve: {error}"));
        assert!(reader.abort_scan());
        let (complete, scan) = permit
            .scan_snapshot(&*snapshot, &BTreeSet::from([vec![0x51]]), || false)
            .unwrap_or_else(|error| panic!("aborted snapshot scan: {error}"));
        assert!(!complete);
        assert_eq!(scan.txouts, 0);
        drop(permit);
        assert_eq!(reader.scan_progress(), None);

        let mut permit = reader
            .reserve_scan()
            .unwrap_or_else(|error| panic!("reserve: {error}"));
        permit.started = Instant::now()
            .checked_sub(MAX_DURATION)
            .unwrap_or_else(|| panic!("monotonic clock has no prior instant"));
        assert!(matches!(
            permit.scan_snapshot(&*snapshot, &BTreeSet::from([vec![0x51]]), || false),
            Err(UtxoScanError::Limit("60 seconds"))
        ));
        drop(permit);
        assert_eq!(reader.scan_progress(), None);
    }

    #[test]
    fn reservation_is_shared_and_drop_clears_abort() {
        let reader = fixture_reader(1);
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
        let snapshot = coin_snapshot(&reader);
        let (complete, scan) = permit
            .scan_snapshot(&*snapshot, &BTreeSet::new(), || false)
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
            UtxoReader::fixture_new().scan_progress(),
            None,
            "restart has no scan"
        );
    }

    #[test]
    fn unwind_releases_the_reservation() {
        let reader = fixture_reader(1);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let permit = reader
                .reserve_scan()
                .unwrap_or_else(|error| panic!("reserve: {error}"));
            let snapshot = coin_snapshot(&reader);
            let _ = permit.scan_snapshot(&*snapshot, &BTreeSet::new(), || {
                panic!("interrupted caller")
            });
        }));
        assert!(outcome.is_err());
        assert_eq!(reader.scan_progress(), None);
        assert!(!reader.abort_scan());
    }

    #[test]
    fn abort_during_traversal_returns_only_visited_matches() {
        let reader = fixture_reader(512);
        let snapshot = coin_snapshot(&reader);
        let permit = reader
            .reserve_scan()
            .unwrap_or_else(|error| panic!("reserve: {error}"));
        let (complete, scan) = permit
            .scan_snapshot(&*snapshot, &BTreeSet::from([vec![0x51]]), || {
                reader.scan_progress().is_some_and(|percent| percent >= 50)
            })
            .unwrap_or_else(|error| panic!("bounded cancellation: {error}"));
        assert!(!complete);
        assert_eq!(scan.txouts, 256);
        assert_eq!(scan.unspents.len(), 256);
    }

    #[test]
    fn a_reserved_walk_observes_the_scan_abort_flag() {
        let reader = fixture_reader(4);
        let permit = reader
            .reserve_scan()
            .unwrap_or_else(|error| panic!("reserve: {error}"));
        assert!(!permit.aborted());
        assert!(reader.abort_scan());
        assert!(
            permit.aborted(),
            "a walk owner must see the abort that status and abort report"
        );
    }

    #[test]
    fn traversal_match_and_payload_bounds_fail_without_complete_results() {
        let reader = fixture_reader(4);
        let snapshot = coin_snapshot(&reader);
        let permit = reader
            .reserve_scan()
            .unwrap_or_else(|error| panic!("reserve: {error}"));
        let scripts = BTreeSet::from([vec![0x51]]);
        for (coins, matches, bytes) in [(3, 4, 4), (4, 3, 4), (4, 4, 3)] {
            assert!(matches!(
                permit.scan_snapshot_bounded(&*snapshot, &scripts, || false, coins, matches, bytes),
                Err(UtxoScanError::Limit(_))
            ));
        }
        let (complete, scan) = permit
            .scan_snapshot_bounded(&*snapshot, &scripts, || false, 4, 4, 4)
            .unwrap_or_else(|error| panic!("inclusive budget: {error}"));
        assert!(complete);
        assert_eq!(scan.txouts, 4);
        assert_eq!(scan.unspents.len(), 4);
    }

    #[test]
    fn needle_and_deadline_bounds_apply_before_traversal() {
        let reader = fixture_reader(1);
        let snapshot = coin_snapshot(&reader);
        let mut permit = reader
            .reserve_scan()
            .unwrap_or_else(|error| panic!("reserve: {error}"));
        let scripts: BTreeSet<Vec<u8>> = (0..=MAX_SCAN_SCRIPTS)
            .map(|n| n.to_le_bytes().to_vec())
            .collect();
        assert!(matches!(
            permit.scan_snapshot(&*snapshot, &scripts, || false),
            Err(UtxoScanError::Limit(_))
        ));
        let scripts = BTreeSet::from([vec![0_u8; MAX_SCAN_SCRIPT_BYTES + 1]]);
        assert!(matches!(
            permit.scan_snapshot(&*snapshot, &scripts, || false),
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
