use std::sync::Arc;

use bitcoin_rs_consensus::primitives::BlockImage;
use bitcoin_rs_storage::commit::{AcceptedPrefix, CommitError, CommitFault};
use parking_lot::Mutex;

use crate::test_fixtures::{TestResult, churn_corpus, funded_chain};
use crate::window_limits::WindowLimits;

#[derive(Default)]
struct BatchRecorder {
    carried: Mutex<Vec<usize>>,
}

impl CommitFault for BatchRecorder {
    fn before_commit(&self, prefix: &AcceptedPrefix) -> Result<(), CommitError> {
        self.carried.lock().push(carried_bytes(prefix));
        Ok(())
    }
}

fn carried_bytes(prefix: &AcceptedPrefix) -> usize {
    let undo: usize = prefix
        .undo_rows
        .iter()
        .map(|(_, _, bytes)| bytes.len())
        .sum();
    let coins: usize = prefix
        .coin_delta
        .records
        .iter()
        .map(|(key, record)| key.as_bytes().len() + record.as_ref().map_or(0, bytes::Bytes::len))
        .sum();
    undo + coins
}

// BUD-06
#[test]
fn window_batches_stay_within_ceiling_under_undo_and_coin_churn() -> TestResult {
    let corpus = churn_corpus()?;
    let payloads: Vec<BlockImage> = corpus.payloads();
    let block_total: usize = payloads.iter().map(|payload| payload.bytes().len()).sum();
    let limits = WindowLimits {
        max_bytes: block_total + 1,
        ..WindowLimits::durable_head_defaults()
    };

    let windowed = funded_chain(&corpus, limits)?;
    let recorder = Arc::new(BatchRecorder::default());
    windowed.set_commit_fault(recorder.clone());
    let refs: Vec<&BlockImage> = payloads.iter().collect();
    windowed.apply_window(&refs)?;
    let batches = recorder.carried.lock().clone();

    let oracle = funded_chain(&corpus, limits)?;
    let single = Arc::new(BatchRecorder::default());
    oracle.set_commit_fault(single.clone());
    for payload in &payloads {
        oracle.apply_window(&[payload])?;
    }
    let single_batches = single.carried.lock().clone();
    assert_eq!(
        single_batches.len(),
        payloads.len(),
        "each single-block window must commit exactly one batch"
    );

    let largest_block_charge = payloads
        .iter()
        .zip(&single_batches)
        .map(|(payload, carried)| payload.bytes().len() + carried)
        .max()
        .unwrap_or(0);
    let ceiling = limits.max_bytes + largest_block_charge;
    assert!(
        !batches.is_empty(),
        "the window must commit at least one batch"
    );
    for (index, carried) in batches.iter().enumerate() {
        assert!(
            *carried <= ceiling,
            "batch {index} carries {carried} undo and coin bytes, above the ceiling {ceiling}"
        );
    }
    Ok(())
}
