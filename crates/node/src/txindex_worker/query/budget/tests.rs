//! IDX-03 / CL-14: incomplete or over-budget reads never become query results.

use super::*;

#[test]
fn historical_and_live_scans_share_the_byte_budget() -> Result<(), TxQueryError> {
    let mut budget = QueryBudget::new();
    budget.remaining_bytes = 5;
    budget.accept_scan(TxIndexScan {
        rows: Vec::new(),
        encoded_bytes: 2,
        complete: true,
    })?;
    budget.accept_live_scan(ScriptLiveScan {
        rows: Vec::new(),
        encoded_bytes: 3,
        complete: true,
    })?;
    assert_eq!(budget.remaining_bytes, 0);
    assert!(matches!(
        budget.next_scan_limit(),
        Err(TxQueryError::Unavailable(_))
    ));
    Ok(())
}

#[test]
fn truncated_scan_families_fail_without_charging_rows_or_bytes() {
    let mut budget = QueryBudget::new();
    let before = (budget.remaining_rows, budget.remaining_bytes);
    let historical = budget.accept_scan(TxIndexScan {
        rows: Vec::new(),
        encoded_bytes: 2,
        complete: false,
    });
    assert!(
        matches!(historical, Err(TxQueryError::Unavailable(reason)) if reason == "txindex prefix scan truncated")
    );
    let live = budget.accept_live_scan(ScriptLiveScan {
        rows: Vec::new(),
        encoded_bytes: 3,
        complete: false,
    });
    assert!(
        matches!(live, Err(TxQueryError::Unavailable(reason)) if reason == "txindex live prefix scan truncated")
    );
    assert_eq!((budget.remaining_rows, budget.remaining_bytes), before);
}

#[test]
fn rejected_scan_charge_does_not_partially_consume_budget() -> Result<(), TxQueryError> {
    let mut budget = QueryBudget::new();
    budget.remaining_rows = 2;
    budget.remaining_bytes = 5;
    for (rows, bytes) in [(3, 1), (1, 6), (usize::MAX, usize::MAX)] {
        assert!(matches!(
            budget.charge_scan(rows, bytes),
            Err(TxQueryError::Unavailable(_))
        ));
        assert_eq!((budget.remaining_rows, budget.remaining_bytes), (2, 5));
    }
    budget.charge_scan(2, 5)?;
    assert_eq!((budget.remaining_rows, budget.remaining_bytes), (0, 0));
    Ok(())
}

#[test]
fn scan_count_rows_and_bytes_each_stop_admission() {
    for (rows, bytes, scans) in [(0, 1, 1), (1, 0, 1), (1, 1, 0)] {
        let mut budget = QueryBudget {
            remaining_rows: rows,
            remaining_bytes: bytes,
            remaining_scans: scans,
            remaining_body_reads: 1,
        };
        assert!(matches!(
            budget.next_scan_limit(),
            Err(TxQueryError::Unavailable(_))
        ));
        assert_eq!(budget.remaining_scans, scans);
    }
}

#[test]
fn scan_limit_is_remaining_work_and_reserves_one_scan() -> Result<(), TxQueryError> {
    let mut budget = QueryBudget::new();
    budget.remaining_rows = 7;
    budget.remaining_bytes = 11;
    budget.remaining_scans = 1;
    let limit = budget.next_scan_limit()?;
    assert_eq!((limit.max_rows, limit.max_bytes), (7, 11));
    assert!(matches!(
        budget.next_scan_limit(),
        Err(TxQueryError::Unavailable(_))
    ));
    Ok(())
}

#[test]
fn bodies_and_scans_share_bytes_but_reserve_body_reads_separately() -> Result<(), TxQueryError> {
    let mut budget = QueryBudget::new();
    budget.remaining_bytes = 5;
    budget.remaining_body_reads = 1;
    assert!(matches!(
        budget.reserve_body_read(6),
        Err(TxQueryError::Unavailable(_))
    ));
    assert_eq!(budget.remaining_body_reads, 1);
    budget.reserve_body_read(5)?;
    assert_eq!(budget.remaining_bytes, 5);
    assert!(matches!(
        budget.reserve_body_read(1),
        Err(TxQueryError::Unavailable(_))
    ));
    budget.charge_body_bytes(3)?;
    assert!(matches!(
        budget.charge_body_bytes(3),
        Err(TxQueryError::Unavailable(_))
    ));
    assert_eq!(budget.remaining_bytes, 2);
    budget.accept_live_scan(ScriptLiveScan {
        rows: Vec::new(),
        encoded_bytes: 2,
        complete: true,
    })?;
    assert_eq!(budget.remaining_bytes, 0);
    Ok(())
}
