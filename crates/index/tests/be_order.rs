//! Big-endian key-order vs numeric-height-order contract tests.

use crate::support::common;

use std::sync::Arc;

use bitcoin_rs_index::{Indexer, ScriptHash};
use bitcoin_rs_primitives::{Hash256, OutPoint, Txid};

use common::{MemoryStore, put_funding_row, put_spending_row};

fn spent_outpoint(label: u8, vout: u32) -> OutPoint {
    OutPoint::new(Txid(Hash256::from_le_bytes(&[label; 32])), vout)
}

#[test]
fn funding_rows_iterate_in_numeric_height_order() -> Result<(), Box<dyn std::error::Error>> {
    let script = vec![0x51, 0x01];
    let scripthash = ScriptHash::from_script_bytes(&script);
    let store = Arc::new(MemoryStore::default());
    put_funding_row(&store, scripthash, 1)?;
    put_funding_row(&store, scripthash, 256)?;
    let indexer = Indexer::new(store);

    let rows = indexer.iter_funding_rows(scripthash)?;
    assert_eq!(rows.len(), 2, "two heights funded the same script");

    assert_eq!(
        rows.iter().map(|row| row.height()).collect::<Vec<_>>(),
        vec![1, 256],
        "BE byte order matches numeric height order"
    );
    Ok(())
}

#[test]
fn spending_rows_also_use_numeric_height_order() -> Result<(), Box<dyn std::error::Error>> {
    let outpoint = spent_outpoint(7, 0);
    let store = Arc::new(MemoryStore::default());
    put_spending_row(&store, &outpoint, 1)?;
    put_spending_row(&store, &outpoint, 256)?;
    let indexer = Indexer::new(store);

    let rows = indexer.iter_spending_rows(&outpoint)?;
    assert_eq!(rows.len(), 2, "two spending rows at two heights");

    assert_eq!(
        rows.iter().map(|row| row.height()).collect::<Vec<_>>(),
        vec![1, 256]
    );
    Ok(())
}
