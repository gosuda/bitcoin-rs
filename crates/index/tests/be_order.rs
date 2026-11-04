use crate::support::{TestError, common};

use std::sync::Arc;

use bitcoin_rs_index::Indexer;
use bitcoin_rs_primitives::{Hash256, OutPoint, Txid};

use common::{MemoryStore, put_spending_row};

fn spent_outpoint(label: u8, vout: u32) -> OutPoint {
    OutPoint::new(Txid(Hash256::from_le_bytes(&[label; 32])), vout)
}

#[test]
fn spending_rows_also_use_numeric_height_order() -> Result<(), TestError> {
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
