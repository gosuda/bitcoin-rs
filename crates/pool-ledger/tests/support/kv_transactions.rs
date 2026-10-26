use super::*;
use bitcoin_rs_storage::{FjallStore, RedbStore};

const SHARES: TableDefinition<'static, u64, &'static [u8]> =
    TableDefinition::new("pplns_shares_v1");
const BALANCES: TableDefinition<'static, u64, &'static [u8]> =
    TableDefinition::new("pplns_balances_v1");

fn exercise(store: &Arc<dyn KvStore>) -> Result<(), Box<dyn std::error::Error>> {
    let first = Database::new(Arc::clone(store));
    let second = Database::new(Arc::clone(store));
    let stale_read = first.begin_read()?;
    let a = first.begin_write()?;
    let b = second.begin_write()?;
    a.open_table(SHARES)?.insert(1u64, b"first".as_slice())?;
    a.open_table(BALANCES)?.insert(1u64, b"credit".as_slice())?;
    b.open_table(SHARES)?.insert(2u64, b"stale".as_slice())?;
    b.open_table(BALANCES)?
        .insert(2u64, b"stale credit".as_slice())?;
    assert!(
        store.iter_prefix(CF, PREFIX)?.next().is_none(),
        "buffering has no effects"
    );
    a.commit()?;
    assert!(
        matches!(b.commit(), Err(LedgerError::Conflict)),
        "stale cross-handle revision rejects entire batch"
    );
    assert!(
        stale_read.open_table(SHARES)?.get(1u64)?.is_none(),
        "read snapshot remains coherent"
    );
    let read = second.begin_read()?;
    let first_row = read
        .open_table(SHARES)?
        .get(1u64)?
        .ok_or_else(|| std::io::Error::other("missing committed row"))?;
    assert_eq!(first_row.value(), b"first");
    assert!(read.open_table(SHARES)?.get(2u64)?.is_none());
    assert!(
        read.open_table(BALANCES)?.get(2u64)?.is_none(),
        "no partial effects in another logical table"
    );
    let dropped = first.begin_write()?;
    dropped.open_table(SHARES)?.remove(1u64)?;
    assert!(dropped.open_table(SHARES)?.get(1u64)?.is_none());
    drop(dropped);
    assert!(
        second
            .begin_read()?
            .open_table(SHARES)?
            .get(1u64)?
            .is_some(),
        "dropping a transaction rolls back all buffered changes"
    );
    Ok(())
}

#[test]
fn redb_snapshot_and_cross_handle_conditional_commit() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store: Arc<dyn KvStore> = Arc::new(RedbStore::open(dir.path().join("store.redb"))?);
    exercise(&store)
}

#[test]
fn fjall_snapshot_and_cross_handle_conditional_commit() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store: Arc<dyn KvStore> = Arc::new(FjallStore::open(dir.path().join("store"))?);
    exercise(&store)
}
