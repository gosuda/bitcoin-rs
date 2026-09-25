//! Object-safety proof for the backend-neutral store trait.
//!
//! The trait carries no associated types or generic methods, so a real
//! backend dispatches every call through a `dyn KvStore` and performs the
//! same storage operation it performs through its concrete type.
#![cfg(feature = "fjall")]
#![expect(clippy::expect_used, reason = "test assertions")]

use bitcoin_rs_storage::{ColumnFamily, KvStore};

/// PRE: none. POST: a put issued through `dyn KvStore` is readable through
/// `dyn KvStore`. INVARIANT: trait-object dispatch performs the same storage
/// operation as the concrete type.
#[test]
fn kv_store_dispatches_through_a_trait_object() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store: Box<dyn KvStore> = Box::new(bitcoin_rs_storage::FjallStore::open(dir.path())?);

    let mut batch = store.new_batch();
    batch.put(ColumnFamily::BlockBodies, b"dispatch-key", b"v");
    store.write(batch)?;

    assert_eq!(
        store.get(ColumnFamily::BlockBodies, b"dispatch-key")?,
        Some(b"v".to_vec())
    );
    Ok(())
}
