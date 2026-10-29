#![cfg(feature = "fjall")]

use bitcoin_rs_storage::{ColumnFamily, KvStore};

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
