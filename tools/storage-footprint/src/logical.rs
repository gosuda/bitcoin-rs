//! Logical owner ledger and column-family scanner.

use bitcoin_rs_storage::{ColumnFamily, KvStore, StorageError};

/// Exact serialized key and value bytes for one logical owner.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct LogicalOwner {
    /// `{namespace}.{column_family}` or a named subsystem such as `blocks.flat_files`.
    pub name: String,
    /// Number of rows or framed records.
    pub rows: u64,
    /// Sum of serialized key lengths.
    pub key_bytes: u64,
    /// Sum of serialized value lengths.
    pub value_bytes: u64,
    /// `key_bytes + value_bytes`. Not a filesystem allocation.
    pub serialized_bytes: u64,
}

impl LogicalOwner {
    #[must_use]
    /// Creates a new logical owner record.
    pub fn new(name: impl Into<String>, rows: u64, key_bytes: u64, value_bytes: u64) -> Self {
        Self {
            name: name.into(),
            rows,
            key_bytes,
            value_bytes,
            serialized_bytes: key_bytes.saturating_add(value_bytes),
        }
    }
}

/// Logical owner ledger. Do not add these bytes to the physical ledger.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LogicalLedger {
    /// Owners in stable name order.
    pub owners: Vec<LogicalOwner>,
}

impl LogicalLedger {
    /// Sum of serialized key and value bytes across owners.
    ///
    /// This is a logical-ledger total only. It is not a data-directory budget.
    #[must_use]
    pub fn serialized_bytes(&self) -> u64 {
        self.owners.iter().fold(0, |total, owner| {
            total.saturating_add(owner.serialized_bytes)
        })
    }

    /// Inserts `owner` and keeps owners sorted by name.
    pub fn push(&mut self, owner: LogicalOwner) {
        self.owners.push(owner);
        self.owners
            .sort_by(|left, right| left.name.cmp(&right.name));
    }
}

/// Exact serialized key and value bytes for every column family in `store`.
///
/// Owner names are `{namespace}.{column_family}`.
pub fn logical_store_owners<S: KvStore>(
    store: &S,
    namespace: &str,
) -> Result<Vec<LogicalOwner>, StorageError> {
    let mut owners = Vec::with_capacity(ColumnFamily::ALL.len());
    for cf in ColumnFamily::ALL.iter().copied() {
        let name = format!("{namespace}.{}", cf.name());
        owners.push(logical_column_family_named(store, cf, &name)?);
    }
    Ok(owners)
}

fn logical_column_family_named<S: KvStore>(
    store: &S,
    cf: ColumnFamily,
    name: &str,
) -> Result<LogicalOwner, StorageError> {
    let mut rows = 0_u64;
    let mut key_bytes = 0_u64;
    let mut value_bytes = 0_u64;
    store.for_each_prefix(cf, &[], &mut |key, value| {
        rows = rows.saturating_add(1);
        key_bytes = key_bytes.saturating_add(u64::try_from(key.len()).unwrap_or(u64::MAX));
        value_bytes = value_bytes.saturating_add(u64::try_from(value.len()).unwrap_or(u64::MAX));
        Ok(())
    })?;
    Ok(LogicalOwner::new(name, rows, key_bytes, value_bytes))
}
