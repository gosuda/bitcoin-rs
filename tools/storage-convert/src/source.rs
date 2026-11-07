use std::io::Read;
use std::path::Path;

use bitcoin_rs_storage::{ColumnFamily, KvStore, RocksDbStore, StorageBackend};
use cap_fs_ext::DirExt;
use cap_std::fs::Dir;
use redb::{
    MultimapTableHandle, ReadableDatabase, ReadableTable, TableDefinition, TableError, TableHandle,
};

use crate::error::{ConvertError, EngineOpenError};
use crate::fs_util::open_file_read_no_follow;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DetectedEngine {
    RocksDb,
    SurrealKv,
    Mdbx,
    Fjall,
    Redb,
}

pub(crate) fn detect_engine(
    scratch_path: &Path,
    dir: &Dir,
    source_epoch: u32,
) -> Result<Option<DetectedEngine>, ConvertError> {
    if source_epoch != 2 {
        let detected = bitcoin_rs_storage::detect_engine(scratch_path)?;
        return match detected {
            None => Ok(None),
            Some(StorageBackend::RocksDb) => Ok(Some(DetectedEngine::RocksDb)),
            Some(StorageBackend::SurrealKv) => Ok(Some(DetectedEngine::SurrealKv)),
            Some(StorageBackend::Mdbx) => Ok(Some(DetectedEngine::Mdbx)),
        };
    }
    let mut has_entries = false;
    let mut has_redb_file = false;
    let mut has_current = false;
    let mut has_options = false;
    let mut has_version = false;
    let mut has_keyspaces_dir = false;

    for entry in dir.entries()? {
        let entry = entry?;
        let file_type = entry.file_type()?;

        if file_type.is_symlink() {
            return Err(ConvertError::InvalidOperation(format!(
                "symlink '{:?}' encountered in storage namespace",
                entry.file_name()
            )));
        }

        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            return Err(ConvertError::InvalidOperation(
                "non-UTF8 file name encountered in storage namespace".into(),
            ));
        };

        if name_str == ".lock" {
            continue;
        }

        has_entries = true;

        if name_str == "redb.db" && file_type.is_file() {
            has_redb_file = true;
        } else if name_str == "CURRENT" && file_type.is_file() {
            has_current = true;
        } else if name_str.starts_with("OPTIONS-") && file_type.is_file() {
            has_options = true;
        } else if name_str == "version" && file_type.is_file() {
            has_version = true;
        } else if name_str == "keyspaces" && file_type.is_dir() {
            has_keyspaces_dir = true;
        }
    }

    if !has_entries {
        return Ok(None);
    }

    let has_keyspaces_zero = has_keyspaces_dir && check_keyspaces_zero(dir);

    let redb_recognized = has_redb_file;
    let rocksdb_recognized = has_current && has_options;

    let mut fjall_recognized = false;
    if has_version && has_keyspaces_zero {
        let mut version_file = open_file_read_no_follow(dir, "version")?;
        let mut version_buf = [0u8; 16];
        let n = version_file.read(&mut version_buf)?;
        if version_buf[..n].starts_with(b"FJL\x03") {
            fjall_recognized = true;
        } else {
            return Err(ConvertError::IncompatibleData(
                "corrupt or unrecognized fjall version marker in namespace directory".into(),
            ));
        }
    }

    let mut recognized_count = 0usize;
    if redb_recognized {
        recognized_count = recognized_count.saturating_add(1);
    }
    if rocksdb_recognized {
        recognized_count = recognized_count.saturating_add(1);
    }
    if fjall_recognized {
        recognized_count = recognized_count.saturating_add(1);
    }
    if recognized_count > 1 {
        return Err(ConvertError::IncompatibleData(
            "multiple recognized storage engines detected in namespace directory".into(),
        ));
    }

    if recognized_count == 0 {
        return Err(ConvertError::IncompatibleData(
            "unrecognized storage engine in namespace directory".into(),
        ));
    }

    if redb_recognized {
        if source_epoch != 2 {
            return Err(ConvertError::IncompatibleData(
                "redb storage backend is only supported for epoch 2 source datadirs".into(),
            ));
        }
        return Ok(Some(DetectedEngine::Redb));
    }

    if fjall_recognized {
        if source_epoch != 2 {
            return Err(ConvertError::IncompatibleData(
                "fjall storage backend is only supported for epoch 2 source datadirs".into(),
            ));
        }
        return Ok(Some(DetectedEngine::Fjall));
    }

    if rocksdb_recognized {
        return Ok(Some(DetectedEngine::RocksDb));
    }

    Err(ConvertError::IncompatibleData(
        "unrecognized storage engine in namespace directory".into(),
    ))
}

fn check_keyspaces_zero(dir: &Dir) -> bool {
    let Ok(kdir) = dir.open_dir_nofollow("keyspaces") else {
        return false;
    };
    let Ok(meta) = kdir.symlink_metadata("0") else {
        return false;
    };
    meta.is_dir()
}

pub(crate) enum SourceNamespace {
    Empty,
    Kv(Box<dyn KvStore>),
    Fjall(fjall::Database),
    RedbGeneric(redb::Database),
    RedbTxIndex(redb::Database),
}

const TXINDEX_TX_CONFIRMED: TableDefinition<&[u8; 12], ()> =
    TableDefinition::new("txindex_v1_tx_confirmed");
const TXINDEX_TX_CONFIRMED_VALUES: TableDefinition<&[u8; 12], &[u8]> =
    TableDefinition::new("txindex_v1_tx_confirmed_values");
const TXINDEX_FUNDING: TableDefinition<&[u8; 12], ()> = TableDefinition::new("txindex_v1_funding");
const TXINDEX_FUNDING_VALUES: TableDefinition<&[u8; 12], &[u8]> =
    TableDefinition::new("txindex_v1_funding_values");
const TXINDEX_SPENDING: TableDefinition<&[u8; 12], ()> =
    TableDefinition::new("txindex_v1_spending");
const TXINDEX_SPENDING_VALUES: TableDefinition<&[u8; 12], &[u8]> =
    TableDefinition::new("txindex_v1_spending_values");
const TXINDEX_BLOCK_HEADERS: TableDefinition<&[u8; 80], ()> =
    TableDefinition::new("txindex_v1_block_headers");
const TXINDEX_SCRIPT_LIVE: TableDefinition<&[u8; 43], ()> =
    TableDefinition::new("txindex_v1_script_live");
const TXINDEX_META: TableDefinition<&[u8], &[u8]> = TableDefinition::new("txindex_v1_meta");
type RedbFixedValueTablePair<'m, 'v> = (
    TableDefinition<'m, &'static [u8; 12], ()>,
    TableDefinition<'v, &'static [u8; 12], &'static [u8]>,
);

impl SourceNamespace {
    pub(crate) fn open(
        path: &Path,
        engine: Option<DetectedEngine>,
    ) -> Result<(Self, &'static str), ConvertError> {
        let Some(engine) = engine else {
            return Ok((Self::Empty, "empty"));
        };

        match engine {
            DetectedEngine::RocksDb => {
                let store = RocksDbStore::open(path)
                    .map_err(|e| ConvertError::EngineOpen(EngineOpenError::Storage(e)))?;
                Ok((Self::Kv(Box::new(store)), "rocksdb"))
            }
            DetectedEngine::SurrealKv => {
                #[cfg(feature = "surrealkv")]
                {
                    let store =
                        bitcoin_rs_storage::SurrealKvStore::open_with_cache(path, 64 * 1024 * 1024)
                            .map_err(|e| ConvertError::EngineOpen(EngineOpenError::Storage(e)))?;
                    Ok((Self::Kv(Box::new(store)), "surrealkv"))
                }
                #[cfg(not(feature = "surrealkv"))]
                {
                    let _ = path;
                    Err(ConvertError::EngineNotCompiled {
                        engine: "surrealkv".to_string(),
                        feature: "surrealkv",
                    })
                }
            }
            DetectedEngine::Mdbx => {
                #[cfg(feature = "mdbx")]
                {
                    let store = bitcoin_rs_storage::MdbxStore::open_with_cache(path, 0)
                        .map_err(|e| ConvertError::EngineOpen(EngineOpenError::Storage(e)))?;
                    Ok((Self::Kv(Box::new(store)), "mdbx"))
                }
                #[cfg(not(feature = "mdbx"))]
                {
                    let _ = path;
                    Err(ConvertError::EngineNotCompiled {
                        engine: "mdbx".to_string(),
                        feature: "mdbx",
                    })
                }
            }
            DetectedEngine::Fjall => {
                let db = fjall::Database::builder(path)
                    .cache_size(32 * 1024 * 1024)
                    .open()
                    .map_err(|e| ConvertError::EngineOpen(EngineOpenError::Fjall(e)))?;
                Ok((Self::Fjall(db), "fjall"))
            }
            DetectedEngine::Redb => {
                let redb_file = path.join("redb.db");
                let db = redb::Database::open(redb_file)
                    .map_err(|e| ConvertError::EngineOpen(EngineOpenError::Redb(e)))?;

                let read_txn = db
                    .begin_read()
                    .map_err(|e| ConvertError::EngineOpen(EngineOpenError::RedbTransaction(e)))?;

                let mut has_specialized = false;
                let mut has_generic = false;

                let table_handles = read_txn
                    .list_tables()
                    .map_err(|e| ConvertError::EngineOpen(EngineOpenError::RedbStorage(e)))?;

                let supported_txindex_tables = [
                    TXINDEX_TX_CONFIRMED.name(),
                    TXINDEX_TX_CONFIRMED_VALUES.name(),
                    TXINDEX_FUNDING.name(),
                    TXINDEX_FUNDING_VALUES.name(),
                    TXINDEX_SPENDING.name(),
                    TXINDEX_SPENDING_VALUES.name(),
                    TXINDEX_BLOCK_HEADERS.name(),
                    TXINDEX_SCRIPT_LIVE.name(),
                    TXINDEX_META.name(),
                ];
                for handle in table_handles {
                    let name = handle.name();
                    if supported_txindex_tables.contains(&name) {
                        has_specialized = true;
                    } else if ColumnFamily::ALL.iter().any(|cf| cf.name() == name) {
                        has_generic = true;
                    } else {
                        return Err(ConvertError::IncompatibleData(format!(
                            "unrecognized table in redb database: {name}"
                        )));
                    }
                }

                let multimap_table_handles = read_txn
                    .list_multimap_tables()
                    .map_err(|e| ConvertError::EngineOpen(EngineOpenError::RedbStorage(e)))?;

                if let Some(handle) = multimap_table_handles.into_iter().next() {
                    return Err(ConvertError::IncompatibleData(format!(
                        "unsupported multimap table in redb database: {}",
                        handle.name()
                    )));
                }

                if has_specialized && has_generic {
                    return Err(ConvertError::IncompatibleData(
                        "mixed specialized txindex and generic tables in redb database".into(),
                    ));
                }

                if has_specialized {
                    Ok((Self::RedbTxIndex(db), "redb"))
                } else {
                    Ok((Self::RedbGeneric(db), "redb"))
                }
            }
        }
    }

    pub(crate) fn for_each_row<F>(&self, cf: ColumnFamily, mut f: F) -> Result<u64, ConvertError>
    where
        F: FnMut(&[u8], &[u8]) -> Result<(), ConvertError>,
    {
        let mut count = 0u64;

        match self {
            Self::Empty => Ok(0),
            Self::Kv(store) => {
                let iter = store.iter_prefix(cf, b"")?;
                for item in iter {
                    let (key, value) = item?;
                    f(&key, &value)?;
                    count = count.saturating_add(1);
                }
                Ok(count)
            }
            Self::Fjall(db) => {
                if !db.keyspace_exists(cf.name()) {
                    return Ok(0);
                }
                let keyspace = db
                    .keyspace(cf.name(), fjall::KeyspaceCreateOptions::default)
                    .map_err(|e| ConvertError::EngineOpen(EngineOpenError::Fjall(e)))?;

                for guard in keyspace.iter() {
                    let (k, v) = guard
                        .into_inner()
                        .map_err(|e| ConvertError::EngineOpen(EngineOpenError::Fjall(e)))?;
                    f(&k, &v)?;
                    count = count.saturating_add(1);
                }
                Ok(count)
            }
            Self::RedbGeneric(db) => {
                let read_txn = db
                    .begin_read()
                    .map_err(|e| ConvertError::EngineOpen(EngineOpenError::RedbTransaction(e)))?;
                let table_def = TableDefinition::<&[u8], &[u8]>::new(cf.name());
                let table = match read_txn.open_table(table_def) {
                    Ok(t) => t,
                    Err(TableError::TableDoesNotExist(_)) => return Ok(0),
                    Err(e) => return Err(ConvertError::EngineOpen(EngineOpenError::RedbTable(e))),
                };

                let iter = table
                    .iter()
                    .map_err(|e| ConvertError::EngineOpen(EngineOpenError::RedbStorage(e)))?;
                for row in iter {
                    let (k, v) =
                        row.map_err(|e| ConvertError::EngineOpen(EngineOpenError::RedbStorage(e)))?;
                    f(k.value(), v.value())?;
                    count = count.saturating_add(1);
                }
                Ok(count)
            }
            Self::RedbTxIndex(db) => {
                let read_txn = db
                    .begin_read()
                    .map_err(|e| ConvertError::EngineOpen(EngineOpenError::RedbTransaction(e)))?;

                match cf {
                    ColumnFamily::TxConfirmed => {
                        let n = Self::scan_redb_fixed_value(
                            &read_txn,
                            (TXINDEX_TX_CONFIRMED, TXINDEX_TX_CONFIRMED_VALUES),
                            &mut f,
                        )?;
                        count = count.saturating_add(n);
                    }
                    ColumnFamily::Funding => {
                        let n = Self::scan_redb_fixed_value(
                            &read_txn,
                            (TXINDEX_FUNDING, TXINDEX_FUNDING_VALUES),
                            &mut f,
                        )?;
                        count = count.saturating_add(n);
                    }
                    ColumnFamily::Spending => {
                        let n = Self::scan_redb_fixed_value(
                            &read_txn,
                            (TXINDEX_SPENDING, TXINDEX_SPENDING_VALUES),
                            &mut f,
                        )?;
                        count = count.saturating_add(n);
                    }
                    ColumnFamily::BlockHeaders => {
                        let n =
                            Self::scan_redb_fixed_unit(&read_txn, TXINDEX_BLOCK_HEADERS, &mut f)?;
                        count = count.saturating_add(n);
                    }
                    ColumnFamily::ScriptLive => {
                        let n = Self::scan_redb_fixed_unit(&read_txn, TXINDEX_SCRIPT_LIVE, &mut f)?;
                        count = count.saturating_add(n);
                    }
                    ColumnFamily::UtxoMeta => {
                        let table = match read_txn.open_table(TXINDEX_META) {
                            Ok(t) => t,
                            Err(TableError::TableDoesNotExist(_)) => return Ok(0),
                            Err(e) => {
                                return Err(ConvertError::EngineOpen(EngineOpenError::RedbTable(
                                    e,
                                )));
                            }
                        };
                        let iter = table.iter().map_err(|e| {
                            ConvertError::EngineOpen(EngineOpenError::RedbStorage(e))
                        })?;
                        for row in iter {
                            let (k, v) = row.map_err(|e| {
                                ConvertError::EngineOpen(EngineOpenError::RedbStorage(e))
                            })?;
                            f(k.value(), v.value())?;
                            count = count.saturating_add(1);
                        }
                    }
                    _ => {}
                }

                Ok(count)
            }
        }
    }

    fn scan_redb_fixed_value<F>(
        read_txn: &redb::ReadTransaction,
        tables: RedbFixedValueTablePair<'_, '_>,
        f: &mut F,
    ) -> Result<u64, ConvertError>
    where
        F: FnMut(&[u8], &[u8]) -> Result<(), ConvertError>,
    {
        let (main_def, val_def) = tables;
        let main_table = match read_txn.open_table(main_def) {
            Ok(t) => Some(t),
            Err(TableError::TableDoesNotExist(_)) => None,
            Err(e) => return Err(ConvertError::EngineOpen(EngineOpenError::RedbTable(e))),
        };
        let values_table = match read_txn.open_table(val_def) {
            Ok(t) => Some(t),
            Err(TableError::TableDoesNotExist(_)) => None,
            Err(e) => return Err(ConvertError::EngineOpen(EngineOpenError::RedbTable(e))),
        };

        let Some(main_table) = main_table else {
            if let Some(vt) = &values_table {
                let has_rows = vt
                    .iter()
                    .map_err(|e| ConvertError::EngineOpen(EngineOpenError::RedbStorage(e)))?
                    .next()
                    .transpose()
                    .map_err(|e| ConvertError::EngineOpen(EngineOpenError::RedbStorage(e)))?
                    .is_some();
                if has_rows {
                    return Err(ConvertError::IncompatibleData(format!(
                        "orphaned value-table row in redb table {}",
                        val_def.name()
                    )));
                }
            }
            return Ok(0);
        };

        let main_rows = main_table
            .iter()
            .map_err(|e| ConvertError::EngineOpen(EngineOpenError::RedbStorage(e)))?;
        let mut value_rows = match &values_table {
            Some(table) => Some(
                table
                    .iter()
                    .map_err(|e| ConvertError::EngineOpen(EngineOpenError::RedbStorage(e)))?,
            ),
            None => None,
        };
        let mut next_value = match &mut value_rows {
            Some(rows) => rows
                .next()
                .transpose()
                .map_err(|e| ConvertError::EngineOpen(EngineOpenError::RedbStorage(e)))?,
            None => None,
        };
        let mut count = 0u64;

        for row in main_rows {
            let (key_guard, _) =
                row.map_err(|e| ConvertError::EngineOpen(EngineOpenError::RedbStorage(e)))?;
            let key = key_guard.value();
            let value = if let Some((value_key_guard, value_guard)) = next_value.take() {
                let value_key = value_key_guard.value();
                if value_key < key {
                    return Err(ConvertError::IncompatibleData(format!(
                        "orphaned value-table row in redb table {}",
                        val_def.name()
                    )));
                }
                if value_key == key {
                    let value = value_guard.value().to_vec();
                    next_value = match &mut value_rows {
                        Some(rows) => rows.next().transpose().map_err(|e| {
                            ConvertError::EngineOpen(EngineOpenError::RedbStorage(e))
                        })?,
                        None => None,
                    };
                    value
                } else {
                    next_value = Some((value_key_guard, value_guard));
                    Vec::new()
                }
            } else {
                Vec::new()
            };

            f(key.as_slice(), &value)?;
            count = count.saturating_add(1);
        }

        if next_value.is_some() {
            return Err(ConvertError::IncompatibleData(format!(
                "orphaned value-table row in redb table {}",
                val_def.name()
            )));
        }

        Ok(count)
    }

    fn scan_redb_fixed_unit<const N: usize, F>(
        read_txn: &redb::ReadTransaction,
        table_def: TableDefinition<&[u8; N], ()>,
        f: &mut F,
    ) -> Result<u64, ConvertError>
    where
        F: FnMut(&[u8], &[u8]) -> Result<(), ConvertError>,
    {
        let table = match read_txn.open_table(table_def) {
            Ok(t) => t,
            Err(TableError::TableDoesNotExist(_)) => return Ok(0),
            Err(e) => return Err(ConvertError::EngineOpen(EngineOpenError::RedbTable(e))),
        };

        let iter = table
            .iter()
            .map_err(|e| ConvertError::EngineOpen(EngineOpenError::RedbStorage(e)))?;

        let mut count = 0u64;
        for row in iter {
            let (key_guard, _) =
                row.map_err(|e| ConvertError::EngineOpen(EngineOpenError::RedbStorage(e)))?;
            let key = key_guard.value();
            f(key.as_slice(), &[])?;
            count = count.saturating_add(1);
        }

        Ok(count)
    }
}
