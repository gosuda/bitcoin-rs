use std::fs;
use std::path::Path;

use bitcoin_rs_storage::{BufferedWriteBatch, ColumnFamily, KvStore, RocksDbStore};
use redb::{Database, TableDefinition};

use super::error::{TestError, TestResult};

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

pub(crate) type KvRow = (Vec<u8>, Vec<u8>);
pub(crate) type FamilyRows = (ColumnFamily, Vec<KvRow>);

pub(crate) fn write_schema_marker(dir: &Path, epoch: u32) -> TestResult<()> {
    fs::create_dir_all(dir)?;
    fs::write(dir.join("CURRENT_SCHEMA"), format!("{epoch}\n"))?;
    Ok(())
}

pub(crate) fn write_fjall_namespace(dir: &Path, data: &[FamilyRows]) -> TestResult<()> {
    fs::create_dir_all(dir)?;
    let db = fjall::Database::builder(dir).open()?;
    for cf in ColumnFamily::ALL {
        let keyspace = db.keyspace(cf.name(), fjall::KeyspaceCreateOptions::default)?;
        if let Some((_, rows)) = data.iter().find(|(c, _)| *c == *cf) {
            for (k, v) in rows {
                keyspace.insert(k, v)?;
            }
        }
    }
    db.persist(fjall::PersistMode::SyncAll)?;
    drop(db);
    Ok(())
}

#[derive(Default)]
pub(crate) struct RedbTxIndexFixture {
    pub(crate) confirmed: Vec<([u8; 12], Option<Vec<u8>>)>,
    pub(crate) funding: Vec<([u8; 12], Vec<u8>)>,
    pub(crate) spending: Vec<([u8; 12], Vec<u8>)>,
    pub(crate) headers: Vec<[u8; 80]>,
    pub(crate) script_live: Vec<[u8; 43]>,
    pub(crate) meta: Vec<KvRow>,
}

pub(crate) fn write_redb_txindex(dir: &Path, fixture: &RedbTxIndexFixture) -> TestResult<()> {
    fs::create_dir_all(dir)?;
    let db_path = dir.join("redb.db");
    let db = Database::create(db_path)?;
    let write_txn = db.begin_write()?;

    {
        let mut t_conf = write_txn.open_table(TXINDEX_TX_CONFIRMED)?;
        let mut t_conf_val = write_txn.open_table(TXINDEX_TX_CONFIRMED_VALUES)?;
        for (k, v_opt) in &fixture.confirmed {
            t_conf.insert(k, ())?;
            if let Some(v) = v_opt {
                if !v.is_empty() {
                    t_conf_val.insert(k, v.as_slice())?;
                }
            }
        }
    }

    {
        let mut t_fund = write_txn.open_table(TXINDEX_FUNDING)?;
        let mut t_fund_val = write_txn.open_table(TXINDEX_FUNDING_VALUES)?;
        for (k, v) in &fixture.funding {
            t_fund.insert(k, ())?;
            if !v.is_empty() {
                t_fund_val.insert(k, v.as_slice())?;
            }
        }
    }

    {
        let mut t_spend = write_txn.open_table(TXINDEX_SPENDING)?;
        let mut t_spend_val = write_txn.open_table(TXINDEX_SPENDING_VALUES)?;
        for (k, v) in &fixture.spending {
            t_spend.insert(k, ())?;
            if !v.is_empty() {
                t_spend_val.insert(k, v.as_slice())?;
            }
        }
    }

    {
        let mut t_headers = write_txn.open_table(TXINDEX_BLOCK_HEADERS)?;
        for k in &fixture.headers {
            t_headers.insert(k, ())?;
        }
    }

    {
        let mut t_script = write_txn.open_table(TXINDEX_SCRIPT_LIVE)?;
        for k in &fixture.script_live {
            t_script.insert(k, ())?;
        }
    }

    {
        let mut t_meta = write_txn.open_table(TXINDEX_META)?;
        for (k, v) in &fixture.meta {
            t_meta.insert(k.as_slice(), v.as_slice())?;
        }
    }

    write_txn.commit()?;
    drop(db);
    Ok(())
}

pub(crate) fn write_rocksdb_namespace(dir: &Path, data: &[FamilyRows]) -> TestResult<()> {
    fs::create_dir_all(dir)?;
    let store = RocksDbStore::open_with_cache(dir, 0)?;
    let mut batch = BufferedWriteBatch::default();
    for (cf, rows) in data {
        for (k, v) in rows {
            batch.put(*cf, k, v);
        }
    }
    store.write_durable(batch)?;
    drop(store);
    Ok(())
}

pub(crate) fn read_rocksdb_all_rows(dir: &Path) -> TestResult<Vec<FamilyRows>> {
    if !dir.is_dir() {
        return Err(TestError::Assertion(format!(
            "namespace directory '{}' does not exist or is not a directory",
            dir.display()
        )));
    }
    let store = RocksDbStore::open_with_cache(dir, 0)?;
    let snapshot = store.snapshot()?;

    let mut result = Vec::new();
    for cf in ColumnFamily::ALL {
        let mut rows = Vec::new();
        for item in snapshot.iter_prefix(*cf, &[])? {
            let (key, val) = item?;
            rows.push((key, val));
        }
        result.push((*cf, rows));
    }
    drop(snapshot);
    drop(store);
    Ok(result)
}

pub(crate) fn write_independent_files(dir: &Path) -> TestResult<Vec<(String, Vec<u8>)>> {
    let files = vec![
        (
            "blocks/blk00000.dat",
            b"BRSB\x01\x02\x03\x04test_block_data".to_vec(),
        ),
        (
            "chainstate-checkpoints/gen-001/manifest-v1.json",
            b"{\"version\":1,\"height\":100}".to_vec(),
        ),
        (
            "chainstate-checkpoints/gen-001/utxo-v4.dat",
            b"test_utxo_checkpoint_data".to_vec(),
        ),
        (
            "assumeutxo-historical-checkpoints/gen-000/manifest-v1.json",
            b"{\"version\":1,\"network\":\"regtest\"}".to_vec(),
        ),
        (
            "chainstate-journal/segment-00000.log",
            b"test_journal_segment_bytes".to_vec(),
        ),
        (
            "chainstate-journal/head.json",
            b"{\"tip\":\"0000000000\"}".to_vec(),
        ),
        ("peers.dat", b"test_peers_binary_data".to_vec()),
        (
            "mempool-snapshot.dat",
            b"test_mempool_snapshot_data".to_vec(),
        ),
        (
            "fee-estimator-history.dat",
            b"test_fee_estimator_history_payload".to_vec(),
        ),
    ];

    for (rel_path, content) in &files {
        let full_path = dir.join(rel_path);
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&full_path, content)?;
    }

    Ok(files.into_iter().map(|(p, c)| (p.to_string(), c)).collect())
}

pub(crate) fn write_ignored_files(dir: &Path) -> TestResult<()> {
    fs::create_dir_all(dir)?;
    fs::write(dir.join(".lock"), b"lock")?;
    fs::write(dir.join("process-epoch"), b"12345")?;
    fs::write(dir.join(".CURRENT_SCHEMA.tmp"), b"temp")?;
    Ok(())
}

pub(crate) fn assert_independent_files_copied_and_ignored_skipped(
    dest_dir: &Path,
    expected_files: &[(String, Vec<u8>)],
) -> TestResult<()> {
    for (rel_path, expected_bytes) in expected_files {
        let dest_file = dest_dir.join(rel_path);
        if !dest_file.is_file() {
            return Err(TestError::Assertion(format!(
                "expected independent file missing in destination: {rel_path}"
            )));
        }
        let actual_bytes = fs::read(&dest_file)?;
        if actual_bytes != *expected_bytes {
            return Err(TestError::Assertion(format!(
                "byte mismatch in copied independent file: {rel_path}"
            )));
        }
    }

    let ignored = [".lock", "process-epoch", ".CURRENT_SCHEMA.tmp"];
    for name in ignored {
        let dest_file = dest_dir.join(name);
        if dest_file.exists() {
            return Err(TestError::Assertion(format!(
                "ignored file was erroneously copied to destination: {name}"
            )));
        }
    }

    Ok(())
}
