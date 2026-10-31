#[cfg(any(feature = "fjall", feature = "redb", feature = "rocksdb"))]
mod bench_runner {
    use std::path::Path;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use bitcoin_rs_index::{
        ConsumerCursorUpdate, IndexCapabilities, IndexReader, IndexWatermark, IndexWriter, Indexer,
        PreparedBatch, PreparedBatchLimits, ScriptHash, SpentCoinScripts,
    };
    use bitcoin_rs_primitives::{Hash256, encode};
    use bitcoin_rs_storage::{KvStore, PrefixScanLimit};

    #[derive(Debug, thiserror::Error)]
    enum BenchError {
        #[error(transparent)]
        Index(#[from] bitcoin_rs_index::IndexError),
        #[error(transparent)]
        Storage(#[from] bitcoin_rs_storage::StorageError),
        #[error(transparent)]
        TryFromInt(#[from] std::num::TryFromIntError),
        #[error("missing {0}")]
        Missing(&'static str),
    }

    impl From<&'static str> for BenchError {
        fn from(value: &'static str) -> Self {
            Self::Missing(value)
        }
    }

    const CHAIN_BLOCKS: u32 = 20_000;

    const REORG_DEPTH: u32 = 6;

    const QUERY_SAMPLES: usize = 200;

    const SCAN_LIMIT: PrefixScanLimit = PrefixScanLimit {
        max_rows: 1_000_000,
        max_bytes: 64 << 20,
    };

    #[derive(Clone, Copy, Debug)]
    enum Family {
        TxLookup,
        ScriptHistory,
        ScriptLive,
    }

    impl Family {
        const fn name(self) -> &'static str {
            match self {
                Self::TxLookup => "tx_lookup",
                Self::ScriptHistory => "script_history",
                Self::ScriptLive => "script_live",
            }
        }

        const fn capabilities(self) -> IndexCapabilities {
            match self {
                Self::TxLookup => IndexCapabilities::TX_LOOKUP,
                Self::ScriptHistory => IndexCapabilities::SCRIPT_HISTORY,
                Self::ScriptLive => IndexCapabilities::SCRIPT_LIVE,
            }
        }
    }

    struct FixedSpentScripts {
        script: Vec<u8>,
    }

    impl SpentCoinScripts for FixedSpentScripts {
        fn script_bytes(&self, _txid: &[u8; 32], _vout: u32) -> Option<&[u8]> {
            Some(&self.script)
        }
    }

    fn script_for(seed: u32) -> Vec<u8> {
        let mut script = Vec::with_capacity(22);
        script.push(0x00);
        script.push(0x14);
        script.extend_from_slice(&[0x11; 20]);
        script[2] = u8::try_from(seed % 251).expect("modulo stays in byte range");
        script
    }

    fn block_body(previous: Hash256, height: u32) -> (Hash256, Vec<u8>) {
        let mut body = Vec::with_capacity(4_096);
        body.extend_from_slice(&1_i32.to_le_bytes());
        body.extend_from_slice(&previous.to_le_bytes());
        body.extend_from_slice(&[0_u8; 32]);
        body.extend_from_slice(&(1_600_000_000_u32.saturating_add(height)).to_le_bytes());
        body.extend_from_slice(&0x207F_FFFF_u32.to_le_bytes());
        body.extend_from_slice(&0_u32.to_le_bytes());
        body.push(9);

        body.extend_from_slice(&1_u32.to_le_bytes());
        body.push(0x01);
        body.extend_from_slice(&[0_u8; 32]);
        body.extend_from_slice(&u32::MAX.to_le_bytes());
        body.push(0x02);
        body.extend_from_slice(&[u8::try_from(height % 251).expect("height residue"), 0xFF]);
        body.extend_from_slice(&0xFFFF_FFFF_u32.to_le_bytes());
        body.push(0x01);
        body.extend_from_slice(&500_000_000_u64.to_le_bytes());
        let coinbase_script = script_for(height);
        body.push(u8::try_from(coinbase_script.len()).expect("script length fits a byte"));
        body.extend_from_slice(&coinbase_script);
        body.extend_from_slice(&0_u32.to_le_bytes());

        for index in 0..8_u32 {
            body.extend_from_slice(&1_u32.to_le_bytes());
            body.push(0x01);
            let mut funding = [0_u8; 32];
            funding[..4].copy_from_slice(&height.to_le_bytes());
            funding[4..8].copy_from_slice(&index.to_le_bytes());
            body.extend_from_slice(&funding);
            body.extend_from_slice(&index.to_le_bytes());
            body.push(0x00);
            body.extend_from_slice(&0xFFFF_FFFF_u32.to_le_bytes());
            body.push(0x01);
            body.extend_from_slice(&1_000_000_u64.to_le_bytes());
            let payment_script = script_for(height.wrapping_add(index));
            body.push(u8::try_from(payment_script.len()).expect("script length fits a byte"));
            body.extend_from_slice(&payment_script);
            body.extend_from_slice(&0_u32.to_le_bytes());
        }

        let block_hash = encode::double_sha256(&body[..80]);
        (block_hash, body)
    }

    fn write_bytes_now() -> u64 {
        let io = std::fs::read_to_string("/proc/self/io").expect("/proc/self/io must be readable");
        io.lines()
            .find_map(|line| line.strip_prefix("write_bytes: "))
            .and_then(|value| value.trim().parse().ok())
            .expect("/proc/self/io must report write_bytes")
    }

    fn directory_bytes(path: &Path) -> u64 {
        let mut total = 0_u64;
        let mut stack = vec![path.to_path_buf()];
        while let Some(next) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&next) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                match entry.metadata() {
                    Ok(metadata) if metadata.is_dir() => stack.push(path),
                    Ok(metadata) => total = total.saturating_add(metadata.len()),
                    Err(_) => {}
                }
            }
        }
        total
    }

    fn percentile_micros(samples: &mut [Duration], percent: usize) -> u128 {
        if samples.is_empty() {
            return 0;
        }
        samples.sort_unstable();
        let index = samples.len().saturating_mul(percent) / 100;
        samples[index.min(samples.len() - 1)].as_micros()
    }

    fn max_micros(samples: &[Duration]) -> u128 {
        samples.iter().map(Duration::as_micros).max().unwrap_or(0)
    }

    struct RunReport {
        family: Family,
        backend: &'static str,
        blocks: u32,
        write_bytes: u64,
        logical_bytes: u64,
        build: Duration,
        snapshot_open: Duration,
        footprint: u64,
        query_p50: u128,
        query_p95: u128,
        query_p99: u128,
        query_max: u128,
        reorg: Duration,
    }

    fn print_report(report: &RunReport) {
        let amplification_permille = if report.logical_bytes == 0 {
            0
        } else {
            report.write_bytes.saturating_mul(1_000) / report.logical_bytes
        };
        println!(
            "family={} backend={} blocks={} write_bytes={} logical_bytes={} amplification_permille={} \
         build_ms={} snapshot_open_us={} footprint_bytes={} query_p50_us={} query_p95_us={} \
         query_p99_us={} query_max_us={} reorg_us={}",
            report.family.name(),
            report.backend,
            report.blocks,
            report.write_bytes,
            report.logical_bytes,
            amplification_permille,
            report.build.as_millis(),
            report.snapshot_open.as_micros(),
            report.footprint,
            report.query_p50,
            report.query_p95,
            report.query_p99,
            report.query_max,
            report.reorg.as_micros(),
        );
    }

    fn measure<S>(
        family: Family,
        backend: &'static str,
        store: &Arc<S>,
        dir: &Path,
    ) -> Result<RunReport, BenchError>
    where
        S: KvStore + Send + Sync + 'static,
    {
        let script = script_for(0);
        let scripthash = ScriptHash::from_script_bytes(&script);
        let scripthash_prefix = scripthash;
        let spent = FixedSpentScripts { script };
        let capabilities = family.capabilities();
        let mut writer = IndexWriter::open(Arc::clone(store), 1)?;
        let footprint_baseline = directory_bytes(dir);

        let mut watermarks: Vec<IndexWatermark> = Vec::with_capacity(CHAIN_BLOCKS as usize);
        let mut bodies: Vec<Vec<u8>> = Vec::with_capacity(REORG_DEPTH as usize);
        let mut previous = Hash256::from_le_bytes(&[0; 32]);
        let mut logical_bytes = 0_u64;
        let write_before = write_bytes_now();
        let build_started = Instant::now();
        for height in 0..CHAIN_BLOCKS {
            let (hash, body) = block_body(previous, height);
            let prepared = writer.prepare_block_with_spent_scripts(
                capabilities,
                height,
                hash.to_le_bytes(),
                &body,
                &spent,
            )?;
            logical_bytes = logical_bytes.saturating_add(u64::try_from(prepared.encoded_bytes)?);
            let mut batch = PreparedBatch::new(PreparedBatchLimits {
                max_rows: usize::MAX,
                max_bytes: usize::MAX,
            });
            if batch.try_push(prepared).is_err() {
                return Err("single-block batch refused the block".into());
            }
            let watermark = writer.commit_forward(batch)?;
            bodies.push(body);
            if bodies.len() > REORG_DEPTH as usize {
                bodies.remove(0);
            }
            watermarks.push(watermark);
            previous = hash;
        }
        let build = build_started.elapsed();
        let write_bytes = write_bytes_now().saturating_sub(write_before);
        drop(writer);

        let snapshot_started = Instant::now();
        let reader = Indexer::new(Arc::clone(store));
        let snapshot = reader.snapshot()?;
        let snapshot_open = snapshot_started.elapsed();

        let mut samples = Vec::with_capacity(QUERY_SAMPLES);
        for _ in 0..QUERY_SAMPLES {
            let started = Instant::now();
            let rows = match family {
                Family::ScriptHistory => snapshot
                    .funding_rows(scripthash_prefix, SCAN_LIMIT)?
                    .rows
                    .len(),
                Family::ScriptLive => snapshot
                    .live_rows(scripthash_prefix, SCAN_LIMIT)?
                    .rows
                    .len(),
                Family::TxLookup => {
                    let txid = bitcoin_rs_primitives::Txid(
                        bitcoin_rs_primitives::Hash256::from_le_bytes(&[0; 32]),
                    );
                    snapshot.transaction_rows(&txid, SCAN_LIMIT)?.rows.len()
                }
            };
            std::hint::black_box(rows);
            samples.push(started.elapsed());
        }
        drop(snapshot);

        let reorg_started = Instant::now();
        let mut writer = IndexWriter::open(Arc::clone(store), 1)?;
        for depth in 0..REORG_DEPTH {
            let height = CHAIN_BLOCKS - 1 - depth;
            let (fence, _) = writer.fenced_watermarks()?;
            let prev = if height == 0 {
                None
            } else {
                Some(watermarks[height as usize - 1])
            };
            let body = &bodies[bodies.len() - 1 - depth as usize];
            writer.commit_rollback_one_for_with_cursor_with_spent_scripts(
                fence,
                capabilities,
                prev,
                body,
                ConsumerCursorUpdate::Keep,
                &spent,
            )?;
        }
        let reorg = reorg_started.elapsed();
        drop(writer);

        Ok(RunReport {
            family,
            backend,
            blocks: CHAIN_BLOCKS,
            write_bytes,
            logical_bytes,
            build,
            snapshot_open,
            footprint: directory_bytes(dir).saturating_sub(footprint_baseline),
            query_p50: percentile_micros(&mut samples, 50),
            query_p95: percentile_micros(&mut samples, 95),
            query_p99: percentile_micros(&mut samples, 99),
            query_max: max_micros(&samples),
            reorg,
        })
    }

    macro_rules! backend_run {
        ($backend:literal, $open:path) => {{
            let root = tempfile::tempdir().expect("temporary datadir");
            for family in [Family::TxLookup, Family::ScriptHistory, Family::ScriptLive] {
                let dir = root.path().join(family.name());
                std::fs::create_dir_all(&dir).expect("family directory");
                let store = Arc::new($open(&dir).expect("store opens"));
                match measure(family, $backend, &store, &dir) {
                    Ok(report) => print_report(&report),
                    Err(error) => println!(
                        "family={} backend={} failed: {error}",
                        family.name(),
                        $backend
                    ),
                }
            }
        }};
    }
    pub(super) fn run() {
        #[cfg(feature = "fjall")]
        backend_run!("fjall", bitcoin_rs_storage::FjallStore::open);
        #[cfg(all(feature = "redb", not(feature = "fjall")))]
        backend_run!("redb", bitcoin_rs_storage::RedbStore::open);
        #[cfg(all(feature = "rocksdb", not(feature = "fjall"), not(feature = "redb")))]
        backend_run!("rocksdb", bitcoin_rs_storage::RocksDbStore::open);
    }
}

#[cfg(any(feature = "fjall", feature = "redb", feature = "rocksdb"))]
fn main() {
    bench_runner::run();
}

#[cfg(not(any(feature = "fjall", feature = "redb", feature = "rocksdb")))]
fn main() {
    println!("no storage backend feature selected; run with --features fjall|redb|rocksdb");
}
