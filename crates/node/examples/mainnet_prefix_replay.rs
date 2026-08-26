#![allow(missing_docs)]
#![allow(clippy::print_stdout)]

#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::ffi::OsString;
#[cfg(feature = "checksig-census")]
use std::fs::OpenOptions;
use std::io::BufReader;
#[cfg(feature = "checksig-census")]
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use bitcoin::consensus::Decodable as _;
use bitcoin::hashes::Hash as _;
use bitcoin::hex::{DisplayHex as _, FromHex as _};
use bitcoin::{Block, BlockHash, Weight};
#[cfg(feature = "checksig-census")]
use bitcoin_rs_consensus::census_checkpoint;
use bitcoin_rs_node::Network;
use bitcoin_rs_node::config::Config;
use bitcoin_rs_node::corpus::CorpusManifest;
use bitcoin_rs_node::corpus::{CoreRestClient, CoreRestError, FetchedBlock, fetch_rest_block};
use bitcoin_rs_node::state::NodeState;
use bitcoin_rs_storage::CoreFrameReader;
use serde_json::json;
use sha2::{Digest as _, Sha256};

/// Consensus-maximum serialized block size in bytes, derived from the
/// maximum block weight (BIP 141). No valid serialized block can be larger.
#[allow(clippy::as_conversions, clippy::cast_possible_truncation)]
const MAX_SERIALIZED_BLOCK_SIZE: u32 = Weight::MAX_BLOCK.to_wu() as u32;
const TXINDEX_POLL_INTERVAL: Duration = Duration::from_millis(10);
const TXINDEX_NO_PROGRESS_TIMEOUT: Duration = Duration::from_secs(30);

/// A reader that hashes every byte it yields.
///
/// Used so a Core-framed archive can be verified with a single streaming pass.
struct HashingReader<R> {
    inner: R,
    state: Sha256,
    bytes_read: u64,
}

impl<R: std::io::Read> HashingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            state: Sha256::new(),
            bytes_read: 0,
        }
    }

    fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    fn digest(&self) -> [u8; 32] {
        let out = self.state.clone().finalize();
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(out.as_ref());
        bytes
    }
}

impl<R: std::io::Read> std::io::Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.state.update(&buf[..n]);
            let increment = u64::try_from(n)
                .map_err(|_| std::io::Error::other("read length does not fit u64"))?;
            self.bytes_read = self
                .bytes_read
                .checked_add(increment)
                .ok_or_else(|| std::io::Error::other("archive byte count overflow"))?;
        }
        Ok(n)
    }
}

/// Proves a window's scripts in one dispatch, then applies its blocks in order.
///
/// Headers go in first because the batch reads median-time-past and softfork
/// state from the block tree, and a header-first peer would have put them there
/// Returns true once the accumulated window should be applied.
///
/// Applies the same byte cap production does, so a replay measures the window
/// production would actually form rather than a larger one. The byte total is
/// accumulated by the caller rather than re-summed here: the window holds up to
/// a thousand blocks and this runs once per block.
/// Totals the replay reports, gathered while it walks the prefix.
struct ReplayTotals {
    start_hash: Option<String>,
    stop_hash: Option<String>,
    tx_count: usize,
    block_bytes: usize,
    fetch_time: Duration,
    decode_time: Duration,
    elapsed: Duration,
}

/// Walks `start_height..=stop_height`, applying each window as it fills.
fn replay_prefix(
    args: &Args,
    manifest: Option<&CorpusManifest>,
    apply_handles: &bitcoin_rs_node::apply::ApplyHandles,
) -> Result<ReplayTotals> {
    let mut tx_count = 0_usize;
    let mut block_bytes = 0_usize;
    let mut fetch_time = Duration::ZERO;
    let mut decode_time = Duration::ZERO;
    let started = Instant::now();
    let mut start_hash = None;
    let mut stop_hash = None;
    let mut prev_hash: Option<BlockHash> = None;

    let window = args.window.max(1);
    let mut source = open_block_source(args, apply_handles.network, manifest)?;
    let mut window_blocks: Vec<Block> = Vec::new();
    let mut window_bytes: Vec<bytes::Bytes> = Vec::new();
    let mut window_bytes_held = 0_usize;
    for height in args.start_height..=args.stop_height {
        let fetch_started = Instant::now();
        let (hash, bytes) = source.fetch(height)?;
        fetch_time += fetch_started.elapsed();
        if height == args.start_height {
            start_hash = Some(hash.clone());
        }
        if height == args.stop_height {
            stop_hash = Some(hash.clone());
        }
        let decode_started = Instant::now();
        let mut cursor = std::io::Cursor::new(bytes.as_slice());
        let block = Block::consensus_decode(&mut cursor)
            .with_context(|| format!("decode block bytes at height {height}"))?;
        let consumed = cursor.position();
        let payload_length =
            u64::try_from(bytes.len()).context("block payload length does not fit u64")?;
        if consumed != payload_length {
            let consumed =
                usize::try_from(consumed).context("decoded block length does not fit usize")?;
            let trailing = bytes
                .len()
                .checked_sub(consumed)
                .context("decoder consumed beyond the block payload")?;
            bail!("block payload at height {height} has {trailing} trailing bytes");
        }
        decode_time += decode_started.elapsed();

        let actual_hash = block.block_hash();
        if actual_hash.to_string() != hash {
            bail!("block hash mismatch at height {height}: source {hash}, decoded {actual_hash}");
        }
        if height == 0 {
            if block.header.prev_blockhash != BlockHash::from_byte_array([0; 32]) {
                bail!(
                    "genesis block at height 0 has non-zero prev_blockhash {}",
                    block.header.prev_blockhash
                );
            }
            if actual_hash.to_string() != apply_handles.network.genesis_block_hash().to_string_be()
            {
                bail!(
                    "genesis block hash mismatch at height 0: expected {}, got {actual_hash}",
                    apply_handles.network.genesis_block_hash().to_string_be()
                );
            }
        } else if let Some(prev) = prev_hash {
            if block.header.prev_blockhash != prev {
                bail!(
                    "prev_blockhash mismatch at height {height}: expected {prev}, got {}",
                    block.header.prev_blockhash
                );
            }
        }
        prev_hash = Some(actual_hash);

        tx_count = tx_count.saturating_add(block.txdata.len());
        block_bytes = block_bytes.saturating_add(bytes.len());
        // Flushed BEFORE appending when this block would cross the byte cap,
        // which is what `window_len` does: it leaves the crossing block for the
        // next window. Appending first and checking after let a replay window
        // exceed the cap by a whole block, so its batch boundaries were not
        // production's and the timings near the cap were not comparable.
        if !window_blocks.is_empty()
            && window_bytes_held.saturating_add(bytes.len())
                > bitcoin_rs_node::apply::SCRIPT_BATCH_MAX_BYTES
        {
            apply_window(apply_handles, &mut window_blocks, &mut window_bytes)?;
            window_bytes_held = 0;
        }
        window_blocks.push(block);
        window_bytes_held = window_bytes_held.saturating_add(bytes.len());
        window_bytes.push(bytes::Bytes::from(bytes));
        if window_blocks.len() >= window {
            apply_window(apply_handles, &mut window_blocks, &mut window_bytes)?;
            window_bytes_held = 0;
        }
    }
    source
        .ensure_eof()
        .with_context(|| "trailing data in Core-framed archive")?;
    apply_window(apply_handles, &mut window_blocks, &mut window_bytes)?;
    Ok(ReplayTotals {
        start_hash,
        stop_hash,
        tx_count,
        block_bytes,
        fetch_time,
        decode_time,
        elapsed: started.elapsed(),
    })
}

/// Inserts headers before applying a window.
///
/// Production receives headers before block bodies. The replay must do the
/// same or the window cannot prove and the driver measures the unbatched path.
fn apply_window(
    handles: &bitcoin_rs_node::apply::ApplyHandles,
    blocks: &mut Vec<Block>,
    raw: &mut Vec<bytes::Bytes>,
) -> Result<()> {
    if blocks.is_empty() {
        return Ok(());
    }
    let headers: Vec<bitcoin::block::Header> = blocks.iter().map(|block| block.header).collect();
    {
        let mut tree = handles.block_tree.write();
        bitcoin_rs_chain::header_sync::accept_headers(
            &mut tree,
            &headers,
            handles.network,
            bitcoin_rs_chain::current_unix_seconds(),
        )
        .context("accept window headers")?;
    }
    let borrowed: Vec<&Block> = blocks.iter().collect();
    bitcoin_rs_node::apply::apply_window(handles, &borrowed, raw).map_err(|error| {
        // Name the block that failed. Most `ApplyError`s carry no height or
        // hash, so a bare "apply window" leaves a 64-block range to search and
        // nothing to resume from. `applied` is the count that committed, so the
        // block at that index is the one that stopped it.
        let blame = borrowed.get(error.applied).map_or_else(
            || "unknown block".to_owned(),
            |block| format!("block {}", block.block_hash()),
        );
        anyhow::Error::new(error.source).context(format!(
            "apply window: {blame} failed after {} of {} blocks committed",
            error.applied,
            borrowed.len()
        ))
    })?;
    blocks.clear();
    raw.clear();
    Ok(())
}

#[derive(Debug)]
struct FileInputs {
    manifest: CorpusManifest,
    manifest_path: PathBuf,
    manifest_bytes_len: u64,
    manifest_sha: [u8; 32],
    blocks_path: PathBuf,
}

fn prepare_file_inputs(args: &Args) -> Result<FileInputs> {
    let blocks_path = args
        .blocks_file
        .as_ref()
        .context("file mode requires --blocks-file")?;
    let manifest_path = args
        .corpus_manifest
        .as_ref()
        .context("file mode requires --corpus-manifest")?;
    let (manifest, manifest_bytes) = CorpusManifest::load_with_bytes(manifest_path)
        .with_context(|| format!("load corpus manifest {}", manifest_path.display()))?;
    if manifest.network != Network::Mainnet {
        bail!(
            "corpus manifest network is {:?}, expected mainnet",
            manifest.network
        );
    }
    if manifest.genesis_hash != Network::Mainnet.genesis_block_hash() {
        bail!(
            "corpus manifest genesis hash {} does not match mainnet genesis {}",
            manifest.genesis_hash.to_string_be(),
            Network::Mainnet.genesis_block_hash().to_string_be()
        );
    }
    if manifest.start_height != 0 {
        bail!(
            "corpus manifest start height is {}, expected 0",
            manifest.start_height
        );
    }
    if manifest.stop_height != args.stop_height {
        bail!(
            "corpus manifest stop height {} does not match --stop-height {}",
            manifest.stop_height,
            args.stop_height
        );
    }
    let archive_size = std::fs::metadata(blocks_path)
        .with_context(|| format!("stat archive {}", blocks_path.display()))?
        .len();
    if archive_size != manifest.archive.size {
        bail!(
            "archive size {} does not match manifest {} for {}",
            archive_size,
            manifest.archive.size,
            blocks_path.display()
        );
    }
    let manifest_digest = Sha256::digest(&manifest_bytes);
    let mut manifest_sha = [0_u8; 32];
    manifest_sha.copy_from_slice(manifest_digest.as_ref());
    let manifest_bytes_len =
        u64::try_from(manifest_bytes.len()).context("manifest length does not fit u64")?;
    Ok(FileInputs {
        manifest,
        manifest_path: manifest_path.clone(),
        manifest_bytes_len,
        manifest_sha,
        blocks_path: blocks_path.clone(),
    })
}
fn main() -> Result<()> {
    let args = Args::parse(std::env::args_os().skip(1))?;
    if args.stop_height < args.start_height {
        bail!("--stop-height must be greater than or equal to --start-height");
    }
    if args.start_height != 0 {
        bail!("mainnet prefix replay currently requires --start-height 0");
    }

    #[cfg(feature = "checksig-census")]
    validate_diagnostic_args(&args)?;

    let mut config = Config::default_for_network(Network::Mainnet);
    config.data_dir.clone_from(&args.data_dir);
    config.storage_backend.clone_from(&args.storage_backend);
    config.p2p_listen.clear();
    config.dns_seeds_enabled = false;
    config.txindex = args.txindex;
    config.assume_valid_height = args.assume_valid_height;

    // In-memory recorder for the apply path's per-stage histograms; the bind
    // address only names the future exporter endpoint and is never served.
    let metrics_handle =
        bitcoin_rs_node::metrics::install_metrics(Some(([127, 0, 0, 1], 0).into()))
            .context("install metrics recorder")?;

    // Validate manifest identity, range, and archive size before opening state.
    // The single replay read validates every frame and the final archive digest.
    let file_mode = args.blocks_file.is_some();
    let file_inputs = if file_mode {
        Some(prepare_file_inputs(&args).context("prepare file-mode inputs")?)
    } else {
        None
    };

    let state = NodeState::open(config).context("open node state")?;
    let mut apply_handles = state.apply_handles();
    // Offline tool: no header sync loop ever runs, so a hash-pinned gate would
    // stay untrusted and silently force full verification when the configured
    // height equals the network anchor. Unpin the gate so `--assume-valid-height`
    // keeps its height-only shortcut semantics for every height.
    apply_handles.assume_valid_gate =
        Arc::new(bitcoin_rs_node::apply::AssumeValidGate::with_anchor(None));

    #[cfg(feature = "checksig-census")]
    if args.census_diagnostic {
        run_census_diagnostic(&args, &apply_handles)?;
        return Ok(());
    }

    let totals = replay_prefix(
        &args,
        file_inputs.as_ref().map(|inputs| &inputs.manifest),
        &apply_handles,
    )?;
    let txindex_catchup = if args.txindex {
        Some(wait_for_txindex(&state)?)
    } else {
        None
    };
    // The full UTXO scan is opt-in and starts after the internal replay timer.
    // Performance custody runs must omit it because process wall and CPU still
    // include the scan; separate validation runs pass this option.
    if let Some(path) = args.validation_output.as_deref() {
        write_validation_artifact(
            path,
            &apply_handles,
            args.stop_height,
            totals.stop_hash.as_deref(),
        )?;
    }
    let artifact = build_replay_artifact(
        &args,
        &state,
        file_inputs.as_ref(),
        &totals,
        txindex_catchup,
        metrics_handle,
    )?;
    let rendered = serde_json::to_string_pretty(&artifact).context("render artifact JSON")?;
    if let Some(output) = args.output {
        std::fs::write(&output, rendered + "\n")
            .with_context(|| format!("write {}", output.display()))?;
    } else {
        println!("{rendered}");
    }
    Ok(())
}

struct ArtifactMetrics {
    block_count: u32,
    window: usize,
    window_verify_success_total: u64,
    stage_seconds: Vec<serde_json::Value>,
    rss_high_water_bytes: Option<u64>,
    txindex_worker_catchup_seconds: Option<f64>,
    txindex_total_elapsed_seconds: Option<f64>,
}

fn build_replay_artifact(
    args: &Args,
    state: &NodeState,
    file_inputs: Option<&FileInputs>,
    totals: &ReplayTotals,
    txindex_catchup: Option<Duration>,
    metrics_handle: Option<bitcoin_rs_node::metrics::MetricsHandle>,
) -> Result<serde_json::Value> {
    let snapshot = metrics_handle
        .as_ref()
        .map(bitcoin_rs_node::metrics::MetricsHandle::snapshot)
        .unwrap_or_default();
    let metrics = ArtifactMetrics {
        block_count: args
            .stop_height
            .saturating_sub(args.start_height)
            .saturating_add(1),
        window: args.window.max(1),
        window_verify_success_total: counter_value(&snapshot, "node.window.verify_success_total"),
        stage_seconds: stage_decomposition(metrics_handle),
        rss_high_water_bytes: rss_high_water_bytes(),
        txindex_worker_catchup_seconds: txindex_catchup.map(|elapsed| elapsed.as_secs_f64()),
        txindex_total_elapsed_seconds: txindex_catchup
            .map(|catchup| totals.elapsed.saturating_add(catchup).as_secs_f64()),
    };
    let Some(inputs) = file_inputs else {
        return Ok(legacy_replay_artifact(args, totals, &metrics));
    };
    if metrics.window <= 1 {
        bail!("file custody requires --window > 1");
    }
    if metrics.window_verify_success_total == 0 {
        bail!("file custody requires at least one successful window verification dispatch");
    }
    let checkpoint_generation = state
        .publish_checkpoint()
        .context("publish clean checkpoint")?;
    Ok(file_replay_artifact(
        args,
        inputs,
        totals,
        &metrics,
        checkpoint_generation,
    ))
}

fn file_replay_artifact(
    args: &Args,
    inputs: &FileInputs,
    totals: &ReplayTotals,
    metrics: &ArtifactMetrics,
    checkpoint_generation: u64,
) -> serde_json::Value {
    json!({
        "schema": "mainnet-prefix-replay-v3",
        "measurement_target": "mainnet-prefix-replay",
        "git_head": git_head().ok(),
        "network": "mainnet",
        "network_magic": inputs.manifest.network_magic.as_slice().to_lower_hex_string(),
        "genesis_hash": inputs.manifest.genesis_hash.to_string_be(),
        "corpus_manifest": {
            "schema": CorpusManifest::SCHEMA,
            "version": CorpusManifest::VERSION,
            "path": &inputs.manifest_path,
            "bytes": inputs.manifest_bytes_len,
            "sha256": inputs.manifest_sha.as_slice().to_lower_hex_string(),
        },
        "archive": {
            "path": &inputs.blocks_path,
            "bytes": inputs.manifest.archive.size,
            "sha256": inputs.manifest.archive.sha256.as_slice().to_lower_hex_string(),
        },
        "start_height": args.start_height,
        "start_hash": &totals.start_hash,
        "stop_height": args.stop_height,
        "stop_hash": &totals.stop_hash,
        "assume_valid_height": args.assume_valid_height,
        "window": metrics.window,
        "window_verify_success_total": metrics.window_verify_success_total,
        "checkpoint_generation": checkpoint_generation,
        "storage_backend": &args.storage_backend,
        "txindex": args.txindex,
        "block_count": metrics.block_count,
        "tx_count": totals.tx_count,
        "block_bytes": totals.block_bytes,
        "elapsed_seconds": totals.elapsed.as_secs_f64(),
        "blocks_per_second": f64::from(metrics.block_count) / totals.elapsed.as_secs_f64(),
        "fetch_seconds": totals.fetch_time.as_secs_f64(),
        "decode_seconds": totals.decode_time.as_secs_f64(),
        "stage_seconds": &metrics.stage_seconds,
        "rss_high_water_bytes": metrics.rss_high_water_bytes,
        "txindex_worker_catchup_seconds": metrics.txindex_worker_catchup_seconds,
        "txindex_total_elapsed_seconds": metrics.txindex_total_elapsed_seconds,
        "block_source": "file",
        "data_dir": &args.data_dir,
    })
}

fn legacy_replay_artifact(
    args: &Args,
    totals: &ReplayTotals,
    metrics: &ArtifactMetrics,
) -> serde_json::Value {
    let block_source = if args.rest_url.is_some() {
        "rest"
    } else {
        "bitcoin-cli"
    };
    json!({
        "schema": "mainnet-prefix-replay-v1",
        "measurement_target": "mainnet-prefix-replay",
        "git_head": git_head().ok(),
        "storage_backend": &args.storage_backend,
        "txindex": args.txindex,
        "assume_valid_height": args.assume_valid_height,
        "window": metrics.window,
        "start_height": args.start_height,
        "start_hash": &totals.start_hash,
        "stop_height": args.stop_height,
        "stop_hash": &totals.stop_hash,
        "block_count": metrics.block_count,
        "tx_count": totals.tx_count,
        "block_bytes": totals.block_bytes,
        "elapsed_seconds": totals.elapsed.as_secs_f64(),
        "blocks_per_second": f64::from(metrics.block_count) / totals.elapsed.as_secs_f64(),
        "fetch_seconds": totals.fetch_time.as_secs_f64(),
        "decode_seconds": totals.decode_time.as_secs_f64(),
        "stage_seconds": &metrics.stage_seconds,
        "rss_high_water_bytes": metrics.rss_high_water_bytes,
        "txindex_worker_catchup_seconds": metrics.txindex_worker_catchup_seconds,
        "txindex_total_elapsed_seconds": metrics.txindex_total_elapsed_seconds,
        "bitcoin_cli": &args.bitcoin_cli,
        "bitcoin_cli_args": &args.bitcoin_cli_args,
        "block_source": block_source,
        "rest_url": &args.rest_url,
        "blocks_file": &args.blocks_file,
        "data_dir": &args.data_dir,
    })
}

fn write_validation_artifact(
    path: &Path,
    handles: &bitcoin_rs_node::apply::ApplyHandles,
    stop_height: u32,
    stop_hash: Option<&str>,
) -> Result<()> {
    let stats = handles
        .utxo
        .with_stable_view(|view| bitcoin_rs_coinstats::scan_coin_stats(view, stop_height, true))
        .context("scan UTXO set for CoinStats validation")?;
    let utxo_hash = bitcoin_rs_utxo::aggregate_hash(&handles.utxo)
        .context("compute deterministic UTXO aggregate hash")?;
    let artifact = json!({
        "schema": "mainnet-prefix-replay-validation-v1",
        "stop_height": stop_height,
        "stop_hash": stop_hash,
        "utxo_hash_serialized_3": utxo_hash.to_string_be(),
        "muhash": stats.muhash.finalize_hash().to_string_be(),
        "utxo_count": stats.utxo_count,
        "total_amount": stats.total_amount,
    });
    let rendered =
        serde_json::to_string_pretty(&artifact).context("render validation artifact JSON")?;
    std::fs::write(path, rendered + "\n").with_context(|| format!("write {}", path.display()))
}

#[derive(Debug)]
struct Args {
    bitcoin_cli: String,
    bitcoin_cli_args: Vec<String>,
    rest_url: Option<String>,
    /// Path to a Core-framed archive (network magic + u32 LE length + block payload).
    blocks_file: Option<PathBuf>,
    /// Path to the validated corpus manifest for the Core-framed archive.
    corpus_manifest: Option<PathBuf>,
    assume_valid_height: u32,
    data_dir: PathBuf,
    output: Option<PathBuf>,
    validation_output: Option<PathBuf>,
    window: usize,
    start_height: u32,
    stop_height: u32,
    storage_backend: String,
    txindex: bool,
    #[cfg(feature = "checksig-census")]
    census_diagnostic: bool,
}

impl Args {
    fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Self> {
        let mut parsed = Self {
            bitcoin_cli: "bitcoin-cli".to_owned(),
            bitcoin_cli_args: Vec::new(),
            rest_url: None,
            blocks_file: None,
            corpus_manifest: None,
            assume_valid_height: 0,
            data_dir: PathBuf::from(".bitcoin-rs-mainnet-prefix-replay"),
            output: None,
            validation_output: None,
            window: bitcoin_rs_node::apply::SCRIPT_BATCH_WINDOW,
            start_height: 0,
            stop_height: 0,
            storage_backend: "fjall".to_owned(),
            txindex: false,
            #[cfg(feature = "checksig-census")]
            census_diagnostic: false,
        };
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            let arg = arg
                .into_string()
                .map_err(|value| anyhow::anyhow!("argument is not UTF-8: {}", value.display()))?;
            match arg.as_str() {
                "-h" | "--help" => {
                    print_usage();
                    std::process::exit(0);
                }
                "--bitcoin-cli" => parsed.bitcoin_cli = next_arg(&mut args, "--bitcoin-cli")?,
                "--rest-url" => parsed.rest_url = Some(next_arg(&mut args, "--rest-url")?),
                "--blocks-file" => {
                    parsed.blocks_file = Some(PathBuf::from(next_arg(&mut args, "--blocks-file")?));
                }
                "--corpus-manifest" => {
                    parsed.corpus_manifest =
                        Some(PathBuf::from(next_arg(&mut args, "--corpus-manifest")?));
                }
                "--assume-valid-height" => {
                    parsed.assume_valid_height =
                        parse_height(&next_arg(&mut args, "--assume-valid-height")?)?;
                }
                "--bitcoin-cli-arg" => {
                    parsed
                        .bitcoin_cli_args
                        .push(next_arg(&mut args, "--bitcoin-cli-arg")?);
                }
                "--data-dir" => parsed.data_dir = PathBuf::from(next_arg(&mut args, "--data-dir")?),
                "--output" => parsed.output = Some(PathBuf::from(next_arg(&mut args, "--output")?)),
                "--validation-output" => {
                    parsed.validation_output =
                        Some(PathBuf::from(next_arg(&mut args, "--validation-output")?));
                }
                "--window" => parsed.window = next_arg(&mut args, "--window")?.parse()?,
                "--start-height" => {
                    parsed.start_height = parse_height(&next_arg(&mut args, "--start-height")?)?;
                }
                "--stop-height" => {
                    parsed.stop_height = parse_height(&next_arg(&mut args, "--stop-height")?)?;
                }
                "--storage-backend" => {
                    parsed.storage_backend = next_arg(&mut args, "--storage-backend")?;
                }
                "--txindex" => parsed.txindex = true,
                #[cfg(feature = "checksig-census")]
                "--cmodern-diagnostic-protocol" => parsed.census_diagnostic = true,
                #[cfg(not(feature = "checksig-census"))]
                "--cmodern-diagnostic-protocol" => {
                    bail!("--cmodern-diagnostic-protocol requires the checksig-census feature")
                }
                other => bail!("unknown argument: {other}"),
            }
        }
        if parsed.blocks_file.is_some() != parsed.corpus_manifest.is_some() {
            bail!("--blocks-file and --corpus-manifest must be provided together");
        }
        Ok(parsed)
    }
}

/// Every histogram the node recorded during the replay (apply stages, storage,
/// utxo — and anything added later), sorted by total time descending.
/// Deliberately unfiltered: a surprise entry in this list is diagnostic
/// signal, not noise.
fn counter_value(
    snapshot: &hashbrown::HashMap<String, bitcoin_rs_node::metrics::MetricValue>,
    name: &str,
) -> u64 {
    match snapshot.get(name) {
        Some(bitcoin_rs_node::metrics::MetricValue::Counter(value)) => *value,
        _ => 0,
    }
}

fn stage_decomposition(
    handle: Option<bitcoin_rs_node::metrics::MetricsHandle>,
) -> Vec<serde_json::Value> {
    let Some(handle) = handle else {
        return Vec::new();
    };
    let mut stages: Vec<(String, u64, f64)> = handle
        .snapshot()
        .into_iter()
        .filter_map(|(name, value)| match value {
            bitcoin_rs_node::metrics::MetricValue::Histogram { count, sum } => {
                Some((name, count, sum))
            }
            _ => None,
        })
        .collect();
    stages.sort_by(|a, b| b.2.total_cmp(&a.2));
    stages
        .into_iter()
        .map(|(name, count, sum)| json!({"stage": name, "count": count, "sum_seconds": sum}))
        .collect()
}

fn next_arg(args: &mut impl Iterator<Item = OsString>, name: &str) -> Result<String> {
    args.next()
        .with_context(|| format!("{name} requires a value"))?
        .into_string()
        .map_err(|value| anyhow::anyhow!("{name} value is not UTF-8: {}", value.display()))
}

fn parse_height(value: &str) -> Result<u32> {
    value
        .parse()
        .with_context(|| format!("parse height {value:?}"))
}

/// Where replay blocks come from: per-call `bitcoin-cli` spawns or a prefetch
/// thread reading ahead over a persistent REST socket.
/// Picks the block source, preferring a local Core-framed archive over REST.
///
/// The file source must win outright: building the REST source spawns a
/// prefetch thread, so choosing it first and discarding it would start an
/// HTTP pipeline the run never reads.
fn open_block_source<'a>(
    args: &'a Args,
    network: Network,
    manifest: Option<&CorpusManifest>,
) -> Result<BlockSource<'a>> {
    if let Some(path) = args.blocks_file.as_ref() {
        let manifest = manifest
            .with_context(|| "file mode requires a corpus manifest")?
            .clone();
        let file = std::fs::File::open(path)
            .with_context(|| format!("open Core-framed archive {}", path.display()))?;
        let reader = CoreFrameReader::new(
            HashingReader::new(BufReader::with_capacity(1 << 20, file)),
            network.magic(),
            MAX_SERIALIZED_BLOCK_SIZE,
        );
        return Ok(BlockSource::File {
            reader: Box::new(reader),
            manifest,
            next_index: 0,
        });
    }
    match &args.rest_url {
        Some(host) => Ok(BlockSource::Rest(spawn_prefetch(
            host,
            args.start_height,
            args.stop_height,
        )?)),
        None => Ok(BlockSource::Cli(args)),
    }
}

enum BlockSource<'a> {
    Cli(&'a Args),
    Rest(crossbeam_channel::Receiver<Result<FetchedBlock>>),
    /// Blocks read sequentially from a local Core-framed archive.
    ///
    /// Each frame is the Bitcoin Core `-loadblock` wire format:
    /// `network magic + u32 little-endian length + consensus block payload`.
    /// Core's `-loadblock` reads the same bytes, so this source removes the
    /// HTTP / second-process CPU overhead that a REST fetch adds.
    File {
        reader: Box<CoreFrameReader<HashingReader<BufReader<std::fs::File>>>>,
        manifest: CorpusManifest,
        next_index: usize,
    },
}

impl BlockSource<'_> {
    /// Returns `(block_hash_hex, raw_block_bytes)` for `height`.
    fn fetch(&mut self, height: u32) -> Result<FetchedBlock> {
        match self {
            Self::Cli(args) => {
                let hash = bitcoin_cli(args, ["getblockhash".to_owned(), height.to_string()])
                    .with_context(|| format!("get block hash at height {height}"))?;
                let block_payload_hex =
                    bitcoin_cli(args, ["getblock".to_owned(), hash.clone(), "0".to_owned()])
                        .with_context(|| format!("get block {hash} at height {height}"))?;
                let bytes = Vec::<u8>::from_hex(block_payload_hex.trim())
                    .with_context(|| format!("decode block hex at height {height}"))?;
                Ok((hash, bytes))
            }
            Self::Rest(receiver) => receiver
                .recv()
                .with_context(|| format!("prefetch thread gone before height {height}"))?,
            Self::File {
                reader,
                manifest,
                next_index,
            } => {
                let offset = reader.offset();
                let record = reader.next_record().with_context(|| {
                    format!("read Core frame at offset {offset} for height {height}")
                })?;
                let Some(record) = record else {
                    bail!("Core-framed archive ended at offset {offset} before height {height}");
                };
                let entry_index = *next_index;
                *next_index += 1;
                let expected_index =
                    usize::try_from(height).context("block height does not fit usize")?;
                if entry_index != expected_index {
                    bail!("manifest entry index mismatch: expected {height}, got {entry_index}");
                }
                let entry = manifest
                    .entries
                    .get(entry_index)
                    .with_context(|| format!("manifest has no entry for height {height}"))?;
                if entry.height != height {
                    bail!(
                        "manifest entry height mismatch: expected {height}, got {}",
                        entry.height
                    );
                }
                if record.metadata.offset != entry.offset {
                    bail!(
                        "frame offset mismatch at height {height}: manifest {}, archive {}",
                        entry.offset,
                        record.metadata.offset
                    );
                }
                if record.metadata.len != entry.payload_length {
                    bail!(
                        "frame payload length mismatch at height {height}: manifest {}, archive {}",
                        entry.payload_length,
                        record.metadata.len
                    );
                }
                let bytes = record.payload;
                let header = bytes
                    .get(..80)
                    .with_context(|| format!("Core frame payload at height {height} is {} bytes, shorter than a block header", bytes.len()))?;
                let hash = bitcoin::BlockHash::from_byte_array(
                    bitcoin::hashes::sha256d::Hash::hash(header).to_byte_array(),
                );
                let expected = bitcoin::BlockHash::from_byte_array(*entry.hash.as_byte_array());
                if hash != expected {
                    bail!(
                        "frame header hash mismatch at height {height}: manifest {expected}, archive {hash}"
                    );
                }
                Ok((hash.to_string(), bytes))
            }
        }
    }

    /// Fails if a Core-framed file source has more frames than the requested range
    /// or if the bytes consumed do not match the manifest's archive digest.
    fn ensure_eof(&mut self) -> Result<()> {
        match self {
            Self::File {
                reader, manifest, ..
            } => {
                let offset = reader.offset();
                match reader
                    .next_record()
                    .with_context(|| format!("trailing Core frame at offset {offset}"))?
                {
                    None => {
                        let hashing = reader.get_ref();
                        let archive_bytes = hashing.bytes_read();
                        if archive_bytes != manifest.archive.size {
                            bail!(
                                "archive size mismatch at EOF: manifest {}, read {}",
                                manifest.archive.size,
                                archive_bytes
                            );
                        }
                        let archive_digest = hashing.digest();
                        if archive_digest != manifest.archive.sha256 {
                            bail!(
                                "archive SHA-256 mismatch at EOF: manifest {}, read {}",
                                manifest.archive.sha256.as_slice().to_lower_hex_string(),
                                archive_digest.as_slice().to_lower_hex_string()
                            );
                        }
                        Ok(())
                    }
                    Some(record) => bail!(
                        "Core-framed archive has an extra frame at offset {} past --stop-height",
                        record.metadata.offset
                    ),
                }
            }
            _ => Ok(()),
        }
    }
}

/// Reads blocks ahead of the apply loop so fetch latency overlaps validation —
/// the serial round-trip-per-block fetch otherwise accounts for ~24% of replay
/// wall-clock (96s of 397s over 0..150k); a real node spends less waiting on
/// download or disk reads than other threads.
fn spawn_prefetch(
    host: &str,
    start_height: u32,
    stop_height: u32,
) -> Result<crossbeam_channel::Receiver<Result<FetchedBlock>>> {
    let mut client =
        CoreRestClient::connect(host).map_err(|e: CoreRestError| anyhow::Error::from(e))?;
    let (sender, receiver) = crossbeam_channel::bounded(32);
    std::thread::spawn(move || {
        for height in start_height..=stop_height {
            let item = fetch_rest_block(&mut client, height)
                .map_err(|e: CoreRestError| anyhow::Error::from(e));
            let failed = item.is_err();
            // A send error means the apply loop dropped the receiver; stop.
            if sender.send(item).is_err() || failed {
                return;
            }
        }
    });
    Ok(receiver)
}

fn bitcoin_cli(args: &Args, command_args: impl IntoIterator<Item = String>) -> Result<String> {
    let output = Command::new(&args.bitcoin_cli)
        .args(&args.bitcoin_cli_args)
        .args(command_args)
        .output()
        .with_context(|| format!("run {}", args.bitcoin_cli))?;
    if !output.status.success() {
        bail!(
            "{} failed with status {}: {}",
            args.bitcoin_cli,
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let stdout = String::from_utf8(output.stdout).context("bitcoin-cli stdout is not UTF-8")?;
    Ok(stdout.trim().to_owned())
}

fn git_head() -> Result<String> {
    let output = Command::new("git")
        .args(["rev-parse", "--verify", "HEAD"])
        .output()
        .context("run git rev-parse")?;
    if !output.status.success() {
        bail!("git rev-parse failed with status {}", output.status);
    }
    Ok(String::from_utf8(output.stdout)
        .context("git stdout is not UTF-8")?
        .trim()
        .to_owned())
}

fn rss_high_water_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(value) = line.strip_prefix("VmHWM:") {
            let kib = value.split_whitespace().next()?.parse::<u64>().ok()?;
            return kib.checked_mul(1024);
        }
    }
    None
}

#[cfg(feature = "checksig-census")]
const DIAGNOSTIC_ROW_MAGIC: &[u8; 8] = b"BRSHGT1\0";
#[cfg(feature = "checksig-census")]
const DIAGNOSTIC_VERSION: u32 = 1;
#[cfg(feature = "checksig-census")]
const DIAGNOSTIC_ROW_SIZE: u32 = 84;

#[cfg(feature = "checksig-census")]
fn validate_diagnostic_args(args: &Args) -> Result<()> {
    if !args.census_diagnostic {
        return Ok(());
    }
    if args.rest_url.is_none() {
        bail!("--cmodern-diagnostic-protocol requires --rest-url");
    }
    if args.blocks_file.is_some() || args.corpus_manifest.is_some() {
        bail!("--cmodern-diagnostic-protocol cannot use --blocks-file or --corpus-manifest");
    }
    if args.start_height != 0 {
        bail!("--cmodern-diagnostic-protocol requires --start-height 0");
    }
    if args.assume_valid_height != 0 {
        bail!("--cmodern-diagnostic-protocol requires --assume-valid-height 0");
    }
    if args.window != 1 {
        bail!("--cmodern-diagnostic-protocol requires --window 1");
    }
    if args.output.is_none() {
        bail!(
            "--cmodern-diagnostic-protocol requires --output because stdout is the binary protocol"
        );
    }
    if args.validation_output.is_some() {
        bail!("--cmodern-diagnostic-protocol does not support --validation-output");
    }
    for var in [
        "BRS_CENSUS_CONTEXTS",
        "BRS_CENSUS_RECORDS",
        "BRS_CENSUS_JOURNAL",
    ] {
        if std::env::var(var).is_err() {
            bail!("--cmodern-diagnostic-protocol requires the {var} environment variable");
        }
    }
    Ok(())
}

#[cfg(feature = "checksig-census")]
fn decode_and_validate_block(
    height: u32,
    hash_str: &str,
    bytes: &[u8],
    prev_hash: &mut Option<BlockHash>,
    network: Network,
) -> Result<Block> {
    let mut cursor = std::io::Cursor::new(bytes);
    let block = Block::consensus_decode(&mut cursor)
        .with_context(|| format!("decode block bytes at height {height}"))?;
    let consumed = cursor.position();
    if consumed != u64::try_from(bytes.len()).expect("block length fits u64") {
        bail!(
            "block payload at height {height} has {} trailing bytes",
            bytes.len() - usize::try_from(consumed).expect("decoded block length fits usize")
        );
    }
    let actual_hash = block.block_hash();
    if actual_hash.to_string() != hash_str {
        bail!("block hash mismatch at height {height}: source {hash_str}, decoded {actual_hash}");
    }
    if height == 0 {
        if block.header.prev_blockhash != BlockHash::from_byte_array([0; 32]) {
            bail!(
                "genesis block at height 0 has non-zero prev_blockhash {}",
                block.header.prev_blockhash
            );
        }
        if actual_hash.to_string() != network.genesis_block_hash().to_string_be() {
            bail!(
                "genesis block hash mismatch at height 0: expected {}, got {actual_hash}",
                network.genesis_block_hash().to_string_be()
            );
        }
    } else if let Some(prev) = prev_hash {
        if block.header.prev_blockhash != *prev {
            bail!(
                "prev_blockhash mismatch at height {height}: expected {prev}, got {}",
                block.header.prev_blockhash
            );
        }
    }
    *prev_hash = Some(actual_hash);
    Ok(block)
}

#[cfg(feature = "checksig-census")]
fn apply_one_block(
    handles: &bitcoin_rs_node::apply::ApplyHandles,
    block: Block,
    raw: Vec<u8>,
) -> Result<()> {
    let mut blocks = vec![block];
    let mut raw: Vec<bytes::Bytes> = vec![bytes::Bytes::from(raw)];
    apply_window(handles, &mut blocks, &mut raw)
}

#[cfg(feature = "checksig-census")]
fn write_diagnostic_preface(out: &mut impl Write) -> Result<()> {
    out.write_all(DIAGNOSTIC_ROW_MAGIC)
        .context("write diagnostic row magic")?;
    out.write_all(&DIAGNOSTIC_VERSION.to_le_bytes())
        .context("write diagnostic version")?;
    out.write_all(&DIAGNOSTIC_ROW_SIZE.to_le_bytes())
        .context("write diagnostic row size")?;
    out.flush().context("flush diagnostic preface")?;
    Ok(())
}

#[cfg(feature = "checksig-census")]
fn write_checkpoint_row(
    out: &mut impl Write,
    height: u32,
    hash: BlockHash,
    checkpoint: &census_checkpoint::CensusCheckpoint,
) -> Result<()> {
    out.write_all(&height.to_le_bytes())
        .context("write checkpoint height")?;
    out.write_all(hash.as_byte_array())
        .context("write checkpoint block hash")?;
    out.write_all(&checkpoint.context_rows.to_le_bytes())
        .context("write checkpoint context_rows")?;
    out.write_all(&checkpoint.context_end.to_le_bytes())
        .context("write checkpoint context_end")?;
    out.write_all(&checkpoint.record_rows.to_le_bytes())
        .context("write checkpoint record_rows")?;
    out.write_all(&checkpoint.record_end.to_le_bytes())
        .context("write checkpoint record_end")?;
    out.write_all(&checkpoint.journal_rows.to_le_bytes())
        .context("write checkpoint journal_rows")?;
    out.write_all(&checkpoint.journal_end.to_le_bytes())
        .context("write checkpoint journal_end")?;
    Ok(())
}

#[cfg(feature = "checksig-census")]
fn read_control_byte(stdin: &mut impl Read) -> Result<u8> {
    let mut buf = [0_u8; 1];
    stdin
        .read_exact(&mut buf)
        .context("controller closed stdin (EOF) or I/O error while reading control byte")?;
    Ok(buf[0])
}

#[cfg(feature = "checksig-census")]
fn write_diagnostic_artifact(
    args: &Args,
    actual_stop_height: u32,
    actual_stop_hash: String,
    elapsed: Duration,
) -> Result<()> {
    let output = args.output.as_deref().expect("validated --output");
    let artifact = json!({
        "schema": "mainnet-prefix-replay-diagnostic-v1",
        "non_certifying": true,
        "block_source": "rest",
        "start_height": args.start_height,
        "requested_stop_height_ceiling": args.stop_height,
        "actual_stop_height": actual_stop_height,
        "actual_stop_hash": actual_stop_hash,
        "window": 1,
        "assume_valid_height": 0,
        "stop_reason": "controller-request",
        "storage_backend": args.storage_backend,
        "txindex": args.txindex,
        "data_dir": args.data_dir,
        "elapsed_seconds": elapsed.as_secs_f64(),
    });
    let rendered =
        serde_json::to_string_pretty(&artifact).context("render diagnostic artifact JSON")?;

    ensure_diagnostic_output_absent(output)?;
    let (mut temp, mut file) = DiagnosticTempOutput::create(output)?;
    file.write_all(rendered.as_bytes()).with_context(|| {
        format!(
            "write temporary diagnostic artifact {}",
            temp.path.display()
        )
    })?;
    file.write_all(b"\n").with_context(|| {
        format!(
            "terminate temporary diagnostic artifact {}",
            temp.path.display()
        )
    })?;
    file.flush().with_context(|| {
        format!(
            "flush temporary diagnostic artifact {}",
            temp.path.display()
        )
    })?;
    file.sync_all().with_context(|| {
        format!(
            "fsync temporary diagnostic artifact {}",
            temp.path.display()
        )
    })?;
    drop(file);

    temp.publish(output)?;
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    OpenOptions::new()
        .read(true)
        .open(parent)
        .with_context(|| format!("open diagnostic output directory {}", parent.display()))?
        .sync_all()
        .with_context(|| format!("fsync diagnostic output directory {}", parent.display()))?;

    Ok(())
}

#[cfg(feature = "checksig-census")]
fn ensure_diagnostic_output_absent(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => bail!(
            "refusing to replace existing diagnostic output {}",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("inspect diagnostic output destination {}", path.display())),
    }
}

#[cfg(feature = "checksig-census")]
struct DiagnosticTempOutput {
    path: PathBuf,
    armed: bool,
}

#[cfg(feature = "checksig-census")]
impl DiagnosticTempOutput {
    fn create(target: &Path) -> Result<(Self, std::fs::File)> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
        let file_name = target.file_name().with_context(|| {
            format!(
                "diagnostic output path {} has no file name",
                target.display()
            )
        })?;
        let parent = target
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create diagnostic output directory {}", parent.display()))?;

        for _ in 0..128 {
            let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let mut temp_name = file_name.to_os_string();
            temp_name.push(format!(".tmp.{}.{id}", std::process::id()));
            let path = parent.join(&temp_name);
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => return Ok((Self { path, armed: true }, file)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("create temporary diagnostic artifact {}", path.display())
                    });
                }
            }
        }
        bail!(
            "could not reserve a temporary diagnostic artifact name beside {} after 128 attempts",
            target.display()
        )
    }

    fn publish(&mut self, target: &Path) -> Result<()> {
        rename_noreplace(&self.path, target).with_context(|| {
            format!(
                "atomically publish {} without replacing {}",
                self.path.display(),
                target.display()
            )
        })?;
        self.armed = false;
        Ok(())
    }
}

#[cfg(feature = "checksig-census")]
impl Drop for DiagnosticTempOutput {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(feature = "checksig-census")]
#[cfg(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    target_os = "redox"
))]
fn rename_noreplace(from: &Path, to: &Path) -> std::io::Result<()> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        from,
        rustix::fs::CWD,
        to,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(Into::into)
}

#[cfg(feature = "checksig-census")]
#[cfg(not(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    target_os = "redox"
)))]
fn rename_noreplace(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::hard_link(from, to)?;
    std::fs::remove_file(from)
}

#[cfg(feature = "checksig-census")]
fn run_census_diagnostic(
    args: &Args,
    apply_handles: &bitcoin_rs_node::apply::ApplyHandles,
) -> Result<()> {
    let rest_url = args.rest_url.as_deref().expect("validated --rest-url");
    let mut client =
        CoreRestClient::connect(rest_url).map_err(|e: CoreRestError| anyhow::Error::from(e))?;

    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    let stdin = std::io::stdin();
    let mut stdin = stdin.lock();

    write_diagnostic_preface(&mut stdout)?;

    let mut prev_hash = None;
    let started = Instant::now();
    let mut prev_checkpoint: Option<census_checkpoint::CensusCheckpoint> = None;

    for height in args.start_height..=args.stop_height {
        let (hash, raw) = fetch_rest_block(&mut client, height)
            .map_err(|e: CoreRestError| anyhow::Error::from(e))?;
        let block =
            decode_and_validate_block(height, &hash, &raw, &mut prev_hash, apply_handles.network)?;
        let block_hash = block.block_hash();
        apply_one_block(apply_handles, block, raw)?;
        let checkpoint = census_checkpoint::capture().context("census checkpoint")?;

        update_prev_checkpoint(&mut prev_checkpoint, checkpoint, height)
            .context("monotonicity check before checkpoint row")?;

        write_checkpoint_row(&mut stdout, height, block_hash, &checkpoint)
            .context("write checkpoint row")?;
        stdout.flush().context("flush checkpoint row to stdout")?;

        let control = read_control_byte(&mut stdin)?;
        match control {
            0x01 => {
                let actual_stop_hash = block_hash.to_string();
                census_checkpoint::flush().context("terminal flush after diagnostic stop")?;
                write_diagnostic_artifact(args, height, actual_stop_hash, started.elapsed())?;
                return Ok(());
            }
            0x00 => {
                if height == args.stop_height {
                    census_checkpoint::flush().context("terminal flush at safety ceiling")?;
                    bail!("safety ceiling exhausted without controller selection");
                }
            }
            b => bail!("invalid control byte 0x{b:02x} from controller"),
        }
    }

    census_checkpoint::flush().context("terminal flush at safety ceiling")?;
    bail!("safety ceiling exhausted without controller selection");
}

#[cfg(feature = "checksig-census")]
fn update_prev_checkpoint(
    prev: &mut Option<census_checkpoint::CensusCheckpoint>,
    next: census_checkpoint::CensusCheckpoint,
    height: u32,
) -> Result<()> {
    if let Some(prev) = prev.as_ref() {
        if !census_checkpoint::is_monotonic(prev, &next) {
            bail!("checkpoint at height {height} is not monotonic relative to the previous row");
        }
    }
    *prev = Some(next);
    Ok(())
}

fn wait_for_txindex(state: &NodeState) -> Result<Duration> {
    let query = state
        .tx_index_query()
        .context("txindex query missing while --txindex is enabled")?;
    let started = Instant::now();
    let mut last_height = None;
    let mut last_progress = Instant::now();

    loop {
        let info = query
            .index_info()
            .map_err(|error| anyhow::anyhow!("txindex catch-up failed: {error}"))?;
        if info.synced {
            return Ok(started.elapsed());
        }
        if last_height != Some(info.best_block_height) {
            last_height = Some(info.best_block_height);
            last_progress = Instant::now();
        } else if last_progress.elapsed() >= TXINDEX_NO_PROGRESS_TIMEOUT {
            bail!(
                "txindex made no progress for {} seconds at height {}",
                TXINDEX_NO_PROGRESS_TIMEOUT.as_secs(),
                info.best_block_height
            );
        }
        std::thread::sleep(TXINDEX_POLL_INTERVAL);
    }
}

fn print_usage() {
    println!(
        "usage: mainnet_prefix_replay --stop-height <height> [--blocks-file <core-framed-archive> --corpus-manifest <manifest> | --rest-url <host:port> | --bitcoin-cli <path>] [--assume-valid-height <height>] [--bitcoin-cli-arg <arg>]... [--data-dir <path>] [--output <path>] [--validation-output <path>] [--txindex]"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::Encodable as _;
    use bitcoin_rs_node::corpus::{ArchiveInfo, CorpusEntry, CorpusManifest};
    use bitcoin_rs_primitives::Hash256;
    use std::io::Cursor;

    fn regtest_genesis_bytes() -> Vec<u8> {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let mut bytes = Vec::new();
        block.consensus_encode(&mut bytes).unwrap();
        bytes
    }

    fn write_archive(magic: [u8; 4], payloads: &[&[u8]]) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut writer = bitcoin_rs_storage::CoreFrameWriter::new(&mut buf, magic);
        for payload in payloads {
            writer.write(payload).unwrap();
        }
        buf
    }

    fn manifest_for_archive(
        network: Network,
        archive: &[u8],
        payloads: &[&[u8]],
    ) -> CorpusManifest {
        let mut entries = Vec::new();
        let mut offset = 0_u64;
        for (height, payload) in payloads.iter().enumerate() {
            let header = payload
                .get(..80)
                .expect("payload must include a block header");
            let hash = Hash256::from_le_bytes(
                &bitcoin::hashes::sha256d::Hash::hash(header).to_byte_array(),
            );
            entries.push(CorpusEntry {
                height: height as u32,
                hash,
                offset,
                payload_length: payload.len() as u32,
            });
            offset = offset
                .checked_add(bitcoin_rs_storage::CORE_FRAME_HEADER_LEN)
                .unwrap()
                .checked_add(payload.len() as u64)
                .unwrap();
        }
        let archive_digest = {
            use sha2::Digest as _;
            let digest = Sha256::digest(archive);
            let mut bytes = [0_u8; 32];
            bytes.copy_from_slice(digest.as_ref());
            bytes
        };
        CorpusManifest::new(
            network,
            ArchiveInfo::new(archive.len() as u64, archive_digest),
            entries,
        )
        .expect("test manifest is valid")
    }

    fn write_manifest(manifest: &CorpusManifest, path: &Path) {
        manifest.save(path).expect("save manifest")
    }

    fn args_for_file(archive_path: &Path, manifest_path: &Path) -> Args {
        let mut args = Args::parse(std::iter::empty::<OsString>()).unwrap();
        args.blocks_file = Some(archive_path.to_path_buf());
        args.corpus_manifest = Some(manifest_path.to_path_buf());
        args
    }

    #[test]
    fn file_source_reads_core_framed_blocks() {
        let magic = Network::Regtest.magic();
        let payload = regtest_genesis_bytes();
        let archive = write_archive(magic, &[&payload[..]]);
        let manifest = manifest_for_archive(Network::Regtest, &archive, &[&payload[..]]);

        let archive_temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(archive_temp.path(), &archive).unwrap();
        let manifest_temp = tempfile::NamedTempFile::new().unwrap();
        write_manifest(&manifest, manifest_temp.path());

        let args = args_for_file(archive_temp.path(), manifest_temp.path());
        let mut source = open_block_source(&args, Network::Regtest, Some(&manifest)).unwrap();
        let (hash, bytes) = source.fetch(0).unwrap();
        let expected = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest)
            .block_hash()
            .to_string();
        assert_eq!(hash, expected);
        assert_eq!(bytes, payload);
        let err = source.fetch(1).unwrap_err();
        assert!(err.to_string().contains("archive ended"), "{err}");
    }

    #[test]
    fn file_source_rejects_wrong_magic() {
        let archive = write_archive(Network::Mainnet.magic(), &[&regtest_genesis_bytes()[..]]);
        let manifest =
            manifest_for_archive(Network::Regtest, &archive, &[&regtest_genesis_bytes()[..]]);
        let archive_temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(archive_temp.path(), &archive).unwrap();

        let args = args_for_file(archive_temp.path(), Path::new("/nonexistent/manifest.json"));
        let mut source = open_block_source(&args, Network::Regtest, Some(&manifest)).unwrap();
        let err = source.fetch(0).unwrap_err();
        assert!(
            format!("{err:?}").to_lowercase().contains("wrong magic"),
            "{err:?}"
        );
    }

    #[test]
    fn file_source_rejects_truncated_frame() {
        let magic = Network::Regtest.magic();
        let payload = regtest_genesis_bytes();
        let full_archive = write_archive(magic, &[&payload[..]]);
        let manifest = manifest_for_archive(Network::Regtest, &full_archive, &[&payload[..]]);
        let archive_temp = tempfile::NamedTempFile::new().unwrap();
        let mut truncated = full_archive.clone();
        truncated.truncate(truncated.len() - 10);
        std::fs::write(archive_temp.path(), &truncated).unwrap();

        let args = args_for_file(archive_temp.path(), Path::new("/nonexistent/manifest.json"));
        let mut source = open_block_source(&args, Network::Regtest, Some(&manifest)).unwrap();
        let err = source.fetch(0).unwrap_err();
        assert!(
            format!("{err:?}")
                .to_lowercase()
                .contains("partial payload"),
            "{err:?}"
        );
    }

    #[test]
    fn file_source_rejects_old_length_only_file() {
        let payload = regtest_genesis_bytes();
        let magic = Network::Regtest.magic();
        let valid_archive = write_archive(magic, &[&payload[..]]);
        let manifest = manifest_for_archive(Network::Regtest, &valid_archive, &[&payload[..]]);
        let mut archive = Vec::new();
        archive.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        archive.extend_from_slice(&payload);
        let archive_temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(archive_temp.path(), &archive).unwrap();

        let args = args_for_file(archive_temp.path(), Path::new("/nonexistent/manifest.json"));
        let mut source = open_block_source(&args, Network::Regtest, Some(&manifest)).unwrap();
        let err = source.fetch(0).unwrap_err();
        assert!(
            format!("{err:?}").to_lowercase().contains("wrong magic"),
            "{err}"
        );
    }

    #[test]
    fn file_source_rejects_extra_frames() {
        let magic = Network::Regtest.magic();
        let payload = regtest_genesis_bytes();
        // Archive with two frames, manifest expecting one.
        let two_frame_archive = write_archive(magic, &[&payload[..], &payload[..]]);
        let one_frame_archive = write_archive(magic, &[&payload[..]]);
        let manifest = manifest_for_archive(Network::Regtest, &one_frame_archive, &[&payload[..]]);
        let archive_temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(archive_temp.path(), &two_frame_archive).unwrap();

        let args = args_for_file(archive_temp.path(), Path::new("/nonexistent/manifest.json"));
        let mut source = open_block_source(&args, Network::Regtest, Some(&manifest)).unwrap();
        source.fetch(0).unwrap();
        let err = source.ensure_eof().unwrap_err();
        assert!(err.to_string().contains("extra frame"), "{err}");
    }

    #[test]
    fn file_source_rejects_hash_mismatch() {
        let magic = Network::Regtest.magic();
        let payload = regtest_genesis_bytes();
        let archive = write_archive(magic, &[&payload[..]]);
        let mut manifest = manifest_for_archive(Network::Regtest, &archive, &[&payload[..]]);
        manifest.entries[0].hash = Hash256::from_le_bytes(&[0xab; 32]);

        let archive_temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(archive_temp.path(), &archive).unwrap();

        let args = args_for_file(archive_temp.path(), Path::new("/nonexistent/manifest.json"));
        let mut source = open_block_source(&args, Network::Regtest, Some(&manifest)).unwrap();
        let err = source.fetch(0).unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("hash mismatch"),
            "{err}"
        );
    }

    #[test]
    fn file_source_rejects_offset_mismatch() {
        let magic = Network::Regtest.magic();
        let payload = regtest_genesis_bytes();
        let archive = write_archive(magic, &[&payload[..]]);
        let mut manifest = manifest_for_archive(Network::Regtest, &archive, &[&payload[..]]);
        manifest.entries[0].offset = 1;

        let archive_temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(archive_temp.path(), &archive).unwrap();

        let args = args_for_file(archive_temp.path(), Path::new("/nonexistent/manifest.json"));
        let mut source = open_block_source(&args, Network::Regtest, Some(&manifest)).unwrap();
        let err = source.fetch(0).unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("offset mismatch"),
            "{err}"
        );
    }

    #[test]
    fn file_source_rejects_length_mismatch() {
        let magic = Network::Regtest.magic();
        let payload = regtest_genesis_bytes();
        let archive = write_archive(magic, &[&payload[..]]);
        let mut manifest = manifest_for_archive(Network::Regtest, &archive, &[&payload[..]]);
        manifest.entries[0].payload_length = 1;

        let archive_temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(archive_temp.path(), &archive).unwrap();

        let args = args_for_file(archive_temp.path(), Path::new("/nonexistent/manifest.json"));
        let mut source = open_block_source(&args, Network::Regtest, Some(&manifest)).unwrap();
        let err = source.fetch(0).unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("length mismatch"),
            "{err}"
        );
    }

    #[test]
    fn file_source_rejects_archive_digest_mismatch() {
        let magic = Network::Regtest.magic();
        let payload = regtest_genesis_bytes();
        let archive = write_archive(magic, &[&payload[..]]);
        let mut manifest = manifest_for_archive(Network::Regtest, &archive, &[&payload[..]]);
        manifest.archive.sha256 = [0xcd; 32];

        let archive_temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(archive_temp.path(), &archive).unwrap();

        let args = args_for_file(archive_temp.path(), Path::new("/nonexistent/manifest.json"));
        let mut source = open_block_source(&args, Network::Regtest, Some(&manifest)).unwrap();
        source.fetch(0).unwrap();
        let err = source.ensure_eof().unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("sha-256 mismatch"),
            "{err}"
        );
    }

    #[test]
    fn file_mode_requires_paired_arguments() {
        let mut args = vec![
            OsString::from("--blocks-file"),
            OsString::from("/tmp/archive"),
        ];
        let err = Args::parse(args.drain(..)).unwrap_err();
        assert!(
            err.to_string()
                .to_lowercase()
                .contains("must be provided together"),
            "{err}"
        );
    }

    #[test]
    fn file_preflight_rejects_regtest_manifest() {
        let payload = regtest_genesis_bytes();
        let archive = write_archive(Network::Regtest.magic(), &[&payload[..]]);
        let manifest = manifest_for_archive(Network::Regtest, &archive, &[&payload[..]]);

        let archive_temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(archive_temp.path(), &archive).unwrap();
        let manifest_temp = tempfile::NamedTempFile::new().unwrap();
        write_manifest(&manifest, manifest_temp.path());

        let mut args = Args::parse(std::iter::empty::<OsString>()).unwrap();
        args.stop_height = 0;
        args.blocks_file = Some(archive_temp.path().to_path_buf());
        args.corpus_manifest = Some(manifest_temp.path().to_path_buf());

        let err = prepare_file_inputs(&args).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("mainnet"), "{err}");
    }

    #[test]
    fn file_preflight_rejects_stop_height_mismatch() {
        let payload = regtest_genesis_bytes();
        let archive = write_archive(Network::Mainnet.magic(), &[&payload[..]]);
        let manifest = {
            let m = manifest_for_archive(Network::Mainnet, &archive, &[&payload[..]]);
            m
        };

        let archive_temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(archive_temp.path(), &archive).unwrap();
        let manifest_temp = tempfile::NamedTempFile::new().unwrap();
        write_manifest(&manifest, manifest_temp.path());

        let mut args = Args::parse(std::iter::empty::<OsString>()).unwrap();
        args.stop_height = 1; // manifest has stop_height 0
        args.blocks_file = Some(archive_temp.path().to_path_buf());
        args.corpus_manifest = Some(manifest_temp.path().to_path_buf());

        let err = prepare_file_inputs(&args).unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("stop height"),
            "{err}"
        );
    }

    #[test]
    fn file_preflight_rejects_archive_size_mismatch() {
        let payload = regtest_genesis_bytes();
        let full_archive = write_archive(Network::Mainnet.magic(), &[&payload[..]]);
        let manifest = manifest_for_archive(Network::Mainnet, &full_archive, &[&payload[..]]);

        let archive_temp = tempfile::NamedTempFile::new().unwrap();
        let mut truncated = full_archive.clone();
        truncated.truncate(truncated.len() - 1);
        std::fs::write(archive_temp.path(), &truncated).unwrap();
        let manifest_temp = tempfile::NamedTempFile::new().unwrap();
        write_manifest(&manifest, manifest_temp.path());

        let mut args = Args::parse(std::iter::empty::<OsString>()).unwrap();
        args.stop_height = 0;
        args.blocks_file = Some(archive_temp.path().to_path_buf());
        args.corpus_manifest = Some(manifest_temp.path().to_path_buf());

        let err = prepare_file_inputs(&args).unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("archive size"),
            "{err}"
        );
    }

    #[cfg(feature = "checksig-census")]
    #[test]
    fn diagnostic_preface_and_row_encoding() {
        let mut out: Vec<u8> = Vec::new();
        write_diagnostic_preface(&mut out).unwrap();
        assert_eq!(out.len(), 16);
        assert_eq!(&out[0..8], b"BRSHGT1\0");
        assert_eq!(
            u32::from_le_bytes(out[8..12].try_into().unwrap()),
            DIAGNOSTIC_VERSION
        );
        assert_eq!(
            u32::from_le_bytes(out[12..16].try_into().unwrap()),
            DIAGNOSTIC_ROW_SIZE
        );

        let checkpoint = census_checkpoint::CensusCheckpoint {
            abi_version: 1,
            struct_size: 56,
            context_rows: 1,
            context_end: 16 + 56,
            record_rows: 2,
            record_end: 16 + 2 * 224,
            journal_rows: 3,
            journal_end: 16 + 3 * 56,
        };
        let hash = BlockHash::from_byte_array([0x42; 32]);
        write_checkpoint_row(&mut out, 7, hash, &checkpoint).unwrap();

        let row_start = 16;
        assert_eq!(out.len(), row_start + 84);
        assert_eq!(
            u32::from_le_bytes(out[row_start..row_start + 4].try_into().unwrap()),
            7
        );
        assert_eq!(&out[row_start + 4..row_start + 36], &[0x42; 32]);
        let read_hash = <[u8; 32]>::try_from(&out[row_start + 4..row_start + 36]).unwrap();
        assert_eq!(read_hash, [0x42; 32]);
    }

    #[cfg(feature = "checksig-census")]
    #[test]
    fn diagnostic_artifact_records_actual_stop_and_controller_reason() {
        let mut args = Args::parse(std::iter::empty::<OsString>()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("diagnostic.json");
        args.output = Some(output.clone());
        write_diagnostic_artifact(
            &args,
            11,
            "000000000000000000000000000000000000000000000000000000000000000a".into(),
            Duration::from_secs(3),
        )
        .unwrap();
        let content = std::fs::read_to_string(&output).unwrap();
        let artifact: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(
            artifact["schema"].as_str(),
            Some("mainnet-prefix-replay-diagnostic-v1")
        );
        assert_eq!(artifact["non_certifying"].as_bool(), Some(true));
        assert_eq!(artifact["block_source"].as_str(), Some("rest"));
        assert_eq!(artifact["actual_stop_height"].as_u64(), Some(11));
        assert_eq!(artifact["requested_stop_height_ceiling"].as_u64(), Some(0));
        assert_eq!(artifact["stop_reason"].as_str(), Some("controller-request"));
        assert!(!content.contains("all-11-observed"));
    }

    #[cfg(feature = "checksig-census")]
    #[test]
    fn diagnostic_artifact_refuses_preexisting_destination() {
        let mut args = Args::parse(std::iter::empty::<OsString>()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("diagnostic.json");
        std::fs::write(&output, b"already here").unwrap();
        args.output = Some(output.clone());
        let err = write_diagnostic_artifact(
            &args,
            11,
            "000000000000000000000000000000000000000000000000000000000000000a".into(),
            Duration::from_secs(3),
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .to_lowercase()
                .contains("refusing to replace existing"),
            "{err}"
        );
        let content = std::fs::read_to_string(&output).unwrap();
        assert_eq!(content, "already here");
    }

    #[cfg(feature = "checksig-census")]
    #[test]
    fn diagnostic_artifact_publishes_dot_tmp_destination_safely() {
        let mut args = Args::parse(std::iter::empty::<OsString>()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("diagnostic.json.tmp");
        args.output = Some(output.clone());
        write_diagnostic_artifact(
            &args,
            7,
            "0000000000000000000000000000000000000000000000000000000000000007".into(),
            Duration::from_secs(1),
        )
        .unwrap();
        let content = std::fs::read_to_string(&output).unwrap();
        let artifact: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(artifact["actual_stop_height"].as_u64(), Some(7));

        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name())
            .collect();
        assert!(
            entries
                .iter()
                .any(|n| n.to_string_lossy() == "diagnostic.json.tmp"),
            "{entries:?}"
        );
    }

    #[cfg(feature = "checksig-census")]
    #[test]
    fn diagnostic_artifact_leaves_no_debris_on_failure() {
        let mut args = Args::parse(std::iter::empty::<OsString>()).unwrap();
        // /nonexistent is guaranteed to fail directory creation.
        args.output = Some(PathBuf::from("/nonexistent/graveyard/diagnostic.json"));
        let err = write_diagnostic_artifact(
            &args,
            11,
            "000000000000000000000000000000000000000000000000000000000000000a".into(),
            Duration::from_secs(3),
        )
        .unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("diagnostic output"),
            "{err}"
        );
    }

    #[cfg(feature = "checksig-census")]
    #[test]
    fn read_control_byte_interprets_bytes() {
        let mut zero = Cursor::new([0x00]);
        assert_eq!(read_control_byte(&mut zero).unwrap(), 0x00);
        let mut one = Cursor::new([0x01]);
        assert_eq!(read_control_byte(&mut one).unwrap(), 0x01);
        let mut empty: Cursor<&[u8]> = Cursor::new(&[]);
        assert!(read_control_byte(&mut empty).is_err());
    }

    #[cfg(feature = "checksig-census")]
    #[test]
    fn validate_diagnostic_args_rejects_window_and_missing_env() {
        let mut args = Args::parse(std::iter::empty::<OsString>()).unwrap();
        args.census_diagnostic = true;
        args.rest_url = Some("127.0.0.1:18443".into());
        args.output = Some(PathBuf::from("/tmp/diagnostic.json"));
        args.window = 2;
        assert!(
            validate_diagnostic_args(&args)
                .unwrap_err()
                .to_string()
                .contains("--window 1")
        );

        args.window = 1;
        // SAFETY: test-only environment mutation.
        unsafe {
            std::env::set_var("BRS_CENSUS_CONTEXTS", "/tmp/ctx");
            std::env::set_var("BRS_CENSUS_RECORDS", "/tmp/rec");
            std::env::set_var("BRS_CENSUS_JOURNAL", "/tmp/jrn");
        }
        validate_diagnostic_args(&args).unwrap();

        // SAFETY: test-only environment mutation.
        unsafe {
            std::env::remove_var("BRS_CENSUS_JOURNAL");
        }
    }

    #[cfg(feature = "checksig-census")]
    #[test]
    fn checkpoint_monotonicity_rejects_decreasing_successor() {
        let mut prev = None;
        let first = census_checkpoint::CensusCheckpoint {
            context_rows: 1,
            context_end: 100,
            record_rows: 1,
            record_end: 100,
            journal_rows: 1,
            journal_end: 100,
            ..Default::default()
        };
        update_prev_checkpoint(&mut prev, first, 0).unwrap();

        let second = census_checkpoint::CensusCheckpoint {
            context_rows: 0,
            context_end: 100,
            record_rows: 1,
            record_end: 100,
            journal_rows: 1,
            journal_end: 100,
            ..Default::default()
        };
        let err = update_prev_checkpoint(&mut prev, second, 1).unwrap_err();
        assert!(err.to_string().contains("not monotonic"), "{err}");
    }
}
