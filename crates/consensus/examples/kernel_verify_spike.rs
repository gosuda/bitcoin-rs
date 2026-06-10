//! U0 kernel-speedup measurement spike (plan 2026-06-10-001, unit U0).
//!
//! Measures bitcoinkernel's per-input script-verify cost and rayon
//! thread-scaling on real heavy mainnet blocks, before any apply-path surgery.
//! The comparator is the recorded ~65 µs/input effective-serial cost of the
//! `bitcoinconsensus` backend on the same machine (cross-binary by design:
//! the two backends cannot share a binary).
//!
//! Two idempotent phases:
//! 1. **Extract** (skipped when the corpus file already exists): stream
//!    mainnet blocks `0..=150_000` from a local `bitcoind -rest` endpoint,
//!    maintain an in-memory outpoint -> prevout map, and keep the top N
//!    (default 300) blocks by non-coinbase input count, together with every
//!    spent prevout (script bytes + amount). Coinbase inputs have no prevout
//!    and are excluded from sampling and measurement.
//! 2. **Measure**: verify every sampled non-coinbase transaction's scripts
//!    through `KernelContext::verify_tx` at rayon widths 1/8/32 (a dedicated
//!    `ThreadPoolBuilder` pool per width), with per-height flags derived
//!    exactly as production's `compute_verify_flags` derives them. Every
//!    pristine input must verify OK; any rejection aborts loudly with
//!    height/txid/input index. The timed window includes the per-tx
//!    serialization + `bitcoinkernel::Transaction` parse inside `verify_tx`
//!    (production pays both per tx) but excludes corpus load and work-item
//!    construction (production amortizes block decode and prevout lookup in
//!    its own pipeline stages).
//!
//! Corpus format (single file, all integers little-endian):
//! ```text
//! magic  b"KSPIKE1\0"                          (8 bytes)
//! u32    block count
//! per block:
//!   u32  height
//!   u32  raw block length, then that many raw block bytes
//!   u32  prevout count, then per prevout (ordered by block tx order, then
//!        input order, non-coinbase txs only):
//!     u64 amount in satoshis
//!     u32 script length, then that many scriptPubKey bytes
//! ```
#![allow(missing_docs)]
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::ffi::OsString;
use std::io::{BufRead as _, BufReader, BufWriter, Read as _, Write as _};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use bitcoin::consensus::Decodable as _;
use bitcoin::{Amount, OutPoint, ScriptBuf, TxOut};
use bitcoin_rs_consensus::UtxoView;
use bitcoin_rs_consensus::kernel::KernelContext;
use bitcoin_rs_primitives::{Network, Tx};
use bitcoin_rs_script::VerifyFlags;
use rayon::prelude::*;
use serde_json::json;

const CORPUS_MAGIC: &[u8; 8] = b"KSPIKE1\0";
const STOP_HEIGHT: u32 = 150_000;
const SAMPLE_BLOCKS: usize = 300;
const MIN_CORPUS_INPUTS: usize = 20_000;
const THREAD_WIDTHS: [usize; 3] = [1, 8, 32];

fn main() -> Result<()> {
    let args = Args::parse(std::env::args_os().skip(1))?;

    if args.corpus.exists() {
        eprintln!(
            "corpus {} exists; skipping extraction",
            args.corpus.display()
        );
    } else {
        extract_corpus(&args)?;
    }

    let corpus = load_corpus(&args.corpus)?;
    let items = build_work_items(&corpus)?;
    let report = measure(&corpus, &items, &args)?;

    let rendered = serde_json::to_string_pretty(&report).context("render report JSON")?;
    println!("{rendered}");
    if let Some(parent) = args.output.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    std::fs::write(&args.output, rendered + "\n")
        .with_context(|| format!("write {}", args.output.display()))?;
    Ok(())
}

#[derive(Debug)]
struct Args {
    rest_url: String,
    corpus: PathBuf,
    output: PathBuf,
}

impl Args {
    fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Self> {
        let mut parsed = Self {
            rest_url: "127.0.0.1:8332".to_owned(),
            corpus: PathBuf::from("/home/alpha/bench-g14/results/u0-spike-corpus/corpus.bin"),
            output: PathBuf::from("/home/alpha/bench-g14/results/u0-kernel-spike.json"),
        };
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            let arg = arg
                .into_string()
                .map_err(|value| anyhow::anyhow!("argument is not UTF-8: {}", value.display()))?;
            match arg.as_str() {
                "--rest-url" => parsed.rest_url = next_arg(&mut args, "--rest-url")?,
                "--corpus" => parsed.corpus = PathBuf::from(next_arg(&mut args, "--corpus")?),
                "--output" => parsed.output = PathBuf::from(next_arg(&mut args, "--output")?),
                other => bail!(
                    "unknown argument: {other}\nusage: kernel_verify_spike \
                     [--rest-url <host:port>] [--corpus <path>] [--output <path>]"
                ),
            }
        }
        Ok(parsed)
    }
}

fn next_arg(args: &mut impl Iterator<Item = OsString>, name: &str) -> Result<String> {
    args.next()
        .with_context(|| format!("{name} requires a value"))?
        .into_string()
        .map_err(|value| anyhow::anyhow!("{name} value is not UTF-8: {}", value.display()))
}

/// Mirrors `compute_verify_flags` in `crates/node/src/apply.rs`: P2SH is
/// always-on for supported validation paths; DERSIG/CLTV/CSV/WITNESS/TAPROOT
/// gate on activation height. Production resolves CSV/segwit through BIP9
/// contextual state with these same height predicates as fallback; at the
/// corpus heights (<= 150k, far below every activation) the two derivations
/// are identical and every flag except P2SH is off.
fn production_verify_flags(network: Network, height: u32) -> VerifyFlags {
    let mut flags = VerifyFlags::P2SH;
    if network.is_bip66_active(height) {
        flags = flags.union(VerifyFlags::DERSIG);
    }
    if network.is_bip65_active(height) {
        flags = flags.union(VerifyFlags::CHECKLOCKTIMEVERIFY);
    }
    if network.is_csv_active(height) {
        flags = flags.union(VerifyFlags::CHECKSEQUENCEVERIFY);
    }
    if network.is_segwit_active(height) {
        flags = flags
            .union(VerifyFlags::WITNESS)
            .union(VerifyFlags::NULLDUMMY);
    }
    if network.is_taproot_active(height) {
        flags = flags.union(VerifyFlags::TAPROOT);
    }
    flags
}

// --- Phase 1: extraction ------------------------------------------------------

/// One prevout spent by a sampled block, in (tx order, input order).
struct PrevoutRec {
    amount: u64,
    script: Vec<u8>,
}

/// One sampled heavy block plus the prevouts its non-coinbase inputs spend.
struct SampleBlock {
    height: u32,
    raw: Vec<u8>,
    prevouts: Vec<PrevoutRec>,
}

fn extract_corpus(args: &Args) -> Result<()> {
    eprintln!(
        "extracting corpus: streaming blocks 0..={STOP_HEIGHT} from {}",
        args.rest_url
    );
    let started = Instant::now();
    let mut client = RestClient::connect(&args.rest_url)?;
    let mut utxo: hashbrown::HashMap<OutPoint, PrevoutRec> = hashbrown::HashMap::new();
    // Capped min-heap of (input_count, height) keys over the candidate set.
    let mut keys: BinaryHeap<Reverse<(usize, u32)>> = BinaryHeap::new();
    let mut candidates: hashbrown::HashMap<u32, SampleBlock> = hashbrown::HashMap::new();

    for height in 0..=STOP_HEIGHT {
        let raw = fetch_block(&mut client, height)?;
        let block = bitcoin::Block::consensus_decode(&mut std::io::Cursor::new(raw.as_slice()))
            .with_context(|| format!("decode block at height {height}"))?;

        let mut prevouts = Vec::new();
        for tx in &block.txdata {
            if !tx.is_coinbase() {
                for (input_index, input) in tx.input.iter().enumerate() {
                    let rec = utxo.remove(&input.previous_output).with_context(|| {
                        format!(
                            "missing prevout {} at height {height} txid {} input {input_index}",
                            input.previous_output,
                            tx.compute_txid()
                        )
                    })?;
                    prevouts.push(rec);
                }
            }
            let txid = tx.compute_txid();
            for (vout, output) in tx.output.iter().enumerate() {
                let vout = u32::try_from(vout).context("vout exceeds u32")?;
                utxo.insert(
                    OutPoint { txid, vout },
                    PrevoutRec {
                        amount: output.value.to_sat(),
                        script: output.script_pubkey.to_bytes(),
                    },
                );
            }
        }

        let input_count = prevouts.len();
        if input_count > 0 {
            let candidate = SampleBlock {
                height,
                raw,
                prevouts,
            };
            if keys.len() < SAMPLE_BLOCKS {
                keys.push(Reverse((input_count, height)));
                candidates.insert(height, candidate);
            } else if let Some(&Reverse((min_count, min_height))) = keys.peek()
                && input_count > min_count
            {
                keys.pop();
                candidates.remove(&min_height);
                keys.push(Reverse((input_count, height)));
                candidates.insert(height, candidate);
            }
        }

        if height % 10_000 == 0 {
            eprintln!(
                "  height {height} ({:.0?} elapsed, {} utxos, {} candidates)",
                started.elapsed(),
                utxo.len(),
                candidates.len()
            );
        }
    }

    let mut samples: Vec<SampleBlock> = candidates.into_values().collect();
    samples.sort_by_key(|sample| sample.height);
    let total_inputs: usize = samples.iter().map(|sample| sample.prevouts.len()).sum();
    eprintln!(
        "sampled {} blocks, {total_inputs} non-coinbase inputs, in {:.0?}",
        samples.len(),
        started.elapsed()
    );
    if total_inputs < MIN_CORPUS_INPUTS {
        bail!(
            "corpus too small: {total_inputs} non-coinbase inputs < required {MIN_CORPUS_INPUTS}"
        );
    }
    write_corpus(&args.corpus, &samples)
}

fn fetch_block(client: &mut RestClient, height: u32) -> Result<Vec<u8>> {
    let hash_bytes = client
        .get(&format!("/rest/blockhashbyheight/{height}.hex"))
        .with_context(|| format!("get block hash at height {height}"))?;
    let hash = String::from_utf8(hash_bytes)
        .context("block hash response is not UTF-8")?
        .trim()
        .to_owned();
    client
        .get(&format!("/rest/block/{hash}.bin"))
        .with_context(|| format!("get block {hash} at height {height}"))
}

fn write_corpus(path: &Path, samples: &[SampleBlock]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let file = std::fs::File::create(path).with_context(|| format!("create {}", path.display()))?;
    let mut writer = BufWriter::new(file);
    writer.write_all(CORPUS_MAGIC)?;
    write_u32(&mut writer, u32::try_from(samples.len())?)?;
    for sample in samples {
        write_u32(&mut writer, sample.height)?;
        write_u32(&mut writer, u32::try_from(sample.raw.len())?)?;
        writer.write_all(&sample.raw)?;
        write_u32(&mut writer, u32::try_from(sample.prevouts.len())?)?;
        for prevout in &sample.prevouts {
            writer.write_all(&prevout.amount.to_le_bytes())?;
            write_u32(&mut writer, u32::try_from(prevout.script.len())?)?;
            writer.write_all(&prevout.script)?;
        }
    }
    writer.flush()?;
    eprintln!("wrote corpus to {}", path.display());
    Ok(())
}

fn load_corpus(path: &Path) -> Result<Vec<SampleBlock>> {
    let file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut magic = [0_u8; 8];
    reader.read_exact(&mut magic)?;
    if &magic != CORPUS_MAGIC {
        bail!("{} is not a KSPIKE1 corpus", path.display());
    }
    let block_count = read_u32(&mut reader)?;
    let mut samples = Vec::with_capacity(usize::try_from(block_count)?);
    for _ in 0..block_count {
        let height = read_u32(&mut reader)?;
        let raw = read_bytes(&mut reader)?;
        let prevout_count = read_u32(&mut reader)?;
        let mut prevouts = Vec::with_capacity(usize::try_from(prevout_count)?);
        for _ in 0..prevout_count {
            let mut amount = [0_u8; 8];
            reader.read_exact(&mut amount)?;
            prevouts.push(PrevoutRec {
                amount: u64::from_le_bytes(amount),
                script: read_bytes(&mut reader)?,
            });
        }
        samples.push(SampleBlock {
            height,
            raw,
            prevouts,
        });
    }
    Ok(samples)
}

fn write_u32(writer: &mut impl std::io::Write, value: u32) -> Result<()> {
    writer.write_all(&value.to_le_bytes())?;
    Ok(())
}

fn read_u32(reader: &mut impl std::io::Read) -> Result<u32> {
    let mut buf = [0_u8; 4];
    reader.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_bytes(reader: &mut impl std::io::Read) -> Result<Vec<u8>> {
    let len = usize::try_from(read_u32(reader)?)?;
    let mut bytes = vec![0_u8; len];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

// --- Phase 2: measurement -----------------------------------------------------

/// Resolved prevouts for one transaction, served through the same `UtxoView`
/// seam `verify_tx` uses in production.
struct PrevoutMap(hashbrown::HashMap<OutPoint, TxOut>);

impl UtxoView for PrevoutMap {
    fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
        self.0.get(outpoint).cloned()
    }
}

/// One pre-resolved transaction verification job. Construction (block decode,
/// prevout binding) happens outside the timed window; the per-tx serialization
/// and kernel parse inside `verify_tx` stay inside it.
struct WorkItem {
    tx: Tx,
    txid: bitcoin::Txid,
    prevouts: PrevoutMap,
    height: u32,
    flags: VerifyFlags,
    input_count: usize,
}

fn build_work_items(corpus: &[SampleBlock]) -> Result<Vec<WorkItem>> {
    let mut items = Vec::new();
    for sample in corpus {
        let block =
            bitcoin::Block::consensus_decode(&mut std::io::Cursor::new(sample.raw.as_slice()))
                .with_context(|| format!("decode corpus block at height {}", sample.height))?;
        let flags = production_verify_flags(Network::Mainnet, sample.height);
        let mut prevouts = sample.prevouts.iter();
        for tx in &block.txdata {
            if tx.is_coinbase() {
                continue;
            }
            let mut map = hashbrown::HashMap::with_capacity(tx.input.len());
            for input in &tx.input {
                let rec = prevouts.next().with_context(|| {
                    format!("corpus prevout underrun at height {}", sample.height)
                })?;
                map.insert(
                    input.previous_output,
                    TxOut {
                        value: Amount::from_sat(rec.amount),
                        script_pubkey: ScriptBuf::from_bytes(rec.script.clone()),
                    },
                );
            }
            items.push(WorkItem {
                txid: tx.compute_txid(),
                input_count: tx.input.len(),
                tx: Tx(tx.clone()),
                prevouts: PrevoutMap(map),
                height: sample.height,
                flags,
            });
        }
        if prevouts.next().is_some() {
            bail!("corpus prevout overrun at height {}", sample.height);
        }
    }
    Ok(items)
}

fn verify_item(kernel: &KernelContext, item: &WorkItem) -> Result<()> {
    kernel
        .verify_tx(&item.tx, &item.prevouts, item.height, item.flags)
        .map_err(|error| {
            anyhow::anyhow!(
                "kernel rejected pristine tx: height {} txid {} ({}) flags {:#x}: {error}",
                item.height,
                item.txid,
                diagnose_failing_input(item),
                item.flags.bits()
            )
        })
}

/// On a rejection, re-runs each input individually through the kernel to name
/// the failing input index — `verify_tx`'s error does not carry it.
fn diagnose_failing_input(item: &WorkItem) -> String {
    let tx_bytes = bitcoin::consensus::encode::serialize(&item.tx.0);
    let Ok(kernel_tx) = bitcoinkernel::Transaction::new(&tx_bytes) else {
        return "kernel tx parse failed".to_owned();
    };
    let mut spent = Vec::with_capacity(item.tx.0.input.len());
    for (input_index, input) in item.tx.0.input.iter().enumerate() {
        let Some(prevout) = item.prevouts.lookup(&input.previous_output) else {
            return format!("input {input_index}: prevout missing");
        };
        spent.push(prevout);
    }
    let mut scripts = Vec::with_capacity(spent.len());
    let mut amounts = Vec::with_capacity(spent.len());
    for (input_index, prevout) in spent.iter().enumerate() {
        let Ok(script) = bitcoinkernel::ScriptPubkey::new(prevout.script_pubkey.as_bytes()) else {
            return format!("input {input_index}: prevout script rejected by kernel");
        };
        let Ok(amount) = i64::try_from(prevout.value.to_sat()) else {
            return format!("input {input_index}: amount exceeds i64");
        };
        scripts.push(script);
        amounts.push(amount);
    }
    let outs: Vec<bitcoinkernel::TxOut> = scripts
        .iter()
        .zip(&amounts)
        .map(|(script, amount)| bitcoinkernel::TxOut::new(script, *amount))
        .collect();
    let Ok(tx_data) = bitcoinkernel::PrecomputedTransactionData::new(&kernel_tx, outs.as_slice())
    else {
        return "kernel precomputed tx data construction failed".to_owned();
    };
    for (input_index, (script, amount)) in scripts.iter().zip(&amounts).enumerate() {
        if let Err(error) = bitcoinkernel::verify(
            script,
            Some(*amount),
            &kernel_tx,
            input_index,
            Some(item.flags.kernel_bits()),
            &tx_data,
        ) {
            return format!("input {input_index}: {error:?}");
        }
    }
    "per-input re-verify found no failing input".to_owned()
}

fn measure(corpus: &[SampleBlock], items: &[WorkItem], args: &Args) -> Result<serde_json::Value> {
    let total_inputs: usize = items.iter().map(|item| item.input_count).sum();
    let height_min = corpus.iter().map(|sample| sample.height).min();
    let height_max = corpus.iter().map(|sample| sample.height).max();
    eprintln!(
        "measuring: {} blocks, {} txs, {total_inputs} inputs, heights {height_min:?}..={height_max:?}",
        corpus.len(),
        items.len()
    );

    let kernel = KernelContext::new(bitcoin::Network::Bitcoin)
        .map_err(|error| anyhow::anyhow!("create kernel context: {error}"))?;

    // Untimed correctness pass: every pristine input must verify OK.
    items
        .par_iter()
        .try_for_each(|item| verify_item(&kernel, item))?;
    eprintln!("correctness pass OK: all {total_inputs} pristine inputs verified");

    let mut runs = Vec::new();
    for width in THREAD_WIDTHS {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(width)
            .build()
            .with_context(|| format!("build rayon pool of width {width}"))?;
        let started = Instant::now();
        pool.install(|| {
            items
                .par_iter()
                .try_for_each(|item| verify_item(&kernel, item))
        })?;
        let elapsed = started.elapsed();
        let wall_ms = elapsed.as_secs_f64() * 1_000.0;
        let us_per_input = duration_us_per_input(elapsed, total_inputs)?;
        eprintln!("width {width}: {wall_ms:.1} ms, {us_per_input:.2} us/input");
        runs.push(json!({
            "threads": width,
            "wall_ms": wall_ms,
            "total_inputs": total_inputs,
            "us_per_input": us_per_input,
        }));
    }

    Ok(json!({
        "schema": "u0-kernel-verify-spike-v1",
        "measurement_target": "bitcoinkernel per-input script verify",
        "git_head": git_head().ok(),
        "comparator": "recorded ~65 us/input effective-serial, bitcoinconsensus backend, same machine",
        "corpus": {
            "path": args.corpus.display().to_string(),
            "block_count": corpus.len(),
            "tx_count": items.len(),
            "input_count": total_inputs,
            "height_min": height_min,
            "height_max": height_max,
        },
        "runs": runs,
    }))
}

fn duration_us_per_input(elapsed: Duration, total_inputs: usize) -> Result<f64> {
    let micros = u32::try_from(elapsed.as_micros()).context("elapsed micros exceed u32")?;
    let inputs = u32::try_from(total_inputs).context("input count exceeds u32")?;
    if inputs == 0 {
        bail!("corpus contains zero inputs");
    }
    Ok(f64::from(micros) / f64::from(inputs))
}

fn git_head() -> Result<String> {
    let output = std::process::Command::new("git")
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

// --- Minimal keep-alive REST client (mirrors mainnet_prefix_replay) ------------

/// Minimal keep-alive HTTP/1.1 client for the local `bitcoind -rest` interface,
/// mirroring `crates/node/examples/mainnet_prefix_replay.rs`.
struct RestClient {
    host: String,
    stream: BufReader<TcpStream>,
}

impl RestClient {
    /// Largest legitimate body is one serialized block; anything bigger means
    /// the URL points at something that is not a bitcoind REST endpoint.
    const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

    fn connect(host: &str) -> Result<Self> {
        let stream = TcpStream::connect(host).with_context(|| format!("connect to {host}"))?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;
        Ok(Self {
            host: host.to_owned(),
            stream: BufReader::new(stream),
        })
    }

    fn get(&mut self, path: &str) -> Result<Vec<u8>> {
        let first_err = match self.request(path) {
            Ok(body) => return Ok(body),
            Err(err) => err,
        };
        // The server may close a kept-alive connection between requests;
        // reconnect once before giving up, keeping the first failure's cause.
        *self =
            Self::connect(&self.host).with_context(|| format!("reconnect after: {first_err:#}"))?;
        self.request(path)
            .with_context(|| format!("retry after: {first_err:#}"))
    }

    fn request(&mut self, path: &str) -> Result<Vec<u8>> {
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\n\r\n",
            self.host
        );
        self.stream.get_mut().write_all(request.as_bytes())?;
        let mut line = String::new();
        self.stream.read_line(&mut line)?;
        let status = line.trim_end().to_owned();
        let mut content_length: Option<usize> = None;
        loop {
            line.clear();
            self.stream.read_line(&mut line)?;
            let header = line.trim_end();
            if header.is_empty() {
                break;
            }
            if let Some(value) = header
                .to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(str::trim)
            {
                content_length = Some(value.parse().context("parse Content-Length")?);
            }
        }
        let length = content_length
            .with_context(|| format!("REST response without Content-Length: {status}"))?;
        if length > Self::MAX_BODY_BYTES {
            bail!("REST GET {path}: Content-Length {length} exceeds sane bound ({status})");
        }
        let mut body = vec![0_u8; length];
        // Drain the body before judging the status so a kept-alive connection
        // stays in sync after an HTTP error response.
        self.stream.read_exact(&mut body)?;
        let status_code = status.split_whitespace().nth(1);
        if status_code != Some("200") {
            bail!("REST GET {path} failed: {status}");
        }
        Ok(body)
    }
}
