use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use swiftsync_poc::chain::{self, Chain, ChainSpec};
use swiftsync_poc::fold::{self, SyncOptions};
use swiftsync_poc::hints::{self, HintSet};
use swiftsync_poc::metrics::{self, Meter};
use swiftsync_poc::{Error, reconstruct};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("swiftsync-poc: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Error> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = args.first() else {
        return Err(Error::Usage);
    };
    let flags = parse_flags(&args[1..])?;
    match command.as_str() {
        "gen" => generate(&flags),
        "sync" => run_sync(&flags),
        "verify" => verify(&flags),
        "reconstruct" => run_reconstruct(&flags),
        other => Err(Error::UnknownArgument {
            argument: other.to_owned(),
        }),
    }
}

fn parse_flags(args: &[String]) -> Result<BTreeMap<String, String>, Error> {
    let mut flags = BTreeMap::new();
    let mut index = 0;
    while index < args.len() {
        let argument = &args[index];
        let Some(name) = argument.strip_prefix("--") else {
            return Err(Error::UnknownArgument {
                argument: argument.clone(),
            });
        };
        let Some(value) = args.get(index.saturating_add(1)) else {
            return Err(Error::MissingFlag {
                flag: format!("--{name}"),
            });
        };
        flags.insert(name.to_owned(), value.clone());
        index = index.saturating_add(2);
    }
    Ok(flags)
}

fn flag<'a>(flags: &'a BTreeMap<String, String>, name: &'static str) -> Result<&'a str, Error> {
    flags
        .get(name.trim_start_matches("--"))
        .map(String::as_str)
        .ok_or_else(|| Error::MissingFlag {
            flag: name.to_owned(),
        })
}

fn line(key: &str, value: impl std::fmt::Display) {
    println!("{key:<26} {value}");
}

fn rss(measure: metrics::Measure) -> String {
    measure
        .process_peak_rss_kib
        .map_or_else(|| "unavailable".to_owned(), metrics::mib)
}

fn generate(flags: &BTreeMap<String, String>) -> Result<(), Error> {
    let out = PathBuf::from(flag(flags, "--out")?);
    std::fs::create_dir_all(&out).map_err(|source| Error::Io {
        path: out.clone(),
        source,
    })?;
    let meter = Meter::start();
    let chain = chain::build(ChainSpec::pinned())?;
    chain.validate()?;
    let hints = HintSet::from_chain(&chain);
    let chain_path = out.join("chain.txt");
    let hints_path = out.join("hints.txt");
    let snapshot_path = out.join("reconstruction.bin");
    chain.write(&chain_path)?;
    hints.write(&hints_path)?;
    let reconstruction = reconstruct(&chain, Some(&snapshot_path))?;
    let measure = meter.finish();
    line("seed", format!("{:#018x}", chain::PINNED_SEED));
    line("blocks", chain.height().saturating_add(1));
    line("transactions", chain.transaction_count());
    line("tip", chain.tip());
    line("final_coins", hints.coins.len());
    line("final_muhash", reconstruction.muhash.to_string_be());
    line("chain_bytes", file_len(&chain_path)?);
    line("hints_bytes", file_len(&hints_path)?);
    line("hints_payload_bytes", hints.payload_bytes());
    line("snapshot_bytes", file_len(&snapshot_path)?);
    line("wall_ms", metrics::milliseconds(measure.wall));
    line("cpu_ms", metrics::milliseconds(measure.cpu));
    line("process_peak_rss_mib", rss(measure));
    Ok(())
}

fn run_sync(flags: &BTreeMap<String, String>) -> Result<(), Error> {
    let chain = Chain::read(Path::new(flag(flags, "--chain")?))?;
    chain.validate()?;
    let hints = HintSet::read(Path::new(flag(flags, "--hints")?))?;
    let checkpoint = flags.get("checkpoint").map(PathBuf::from);
    let options = SyncOptions {
        checkpoint: checkpoint.as_deref(),
        checkpoint_every: 100,
        simulate_crash_after: match flags.get("simulate-crash-after") {
            Some(value) => Some(value.parse::<u32>().map_err(|_| Error::FlagValue {
                flag: "--simulate-crash-after",
                value: value.clone(),
            })?),
            None => None,
        },
    };
    let meter = Meter::start();
    let report = fold::sync(&chain, &hints, &options)?;
    let measure = meter.finish();
    let diff = hints::compare(&hints, &chain.final_set);
    line("blocks_folded", report.folded);
    line("resumed_from", report.resumed_from);
    line("hint_coins", report.hint_coins);
    line("created", report.created);
    line("spent", report.spent);
    line("body_bytes_folded", report.body_bytes);
    line("folded_muhash", report.folded_muhash.to_string_be());
    line("aggregate_muhash", report.aggregate_muhash.to_string_be());
    line(
        "hint_set_diff",
        format!(
            "{} missing, {} extra, {} mismatched",
            diff.missing, diff.extra, diff.mismatched
        ),
    );
    line("wall_ms", metrics::milliseconds(measure.wall));
    line("cpu_ms", metrics::milliseconds(measure.cpu));
    line("process_peak_rss_mib", rss(measure));
    Ok(())
}

fn verify(flags: &BTreeMap<String, String>) -> Result<(), Error> {
    let chain = Chain::read(Path::new(flag(flags, "--chain")?))?;
    chain.validate()?;
    let hints = HintSet::read(Path::new(flag(flags, "--hints")?))?;
    let snapshot = flags.get("snapshot").map(PathBuf::from);
    let fold_meter = Meter::start();
    let report = fold::sync(&chain, &hints, &SyncOptions::default())?;
    let fold_measure = fold_meter.finish();
    let reconstruct_meter = Meter::start();
    let reconstruction = reconstruct(&chain, snapshot.as_deref())?;
    let reconstruct_measure = reconstruct_meter.finish();
    let diff = hints::compare(&hints, &chain.final_set);
    if !diff.is_empty() {
        return Err(Error::HintSetMismatch {
            missing: diff.missing,
            extra: diff.extra,
            mismatched: diff.mismatched,
        });
    }
    if report.folded_muhash != reconstruction.muhash {
        return Err(Error::StatsDivergence {
            listener: report.folded_muhash.to_string_be(),
            scan: reconstruction.muhash.to_string_be(),
        });
    }
    line("blocks", chain.height().saturating_add(1));
    line("tx_count", reconstruction.tx_count);
    line("final_coins", reconstruction.coins);
    line("final_muhash", reconstruction.muhash.to_string_be());
    line("fold_body_bytes", report.body_bytes);
    line("fold_created", report.created);
    line("fold_spent", report.spent);
    line("fold_wall_ms", metrics::milliseconds(fold_measure.wall));
    line("fold_cpu_ms", metrics::milliseconds(fold_measure.cpu));
    line("fold_peak_rss_mib", rss(fold_measure));
    line("reconstruct_body_bytes", reconstruction.body_bytes);
    line("reconstruct_prevout_reads", reconstruction.prevout_reads);
    line("reconstruct_coins_written", reconstruction.coins_written);
    line("reconstruct_undo_entries", reconstruction.undo_entries);
    line(
        "reconstruct_accounted_bytes",
        reconstruction.accounted_bytes,
    );
    line(
        "reconstruct_snapshot_bytes",
        reconstruction
            .snapshot_bytes
            .map_or_else(|| "not written".to_owned(), |value| value.to_string()),
    );
    line(
        "reconstruct_wall_ms",
        metrics::milliseconds(reconstruct_measure.wall),
    );
    line(
        "reconstruct_cpu_ms",
        metrics::milliseconds(reconstruct_measure.cpu),
    );
    line("process_peak_rss_mib", rss(reconstruct_measure));
    line("aggregate", "identity (zero)");
    line("hint_set", "equals the reconstructed final set");
    line(
        "muhash",
        "fold equals gettxoutsetinfo over the reconstruction",
    );
    Ok(())
}

fn run_reconstruct(flags: &BTreeMap<String, String>) -> Result<(), Error> {
    let chain = Chain::read(Path::new(flag(flags, "--chain")?))?;
    chain.validate()?;
    let snapshot = flags.get("snapshot").map(PathBuf::from);
    let meter = Meter::start();
    let report = reconstruct(&chain, snapshot.as_deref())?;
    let measure = meter.finish();
    line("blocks", report.blocks);
    line("tx_count", report.tx_count);
    line("final_coins", report.coins);
    line("final_muhash", report.muhash.to_string_be());
    line("body_bytes", report.body_bytes);
    line("prevout_reads", report.prevout_reads);
    line("coins_written", report.coins_written);
    line("undo_entries", report.undo_entries);
    line("accounted_bytes", report.accounted_bytes);
    line(
        "snapshot_bytes",
        report
            .snapshot_bytes
            .map_or_else(|| "not written".to_owned(), |value| value.to_string()),
    );
    line("wall_ms", metrics::milliseconds(measure.wall));
    line("cpu_ms", metrics::milliseconds(measure.cpu));
    line("process_peak_rss_mib", rss(measure));
    Ok(())
}

fn file_len(path: &Path) -> Result<u64, Error> {
    std::fs::metadata(path)
        .map(|metadata| metadata.len())
        .map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })
}
