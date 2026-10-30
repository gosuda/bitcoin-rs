use std::fs::File;
use std::io::{self, BufReader, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use bitcoin_rs_p2pk_scan::{ScanError, ScanReport, scan_blocks};
use clap::Parser;

#[derive(Parser)]
#[command(
    about = "List unspent pay-to-pubkey outputs from a raw block file",
    version
)]
struct Args {
    /// Hexadecimal blocks, one per line, in canonical order from the genesis block
    blocks: PathBuf,
    /// Emit the report as JSON
    #[arg(long)]
    json: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _stderr_gone = writeln!(io::stderr(), "p2pk-scan: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &Args) -> Result<(), RunError> {
    let file = File::open(&args.blocks).map_err(|source| RunError::Open {
        path: args.blocks.clone(),
        source,
    })?;
    let report = scan_blocks(BufReader::with_capacity(1 << 20, file))?;
    let stdout = io::stdout();
    let mut out = stdout.lock();
    if args.json {
        let json = sonic_rs::to_vec_pretty(&report)?;
        out.write_all(&json)?;
        out.write_all(b"\n")?;
    } else {
        write_table(&mut out, &report)?;
    }
    Ok(())
}

fn write_table(out: &mut impl Write, report: &ScanReport) -> io::Result<()> {
    writeln!(out, "TXID:VOUT HEIGHT VALUE_SAT KEY PUBKEY")?;
    for coin in &report.p2pk {
        writeln!(
            out,
            "{}:{} {} {} {} {}",
            coin.txid,
            coin.vout,
            coin.height,
            coin.value_sat,
            key_label(coin.key),
            coin.pubkey
        )?;
    }
    writeln!(
        out,
        "p2pk_outputs {} value_sat {} utxo_outputs {} blocks {} tip_height {}",
        report.p2pk_outputs,
        report.p2pk_value_sat,
        report.utxo_outputs,
        report.blocks,
        report.tip_height
    )
}

const fn key_label(key: bitcoin_rs_p2pk_scan::KeyShape) -> &'static str {
    match key {
        bitcoin_rs_p2pk_scan::KeyShape::Compressed => "compressed",
        bitcoin_rs_p2pk_scan::KeyShape::Uncompressed => "uncompressed",
    }
}

#[derive(Debug, thiserror::Error)]
enum RunError {
    #[error("{path}: {source}", path = path.display())]
    Open {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(transparent)]
    Scan(#[from] ScanError),
    #[error("report output failed: {0}")]
    Output(#[from] io::Error),
    #[error("report encoding failed: {0}")]
    Json(#[from] sonic_rs::Error),
}
