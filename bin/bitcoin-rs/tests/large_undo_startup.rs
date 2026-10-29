#![cfg(feature = "fjall")]

use bitcoin::hashes::Hash;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use bitcoin_rs_e2e::{Kind, ProcessNode, SpawnOptions};
use bitcoin_rs_storage::{FjallStore, KvUndoStore, UndoStore};
use sonic_rs::json;
use std::error::Error;
use std::sync::Arc;
use std::time::{Duration, Instant};

type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;

#[path = "support/regtest_blocks.rs"]
mod regtest_blocks;
use regtest_blocks::{block, coinbase, submit};

#[test]
#[ignore = "manual pinned-Core reproduction: writes over 64 MiB of real spent scripts"]
fn valid_large_undo_reopens_and_verifies() -> Result {
    let mut core = ProcessNode::spawn(Kind::Core)?;
    let options = SpawnOptions::default();
    let mut native = ProcessNode::spawn_with(Kind::BitcoinRs, &options)?;
    println!(
        "D native_pid={} evidence={} core_evidence={}",
        native.pid(),
        native.evidence.display(),
        core.evidence.display()
    );
    let candidate = fund_spendable_scripts(&core, &native)?;
    let evidence = native.evidence.clone();
    std::fs::write(
        evidence.join("spent-block.dat"),
        bitcoin::consensus::serialize(&candidate),
    )?;
    submit(&core, &candidate)?;
    submit(&native, &candidate)?;
    println!(
        "D native_accepted={} core_accepted={}",
        native.rpc("getblockcount", &json!([]))?,
        core.rpc("getblockcount", &json!([]))?
    );
    println!("D peak_before_verify_bytes={}", peak_rss(native.pid())?);
    let started = Instant::now();
    println!(
        "D core_verify={:?} elapsed_ms={}",
        core.rpc("verifychain", &json!([2, 1])),
        started.elapsed().as_millis()
    );
    let started = Instant::now();
    let verified = native.rpc("verifychain", &json!([2, 1]));
    println!(
        "D native_verify={verified:?} elapsed_ms={}",
        started.elapsed().as_millis()
    );
    assert_eq!(verified?, json!(true));
    println!("D peak_after_verify_bytes={}", peak_rss(native.pid())?);
    let directory = native.stop_keep_datadir()?;
    {
        let store = Arc::new(FjallStore::open(directory.path().join("node/chainstate"))?);
        let undo = KvUndoStore::new(store);
        let hash =
            bitcoin_rs_primitives::Hash256::from_le_bytes(&candidate.block_hash().to_byte_array());
        let started = Instant::now();
        let record = undo.load_undo(189, hash)?.ok_or("node-written undo")?;
        println!(
            "D node_written_undo_bytes={} read_ms={}",
            record.len(),
            started.elapsed().as_millis()
        );
        assert!(record.len() > 64 * 1024 * 1024);
        std::fs::write(evidence.join("undo.dat"), &record)?;
    }
    let started = Instant::now();
    let restarted = ProcessNode::spawn_in_datadir(
        Kind::BitcoinRs,
        &SpawnOptions {
            timeout: Some(Duration::from_secs(90)),
            ..options
        },
        directory,
    );
    println!(
        "D native_restart={:?} elapsed_ms={}",
        restarted.as_ref().map(ProcessNode::pid),
        started.elapsed().as_millis()
    );
    let mut node = restarted?;
    println!("D restart_peak_bytes={}", peak_rss(node.pid())?);
    assert_eq!(node.rpc("verifychain", &json!([2, 1]))?, json!(true));
    node.stop()?;
    let directory = core.stop_keep_datadir()?;
    let mut restarted =
        ProcessNode::spawn_in_datadir(Kind::Core, &SpawnOptions::default(), directory)?;
    assert_eq!(restarted.rpc("verifychain", &json!([2, 1]))?, json!(true));
    restarted.stop()?;
    Ok(())
}

fn peak_rss(pid: u32) -> Result<String> {
    #[cfg(windows)]
    {
        let output = std::process::Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-Command",
                &format!("(Get-Process -Id {pid}).PeakWorkingSet64"),
            ])
            .output()?;
        if !output.status.success() {
            return Err("peak RSS query failed".into());
        }
        Ok(String::from_utf8(output.stdout)?.trim().to_owned())
    }
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
        let kilobytes: u64 = status
            .lines()
            .find(|line| line.starts_with("VmHWM:"))
            .ok_or("VmHWM")?
            .split_whitespace()
            .nth(1)
            .ok_or("VmHWM value")?
            .parse()?;
        Ok(kilobytes
            .checked_mul(1024)
            .ok_or("RSS overflow")?
            .to_string())
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = pid;
        Ok("not measured on this platform".to_owned())
    }
}

fn fund_spendable_scripts(core: &ProcessNode, native: &ProcessNode) -> Result<bitcoin::Block> {
    let mut script = vec![0x00, 0x63];
    for _ in 0..19 {
        script.extend_from_slice(&[0x4d, 0x08, 0x02]);
        script.extend_from_slice(&[0; 520]);
    }
    script.push(58);
    script.extend_from_slice(&[0; 58]);
    script.extend_from_slice(&[0x68, 0x51]);
    assert_eq!(script.len(), 10_000);
    let funding = TxOut {
        value: Amount::from_sat(1_000),
        script_pubkey: ScriptBuf::from_bytes(script),
    };
    let simple = || TxOut {
        value: Amount::from_sat(0),
        script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
    };
    let mut previous =
        bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest).block_hash();
    let time = 1_792_394_894;
    println!("D fixture_time={time}");
    let mut inputs = Vec::new();
    let started = Instant::now();
    for height in 1..=188 {
        let outputs = if height <= 88 {
            vec![funding.clone(); 80]
        } else {
            vec![simple()]
        };
        let cb = coinbase(height, outputs);
        if height <= 88 {
            for vout in 0..80 {
                if inputs.len() < 7_000 {
                    inputs.push(TxIn {
                        previous_output: OutPoint::new(cb.compute_txid(), vout),
                        script_sig: ScriptBuf::new(),
                        sequence: Sequence::MAX,
                        witness: Witness::new(),
                    });
                }
            }
        }
        let candidate = block(previous, time + height, vec![cb])?;
        submit(core, &candidate)?;
        submit(native, &candidate)?;
        previous = candidate.block_hash();
    }
    let spend = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: inputs,
        output: vec![TxOut {
            value: Amount::from_sat(6_999_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let candidate = block(
        previous,
        time + 189,
        vec![coinbase(189, vec![simple()]), spend],
    )?;
    println!(
        "D funding_ms={} inputs=7000 previous_script_bytes=10000 block_bytes={} weight={}",
        started.elapsed().as_millis(),
        bitcoin::consensus::serialize(&candidate).len(),
        candidate.weight().to_wu()
    );
    Ok(candidate)
}
