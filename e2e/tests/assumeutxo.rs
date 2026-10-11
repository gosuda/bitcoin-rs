//! Core-produced portable snapshots over the public RPC and P2P boundaries.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::path::Path;
use std::time::{Duration, Instant};

use bitcoin::consensus::{deserialize, encode::serialize_hex};
use bitcoin::hex::FromHex as _;
use bitcoin::{Block, Witness};
use bitcoin_rs_e2e::helpers::{
    funding_address, funding_output, grind_pow, mempool_txids, op_true_script, spend_anyone,
};
use bitcoin_rs_e2e::live_peer::LivePeer;
use bitcoin_rs_e2e::{Error, Kind, ProcessNode, Result, SpawnOptions, ValueExt};
use serde_json::{Value, json};

const BASE: &str = "385901ccbd69dff6bbd00065d01fb8a9e464dede7cfe0372443884f9b1dcf6b9";
const COMMITMENT: &str = "17dcc016d188d16068907cdeb38b75691a118d43053b8cd6a25969419381d13a";
const CORE_SNAPSHOT: &[u8] = include_bytes!("../../crates/utxo/tests/fixtures/core-v2/core200.dat");
const CORE_BLOCKS: &str = include_str!("../../crates/utxo/tests/fixtures/core-v2/blocks200.json");

fn core_blocks() -> Result<Vec<Block>> {
    let hex: Vec<String> = serde_json::from_str(CORE_BLOCKS)?;
    hex.iter()
        .map(|raw| {
            let bytes =
                Vec::<u8>::from_hex(raw).map_err(|error| Error::Assertion(error.to_string()))?;
            deserialize(&bytes).map_err(|error| Error::Assertion(error.to_string()))
        })
        .collect()
}

fn admit_headers(node: &mut ProcessNode, blocks: &[Block]) -> Result<()> {
    for block in blocks {
        assert!(
            node.rpc("submitheader", &json!([serialize_hex(&block.header)]))?
                .is_null()
        );
    }
    Ok(())
}

fn states(node: &mut ProcessNode) -> Result<Value> {
    // Sending a historical block is not an acknowledgement that validation has
    // released the lifecycle owner. Retry only this declared transient result,
    // with one deadline shared by transport and polling; preserve other errors.
    let deadline = Instant::now() + bitcoin_rs_e2e::node::REQUEST_TIMEOUT;
    loop {
        match node.rpc_until("getchainstates", &json!([]), deadline) {
            Err(Error::Rpc {
                ref method,
                code: -32603,
                ref message,
            }) if method == "getchainstates"
                && message == "internal error: snapshot lifecycle update is in progress"
                && Instant::now() < deadline =>
            {
                std::thread::sleep(
                    Duration::from_millis(10)
                        .min(deadline.saturating_duration_since(Instant::now())),
                );
            }
            result => return result,
        }
    }
}

fn reject(node: &mut ProcessNode, path: &Path, code: i64) -> Result<()> {
    let reply =
        node.rpc_raw(&json!({"jsonrpc":"2.0","id":1,"method":"loadtxoutset","params":[path]}))?;
    assert_eq!(reply["error"]["code"], json!(code), "{reply}");
    Ok(())
}

fn record_import_resources(node: &ProcessNode, snapshot: &Path) -> Result<()> {
    // Linux reports the process-wide high-water RSS, including startup. Other
    // platforms report unavailable instead of inventing an equivalent metric.
    let peak_rss_kib = if cfg!(target_os = "linux") {
        std::fs::read_to_string(format!("/proc/{}/status", node.pid()))
            .ok()
            .and_then(|status| {
                status.lines().find_map(|line| {
                    line.strip_prefix("VmHWM:")?
                        .split_whitespace()
                        .next()?
                        .parse::<u64>()
                        .ok()
                })
            })
    } else {
        None
    };
    let evidence = json!({
        "platform": std::env::consts::OS,
        "architecture": std::env::consts::ARCH,
        "snapshot_bytes": std::fs::metadata(snapshot)?.len(),
        "unspent_outputs": 200,
        "process_peak_rss_kib_at_import": peak_rss_kib,
        "scope": "Core regtest 200-height import; whole-process high-water, not incremental import RSS or mainnet qualification",
    });
    std::fs::write(
        node.evidence.join("snapshot-import-resources.json"),
        serde_json::to_vec_pretty(&evidence)?,
    )?;
    Ok(())
}

fn produce_core_snapshot(snapshot_path: &Path) -> Result<(ProcessNode, Vec<Block>)> {
    let mut core = ProcessNode::spawn(Kind::Core)?;
    let mut blocks = core_blocks()?;
    for block in &blocks {
        assert!(
            core.rpc("submitblock", &json!([serialize_hex(block)]))?
                .is_null()
        );
    }
    let dump = core.rpc("dumptxoutset", &json!([snapshot_path, "latest"]))?;
    assert_eq!(dump["base_hash"], BASE);
    assert_eq!(dump["txoutset_hash"], COMMITMENT);
    assert_eq!(dump["nchaintx"], 201);
    assert_eq!(dump["coins_written"], 200);
    assert_eq!(
        std::fs::read(snapshot_path)?,
        CORE_SNAPSHOT,
        "unmodified Core artifact must reproduce the fixture"
    );
    let hashes = core.rpc(
        "generatetoaddress",
        &json!([6, funding_address()?.to_string()]),
    )?;
    for hash in hashes
        .as_array()
        .ok_or_else(|| Error::Assertion("mined hashes not an array".into()))?
    {
        let raw = core.rpc("getblock", &json!([hash, 0]))?;
        let bytes = Vec::<u8>::from_hex(
            raw.as_str()
                .ok_or_else(|| Error::Assertion("block hex absent".into()))?,
        )
        .map_err(|error| Error::Assertion(error.to_string()))?;
        blocks.push(deserialize(&bytes).map_err(|error| Error::Assertion(error.to_string()))?);
    }
    Ok((core, blocks))
}

fn reach_partial_history(node: &mut ProcessNode, blocks: &[Block]) -> Result<()> {
    // Hold back history after height 10 while serving the Core-generated
    // foreground suffix. This proves the roles can advance independently and
    // gives restart a deterministic nonterminal point without timing races.
    let allowed: BTreeSet<_> = blocks[..10]
        .iter()
        .chain(blocks[200..].iter())
        .map(Block::block_hash)
        .collect();
    let mut peer = LivePeer::connect_with_height(node, "assumeutxo-partial", 206)?;
    peer.offer_chain(blocks);
    peer.announce_headers(blocks, Instant::now() + Duration::from_secs(10))?;
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut last = Value::Null;
    while Instant::now() < deadline {
        peer.pump(Duration::from_millis(100), &mut |peer, items| {
            for item in items {
                let hash = match item {
                    bitcoin::p2p::message_blockdata::Inventory::Block(hash)
                    | bitcoin::p2p::message_blockdata::Inventory::WitnessBlock(hash)
                    | bitcoin::p2p::message_blockdata::Inventory::CompactBlock(hash) => hash,
                    _ => continue,
                };
                if allowed.contains(hash) {
                    peer.serve_item(item, Instant::now() + Duration::from_secs(2))
                        .expect("serve bounded Core body");
                }
            }
        });
        last = states(node)?;
        if last["chainstates"][0]["blocks"] == 10 && last["chainstates"][1]["blocks"] == 206 {
            break;
        }
    }
    assert_eq!(last["chainstates"][0]["blocks"], 10, "{last}");
    assert_eq!(last["chainstates"][1]["blocks"], 206, "{last}");
    assert!(
        peer.requests_for(&blocks[10].block_hash()) > 0,
        "history must be waiting on a real withheld body"
    );
    drop(peer);
    Ok(())
}

/// Produce the portable bytes anew with the pinned Core process, then prove
/// foreground progress, partial historical validation, restart, and convergence.
#[test]
fn core_snapshot_import_syncs_both_roles_and_recovers() -> Result<()> {
    let artifacts = tempfile::tempdir()?;
    let snapshot_path = artifacts.path().join("core200.dat");
    let (mut core, blocks) = produce_core_snapshot(&snapshot_path)?;
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    let ordinary = states(&mut node)?;
    assert_eq!(ordinary["chainstates"].as_array().unwrap().len(), 1);
    assert_eq!(ordinary["chainstates"][0]["validated"], true);
    admit_headers(&mut node, &blocks)?;
    let imported = node.rpc("loadtxoutset", &json!([snapshot_path]))?;
    assert_eq!(imported["coins_loaded"], 200);
    assert_eq!(imported["tip_hash"], BASE);
    assert_eq!(imported["base_height"], 200);
    record_import_resources(&node, &snapshot_path)?;
    let assumed = states(&mut node)?;
    assert_eq!(assumed["headers"], 206);
    assert_eq!(assumed["chainstates"].as_array().unwrap().len(), 2);
    assert_eq!(assumed["chainstates"][0]["blocks"], 0);
    assert_eq!(assumed["chainstates"][0]["validated"], true);
    assert_eq!(assumed["chainstates"][1]["blocks"], 200);
    assert_eq!(assumed["chainstates"][1]["snapshot_blockhash"], BASE);
    assert_eq!(assumed["chainstates"][1]["validated"], false);
    reject(&mut node, &snapshot_path, -32603)?;

    reach_partial_history(&mut node, &blocks)?;
    let datadir = node.stop_keep_datadir()?;
    let mut node =
        ProcessNode::spawn_in_datadir(Kind::BitcoinRs, &SpawnOptions::default(), datadir)?;
    // Recovery reconstructs coins from the retained historical archive; it
    // must not fabricate the durable cursor before that replay completes.
    let recovered = node.wait_for(
        "recover historical archive without a peer",
        Duration::from_secs(15),
        |node| {
            let view = states(node)?;
            Ok((view["chainstates"][0]["blocks"] == 10).then_some(view))
        },
    )?;
    assert_eq!(recovered["chainstates"][0]["blocks"], 10, "{recovered}");
    assert_eq!(recovered["chainstates"][1]["blocks"], 206, "{recovered}");
    assert_eq!(recovered["chainstates"][1]["validated"], false);

    // A genuine Core P2P peer supplies the remaining historical bodies.
    node.rpc("addnode", &json!([core.p2p_addr.to_string(), "onetry"]))?;
    node.wait_for(
        "snapshot historical convergence",
        Duration::from_secs(120),
        |node| {
            let view = states(node)?;
            Ok((view["chainstates"]
                .as_array()
                .is_some_and(|rows| rows.len() == 1)
                && view["chainstates"][0]["validated"] == true)
                .then_some(view))
        },
    )?;
    assert_eq!(
        node.rpc("getbestblockhash", &json!([]))?,
        core.rpc("getbestblockhash", &json!([]))?
    );
    assert_eq!(
        node.rpc("gettxoutsetinfo", &json!(["hash_serialized_3"]))?["hash_serialized_3"],
        core.rpc("gettxoutsetinfo", &json!(["hash_serialized_3"]))?["hash_serialized_3"]
    );
    assert_eq!(
        std::fs::read(&snapshot_path)?,
        CORE_SNAPSHOT,
        "source artifact unchanged"
    );
    let datadir = node.stop_keep_datadir()?;
    let mut node =
        ProcessNode::spawn_in_datadir(Kind::BitcoinRs, &SpawnOptions::default(), datadir)?;
    let final_view = states(&mut node)?;
    assert_eq!(final_view["chainstates"].as_array().unwrap().len(), 1);
    assert_eq!(final_view["chainstates"][0]["blocks"], 206);
    assert_eq!(final_view["chainstates"][0]["validated"], true);
    assert_eq!(final_view["chainstates"][0]["snapshot_blockhash"], BASE);
    node.stop()?;
    core.stop()
}

#[test]
fn invalid_core_snapshots_fail_without_activating() -> Result<()> {
    let datadir = tempfile::tempdir()?;
    let snapshot = datadir.path().join("node/core200.dat");
    let mut node =
        ProcessNode::spawn_in_datadir(Kind::BitcoinRs, &SpawnOptions::default(), datadir)?;
    std::fs::write(&snapshot, CORE_SNAPSHOT)?;
    // A correct portable snapshot cannot bootstrap trusted headers by itself.
    reject(&mut node, &snapshot, -32603)?;
    assert_eq!(states(&mut node)?["chainstates"][0]["blocks"], 0);
    admit_headers(&mut node, &core_blocks()?)?;
    let cases = tempfile::tempdir()?;
    let mut malformed = Vec::new();
    malformed.push((
        "truncated",
        CORE_SNAPSHOT[..CORE_SNAPSHOT.len() - 1].to_vec(),
    ));
    let mut wrong_network = CORE_SNAPSHOT.to_vec();
    wrong_network[7] ^= 1;
    malformed.push(("wrong-network", wrong_network));
    let mut unpinned = CORE_SNAPSHOT.to_vec();
    unpinned[11] ^= 1;
    malformed.push(("unpinned", unpinned));
    let mut wrong_commitment = CORE_SNAPSHOT.to_vec();
    *wrong_commitment.last_mut().unwrap() ^= 1;
    malformed.push(("wrong-commitment", wrong_commitment));
    let mut trailing = CORE_SNAPSHOT.to_vec();
    trailing.push(0);
    malformed.push(("trailing", trailing));
    let mut duplicate = CORE_SNAPSHOT.to_vec();
    duplicate[43..51].copy_from_slice(&400_u64.to_le_bytes());
    duplicate.extend_from_slice(&CORE_SNAPSHOT[51..]);
    malformed.push(("duplicate", duplicate));
    for (name, bytes) in malformed {
        let path = cases.path().join(name);
        std::fs::write(&path, &bytes)?;
        reject(&mut node, &path, -22)?;
        assert_eq!(std::fs::read(&path)?, bytes);
        let view = states(&mut node)?;
        assert_eq!(
            view["chainstates"].as_array().unwrap().len(),
            1,
            "{name}: {view}"
        );
        assert_eq!(view["chainstates"][0]["blocks"], 0, "{name}: {view}");
    }
    // The RPC argument is UTF-8, but canonicalization can resolve its symlink
    // to a non-UTF-8 filename. Response serialization must still succeed after
    // activation; it must not report a post-commit error.
    #[cfg(unix)]
    {
        use std::os::unix::{ffi::OsStringExt as _, fs::symlink};
        let target =
            snapshot.with_file_name(std::ffi::OsString::from_vec(b"core-\xff.dat".to_vec()));
        std::fs::rename(&snapshot, &target)?;
        symlink(&target, &snapshot)?;
    }
    let imported = node.rpc("loadtxoutset", &json!({"path":"core200.dat"}))?;
    assert_eq!(
        imported["path"],
        snapshot.canonicalize()?.to_string_lossy().as_ref()
    );
    assert_eq!(imported["coins_loaded"], 200);
    assert!(Path::new(imported.str_field("path")?).is_absolute());
    reject(&mut node, &snapshot, -32603)?;
    node.stop()
}

fn ordinary_chainstate(node: &mut ProcessNode) -> Result<Value> {
    let view = states(node)?;
    assert_eq!(view["chainstates"].as_array().unwrap().len(), 1, "{view}");
    let active = &view["chainstates"][0];
    assert_eq!(active["validated"], true, "{view}");
    assert!(active["snapshot_blockhash"].is_null(), "{view}");
    Ok(json!({
        "headers": view["headers"],
        "blocks": active["blocks"],
        "bestblockhash": active["bestblockhash"],
    }))
}

/// The pinned base must belong to the best header chain, even while all
/// competing bodies are deliberately withheld. Restoring that ancestry must
/// allow a retry in the same process, without a failed-import lifecycle left over.
#[test]
fn snapshot_base_must_belong_to_best_header_chain() -> Result<()> {
    let artifacts = tempfile::tempdir()?;
    let snapshot = artifacts.path().join("core200.dat");
    std::fs::write(&snapshot, CORE_SNAPSHOT)?;
    let blocks = core_blocks()?;
    // A different height-200 header and its child beat the pinned branch.
    // These are header-only candidates: valid PoW and timestamps are checked
    // by both daemons; no corresponding block body is offered.
    let mut fork = blocks[199].header;
    fork.time += 1;
    fork.nonce = 0;
    grind_pow(&mut fork)?;
    assert_ne!(fork.block_hash().to_string(), BASE);
    let mut fork_child = fork;
    fork_child.prev_blockhash = fork.block_hash();
    fork_child.time += 1;
    fork_child.nonce = 0;
    grind_pow(&mut fork_child)?;

    let mut extension = blocks[199].header;
    extension.prev_blockhash = blocks[199].block_hash();
    extension.time += 1;
    extension.nonce = 0;
    grind_pow(&mut extension)?;
    let mut winner = extension;
    winner.prev_blockhash = extension.block_hash();
    winner.time += 1;
    winner.nonce = 0;
    grind_pow(&mut winner)?;

    for kind in [Kind::Core, Kind::BitcoinRs] {
        let mut node = ProcessNode::spawn(kind)?;
        admit_headers(&mut node, &blocks)?;
        for header in [&fork, &fork_child] {
            assert!(
                node.rpc("submitheader", &json!([serialize_hex(header)]))?
                    .is_null()
            );
        }
        let before = ordinary_chainstate(&mut node)?;
        assert_eq!(before["headers"], 201);
        reject(&mut node, &snapshot, -32603)?;
        assert_eq!(ordinary_chainstate(&mut node)?, before);
        assert_eq!(std::fs::read(&snapshot)?, CORE_SNAPSHOT);
        for header in [&extension, &winner] {
            assert!(
                node.rpc("submitheader", &json!([serialize_hex(header)]))?
                    .is_null()
            );
        }
        let imported = node.rpc("loadtxoutset", &json!([snapshot]))?;
        assert_eq!(imported["tip_hash"], BASE);
        assert_eq!(imported["coins_loaded"], 200);
        node.stop()?;
    }
    Ok(())
}

#[test]
fn invalidated_snapshot_base_cannot_activate() -> Result<()> {
    let artifacts = tempfile::tempdir()?;
    let snapshot = artifacts.path().join("core200.dat");
    std::fs::write(&snapshot, CORE_SNAPSHOT)?;
    let blocks = core_blocks()?;
    for kind in [Kind::Core, Kind::BitcoinRs] {
        let mut node = ProcessNode::spawn(kind)?;
        // Keep the surviving parent fully validated so invalidation does not
        // also need to fetch missing historical bodies on the ordinary chain.
        for block in &blocks[..199] {
            assert!(
                node.rpc("submitblock", &json!([serialize_hex(block)]))?
                    .is_null()
            );
        }
        admit_headers(&mut node, &blocks[199..])?;
        assert!(node.rpc("invalidateblock", &json!([BASE]))?.is_null());
        let before = ordinary_chainstate(&mut node)?;
        reject(&mut node, &snapshot, -32603)?;
        assert_eq!(ordinary_chainstate(&mut node)?, before);
        assert_eq!(std::fs::read(&snapshot)?, CORE_SNAPSHOT);
        node.stop()?;
    }
    Ok(())
}

/// Refusing a nonempty pool must preserve the transaction and ordinary tip.
/// Confirming it on a short active fork drains the pool while the original
/// 200-header branch still wins, allowing an immediate import retry.
#[test]
fn nonempty_mempool_refuses_snapshot_without_losing_transaction() -> Result<()> {
    let artifacts = tempfile::tempdir()?;
    let snapshot = artifacts.path().join("core200.dat");
    std::fs::write(&snapshot, CORE_SNAPSHOT)?;
    let blocks = core_blocks()?;
    let (outpoint, prevout) = funding_output(&blocks[0].txdata[0])?;
    let witness_script = op_true_script();
    assert_eq!(prevout.script_pubkey, witness_script.to_p2wsh());
    let mut spend = spend_anyone(outpoint, &prevout, 1_000);
    spend.input[0].witness = Witness::from_slice(&[witness_script.as_bytes()]);
    let txid = spend.compute_txid().to_string();
    let mut confirmation: Option<Block> = None;
    for kind in [Kind::Core, Kind::BitcoinRs] {
        let mut node = ProcessNode::spawn(kind)?;
        for block in &blocks[..101] {
            assert!(
                node.rpc("submitblock", &json!([serialize_hex(block)]))?
                    .is_null()
            );
        }
        admit_headers(&mut node, &blocks[101..])?;
        assert_eq!(
            node.rpc("sendrawtransaction", &json!([serialize_hex(&spend)]))?,
            txid
        );
        assert_eq!(mempool_txids(&mut node)?, std::slice::from_ref(&txid));
        let before = ordinary_chainstate(&mut node)?;
        assert_eq!(before["blocks"], 101);
        let reply = node.rpc_raw(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "loadtxoutset", "params": [snapshot]
        }))?;
        assert_eq!(reply["error"]["code"], -32603, "{reply}");
        assert!(
            reply["error"]["message"]
                .as_str()
                .unwrap()
                .contains("mempool"),
            "{reply}"
        );
        assert_eq!(mempool_txids(&mut node)?, std::slice::from_ref(&txid));
        assert_eq!(ordinary_chainstate(&mut node)?, before);
        assert_eq!(std::fs::read(&snapshot)?, CORE_SNAPSHOT);

        if kind == Kind::Core {
            let mined = node.rpc(
                "generateblock",
                &json!([funding_address()?.to_string(), [txid]]),
            )?;
            let raw = node.rpc("getblock", &json!([mined["hash"], 0]))?;
            let bytes = Vec::<u8>::from_hex(raw.as_str().unwrap())
                .map_err(|error| Error::Assertion(error.to_string()))?;
            confirmation =
                Some(deserialize(&bytes).map_err(|error| Error::Assertion(error.to_string()))?);
        } else {
            assert!(
                node.rpc(
                    "submitblock",
                    &json!([serialize_hex(confirmation.as_ref().unwrap())])
                )?
                .is_null()
            );
        }
        assert_eq!(mempool_txids(&mut node)?, Vec::<String>::new());
        assert_eq!(ordinary_chainstate(&mut node)?["blocks"], 102);
        let imported = node.rpc("loadtxoutset", &json!([snapshot]))?;
        assert_eq!(imported["tip_hash"], BASE);
        assert_eq!(imported["coins_loaded"], 200);
        node.stop()?;
    }
    Ok(())
}

#[test]
fn corrupt_snapshot_recovery_fails_closed() -> Result<()> {
    let artifacts = tempfile::tempdir()?;
    let snapshot = artifacts.path().join("core200.dat");
    std::fs::write(&snapshot, CORE_SNAPSHOT)?;
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    admit_headers(&mut node, &core_blocks()?)?;
    node.rpc("loadtxoutset", &json!([snapshot]))?;
    // A crash leaves the committed import archive authoritative. A clean
    // shutdown could legitimately publish a newer checkpoint superseding it.
    let datadir = node.take_datadir()?;
    node.send_sigkill();
    drop(node);
    let recovery = datadir.path().join("node/assumeutxo");
    let base_dir = std::fs::read_dir(&recovery)?
        .next()
        .ok_or_else(|| Error::Assertion("snapshot archive absent".into()))??
        .path();
    let coins = base_dir.join("coins.dat");
    let mut bytes = std::fs::read(&coins)?;
    bytes[0] ^= 1;
    std::fs::write(&coins, bytes)?;
    let start = ProcessNode::spawn_in_datadir(Kind::BitcoinRs, &SpawnOptions::default(), datadir);
    let evidence = match start {
        Err(Error::ChildExit { evidence, .. }) => evidence,
        other => {
            return Err(Error::Assertion(format!(
                "corrupt archive must refuse startup: {other:?}"
            )));
        }
    };
    let stderr = std::fs::read_to_string(evidence.join("stderr.log"))?;
    assert!(
        stderr.contains("invalid snapshot magic"),
        "startup must reject the committed corrupt archive: {stderr}"
    );
    assert_eq!(std::fs::read(&snapshot)?, CORE_SNAPSHOT);
    Ok(())
}

#[test]
fn core_import_preserves_source_hardlinked_to_archive_staging() -> Result<()> {
    let artifacts = tempfile::tempdir()?;
    let source = artifacts.path().join("core200.dat");
    std::fs::write(&source, CORE_SNAPSHOT)?;
    let datadir = tempfile::tempdir()?;
    let archive = datadir.path().join("node/assumeutxo").join(BASE);
    let mut node =
        ProcessNode::spawn_in_datadir(Kind::BitcoinRs, &SpawnOptions::default(), datadir)?;
    admit_headers(&mut node, &core_blocks()?)?;
    std::fs::create_dir_all(&archive)?;
    for name in ["coins.tmp", "headers.tmp", "coins.dat", "headers.dat"] {
        std::fs::hard_link(&source, archive.join(name))?;
    }
    node.rpc("loadtxoutset", &json!([source]))?;
    assert_eq!(std::fs::read(&source)?, CORE_SNAPSHOT);
    for name in ["coins.tmp", "headers.tmp"] {
        assert_eq!(
            std::fs::read(archive.join(name))?,
            CORE_SNAPSHOT,
            "pre-existing {name} must be preserved"
        );
    }
    // Model identifiable reservations left by an interrupted writer. Their
    // payloads come from the real node's native archive, not a lookalike codec.
    let orphan_coins = archive.join(".coins.dat.12345.100.tmp");
    let orphan_headers = archive.join(".headers.dat.12345.101.tmp");
    std::fs::copy(archive.join("coins.dat"), &orphan_coins)?;
    std::fs::copy(archive.join("headers.dat"), &orphan_headers)?;
    // Even an exact reservation-shaped name is not removable when its content
    // belongs to the operator's portable artifact rather than native staging.
    let unknown_alias = archive.join(".coins.dat.12345.102.tmp");
    std::fs::hard_link(&source, &unknown_alias)?;
    // Recover from the newly committed native archives, not a clean-shutdown
    // checkpoint that could mask an invalid archive publication.
    let datadir = node.take_datadir()?;
    node.send_sigkill();
    drop(node);
    let mut node =
        ProcessNode::spawn_in_datadir(Kind::BitcoinRs, &SpawnOptions::default(), datadir)?;
    let view = states(&mut node)?;
    assert_eq!(view["chainstates"][1]["blocks"], 200);
    assert_eq!(view["chainstates"][1]["snapshot_blockhash"], BASE);
    assert_eq!(std::fs::read(&source)?, CORE_SNAPSHOT);
    assert!(!orphan_coins.exists());
    assert!(!orphan_headers.exists());
    assert_eq!(std::fs::read(&unknown_alias)?, CORE_SNAPSHOT);
    for name in ["coins.tmp", "headers.tmp"] {
        assert_eq!(std::fs::read(archive.join(name))?, CORE_SNAPSHOT);
    }
    node.stop()
}
