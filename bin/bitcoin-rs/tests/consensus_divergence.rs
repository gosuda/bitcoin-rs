use crate::support::TestError;
use bitcoin_rs_e2e::{Kind, ProcessNode, SpawnOptions};
use sonic_rs::{JsonValueTrait as _, json};
use std::path::Path;

#[cfg(unix)]
fn core_reference() -> Result<ProcessNode, TestError> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut core = ProcessNode::spawn_with(
        Kind::Core,
        &SpawnOptions {
            extra_args: &[
                "-assumevalid=0",
                "-testactivationheight=bip34@500",
                "-testactivationheight=dersig@1251",
                "-testactivationheight=cltv@1351",
                "-testactivationheight=csv@432",
            ],
            ..Default::default()
        },
    )?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TestError::Missing("clock"))?
        .as_secs();
    core.rpc("setmocktime", &json!([now]))?;
    Ok(core)
}

// DIV-01, DIV-02, DIV-03, DIV-04
#[cfg(unix)]
#[test]
fn reference_pair_confirms_both_injected_consensus_disagreements() -> Result<(), TestError> {
    use bitcoin_rs_e2e::{differential::mine_common_chain, helpers};
    for rejected in ["local", "reference", "fork"] {
        let mut core = core_reference()?;
        let options = SpawnOptions {
            binary: Some(Path::new(env!("CARGO_BIN_EXE_bitcoin-rs"))),
            ..Default::default()
        };
        let mut node = ProcessNode::spawn_with(Kind::BitcoinRs, &options)?;
        mine_common_chain(&mut core, &mut node, 2)?;
        if rejected != "reference" {
            core.rpc(
                "generatetoaddress",
                &json!([1, helpers::funding_address()?.to_string()]),
            )?;
        }
        if rejected != "local" {
            helpers::mine_bare_blocks(&mut node, 1)?;
        }
        let output = std::process::Command::new("python3")
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/divergence_witness.py"))
            .args([
                node.rpc_addr.port().to_string(),
                core.rpc_addr.port().to_string(),
                rejected.to_owned(),
            ])
            .output()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        if rejected == "fork" {
            assert_eq!(node.rpc("getblockcount", &json!([]))?.as_u64(), Some(3));
            node.stop()?;
            core.stop()?;
            continue;
        }
        let tip = node.rpc("getblockchaininfo", &json!([]))?["bestblockhash"].clone();
        for method in ["getblock", "getblockheader"] {
            let block = node.rpc(method, &json!([tip]))?;
            assert_eq!(
                block["consensus_quarantine"].as_bool(),
                Some(true),
                "{method}"
            );
        }
        for method in [
            "getblockcount",
            "getblocktemplate",
            "submitblock",
            "sendrawtransaction",
        ] {
            let reply =
                node.rpc_raw(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":[]}))?;
            assert_eq!(
                reply["error"]["code"].as_i64(),
                Some(-32001),
                "{method}: {reply}"
            );
        }
        assert_eq!(node.http_get("/api/health")?.status, 503);
        let dir = node.stop_keep_datadir()?;
        let datadir = dir.path().join("node");
        let record: sonic_rs::Value =
            sonic_rs::from_slice(&std::fs::read(datadir.join("consensus-divergence.json"))?)?;
        let incident_id = record["incident_id"]
            .as_str()
            .ok_or(TestError::Missing("incident ID"))?;
        let archive = dir.path().join("archived.json");
        let output = std::process::Command::new("python3")
            .arg(bitcoin_rs_e2e::node::workspace().join("scripts/consensus_monitor.py"))
            .arg("--datadir")
            .arg(&datadir)
            .args(["clear", "--incident-id", incident_id, "--archive"])
            .arg(&archive)
            .args([
                "--verification",
                "regtest injected verdict removed; exact block reproduced",
            ])
            .output()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(std::fs::metadata(&archive)?.permissions().mode() & 0o077, 0);
        let mut resumed = ProcessNode::spawn_in_datadir(Kind::BitcoinRs, &options, dir)?;
        assert_eq!(
            resumed.rpc("getblockcount", &json!([]))?.as_u64(),
            Some(if rejected == "local" { 2 } else { 3 })
        );
        resumed.stop()?;
        core.stop()?;
    }
    Ok(())
}

// DIV-01, DIV-02, DIV-03
#[cfg(unix)]
#[test]
fn replays_a_real_core_cached_rejection_without_promoting_administrative_flags()
-> Result<(), TestError> {
    use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
    use bitcoin::hex::DisplayHex as _;
    use bitcoin_rs_e2e::{differential::mine_common_chain, helpers};

    let mut core = core_reference()?;
    let mut replay = core_reference()?;
    let mut node = ProcessNode::spawn_with(
        Kind::BitcoinRs,
        &SpawnOptions {
            binary: Some(Path::new(env!("CARGO_BIN_EXE_bitcoin-rs"))),
            ..Default::default()
        },
    )?;
    let common = mine_common_chain(&mut core, &mut node, 2)?;
    for bytes in common.common_block_bytes {
        assert!(
            replay
                .rpc("submitblock", &json!([bytes.as_hex().to_string()]))?
                .is_null()
        );
    }
    helpers::mine_bare_blocks(&mut node, 1)?;
    let tip = node.rpc("getbestblockhash", &json!([]))?;
    let body = node.rpc("getblock", &json!([tip, 0]))?;
    let mut valid: bitcoin::Block = deserialize_hex(
        body.as_str()
            .ok_or(TestError::Missing("local block bytes"))?,
    )?;
    valid.txdata[0].output[0].value = bitcoin::Amount::from_sat(5_000_000_001);
    let invalid = crate::support::regtest_blocks::block(
        valid.header.prev_blockhash,
        valid.header.time,
        valid.txdata,
    )?;
    let output = std::process::Command::new("python3")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/divergence_witness.py"))
        .arg("cached")
        .args([
            node.rpc_addr.port().to_string(),
            core.rpc_addr.port().to_string(),
            replay.rpc_addr.port().to_string(),
            serialize_hex(&invalid),
            helpers::funding_address()?.to_string(),
        ])
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    node.stop()?;
    core.stop()?;
    replay.stop()?;
    Ok(())
}

// DIV-03
#[cfg(any(feature = "pool", feature = "pool-sv2"))]
#[test]
fn live_quarantine_disconnects_an_sv1_miner_with_cached_work() -> Result<(), TestError> {
    use std::io::{BufRead as _, BufReader, Write as _};
    use std::net::{TcpListener, TcpStream};
    use std::time::Duration;
    let dir = tempfile::tempdir()?;
    let pooldir = dir.path().join("pool");
    let datadir = dir.path().join("node");
    let address = bitcoin_rs_e2e::helpers::funding_address()?;
    let script = format!("{:x}", address.script_pubkey());
    let reserve = TcpListener::bind("127.0.0.1:0")?;
    let bind = reserve.local_addr()?;
    let pool = format!(
        "pool = true\npool_datadir = {pooldir:?}\npool_v1_bind = \"{bind}\"\npool_share_difficulty = \"1\"\npool_window_work = 100\npool_reward_script = \"{script}\"\nmining_payout_address = \"{address}\"\n"
    );
    #[cfg(all(unix, feature = "pool-sv2"))]
    let (pool, sv2_bind) = {
        use std::os::unix::fs::OpenOptionsExt as _;
        let sv2_bind = TcpListener::bind("127.0.0.1:0")?.local_addr()?;
        let path = dir.path().join("authority");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        writeln!(
            file,
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 {:064x}",
            1
        )?;
        (
            format!("{pool}pool_sv2_bind = \"{sv2_bind}\"\npool_sv2_authority_key = {path:?}\n"),
            sv2_bind,
        )
    };
    drop(reserve);
    let options = SpawnOptions {
        binary: Some(Path::new(env!("CARGO_BIN_EXE_bitcoin-rs"))),
        toml_extra: &pool,
        ..Default::default()
    };
    let mut node = ProcessNode::spawn_in_datadir(Kind::BitcoinRs, &options, dir)?;
    node.rpc("registerpoolaccount", &json!([1, script]))?;
    #[cfg(all(unix, feature = "pool-sv2"))]
    let mut sv2 = {
        let stream = TcpStream::connect(sv2_bind)?;
        stream.set_read_timeout(Some(Duration::from_secs(8)))?;
        stream
    };
    let stream = TcpStream::connect(bind)?;
    stream.set_read_timeout(Some(Duration::from_secs(8)))?;
    let mut miner = BufReader::new(stream);
    miner.get_mut().write_all(b"{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[]}\n{\"id\":2,\"method\":\"mining.authorize\",\"params\":[\"1.worker\",\"x\"]}\n")?;
    loop {
        let mut line = String::new();
        if miner.read_line(&mut line)? == 0 {
            return Err(TestError::Missing("initial SV1 work"));
        }
        let message: sonic_rs::Value = sonic_rs::from_str(&line)?;
        if message["method"].as_str() == Some("mining.notify") {
            break;
        }
    }
    std::fs::write(datadir.join("consensus-divergence.json"), b"{}")?;
    loop {
        let mut line = String::new();
        match miner.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => break,
            Err(e) => return Err(e.into()),
        }
    }
    #[cfg(all(unix, feature = "pool-sv2"))]
    {
        use std::io::Read as _;
        let mut byte = [0; 1];
        match sv2.read(&mut byte) {
            Ok(n) => assert_eq!(n, 0),
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
            Err(e) => return Err(e.into()),
        }
    }
    assert_eq!(
        node.rpc("getrpcinfo", &json!([]))?["consensus_quarantine"].as_bool(),
        Some(true)
    );
    assert_eq!(node.http_get("/api/blocks/tip/height")?.status, 503);
    let dir = node.stop_keep_datadir()?;
    let mut restarted = ProcessNode::spawn_in_datadir(Kind::BitcoinRs, &options, dir)?;
    assert!(TcpStream::connect(bind).is_err());
    #[cfg(all(unix, feature = "pool-sv2"))]
    assert!(TcpStream::connect(sv2_bind).is_err());
    assert_eq!(
        restarted.rpc("getrpcinfo", &json!([]))?["consensus_quarantine"].as_bool(),
        Some(true)
    );
    restarted.stop()?;
    Ok(())
}

// DIV-03, DIV-04
#[test]
fn quarantine_survives_restart_and_preserves_diagnostic_access() -> Result<(), TestError> {
    let options = SpawnOptions {
        binary: Some(Path::new(env!("CARGO_BIN_EXE_bitcoin-rs"))),
        ..Default::default()
    };
    let node = ProcessNode::spawn_with(Kind::BitcoinRs, &options)?;
    let dir = node.stop_keep_datadir()?;
    let marker = dir.path().join("node/consensus-divergence.json");
    std::fs::write(&marker, b"{}")?;
    let mut node = ProcessNode::spawn_in_datadir(Kind::BitcoinRs, &options, dir)?;
    let info = node.rpc("getrpcinfo", &json!([]))?;
    assert_eq!(info["consensus_quarantine"].as_bool(), Some(true));
    let reply =
        node.rpc_raw(&json!({"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}))?;
    assert_eq!(reply["error"]["code"].as_i64(), Some(-32001));
    assert_eq!(node.http_get("/api/blocks/tip/height")?.status, 503);
    let dir = node.stop_keep_datadir()?;
    assert_eq!(std::fs::read(marker)?, b"{}");
    drop(dir);
    Ok(())
}
