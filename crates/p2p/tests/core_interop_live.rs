//! Live Bitcoin Core differential verifier — the env-gated cut lane.
//!
//! NOT part of the default suite: requires a real `bitcoind` driven by
//! `scripts/run-p2p-core-interop.sh`, which starts Bitcoin Core (regtest),
//! brings up a bitcoin-rs node, syncs them over the P2P v1 transport, diffs
//! observable chain-identity RPCs, and writes an evidence JSON.
//!
//! Run via:
//! ```text
//! scripts/run-p2p-core-interop.sh --bitcoind-command "$(scripts/install-bitcoind.sh)"
//! ```
//! or directly with `--ignored --nocapture` after setting
//! `P2P_CORE_INTEROP_EVIDENCE=<path to evidence json>`.

#![cfg(unix)]

use std::path::PathBuf;

use bitcoin_rs_primitives::USER_AGENT;

const EVIDENCE_ENV: &str = "P2P_CORE_INTEROP_EVIDENCE";
const SCHEMA: &str = "bitcoin-rs-core-differential-v1";

fn main_error(message: impl std::fmt::Display) -> Box<dyn std::error::Error> {
    Box::<std::io::Error>::new(std::io::Error::other(message.to_string())).into()
}

/// Parses Core's user agent into its dotted version.
///
/// Core reports `getnetworkinfo.subversion` in BIP 14 form
/// (`/Satoshi:<version>(<comment>)/`), e.g. `/Satoshi:31.1.0/` or
/// `/Satoshi:31.1.0(testsuite)/`. Returns `None` for anything that is not a
/// Satoshi-format agent.
fn parse_core_subversion(subversion: &str) -> Option<&str> {
    let rest = subversion.strip_prefix("/Satoshi:")?;
    let rest = rest.strip_suffix('/')?;
    let version = match rest.split_once('(') {
        Some((version, comment)) => {
            if !comment.ends_with(')') {
                return None;
            }
            version
        }
        None => rest,
    };
    let dotted = !version.is_empty()
        && version
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()));
    if !dotted {
        return None;
    }
    Some(version)
}

#[test]
#[ignore = "requires live bitcoind; run scripts/run-p2p-core-interop.sh"]
fn live_bitcoin_core_p2p_interop_matches_contract() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::var(EVIDENCE_ENV).map_err(|_| {
        format!(
            "{EVIDENCE_ENV} must point at the evidence JSON from scripts/run-p2p-core-interop.sh"
        )
    })?;
    let raw = std::fs::read_to_string(PathBuf::from(&path))?;
    let evidence: serde_json::Value = serde_json::from_str(&raw)?;

    let schema = evidence
        .get("schema")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| main_error("evidence missing `schema`"))?;
    assert_eq!(schema, SCHEMA, "evidence schema");
    let core_version = evidence
        .get("core_version")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| main_error("evidence missing `core_version`"))?;
    // Core reports its user agent in BIP 14 form (`/Satoshi:31.1.0/`), not a
    // bare version; normalize before pinning the 31.x line.
    let parsed_core_version = parse_core_subversion(core_version).ok_or_else(|| {
        main_error(format!(
            "Core subversion {core_version:?} is not Satoshi-format \
             (`/Satoshi:<version>(<comment>)/`)"
        ))
    })?;
    assert!(
        parsed_core_version.starts_with("31."),
        "pinned Bitcoin Core 31.x: raw subversion {core_version:?}, parsed version \
         {parsed_core_version:?}"
    );
    let magic = evidence
        .get("magic")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| main_error("evidence missing `magic`"))?;
    assert_eq!(
        magic, "fabfb5da",
        "regtest magic must match Network::Regtest.magic()"
    );

    // Handshake, as observed by Core itself: it accepted our version message
    // (services + user agent recorded) and completed verack as an inbound peer.
    let peer = evidence
        .get("peer")
        .ok_or_else(|| main_error("evidence missing `peer`"))?;
    let inbound = peer
        .get("inbound")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| main_error("evidence peer missing `inbound`"))?;
    assert!(
        inbound,
        "bitcoin-rs dials Core; Core must see the connection as inbound"
    );
    let subver = peer
        .get("subver")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| main_error("evidence peer missing `subver`"))?;
    assert_eq!(
        subver, USER_AGENT,
        "Core recorded our user agent from the version message"
    );
    let services = peer
        .get("services")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| main_error("evidence peer missing `services`"))?;
    let network_bit = bitcoin::p2p::ServiceFlags::NETWORK.to_u64();
    let witness_bit = bitcoin::p2p::ServiceFlags::WITNESS.to_u64();
    assert_ne!(services & network_bit, 0, "NODE_NETWORK advertised");
    assert_ne!(services & witness_bit, 0, "NODE_WITNESS advertised");

    // Heights: initial sync proves version/verack + getheaders/headers +
    // getdata/block; the catch-up round proves live post-handshake relay.
    let initial = evidence
        .get("initial_sync_height")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| main_error("evidence missing `initial_sync_height`"))?;
    let catchup_from = evidence
        .get("catchup_from")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| main_error("evidence missing `catchup_from`"))?;
    let catchup_to = evidence
        .get("catchup_to")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| main_error("evidence missing `catchup_to`"))?;
    let rs_height = evidence
        .get("bitcoin_rs_height")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| main_error("evidence missing `bitcoin_rs_height`"))?;

    assert!(
        initial >= catchup_from,
        "initial sync must reach at least the pre-catchup Core height"
    );
    assert!(
        catchup_to > catchup_from,
        "catch-up round must mine new blocks"
    );
    assert_eq!(
        rs_height, catchup_to,
        "bitcoin-rs followed Core's post-handshake blocks over P2P"
    );

    let chain = evidence
        .get("chain")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| main_error("evidence missing `chain`"))?;
    assert_eq!(chain, "regtest", "differential runs on regtest");
    let core_tip = evidence
        .get("bestblockhash")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| main_error("evidence missing `bestblockhash`"))?;
    let rs_tip = evidence
        .get("bitcoin_rs_bestblockhash")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| main_error("evidence missing `bitcoin_rs_bestblockhash`"))?;
    assert_eq!(
        core_tip, rs_tip,
        "getbestblockhash must match after P2P catch-up"
    );
    let core_blocks = evidence
        .get("core_blocks")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| main_error("evidence missing `core_blocks`"))?;
    let rs_blocks = evidence
        .get("bitcoin_rs_blocks")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| main_error("evidence missing `bitcoin_rs_blocks`"))?;
    assert_eq!(
        core_blocks, rs_blocks,
        "getblockchaininfo.blocks must match after P2P catch-up"
    );
    assert_eq!(
        rs_blocks, rs_height,
        "getblockchaininfo.blocks must match getblockcount"
    );
    Ok(())
}

#[test]
fn parses_satoshi_subversions() {
    assert_eq!(parse_core_subversion("/Satoshi:31.1.0/"), Some("31.1.0"));
    assert_eq!(
        parse_core_subversion("/Satoshi:31.1.0(comment)/"),
        Some("31.1.0")
    );
    assert_eq!(
        parse_core_subversion("/Satoshi:31.1.0(testsuite)/"),
        Some("31.1.0")
    );
    assert_eq!(parse_core_subversion("/Satoshi:0.21.99/"), Some("0.21.99"));
}

#[test]
fn rejects_non_satoshi_subversions() {
    assert_eq!(parse_core_subversion("/btcwire:0.5.0/btcd:0.23.0/"), None);
    assert_eq!(parse_core_subversion("/Satoshi:not.a.version/"), None);
    assert_eq!(parse_core_subversion("/Satoshi:/"), None);
    assert_eq!(parse_core_subversion(""), None);
}
