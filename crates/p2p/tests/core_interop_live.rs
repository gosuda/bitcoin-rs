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
use serde_json::Value;

const EVIDENCE_ENV: &str = "P2P_CORE_INTEROP_EVIDENCE";
const SCHEMA: &str = "bitcoin-rs-core-differential-v1";

type LiveError = Box<dyn std::error::Error>;

fn main_error(message: impl std::fmt::Display) -> LiveError {
    Box::<std::io::Error>::new(std::io::Error::other(message.to_string())).into()
}

fn evidence_str<'a>(value: &'a Value, key: &str) -> Result<&'a str, LiveError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| main_error(format!("evidence missing `{key}`")))
}

fn evidence_u64(value: &Value, key: &str) -> Result<u64, LiveError> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| main_error(format!("evidence missing `{key}`")))
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

/// `31.1` matches `31.1` and `31.1.0`; it does not match `31.10.0` or `31.2.0`.
fn version_is_pinned_line(parsed: &str, pinned: &str) -> bool {
    let parsed: Vec<&str> = parsed.split('.').collect();
    let pinned: Vec<&str> = pinned.split('.').collect();
    parsed.len() >= pinned.len() && parsed[..pinned.len()] == pinned[..]
}

fn load_evidence() -> Result<Value, LiveError> {
    let path = std::env::var(EVIDENCE_ENV).map_err(|_| {
        format!(
            "{EVIDENCE_ENV} must point at the evidence JSON from scripts/run-p2p-core-interop.sh"
        )
    })?;
    let raw = std::fs::read_to_string(PathBuf::from(&path))?;
    Ok(serde_json::from_str(&raw)?)
}

fn assert_pinned_core_and_network(evidence: &Value) -> Result<(), LiveError> {
    assert_eq!(evidence_str(evidence, "schema")?, SCHEMA, "evidence schema");
    let core_version = evidence_str(evidence, "core_version")?;
    let parsed_core_version = parse_core_subversion(core_version).ok_or_else(|| {
        main_error(format!(
            "Core subversion {core_version:?} is not Satoshi-format \
             (`/Satoshi:<version>(<comment>)/`)"
        ))
    })?;
    assert!(
        version_is_pinned_line(
            parsed_core_version,
            bitcoin_rs_p2p::compat::PINNED_CORE_VERSION
        ),
        "pinned Bitcoin Core {}: raw subversion {core_version:?}, parsed version \
         {parsed_core_version:?}",
        bitcoin_rs_p2p::compat::PINNED_CORE_VERSION
    );
    assert_eq!(
        evidence_str(evidence, "magic")?,
        "fabfb5da",
        "regtest magic must match Network::Regtest.magic()"
    );
    Ok(())
}

fn assert_inbound_handshake(evidence: &Value) -> Result<(), LiveError> {
    let peer = evidence
        .get("peer")
        .ok_or_else(|| main_error("evidence missing `peer`"))?;
    let inbound = peer
        .get("inbound")
        .and_then(Value::as_bool)
        .ok_or_else(|| main_error("evidence peer missing `inbound`"))?;
    assert!(
        inbound,
        "bitcoin-rs dials Core; Core must see the connection as inbound"
    );
    assert_eq!(
        evidence_str(peer, "subver")?,
        USER_AGENT,
        "Core recorded our user agent from the version message"
    );
    let services = evidence_u64(peer, "services")?;
    let network_bit = bitcoin::p2p::ServiceFlags::NETWORK.to_u64();
    let witness_bit = bitcoin::p2p::ServiceFlags::WITNESS.to_u64();
    assert_ne!(services & network_bit, 0, "NODE_NETWORK advertised");
    assert_ne!(services & witness_bit, 0, "NODE_WITNESS advertised");
    Ok(())
}

fn assert_chain_identity(evidence: &Value) -> Result<(), LiveError> {
    let initial = evidence_u64(evidence, "initial_sync_height")?;
    let catchup_from = evidence_u64(evidence, "catchup_from")?;
    let catchup_to = evidence_u64(evidence, "catchup_to")?;
    let rs_height = evidence_u64(evidence, "bitcoin_rs_height")?;
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
    assert_eq!(
        evidence_str(evidence, "chain")?,
        "regtest",
        "differential runs on regtest"
    );
    assert_eq!(
        evidence_str(evidence, "bestblockhash")?,
        evidence_str(evidence, "bitcoin_rs_bestblockhash")?,
        "getbestblockhash must match after P2P catch-up"
    );
    let rs_blocks = evidence_u64(evidence, "bitcoin_rs_blocks")?;
    assert_eq!(
        evidence_u64(evidence, "core_blocks")?,
        rs_blocks,
        "getblockchaininfo.blocks must match after P2P catch-up"
    );
    assert_eq!(
        rs_blocks, rs_height,
        "getblockchaininfo.blocks must match getblockcount"
    );
    Ok(())
}

#[test]
#[ignore = "requires live bitcoind; run scripts/run-p2p-core-interop.sh"]
fn live_bitcoin_core_p2p_interop_matches_contract() -> Result<(), LiveError> {
    let evidence = load_evidence()?;
    assert_pinned_core_and_network(&evidence)?;
    assert_inbound_handshake(&evidence)?;
    assert_chain_identity(&evidence)?;
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
fn pinned_core_line_rejects_31_10() {
    assert!(version_is_pinned_line(
        "31.1.0",
        bitcoin_rs_p2p::compat::PINNED_CORE_VERSION
    ));
    assert!(version_is_pinned_line(
        "31.1",
        bitcoin_rs_p2p::compat::PINNED_CORE_VERSION
    ));
    assert!(!version_is_pinned_line(
        "31.10.0",
        bitcoin_rs_p2p::compat::PINNED_CORE_VERSION
    ));
    assert!(!version_is_pinned_line(
        "31.2.0",
        bitcoin_rs_p2p::compat::PINNED_CORE_VERSION
    ));
    assert!(!version_is_pinned_line(
        "30.1.0",
        bitcoin_rs_p2p::compat::PINNED_CORE_VERSION
    ));
}

#[test]
fn rejects_non_satoshi_subversions() {
    assert_eq!(parse_core_subversion("/btcwire:0.5.0/btcd:0.23.0/"), None);
    assert_eq!(parse_core_subversion("/Satoshi:not.a.version/"), None);
    assert_eq!(parse_core_subversion("/Satoshi:/"), None);
    assert_eq!(parse_core_subversion(""), None);
}
