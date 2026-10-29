#![cfg(unix)]

use std::path::PathBuf;

use bitcoin_rs_primitives::USER_AGENT;
use sonic_rs::{JsonValueTrait, Value};

const EVIDENCE_ENV: &str = "P2P_CORE_INTEROP_EVIDENCE";
const SCHEMA: &str = "bitcoin-rs-core-differential-v4";

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

fn evidence_bool(value: &Value, key: &str) -> Result<bool, LiveError> {
    value
        .get(key)
        .and_then(Value::as_bool)
        .ok_or_else(|| main_error(format!("evidence missing `{key}`")))
}

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
    Ok(sonic_rs::from_str(&raw)?)
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
    assert_bip152_relay(&evidence)?;
    assert_block_announcements(&evidence)?;
    assert_transports(&evidence)?;
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

fn assert_bip152_relay(evidence: &Value) -> Result<(), LiveError> {
    let compact = evidence
        .get("compact")
        .ok_or_else(|| main_error("evidence missing `compact`"))?;
    let phase_a_blocks = evidence_u64(compact, "phase_a_blocks")?;
    let batches = evidence_u64(compact, "near_tip_compact_batches")?;
    let reconstructions = evidence_u64(compact, "reconstructions_complete")?;
    let recoveries = evidence_u64(compact, "getblocktxn_requests")?;
    let fallbacks = evidence_u64(compact, "full_block_fallbacks")?;
    assert!(
        batches >= 1,
        "near-tip compact fetches must appear in the log"
    );
    assert!(
        reconstructions >= phase_a_blocks,
        "every coinbase-only compact block must reconstruct fully: \
         {reconstructions} reconstructions for {phase_a_blocks} phase-A blocks"
    );
    assert!(
        recoveries >= 1,
        "the seeded missing-tx block must recover via getblocktxn"
    );
    assert!(
        fallbacks >= 1,
        "the 130-tx block must exceed the bounded missing list and fall back"
    );

    let probe = evidence
        .get("bip152_probe")
        .ok_or_else(|| main_error("evidence missing `bip152_probe`"))?;
    for key in [
        "served_cmpctblock",
        "served_blocktxn",
        "cmpct_header_hash_matches_tip",
        "malformed_getblocktxn_disconnected",
    ] {
        assert!(
            evidence_bool(probe, key)?,
            "raw BIP152 probe outcome `{key}` must hold"
        );
    }

    let performance = evidence
        .get("performance")
        .ok_or_else(|| main_error("evidence missing `performance`"))?;
    for key in [
        "ibd_seconds",
        "near_tip_seconds",
        "ibd_bytes_core_to_rs",
        "near_tip_bytes_core_to_rs",
        "ibd_bytes_rs_to_core",
        "near_tip_bytes_rs_to_core",
    ] {
        evidence_u64(performance, key)?;
    }
    Ok(())
}

fn assert_block_announcements(evidence: &Value) -> Result<(), LiveError> {
    let announcements = evidence
        .get("block_announcements")
        .ok_or_else(|| main_error("evidence missing `block_announcements`"))?;
    for round in ["first", "reorg"] {
        let observed = announcements
            .get(round)
            .ok_or_else(|| main_error(format!("block announcements missing `{round}`")))?;
        for implementation in ["core", "bitcoin_rs"] {
            let node = observed.get(implementation).ok_or_else(|| {
                main_error(format!("{round} announcements missing `{implementation}`"))
            })?;
            for (mode, expected) in [
                ("inv", "inv"),
                ("headers", "headers"),
                ("compact", "cmpctblock"),
            ] {
                assert_eq!(
                    evidence_str(node, mode)?,
                    expected,
                    "{implementation} must use {expected} for the {mode} peer in the {round} round"
                );
            }
        }
    }

    let stale = announcements
        .get("abandoned_reannounced")
        .ok_or_else(|| main_error("block announcements missing `abandoned_reannounced`"))?;
    for implementation in ["core", "bitcoin_rs"] {
        assert!(
            !evidence_bool(stale, implementation)?,
            "{implementation} must not announce the abandoned tip after the reorg begins"
        );
    }

    for key in ["parent_tip", "first_tip", "reorg_tip"] {
        let hash = evidence_str(announcements, key)?;
        assert_eq!(hash.len(), 64, "{key} must be a display-form block hash");
    }
    assert_ne!(
        evidence_str(announcements, "first_tip")?,
        evidence_str(announcements, "reorg_tip")?,
        "the reorg must replace the first announced tip"
    );
    Ok(())
}

fn assert_transports(evidence: &Value) -> Result<(), LiveError> {
    let transports = evidence
        .get("transports")
        .ok_or_else(|| main_error("evidence missing `transports`"))?;
    let core_tip = evidence_str(transports, "core_tip")?;
    let leg = |name: &str| {
        transports
            .get(name)
            .ok_or_else(|| main_error(format!("transports missing `{name}`")))
    };

    for (name, bitcoin_rs_dials) in [("rs_to_core_v2", true), ("core_to_rs_v2", false)] {
        let leg = leg(name)?;
        assert_eq!(
            evidence_str(leg, "core_transport")?,
            "v2",
            "{name}: Core side"
        );
        assert_eq!(
            evidence_str(leg, "bitcoin_rs_transport")?,
            "v2",
            "{name}: bitcoin-rs side"
        );
        let session_id = evidence_str(leg, "core_session_id")?;
        assert!(
            session_id.len() == 64
                && session_id
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')),
            "{name}: Core reports a 32-byte session id in lowercase hex, got {session_id:?}"
        );
        assert_eq!(
            evidence_str(leg, "bitcoin_rs_session_id")?,
            session_id,
            "{name}: both ends derive the same session id"
        );
        assert_eq!(
            evidence_bool(leg, "core_inbound")?,
            bitcoin_rs_dials,
            "{name}: Core sees the direction that was dialed"
        );
        assert_eq!(
            evidence_bool(leg, "bitcoin_rs_inbound")?,
            !bitcoin_rs_dials,
            "{name}: bitcoin-rs sees the direction that was dialed"
        );
        assert!(
            evidence_bool(leg, "ping_answered")?,
            "{name}: bitcoin-rs answers Core's ping over the session"
        );
    }
    assert_eq!(
        evidence_u64(leg("core_to_rs_v2")?, "bitcoin_rs_peers")?,
        1,
        "the node Core dials has no other peer to sync from"
    );

    let v1 = leg("rs_to_core_v1")?;
    for side in ["core_transport", "bitcoin_rs_transport"] {
        assert_eq!(evidence_str(v1, side)?, "v1", "rs_to_core_v1: {side}");
    }
    for side in ["core_session_id", "bitcoin_rs_session_id"] {
        assert_eq!(
            evidence_str(v1, side)?,
            "",
            "rs_to_core_v1: {side} is empty"
        );
    }

    for name in ["rs_to_core_v1", "rs_to_core_v2", "core_to_rs_v2"] {
        assert_eq!(
            evidence_str(leg(name)?, "bitcoin_rs_tip")?,
            core_tip,
            "{name}: the node syncs Core's chain over that connection"
        );
    }

    let cost = transports
        .get("ibd_cost")
        .ok_or_else(|| main_error("transports missing `ibd_cost`"))?;
    for transport in ["v1", "v2"] {
        let run = cost
            .get(transport)
            .ok_or_else(|| main_error(format!("ibd_cost missing `{transport}`")))?;
        assert_eq!(
            evidence_str(run, "transport")?,
            transport,
            "ibd_cost.{transport}"
        );
        for key in ["bytes_core_to_rs", "bytes_rs_to_core"] {
            assert!(evidence_u64(run, key)? > 0, "ibd_cost.{transport}.{key}");
        }
    }
    let v1_cost = cost
        .get("v1")
        .ok_or_else(|| main_error("ibd_cost missing `v1`"))?;
    assert_eq!(
        evidence_str(v1_cost, "bitcoin_rs_tip")?,
        core_tip,
        "ibd_cost.v1: the v2-off node synced Core's chain"
    );
    Ok(())
}

#[test]
fn rejects_non_satoshi_subversions() {
    assert_eq!(parse_core_subversion("/btcwire:0.5.0/btcd:0.23.0/"), None);
    assert_eq!(parse_core_subversion("/Satoshi:not.a.version/"), None);
    assert_eq!(parse_core_subversion("/Satoshi:/"), None);
    assert_eq!(parse_core_subversion(""), None);
}
