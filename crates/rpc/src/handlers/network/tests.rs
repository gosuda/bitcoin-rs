use super::*;
use alloc::sync::Arc;
use sonic_rs::{JsonContainerTrait, JsonValueTrait, json};

#[test]
fn configured_overlay_route_is_reported_without_claiming_an_operational_peer() {
    let mut ctx = Context::new();
    let p2p = Arc::new(bitcoin_rs_p2p::P2pService::new(
        bitcoin_rs_p2p::P2pServiceConfig {
            overlay: bitcoin_rs_p2p::overlay::OverlayConfig {
                onion_proxy: Some(
                    "127.0.0.1:9050"
                        .parse()
                        .unwrap_or_else(|error| panic!("proxy: {error}")),
                ),
                onlynet: vec![bitcoin_rs_p2p::PeerNetwork::Onion],
                ..bitcoin_rs_p2p::overlay::OverlayConfig::default()
            },
            ..bitcoin_rs_p2p::P2pServiceConfig::default()
        },
        bitcoin_rs_chain::LatchReader::fixture_never(),
    ));
    ctx.network.peer_table = p2p.table();
    ctx.network.p2p = p2p;
    let ctx = Arc::new(ctx);
    let result = getnetworkinfo(&ctx, &json!([])).unwrap_or_else(|error| panic!("RPC: {error}"));
    let networks = result
        .get("networks")
        .and_then(|value| value.as_array())
        .unwrap_or_else(|| panic!("networks"));
    for row in networks {
        let name = row
            .get("name")
            .and_then(JsonValueTrait::as_str)
            .unwrap_or_default();
        assert_eq!(
            row.get("reachable").and_then(JsonValueTrait::as_bool),
            Some(name == "onion")
        );
        assert_eq!(
            row.get("limited").and_then(JsonValueTrait::as_bool),
            Some(name != "onion")
        );
        if name == "onion" {
            assert_eq!(
                row.get("proxy").and_then(JsonValueTrait::as_str),
                Some("127.0.0.1:9050")
            );
        }
    }
    assert!(addnode(&ctx, &json!(["127.0.0.1:8333", "onetry"])).is_err());
}

#[test]
fn getnetworkinfo_reports_zero_connections_on_fresh_context() {
    let ctx = Arc::new(Context::new());
    let result = getnetworkinfo(&ctx, &json!(null))
        .unwrap_or_else(|err| panic!("getnetworkinfo failed: {err}"));
    let Some(connections) = result.get("connections").and_then(JsonValueTrait::as_u64) else {
        panic!("connections missing: {result:?}");
    };
    assert_eq!(connections, 0);
    let Some(connections_in) = result
        .get("connections_in")
        .and_then(JsonValueTrait::as_u64)
    else {
        panic!("connections_in missing: {result:?}");
    };
    assert_eq!(connections_in, 0);
}

#[test]
fn getnetworkinfo_reports_configured_overlay_state_without_probing()
-> Result<(), Box<dyn std::error::Error>> {
    let mut ctx = Context::new();
    let p2p = Arc::new(bitcoin_rs_p2p::P2pService::new(
        bitcoin_rs_p2p::P2pServiceConfig {
            overlay: bitcoin_rs_p2p::overlay::OverlayConfig {
                onion_proxy: Some("127.0.0.1:1".parse()?),
                i2p_sam: Some("127.0.0.1:2".parse()?),
                randomize_credentials: true,
                ..bitcoin_rs_p2p::overlay::OverlayConfig::default()
            },
            ..bitcoin_rs_p2p::P2pServiceConfig::default()
        },
        bitcoin_rs_chain::LatchReader::fixture_never(),
    ));
    ctx.network.peer_table = p2p.table();
    ctx.network.p2p = p2p;
    let ctx = Arc::new(ctx);
    let result = getnetworkinfo(&ctx, &json!(null))?;
    let Some(networks) = result
        .get("networks")
        .and_then(JsonContainerTrait::as_array)
    else {
        return Err("networks array missing".into());
    };
    let by_name = |name: &str| {
        networks
            .iter()
            .find(|n| n.get("name").and_then(JsonValueTrait::as_str) == Some(name))
            .cloned()
            .ok_or_else(|| format!("network {name} missing"))
    };
    let onion = by_name("onion")?;
    assert_eq!(
        onion.get("reachable").and_then(JsonValueTrait::as_bool),
        Some(true)
    );
    assert_eq!(
        onion.get("limited").and_then(JsonValueTrait::as_bool),
        Some(false)
    );
    assert_eq!(
        onion.get("proxy").and_then(JsonValueTrait::as_str),
        Some("127.0.0.1:1")
    );
    assert_eq!(
        onion
            .get("proxy_randomize_credentials")
            .and_then(JsonValueTrait::as_bool),
        Some(true)
    );
    let i2p = by_name("i2p")?;
    assert_eq!(
        i2p.get("reachable").and_then(JsonValueTrait::as_bool),
        Some(true)
    );
    assert_eq!(
        i2p.get("limited").and_then(JsonValueTrait::as_bool),
        Some(false)
    );
    assert_eq!(
        i2p.get("proxy").and_then(JsonValueTrait::as_str),
        Some("127.0.0.1:2")
    );
    assert_eq!(
        i2p.get("proxy_randomize_credentials")
            .and_then(JsonValueTrait::as_bool),
        Some(false)
    );
    Ok(())
}

#[test]
fn getnetworkinfo_does_not_call_onion_reachable_with_control_only()
-> Result<(), Box<dyn std::error::Error>> {
    let mut ctx = Context::new();
    let p2p = Arc::new(bitcoin_rs_p2p::P2pService::new(
        bitcoin_rs_p2p::P2pServiceConfig {
            overlay: bitcoin_rs_p2p::overlay::OverlayConfig {
                tor_control: Some("127.0.0.1:9051".parse()?),
                ..bitcoin_rs_p2p::overlay::OverlayConfig::default()
            },
            ..bitcoin_rs_p2p::P2pServiceConfig::default()
        },
        bitcoin_rs_chain::LatchReader::fixture_never(),
    ));
    ctx.network.peer_table = p2p.table();
    ctx.network.p2p = p2p;
    let ctx = Arc::new(ctx);

    let result = getnetworkinfo(&ctx, &json!(null))?;
    let Some(networks) = result
        .get("networks")
        .and_then(JsonContainerTrait::as_array)
    else {
        return Err("networks array missing".into());
    };
    let Some(onion) = networks
        .iter()
        .find(|n| n.get("name").and_then(JsonValueTrait::as_str) == Some("onion"))
    else {
        return Err("onion entry missing".into());
    };
    assert_eq!(
        onion.get("reachable").and_then(JsonValueTrait::as_bool),
        Some(false),
        "no outbound SOCKS route is configured, so onion is not dialable"
    );
    assert_eq!(
        onion.get("limited").and_then(JsonValueTrait::as_bool),
        Some(true)
    );
    assert_eq!(
        onion.get("proxy").and_then(JsonValueTrait::as_str),
        Some(""),
        "control port is not a SOCKS proxy and must not be reported as one"
    );
    let Some(addresses) = result
        .get("localaddresses")
        .and_then(JsonContainerTrait::as_array)
    else {
        return Err("localaddresses array missing".into());
    };
    assert!(
        addresses.is_empty(),
        "configuration alone publishes no local address: {addresses:?}"
    );
    Ok(())
}

#[test]
fn getnetworkinfo_calls_onion_reachable_with_an_outbound_socks_route()
-> Result<(), Box<dyn std::error::Error>> {
    for (label, overlay, expect_reachable) in [
        (
            "onion route",
            bitcoin_rs_p2p::overlay::OverlayConfig {
                onion_proxy: Some("127.0.0.1:9050".parse()?),
                ..bitcoin_rs_p2p::overlay::OverlayConfig::default()
            },
            true,
        ),
        (
            "general proxy alone",
            bitcoin_rs_p2p::overlay::OverlayConfig {
                proxy: Some("127.0.0.1:9050".parse()?),
                ..bitcoin_rs_p2p::overlay::OverlayConfig::default()
            },
            false,
        ),
    ] {
        let mut ctx = Context::new();
        let p2p = Arc::new(bitcoin_rs_p2p::P2pService::new(
            bitcoin_rs_p2p::P2pServiceConfig {
                overlay,
                ..bitcoin_rs_p2p::P2pServiceConfig::default()
            },
            bitcoin_rs_chain::LatchReader::fixture_never(),
        ));
        ctx.network.peer_table = p2p.table();
        ctx.network.p2p = p2p;
        let ctx = Arc::new(ctx);
        let result = getnetworkinfo(&ctx, &json!(null))?;
        let Some(networks) = result
            .get("networks")
            .and_then(JsonContainerTrait::as_array)
        else {
            return Err("networks array missing".into());
        };
        let Some(onion) = networks
            .iter()
            .find(|n| n.get("name").and_then(JsonValueTrait::as_str) == Some("onion"))
        else {
            return Err("onion entry missing".into());
        };
        assert_eq!(
            onion.get("reachable").and_then(JsonValueTrait::as_bool),
            Some(expect_reachable),
            "{label} onion reachability"
        );
        assert_eq!(
            onion.get("limited").and_then(JsonValueTrait::as_bool),
            Some(!expect_reachable),
            "{label} onion limited"
        );
        assert_eq!(
            onion.get("proxy").and_then(JsonValueTrait::as_str),
            if expect_reachable {
                Some("127.0.0.1:9050")
            } else {
                Some("")
            },
            "{label} must report the SOCKS endpoint it dials"
        );
    }
    Ok(())
}

#[test]
fn getnetworkinfo_reports_default_overlays_unconfigured_and_unreachable()
-> Result<(), Box<dyn std::error::Error>> {
    let plain = getnetworkinfo(&Arc::new(Context::new()), &json!(null))?;
    let Some(plain_networks) = plain.get("networks").and_then(JsonContainerTrait::as_array) else {
        return Err("plain networks array missing".into());
    };
    let Some(plain_onion) = plain_networks
        .iter()
        .find(|n| n.get("name").and_then(JsonValueTrait::as_str) == Some("onion"))
    else {
        return Err("plain onion entry missing".into());
    };
    assert_eq!(
        plain_onion
            .get("reachable")
            .and_then(JsonValueTrait::as_bool),
        Some(false)
    );
    assert_eq!(
        plain_onion.get("limited").and_then(JsonValueTrait::as_bool),
        Some(true)
    );
    assert_eq!(
        plain_onion
            .get("proxy_randomize_credentials")
            .and_then(JsonValueTrait::as_bool),
        Some(false)
    );
    let Some(plain_i2p) = plain_networks
        .iter()
        .find(|n| n.get("name").and_then(JsonValueTrait::as_str) == Some("i2p"))
    else {
        return Err("plain i2p entry missing".into());
    };
    assert_eq!(
        plain_i2p.get("reachable").and_then(JsonValueTrait::as_bool),
        Some(false)
    );
    assert_eq!(
        plain_i2p.get("limited").and_then(JsonValueTrait::as_bool),
        Some(true)
    );
    assert_eq!(
        plain_i2p.get("proxy").and_then(JsonValueTrait::as_str),
        Some("")
    );
    assert_eq!(
        plain_i2p
            .get("proxy_randomize_credentials")
            .and_then(JsonValueTrait::as_bool),
        Some(false)
    );
    Ok(())
}

#[test]
fn getnetworkinfo_reports_onlynet_and_credential_isolation()
-> Result<(), Box<dyn std::error::Error>> {
    let mut ctx = Context::new();
    let p2p = Arc::new(bitcoin_rs_p2p::P2pService::new(
        bitcoin_rs_p2p::P2pServiceConfig {
            overlay: bitcoin_rs_p2p::overlay::OverlayConfig {
                proxy: Some("127.0.0.1:9050".parse()?),
                onion_proxy: Some("127.0.0.1:9050".parse()?),
                randomize_credentials: false,
                onlynet: vec![bitcoin_rs_p2p::PeerNetwork::Onion],
                ..bitcoin_rs_p2p::overlay::OverlayConfig::default()
            },
            ..bitcoin_rs_p2p::P2pServiceConfig::default()
        },
        bitcoin_rs_chain::LatchReader::fixture_never(),
    ));
    ctx.network.peer_table = p2p.table();
    ctx.network.p2p = p2p;
    let ctx = Arc::new(ctx);
    let result = getnetworkinfo(&ctx, &json!(null))?;
    let Some(networks) = result
        .get("networks")
        .and_then(JsonContainerTrait::as_array)
    else {
        return Err("networks array missing".into());
    };
    let by_name = |name: &str| {
        networks
            .iter()
            .find(|n| n.get("name").and_then(JsonValueTrait::as_str) == Some(name))
            .cloned()
            .ok_or_else(|| format!("network {name} missing"))
    };
    let ipv4 = by_name("ipv4")?;
    assert_eq!(
        ipv4.get("reachable").and_then(JsonValueTrait::as_bool),
        Some(false)
    );
    assert_eq!(
        ipv4.get("limited").and_then(JsonValueTrait::as_bool),
        Some(true)
    );
    assert_eq!(
        ipv4.get("proxy").and_then(JsonValueTrait::as_str),
        Some("127.0.0.1:9050")
    );
    assert_eq!(
        ipv4.get("proxy_randomize_credentials")
            .and_then(JsonValueTrait::as_bool),
        Some(false)
    );

    let onion = by_name("onion")?;
    assert_eq!(
        onion.get("reachable").and_then(JsonValueTrait::as_bool),
        Some(true)
    );
    assert_eq!(
        onion.get("limited").and_then(JsonValueTrait::as_bool),
        Some(false)
    );
    assert_eq!(
        onion.get("proxy").and_then(JsonValueTrait::as_str),
        Some("127.0.0.1:9050")
    );
    assert_eq!(
        onion
            .get("proxy_randomize_credentials")
            .and_then(JsonValueTrait::as_bool),
        Some(false)
    );

    let i2p = by_name("i2p")?;
    assert_eq!(
        i2p.get("reachable").and_then(JsonValueTrait::as_bool),
        Some(false)
    );
    assert_eq!(
        i2p.get("limited").and_then(JsonValueTrait::as_bool),
        Some(true)
    );
    Ok(())
}

#[test]
fn getnetworkinfo_emits_relayfee_default_of_one_sat_per_vbyte() {
    use alloc::sync::Arc;

    let ctx = Arc::new(Context::new());
    let result = getnetworkinfo(&ctx, &json!(null))
        .unwrap_or_else(|err| panic!("getnetworkinfo failed: {err}"));
    let Some(relayfee) = result.get("relayfee").and_then(JsonValueTrait::as_f64) else {
        panic!("relayfee missing: {result:?}");
    };
    assert!(
        (relayfee - 0.00001).abs() < 1e-9,
        "expected ~0.00001, got {relayfee}"
    );
}

#[test]
fn getnetworkinfo_localservices_advertises_only_supported_services() {
    let ctx = Arc::new(Context::new());
    let result = getnetworkinfo(&ctx, &json!(null))
        .unwrap_or_else(|err| panic!("getnetworkinfo failed: {err}"));
    assert_eq!(
        result.get("localservices").and_then(|v| v.as_str()),
        Some("0000000000000009")
    );
    let names: Vec<String> = result
        .get("localservicesnames")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|n| n.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    assert!(names.contains(&"NETWORK".to_owned()));
    assert!(names.contains(&"WITNESS".to_owned()));
    assert!(!names.contains(&"COMPACT_FILTERS".to_owned()));
}
