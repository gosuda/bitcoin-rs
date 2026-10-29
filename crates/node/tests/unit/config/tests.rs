use std::net::SocketAddr;
use std::path::PathBuf;

use super::{Auth, NetworkSelection, NodeConfig, ScriptIndexMode, ValidationEngine};
use crate::options::{
    ChainstateJournalOverrides, P2pOverrides, RpcOverrides, StorageOverrides, UserConfig,
    ValidationOverrides,
};

#[test]
fn auth_debug_redacts_secrets() {
    let auth = Auth::basic("operator", "s3cret");
    let rendered = format!("{auth:?}");
    assert!(rendered.contains("operator"));
    assert!(!rendered.contains("s3cret"));
    assert!(rendered.contains("<redacted>"));

    let auth = Auth::Cookie {
        path: PathBuf::from("/secret/.cookie"),
    };
    let rendered = format!("{auth:?}");
    assert!(!rendered.contains("/secret/.cookie"));
    assert!(rendered.contains("<redacted>"));
}

#[test]
fn mempool_persistence_can_be_disabled_without_changing_other_settings() {
    assert!(
        NodeConfig::default_for_network(bitcoin_rs_primitives::Network::Regtest).persist_mempool
    );
    let layer = UserConfig {
        persist_mempool: Some(false),
        ..Default::default()
    };
    let config = resolved(&[&layer]);
    assert!(!config.persist_mempool);
    assert_eq!(config.storage.dbcache_mb, 450);
    let enable = UserConfig {
        persist_mempool: Some(true),
        ..Default::default()
    };
    assert!(resolved(&[&layer, &enable]).persist_mempool);
}

#[test]
fn mempool_snapshot_budget_is_configurable_and_bounded() {
    let defaults = resolved(&[]);
    assert_eq!(
        defaults.mempool_snapshot_max_bytes,
        bitcoin_rs_mempool::snapshot::DEFAULT_MAX_BYTES
    );
    let layer = UserConfig {
        mempool_snapshot_max_mb: Some(2048),
        ..Default::default()
    };
    assert_eq!(
        resolved(&[&layer]).mempool_snapshot_max_bytes,
        2048 * 1024 * 1024
    );
    for mb in [0, u64::MAX] {
        let layer = UserConfig {
            mempool_snapshot_max_mb: Some(mb),
            ..Default::default()
        };
        assert!(super::resolve(&[&layer]).is_err());
    }
}

#[test]
fn mempool_snapshot_restore_timeout_is_configurable_and_scales_with_budget() {
    let defaults = resolved(&[]);
    assert_eq!(defaults.mempool_snapshot_restore_timeout_secs, 64);

    let large_budget = UserConfig {
        mempool_snapshot_max_mb: Some(120),
        ..Default::default()
    };
    assert_eq!(
        resolved(&[&large_budget]).mempool_snapshot_restore_timeout_secs,
        120
    );

    let explicit = UserConfig {
        mempool_snapshot_max_mb: Some(120),
        mempool_snapshot_restore_timeout_secs: Some(300),
        ..Default::default()
    };
    assert_eq!(
        resolved(&[&explicit]).mempool_snapshot_restore_timeout_secs,
        300
    );

    for seconds in [0, u64::MAX] {
        let invalid = UserConfig {
            mempool_snapshot_restore_timeout_secs: Some(seconds),
            ..Default::default()
        };
        assert!(super::resolve(&[&invalid]).is_err());
        let mut config = NodeConfig::default_for_network(bitcoin_rs_primitives::Network::Regtest);
        config.mempool_snapshot_restore_timeout_secs = seconds;
        assert!(
            config.validate().is_err(),
            "direct embedding config must also reject {seconds}"
        );
    }
}

#[test]
fn default_rpc_auth_uses_a_generated_cookie() {
    let layer = UserConfig {
        data_dir: Some(PathBuf::from("test-node")),
        ..UserConfig::default()
    };
    let config = resolved(&[&layer]);
    assert_eq!(config.rpc.auth, Auth::GeneratedCookie);
}

#[test]
fn generated_rpc_cookie_is_private_and_rotates() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join(".cookie");
    // A temporary file left by an interrupted start must not block the next.
    std::fs::write(dir.path().join(".cookie.tmp"), "stale")?;
    let auth = Auth::GeneratedCookie;

    auth.to_rpc_auth(dir.path())?;
    let first = std::fs::read_to_string(&path)?;
    assert!(!dir.path().join(".cookie.tmp").exists());
    assert!(first.starts_with("__cookie__:"));
    assert_eq!(first.len(), "__cookie__:".len() + 64);
    assert!(
        !first.ends_with('\n'),
        "the generated cookie carries no trailing newline"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&path)?.permissions().mode() & 0o777,
            0o600
        );
    }

    auth.to_rpc_auth(dir.path())?;
    let second = std::fs::read_to_string(&path)?;
    assert_ne!(first, second, "each startup must rotate the cookie");
    Ok(())
}

#[test]
fn overlay_targets_without_routes_are_rejected() -> anyhow::Result<()> {
    let onlynet_onion = UserConfig {
        p2p: P2pOverrides {
            onlynet: Some(vec![bitcoin_rs_p2p::PeerNetwork::Onion]),
            ..P2pOverrides::default()
        },
        ..UserConfig::default()
    };
    assert!(super::resolve(&[&onlynet_onion]).is_err());

    let onlynet_i2p = UserConfig {
        p2p: P2pOverrides {
            onlynet: Some(vec![bitcoin_rs_p2p::PeerNetwork::I2p]),
            ..P2pOverrides::default()
        },
        ..UserConfig::default()
    };
    assert!(super::resolve(&[&onlynet_i2p]).is_err());

    let accept_without_sam = UserConfig {
        p2p: P2pOverrides {
            i2p_accept: Some(true),
            ..P2pOverrides::default()
        },
        ..UserConfig::default()
    };
    assert!(super::resolve(&[&accept_without_sam]).is_err());

    // With routes configured, the same selections resolve and the
    // resolved overlay carries them through.
    let routed = UserConfig {
        p2p: P2pOverrides {
            dns_seeds: Some(false),
            onion_proxy: Some(SocketAddr::from(([127, 0, 0, 1], 9050))),
            i2p_sam: Some(SocketAddr::from(([127, 0, 0, 1], 7656))),
            i2p_accept: Some(true),
            onlynet: Some(vec![
                bitcoin_rs_p2p::PeerNetwork::Onion,
                bitcoin_rs_p2p::PeerNetwork::I2p,
            ]),
            ..P2pOverrides::default()
        },
        ..UserConfig::default()
    };
    let config = super::resolve(&[&routed])?;
    assert_eq!(
        config.p2p.overlay.onion_proxy,
        Some(SocketAddr::from(([127, 0, 0, 1], 9050)))
    );
    assert!(config.p2p.overlay.i2p_accept);
    assert_eq!(config.p2p.overlay.onlynet.len(), 2);
    assert!(
        !config.p2p.overlay.identity_dir.as_os_str().is_empty(),
        "inbound overlay services require an identity directory"
    );
    assert_eq!(
        config.p2p.overlay.port,
        NetworkSelection::Mainnet
            .consensus_network()
            .default_p2p_port()
    );
    Ok(())
}

#[test]
fn malformed_overlay_connect_targets_are_rejected() -> anyhow::Result<()> {
    let good_tor =
        bitcoin_rs_p2p::endpoint::format_endpoint(bitcoin_rs_primitives::PeerEndpoint::TorV3 {
            key: [3u8; 32],
            port: 8333,
        });
    let (good_onion_host, _) = good_tor
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("formatted Tor endpoint contains port separator"))?;

    let routes_layer = UserConfig {
        p2p: P2pOverrides {
            dns_seeds: Some(false),
            onion_proxy: Some(SocketAddr::from(([127, 0, 0, 1], 9050))),
            ..P2pOverrides::default()
        },
        ..UserConfig::default()
    };

    // Prove valid canonical counterpart validates under identical route config.
    let valid_user_config = UserConfig {
        p2p: P2pOverrides {
            connect: Some(vec![good_tor.clone()]),
            ..P2pOverrides::default()
        },
        ..UserConfig::default()
    };
    let valid_config = super::resolve(&[&routes_layer, &valid_user_config])?;
    assert_eq!(valid_config.p2p.connect, vec![good_tor.clone()]);

    // 1. Bad Tor v3 checksum (change first character of public key)
    let mut chars: Vec<char> = good_tor.chars().collect();
    chars[0] = if chars[0] == 'a' { 'b' } else { 'a' };
    let bad_checksum_onion: String = chars.into_iter().collect();

    // 2. Missing port
    let missing_port_onion = good_onion_host.to_owned();

    // 3. Invalid port (non-numeric, overflow)
    let non_numeric_port = format!("{good_onion_host}:notaport");
    let overflow_port = format!("{good_onion_host}:99999");

    // 4. Zero port
    let zero_port_onion = format!("{good_onion_host}:0");

    let rejected_targets = [
        bad_checksum_onion,
        missing_port_onion,
        non_numeric_port,
        overflow_port,
        zero_port_onion,
    ];

    for target in rejected_targets {
        let invalid_config = UserConfig {
            p2p: P2pOverrides {
                connect: Some(vec![target.clone()]),
                ..P2pOverrides::default()
            },
            ..UserConfig::default()
        };
        // Verify rejection both without routes and with routes configured.
        assert!(super::resolve(&[&invalid_config]).is_err());
        assert!(super::resolve(&[&routes_layer, &invalid_config]).is_err());
    }
    Ok(())
}

#[test]
fn malformed_i2p_with_routes_configured_rejects_target_not_missing_route() -> anyhow::Result<()> {
    let good_i2p = format!("{}.b32.i2p:8333", "a".repeat(52));
    let routes_layer = UserConfig {
        p2p: P2pOverrides {
            dns_seeds: Some(false),
            i2p_sam: Some(SocketAddr::from(([127, 0, 0, 1], 7656))),
            ..P2pOverrides::default()
        },
        ..UserConfig::default()
    };

    // Prove valid canonical counterpart validates under identical route config.
    let valid_user_config = UserConfig {
        p2p: P2pOverrides {
            connect: Some(vec![good_i2p.clone()]),
            ..P2pOverrides::default()
        },
        ..UserConfig::default()
    };
    let valid_config = super::resolve(&[&routes_layer, &valid_user_config])?;
    assert_eq!(valid_config.p2p.connect, vec![good_i2p]);

    // Explicit I2P port 0 (unspecified/default service port) validates
    // under identical route config and classifies as I2P port 0.
    let zero_port_i2p = format!("{}.b32.i2p:0", "a".repeat(52));
    let zero_port_user_config = UserConfig {
        p2p: P2pOverrides {
            connect: Some(vec![zero_port_i2p.clone()]),
            ..P2pOverrides::default()
        },
        ..UserConfig::default()
    };
    let zero_port_config = super::resolve(&[&routes_layer, &zero_port_user_config])?;
    assert_eq!(zero_port_config.p2p.connect, vec![zero_port_i2p.clone()]);
    assert_eq!(
        bitcoin_rs_p2p::endpoint::classify_endpoint(&zero_port_i2p),
        bitcoin_rs_p2p::endpoint::ClassifiedEndpoint::Valid(
            bitcoin_rs_primitives::PeerEndpoint::I2p {
                hash: [0u8; 32],
                port: 0,
            }
        )
    );

    // An absent port is still malformed: port 0 must be explicit (`:0`).
    // Short/long payloads, non-numeric ports, and invalid payloads stay
    // rejected as well.
    let malformed_i2p_targets = [
        format!("{}.b32.i2p:8333", "a".repeat(51)),
        format!("{}.b32.i2p:8333", "a".repeat(53)),
        format!("{}.b32.i2p", "a".repeat(52)),
        format!("{}.b32.i2p:notaport", "a".repeat(52)),
        "invalid.b32.i2p:8333".to_owned(),
    ];

    for target in malformed_i2p_targets {
        let invalid_config = UserConfig {
            p2p: P2pOverrides {
                connect: Some(vec![target.clone()]),
                ..P2pOverrides::default()
            },
            ..UserConfig::default()
        };
        assert!(super::resolve(&[&invalid_config]).is_err());
        assert!(super::resolve(&[&routes_layer, &invalid_config]).is_err());
    }
    Ok(())
}

#[test]
fn ordinary_hostname_connect_targets_remain_accepted_at_startup() -> anyhow::Result<()> {
    for target in [
        "drynet4.drivechain.dev:8533",
        "seed.bitcoin.sipa.be:8333",
        "dnsseed.bluematt.me:8333",
    ] {
        let user_config = UserConfig {
            p2p: P2pOverrides {
                connect: Some(vec![target.to_owned()]),
                ..P2pOverrides::default()
            },
            ..UserConfig::default()
        };
        let config = super::resolve(&[&user_config])?;
        assert_eq!(config.p2p.connect, vec![target.to_owned()]);
    }
    Ok(())
}

#[test]
fn valid_overlay_connect_targets_enforce_routes() -> anyhow::Result<()> {
    let good_tor =
        bitcoin_rs_p2p::endpoint::format_endpoint(bitcoin_rs_primitives::PeerEndpoint::TorV3 {
            key: [3u8; 32],
            port: 8333,
        });
    let good_i2p = format!("{}.b32.i2p:8333", "a".repeat(52));

    let tor_no_route = UserConfig {
        p2p: P2pOverrides {
            connect: Some(vec![good_tor.clone()]),
            ..P2pOverrides::default()
        },
        ..UserConfig::default()
    };
    assert!(super::resolve(&[&tor_no_route]).is_err());

    let i2p_no_route = UserConfig {
        p2p: P2pOverrides {
            connect: Some(vec![good_i2p.clone()]),
            ..P2pOverrides::default()
        },
        ..UserConfig::default()
    };
    assert!(super::resolve(&[&i2p_no_route]).is_err());

    let routed = UserConfig {
        p2p: P2pOverrides {
            onion_proxy: Some(SocketAddr::from(([127, 0, 0, 1], 9050))),
            dns_seeds: Some(false),
            i2p_sam: Some(SocketAddr::from(([127, 0, 0, 1], 7656))),
            connect: Some(vec![good_tor.clone(), good_i2p.clone()]),
            ..P2pOverrides::default()
        },
        ..UserConfig::default()
    };
    let config = super::resolve(&[&routed])?;
    assert_eq!(config.p2p.connect, vec![good_tor.clone(), good_i2p]);

    // Tor also routes through a general proxy.
    let proxy_routed = UserConfig {
        p2p: P2pOverrides {
            dns_seeds: Some(false),
            proxy: Some(SocketAddr::from(([127, 0, 0, 1], 9050))),
            connect: Some(vec![good_tor.clone()]),
            ..P2pOverrides::default()
        },
        ..UserConfig::default()
    };
    let proxy_config = super::resolve(&[&proxy_routed])?;
    assert_eq!(proxy_config.p2p.connect, vec![good_tor]);

    Ok(())
}

#[test]
fn privacy_routes_with_default_dns_seeds_are_rejected() {
    // DNS seeds resolve through the local system resolver, so leaving them
    // enabled behind a privacy route would leak intent around the overlay.
    // Resolution must fail fast instead of bypassing the proxy/bridge.
    let proxy = SocketAddr::from(([127, 0, 0, 1], 9050));
    let sam = SocketAddr::from(([127, 0, 0, 1], 7656));
    for p2p in [
        P2pOverrides {
            proxy: Some(proxy),
            ..P2pOverrides::default()
        },
        P2pOverrides {
            onion_proxy: Some(proxy),
            ..P2pOverrides::default()
        },
        P2pOverrides {
            i2p_sam: Some(sam),
            ..P2pOverrides::default()
        },
    ] {
        let layer = UserConfig {
            p2p,
            ..UserConfig::default()
        };
        let Err(error) = super::resolve(&[&layer]) else {
            panic!("a privacy route with default DNS seeds must fail validation");
        };
        assert!(
            error.to_string().contains("--dns-seeds-enabled=false"),
            "{error}"
        );
    }
}

#[test]
fn privacy_route_with_dns_disabled_accepts_literal_ip() -> anyhow::Result<()> {
    // Explicitly disabling DNS seeds opts into private routing; a literal
    // IP fixed peer needs no resolution and stays supported.
    let layer = UserConfig {
        p2p: P2pOverrides {
            proxy: Some(SocketAddr::from(([127, 0, 0, 1], 9050))),
            dns_seeds: Some(false),
            connect: Some(vec!["127.0.0.1:8333".to_owned()]),
            ..P2pOverrides::default()
        },
        ..UserConfig::default()
    };
    let config = super::resolve(&[&layer])?;
    assert!(!config.p2p.dns_seeds_enabled);
    assert_eq!(config.p2p.connect, vec!["127.0.0.1:8333".to_owned()]);
    Ok(())
}

#[test]
fn hostname_connect_targets_are_rejected_with_privacy_route() {
    // Ordinary hostnames resolve via `resolve()` on the dial path, bypassing
    // any proxy/bridge, so they are refused while a privacy route stands.
    let proxy = SocketAddr::from(([127, 0, 0, 1], 9050));
    let sam = SocketAddr::from(([127, 0, 0, 1], 7656));
    for p2p in [
        P2pOverrides {
            proxy: Some(proxy),
            dns_seeds: Some(false),
            connect: Some(vec!["seed.bitcoin.sipa.be:8333".to_owned()]),
            ..P2pOverrides::default()
        },
        P2pOverrides {
            onion_proxy: Some(proxy),
            dns_seeds: Some(false),
            connect: Some(vec!["seed.bitcoin.sipa.be:8333".to_owned()]),
            ..P2pOverrides::default()
        },
        P2pOverrides {
            i2p_sam: Some(sam),
            dns_seeds: Some(false),
            connect: Some(vec!["seed.bitcoin.sipa.be:8333".to_owned()]),
            ..P2pOverrides::default()
        },
    ] {
        let layer = UserConfig {
            p2p,
            ..UserConfig::default()
        };
        let Err(error) = super::resolve(&[&layer]) else {
            panic!("a hostname --connect target with a privacy route must fail validation");
        };
        assert!(error.to_string().contains("--connect"), "{error}");
    }
}

#[test]
fn typed_overlay_connect_targets_are_accepted_with_dns_disabled() -> anyhow::Result<()> {
    // Typed endpoints need no DNS: Tor/I2P names validate locally and dial
    // through their route, so they stay supported with seeds disabled.
    let good_tor =
        bitcoin_rs_p2p::endpoint::format_endpoint(bitcoin_rs_primitives::PeerEndpoint::TorV3 {
            key: [9u8; 32],
            port: 8333,
        });
    let good_i2p = format!("{}.b32.i2p:8333", "a".repeat(52));
    let proxy = SocketAddr::from(([127, 0, 0, 1], 9050));
    let sam = SocketAddr::from(([127, 0, 0, 1], 7656));

    let onion_routed = UserConfig {
        p2p: P2pOverrides {
            dns_seeds: Some(false),
            onion_proxy: Some(proxy),
            connect: Some(vec![good_tor.clone()]),
            ..P2pOverrides::default()
        },
        ..UserConfig::default()
    };
    assert_eq!(
        super::resolve(&[&onion_routed])?.p2p.connect,
        vec![good_tor.clone()]
    );

    let proxy_routed = UserConfig {
        p2p: P2pOverrides {
            dns_seeds: Some(false),
            proxy: Some(proxy),
            connect: Some(vec![good_tor.clone()]),
            ..P2pOverrides::default()
        },
        ..UserConfig::default()
    };
    assert_eq!(
        super::resolve(&[&proxy_routed])?.p2p.connect,
        vec![good_tor]
    );

    let i2p_routed = UserConfig {
        p2p: P2pOverrides {
            dns_seeds: Some(false),
            i2p_sam: Some(sam),
            connect: Some(vec![good_i2p.clone()]),
            ..P2pOverrides::default()
        },
        ..UserConfig::default()
    };
    assert_eq!(super::resolve(&[&i2p_routed])?.p2p.connect, vec![good_i2p]);

    // A literal IP fixed peer alongside a privacy route needs no DNS either.
    let ip_routed = UserConfig {
        p2p: P2pOverrides {
            dns_seeds: Some(false),
            proxy: Some(proxy),
            connect: Some(vec!["192.0.2.1:8333".to_owned()]),
            ..P2pOverrides::default()
        },
        ..UserConfig::default()
    };
    let config = super::resolve(&[&ip_routed])?;
    assert!(!config.p2p.dns_seeds_enabled);
    assert_eq!(config.p2p.connect, vec!["192.0.2.1:8333".to_owned()]);
    Ok(())
}

#[test]
fn rpc_rejects_missing_or_public_credentials() {
    let binding = SocketAddr::from(([0, 0, 0, 0], 8332));
    let exposed = UserConfig {
        rpc: RpcOverrides {
            bind: Some(binding),
            ..RpcOverrides::default()
        },
        ..UserConfig::default()
    };
    let Err(error) = super::resolve(&[&exposed]) else {
        panic!("a non-loopback bind without credentials must fail validation");
    };
    assert!(
        error.to_string().contains("non-loopback RPC bind"),
        "{error}"
    );

    let user_without_password = UserConfig {
        rpc: RpcOverrides {
            user: Some("operator".to_owned()),
            ..RpcOverrides::default()
        },
        ..UserConfig::default()
    };
    let Err(error) = super::resolve(&[&user_without_password]) else {
        panic!("a user without a password must fail validation");
    };
    assert!(
        error.to_string().contains("nonempty username and password"),
        "{error}"
    );

    let legacy_password = UserConfig {
        rpc: RpcOverrides {
            user: Some("bitcoin-rs".to_owned()),
            password: Some("bitcoin-rs".to_owned()),
            ..RpcOverrides::default()
        },
        ..UserConfig::default()
    };
    let Err(error) = super::resolve(&[&legacy_password]) else {
        panic!("the legacy public password must fail validation");
    };
    assert!(
        error.to_string().contains("publicly known legacy default"),
        "{error}"
    );

    let explicit_password = UserConfig {
        rpc: RpcOverrides {
            bind: Some(binding),
            password: Some("non-default-secret".to_owned()),
            ..RpcOverrides::default()
        },
        ..UserConfig::default()
    };
    let config = resolved(&[&explicit_password]);
    assert_eq!(
        basic_auth(&config.rpc.auth),
        ("bitcoin-rs".to_owned(), "non-default-secret".to_owned())
    );

    let explicit_cookie = UserConfig {
        rpc: RpcOverrides {
            bind: Some(binding),
            cookie: Some(PathBuf::from("/operator/auth.cookie")),
            ..RpcOverrides::default()
        },
        ..UserConfig::default()
    };
    assert!(matches!(
        resolved(&[&explicit_cookie]).rpc.auth,
        Auth::Cookie { .. }
    ));
}

// ---- Named config-option coverage -------------------------------------
//
// Retained source precedence, absent nested overrides, and cross-field
// validation are exercised here at the one resolver every input layer
// feeds, so no adapter can bypass the named rules.

fn resolved(layers: &[&UserConfig]) -> NodeConfig {
    super::resolve(layers).unwrap_or_else(|error| panic!("valid layered configuration: {error}"))
}

/// Reads the two halves of Basic authentication, failing on cookie auth.
fn basic_auth(auth: &Auth) -> (String, String) {
    match auth {
        Auth::Basic { user, password } => (user.clone(), password.clone()),
        Auth::Cookie { .. } | Auth::GeneratedCookie => panic!("expected basic auth"),
    }
}

#[test]
fn resolve_prefers_higher_layers_field_by_field() {
    let base = UserConfig {
        storage: StorageOverrides {
            prune_target_mb: Some(550),
            dbcache_mb: Some(300),
            ..StorageOverrides::default()
        },
        rpc: RpcOverrides {
            user: Some("lower-user".to_owned()),
            ..RpcOverrides::default()
        },
        ..UserConfig::default()
    };
    let higher = UserConfig {
        storage: StorageOverrides {
            prune_target_mb: Some(900),
            ..StorageOverrides::default()
        },
        rpc: RpcOverrides {
            password: Some("higher-password".to_owned()),
            ..RpcOverrides::default()
        },
        ..UserConfig::default()
    };
    let config = resolved(&[&base, &higher]);
    assert_eq!(config.storage.prune_target_mb, 900);
    assert_eq!(
        config.storage.dbcache_mb, 300,
        "a field absent in the higher layer keeps the lower layer's value"
    );
    let (user, password) = basic_auth(&config.rpc.auth);
    assert_eq!(user, "lower-user");
    assert_eq!(password, "higher-password");
}

#[test]
fn resolve_keeps_absent_nested_fields_at_their_network_defaults() {
    let layer = UserConfig {
        network: Some(NetworkSelection::Regtest),
        storage: StorageOverrides {
            dbcache_mb: Some(120),
            ..StorageOverrides::default()
        },
        ..UserConfig::default()
    };
    let config = resolved(&[&layer]);
    assert_eq!(config.storage.dbcache_mb, 120);
    assert_eq!(config.storage.prune_target_mb, 0);
    assert!(!config.indexes.txindex);
    assert_eq!(config.indexes.script_index, ScriptIndexMode::Disabled);
    assert_eq!(config.observability.metrics_bind, None);
    assert!(config.chainstate_journal.enabled);
    assert_eq!(
        config.validation.assume_valid_height, 0,
        "regtest pins no assume-valid anchor"
    );
}

// ---- Unified validation engine ----------------------------------------
//
// The `kernel` feature is capability ("bitcoinkernel support is compiled
// in"), not selection. `validation.engine` is the one authoritative engine
// setting: it resolves once here, defaults to `native` in every build, and a
// build without kernel support must reject `kernel` before any node state,
// chainstate, or worker exists.

#[test]
fn validation_engine_defaults_to_native_and_layers_field_by_field() {
    let config = resolved(&[]);
    assert_eq!(config.validation.engine, ValidationEngine::Native);

    // An explicit `native` setting resolves in every build. The
    // lower-layer-wins claim needs a non-default engine to be observable and
    // lives in the kernel-gated layering test below.
    let base = UserConfig {
        network: Some(NetworkSelection::Regtest),
        validation: ValidationOverrides {
            engine: Some(ValidationEngine::Native),
            ..ValidationOverrides::default()
        },
        ..UserConfig::default()
    };
    let higher = UserConfig::default();
    let config = resolved(&[&base, &higher]);
    assert_eq!(
        config.validation.engine,
        ValidationEngine::Native,
        "an explicit `native` setting resolves in every build"
    );
}

#[test]
#[cfg(feature = "kernel")]
fn validation_engine_kernel_is_supported_when_compiled() {
    let layer = UserConfig {
        validation: ValidationOverrides {
            engine: Some(ValidationEngine::Kernel),
            ..ValidationOverrides::default()
        },
        ..UserConfig::default()
    };
    let config = resolved(&[&layer]);
    assert_eq!(config.validation.engine, ValidationEngine::Kernel);
}

/// The two-layer absent case, observable only where `kernel` is a usable
/// non-default value: the lower layer's engine survives a higher layer that
/// omits the field, and a higher layer that names one wins. The always-on
/// test above cannot show this — both `native` and the fallback land on the
/// default.
#[test]
#[cfg(feature = "kernel")]
fn validation_engine_layering_keeps_the_lower_layer_value() {
    let base = UserConfig {
        validation: ValidationOverrides {
            engine: Some(ValidationEngine::Kernel),
            ..ValidationOverrides::default()
        },
        ..UserConfig::default()
    };
    let higher = UserConfig::default();
    let config = resolved(&[&base, &higher]);
    assert_eq!(
        config.validation.engine,
        ValidationEngine::Kernel,
        "an engine absent in the higher layer keeps the lower layer's value"
    );

    let higher = UserConfig {
        validation: ValidationOverrides {
            engine: Some(ValidationEngine::Native),
            ..ValidationOverrides::default()
        },
        ..UserConfig::default()
    };
    let config = resolved(&[&base, &higher]);
    assert_eq!(
        config.validation.engine,
        ValidationEngine::Native,
        "a higher layer that names an engine wins"
    );
}

#[test]
#[cfg(not(feature = "kernel"))]
fn validation_engine_kernel_is_rejected_without_kernel_support() {
    let layer = UserConfig {
        validation: ValidationOverrides {
            engine: Some(ValidationEngine::Kernel),
            ..ValidationOverrides::default()
        },
        ..UserConfig::default()
    };
    let error = match super::resolve(&[&layer]) {
        Ok(_) => panic!("a build without kernel support must reject engine = kernel"),
        Err(error) => error,
    };
    let message = error.to_string();
    assert!(
        message.contains("not compiled") && message.contains("kernel"),
        "unsupported-build error must name the missing capability, got {message}"
    );
}

#[test]
fn journal_nested_overrides_apply_field_by_field_across_layers() {
    let base = UserConfig {
        chainstate_journal: ChainstateJournalOverrides {
            blocks: Some(200),
            ..ChainstateJournalOverrides::default()
        },
        ..UserConfig::default()
    };
    let higher = UserConfig {
        chainstate_journal: ChainstateJournalOverrides {
            seconds: Some(45),
            ..ChainstateJournalOverrides::default()
        },
        ..UserConfig::default()
    };
    let config = resolved(&[&base, &higher]);
    assert_eq!(config.chainstate_journal.blocks, 200);
    assert_eq!(config.chainstate_journal.seconds, 45);
    assert_eq!(
        config.chainstate_journal.rotate_mib, 256,
        "untouched bounds keep the network defaults"
    );
    assert_eq!(config.chainstate_journal.max_journal_mib, 2048);
}

#[test]
fn rpc_cookie_and_credential_layers_keep_one_auth_source() {
    let cookie = UserConfig {
        rpc: RpcOverrides {
            cookie: Some(PathBuf::from("/secure/.cookie")),
            ..RpcOverrides::default()
        },
        ..UserConfig::default()
    };
    let credentials = UserConfig {
        rpc: RpcOverrides {
            user: Some("later-user".to_owned()),
            password: Some("later-password".to_owned()),
            ..RpcOverrides::default()
        },
        ..UserConfig::default()
    };
    let config = resolved(&[&credentials, &cookie]);
    assert!(
        matches!(config.rpc.auth, Auth::Cookie { .. }),
        "a higher cookie layer wins over lower credentials"
    );
    let config = resolved(&[&cookie, &credentials]);
    let (user, password) = basic_auth(&config.rpc.auth);
    assert_eq!(user, "later-user");
    assert_eq!(password, "later-password");
}

#[test]
fn p2p_magic_override_is_cross_field_validated() {
    let magic = [1, 2, 3, 4];
    let connect = || vec!["127.0.0.1:8333".to_owned()];

    let regtest = UserConfig {
        network: Some(NetworkSelection::Regtest),
        p2p: P2pOverrides {
            magic: Some(magic),
            connect: Some(connect()),
            dns_seeds: Some(false),
            ..P2pOverrides::default()
        },
        ..UserConfig::default()
    };
    let Err(error) = super::resolve(&[&regtest]) else {
        panic!("a non-mainnet magic override must fail validation");
    };
    assert!(
        error.to_string().contains("require --network mainnet"),
        "{error}"
    );

    let without_connect = UserConfig {
        p2p: P2pOverrides {
            magic: Some(magic),
            dns_seeds: Some(false),
            ..P2pOverrides::default()
        },
        ..UserConfig::default()
    };
    let Err(error) = super::resolve(&[&without_connect]) else {
        panic!("a magic override without a connect peer must fail validation");
    };
    assert!(
        error.to_string().contains("at least one --connect peer"),
        "{error}"
    );

    let with_dns_seeds = UserConfig {
        p2p: P2pOverrides {
            magic: Some(magic),
            connect: Some(connect()),
            ..P2pOverrides::default()
        },
        ..UserConfig::default()
    };
    let Err(error) = super::resolve(&[&with_dns_seeds]) else {
        panic!("a magic override with dns seeds on must fail validation");
    };
    assert!(
        error
            .to_string()
            .contains("require --dns-seeds-enabled=false"),
        "{error}"
    );

    let valid = UserConfig {
        p2p: P2pOverrides {
            magic: Some(magic),
            connect: Some(connect()),
            dns_seeds: Some(false),
            ..P2pOverrides::default()
        },
        ..UserConfig::default()
    };
    assert_eq!(resolved(&[&valid]).p2p.magic, magic);
}

#[test]
fn journal_retention_and_lag_bounds_are_cross_field_validated() {
    let inverted_retention = UserConfig {
        chainstate_journal: ChainstateJournalOverrides {
            rotate_mib: Some(4096),
            max_journal_mib: Some(2048),
            ..ChainstateJournalOverrides::default()
        },
        ..UserConfig::default()
    };
    let Err(error) = super::resolve(&[&inverted_retention]) else {
        panic!("retention below rotation must fail validation");
    };
    assert!(
        error
            .to_string()
            .contains("max_journal_mib must be >= rotate_mib"),
        "{error}"
    );

    let inverted_lag = UserConfig {
        chainstate_journal: ChainstateJournalOverrides {
            blocks: Some(500),
            max_lag_blocks: Some(100),
            ..ChainstateJournalOverrides::default()
        },
        ..UserConfig::default()
    };
    let Err(error) = super::resolve(&[&inverted_lag]) else {
        panic!("a lag bound below the batch size must fail validation");
    };
    assert!(
        error
            .to_string()
            .contains("max_lag_blocks must be >= blocks"),
        "{error}"
    );

    let zero_period = UserConfig {
        chainstate_journal: ChainstateJournalOverrides {
            seconds: Some(0),
            ..ChainstateJournalOverrides::default()
        },
        ..UserConfig::default()
    };
    let Err(error) = super::resolve(&[&zero_period]) else {
        panic!("a non-positive period must fail validation");
    };
    assert!(
        error.to_string().contains("seconds must be positive"),
        "{error}"
    );
}

#[test]
fn earlier_set_fields_survive_a_later_bare_network_selection() {
    let overrides = UserConfig {
        p2p: P2pOverrides {
            connect: Some(vec!["127.0.0.1:8333".to_owned()]),
            dns_seeds: Some(false),
            ..P2pOverrides::default()
        },
        validation: ValidationOverrides {
            assume_valid_height: Some(7),
            mode: None,
            engine: None,
        },
        ..UserConfig::default()
    };
    let selection = UserConfig {
        network: Some(NetworkSelection::Regtest),
        ..UserConfig::default()
    };
    let config = resolved(&[&overrides, &selection]);
    assert_eq!(config.network, bitcoin_rs_primitives::Network::Regtest);
    assert_eq!(
        config.p2p.connect,
        vec!["127.0.0.1:8333"],
        "a later bare network selection keeps the peer list an operator set"
    );
    assert!(
        !config.p2p.dns_seeds_enabled,
        "a later bare network selection keeps the seed choice an operator set"
    );
    assert_eq!(
        config.validation.assume_valid_height, 7,
        "a later bare network selection keeps the height an operator pinned"
    );
    assert_eq!(
        config.p2p.magic,
        bitcoin_rs_primitives::Network::Regtest.magic(),
        "a field no layer set still fills from the winning profile"
    );
}
