//! Public configuration contracts preserved across internal module boundaries.

#[cfg(feature = "fjall")]
use std::path::PathBuf;

use bitcoin_rs_node::config::{
    ChainstateJournalOverrides, NetworkSelection, P2pOverrides, RpcOverrides, ScriptIndexMode,
    StorageOverrides, UserConfig,
};
#[cfg(feature = "fjall")]
use bitcoin_rs_node::config::{Auth, resolve};

#[test]
// CONTRACT: docs/contracts/architecture.md#ARCH-05
fn empty_layer_preserves_explicit_values() {
    let mut layer = UserConfig {
        storage: StorageOverrides {
            dbcache_mb: Some(0),
            ..StorageOverrides::default()
        },
        p2p: P2pOverrides {
            dns_seeds: Some(false),
            connect: Some(Vec::new()),
            ..P2pOverrides::default()
        },
        rpc: RpcOverrides {
            password: Some(String::new()),
            ..RpcOverrides::default()
        },
        chainstate_journal: Some(ChainstateJournalOverrides {
            enabled: Some(false),
            blocks: Some(1),
            ..ChainstateJournalOverrides::default()
        }),
        ..UserConfig::default()
    };

    layer.overlay(&UserConfig::default());

    assert_eq!(layer.storage.dbcache_mb, Some(0));
    assert_eq!(layer.p2p.dns_seeds, Some(false));
    assert_eq!(layer.p2p.connect, Some(Vec::new()));
    assert_eq!(layer.rpc.password.as_deref(), Some(""));
    assert_eq!(
        layer.chainstate_journal,
        Some(ChainstateJournalOverrides {
            enabled: Some(false),
            blocks: Some(1),
            ..ChainstateJournalOverrides::default()
        })
    );
}

#[test]
// CONTRACT: docs/contracts/architecture.md#ARCH-05
fn explicit_false_zero_and_empty_values_override_lower_layers() {
    let mut lower = UserConfig {
        storage: StorageOverrides {
            prune_target_mb: Some(550),
            ..StorageOverrides::default()
        },
        p2p: P2pOverrides {
            dns_seeds: Some(true),
            connect: Some(vec!["127.0.0.1:8333".to_owned()]),
            ..P2pOverrides::default()
        },
        rpc: RpcOverrides {
            password: Some("lower-password".to_owned()),
            ..RpcOverrides::default()
        },
        ..UserConfig::default()
    };
    let higher = UserConfig {
        storage: StorageOverrides {
            prune_target_mb: Some(0),
            ..StorageOverrides::default()
        },
        p2p: P2pOverrides {
            dns_seeds: Some(false),
            connect: Some(Vec::new()),
            ..P2pOverrides::default()
        },
        rpc: RpcOverrides {
            password: Some(String::new()),
            ..RpcOverrides::default()
        },
        ..UserConfig::default()
    };

    lower.overlay(&higher);

    assert_eq!(lower.storage.prune_target_mb, Some(0));
    assert_eq!(lower.p2p.dns_seeds, Some(false));
    assert_eq!(lower.p2p.connect, Some(Vec::new()));
    assert_eq!(lower.rpc.password.as_deref(), Some(""));
}

#[test]
// CONTRACT: docs/contracts/architecture.md#ARCH-05 (network aliases)
fn network_aliases_preserve_the_selected_profile() {
    for (value, expected) in [
        (" BITCOIN ", NetworkSelection::Mainnet),
        ("main", NetworkSelection::Mainnet),
        ("test", NetworkSelection::Testnet3),
        ("testnet", NetworkSelection::Testnet3),
        ("testnet3", NetworkSelection::Testnet3),
        ("testnet4", NetworkSelection::Testnet4),
        ("SIGNET", NetworkSelection::Signet),
        ("regtest", NetworkSelection::Regtest),
        ("drynet4", NetworkSelection::Drynet4),
    ] {
        assert_eq!(NetworkSelection::parse(value), Some(expected));
    }
    assert_eq!(NetworkSelection::parse("unknown"), None);
    assert_eq!(
        NetworkSelection::Drynet4.consensus_network(),
        NetworkSelection::Mainnet.consensus_network()
    );
}

#[test]
// CONTRACT: docs/contracts/indexing.md#IDX-01
fn script_index_boolean_aliases_preserve_history_selection() {
    for value in ["full", "TRUE", "1", " yes "] {
        assert_eq!(ScriptIndexMode::parse(value), Some(ScriptIndexMode::Full));
    }
    for value in ["FALSE", "0", " no "] {
        assert_eq!(ScriptIndexMode::parse(value), Some(ScriptIndexMode::Disabled));
    }
    assert_eq!(ScriptIndexMode::parse("utxo"), Some(ScriptIndexMode::Utxo));
    assert!(ScriptIndexMode::Utxo.is_enabled());
    assert!(!ScriptIndexMode::Utxo.keeps_history());
    assert!(ScriptIndexMode::Full.keeps_history());
    assert!(!ScriptIndexMode::Disabled.is_enabled());
    assert_eq!(ScriptIndexMode::parse("unknown"), None);
}

#[cfg(feature = "fjall")]
#[test]
// CONTRACT: docs/contracts/architecture.md#ARCH-05 (authentication layering)
fn resolve_keeps_cookie_and_partial_basic_auth_precedence() -> anyhow::Result<()> {
    let lower = UserConfig {
        rpc: RpcOverrides {
            user: Some("lower-user".to_owned()),
            password: Some("lower-password".to_owned()),
            cookie: Some(PathBuf::from("not-opened.cookie")),
            ..RpcOverrides::default()
        },
        ..UserConfig::default()
    };
    assert_eq!(
        resolve(&[&lower])?.rpc.auth,
        Auth::Cookie {
            path: PathBuf::from("not-opened.cookie")
        }
    );

    let higher = UserConfig {
        rpc: RpcOverrides {
            user: Some("higher-user".to_owned()),
            ..RpcOverrides::default()
        },
        ..UserConfig::default()
    };
    assert_eq!(
        resolve(&[&lower, &higher])?.rpc.auth,
        Auth::basic("higher-user", "bitcoin-rs")
    );
    Ok(())
}

#[cfg(feature = "fjall")]
#[test]
// CONTRACT: docs/contracts/architecture.md#ARCH-05 (network reset ordering and defaults)
fn network_selection_resets_defaults_before_same_layer_overrides() -> anyhow::Result<()> {
    use std::net::SocketAddr;

    let lower = UserConfig {
        rpc: RpcOverrides {
            bind: Some(SocketAddr::from(([127, 0, 0, 1], 1234))),
            ..RpcOverrides::default()
        },
        p2p: P2pOverrides {
            dns_seeds: Some(false),
            connect: Some(vec!["127.0.0.1:8333".to_owned()]),
            ..P2pOverrides::default()
        },
        ..UserConfig::default()
    };
    let higher = UserConfig {
        network: Some(NetworkSelection::Regtest),
        p2p: P2pOverrides {
            listen: Some(Vec::new()),
            ..P2pOverrides::default()
        },
        ..UserConfig::default()
    };

    let config = resolve(&[&lower, &higher])?;

    assert_eq!(config.network, NetworkSelection::Regtest.consensus_network());
    assert_eq!(config.rpc.bind, SocketAddr::from(([127, 0, 0, 1], 18443)));
    assert!(config.p2p.dns_seeds_enabled);
    assert!(config.p2p.connect.is_empty());
    assert!(config.p2p.listen.is_empty());
    Ok(())
}
is_empty());
    Ok(())
}
