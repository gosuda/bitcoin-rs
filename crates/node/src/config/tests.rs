use std::net::SocketAddr;
use std::path::PathBuf;

#[cfg(feature = "fjall")]
use bitcoin_rs_primitives::Network;

use super::*;

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
// CONTRACT: docs/contracts/architecture.md#ARCH-05
fn user_config_overlay_lets_set_fields_win() {
    let mut base = UserConfig {
        storage: StorageOverrides {
            prune_target_mb: Some(550),
            ..StorageOverrides::default()
        },
        rpc: RpcOverrides {
            user: Some("global".to_owned()),
            password: Some("g".to_owned()),
            ..RpcOverrides::default()
        },
        chainstate_journal: Some(ChainstateJournalOverrides {
            blocks: Some(900),
            ..ChainstateJournalOverrides::default()
        }),
        ..UserConfig::default()
    };
    let other = UserConfig {
        storage: StorageOverrides {
            prune_target_mb: Some(900),
            ..StorageOverrides::default()
        },
        rpc: RpcOverrides {
            user: Some("regtest".to_owned()),
            ..RpcOverrides::default()
        },
        chainstate_journal: Some(ChainstateJournalOverrides {
            seconds: Some(45),
            ..ChainstateJournalOverrides::default()
        }),
        ..UserConfig::default()
    };
    base.overlay(&other);
    assert_eq!(base.storage.prune_target_mb, Some(900));
    assert_eq!(base.rpc.user.as_deref(), Some("regtest"));
    assert_eq!(base.rpc.password.as_deref(), Some("g"));
    assert_eq!(
        base.chainstate_journal,
        Some(ChainstateJournalOverrides {
            blocks: Some(900),
            seconds: Some(45),
            ..ChainstateJournalOverrides::default()
        })
    );
    assert_eq!(base.mining.payout_address.as_deref(), None);
}

#[test]
// CONTRACT: docs/contracts/architecture.md#ARCH-05
fn mining_payout_overlay_lets_the_later_address_win() {
    let mut base = UserConfig {
        mining: MiningOverrides {
            payout_address: Some("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080".to_owned()),
        },
        ..UserConfig::default()
    };
    let other = UserConfig {
        mining: MiningOverrides {
            payout_address: Some("bcrt1qjqmxmkpmxt80xz4y3746zgt0q3u3ferr34acd5".to_owned()),
        },
        ..UserConfig::default()
    };
    base.overlay(&other);
    assert_eq!(
        base.mining.payout_address.as_deref(),
        Some("bcrt1qjqmxmkpmxt80xz4y3746zgt0q3u3ferr34acd5")
    );
}

#[test]
// CONTRACT: docs/contracts/architecture.md#ARCH-05
fn explicit_false_zero_and_empty_values_override_without_clearing_absent_fields() {
    let listen = SocketAddr::from(([127, 0, 0, 1], 18444));
    let mut base = UserConfig {
        storage: StorageOverrides {
            dbcache_mb: Some(450),
            prune_target_mb: Some(550),
            ..StorageOverrides::default()
        },
        p2p: P2pOverrides {
            listen: Some(vec![listen]),
            dns_seeds: Some(true),
            connect: Some(vec!["127.0.0.1:18444".to_owned()]),
            ..P2pOverrides::default()
        },
        rpc: RpcOverrides {
            user: Some("operator".to_owned()),
            password: Some("preserved".to_owned()),
            rest: Some(true),
            ..RpcOverrides::default()
        },
        indexes: IndexOverrides {
            txindex: Some(true),
            script_index: Some(ScriptIndexMode::Full),
        },
        ..UserConfig::default()
    };
    let layer = UserConfig {
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
            user: Some(String::new()),
            rest: Some(false),
            ..RpcOverrides::default()
        },
        indexes: IndexOverrides {
            txindex: Some(false),
            script_index: Some(ScriptIndexMode::Disabled),
        },
        ..UserConfig::default()
    };
    base.overlay(&layer);
    assert_eq!(base.storage.dbcache_mb, Some(450));
    assert_eq!(base.storage.prune_target_mb, Some(0));
    assert_eq!(base.p2p.listen, Some(vec![listen]));
    assert_eq!(base.p2p.dns_seeds, Some(false));
    assert_eq!(base.p2p.connect, Some(Vec::new()));
    assert_eq!(base.rpc.user.as_deref(), Some(""));
    assert_eq!(base.rpc.password.as_deref(), Some("preserved"));
    assert_eq!(base.rpc.rest, Some(false));
    assert_eq!(base.indexes.txindex, Some(false));
    assert_eq!(base.indexes.script_index, Some(ScriptIndexMode::Disabled));
}

#[cfg(feature = "fjall")]
#[test]
// CONTRACT: docs/contracts/architecture.md#ARCH-05
fn later_network_defaults_precede_same_layer_overrides() {
    let lower = UserConfig {
        network: Some(NetworkSelection::Testnet4),
        rpc: RpcOverrides {
            bind: Some(SocketAddr::from(([127, 0, 0, 1], 12345))),
            password: Some("preserved".to_owned()),
            ..RpcOverrides::default()
        },
        ..UserConfig::default()
    };
    let listen = SocketAddr::from(([127, 0, 0, 1], 23456));
    let higher = UserConfig {
        network: Some(NetworkSelection::Regtest),
        p2p: P2pOverrides {
            listen: Some(vec![listen]),
            dns_seeds: Some(false),
            ..P2pOverrides::default()
        },
        rpc: RpcOverrides {
            user: Some("operator".to_owned()),
            ..RpcOverrides::default()
        },
        ..UserConfig::default()
    };
    let config = resolve(&[&lower, &higher]).expect("valid layers");
    assert_eq!(config.network, Network::Regtest);
    assert_eq!(config.rpc.bind.port(), Network::Regtest.default_rpc_port());
    assert_eq!(config.p2p.magic, Network::Regtest.magic());
    assert_eq!(config.p2p.listen, vec![listen]);
    assert!(!config.p2p.dns_seeds_enabled);
    assert_eq!(config.rpc.auth, Auth::basic("operator", "preserved"));
}

#[cfg(feature = "fjall")]
#[test]
// CONTRACT: docs/contracts/architecture.md#ARCH-05
fn switching_cookie_to_partial_basic_auth_uses_the_default_missing_credential() {
    let lower = UserConfig {
        rpc: RpcOverrides {
            cookie: Some(PathBuf::from("unused-cookie")),
            ..RpcOverrides::default()
        },
        ..UserConfig::default()
    };
    let higher = UserConfig {
        rpc: RpcOverrides {
            user: Some("operator".to_owned()),
            ..RpcOverrides::default()
        },
        ..UserConfig::default()
    };
    let config = resolve(&[&lower, &higher]).expect("valid layers");
    assert_eq!(config.rpc.auth, Auth::basic("operator", "bitcoin-rs"));
}
