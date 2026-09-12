use std::path::PathBuf;

use super::{
    Auth, ChainstateJournalOverrides, MiningOverrides, NetworkSelection, NodeConfig, P2pOverrides,
    RpcOverrides, ScriptIndexMode, StorageOverrides, UserConfig, ValidationOverrides,
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

// ---- #653 named config-option coverage --------------------------------
//
// Retained source precedence, absent nested overrides, and cross-field
// validation are exercised here at the one resolver every input layer
// feeds, so no adapter can bypass the named rules.

fn resolved(layers: &[&UserConfig]) -> NodeConfig {
    super::resolve(layers).unwrap_or_else(|error| panic!("valid layered configuration: {error}"))
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
    let (user, password) = config.rpc.auth.basic_parts();
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

#[test]
fn journal_nested_overrides_apply_field_by_field_across_layers() {
    let base = UserConfig {
        chainstate_journal: Some(ChainstateJournalOverrides {
            blocks: Some(200),
            ..ChainstateJournalOverrides::default()
        }),
        ..UserConfig::default()
    };
    let higher = UserConfig {
        chainstate_journal: Some(ChainstateJournalOverrides {
            seconds: Some(45),
            ..ChainstateJournalOverrides::default()
        }),
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
    let (user, password) = config.rpc.auth.basic_parts();
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
        chainstate_journal: Some(ChainstateJournalOverrides {
            rotate_mib: Some(4096),
            max_journal_mib: Some(2048),
            ..ChainstateJournalOverrides::default()
        }),
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
        chainstate_journal: Some(ChainstateJournalOverrides {
            blocks: Some(500),
            max_lag_blocks: Some(100),
            ..ChainstateJournalOverrides::default()
        }),
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
        chainstate_journal: Some(ChainstateJournalOverrides {
            seconds: Some(0),
            ..ChainstateJournalOverrides::default()
        }),
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
fn later_network_selection_resets_earlier_p2p_overrides_atomically() {
    let overrides = UserConfig {
        p2p: P2pOverrides {
            magic: Some([1, 2, 3, 4]),
            connect: Some(vec!["127.0.0.1:8333".to_owned()]),
            dns_seeds: Some(false),
            ..P2pOverrides::default()
        },
        validation: ValidationOverrides {
            assume_valid_height: Some(7),
        },
        ..UserConfig::default()
    };
    let selection = UserConfig {
        network: Some(NetworkSelection::Regtest),
        ..UserConfig::default()
    };
    let config = resolved(&[&overrides, &selection]);
    assert_eq!(
        config.p2p.magic,
        bitcoin_rs_primitives::Network::Regtest.magic()
    );
    assert!(
        config.p2p.connect.is_empty(),
        "the network profile owns the connect list"
    );
    assert!(config.p2p.dns_seeds_enabled);
    assert_eq!(
        config.validation.assume_valid_height, 0,
        "the network anchor replaces the pinned height"
    );
}
