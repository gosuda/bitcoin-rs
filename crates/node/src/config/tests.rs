use std::path::PathBuf;

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
fn absent_fields_preserve_values_and_explicit_empty_values_win() {
    let mut base = UserConfig {
        storage: StorageOverrides {
            dbcache_mb: Some(100),
            prune_target_mb: Some(550),
            ..StorageOverrides::default()
        },
        p2p: P2pOverrides {
            dns_seeds: Some(true),
            connect: Some(vec!["127.0.0.1:18444".into()]),
            ..P2pOverrides::default()
        },
        rpc: RpcOverrides {
            rest: Some(true),
            password: Some("lower".into()),
            ..RpcOverrides::default()
        },
        indexes: IndexOverrides {
            txindex: Some(true),
            script_index: Some(ScriptIndexMode::Full),
        },
        chainstate_journal: Some(ChainstateJournalOverrides {
            enabled: Some(true),
            blocks: Some(100),
            ..ChainstateJournalOverrides::default()
        }),
        ..UserConfig::default()
    };
    base.overlay(&UserConfig::default());
    assert_eq!(base.storage.dbcache_mb, Some(100));
    assert_eq!(base.p2p.dns_seeds, Some(true));
    assert_eq!(base.rpc.password.as_deref(), Some("lower"));

    base.overlay(&UserConfig {
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
            rest: Some(false),
            password: Some(String::new()),
            ..RpcOverrides::default()
        },
        indexes: IndexOverrides {
            txindex: Some(false),
            script_index: Some(ScriptIndexMode::Disabled),
        },
        chainstate_journal: Some(ChainstateJournalOverrides {
            enabled: Some(false),
            ..ChainstateJournalOverrides::default()
        }),
        ..UserConfig::default()
    });
    assert_eq!(base.storage.dbcache_mb, Some(0));
    assert_eq!(base.storage.prune_target_mb, Some(550));
    assert_eq!(base.p2p.dns_seeds, Some(false));
    assert_eq!(base.p2p.connect, Some(Vec::new()));
    assert_eq!(base.rpc.rest, Some(false));
    assert_eq!(base.rpc.password.as_deref(), Some(""));
    assert_eq!(base.indexes.txindex, Some(false));
    assert_eq!(base.indexes.script_index, Some(ScriptIndexMode::Disabled));
    assert_eq!(
        base.chainstate_journal,
        Some(ChainstateJournalOverrides {
            enabled: Some(false),
            blocks: Some(100),
            ..ChainstateJournalOverrides::default()
        })
    );
}

// CONTRACT: docs/contracts/architecture.md#ARCH-05
#[test]
// CONTRACT: docs/contracts/architecture.md#ARCH-05
fn journal_validation_keeps_each_bound_and_its_error() {
    let defaults = ChainstateJournalConfig::default();
    assert!(defaults.validate().is_ok());
    let cases = [
        (
            ChainstateJournalConfig { blocks: 0, ..defaults },
            "chainstate_journal.blocks must be positive",
        ),
        (
            ChainstateJournalConfig { seconds: 0, ..defaults },
            "chainstate_journal.seconds must be positive",
        ),
        (
            ChainstateJournalConfig { rotate_mib: 0, ..defaults },
            "chainstate_journal.rotate_mib must be positive",
        ),
        (
            ChainstateJournalConfig { max_journal_mib: 0, ..defaults },
            "chainstate_journal.max_journal_mib must be >= rotate_mib",
        ),
        (
            ChainstateJournalConfig { max_lag_blocks: 0, ..defaults },
            "chainstate_journal.max_lag_blocks must be >= blocks",
        ),
        (
            ChainstateJournalConfig { max_lag_seconds: 0, ..defaults },
            "chainstate_journal.max_lag_seconds must be positive",
        ),
    ];
    for (journal, expected) in cases {
        assert_eq!(journal.validate().map_err(|error| error.to_string()), Err(expected.into()));
    }
}

// CONTRACT: docs/contracts/architecture.md#ARCH-05
#[test]
// CONTRACT: docs/contracts/architecture.md#ARCH-05
fn disabled_journal_still_validates_settings() {
    let journal = ChainstateJournalConfig {
        enabled: false,
        blocks: 0,
        ..ChainstateJournalConfig::default()
    };
    assert_eq!(
        journal.validate().map_err(|error| error.to_string()),
        Err("chainstate_journal.blocks must be positive".into())
    );
}

#[cfg(feature = "fjall")]
mod resolution {
    use bitcoin_rs_primitives::Network;

    use super::*;

    #[test]
    // CONTRACT: docs/contracts/architecture.md#ARCH-05
    fn later_network_resets_earlier_profile_settings() -> anyhow::Result<()> {
        let earlier = UserConfig {
            rpc: RpcOverrides {
                bind: Some(([127, 0, 0, 1], 12345).into()),
                ..RpcOverrides::default()
            },
            p2p: P2pOverrides {
                connect: Some(vec!["127.0.0.1:12346".into()]),
                ..P2pOverrides::default()
            },
            ..UserConfig::default()
        };
        let later = UserConfig {
            network: Some(NetworkSelection::Regtest),
            ..UserConfig::default()
        };
        let config = resolve(&[&earlier, &later])?;
        assert_eq!(config.network, Network::Regtest);
        assert_eq!(config.rpc.bind.port(), Network::Regtest.default_rpc_port());
        assert!(config.p2p.connect.is_empty());
        assert_eq!(config.p2p.magic, Network::Regtest.magic());
        Ok(())
    }

    // CONTRACT: docs/contracts/architecture.md#ARCH-05
    #[test]
    // CONTRACT: docs/contracts/architecture.md#ARCH-05
    fn explicit_fields_override_the_same_layers_network_defaults() -> anyhow::Result<()> {
        let layer = UserConfig {
            network: Some(NetworkSelection::Regtest),
            rpc: RpcOverrides {
                bind: Some(([127, 0, 0, 1], 12345).into()),
                ..RpcOverrides::default()
            },
            ..UserConfig::default()
        };
        let config = resolve(&[&layer])?;
        assert_eq!(config.rpc.bind.port(), 12345);
        Ok(())
    }

    // CONTRACT: docs/contracts/architecture.md#ARCH-05
    #[test]
    // CONTRACT: docs/contracts/architecture.md#ARCH-05
    fn mining_address_is_decoded_against_the_final_network() -> anyhow::Result<()> {
        let earlier = UserConfig {
            mining: MiningOverrides {
                payout_address: Some("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn".into()),
            },
            ..UserConfig::default()
        };
        assert!(resolve(&[&earlier]).is_err());
        let later = UserConfig {
            network: Some(NetworkSelection::Regtest),
            ..UserConfig::default()
        };
        let config = resolve(&[&earlier, &later])?;
        assert_eq!(config.network, Network::Regtest);
        assert!(!config.mining.payout_script.is_empty());
        Ok(())
    }

    // CONTRACT: docs/contracts/architecture.md#ARCH-05
    #[test]
    // CONTRACT: docs/contracts/architecture.md#ARCH-05
    fn only_the_last_set_mining_address_is_decoded() -> anyhow::Result<()> {
        let invalid = UserConfig {
            mining: MiningOverrides {
                payout_address: Some("not-an-address".into()),
            },
            ..UserConfig::default()
        };
        let valid = UserConfig {
            mining: MiningOverrides {
                payout_address: Some("1BoatSLRHtKNngkdXEeobR76b53LETtpyT".into()),
            },
            ..UserConfig::default()
        };
        let absent = UserConfig::default();
        assert!(!resolve(&[&invalid, &valid, &absent])?.mining.payout_script.is_empty());
        assert!(resolve(&[&valid, &invalid]).is_err());
        Ok(())
    }

    // CONTRACT: docs/contracts/architecture.md#ARCH-05
    #[test]
    // CONTRACT: docs/contracts/architecture.md#ARCH-05
    fn an_explicit_empty_mining_address_is_not_absent() {
        let layer = UserConfig {
            mining: MiningOverrides {
                payout_address: Some(String::new()),
            },
            ..UserConfig::default()
        };
        assert!(resolve(&[&layer]).is_err());
    }

    // CONTRACT: docs/contracts/architecture.md#ARCH-05
    #[test]
    // CONTRACT: docs/contracts/external-api.md#API-06
    fn cookie_wins_within_a_layer_and_later_basic_auth_uses_defaults() -> anyhow::Result<()> {
        let cookie = UserConfig {
            rpc: RpcOverrides {
                user: Some("ignored".into()),
                password: Some("ignored".into()),
                cookie: Some(PathBuf::from(".cookie")),
                ..RpcOverrides::default()
            },
            ..UserConfig::default()
        };
        assert_eq!(resolve(&[&cookie])?.rpc.auth, Auth::Cookie { path: ".cookie".into() });
        let basic = UserConfig {
            rpc: RpcOverrides {
                user: Some("operator".into()),
                ..RpcOverrides::default()
            },
            ..UserConfig::default()
        };
        assert_eq!(resolve(&[&cookie, &basic])?.rpc.auth, Auth::basic("operator", "bitcoin-rs"));
        Ok(())
    }
}
