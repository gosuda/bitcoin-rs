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
