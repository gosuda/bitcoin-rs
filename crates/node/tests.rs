mod budget {
    use bitcoin_rs_chain::chain::NodeStatus;
    use bitcoin_rs_node::budget::{BudgetedIngressLedger, BudgetedOutboundLedger, NodeBudget};
    use bitcoin_rs_node::state::NodeState;
    use bitcoin_rs_node::{Network, NodeConfig};
    use bitcoin_rs_p2p::connection::OutboundLedger;
    use bitcoin_rs_p2p::inbound::block_memory::BlockMemory;
    use bitcoin_rs_storage::{
        budget::{BudgetError, BudgetOwner, BudgetRefusal},
        split_chainstate_cache_budget,
    };
    use std::sync::Arc;
    #[expect(clippy::expect_used)]
    fn open_test_node() -> (NodeState, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir succeeds");
        let mut config = NodeConfig::default_for_network(Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p.listen.clear();
        let state = NodeState::open(config, None).expect("node open succeeds");
        (state, dir)
    }
    // BUD-02, BUD-06
    #[test]
    #[expect(clippy::expect_used)]
    fn ingress_and_peer_outbound_charges_return_to_their_owner_on_release() {
        let budget = Arc::new(NodeBudget::from_chainstate_cache_budget(
            split_chainstate_cache_budget(64 * 1024 * 1024),
            8,
        ));
        let ledger = Arc::new(BudgetedIngressLedger::new(Arc::clone(&budget)));
        let block_memory = Arc::new(BlockMemory::new(ledger));
        let outbound = BudgetedOutboundLedger::new(Arc::clone(&budget));

        let ingress_bytes: usize = 1024 * 1024;
        let credit = block_memory
            .reserve(ingress_bytes, || false)
            .expect("ingress reservation succeeds");
        assert_eq!(
            budget.charged_bytes(BudgetOwner::StagedImages),
            1024 * 1024,
            "the staged block charge rises while the credit is held"
        );
        drop(credit);
        assert_eq!(
            budget.charged_bytes(BudgetOwner::StagedImages),
            0,
            "dropping the staged block credit returns its charge"
        );

        assert!(
            outbound.try_take(4096),
            "an outbound reservation inside the cap is admitted"
        );
        assert_eq!(
            budget.charged_bytes(BudgetOwner::PeerOutbound),
            4096,
            "the outbound reservation charges the peer owner"
        );
        outbound.give_back(4096);
        assert_eq!(
            budget.charged_bytes(BudgetOwner::PeerOutbound),
            0,
            "releasing the outbound bytes returns the peer owner charge"
        );
        assert!(budget.is_safe());
    }

    // BUD-03
    #[test]
    #[expect(clippy::expect_used)]
    fn full_budget_refuses_ingress_without_marking_invalid() {
        let (state, _dir) = open_test_node();
        let budget = state.budget();
        let block_memory = state.block_memory();

        let owners = [
            BudgetOwner::StagedImages,
            BudgetOwner::EngineCache,
            BudgetOwner::CoinCache,
            BudgetOwner::FactsQueue,
            BudgetOwner::IndexBuilder,
            BudgetOwner::QueryViews,
            BudgetOwner::PeerOutbound,
            BudgetOwner::PeerReceive,
        ];
        for owner in owners {
            let avail = budget.available(owner);
            if avail > 0 {
                budget.reserve(owner, avail).expect("reserve available");
                budget.allocate(owner, avail).expect("allocate available");
            }
        }

        let Err(error) = budget.reserve(BudgetOwner::StagedImages, 1024 * 1024) else {
            panic!("staged-image reservation must be refused when the budget is full");
        };
        assert_eq!(
            error,
            BudgetError::BudgetExhausted,
            "a full budget refuses staged images with BudgetExhausted"
        );
        assert_eq!(
            error.refusal(),
            Some(BudgetRefusal::RetryLater),
            "a full-budget refusal is RetryLater backpressure"
        );

        assert!(
            !block_memory.ledger().try_take(1024 * 1024),
            "the ingress ledger must refuse block bytes when the budget is full"
        );

        assert!(
            budget.ingress_refused(),
            "budget must record ingress refusal"
        );

        let refused_hash = Network::Regtest.genesis_block_hash();
        let tree = state.chainstate().block_tree_reader();
        let tree_read = tree.read();
        if let Some(id) = tree_read.lookup(refused_hash) {
            let Ok(node) = tree_read.node(id) else {
                panic!("BlockTree lookup returned an unknown node");
            };
            assert_ne!(
                node.status,
                NodeStatus::Invalid,
                "refused block must NEVER be marked Invalid in BlockTree (BUD-03)"
            );
        }
    }
}
mod config_layered {
    use std::str::FromStr as _;

    use bitcoin_rs_node::test_support::TestError;

    type Result<T, E = TestError> = core::result::Result<T, E>;
    use bitcoin_rs_consensus::primitives::Network;
    use bitcoin_rs_node::{
        NetworkSelection, NodeConfig, NotificationConfig, P2pOverrides, ScriptIndexMode,
        UserConfig, ValidationOverrides, ZmqEndpointConfig, resolve,
    };
    use bitcoin_rs_wire::zmq::ZmqTopic;

    #[test]
    fn public_listener_is_opt_in_and_budgets_resolve_independently() -> Result<()> {
        let defaults = NodeConfig::default_for_network(Network::Regtest);
        assert_eq!(defaults.rpc.public_bind, None);
        assert_eq!(defaults.rpc.max_connections, 128);
        assert_eq!(defaults.rpc.public_max_connections, 128);
        let file: UserConfig = toml::from_str(
            "public_bind = '0.0.0.0:8080'\nrpc_max_connections = 8\npublic_max_connections = 32",
        )?;
        let mut environment = UserConfig::default();
        environment.apply_env(
            "BITCOIN_RS_PUBLIC_BIND",
            std::ffi::OsStr::new("127.0.0.1:9090"),
        )?;
        environment.apply_env(
            "BITCOIN_RS_PUBLIC_MAX_CONNECTIONS",
            std::ffi::OsStr::new("16"),
        )?;
        let config = resolve(&[&file, &environment])?;
        assert_eq!(config.rpc.public_bind, Some("127.0.0.1:9090".parse()?));
        assert_eq!(config.rpc.max_connections, 8);
        assert_eq!(config.rpc.public_max_connections, 16);
        for invalid in [
            "rpc_max_connections = 0",
            "public_max_connections = 0",
            "rpc_bind = '127.0.0.1:8332'\npublic_bind = '127.0.0.1:8332'",
        ] {
            let layer: UserConfig = toml::from_str(invalid)?;
            assert!(resolve(&[&layer]).is_err(), "{invalid}");
        }
        Ok(())
    }

    #[test]
    fn public_listener_bind_validation_handles_wildcards_and_ephemeral_ports() -> Result<()> {
        for (management, public, valid) in [
            ("127.0.0.1:8332", "127.0.0.1:8332", false),
            ("0.0.0.0:8332", "127.0.0.1:8332", false),
            ("127.0.0.1:8332", "0.0.0.0:8332", false),
            ("[::]:8332", "[::1]:8332", false),
            ("[::1]:8332", "[::]:8332", false),
            ("127.0.0.1:8332", "127.0.0.2:8332", true),
            ("127.0.0.1:8332", "127.0.0.1:8080", true),
            ("0.0.0.0:0", "0.0.0.0:0", true),
            ("127.0.0.1:0", "127.0.0.1:8332", true),
            ("127.0.0.1:8332", "127.0.0.1:0", true),
        ] {
            let mut config = NodeConfig::default_for_network(Network::Regtest);
            config.rpc.bind = management.parse()?;
            config.rpc.public_bind = Some(public.parse()?);
            config.rpc.auth = bitcoin_rs_node::Auth::basic("operator", "secret");
            let result = config.validate();
            assert_eq!(result.is_ok(), valid, "{management}, {public}: {result:?}");
            if let Err(error) = result {
                assert!(
                    matches!(error, bitcoin_rs_node::ConfigError::RpcBindOverlap),
                    "{error:?}"
                );
            }
        }
        let management = std::net::TcpListener::bind("0.0.0.0:0")?;
        let public = std::net::TcpListener::bind("0.0.0.0:0")?;
        assert_ne!(management.local_addr()?.port(), public.local_addr()?.port());
        Ok(())
    }

    #[test]
    fn overlay_routing_is_opt_in_and_layered_without_implicit_fallback() -> Result<()> {
        let default = NodeConfig::default_for_network(Network::Regtest);
        assert!(default.p2p.overlay.proxy.is_none());
        assert!(default.p2p.overlay.onion_proxy.is_none());
        assert!(default.p2p.overlay.i2p_sam.is_none());
        let file: UserConfig = toml::from_str(
            r#"
        network = "regtest"
        dns_seeds_enabled = false
        onion_proxy = "127.0.0.1:9050"
        onlynet = ["onion"]
        proxy_randomize_credentials = false
        overlay_port = 18445
    "#,
        )?;
        let mut environment = UserConfig::default();
        environment.apply_env("BITCOIN_RS_ONLYNET", std::ffi::OsStr::new("onion,i2p"))?;
        environment.apply_env("BITCOIN_RS_I2P_SAM", std::ffi::OsStr::new("127.0.0.1:7656"))?;
        let config = resolve(&[&file, &environment])?;
        assert!(
            config
                .p2p
                .overlay
                .allows(bitcoin_rs_consensus::primitives::PeerNetwork::Onion)
        );
        assert!(
            config
                .p2p
                .overlay
                .allows(bitcoin_rs_consensus::primitives::PeerNetwork::I2p)
        );
        assert!(
            !config
                .p2p
                .overlay
                .allows(bitcoin_rs_consensus::primitives::PeerNetwork::Ipv4)
        );
        assert!(!config.p2p.overlay.randomize_credentials);
        assert_eq!(config.p2p.overlay.port, 18445);
        for text in [
            "onlynet = ['onion']",
            "i2p_accept = true",
            "onion_proxy = '8.8.8.8:9050'",
            "tor_control = '127.0.0.1:9051'",
        ] {
            let layer: UserConfig = toml::from_str(text)?;
            assert!(resolve(&[&layer]).is_err(), "{text}");
        }
        Ok(())
    }

    #[test]
    fn blank_onlynet_environment_clears_an_inherited_network_list() -> Result<()> {
        let file: UserConfig = toml::from_str("onlynet = ['ipv4']")?;
        let mut environment = UserConfig::default();
        environment.apply_env("BITCOIN_RS_ONLYNET", std::ffi::OsStr::new("  "))?;
        assert_eq!(
            resolve(&[&file, &environment])?.p2p.overlay.onlynet,
            Vec::<bitcoin_rs_consensus::primitives::PeerNetwork>::new()
        );
        assert!(
            environment
                .apply_env("BITCOIN_RS_ONLYNET", std::ffi::OsStr::new("ipv4,"))
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn silent_payments_toml_overlay_preserves_explicit_disable() -> Result<()> {
        assert!(
            !NodeConfig::default_for_network(Network::Regtest)
                .rpc
                .silent_payments
        );
        let enabled: UserConfig = toml::from_str("silent_payments = true")?;
        let disabled: UserConfig = toml::from_str("silent_payments = false")?;
        assert!(!resolve(&[&enabled, &disabled])?.rpc.silent_payments);
        let mut environment = UserConfig::default();
        environment.apply_env("BITCOIN_RS_SILENT_PAYMENTS", std::ffi::OsStr::new("false"))?;
        assert!(!resolve(&[&enabled, &environment])?.rpc.silent_payments);
        let result = resolve(&[&disabled, &enabled]);
        if cfg!(feature = "silent-payments") {
            assert!(result?.rpc.silent_payments);
        } else {
            assert!(result.is_err_and(|error| matches!(
                error,
                bitcoin_rs_node::ConfigError::SilentPaymentsFeatureRequired
            )));
        }
        Ok(())
    }

    #[test]
    fn compressed_transactions_default_off_and_overlay() -> Result<()> {
        assert!(
            !NodeConfig::default_for_network(Network::Regtest)
                .rpc
                .compressed_transactions
        );
        let enabled: UserConfig = toml::from_str("compressed_transactions = true")?;
        assert!(resolve(&[&enabled])?.rpc.compressed_transactions);
        let mut environment = UserConfig::default();
        environment.apply_env(
            "BITCOIN_RS_COMPRESSED_TRANSACTIONS",
            std::ffi::OsStr::new("false"),
        )?;
        assert!(
            !resolve(&[&enabled, &environment])?
                .rpc
                .compressed_transactions
        );
        Ok(())
    }

    #[test]
    fn standard_network_uses_builtin_defaults() -> Result<()> {
        let layer = UserConfig {
            network: Some(NetworkSelection::Testnet4),
            ..Default::default()
        };
        let config = resolve(&[&layer])?;
        assert_eq!(config.network, Network::Testnet4);
        assert_eq!(config.p2p.magic, Network::Testnet4.magic());
        assert_eq!(config.p2p.connect, Vec::<String>::new());
        assert!(config.p2p.dns_seeds_enabled);
        Ok(())
    }

    #[test]
    fn drynet4_network_applies_atomic_p2p_profile() -> Result<()> {
        let layer = UserConfig {
            network: Some(NetworkSelection::Drynet4),
            ..Default::default()
        };
        let config = resolve(&[&layer])?;
        assert_eq!(config.network, Network::Mainnet);
        assert_eq!(config.p2p.magic, [0xec, 0xa5, 0xd4, 0x04]);
        assert_eq!(config.p2p.connect, vec!["drynet4.drivechain.dev:8533"]);
        assert!(!config.p2p.dns_seeds_enabled);
        Ok(())
    }

    #[test]
    fn p2p_magic_override_preserves_consensus_network() -> Result<()> {
        let layer = UserConfig {
            p2p: P2pOverrides {
                magic: Some([0xec, 0xa5, 0xd4, 0x34]),
                dns_seeds: Some(false),
                connect: Some(vec!["127.0.0.1:8333".to_owned()]),
                ..Default::default()
            },
            ..Default::default()
        };
        let config = resolve(&[&layer])?;
        assert_eq!(config.network, Network::Mainnet);
        assert_eq!(config.p2p.magic, [0xec, 0xa5, 0xd4, 0x34]);
        assert_eq!(config.p2p.connect, vec!["127.0.0.1:8333"]);
        assert!(!config.p2p.dns_seeds_enabled);
        Ok(())
    }

    #[test]
    fn same_layer_explicit_overrides_follow_network_profile() -> Result<()> {
        let layer = UserConfig {
            network: Some(NetworkSelection::Drynet4),
            p2p: P2pOverrides {
                magic: Some([1, 2, 3, 4]),
                connect: Some(vec!["127.0.0.1:8333".to_owned()]),
                dns_seeds: Some(false),
                ..Default::default()
            },
            ..Default::default()
        };
        let config = resolve(&[&layer])?;
        assert_eq!(config.p2p.magic, [1, 2, 3, 4]);
        assert_eq!(config.p2p.connect, vec!["127.0.0.1:8333"]);
        Ok(())
    }

    #[test]
    fn script_index_is_valid_without_core_txindex() -> Result<()> {
        let layer = UserConfig {
            indexes: bitcoin_rs_node::IndexOverrides {
                script_index: Some(ScriptIndexMode::Full),
                txindex: Some(false),
                ..Default::default()
            },
            ..Default::default()
        };
        let config = resolve(&[&layer])?;
        assert!(!config.indexes.txindex);
        assert!(config.indexes.script_index.is_enabled());
        Ok(())
    }

    #[test]
    fn scriptindex_utxo_mode_is_live_only() -> Result<()> {
        let layer = UserConfig {
            indexes: bitcoin_rs_node::IndexOverrides {
                script_index: Some(ScriptIndexMode::Utxo),
                ..Default::default()
            },
            ..Default::default()
        };
        let config = resolve(&[&layer])?;
        assert_eq!(config.indexes.script_index, ScriptIndexMode::Utxo);
        assert!(config.indexes.script_index.is_enabled());
        assert_eq!(
            config
                .indexes
                .script_index
                .enabled_capabilities(config.indexes.txindex),
            bitcoin_rs_index::IndexCapabilities::SCRIPT_LIVE
        );
        Ok(())
    }

    #[test]
    fn zmq_endpoint_groups_keep_topics_and_publisher_default_hwm() -> Result<()> {
        let layer = UserConfig {
            notifications: Some(NotificationConfig {
                zmq: vec![
                    ZmqEndpointConfig {
                        endpoint: "tcp://127.0.0.1:28332".to_owned(),
                        topics: vec![ZmqTopic::HashBlock, ZmqTopic::RawBlock, ZmqTopic::Sequence],
                        hwm: None,
                    },
                    ZmqEndpointConfig {
                        endpoint: "tcp://127.0.0.1:28333".to_owned(),
                        topics: vec![ZmqTopic::HashTx, ZmqTopic::RawTx],
                        hwm: Some(5_000),
                    },
                ],
            }),
            ..Default::default()
        };
        let config = resolve(&[&layer])?;
        let endpoints = config.notifications.zmq;
        assert_eq!(endpoints.len(), 2);
        assert_eq!(endpoints[0].endpoint, "tcp://127.0.0.1:28332");
        assert_eq!(
            endpoints[0]
                .topics
                .iter()
                .map(|topic| topic.as_str())
                .collect::<Vec<_>>(),
            ["hashblock", "rawblock", "sequence"]
        );
        assert_eq!(endpoints[0].hwm, None);
        assert_eq!(endpoints[0].effective_hwm(), 1_000);
        assert_eq!(endpoints[1].endpoint, "tcp://127.0.0.1:28333");
        assert_eq!(endpoints[1].effective_hwm(), 5_000);
        Ok(())
    }

    #[test]
    fn higher_layer_replaces_zmq_endpoint_groups() -> Result<()> {
        let lower = UserConfig {
            notifications: Some(NotificationConfig {
                zmq: vec![
                    ZmqEndpointConfig {
                        endpoint: "tcp://127.0.0.1:28332".to_owned(),
                        topics: vec![ZmqTopic::HashBlock],
                        hwm: Some(42),
                    },
                    ZmqEndpointConfig {
                        endpoint: "tcp://127.0.0.1:28333".to_owned(),
                        topics: vec![ZmqTopic::RawTx],
                        hwm: None,
                    },
                ],
            }),
            ..Default::default()
        };
        let higher = UserConfig {
            notifications: Some(NotificationConfig {
                zmq: vec![ZmqEndpointConfig {
                    endpoint: "tcp://127.0.0.1:28334".to_owned(),
                    topics: vec![ZmqTopic::HashBlock],
                    hwm: Some(7),
                }],
            }),
            ..Default::default()
        };

        let config = resolve(&[&lower, &higher])?;
        assert_eq!(
            config.notifications.zmq,
            vec![ZmqEndpointConfig {
                endpoint: "tcp://127.0.0.1:28334".to_owned(),
                topics: vec![ZmqTopic::HashBlock],
                hwm: Some(7),
            }]
        );
        Ok(())
    }

    #[test]
    fn absent_higher_layer_notifications_preserve_lower_layer() -> Result<()> {
        let lower = UserConfig {
            notifications: Some(NotificationConfig {
                zmq: vec![ZmqEndpointConfig {
                    endpoint: "tcp://127.0.0.1:28332".to_owned(),
                    topics: vec![ZmqTopic::HashBlock],
                    hwm: Some(42),
                }],
            }),
            ..Default::default()
        };
        let higher = UserConfig::default();
        let config = resolve(&[&lower, &higher])?;
        assert_eq!(config.notifications.zmq[0].effective_hwm(), 42);
        Ok(())
    }

    #[test]
    fn zmq_endpoint_groups_reject_duplicate_socket_and_topic_ownership() {
        let mut config = NodeConfig::default_for_network(Network::Regtest);
        config.notifications.zmq = vec![
            ZmqEndpointConfig {
                endpoint: "tcp://127.0.0.1:28332".to_owned(),
                topics: vec![ZmqTopic::HashBlock],
                hwm: None,
            },
            ZmqEndpointConfig {
                endpoint: "tcp://127.0.0.1:28332".to_owned(),
                topics: vec![ZmqTopic::RawBlock],
                hwm: Some(5_000),
            },
        ];
        assert!(config.validate().is_err());

        config.notifications.zmq.truncate(1);
        config.notifications.zmq[0].topics.push(ZmqTopic::HashBlock);
        assert!(config.validate().is_err());
    }

    #[test]
    fn resolved_zmq_hwm_is_validated() {
        let mut config = NodeConfig::default_for_network(Network::Regtest);
        config.notifications.zmq.push(ZmqEndpointConfig {
            endpoint: "tcp://127.0.0.1:28332".to_owned(),
            topics: vec![ZmqTopic::HashBlock],
            hwm: Some(2_147_483_648),
        });
        let error = match config.validate() {
            Ok(()) => panic!("out-of-range resolved ZMQ HWM must be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("ZMQ HWM exceeds libzmq"));

        config.notifications.zmq[0].hwm = Some(0);
        let Err(error) = config.validate() else {
            panic!("zero disables libzmq's outbound queue limit");
        };
        assert!(error.to_string().contains("ZMQ HWM must be positive"));

        for hwm in [Some(1), Some(2_147_483_647), None] {
            config.notifications.zmq[0].hwm = hwm;
            assert!(config.validate().is_ok(), "valid ZMQ HWM rejected: {hwm:?}");
        }
    }

    #[test]
    fn connect_hostnames_are_preserved_for_later_resolution() -> Result<()> {
        let layer = UserConfig {
            p2p: P2pOverrides {
                connect: Some(vec!["localhost:18444".to_owned()]),
                ..Default::default()
            },
            ..Default::default()
        };
        let config = resolve(&[&layer])?;
        assert_eq!(config.p2p.connect, vec!["localhost:18444"]);
        Ok(())
    }

    #[test]
    fn assume_valid_height_override_has_precedence() -> Result<()> {
        let low = UserConfig {
            validation: ValidationOverrides {
                assume_valid_height: Some(10_000),
                mode: None,
                engine: None,
            },
            ..Default::default()
        };
        let high = UserConfig {
            validation: ValidationOverrides {
                assume_valid_height: Some(30_000),
                mode: None,
                engine: None,
            },
            ..Default::default()
        };
        let config = resolve(&[&low, &high])?;
        assert_eq!(config.validation.assume_valid_height, 30_000);
        Ok(())
    }

    #[test]
    fn assume_valid_height_defaults_to_mainnet_anchor() -> Result<()> {
        let config = resolve(&[])?;
        assert_eq!(
            config.validation.assume_valid_height,
            Network::Mainnet
                .assume_valid_anchor()
                .map_or(0, |(height, _)| height)
        );
        Ok(())
    }

    #[test]
    fn mining_payout_address_decodes_after_all_layers() -> Result<()> {
        use bitcoin_rs_node::MiningOverrides;

        const ADDRESS: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
        let network = UserConfig {
            network: Some(NetworkSelection::Regtest),
            ..Default::default()
        };
        let payout = UserConfig {
            mining: MiningOverrides {
                payout_address: Some(ADDRESS.to_owned()),
                ..Default::default()
            },
            ..Default::default()
        };
        let config = resolve(&[&network, &payout])?;
        let expected = bitcoin::Address::from_str(ADDRESS)?
            .require_network(bitcoin::Network::Regtest)?
            .script_pubkey()
            .as_bytes()
            .to_vec();
        assert_eq!(config.mining.payout_script, expected);
        Ok(())
    }

    #[test]
    fn mining_payout_address_must_match_the_resolved_network() {
        use bitcoin_rs_node::MiningOverrides;

        let layer = UserConfig {
            network: Some(NetworkSelection::Regtest),
            mining: MiningOverrides {
                payout_address: Some("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_owned()),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(resolve(&[&layer]).is_err());
    }

    #[test]
    fn operator_noban_defaults_empty_and_uses_the_subnet_owner() -> Result<()> {
        assert_eq!(
            NodeConfig::default_for_network(Network::Regtest)
                .p2p
                .noban_subnets,
            Vec::<bitcoin_rs_p2p::IpSubnet>::new()
        );
        let layer: UserConfig = toml::from_str(
            r#"network = "regtest"
p2p_noban = ["192.0.2.99/24", "::1"]
"#,
        )?;
        let config = resolve(&[&layer])?;
        assert_eq!(config.p2p.noban_subnets[0].to_string(), "192.0.2.0/24");
        assert!(config.p2p.noban_subnets[0].contains("::ffff:192.0.2.1".parse()?));
        assert_eq!(config.p2p.noban_subnets[1].to_string(), "::1/128");
        assert!(toml::from_str::<UserConfig>(r#"p2p_noban = ["192.0.2.0/99"]"#).is_err());
        let mut environment = UserConfig::default();
        environment.apply_env(
            "BITCOIN_RS_P2P_NOBAN",
            std::ffi::OsStr::new("198.51.100.1, ::1"),
        )?;
        let config = resolve(&[&layer, &environment])?;
        assert_eq!(config.p2p.noban_subnets[0].to_string(), "198.51.100.1/32");
        assert_eq!(config.p2p.noban_subnets.len(), 2);
        environment.apply_env("BITCOIN_RS_P2P_NOBAN", std::ffi::OsStr::new(""))?;
        assert_eq!(
            resolve(&[&layer, &environment])?.p2p.noban_subnets,
            Vec::<bitcoin_rs_p2p::IpSubnet>::new()
        );
        assert!(
            environment
                .apply_env("BITCOIN_RS_P2P_NOBAN", std::ffi::OsStr::new("bad-subnet"))
                .is_err()
        );
        Ok(())
    }

    fn environment(key: &str, value: &str) -> Result<UserConfig> {
        let mut layer = UserConfig::default();
        layer.apply_env(key, std::ffi::OsStr::new(value))?;
        Ok(layer)
    }

    fn refusal(layers: &[&UserConfig]) -> String {
        match resolve(layers) {
            Ok(_) => panic!("configuration must be refused"),
            Err(error) => error.to_string(),
        }
    }

    #[test]
    fn relay_features_are_opt_in_per_flag_and_follow_layer_precedence() -> Result<()> {
        let off = resolve(&[])?.p2p.relay_offers;
        assert!(!off.package_relay && !off.stale_tip_relay && !off.stale_tip_prefers_blocks);

        let package: UserConfig = toml::from_str("p2p_package_relay = true")?;
        let offers = resolve(&[&package])?.p2p.relay_offers;
        assert!(
            offers.package_relay && !offers.stale_tip_relay && !offers.stale_tip_prefers_blocks
        );

        let stale: UserConfig = toml::from_str("p2p_stale_tip_relay = true")?;
        let offers = resolve(&[&stale])?.p2p.relay_offers;
        assert!(
            !offers.package_relay && offers.stale_tip_relay && !offers.stale_tip_prefers_blocks
        );

        let disabled = environment("BITCOIN_RS_P2P_PACKAGE_RELAY", "false")?;
        assert!(
            !resolve(&[&package, &disabled])?
                .p2p
                .relay_offers
                .package_relay
        );
        let enabled = environment("BITCOIN_RS_P2P_STALE_TIP_RELAY", "on")?;
        assert!(resolve(&[&enabled])?.p2p.relay_offers.stale_tip_relay);

        let regtest: UserConfig = toml::from_str("network = \"regtest\"")?;
        assert!(
            resolve(&[&regtest, &stale])?
                .p2p
                .relay_offers
                .stale_tip_relay
        );

        assert!(environment("BITCOIN_RS_P2P_PACKAGE_RELAY", "maybe").is_err());
        assert!(toml::from_str::<UserConfig>("p2p_stale_tip_relay = \"yes\"").is_err());
        Ok(())
    }

    #[test]
    fn stale_tip_prefers_blocks_needs_the_relay_it_modifies() -> Result<()> {
        let prefers = environment("BITCOIN_RS_P2P_STALE_TIP_PREFERS_BLOCKS", "true")?;
        assert!(refusal(&[&prefers]).contains("requires --p2p-stale-tip-relay"));

        let relay: UserConfig = toml::from_str("p2p_stale_tip_relay = true")?;
        let offers = resolve(&[&relay, &prefers])?.p2p.relay_offers;
        assert!(offers.stale_tip_relay && offers.stale_tip_prefers_blocks);

        let relay_off = environment("BITCOIN_RS_P2P_STALE_TIP_RELAY", "false")?;
        assert!(
            refusal(&[&relay, &prefers, &relay_off]).contains("requires --p2p-stale-tip-relay")
        );

        assert!(
            !resolve(&[&relay])?
                .p2p
                .relay_offers
                .stale_tip_prefers_blocks
        );
        Ok(())
    }

    #[test]
    fn index_bundle_is_an_explicit_one_shot_request() -> Result<()> {
        let indexes = resolve(&[])?.indexes;
        assert_eq!((indexes.bundle_import, indexes.bundle_export), (None, None));

        let txindex: UserConfig = toml::from_str("txindex = true")?;
        let import: UserConfig = toml::from_str("index_bundle_import = \"/srv/bundle\"")?;
        let indexes = resolve(&[&txindex, &import])?.indexes;
        assert_eq!(
            indexes.bundle_import.as_deref(),
            Some(std::path::Path::new("/srv/bundle"))
        );
        assert_eq!(indexes.bundle_export, None);

        let elsewhere = environment("BITCOIN_RS_INDEX_BUNDLE_IMPORT", "/nonexistent/elsewhere")?;
        let indexes = resolve(&[&txindex, &import, &elsewhere])?.indexes;
        assert_eq!(
            indexes.bundle_import.as_deref(),
            Some(std::path::Path::new("/nonexistent/elsewhere"))
        );

        let export = environment("BITCOIN_RS_INDEX_BUNDLE_EXPORT", "relative/out")?;
        let indexes = resolve(&[&txindex, &export])?.indexes;
        assert_eq!(indexes.bundle_import, None);
        assert_eq!(
            indexes.bundle_export.as_deref(),
            Some(std::path::Path::new("relative/out"))
        );
        Ok(())
    }

    #[test]
    fn index_bundle_import_and_export_never_resolve_by_precedence() -> Result<()> {
        let txindex: UserConfig = toml::from_str("txindex = true")?;
        let import: UserConfig = toml::from_str("index_bundle_import = \"/srv/in\"")?;
        let export = environment("BITCOIN_RS_INDEX_BUNDLE_EXPORT", "/srv/out")?;
        for layers in [[&txindex, &import, &export], [&txindex, &export, &import]] {
            assert!(refusal(&layers).contains("mutually exclusive"));
        }
        let both: UserConfig = toml::from_str(
            "index_bundle_import = \"/srv/in\"\nindex_bundle_export = \"/srv/out\"",
        )?;
        assert!(refusal(&[&txindex, &both]).contains("mutually exclusive"));
        Ok(())
    }

    #[test]
    fn index_bundle_requires_the_transaction_index_it_moves() -> Result<()> {
        let import: UserConfig = toml::from_str("index_bundle_import = \"/srv/in\"")?;
        assert!(refusal(&[&import]).contains("--index-bundle-import requires --txindex"));
        let export = environment("BITCOIN_RS_INDEX_BUNDLE_EXPORT", "/srv/out")?;
        assert!(refusal(&[&export]).contains("--index-bundle-export requires --txindex"));

        let txindex: UserConfig = toml::from_str("txindex = true")?;
        let no_txindex = environment("BITCOIN_RS_TXINDEX", "false")?;
        assert!(refusal(&[&txindex, &import, &no_txindex]).contains("requires --txindex"));
        Ok(())
    }

    #[test]
    fn index_bundle_rejects_empty_and_unusable_directories_on_every_surface() {
        for key in ["index_bundle_import", "index_bundle_export"] {
            for value in ["", "   ", "a\u{0}b"] {
                let text = format!("{key} = \"{value}\"");
                assert!(
                    toml::from_str::<UserConfig>(&text).is_err(),
                    "TOML accepted {text}"
                );
            }
        }
        for key in [
            "BITCOIN_RS_INDEX_BUNDLE_IMPORT",
            "BITCOIN_RS_INDEX_BUNDLE_EXPORT",
        ] {
            for value in ["", "\t", "a\0b"] {
                assert!(
                    environment(key, value).is_err(),
                    "environment accepted {key}={value:?}"
                );
            }
        }

        for unusable in ["", "   ", "\t\n", "foo\0bar"] {
            let mut config = NodeConfig::default_for_network(Network::Regtest);
            config.indexes.txindex = true;
            config.indexes.bundle_import = Some(std::path::PathBuf::from(unusable));
            let error = config.validate().err().map(|error| error.to_string());
            assert!(
                error.is_some_and(|error| {
                    error.contains("must not be empty") || error.contains("must not contain a NUL")
                }),
                "validate accepted {unusable:?}"
            );
        }
    }
}
mod embed {
    use bitcoin_rs_node::test_support::TestError;

    type Result<T, E = TestError> = core::result::Result<T, E>;
    use crate::support::{block_on, p2sh_true_output, p2sh_true_spend_script_sig};
    use bitcoin_rs_chain::chain::regtest_fixture::{self, REGTEST_BITS};
    use bitcoin_rs_consensus::primitives::{
        Amount, Block, BlockHash, CompactTarget, Hash256, LockTime, OutPoint, Sequence, Tx, TxIn,
        TxOut, Txid, Witness, consensus_bytes,
    };
    use bitcoin_rs_consensus::script::push_int;
    use bitcoin_rs_index::ScriptHash;
    use bitcoin_rs_index::query_api::{Answer, TxQueryError};
    use bitcoin_rs_mempool::MutationOutcome;
    use bitcoin_rs_node::ScriptIndexMode;
    use bitcoin_rs_node::state::NodeState;
    use bitcoin_rs_node::{Network, Node, NodeConfig, NodeError};

    const SEED_BLOCKS: u32 = 100;
    const SEED_BASE_TIME: u32 = 1_296_688_603;
    const SEED_BLOCK_INTERVAL: u32 = 600;
    const REGTEST_SUBSIDY_SATS: u64 = 50 * 100_000_000;
    const MEMPOOL_TX_FEE_SATS: u64 = 10_000;

    // EMB-06, EMB-07
    #[test]
    fn embedded_node_lifecycle_round_trip() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let data_dir = dir.path().join("node");

        let (seed_tip_hash, first_block_hash, first_block_bytes) = {
            let state = NodeState::open(seed_config(&data_dir), None)?;
            state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                Network::Regtest.genesis_block(),
            ))?;
            let outcome = seed_chain(&state, SEED_BLOCKS)?;
            let _ = state.publish_checkpoint()?;
            drop(state);
            outcome
        };

        let spawn_config = embedded_config(&data_dir)?;
        let reopen_config = spawn_config.clone();
        let node = block_on(Node::start(
            spawn_config,
            bitcoin_rs_node::RuntimeInputs::default(),
        ))?;

        assert_embedded_node_readiness(&node, seed_tip_hash, first_block_hash, &first_block_bytes)?;

        let before_import = node.snapshot();
        let summary = node.chainstates_summary()?;
        assert!(summary.active_chainstate.validated);
        assert!(summary.historical_chainstate.is_none());
        let invalid_snapshot = dir.path().join("invalid-snapshot.dat");
        std::fs::write(&invalid_snapshot, b"not a UTXO snapshot")?;
        assert!(matches!(
            block_on(node.import_manifest(&invalid_snapshot)),
            Err(NodeError::Snapshot(_))
        ));
        assert_eq!(node.snapshot(), before_import);

        assert_broadcast_and_lookups(&node)?;

        block_on(node.shutdown())?;

        let node = block_on(Node::start(
            reopen_config,
            bitcoin_rs_node::RuntimeInputs::default(),
        ))?;
        assert_eq!(
            node.snapshot().tip_height,
            SEED_BLOCKS,
            "reopen must resume the seeded chain"
        );
        assert_eq!(
            node.mempool_info().txs,
            1,
            "clean restart restores the admitted spend"
        );
        let spend = seed_coinbase_spend();
        assert_eq!(
            consensus_bytes(&block_on(node.tx_by_id(spend.txid()))?),
            consensus_bytes(&spend)
        );
        block_on(node.shutdown())?;
        Ok(())
    }

    #[test]
    fn clean_shutdown_and_reopen_preserve_rejected_fee_history() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let data_dir = dir.path().join("node");
        {
            let state = NodeState::open(seed_config(&data_dir), None)?;
            state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                Network::Regtest.genesis_block(),
            ))?;
            state.publish_checkpoint()?;
        }
        let history_path = data_dir.join("fee-estimator-history.dat");
        let rejected = [0xff; 128];
        std::fs::write(&history_path, rejected)?;

        let node = block_on(Node::start(
            embedded_config(&data_dir)?,
            bitcoin_rs_node::RuntimeInputs::default(),
        ))?;
        assert_eq!(node.fee_estimate(1), None);
        block_on(node.shutdown())?;
        assert_eq!(std::fs::read(&history_path)?, rejected);
        assert!(!data_dir.join("fee-estimator-history.dat.tmp").exists());
        Ok(())
    }

    fn assert_embedded_node_readiness(
        node: &Node,
        seed_tip_hash: Hash256,
        first_block_hash: Hash256,
        first_block_bytes: &[u8],
    ) -> Result<()> {
        let snapshot = node.snapshot();
        assert_eq!(snapshot.tip_height, SEED_BLOCKS, "seeded tip must be live");
        assert_eq!(snapshot.tip_hash, seed_tip_hash);
        assert!(snapshot.epoch >= 1, "the process epoch is allocated");
        assert_eq!(
            snapshot.sequence, 0,
            "no commit has happened in this run yet"
        );
        let progress = node.sync_progress();
        assert_eq!(progress.network, Network::Regtest);
        assert_eq!(progress.blocks, SEED_BLOCKS);
        assert_eq!(progress.headers, SEED_BLOCKS);
        assert_eq!(progress.best_block_hash, seed_tip_hash);
        assert!(
            progress.verification_progress > 0.0 && progress.verification_progress <= 1.0,
            "progress must be a fraction in (0, 1], got {}",
            progress.verification_progress
        );
        assert!(
            progress.initial_block_download,
            "a 2011-dated tip keeps the node in IBD"
        );
        assert!(
            !progress.pruned && progress.prune_height.is_none(),
            "default config does not prune"
        );

        let capabilities = node.capabilities();
        assert!(
            !capabilities.capabilities.is_empty(),
            "the registry reports its compiled capabilities"
        );
        assert!(
            capabilities
                .capabilities
                .iter()
                .all(|capability| capability.compiled),
            "compiled rows are reported regardless of the runtime toggle"
        );

        let first_block = block_on(node.block_by_hash(BlockHash::from(first_block_hash)))?
            .unwrap_or_else(|| panic!("seeded block must resolve"));
        assert_eq!(first_block.block_hash(), BlockHash::from(first_block_hash));
        assert_eq!(
            consensus_bytes(&first_block),
            first_block_bytes,
            "resolved bytes must round-trip"
        );
        let unknown_hash = Hash256::from_le_bytes(&[0x07; 32]);
        assert!(
            block_on(node.block_by_hash(BlockHash::from(unknown_hash)))?.is_none(),
            "an unknown hash is a clean None"
        );
        Ok(())
    }

    fn assert_broadcast_and_lookups(node: &Node) -> Result<()> {
        let spend = seed_coinbase_spend();
        let spend_txid = spend.txid();
        let mutation = block_on(node.broadcast(spend))?;
        assert_eq!(mutation.len(), 1, "one admission, one change");
        assert_eq!(
            mutation.changes[0].outcome,
            MutationOutcome::Accepted,
            "the funded spend must be accepted"
        );
        assert_eq!(
            mutation.sequence_of(0),
            Some(1),
            "first change of the run carries mempool sequence 1"
        );

        let read_back = block_on(node.tx_by_id(spend_txid))?;
        assert_eq!(read_back.txid(), spend_txid);
        assert_eq!(node.mempool_info().txs, 1, "the spend sits in the pool");

        assert_eq!(
            node.fee_estimate(6),
            None,
            "an estimator without history must refuse, not fabricate"
        );

        let unknown_txid = Txid(Hash256::from_le_bytes(&[0xAA; 32]));
        match block_on(node.tx_by_id(unknown_txid)) {
            Err(NodeError::Unavailable(message)) => {
                assert!(
                    message.contains("txindex"),
                    "the gate must name the missing capability: {message}"
                );
            }
            other => {
                return Err(TestError::message(format!(
                    "expected the TxLookup gate error, got {other:?}"
                )));
            }
        }
        Ok(())
    }

    fn seed_config(data_dir: &std::path::Path) -> NodeConfig {
        let mut config = NodeConfig::default_for_network(Network::Regtest);
        config.data_dir = data_dir.to_path_buf();
        config.p2p.listen.clear();
        config
    }

    fn embedded_config(data_dir: &std::path::Path) -> Result<NodeConfig> {
        let mut config = seed_config(data_dir);
        let rpc_bind: std::net::SocketAddr = "127.0.0.1:0".parse()?;
        config.rpc.bind = rpc_bind;
        Ok(config)
    }

    fn historical_config(data_dir: &std::path::Path) -> Result<NodeConfig> {
        let mut config = seed_config(data_dir);
        config.indexes.txindex = true;
        config.indexes.script_index = ScriptIndexMode::Full;
        let rpc_bind: std::net::SocketAddr = "127.0.0.1:0".parse()?;
        config.rpc.bind = rpc_bind;
        Ok(config)
    }

    fn wait_historical_transaction(node: &Node, txid: &Txid) -> Result<Answer<Option<(u32, Tx)>>> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            match node.transaction_at_prefix(txid) {
                Ok(answer) => return Ok(answer),
                Err(
                    TxQueryError::Retry(_)
                    | TxQueryError::Unavailable(_)
                    | TxQueryError::ExpiredView,
                ) => {}
                Err(TxQueryError::Storage(message)) => {
                    return Err(TestError::message(format!(
                        "historical index storage error while waiting: {message}"
                    )));
                }
            }
            if std::time::Instant::now() >= deadline {
                return Err(TestError::message(
                    "historical index did not become ready in 60s",
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    // IDX-12
    #[test]
    fn embedded_node_historical_prefix_queries() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let data_dir = dir.path().join("node");

        {
            let state = NodeState::open(seed_config(&data_dir), None)?;
            state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                Network::Regtest.genesis_block(),
            ))?;
            let _ = seed_chain(&state, SEED_BLOCKS)?;
            let _ = state.publish_checkpoint()?;
        }

        let node = block_on(Node::start(
            historical_config(&data_dir)?,
            bitcoin_rs_node::RuntimeInputs::default(),
        ))?;

        let known_tx = seed_coinbase(1);
        let known_txid = known_tx.txid();
        let known_outpoint = OutPoint::new(known_txid, 0);
        let script = ScriptHash::from_script_bytes(known_tx.outputs[0].script_pubkey.as_bytes());

        let ready = wait_historical_transaction(&node, &known_txid)?;
        assert_eq!(ready.coverage.floor, 0, "seeded chain covers from genesis");
        assert_eq!(ready.coverage.height, SEED_BLOCKS);
        assert_eq!(ready.coverage.hash, node.snapshot().tip_hash);

        let at = node.transaction_at_prefix(&known_txid)?;
        assert_eq!(at.coverage.floor, 0);
        assert_eq!(at.coverage.height, SEED_BLOCKS);
        assert_eq!(at.coverage.hash, node.snapshot().tip_hash);
        let Some((height, tx)) = at.value else {
            return Err(TestError::message(
                "known seed coinbase must resolve historically",
            ));
        };
        assert_eq!(height, 1);
        assert!(at.coverage.floor <= height && height <= at.coverage.height);
        assert_eq!(consensus_bytes(&tx), consensus_bytes(&known_tx));

        let unknown_txid = Txid(Hash256::from_le_bytes(&[0xAA; 32]));
        let absent = node.transaction_at_prefix(&unknown_txid)?;
        assert!(absent.value.is_none(), "unknown txid is a scoped None");
        assert_eq!(absent.coverage.height, SEED_BLOCKS);
        assert_eq!(absent.coverage.hash, node.snapshot().tip_hash);

        let history = node.script_history_at_prefix(script)?;
        assert_eq!(history.coverage.floor, 0);
        assert_eq!(history.coverage.height, SEED_BLOCKS);
        assert_eq!(history.coverage.hash, node.snapshot().tip_hash);
        assert!(
            history
                .value
                .history
                .iter()
                .any(|record| record.height == 1),
            "history must contain the height-1 funding"
        );
        assert!(
            history
                .value
                .history
                .iter()
                .all(|record| history.coverage.floor <= record.height
                    && record.height <= history.coverage.height),
            "history rows stay inside the covered prefix"
        );

        let spend = node.spender_at_prefix(known_outpoint)?;
        assert_eq!(spend.coverage.height, SEED_BLOCKS);
        assert_eq!(spend.coverage.hash, node.snapshot().tip_hash);
        assert!(
            spend.value.is_none(),
            "unspent seed outpoint has no spend in range"
        );
        let via_index = block_on(node.tx_by_id(known_txid))?;
        assert_eq!(consensus_bytes(&via_index), consensus_bytes(&known_tx));

        block_on(node.shutdown())?;
        Ok(())
    }

    fn seed_chain(state: &NodeState, count: u32) -> Result<(Hash256, Hash256, Vec<u8>)> {
        let applied = state.chainstate().applied_tip_reader();
        let mut tip = applied
            .load_full()
            .ok_or_else(|| TestError::message("genesis must publish an applied tip"))?;
        let mut first_block: Option<(Hash256, Vec<u8>)> = None;
        for height in 1..=count {
            let coinbase = seed_coinbase(height);
            let mut block = Block {
                header: bitcoin_rs_consensus::primitives::Header {
                    version: 0x2000_0000,
                    prev_blockhash: BlockHash::from(tip.hash),
                    merkle_root: Hash256::from_le_bytes(&[0_u8; 32]),
                    time: SEED_BASE_TIME.saturating_add(SEED_BLOCK_INTERVAL.saturating_mul(height)),
                    bits: CompactTarget::from_consensus(REGTEST_BITS),
                    nonce: 0,
                },
                txs: vec![coinbase],
            };
            block.header.merkle_root = regtest_fixture::merkle_root(&block.txs)
                .ok_or_else(|| TestError::message("seed block must have a merkle root"))?;
            regtest_fixture::mine_block_to_declared_target(&mut block)?;
            state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                block.clone(),
            ))?;
            tip = applied
                .load_full()
                .ok_or_else(|| TestError::message("applied tip must exist after apply"))?;
            assert_eq!(tip.height, height, "seed block must become the tip");
            if height == 1 {
                first_block = Some((Hash256::from(block.block_hash()), consensus_bytes(&block)));
            }
        }
        let (first_hash, first_bytes) =
            first_block.ok_or_else(|| TestError::message("at least one block must be seeded"))?;
        Ok((tip.hash, first_hash, first_bytes))
    }

    fn seed_coinbase(height: u32) -> Tx {
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: [push_int(i64::from(height)), push_int(0)].concat().into(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(REGTEST_SUBSIDY_SATS),
                script_pubkey: p2sh_true_output(),
            }],
            lock_time: LockTime::ZERO,
        }
    }

    fn seed_coinbase_spend() -> Tx {
        let seed_coinbase = seed_coinbase(1);
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(seed_coinbase.txid(), 0),
                script_sig: p2sh_true_spend_script_sig(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(REGTEST_SUBSIDY_SATS - MEMPOOL_TX_FEE_SATS),
                script_pubkey: [vec![0x00, 0x14], vec![0x11; 20]].concat().into(),
            }],
            lock_time: LockTime::ZERO,
        }
    }

    // EMB-07
    #[test]
    fn dropped_node_releases_services_and_datadir_for_reopen() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let data_dir = dir.path().join("node");

        let (_seed_tip_hash, _first, _bytes) = {
            let state = NodeState::open(seed_config(&data_dir), None)?;
            state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                Network::Regtest.genesis_block(),
            ))?;
            let outcome = seed_chain(&state, 1)?;
            let _ = state.publish_checkpoint()?;
            drop(state);
            outcome
        };
        let current_path = data_dir.join("chainstate-checkpoints").join("CURRENT");
        let seeded_current = std::fs::read(&current_path)?;

        {
            let node = block_on(Node::start(
                embedded_config(&data_dir)?,
                bitcoin_rs_node::RuntimeInputs::default(),
            ))?;
            assert_eq!(node.snapshot().tip_height, 1);
        }
        assert_eq!(
            std::fs::read(&current_path)?,
            seeded_current,
            "a dropped node must not publish a clean-shutdown checkpoint"
        );

        let resumed = NodeState::open(seed_config(&data_dir), None)?;
        let tip = resumed
            .chainstate()
            .applied_tip_snapshot()
            .unwrap_or_else(|| panic!("seeded checkpoint must restore an applied tip"));
        assert_eq!(tip.height, 1);
        drop(resumed);

        Ok(())
    }

    #[test]
    fn startup_failure_after_state_open_rolls_back_releases_state() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let held_dir = dir.path().join("held");
        let failed_dir = dir.path().join("failed");

        let probe = std::net::TcpListener::bind("127.0.0.1:0")?;
        let port = probe.local_addr()?;
        drop(probe);

        let mut held_config = embedded_config(&held_dir)?;
        held_config.rpc.bind = port;
        let held = block_on(Node::start(
            held_config,
            bitcoin_rs_node::RuntimeInputs::default(),
        ))?;

        let mut failed_config = embedded_config(&failed_dir)?;
        failed_config.rpc.bind = port;
        match block_on(Node::start(
            failed_config,
            bitcoin_rs_node::RuntimeInputs::default(),
        )) {
            Err(NodeError::Startup(message)) => {
                let lowered = message.to_lowercase();
                assert!(
                    lowered.contains("address")
                        || lowered.contains("bind")
                        || lowered.contains("10048")
                        || lowered.contains("주소"),
                    "the failure should name the bind conflict, got: {message}"
                );
            }
            other => {
                return Err(TestError::message(format!(
                    "expected a startup failure on the held port, got {:?}",
                    other.err()
                )));
            }
        }

        let resumed = NodeState::open(seed_config(&failed_dir), None)?;
        drop(resumed);

        block_on(held.shutdown())?;
        Ok(())
    }
}
mod lease_registration_215 {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use arc_swap::ArcSwapOption;
    use bitcoin_rs_chain::Chainstate;
    use bitcoin_rs_chain::chain::BlockTree;
    use bitcoin_rs_node::{BlockSync, Network};
    use bitcoin_rs_p2p::{PeerInfo, PeerLease, PeerTable, QueuedFrame};
    use bitcoin_rs_storage::utxo::UtxoSet;
    use bitcoin_rs_storage::utxo::stats::{CoinStats, CoinStatsListener};
    use crossbeam_channel::unbounded;
    use parking_lot::RwLock;

    fn make_sync(peer_table: Arc<PeerTable>) -> BlockSync {
        let block_tree = Arc::new(RwLock::new(BlockTree::new()));
        let chain_tip = block_tree.write().tip_handle();
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let (_headers_tx, headers_rx) = unbounded();
        let (_blocks_tx, blocks_rx) = unbounded();
        let coin_stats = Arc::new(CoinStatsListener::new(CoinStats::default()));
        let mut utxo = UtxoSet::new();
        utxo.track_coin_stats((*coin_stats).clone());
        let handles = Chainstate::new(
            Network::Regtest,
            chain_tip,
            applied_tip,
            block_tree,
            Arc::new(utxo),
            coin_stats,
            Arc::new(bitcoin_rs_chain::events::ChainEventPublisher::detached(0)),
        );
        let ibd = handles.ibd_latch();
        bitcoin_rs_node::sync::block_sync(bitcoin_rs_node::sync::BlockSyncInputs {
            handles: Arc::new(handles),
            followers: bitcoin_rs_node::ChainFollowers::noop(),
            peer_table,
            inbound_headers_rx: headers_rx,
            inbound_blocks_rx: blocks_rx,
            ibd,
            assumeutxo: None,
            budget: Arc::new(
                bitcoin_rs_node::budget::NodeBudget::from_chainstate_cache_budget(
                    bitcoin_rs_storage::split_chainstate_cache_budget(16),
                    1,
                ),
            ),
        })
    }

    fn info(addr: SocketAddr) -> PeerInfo {
        PeerInfo {
            wtxid_relay: false,
            relay_transactions: true,
            compact_block_relay: false,
            endpoint: Some(bitcoin_rs_p2p::PeerEndpoint::Ip(addr)),
            network: bitcoin_rs_p2p::PeerEndpoint::Ip(addr).net(),
            addr: addr.into(),
            send_headers: false,
            version: 70_016,
            services: 1,
            user_agent: String::from("/test/"),
            start_height: 0,
            best_known_height: 0,
            conn_time: 0,
            addr_bind: bitcoin_rs_p2p::TransportRemote::new(addr),
            time_offset: 0,
            counters: Arc::new(bitcoin_rs_p2p::PeerCounters::default()),
            inbound: true,
            transport: bitcoin_rs_p2p::TransportProtocol::V1,
        }
    }

    #[test]
    fn peer_table_owns_handshake_publication_and_replacement() {
        let table = Arc::new(PeerTable::new());
        let addr = SocketAddr::from(([127, 0, 0, 1], 18_447));
        let (old_tx, _old_rx) = unbounded::<QueuedFrame>();
        let old = PeerLease::new(old_tx);
        assert!(!table.register(bitcoin_rs_p2p::PeerEndpoint::Ip(addr), old.clone()));
        assert!(table.publish_info(bitcoin_rs_p2p::PeerEndpoint::Ip(addr), &old, info(addr)));
        assert!(!old.is_cancelled());
        assert_eq!(table.len(), 1);
        assert_eq!(table.infos().len(), 1);

        let (new_tx, _new_rx) = unbounded::<QueuedFrame>();
        let new = PeerLease::new(new_tx);
        assert!(table.register(bitcoin_rs_p2p::PeerEndpoint::Ip(addr), new.clone()));
        assert!(old.is_cancelled());
        assert!(!new.is_cancelled());
        assert!(table.is_current(new.source_ip(addr)));

        let sync = make_sync(Arc::clone(&table));
        sync.tick();
        assert_eq!(table.live_sessions().len(), 1);
    }
}
mod mining {

    mod support {
        use std::fmt::Write as _;
        use std::sync::Arc;
        use std::thread::{self, JoinHandle};
        use std::time::{Duration, Instant};

        use bitcoin_rs_node::test_support::TestError;

        type Result<T, E = TestError> = core::result::Result<T, E>;
        use bitcoin::hex::FromHex;
        use bitcoin_rs_chain::chain::regtest_fixture::{self, REGTEST_BITS};
        use bitcoin_rs_consensus::primitives::{
            Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, OutPoint, Script,
            Sequence, Tx, TxIn, TxOut, Txid, Witness, deserialize as native_deserialize,
            encode::double_sha256,
        };
        use bitcoin_rs_consensus::script::push_int;
        use bitcoin_rs_mempool::{AdmissionOrigin, BodyInterest, MempoolEntry, SubmitOutcome};
        use bitcoin_rs_node::{MiningCoordinator, Network, NodeConfig, state::NodeState};
        use bitcoin_rs_wire::mining::{
            BlockTemplate, BlockTemplateMode, BlockTemplateRequest, BlockTemplateResult,
            BlockValidationResult, CoinbaseBudget, MempoolSequenceWake, MiningControl,
            MiningGenerationSignal, solve_block,
        };
        use bitcoin_rs_wire::{
            Handler,
            context::{
                ChainAdmissionView, ChainHandles, Context, ContextHandles, IndexHandles,
                MempoolHandles, MiningHandles, NetworkHandles,
            },
        };
        use compact_str::CompactString;
        use crossbeam_channel::{Receiver, bounded};
        use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, json};

        pub(crate) const SEED_BLOCKS: u32 = 100;
        pub(crate) const SEED_BASE_TIME: u32 = 1_296_688_603;
        pub(crate) const SEED_BLOCK_INTERVAL: u32 = 600;
        pub(crate) const REGTEST_SUBSIDY_SATS: u64 = 50 * 100_000_000;
        pub(crate) const MEMPOOL_TX_FEE_SATS: u64 = 10_000;
        pub(crate) const WITNESS_RESERVED: [u8; 32] = [0_u8; 32];
        pub(crate) const WITNESS_COMMITMENT_PREFIX: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];

        pub(crate) struct NodeFixture {
            pub(crate) state: NodeState,
            _dir: tempfile::TempDir,
        }

        impl std::ops::Deref for NodeFixture {
            type Target = NodeState;

            fn deref(&self) -> &Self::Target {
                &self.state
            }
        }

        pub(crate) fn open_network(network: Network) -> Result<NodeFixture> {
            let dir = tempfile::tempdir()?;
            let mut config = NodeConfig::default_for_network(network);
            config.data_dir = dir.path().join("node");
            config.p2p.listen.clear();
            let state = NodeState::open(config, None)?;
            Ok(NodeFixture { state, _dir: dir })
        }

        pub(crate) fn open_at_genesis(network: Network) -> Result<NodeFixture> {
            let fixture = open_network(network)?;
            let _ = fixture.state.apply_block(
                &bitcoin_rs_consensus::primitives::BlockImage::from_local(network.genesis_block()),
            )?;
            Ok(fixture)
        }

        pub(crate) fn regtest_mining() -> Result<(NodeFixture, MiningCoordinator)> {
            let fixture = open_at_genesis(Network::Regtest)?;
            let mining = coordinator(&fixture.state);
            Ok((fixture, mining))
        }

        pub(crate) fn coordinator(state: &NodeState) -> MiningCoordinator {
            MiningCoordinator::new(
                state.mempool_reader(),
                state.chainstate(),
                state.block_memory(),
                state.stable_read(),
                state.chain_followers(),
                state.config().mining.payout_script.clone(),
                state.config().mining.coinbase_reserve,
            )
        }

        pub(crate) fn advance_mempool_sequence(state: &NodeState) -> Result<()> {
            let mempool = state.mempool();
            let mut guard = mempool.write();
            guard
                .insert_entry(MempoolEntry::new(
                    Arc::new(mempool_sequence_tx()),
                    100,
                    10_000,
                    1,
                    7,
                    0,
                ))
                .map_err(|error| TestError::message(format!("seed insert failed: {error}")))?;
            guard.clear();
            Ok(())
        }

        pub(crate) fn template_request(
            long_poll_id: Option<CompactString>,
        ) -> BlockTemplateRequest {
            BlockTemplateRequest {
                mode: BlockTemplateMode::Template,
                capabilities: Vec::new(),
                rules: Vec::new(),
                long_poll_id,
                coinbase_budget: None,
            }
        }

        pub(crate) fn budgeted_template_request(budget: CoinbaseBudget) -> BlockTemplateRequest {
            BlockTemplateRequest {
                coinbase_budget: Some(budget),
                ..template_request(None)
            }
        }

        pub(crate) fn expect_template(result: BlockTemplateResult) -> BlockTemplate {
            match result {
                BlockTemplateResult::Template(template) => template,
                other @ BlockTemplateResult::Proposal(_) => {
                    panic!("expected template, got {other:?}")
                }
            }
        }

        pub(crate) fn to_lower_hex(bytes: &[u8]) -> String {
            let mut out = String::with_capacity(bytes.len() * 2);
            for byte in bytes {
                let _ = write!(out, "{byte:02x}");
            }
            out
        }

        pub(crate) fn is_witness_commitment(script_pubkey: &[u8]) -> bool {
            script_pubkey.len() >= 38 && script_pubkey.starts_with(&WITNESS_COMMITMENT_PREFIX)
        }

        pub(crate) fn solved_template_block(mining: &MiningCoordinator) -> Result<Block> {
            let template = expect_template(mining.get_block_template(template_request(None))?);
            let mut block = template.candidate.into_unsolved_block()?;
            solve_block(&mut block, 1_000_000)?;
            Ok(block)
        }

        pub(crate) fn mined_child(prev: BlockHash) -> Result<Block> {
            mined_child_labeled(prev, 1)
        }

        pub(crate) fn mined_child_labeled(prev: BlockHash, label: i64) -> Result<Block> {
            let script_opcode = u8::try_from(label + 0x50)?;
            let coinbase = Tx {
                version: 2,
                lock_time: LockTime::ZERO,
                inputs: vec![TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: Script::from_bytes(vec![script_opcode, 0x51]),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(50 * 100_000_000),
                    script_pubkey: Script::from_bytes(vec![0x51]),
                }],
            };
            let mut block = Block {
                header: Header {
                    version: 0x2000_0000,
                    prev_blockhash: prev,
                    merkle_root: Hash256::default(),
                    time: 1_296_688_603 + 600,
                    bits: CompactTarget::from_consensus(regtest_fixture::REGTEST_BITS),
                    nonce: 0,
                },
                txs: vec![coinbase],
            };
            block.header.merkle_root = block.txs[0].txid().into();
            regtest_fixture::mine_block_to_declared_target(&mut block)?;
            Ok(block)
        }

        pub(crate) fn mined_regtest_header(prev: BlockHash, time: u32, version: i32) -> Header {
            let mut header = Header {
                version,
                prev_blockhash: prev,
                merkle_root: Hash256::default(),
                time,
                bits: CompactTarget::from_consensus(regtest_fixture::REGTEST_BITS),
                nonce: 0,
            };
            regtest_fixture::mine_header_to_declared_target(&mut header)
                .unwrap_or_else(|error| panic!("regtest fixture header: {error}"));
            header
        }

        pub(crate) fn excess_coinbase_child(prev: BlockHash) -> Result<Block> {
            let mut block = mined_child(prev)?;
            let Some(output) = block.txs.first_mut().and_then(|tx| tx.outputs.first_mut()) else {
                panic!("coinbase has no output");
            };
            output.value = output.value.saturating_add(Amount::from_sat(1));
            block.header.merkle_root = regtest_fixture::merkle_root(&block.txs)
                .ok_or_else(|| TestError::message("test block has no merkle root"))?;
            regtest_fixture::mine_block_to_declared_target(&mut block)?;
            Ok(block)
        }

        pub(crate) fn mempool_sequence_tx() -> Tx {
            Tx {
                version: 2,
                lock_time: LockTime::ZERO,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[0x42; 32])), 0),
                    script_sig: Script::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(1_000),
                    script_pubkey: Script::from_bytes(vec![0x51]),
                }],
            }
        }

        pub(crate) fn propose_block(
            mining: &MiningCoordinator,
            block: Block,
        ) -> Result<BlockValidationResult> {
            match mining.get_block_template(BlockTemplateRequest {
                mode: BlockTemplateMode::Proposal(block),
                capabilities: Vec::new(),
                rules: Vec::new(),
                long_poll_id: None,
                coinbase_budget: None,
            })? {
                BlockTemplateResult::Proposal(result) => Ok(result),
                other @ BlockTemplateResult::Template(_) => {
                    panic!("expected a proposal result, got {other:?}")
                }
            }
        }

        pub(crate) fn disconnect_applied(state: &NodeState, block: &Block) -> Result<()> {
            let genesis = Network::Regtest.genesis_block();
            let target = state
                .chainstate()
                .block_tree_reader()
                .read()
                .lookup(Hash256::from(genesis.block_hash()))
                .ok_or_else(|| TestError::message("missing genesis node"))?;
            let block_hash = Hash256::from(block.block_hash());
            let body = block.clone();
            bitcoin_rs_node::reorg::switch_to_branch(
                &state.chainstate(),
                &state.chain_followers(),
                target,
                |hash| {
                    (hash == block_hash).then(|| {
                        bitcoin_rs_consensus::primitives::BlockImage::from_local(body.clone())
                    })
                },
                |_| {},
            )
            .map_err(|error| TestError::message(error.to_string()))
        }

        pub(crate) fn open_regtest() -> Result<(NodeState, tempfile::TempDir)> {
            let dir = tempfile::tempdir()?;
            let mut config = NodeConfig::default_for_network(Network::Regtest);
            config.data_dir = dir.path().join("node");
            config.p2p.listen.clear();
            let state = NodeState::open(config, None)?;
            Ok((state, dir))
        }

        pub(crate) fn apply_genesis(state: &NodeState) -> Result<()> {
            let genesis = Network::Regtest.genesis_block();
            state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                genesis,
            ))?;
            Ok(())
        }

        pub(crate) fn seed_chain(state: &NodeState, count: u32) -> Result<Hash256> {
            let mut tip = current_tip(state)?;
            for height in 1..=count {
                let coinbase = Tx {
                    version: 2,
                    inputs: vec![TxIn {
                        previous_output: OutPoint::null(),
                        script_sig: Script::from_bytes(
                            [push_int(i64::from(height)), push_int(0)].concat(),
                        ),
                        sequence: Sequence::MAX,
                        witness: Witness::new(),
                    }],
                    outputs: vec![TxOut {
                        value: Amount::from_sat(REGTEST_SUBSIDY_SATS),
                        script_pubkey: p2sh_true_output(),
                    }],
                    lock_time: LockTime::ZERO,
                };
                let mut block = Block {
                    header: Header {
                        version: 0x2000_0000,
                        prev_blockhash: BlockHash::from(tip.hash),
                        merkle_root: Hash256::from_le_bytes(&[0_u8; 32]),
                        time: SEED_BASE_TIME
                            .saturating_add(SEED_BLOCK_INTERVAL.saturating_mul(height)),
                        bits: CompactTarget::from_consensus(REGTEST_BITS),
                        nonce: 0,
                    },
                    txs: vec![coinbase],
                };
                block.header.merkle_root = regtest_fixture::merkle_root(&block.txs)
                    .ok_or_else(|| TestError::message("seed block must have a merkle root"))?;
                regtest_fixture::mine_block_to_declared_target(&mut block)?;
                state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                    block,
                ))?;
                tip = current_tip(state)?;
                assert_eq!(tip.height, height, "seed block must become the tip");
            }
            Ok(tip.hash)
        }

        pub(crate) fn current_tip(
            state: &NodeState,
        ) -> Result<bitcoin_rs_chain::chain::TipSnapshot> {
            let Some(tip) = state.chainstate().applied_tip_snapshot() else {
                return Err(TestError::message("applied tip must exist"));
            };
            Ok((*tip).clone())
        }

        pub(crate) fn assemble_from_template(
            template: &sonic_rs::Value,
            template_txs: &[sonic_rs::Value],
        ) -> Result<Block> {
            let prev_hex = required_str(template, "previousblockhash")?;
            let height = required_u64(template, "height")?;
            let coinbase_value = required_u64(template, "coinbasevalue")?;
            let bits = u32::from_str_radix(&required_str(template, "bits")?, 16)?;
            let curtime = u32::try_from(required_u64(template, "curtime")?).unwrap_or(u32::MAX);
            let version = i32::try_from(required_u64(template, "version")?).unwrap_or(0);
            let commitment_script =
                Vec::<u8>::from_hex(&required_str(template, "default_witness_commitment")?)?;
            assert!(
                commitment_script.starts_with(&[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]),
                "default_witness_commitment must be the BIP141 commitment script"
            );

            let mut txs = Vec::with_capacity(template_txs.len());
            for entry in template_txs {
                let data = entry
                    .get("data")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| TestError::message("template transaction missing data hex"))?;
                txs.push(native_deserialize::<Tx>(&Vec::<u8>::from_hex(data)?)?);
            }

            assemble_block(
                prev_hex.as_str(),
                u32::try_from(height).unwrap_or(u32::MAX),
                version,
                bits,
                curtime,
                coinbase_value,
                commitment_script,
                txs,
            )
        }

        pub(crate) fn seed_coinbase_spend() -> Tx {
            seed_coinbase_spend_with_fee(MEMPOOL_TX_FEE_SATS)
        }

        pub(crate) fn seed_coinbase_spend_with_fee(fee_sats: u64) -> Tx {
            seed_coinbase_spend_at(1, fee_sats)
        }

        pub(crate) fn seed_coinbase_spend_at(height: u32, fee_sats: u64) -> Tx {
            let seed_coinbase = Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: Script::from_bytes(
                        [push_int(i64::from(height)), push_int(0)].concat(),
                    ),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(REGTEST_SUBSIDY_SATS),
                    script_pubkey: p2sh_true_output(),
                }],
                lock_time: LockTime::ZERO,
            };
            Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(seed_coinbase.txid(), 0),
                    script_sig: p2sh_true_spend_script_sig(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(REGTEST_SUBSIDY_SATS - fee_sats),
                    script_pubkey: p2sh_true_output(),
                }],
                lock_time: LockTime::ZERO,
            }
        }

        pub(crate) use crate::support::{p2sh_true_output, p2sh_true_spend_script_sig};

        pub(crate) fn assemble_regtest_block(
            prev: Hash256,
            height: u32,
            txs: Vec<Tx>,
        ) -> Result<Block> {
            let coinbase = Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: Script::from_bytes(
                        [push_int(i64::from(height)), push_int(0)].concat(),
                    ),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(REGTEST_SUBSIDY_SATS),
                    script_pubkey: Script::from_bytes(vec![0x51]),
                }],
                lock_time: LockTime::ZERO,
            };
            let mut block = Block {
                header: Header {
                    version: 0x2000_0000,
                    prev_blockhash: BlockHash::from(prev),
                    merkle_root: Hash256::from_le_bytes(&[0_u8; 32]),
                    time: SEED_BASE_TIME.saturating_add(SEED_BLOCK_INTERVAL.saturating_mul(height)),
                    bits: CompactTarget::from_consensus(REGTEST_BITS),
                    nonce: 0,
                },
                txs: std::iter::once(coinbase).chain(txs).collect(),
            };
            block.header.merkle_root = regtest_fixture::merkle_root(&block.txs)
                .ok_or_else(|| TestError::message("regtest block must have a merkle root"))?;
            regtest_fixture::mine_block_to_declared_target(&mut block)?;
            Ok(block)
        }

        pub(crate) fn admit_to_mempool(state: &NodeState, tx: &Tx) -> Result<()> {
            let utxo = state.chainstate().utxo_reader();
            let applied_tip = state.chainstate().applied_tip_reader();
            let block_tree = state.chainstate().block_tree_reader();
            let view = ChainAdmissionView::new(utxo, applied_tip, block_tree, Network::Regtest);
            let outcome = state.mempool_gateway().submit_transaction(
                Arc::new(tx.clone()),
                AdmissionOrigin::Rpc,
                None,
                bitcoin_rs_consensus::primitives::unix_time_secs(),
                &view,
            );
            assert!(
                matches!(outcome, Ok(SubmitOutcome::Committed(_))),
                "gateway admission must commit the spend, got: {outcome:?}"
            );
            Ok(())
        }

        pub(crate) fn mine_regtest_block(
            state: &NodeState,
            prev: Hash256,
            height: u32,
            txs: Vec<Tx>,
        ) -> Result<Block> {
            let coinbase = Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: Script::from_bytes(
                        [push_int(i64::from(height)), push_int(0)].concat(),
                    ),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(REGTEST_SUBSIDY_SATS),
                    script_pubkey: Script::from_bytes(vec![0x51]),
                }],
                lock_time: LockTime::ZERO,
            };
            let mut block = Block {
                header: Header {
                    version: 0x2000_0000,
                    prev_blockhash: BlockHash::from(prev),
                    merkle_root: Hash256::from_le_bytes(&[0_u8; 32]),
                    time: SEED_BASE_TIME.saturating_add(SEED_BLOCK_INTERVAL.saturating_mul(height)),
                    bits: CompactTarget::from_consensus(REGTEST_BITS),
                    nonce: 0,
                },
                txs: std::iter::once(coinbase).chain(txs).collect(),
            };
            block.header.merkle_root = regtest_fixture::merkle_root(&block.txs)
                .ok_or_else(|| TestError::message("mined block must have a merkle root"))?;
            regtest_fixture::mine_block_to_declared_target(&mut block)?;
            state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                block.clone(),
            ))?;
            Ok(block)
        }

        pub(crate) fn mining_handler(state: &NodeState) -> Handler {
            rpc_handler(state, Arc::new(coordinator(state)))
        }

        pub(crate) fn rpc_handler(
            state: &NodeState,
            mining_control: Arc<dyn MiningControl>,
        ) -> Handler {
            let ctx = Context::from_handles(ContextHandles {
                chain: ChainHandles {
                    chain_tip: state.chainstate().header_tip_reader(),
                    applied_tip: state.chainstate().applied_tip_reader(),
                    active_tip_wait: Some(state.chainstate()),
                    progress: state.chainstate().chain_progress_reader(),
                    blocks: state.block_log_reader(),
                    utxo: bitcoin_rs_storage::utxo::UtxoReader::fixture_new(),
                    coin_stats: state.chainstate().coin_stats_handle(),
                    block_tree: state.chainstate().block_tree_reader(),
                    chain_network: state.config().network,
                    chain_transition: state.stable_read(),
                    closed_for_recovery: state.chainstate().closed_for_recovery_reader(),
                    ..ChainHandles::default()
                },
                mempool: MempoolHandles {
                    gateway: state.mempool_gateway(),
                },
                indexes: IndexHandles::default(),
                network: NetworkHandles {
                    overlay: bitcoin_rs_p2p::overlay::OverlayConfig::default(),
                    peer_table: state.peer_table(),
                    p2p: state.p2p(),
                    local_services: state.p2p().local_services().to_u64(),
                    user_agent: state.p2p().user_agent().to_owned(),
                    v2_transport: state.config().p2p.v2_transport,
                },
                mining: MiningHandles {
                    mining_control: Some(mining_control),
                },
                ..ContextHandles::default()
            })
            .with_chain_transition(state.stable_read());
            Handler::new(Arc::new(ctx))
        }

        pub(crate) fn assemble_block(
            prev_hex: &str,
            height: u32,
            version: i32,
            bits: u32,
            curtime: u32,
            coinbase_value: u64,
            commitment_script: Vec<u8>,
            txs: Vec<Tx>,
        ) -> Result<Block> {
            let coinbase = Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: Script::from_bytes(push_int(i64::from(height))),
                    sequence: Sequence::MAX,
                    witness: Witness::from_stack(vec![WITNESS_RESERVED.to_vec()]),
                }],
                outputs: vec![
                    TxOut {
                        value: Amount::from_sat(coinbase_value),
                        script_pubkey: Script::from_bytes(vec![0x51]),
                    },
                    TxOut {
                        value: Amount::from_sat(0),
                        script_pubkey: Script::from_bytes(commitment_script),
                    },
                ],
                lock_time: LockTime::ZERO,
            };

            let mut block_txs = Vec::with_capacity(txs.len() + 1);
            block_txs.push(coinbase);
            block_txs.extend(txs);

            let mut block = Block {
                header: Header {
                    version,
                    prev_blockhash: prev_hex.parse::<BlockHash>().map_err(|err| {
                        TestError::message(format!("invalid previousblockhash: {err}"))
                    })?,
                    merkle_root: Hash256::from_le_bytes(&[0_u8; 32]),
                    time: curtime,
                    bits: CompactTarget::from_consensus(bits),
                    nonce: 0,
                },
                txs: block_txs,
            };
            block.header.merkle_root = regtest_fixture::merkle_root(&block.txs)
                .ok_or_else(|| TestError::message("block must have a merkle root"))?;
            regtest_fixture::mine_block_to_declared_target(&mut block)?;
            Ok(block)
        }

        pub(crate) fn required_str(value: &sonic_rs::Value, key: &str) -> Result<String> {
            let text = value
                .get(key)
                .and_then(|text| text.as_str())
                .ok_or_else(|| {
                    TestError::message(format!("template field {key} missing or not a string"))
                })?;
            Ok(text.to_owned())
        }

        pub(crate) fn required_u64(value: &sonic_rs::Value, key: &str) -> Result<u64> {
            value
                .get(key)
                .and_then(sonic_rs::JsonValueTrait::as_i64)
                .and_then(|number| u64::try_from(number).ok())
                .ok_or_else(|| {
                    TestError::message(format!("template field {key} missing or not a number"))
                })
        }

        pub(crate) fn compute_witness_merkle_root(txs: &[Tx]) -> Option<Hash256> {
            if txs.is_empty() {
                return None;
            }
            let mut level: Vec<[u8; 32]> = Vec::with_capacity(txs.len().saturating_add(1));
            level.push([0_u8; 32]);
            for tx in txs {
                level.push(*tx.wtxid().as_bytes());
            }
            while level.len() > 1 {
                let mut next = Vec::with_capacity(level.len().div_ceil(2));
                for pos in 0..level.len().div_ceil(2) {
                    let left = level[2 * pos];
                    let right = level[(2 * pos + 1).min(level.len() - 1)];
                    let mut pair = [0_u8; 64];
                    pair[..32].copy_from_slice(&left);
                    pair[32..].copy_from_slice(&right);
                    next.push(*double_sha256(&pair).as_byte_array());
                }
                level = next;
            }
            Some(Hash256::from_le_bytes(&level[0]))
        }

        pub(crate) const PRIORITY_SEED_BLOCKS: u32 = SEED_BLOCKS + 2;
        pub(crate) const LOW_FEE_SATS: u64 = 10_000;
        pub(crate) const HIGH_FEE_SATS: u64 = 20_000;
        pub(crate) const LATE_FEE_SATS: u64 = 15_000;
        pub(crate) const PRIORITY_DELTA_SATS: i64 = 50_000;
        pub(crate) const PROMPT: Duration = Duration::from_secs(5);
        const PARK_DEADLINE: Duration = Duration::from_secs(10);

        #[derive(Clone, Debug, Eq, PartialEq)]
        pub(crate) struct LongPollId {
            pub(crate) tip: String,
            pub(crate) mempool_sequence: u64,
            pub(crate) fee_delta_sequence: u64,
        }

        impl LongPollId {
            pub(crate) fn parse(id: &str) -> Result<Self> {
                let (tip, counters) = id.split_at_checked(64).ok_or_else(|| {
                    TestError::message(format!("longpollid {id:?} is shorter than a tip hash"))
                })?;
                if !tip.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return Err(TestError::message(format!(
                        "longpollid {id:?} does not start with a hex tip hash"
                    )));
                }
                let (mempool, fee_delta_sequence) = match counters.split_once(':') {
                    Some((mempool, fee)) => (mempool.parse()?, fee.parse()?),
                    None => (counters.parse()?, 0),
                };
                Ok(Self {
                    tip: tip.to_owned(),
                    mempool_sequence: mempool,
                    fee_delta_sequence,
                })
            }
        }

        pub(crate) fn live_long_poll_id(state: &NodeState) -> Result<String> {
            let tip = current_tip(state)?;
            let mempool = state.mempool();
            let pool = mempool.read();
            let mut id = format!("{}{}", tip.hash.to_string_be(), pool.sequence_number());
            let fee = pool.fee_delta_sequence_number();
            if fee != 0 {
                id.push(':');
                id.push_str(&fee.to_string());
            }
            Ok(id)
        }

        #[derive(Clone, Debug, Eq, PartialEq)]
        pub(crate) struct TemplateView {
            pub(crate) long_poll_id: String,
            pub(crate) txids: Vec<String>,
            pub(crate) fees: Vec<u64>,
            pub(crate) coinbase_value: u64,
        }

        impl TemplateView {
            pub(crate) fn id(&self) -> Result<LongPollId> {
                LongPollId::parse(&self.long_poll_id)
            }
        }

        pub(crate) fn template_view(template: &sonic_rs::Value) -> Result<TemplateView> {
            let entries = template
                .get("transactions")
                .and_then(|value| value.as_array())
                .ok_or_else(|| TestError::message("template has no transactions array"))?
                .as_slice();
            let mut txids = Vec::with_capacity(entries.len());
            let mut fees = Vec::with_capacity(entries.len());
            for entry in entries {
                txids.push(required_str(entry, "txid")?);
                fees.push(required_u64(entry, "fee")?);
            }
            Ok(TemplateView {
                long_poll_id: required_str(template, "longpollid")?,
                txids,
                fees,
                coinbase_value: required_u64(template, "coinbasevalue")?,
            })
        }

        pub(crate) fn gbt_view(
            handler: &Handler,
            long_poll_id: Option<&str>,
        ) -> Result<TemplateView> {
            let params = if let Some(id) = long_poll_id {
                json!([{"rules": ["segwit"], "longpollid": id}])
            } else {
                json!([{"rules": ["segwit"]}])
            };
            template_view(&handler.dispatch("getblocktemplate", &params)?)
        }

        pub(crate) struct PendingPoll<T> {
            done: Receiver<T>,
            thread: Option<JoinHandle<()>>,
            release: Box<dyn Fn() + Send>,
        }

        impl<T> PendingPoll<T> {
            pub(crate) fn spawn(
                release: impl Fn() + Send + 'static,
                call: impl FnOnce() -> T + Send + 'static,
            ) -> Self
            where
                T: Send + 'static,
            {
                let (done_tx, done) = bounded(1);
                let thread = thread::spawn(move || {
                    let _ = done_tx.send(call());
                });
                Self {
                    done,
                    thread: Some(thread),
                    release: Box::new(release),
                }
            }

            pub(crate) fn is_finished(&self) -> bool {
                self.thread.as_ref().is_none_or(JoinHandle::is_finished)
            }

            pub(crate) fn collect(mut self, within: Duration) -> Result<T> {
                let value = self.done.recv_timeout(within).map_err(|error| {
                    TestError::message(format!(
                        "the call did not return within {within:?}: {error}"
                    ))
                })?;
                if let Some(thread) = self.thread.take() {
                    thread
                        .join()
                        .map_err(|_| TestError::message("the call's thread panicked"))?;
                }
                Ok(value)
            }
        }

        impl<T> Drop for PendingPoll<T> {
            fn drop(&mut self) {
                let Some(thread) = self.thread.take() else {
                    return;
                };
                (self.release)();
                let _ = thread.join();
            }
        }

        pub(crate) fn await_parked<T>(
            mining: &MiningCoordinator,
            poll: &PendingPoll<T>,
        ) -> Result<()> {
            let deadline = Instant::now() + PARK_DEADLINE;
            loop {
                if mining.parked_long_poll_waiters() >= 1 {
                    return Ok(());
                }
                if poll.is_finished() {
                    return Err(TestError::message(
                        "the long poll returned without ever waiting",
                    ));
                }
                if Instant::now() >= deadline {
                    return Err(TestError::message(format!(
                        "the long poll did not register as a waiter within {PARK_DEADLINE:?}"
                    )));
                }
                thread::sleep(Duration::from_millis(1));
            }
        }

        pub(crate) struct WiredMining {
            pub(crate) mining: Arc<MiningCoordinator>,
            pub(crate) handler: Arc<Handler>,
        }

        pub(crate) fn wire_mining(state: &NodeState) -> Result<WiredMining> {
            let mining = Arc::new(coordinator(state));
            let signal = Arc::new(MiningGenerationSignal::new());
            let control: Arc<dyn MiningControl> = mining.clone();
            let wake: Arc<dyn MempoolSequenceWake> = mining.clone();
            signal.attach(&control);
            signal.attach_sequence_wake(&wake);
            state
                .mempool_gateway()
                .attach_observer_leg("mining-test", signal, BodyInterest::Metadata)
                .map_err(TestError::message)?;
            let handler = Arc::new(rpc_handler(state, control));
            Ok(WiredMining { mining, handler })
        }

        pub(crate) fn txid_strings(txs: &[&Tx]) -> Vec<String> {
            txs.iter().map(|tx| tx.txid().to_string()).collect()
        }

        pub(crate) type Poll = PendingPoll<Result<TemplateView>>;

        pub(crate) struct PriorityFixture {
            pub(crate) wired: WiredMining,
            pub(crate) state: NodeState,
            _dir: tempfile::TempDir,
            pub(crate) low: Tx,
            pub(crate) high: Tx,
        }

        pub(crate) fn priority_fixture() -> Result<PriorityFixture> {
            let (state, dir) = open_regtest()?;
            apply_genesis(&state)?;
            seed_chain(&state, PRIORITY_SEED_BLOCKS)?;
            let wired = wire_mining(&state)?;
            let low = seed_coinbase_spend_at(1, LOW_FEE_SATS);
            let high = seed_coinbase_spend_at(2, HIGH_FEE_SATS);
            admit_to_mempool(&state, &low)?;
            admit_to_mempool(&state, &high)?;
            Ok(PriorityFixture {
                wired,
                state,
                _dir: dir,
                low,
                high,
            })
        }

        impl PriorityFixture {
            pub(crate) fn mining(&self) -> &MiningCoordinator {
                &self.wired.mining
            }

            pub(crate) fn template(&self) -> Result<TemplateView> {
                gbt_view(&self.wired.handler, None)
            }

            pub(crate) fn prioritise(&self, tx: &Tx, delta: i64) -> Result<()> {
                let accepted = self.wired.handler.dispatch(
                    "prioritisetransaction",
                    &json!([tx.txid().to_string(), 0, delta]),
                )?;
                if accepted.as_bool() != Some(true) {
                    return Err(TestError::message(format!(
                        "prioritisetransaction answered {accepted}"
                    )));
                }
                Ok(())
            }

            pub(crate) fn admit_late(&self) -> Result<Tx> {
                let late = seed_coinbase_spend_at(3, LATE_FEE_SATS);
                admit_to_mempool(&self.state, &late)?;
                Ok(late)
            }

            pub(crate) fn park_long_poll(&self) -> Result<(TemplateView, Poll)> {
                let current = self.template()?;
                let poll = self.poll(&current.long_poll_id);
                await_parked(self.mining(), &poll)?;
                if poll.is_finished() {
                    return Err(TestError::message(
                        "the long poll returned before anything was published",
                    ));
                }
                Ok((current, poll))
            }

            pub(crate) fn poll(&self, id: &str) -> Poll {
                let handler = Arc::clone(&self.wired.handler);
                let id = id.to_owned();
                let chainstate = self.state.chainstate();
                PendingPoll::spawn(
                    move || chainstate.request_shutdown(),
                    move || gbt_view(&handler, Some(&id)),
                )
            }
        }
    }

    mod coordination {
        use std::str::FromStr as _;
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        use std::thread;
        use std::time::Duration;

        use bitcoin_rs_node::test_support::TestError;

        type Result<T, E = TestError> = core::result::Result<T, E>;
        use bitcoin_rs_consensus::primitives::{Hash256, Tx};
        use bitcoin_rs_node::{
            MiningCoordinator, MiningOverrides, Network, NetworkSelection, UserConfig, resolve,
            state::NodeState,
        };
        use bitcoin_rs_wire::mining::{
            BlockTemplate, MempoolSequenceWake, MiningControl, MiningControlError,
        };
        use compact_str::CompactString;
        use crossbeam_channel::bounded;
        use parking_lot::Mutex;

        use super::preparation_barrier::{
            BarrierNode, barrier_bound, fresh_tip_child, open_barrier_node, seed_fresh_chain,
        };
        use super::support::{
            HIGH_FEE_SATS, LATE_FEE_SATS, LOW_FEE_SATS, PRIORITY_DELTA_SATS, PRIORITY_SEED_BLOCKS,
            PROMPT, PendingPoll, REGTEST_SUBSIDY_SATS, admit_to_mempool, advance_mempool_sequence,
            coordinator, current_tip, expect_template, live_long_poll_id, mined_child,
            open_at_genesis, priority_fixture, regtest_mining, rpc_handler, seed_coinbase_spend_at,
            template_request, to_lower_hex, txid_strings,
        };
        use sonic_rs::{JsonValueTrait as _, json};

        #[test]
        fn cache_reuses_candidate_for_identical_generation_key() -> Result<()> {
            let (_state, mining) = regtest_mining()?;
            mining.publish_generation();

            let first = expect_template(mining.get_block_template(template_request(None))?);
            let second = expect_template(mining.get_block_template(template_request(None))?);
            assert_eq!(
                first.candidate.template_id.as_str(),
                second.candidate.template_id.as_str()
            );
            assert!(
                Arc::ptr_eq(&first.candidate, &second.candidate),
                "identical generation must reuse the cached candidate arc"
            );
            Ok(())
        }

        #[test]
        fn watch_only_payout_lands_in_candidate_coinbase() -> Result<()> {
            const ADDRESS: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
            let dir = tempfile::tempdir()?;
            let layer = UserConfig {
                network: Some(NetworkSelection::Regtest),
                mining: MiningOverrides {
                    payout_address: Some(ADDRESS.to_owned()),
                    ..Default::default()
                },
                ..Default::default()
            };
            let mut config = resolve(&[&layer])?;
            config.data_dir = dir.path().join("node");
            config.p2p.listen.clear();
            std::mem::forget(dir);
            let state = NodeState::open(config, None)?;
            let _ =
                state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                    Network::Regtest.genesis_block(),
                ))?;
            let mining = coordinator(&state);
            mining.publish_generation();
            let template = expect_template(mining.get_block_template(template_request(None))?);
            let expected = bitcoin::Address::from_str(ADDRESS)?
                .require_network(bitcoin::Network::Regtest)?
                .script_pubkey()
                .as_bytes()
                .to_vec();
            assert_eq!(
                template.candidate.coinbase.outputs[0].script_pubkey, expected,
                "configured watch-only payout must be the candidate coinbase script"
            );
            Ok(())
        }

        #[test]
        fn network_hash_ps_answers_on_the_applied_tip() -> Result<()> {
            let (_state, mining) = regtest_mining()?;
            let genesis_rate = mining.network_hash_ps(120, -1)?;
            assert!(
                genesis_rate.abs() < f64::EPSILON,
                "genesis has no lookback window, got {genesis_rate}"
            );
            let genesis_height_rate = mining.network_hash_ps(120, 0)?;
            assert!(
                genesis_height_rate.abs() < f64::EPSILON,
                "Core reports 0 at the genesis height, got {genesis_height_rate}"
            );
            Ok(())
        }

        #[test]
        fn network_hash_ps_rejects_core_invalid_windows() -> Result<()> {
            let (_state, mining) = regtest_mining()?;
            match mining.network_hash_ps(0, -1) {
                Err(MiningControlError::InvalidRequest(message)) => {
                    assert_eq!(
                        message.as_str(),
                        "Invalid nblocks. Must be a positive number or -1."
                    );
                }
                other => panic!("nblocks 0 must be invalid, got {other:?}"),
            }
            match mining.network_hash_ps(-2, -1) {
                Err(MiningControlError::InvalidRequest(message)) => {
                    assert_eq!(
                        message.as_str(),
                        "Invalid nblocks. Must be a positive number or -1."
                    );
                }
                other => panic!("nblocks -2 must be invalid, got {other:?}"),
            }
            match mining.network_hash_ps(120, -10) {
                Err(MiningControlError::InvalidRequest(message)) => {
                    assert_eq!(message.as_str(), "Block does not exist at specified height");
                }
                other => panic!("height -10 must be invalid, got {other:?}"),
            }
            match mining.network_hash_ps(120, 1) {
                Err(MiningControlError::InvalidRequest(message)) => {
                    assert_eq!(message.as_str(), "Block does not exist at specified height");
                }
                other => panic!("height above the tip must be invalid, got {other:?}"),
            }
            Ok(())
        }

        #[test]
        fn key_invalidation_rebuilds_after_mempool_sequence_change() -> Result<()> {
            let (state, mining) = regtest_mining()?;
            mining.publish_generation();
            let first = expect_template(mining.get_block_template(template_request(None))?);

            advance_mempool_sequence(&state)?;
            mining.publish_generation();
            let second = expect_template(mining.get_block_template(template_request(None))?);
            assert_ne!(
                first.candidate.template_id.as_str(),
                second.candidate.template_id.as_str(),
                "mempool sequence change must invalidate the generation key"
            );
            assert!(!Arc::ptr_eq(&first.candidate, &second.candidate));
            Ok(())
        }

        #[test]
        fn concurrent_requests_share_single_flight_assembly() -> Result<()> {
            let (_state, mining) = regtest_mining()?;
            let mining = Arc::new(mining);
            mining.publish_generation();

            let barrier = Arc::new(std::sync::Barrier::new(8));
            let candidates = Arc::new(Mutex::new(Vec::new()));
            let mut handles = Vec::new();
            for _ in 0..8 {
                let mining = Arc::clone(&mining);
                let barrier = Arc::clone(&barrier);
                let candidates = Arc::clone(&candidates);
                handles.push(thread::spawn(move || {
                    barrier.wait();
                    let template = expect_template(
                        mining
                            .get_block_template(template_request(None))
                            .unwrap_or_else(|error| panic!("template failed: {error}")),
                    );
                    candidates.lock().push(Arc::clone(&template.candidate));
                }));
            }
            for handle in handles {
                handle.join().unwrap_or_else(|_| panic!("worker panicked"));
            }
            let candidates = candidates.lock();
            let first = &candidates[0];
            assert!(
                candidates
                    .iter()
                    .all(|candidate| Arc::ptr_eq(candidate, first)),
                "all concurrent waiters must observe the same single-flight candidate"
            );
            Ok(())
        }

        #[test]
        fn long_poll_wakes_on_tip_change() -> Result<()> {
            let (state, mining) = regtest_mining()?;
            let mining = Arc::new(mining);
            mining.publish_generation();
            let current = expect_template(mining.get_block_template(template_request(None))?);
            let long_poll_id = CompactString::from(current.candidate.template_id.as_str());
            let (started_tx, started_rx) = bounded::<()>(1);
            let mining_wait = Arc::clone(&mining);
            let waiter = thread::spawn(move || {
                started_tx
                    .send(())
                    .unwrap_or_else(|error| panic!("start signal failed: {error}"));
                mining_wait.get_block_template(template_request(Some(long_poll_id)))
            });
            started_rx.recv_timeout(Duration::from_secs(2))?;
            thread::sleep(Duration::from_millis(50));
            let genesis = Network::Regtest.genesis_block();
            let child = mined_child(genesis.block_hash())?;
            let _ = state.apply_block(
                &bitcoin_rs_consensus::primitives::BlockImage::from_local(child.clone()),
            )?;
            mining.publish_generation();
            let result = waiter
                .join()
                .unwrap_or_else(|_| panic!("long-poll waiter panicked"))
                .unwrap_or_else(|error| panic!("long poll failed: {error}"));
            let template = expect_template(result);
            assert_ne!(
                template.candidate.template_id.as_str(),
                current.candidate.template_id.as_str()
            );
            let child_hash = Hash256::from_le_bytes(child.block_hash().as_bytes());
            assert_eq!(template.candidate.previous_block_hash, child_hash);
            assert_eq!(template.submit_old, Some(false));
            assert_eq!(
                template.rules.iter().any(|rule| rule.as_str() == "csv"),
                template.candidate.csv_active
            );
            assert_eq!(
                template.rules.iter().any(|rule| rule.as_str() == "segwit"),
                template.candidate.segwit_active
            );
            Ok(())
        }

        #[test]
        fn long_poll_wakes_on_mempool_sequence_change() -> Result<()> {
            let (state, mining) = regtest_mining()?;
            let mining = Arc::new(mining);
            mining.publish_generation();
            let current = expect_template(mining.get_block_template(template_request(None))?);
            let long_poll_id = CompactString::from(current.candidate.template_id.as_str());
            let (started_tx, started_rx) = bounded::<()>(1);
            let mining_wait = Arc::clone(&mining);
            let waiter = thread::spawn(move || {
                started_tx
                    .send(())
                    .unwrap_or_else(|error| panic!("start signal failed: {error}"));
                mining_wait.get_block_template(template_request(Some(long_poll_id)))
            });
            started_rx.recv_timeout(Duration::from_secs(2))?;
            thread::sleep(Duration::from_millis(50));
            advance_mempool_sequence(&state)?;
            mining.publish_generation();
            let result = waiter
                .join()
                .unwrap_or_else(|_| panic!("mempool long-poll waiter panicked"))
                .unwrap_or_else(|error| panic!("mempool long poll failed: {error}"));
            let template = expect_template(result);
            assert_ne!(
                template.candidate.mempool_sequence,
                current.candidate.mempool_sequence
            );
            assert_eq!(
                template.candidate.previous_block_hash,
                current.candidate.previous_block_hash
            );
            assert_eq!(template.submit_old, Some(true));
            Ok(())
        }

        #[test]
        fn shutdown_ends_long_poll_without_wake() -> Result<()> {
            let state = open_at_genesis(Network::Regtest)?;
            let mining = Arc::new(MiningCoordinator::new(
                state.mempool_reader(),
                state.chainstate(),
                state.block_memory(),
                state.stable_read(),
                state.chain_followers(),
                state.config().mining.payout_script.clone(),
                state.config().mining.coinbase_reserve,
            ));
            mining.publish_generation();
            let current = expect_template(mining.get_block_template(template_request(None))?);
            let long_poll_id = CompactString::from(current.candidate.template_id.as_str());
            let mining_wait = Arc::clone(&mining);
            let waiter = thread::spawn(move || {
                mining_wait.get_block_template(template_request(Some(long_poll_id)))
            });
            thread::sleep(Duration::from_millis(50));
            state.chainstate().request_shutdown();
            let outcome = waiter
                .join()
                .unwrap_or_else(|_| panic!("shutdown waiter panicked"));
            let Err(err) = outcome else {
                panic!("shutdown wait unexpectedly succeeded");
            };
            assert!(matches!(err, MiningControlError::Unavailable(_)));
            Ok(())
        }

        #[test]
        fn mining_info_reports_default_signet_challenge() -> Result<()> {
            let state = open_at_genesis(Network::Signet)?;
            let mining = coordinator(&state);
            let info = mining.mining_info()?;
            let Some(signet) = info.signet.as_ref() else {
                panic!("default Signet did not expose challenge metadata");
            };
            assert_eq!(
                to_lower_hex(&signet.challenge),
                concat!(
                    "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430",
                    "210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae",
                )
            );
            Ok(())
        }

        #[test]
        fn mining_info_omits_signet_on_regtest() -> Result<()> {
            let (_state, mining) = regtest_mining()?;
            let info = mining.mining_info()?;
            assert!(info.signet.is_none());
            Ok(())
        }

        #[test]
        fn mining_info_reports_network_hashps_after_genesis() -> Result<()> {
            let (_state, mining) = regtest_mining()?;
            let info = mining.mining_info()?;
            assert_eq!(info.blocks, 0);
            assert!(
                info.network_hashes_per_second.is_finite(),
                "hashps must be a finite projection"
            );
            Ok(())
        }

        #[test]
        fn last_candidate_counts_include_the_coinbase() -> Result<()> {
            use super::support::{SEED_BLOCKS, seed_chain, seed_coinbase_spend};

            let (state, mining) = regtest_mining()?;
            seed_chain(&state, SEED_BLOCKS)?;
            mining.publish_generation();
            let empty = expect_template(mining.get_block_template(template_request(None))?);
            let empty_info = mining.mining_info()?;
            assert!(empty.candidate.transactions.is_empty());
            assert_eq!(
                empty_info.last_candidate.map(|info| info.transactions),
                Some(1)
            );

            admit_to_mempool(&state, &seed_coinbase_spend())?;
            mining.publish_generation();
            let one = expect_template(mining.get_block_template(template_request(None))?);
            let one_info = mining.mining_info()?;
            assert_eq!(one.candidate.transactions.len(), 1);
            assert_eq!(
                one_info.last_candidate.map(|info| info.transactions),
                Some(2)
            );
            Ok(())
        }

        #[test]
        fn concurrent_publish_generation_paths_do_not_deadlock() -> Result<()> {
            let (_state, mining) = regtest_mining()?;
            let mining = Arc::new(mining);

            let stop = Arc::new(AtomicBool::new(false));

            let (tip_done_tx, tip_done_rx) = bounded::<()>(1);
            let mining_tip = Arc::clone(&mining);
            let stop_tip = Arc::clone(&stop);
            let tip_thread = thread::spawn(move || {
                while !stop_tip.load(Ordering::Relaxed) {
                    mining_tip.publish_generation();
                }
                let _ = tip_done_tx.send(());
            });

            let (seq_done_tx, seq_done_rx) = bounded::<()>(1);
            let mining_seq = Arc::clone(&mining);
            let stop_seq = Arc::clone(&stop);
            let seq_thread = thread::spawn(move || {
                let mut seq = 1_u64;
                while !stop_seq.load(Ordering::Relaxed) {
                    mining_seq.publish_generation_from(seq);
                    seq = seq.wrapping_add(1);
                }
                let _ = seq_done_tx.send(());
            });

            thread::sleep(Duration::from_millis(200));
            stop.store(true, Ordering::Relaxed);

            tip_done_rx
                .recv_timeout(Duration::from_millis(500))
                .map_err(|_| TestError::message("tip publish_generation thread deadlocked"))?;
            seq_done_rx
                .recv_timeout(Duration::from_millis(500))
                .map_err(|_| {
                    TestError::message("sequence publish_generation_from thread deadlocked")
                })?;

            tip_thread
                .join()
                .unwrap_or_else(|_| panic!("tip publish_generation thread panicked"));
            seq_thread
                .join()
                .unwrap_or_else(|_| panic!("sequence publish_generation_from thread panicked"));
            Ok(())
        }

        #[test]
        fn publish_generation_from_does_not_take_mempool_lock() -> Result<()> {
            let (state, mining) = regtest_mining()?;

            let mempool = state.mempool();
            let _write_guard = mempool.write();

            let (done_tx, done_rx) = bounded::<()>(1);
            let handle = thread::spawn(move || {
                mining.publish_generation_from(1);
                let _ = done_tx.send(());
            });

            done_rx
                .recv_timeout(Duration::from_millis(200))
                .map_err(|_| {
                    TestError::message(
                        "publish_generation_from deadlocked under the mempool write lock \
                 - it must not take the mempool read lock",
                    )
                })?;
            handle
                .join()
                .unwrap_or_else(|_| panic!("publish_generation_from thread panicked"));
            Ok(())
        }

        #[test]
        fn long_poll_returns_quickly_on_mempool_sequence_wake() -> Result<()> {
            let state = open_at_genesis(Network::Regtest)?;

            let mining = Arc::new(MiningCoordinator::new(
                state.mempool_reader(),
                state.chainstate(),
                state.block_memory(),
                state.stable_read(),
                state.chain_followers(),
                state.config().mining.payout_script.clone(),
                state.config().mining.coinbase_reserve,
            ));
            mining.publish_generation();
            let current = expect_template(mining.get_block_template(template_request(None))?);
            let long_poll_id = CompactString::from(current.candidate.template_id.as_str());

            let (started_tx, started_rx) = bounded::<()>(1);
            let (done_tx, done_rx) = bounded(1);
            let mining_wait = Arc::clone(&mining);
            let waiter = thread::spawn(move || {
                started_tx
                    .send(())
                    .unwrap_or_else(|error| panic!("start signal failed: {error}"));
                let result = mining_wait.get_block_template(template_request(Some(long_poll_id)));
                let _ = done_tx.send(result);
            });

            started_rx.recv_timeout(Duration::from_secs(2))?;
            thread::sleep(Duration::from_millis(50));

            advance_mempool_sequence(&state)?;
            let seq = state.mempool().read().sequence_number();
            let wake_start = std::time::Instant::now();
            mining.publish_generation_from(seq);

            let result = done_rx
                .recv_timeout(Duration::from_secs(2))
                .map_err(|error| {
                    TestError::message(format!(
                        "mempool long-poll waiter did not complete: {error}"
                    ))
                })?;
            let elapsed = wake_start.elapsed();
            waiter
                .join()
                .unwrap_or_else(|_| panic!("mempool long-poll waiter panicked"));
            let result = result.unwrap_or_else(|error| panic!("mempool long poll failed: {error}"));

            assert!(
                elapsed < Duration::from_millis(800),
                "long-poll waiter returned in {elapsed:?}, expected well under 1 s"
            );
            let template = expect_template(result);
            assert_ne!(
                template.candidate.mempool_sequence,
                current.candidate.mempool_sequence
            );
            assert_eq!(
                template.candidate.previous_block_hash,
                current.candidate.previous_block_hash
            );
            assert_eq!(template.submit_old, Some(true));
            Ok(())
        }

        #[test]
        fn network_hash_ps_matches_mining_info_default_window() -> Result<()> {
            let (_state, mining) = regtest_mining()?;
            let info = mining.mining_info()?;
            let rate = mining.network_hash_ps(120, -1)?;
            assert!(
                (rate - info.network_hashes_per_second).abs() < f64::EPSILON,
                "default-window hash rate must match mining info: {rate} vs {}",
                info.network_hashes_per_second
            );
            Ok(())
        }

        #[test]
        fn priority_change_replaces_the_cached_candidate_for_an_unchanged_pool() -> Result<()> {
            let fx = priority_fixture()?;
            let first = expect_template(fx.mining().get_block_template(template_request(None))?);
            let again = expect_template(fx.mining().get_block_template(template_request(None))?);
            assert!(
                Arc::ptr_eq(&first.candidate, &again.candidate),
                "precondition: an unchanged generation is served from the cache"
            );
            let ranked = |template: &bitcoin_rs_wire::mining::BlockTemplate| {
                template
                    .candidate
                    .transactions
                    .iter()
                    .map(|tx| (tx.txid.to_string(), tx.fee))
                    .collect::<Vec<_>>()
            };
            let high = || (fx.high.txid().to_string(), HIGH_FEE_SATS);
            let low = || (fx.low.txid().to_string(), LOW_FEE_SATS);
            assert_eq!(ranked(&first), vec![high(), low()]);

            fx.prioritise(&fx.low, PRIORITY_DELTA_SATS)?;

            let after = expect_template(fx.mining().get_block_template(template_request(None))?);
            assert!(
                !Arc::ptr_eq(&first.candidate, &after.candidate),
                "a priority change must not be answered from the stale cached candidate"
            );
            assert_ne!(
                first.candidate.template_id.as_str(),
                after.candidate.template_id.as_str(),
                "the generation identity must change with the fee-priority sequence"
            );
            assert_eq!(
                after.candidate.mempool_sequence, first.candidate.mempool_sequence,
                "prioritisation does not change pool membership"
            );
            assert_eq!(
                after.candidate.previous_block_hash,
                first.candidate.previous_block_hash
            );
            assert_eq!(
                ranked(&after),
                vec![low(), high()],
                "the prioritised transaction ranks first; actual fees are unchanged"
            );
            assert_eq!(
                after.candidate.template_id.as_str(),
                live_long_poll_id(&fx.state)?,
                "the candidate identity is the live generation's longpollid"
            );
            Ok(())
        }

        #[test]
        fn priority_change_returns_a_pending_long_poll_with_the_reordered_template() -> Result<()> {
            let fx = priority_fixture()?;
            let (before, poll) = fx.park_long_poll()?;
            assert_eq!(
                before.txids,
                txid_strings(&[&fx.high, &fx.low]),
                "precondition: high ranks over low"
            );

            fx.prioritise(&fx.low, PRIORITY_DELTA_SATS)?;

            let after = poll.collect(PROMPT)??;
            assert_eq!(
                after.txids,
                txid_strings(&[&fx.low, &fx.high]),
                "the pending poll must return the reordered template, not the stale one"
            );
            assert_eq!(after.fees, [LOW_FEE_SATS, HIGH_FEE_SATS]);
            assert_eq!(
                after.coinbase_value, before.coinbase_value,
                "prioritisation never changes the fees the coinbase claims"
            );
            let (waited, answered) = (before.id()?, after.id()?);
            assert_eq!(answered.tip, waited.tip);
            assert_eq!(answered.mempool_sequence, waited.mempool_sequence);
            assert_ne!(
                answered.fee_delta_sequence, waited.fee_delta_sequence,
                "the fee-priority component must advance"
            );
            assert_eq!(after.long_poll_id, live_long_poll_id(&fx.state)?);
            Ok(())
        }

        #[test]
        fn admission_after_a_priority_change_returns_a_pending_long_poll_and_keeps_the_fee_component()
        -> Result<()> {
            let fx = priority_fixture()?;
            let initial = fx.template()?.id()?;
            fx.prioritise(&fx.low, PRIORITY_DELTA_SATS)?;
            let (prioritised, poll) = fx.park_long_poll()?;
            let prioritised_id = prioritised.id()?;
            assert_ne!(
                prioritised_id.fee_delta_sequence, initial.fee_delta_sequence,
                "precondition: the priority change moved the fee component"
            );

            let late = fx.admit_late()?;

            let after = poll.collect(PROMPT)??;
            assert_eq!(
                after.txids,
                txid_strings(&[&fx.low, &fx.high, &late]),
                "the admission joins the template; the priority ordering survives it"
            );
            assert_eq!(after.fees, [LOW_FEE_SATS, HIGH_FEE_SATS, LATE_FEE_SATS]);
            assert_eq!(
                after.coinbase_value,
                REGTEST_SUBSIDY_SATS + LOW_FEE_SATS + HIGH_FEE_SATS + LATE_FEE_SATS
            );
            let answered = after.id()?;
            assert_eq!(answered.tip, prioritised_id.tip);
            assert_ne!(
                answered.mempool_sequence, prioritised_id.mempool_sequence,
                "an admission moves the membership sequence"
            );
            assert_eq!(
                answered.fee_delta_sequence, prioritised_id.fee_delta_sequence,
                "an ordinary admission must carry the priority component forward"
            );
            assert_eq!(after.long_poll_id, live_long_poll_id(&fx.state)?);
            Ok(())
        }

        #[test]
        fn long_poll_on_the_pre_priority_id_returns_the_new_generation_without_waiting()
        -> Result<()> {
            let fx = priority_fixture()?;
            let before = fx.template()?;
            fx.prioritise(&fx.low, PRIORITY_DELTA_SATS)?;

            let after = fx.poll(&before.long_poll_id).collect(PROMPT)??;

            assert_ne!(after.long_poll_id, before.long_poll_id);
            assert_eq!(
                after.txids,
                txid_strings(&[&fx.low, &fx.high]),
                "the stale id must be answered with the reordered template"
            );
            assert_eq!(after.long_poll_id, live_long_poll_id(&fx.state)?);
            Ok(())
        }

        #[test]
        fn long_poll_legacy_id_parses_as_fee_zero_and_malformed_ids_are_rejected() -> Result<()> {
            let (state, mining) = regtest_mining()?;
            let mining = Arc::new(mining);
            mining.publish_generation();
            let current = expect_template(mining.get_block_template(template_request(None))?);
            let id = current.candidate.template_id.as_str();
            assert!(
                !id.contains(':'),
                "precondition: the live id {id:?} carries no fee suffix"
            );
            let (tip, sequence) = id.split_at(64);
            let rejected = [
                format!("{tip}:"),
                format!("{tip}{sequence}:7:8"),
                format!("{tip}{sequence}x"),
                format!("{tip}-1:2"),
                format!("{tip}5:x"),
                format!("{}é:1", "a".repeat(63)),
            ];

            for rejected_id in rejected {
                let call_id = CompactString::from(rejected_id.as_str());
                let call_mining = Arc::clone(&mining);
                let chainstate = state.chainstate();
                let outcome = PendingPoll::spawn(
                    move || chainstate.request_shutdown(),
                    move || call_mining.get_block_template(template_request(Some(call_id))),
                )
                .collect(PROMPT)?;
                match outcome {
                    Err(MiningControlError::InvalidRequest(message)) => assert!(
                        message.as_str().contains("malformed"),
                        "id {rejected_id:?} was rejected with {message:?}"
                    ),
                    other => {
                        panic!("long-poll id {rejected_id:?} must be malformed, got {other:?}")
                    }
                }
            }
            advance_mempool_sequence(&state)?;
            let membership = state.mempool().read().sequence_number();
            mining.publish_generation_from(membership);
            let stale = CompactString::from(id);
            let answered =
                expect_template(mining.get_block_template(template_request(Some(stale)))?);
            assert_ne!(
                answered.candidate.mempool_sequence, current.candidate.mempool_sequence,
                "a legacy id must resolve against the fee-zero generation, not fail as malformed"
            );
            Ok(())
        }

        #[test]
        fn publish_fee_delta_generation_does_not_take_mempool_lock() -> Result<()> {
            let (state, mining) = regtest_mining()?;

            let mempool = state.mempool();
            let _write_guard = mempool.write();

            let (done_tx, done_rx) = bounded::<()>(1);
            let handle = thread::spawn(move || {
                mining.publish_fee_delta_generation(1);
                let _ = done_tx.send(());
            });

            done_rx
                .recv_timeout(Duration::from_millis(200))
                .map_err(|_| {
                    TestError::message(
                        "publish_fee_delta_generation deadlocked under the mempool write lock \
                 - it must not take the mempool read lock",
                    )
                })?;
            handle
                .join()
                .unwrap_or_else(|_| panic!("publish_fee_delta_generation thread panicked"));
            Ok(())
        }

        struct BarrierSetup {
            node: BarrierNode,
            mining: Arc<MiningCoordinator>,
            low: Tx,
            high: Tx,
        }

        fn barrier_setup() -> Result<BarrierSetup> {
            let node = open_barrier_node()?;
            seed_fresh_chain(&node.state, PRIORITY_SEED_BLOCKS)?;
            let mining = Arc::new(coordinator(&node.state));
            node.state.attach_mining_coordinator(&mining);
            let low = seed_coinbase_spend_at(1, LOW_FEE_SATS);
            let high = seed_coinbase_spend_at(2, HIGH_FEE_SATS);
            admit_to_mempool(&node.state, &low)?;
            admit_to_mempool(&node.state, &high)?;
            Ok(BarrierSetup {
                node,
                mining,
                low,
                high,
            })
        }

        fn txids_of(template: &BlockTemplate) -> Vec<String> {
            template
                .candidate
                .transactions
                .iter()
                .map(|entry| entry.txid.to_string())
                .collect()
        }

        #[test]
        fn staged_preparation_does_not_publish_before_commit() -> Result<()> {
            let setup = barrier_setup()?;
            let state = &setup.node.state;
            let gate = &setup.node.gate;
            let mining = &setup.mining;
            let old_tip = current_tip(state)?;
            let baseline = expect_template(mining.get_block_template(template_request(None))?);
            assert_eq!(
                baseline.candidate.previous_block_hash, old_tip.hash,
                "precondition: the template builds on the applied tip"
            );
            assert_eq!(
                txids_of(&baseline),
                txid_strings(&[&setup.high, &setup.low]),
                "precondition: high fee ranks over low"
            );

            let block = fresh_tip_child(state, vec![setup.low.clone()])?;
            let new_hash = Hash256::from(block.block_hash());

            thread::scope(|scope| {
                let _release = gate.release_guard();
                gate.arm();
                let apply = scope.spawn(|| {
                    state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                        block.clone(),
                    ))
                });
                assert!(
                    gate.wait_entered(barrier_bound()),
                    "the commit never reached the body-store sync boundary"
                );
                assert!(
                    mining
                        .wait_for_prepared_candidate(new_hash, barrier_bound())
                        .is_some(),
                    "the preparation worker never finished the staged tip while sync was held"
                );

                let held_tip = current_tip(state)?;
                assert_eq!(
                    held_tip.hash, old_tip.hash,
                    "the applied tip must not advance before the durable commit"
                );
                let held = expect_template(mining.get_block_template(template_request(None))?);
                assert_eq!(
                    held.candidate.previous_block_hash, old_tip.hash,
                    "an ordinary template must still build on the old parent while sync is held"
                );
                assert_eq!(
                    txids_of(&held),
                    txid_strings(&[&setup.high, &setup.low]),
                    "the held template must still carry both pooled spends"
                );
                let mempool = state.mempool();
                let pool = mempool.read();
                assert!(
                    pool.contains_txid(&setup.low.txid()),
                    "the consumed spend must stay pooled until the commit removes it"
                );
                drop(pool);

                gate.release();
                apply
                    .join()
                    .map_err(|_| TestError::message("barrier apply thread panicked"))??;
                assert_eq!(
                    current_tip(state)?.hash,
                    new_hash,
                    "releasing the sync must let the real commit land the new tip"
                );
                Ok(())
            })
        }

        #[test]
        fn prepared_candidate_installs_on_commit_with_arc_reuse() -> Result<()> {
            let setup = barrier_setup()?;
            let state = &setup.node.state;
            let gate = &setup.node.gate;
            let mining = &setup.mining;
            let block = fresh_tip_child(state, vec![setup.low.clone()])?;
            let new_hash = Hash256::from(block.block_hash());

            thread::scope(|scope| {
                let _release = gate.release_guard();
                gate.arm();
                let apply = scope.spawn(|| {
                    state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                        block.clone(),
                    ))
                });
                assert!(
                    gate.wait_entered(barrier_bound()),
                    "the commit never reached the body-store sync boundary"
                );
                let prepared = mining
            .wait_for_prepared_candidate(new_hash, barrier_bound())
            .ok_or_else(|| {
                TestError::message(
                    "the preparation worker never finished the staged tip while sync was held",
                )
            })?;

                gate.release();
                apply
                    .join()
                    .map_err(|_| TestError::message("barrier apply thread panicked"))??;
                assert_eq!(
                    current_tip(state)?.hash,
                    new_hash,
                    "the commit must land the staged tip"
                );

                let first = expect_template(mining.get_block_template(template_request(None))?);
                assert_eq!(
                    first.candidate.previous_block_hash, new_hash,
                    "the first template must build on the committed tip"
                );
                assert!(
                    Arc::ptr_eq(&first.candidate, &prepared),
                    "the first template on the new tip must install the prepared candidate arc"
                );
                assert_eq!(
                    txids_of(&first),
                    txid_strings(&[&setup.high]),
                    "the installed candidate must carry exactly the removal survivors"
                );
                let mempool = state.mempool();
                let pool = mempool.read();
                assert!(
                    !pool.contains_txid(&setup.low.txid()),
                    "the block's spend must leave the pool on commit"
                );
                assert!(
                    pool.contains_txid(&setup.high.txid()),
                    "the survivor must stay pooled after the commit"
                );
                drop(pool);
                assert_eq!(
                    first.candidate.coinbase_value,
                    REGTEST_SUBSIDY_SATS + HIGH_FEE_SATS,
                    "the installed coinbase must claim the survivors' actual fees"
                );
                Ok(())
            })
        }

        #[test]
        fn fee_priority_race_discards_stale_preparation() -> Result<()> {
            let setup = barrier_setup()?;
            let state = &setup.node.state;
            let gate = &setup.node.gate;
            let mining = &setup.mining;
            let block = fresh_tip_child(state, Vec::new())?;
            let new_hash = Hash256::from(block.block_hash());

            thread::scope(|scope| {
                let _release = gate.release_guard();
                gate.arm();
                let apply = scope.spawn(|| {
                    state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                        block.clone(),
                    ))
                });
                assert!(
                    gate.wait_entered(barrier_bound()),
                    "the commit never reached the body-store sync boundary"
                );
                let prepared = mining
            .wait_for_prepared_candidate(new_hash, barrier_bound())
            .ok_or_else(|| {
                TestError::message(
                    "the preparation worker never finished the staged tip while sync was held",
                )
            })?;
                let staged_order: Vec<String> = prepared
                    .transactions
                    .iter()
                    .map(|entry| entry.txid.to_string())
                    .collect();
                assert_eq!(
                    staged_order,
                    txid_strings(&[&setup.high, &setup.low]),
                    "precondition: the staged candidate ranks high over low"
                );

                let handler = rpc_handler(state, mining.clone());
                let accepted = handler.dispatch(
                    "prioritisetransaction",
                    &json!([setup.low.txid().to_string(), 0, PRIORITY_DELTA_SATS]),
                )?;
                assert_eq!(
                    accepted.as_bool(),
                    Some(true),
                    "the raced prioritisation must commit, got {accepted}"
                );

                gate.release();
                apply
                    .join()
                    .map_err(|_| TestError::message("barrier apply thread panicked"))??;
                assert_eq!(
                    current_tip(state)?.hash,
                    new_hash,
                    "the commit must land the staged tip"
                );

                let first = expect_template(mining.get_block_template(template_request(None))?);
                assert_eq!(
                    first.candidate.previous_block_hash, new_hash,
                    "the first template must build on the committed tip"
                );
                assert!(
                    !Arc::ptr_eq(&first.candidate, &prepared),
                    "a fee race between staging and publish must discard the stale preparation"
                );
                assert_eq!(
                    txids_of(&first),
                    txid_strings(&[&setup.low, &setup.high]),
                    "the post-commit template must reflect the committed priority"
                );
                assert_eq!(
                    first.candidate.template_id.as_str(),
                    live_long_poll_id(state)?,
                    "the served generation must be the live one"
                );
                Ok(())
            })
        }

        #[test]
        fn shutdown_with_staged_work_installs_nothing_and_answers_unavailable() -> Result<()> {
            let setup = barrier_setup()?;
            let state = &setup.node.state;
            let gate = &setup.node.gate;
            let mining = &setup.mining;
            let block = fresh_tip_child(state, Vec::new())?;
            let new_hash = Hash256::from(block.block_hash());

            thread::scope(|scope| {
                let _release = gate.release_guard();
                gate.arm();
                let apply = scope.spawn(|| {
                    state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                        block.clone(),
                    ))
                });
                assert!(
                    gate.wait_entered(barrier_bound()),
                    "the commit never reached the body-store sync boundary"
                );

                state.request_shutdown();
                gate.release();
                let inner = apply
                    .join()
                    .map_err(|_| TestError::message("barrier apply thread panicked"))?;
                let _ = inner;

                match mining.get_block_template(template_request(None)) {
                    Err(MiningControlError::Unavailable(_)) => {}
                    other => {
                        panic!("getblocktemplate after shutdown must be unavailable, got {other:?}")
                    }
                }
                assert!(
                    mining
                        .wait_for_prepared_candidate(new_hash, Duration::from_secs(2))
                        .is_none(),
                    "shutdown must release prepared waiters with nothing to install"
                );
                assert!(
                    mining.mining_info()?.last_candidate.is_none(),
                    "shutdown with staged work held must install nothing"
                );
                Ok(())
            })
        }
    }

    mod generation {
        use bitcoin_rs_node::test_support::TestError;

        type Result<T, E = TestError> = core::result::Result<T, E>;
        use bitcoin_rs_consensus::primitives::{
            Amount, BlockImage, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut,
            Txid, Witness,
        };
        use bitcoin_rs_node::{MiningCoordinator, Network};
        use bitcoin_rs_wire::mining::{
            BlockValidationResult, GenerateRequest, GenerateSelection, GenerateTx, MiningControl,
            MiningControlError,
        };

        use super::support::{open_at_genesis, regtest_mining, solved_template_block};

        #[test]
        fn generateblock_rejects_unknown_mempool_txid() -> Result<()> {
            let (_state, mining) = regtest_mining()?;
            let missing = Txid::from(Hash256::from_le_bytes(&[0xcd; 32]));
            let error = mining
                .generate(GenerateRequest {
                    payout: vec![0x51],
                    count: 1,
                    max_tries: 16,
                    selection: GenerateSelection::Ordered(vec![GenerateTx::Mempool(missing)]),
                    submit: true,
                })
                .err()
                .unwrap_or_else(|| panic!("missing mempool txid must fail"));
            assert!(matches!(error, MiningControlError::InvalidRequest(_)));
            Ok(())
        }

        #[test]
        fn generateblock_raw_tx_does_not_require_mempool_admission() -> Result<()> {
            let (_state, mining) = regtest_mining()?;
            mining.publish_generation();
            let raw = Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(
                        Txid::from(Hash256::from_le_bytes(&[0x11; 32])),
                        0,
                    ),
                    script_sig: Script::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: Script::from_bytes(vec![0x51]),
                }],
                lock_time: LockTime::ZERO,
            };
            let error = mining
                .generate(GenerateRequest {
                    payout: vec![0x51],
                    count: 1,
                    max_tries: 16,
                    selection: GenerateSelection::Ordered(vec![GenerateTx::Raw(raw)]),
                    submit: false,
                })
                .err()
                .unwrap_or_else(|| {
                    panic!("invalid raw spend must fail validation, not mempool lookup")
                });
            match error {
                MiningControlError::Rejected(reason) => {
                    assert!(
                        reason.starts_with("TestBlockValidity failed:"),
                        "Core wraps TestBlockValidity: {reason}"
                    );
                    assert!(
                        reason.contains("bad-txns-inputs-missingorspent"),
                        "missing prevout is Core's GetRejectReason: {reason}"
                    );
                }
                other => panic!("raw generateblock txs skip mempool membership: {other:?}"),
            }
            Ok(())
        }

        // API-05
        #[test]
        fn generate_without_submit_does_not_advance_the_tip() -> Result<()> {
            let (state, mining) = regtest_mining()?;
            mining.publish_generation();
            let before = state
                .chainstate()
                .applied_tip_snapshot()
                .unwrap_or_else(|| panic!("applied tip missing before generate"));
            let generated = mining.generate(GenerateRequest {
                payout: vec![0x51],
                count: 1,
                max_tries: GenerateRequest::DEFAULT_MAX_TRIES,
                selection: GenerateSelection::Ordered(Vec::new()),
                submit: false,
            })?;
            assert_eq!(generated.len(), 1);
            assert_ne!(generated[0].hex, "");
            let after = state
                .chainstate()
                .applied_tip_snapshot()
                .unwrap_or_else(|| panic!("applied tip missing after generate"));
            assert_eq!(after.height, before.height);
            assert_eq!(after.hash, before.hash);
            Ok(())
        }

        #[test]
        fn generateblock_raw_p2sh_costs_use_confirmed_prevouts() -> Result<()> {
            let state = open_at_genesis(Network::Regtest)?;
            let redeem = [vec![0x00, 0x63], vec![0xae; 199], vec![0x68, 0x51]].concat();
            let payout = bitcoin::ScriptBuf::from_bytes(redeem.clone())
                .to_p2sh()
                .into_bytes();
            let mining = MiningCoordinator::new(
                state.mempool_reader(),
                state.chainstate(),
                state.block_memory(),
                state.stable_read(),
                state.chain_followers(),
                payout,
                state.config().mining.coinbase_reserve,
            );
            let mut inputs = Vec::new();
            for _ in 0..6 {
                let block = solved_template_block(&mining)?;
                inputs.push(TxIn {
                    previous_output: OutPoint::new(block.txs[0].txid(), 0),
                    script_sig: bitcoin_rs_consensus::script::push_data(&redeem).into(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                });
                assert_eq!(
                    mining.submit_block(BlockImage::from_local(block))?,
                    BlockValidationResult::Accepted
                );
            }
            mining.generate(GenerateRequest {
                payout: vec![0x51],
                count: 100,
                max_tries: GenerateRequest::DEFAULT_MAX_TRIES,
                selection: GenerateSelection::Ordered(Vec::new()),
                submit: true,
            })?;
            let before = state
                .chainstate()
                .applied_tip_snapshot()
                .ok_or_else(|| TestError::message("missing tip"))?;
            let mut raw = Tx {
                version: 2,
                lock_time: LockTime::ZERO,
                inputs: inputs[..5].to_vec(),
                outputs: vec![TxOut {
                    value: Amount::from_sat(1_000),
                    script_pubkey: vec![0xac; 100].into(),
                }],
            };
            let request = |tx, max_tries| GenerateRequest {
                payout: vec![0x51],
                count: 1,
                max_tries,
                selection: GenerateSelection::Ordered(vec![GenerateTx::Raw(tx)]),
                submit: false,
            };
            assert_eq!(
                mining
                    .generate(request(raw.clone(), GenerateRequest::DEFAULT_MAX_TRIES))?
                    .len(),
                1
            );
            raw.inputs.push(inputs[5].clone());
            let error = mining.generate(request(raw, 0)).err().ok_or_else(|| {
                TestError::message("over-budget raw transaction must fail before solve")
            })?;
            assert!(
                matches!(error, MiningControlError::Rejected(ref reason) if reason == "TestBlockValidity failed: bad-blk-sigops"),
                "unexpected refusal: {error:?}"
            );
            let after = state
                .chainstate()
                .applied_tip_snapshot()
                .ok_or_else(|| TestError::message("missing tip"))?;
            assert_eq!(after.hash, before.hash);
            assert!(state.mempool().read().is_empty());
            Ok(())
        }
    }

    mod integration {
        use std::sync::Arc;

        use bitcoin_rs_node::test_support::TestError;

        type Result<T, E = TestError> = core::result::Result<T, E>;
        use bitcoin::hex::DisplayHex;
        use bitcoin_rs_consensus::primitives::{
            Amount, Hash256, LockTime, OutPoint, Sequence, Tx, TxIn, TxOut, Witness,
            consensus_bytes, encode::double_sha256,
        };
        use bitcoin_rs_mempool::{
            BodyInterest, MempoolObserver, MutationEnvelope, MutationOutcome,
        };
        use parking_lot::Mutex;
        use sonic_rs::{JsonContainerTrait as _, JsonValueTrait, json};

        use super::support::{
            LongPollId, MEMPOOL_TX_FEE_SATS, PRIORITY_DELTA_SATS, PROMPT, REGTEST_SUBSIDY_SATS,
            SEED_BLOCKS, WITNESS_RESERVED, admit_to_mempool, apply_genesis, assemble_from_template,
            assemble_regtest_block, compute_witness_merkle_root, current_tip, live_long_poll_id,
            mine_regtest_block, mining_handler, open_regtest, p2sh_true_output,
            p2sh_true_spend_script_sig, priority_fixture, required_str, required_u64, seed_chain,
            seed_coinbase_spend, seed_coinbase_spend_with_fee, txid_strings,
        };

        #[test]
        fn template_renders_coinbase_subsidy_plus_fees_and_bip22_fields() -> Result<()> {
            let (state, _guard) = open_regtest()?;
            apply_genesis(&state)?;
            let seed_tip_hash = seed_chain(&state, SEED_BLOCKS)?;

            let mempool_tx = seed_coinbase_spend();
            admit_to_mempool(&state, &mempool_tx)?;

            let handler = mining_handler(&state);
            let template = handler.dispatch("getblocktemplate", &json!([{"rules": ["segwit"]}]))?;

            assert_eq!(
                required_u64(&template, "coinbasevalue")?,
                REGTEST_SUBSIDY_SATS + MEMPOOL_TX_FEE_SATS,
                "coinbasevalue must be subsidy plus selected fees"
            );

            let template_txs = template
                .get("transactions")
                .and_then(|entry| entry.as_array())
                .map_or(&[][..], |entries| entries.as_slice());
            assert_eq!(template_txs.len(), 1, "the mempool tx must be selected");

            assert_eq!(
                required_u64(&template_txs[0], "weight")?,
                mempool_tx.weight(),
                "rendered weight must match the transaction weight"
            );
            assert_eq!(required_u64(&template_txs[0], "sigops")?, 0);

            let mutable = template
                .get("mutable")
                .and_then(|v| v.as_array())
                .map_or(&[][..], |a| a.as_slice());
            for expected in ["time", "transactions", "prevblock"] {
                assert!(
                    mutable.iter().any(|v| v.as_str() == Some(expected)),
                    "mutable must contain {expected}"
                );
            }
            let capabilities = template
                .get("capabilities")
                .and_then(|v| v.as_array())
                .map_or(&[][..], |a| a.as_slice());
            for expected in ["proposal", "longpoll"] {
                assert!(
                    capabilities.iter().any(|v| v.as_str() == Some(expected)),
                    "capabilities must contain {expected}"
                );
            }

            assert_eq!(
                required_str(&template, "previousblockhash")?,
                seed_tip_hash.to_string_be()
            );
            assert_eq!(
                required_u64(&template, "height")?,
                u64::from(SEED_BLOCKS + 1)
            );
            assert_eq!(required_str(&template, "bits")?, "207fffff");
            assert_eq!(
                required_str(&template, "target")?,
                "7fffff0000000000000000000000000000000000000000000000000000000000"
            );
            assert_eq!(required_str(&template, "noncerange")?, "00000000ffffffff");
            assert_eq!(required_u64(&template, "sigoplimit")?, 80_000);
            assert_eq!(required_u64(&template, "sizelimit")?, 4_000_000);
            assert_eq!(required_u64(&template, "weightlimit")?, 4_000_000);
            assert!(required_u64(&template, "mintime")? <= required_u64(&template, "curtime")?);
            let rules = template
                .get("rules")
                .and_then(|v| v.as_array())
                .map_or(&[][..], |a| a.as_slice());
            assert!(
                rules.iter().any(|x| x.as_str() == Some("!segwit")),
                "segwit is mandatory"
            );

            assert_template_witness_commitment(&template, &mempool_tx)?;
            let long_poll_id = required_str(&template, "longpollid")?;
            assert_eq!(
                LongPollId::parse(&long_poll_id)?.tip,
                seed_tip_hash.to_string_be(),
                "longpollid starts with the applied tip hash"
            );
            assert_eq!(
                long_poll_id,
                live_long_poll_id(&state)?,
                "longpollid is {{tip}}{{mempool_sequence}}[:{{fee_delta_sequence}}] of the live pool"
            );

            let sequence = state.mempool().read().sequence_number();
            assert_eq!(
                handler
                    .dispatch(
                        "prioritisetransaction",
                        &json!([mempool_tx.txid().to_string(), 0, 100_000])
                    )?
                    .as_bool(),
                Some(true)
            );
            assert_eq!(state.mempool().read().sequence_number(), sequence);
            let refreshed =
                handler.dispatch("getblocktemplate", &json!([{"rules": ["segwit"]}]))?;
            assert_ne!(required_str(&refreshed, "longpollid")?, long_poll_id);
            assert_eq!(
                required_u64(&refreshed, "coinbasevalue")?,
                REGTEST_SUBSIDY_SATS + MEMPOOL_TX_FEE_SATS
            );

            Ok(())
        }

        fn assert_template_witness_commitment(
            template: &sonic_rs::Value,
            mempool_tx: &Tx,
        ) -> Result<()> {
            let commitment = required_str(template, "default_witness_commitment")?;
            assert!(
                commitment.starts_with("6a24aa21a9ed"),
                "default witness commitment carries BIP141 prefix"
            );
            let expected_root = compute_witness_merkle_root(std::slice::from_ref(mempool_tx))
                .ok_or_else(|| TestError::message("single-tx witness merkle root must exist"))?;
            let mut commitment_input = [0_u8; 64];
            commitment_input[..32].copy_from_slice(&expected_root.to_le_bytes());
            commitment_input[32..].copy_from_slice(&WITNESS_RESERVED);
            let expected_commitment = double_sha256(&commitment_input).to_le_bytes();
            assert_eq!(
                &commitment[12..],
                expected_commitment.to_lower_hex_string(),
                "rendered commitment must be SHA256D(witness merkle root || witness reserved value)"
            );
            Ok(())
        }

        #[test]
        fn template_orders_parent_then_child_with_dependency() -> Result<()> {
            let (state, _guard) = open_regtest()?;
            apply_genesis(&state)?;
            let _seed_tip_hash = seed_chain(&state, SEED_BLOCKS)?;

            let parent = seed_coinbase_spend();
            let parent_txid = parent.txid();
            let child = Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(parent_txid, 0),
                    script_sig: p2sh_true_spend_script_sig(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(REGTEST_SUBSIDY_SATS - 2 * MEMPOOL_TX_FEE_SATS),
                    script_pubkey: p2sh_true_output(),
                }],
                lock_time: LockTime::ZERO,
            };
            let child_txid = child.txid();

            admit_to_mempool(&state, &parent)?;
            admit_to_mempool(&state, &child)?;

            let handler = mining_handler(&state);
            let template = handler.dispatch("getblocktemplate", &json!([{"rules": ["segwit"]}]))?;
            let template_txs = template
                .get("transactions")
                .and_then(|entry| entry.as_array())
                .map_or(&[][..], |entries| entries.as_slice());
            assert_eq!(template_txs.len(), 2, "both txs must be selected");
            assert_eq!(
                template_txs[0]
                    .get("txid")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| TestError::message("first template tx missing txid"))?,
                parent_txid.to_string(),
                "parent must precede child in topological template order"
            );
            assert_eq!(
                template_txs[1]
                    .get("txid")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| TestError::message("second template tx missing txid"))?,
                child_txid.to_string(),
                "child must follow parent in topological template order"
            );

            let parent_depends = template_txs[0]
                .get("depends")
                .and_then(|value| value.as_array())
                .map_or(&[][..], |entries| entries.as_slice());
            assert!(
                parent_depends.is_empty(),
                "parent has no in-template dependencies"
            );

            let child_depends = template_txs[1]
                .get("depends")
                .and_then(|value| value.as_array())
                .map_or(&[][..], |entries| entries.as_slice());
            assert_eq!(
                child_depends.len(),
                1,
                "child depends on the one in-template parent"
            );
            assert_eq!(
                child_depends[0]
                    .as_i64()
                    .and_then(|n| u64::try_from(n).ok()),
                Some(1_u64),
                "child depends index must be the one-based parent position"
            );

            Ok(())
        }

        #[test]
        fn invalidateblock_readmits_parent_before_child_in_dependency_order() -> Result<()> {
            let (state, _guard) = open_regtest()?;
            apply_genesis(&state)?;
            let seed_tip_hash = seed_chain(&state, SEED_BLOCKS)?;

            let parent = seed_coinbase_spend();
            let parent_txid = parent.txid();
            let child = Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(parent_txid, 0),
                    script_sig: p2sh_true_spend_script_sig(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(REGTEST_SUBSIDY_SATS - 2 * MEMPOOL_TX_FEE_SATS),
                    script_pubkey: p2sh_true_output(),
                }],
                lock_time: LockTime::ZERO,
            };
            let child_txid = child.txid();

            admit_to_mempool(&state, &parent)?;
            admit_to_mempool(&state, &child)?;
            let sequence_before_reorg = state.mempool().read().sequence_number();

            let block =
                mine_regtest_block(&state, seed_tip_hash, SEED_BLOCKS + 1, vec![parent, child])?;
            assert_eq!(
                state.mempool().read().len(),
                0,
                "connect must drain the confirmed pair"
            );
            let mined_hash = Hash256::from(block.block_hash());

            bitcoin_rs_node::reorg::invalidate_block(
                &state.chainstate(),
                &state.chain_followers(),
                mined_hash,
            )
            .map_err(|error| TestError::message(format!("invalidateblock failed: {error}")))?;

            let tip = current_tip(&state)?;
            assert_eq!(tip.height, SEED_BLOCKS, "the mined block must roll back");
            {
                let mempool = state.mempool();
                let pool = mempool.read();
                assert!(pool.contains_txid(&parent_txid), "the parent returns");
                assert!(
                    pool.contains_txid(&child_txid),
                    "the child follows its parent"
                );
                assert_eq!(pool.len(), 2, "the coinbase must stay out");
                assert_eq!(
                    pool.sequence_number(),
                    sequence_before_reorg + 4,
                    "connect removes two, reconsideration admits parent then child"
                );
            }
            Ok(())
        }

        #[derive(Default)]
        struct RecordingMempoolObserver {
            changes: Mutex<Vec<(u64, Hash256, MutationOutcome)>>,
        }

        impl MempoolObserver for RecordingMempoolObserver {
            fn on_mutation(&self, envelope: &MutationEnvelope) {
                let result = &envelope.result;
                let mut changes = self.changes.lock();
                for (offset, change) in result.changes.iter().enumerate() {
                    let sequence = result.sequence_of(offset).unwrap_or(u64::MAX);
                    changes.push((sequence, change.txid, change.outcome));
                }
            }
        }

        #[test]
        fn invalidateblock_readmission_publishes_events_through_composed_gateway() -> Result<()> {
            let (state, _guard) = open_regtest()?;
            apply_genesis(&state)?;
            let seed_tip_hash = seed_chain(&state, SEED_BLOCKS)?;

            let observer = Arc::new(RecordingMempoolObserver::default());
            let gateway = state.mempool_gateway();
            assert!(Arc::ptr_eq(gateway.pool(), &state.mempool()));
            assert_eq!(gateway.engine(), state.config().validation.engine);
            gateway
                .attach_observer_leg("test-recorder", observer.clone(), BodyInterest::Metadata)
                .unwrap_or_else(|error| {
                    panic!("the node installs an observer slot to extend: {error}")
                });
            let parent = seed_coinbase_spend();
            let parent_txid = parent.txid();
            let child = Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(parent_txid, 0),
                    script_sig: p2sh_true_spend_script_sig(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(REGTEST_SUBSIDY_SATS - 2 * MEMPOOL_TX_FEE_SATS),
                    script_pubkey: p2sh_true_output(),
                }],
                lock_time: LockTime::ZERO,
            };
            let child_txid = child.txid();

            let block =
                mine_regtest_block(&state, seed_tip_hash, SEED_BLOCKS + 1, vec![parent, child])?;
            let mined_hash = Hash256::from(block.block_hash());
            bitcoin_rs_node::reorg::invalidate_block(
                &state.chainstate(),
                &state.chain_followers(),
                mined_hash,
            )
            .map_err(|error| TestError::message(format!("invalidateblock failed: {error}")))?;

            let tip = current_tip(&state)?;
            assert_eq!(tip.height, SEED_BLOCKS, "the mined block must roll back");
            let changes = observer.changes.lock();
            assert_eq!(
                *changes,
                vec![
                    (1, Hash256::from(parent_txid), MutationOutcome::Accepted,),
                    (2, Hash256::from(child_txid), MutationOutcome::Accepted,),
                ],
                "parent before child, contiguous sequences"
            );
            Ok(())
        }

        #[test]
        fn invalidateblock_readmits_a_below_floor_family_through_the_deferred_fence() -> Result<()>
        {
            let (state, _guard) = open_regtest()?;
            apply_genesis(&state)?;
            let seed_tip_hash = seed_chain(&state, SEED_BLOCKS)?;

            let parent = seed_coinbase_spend_with_fee(1);
            let parent_txid = parent.txid();
            let child = Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(parent_txid, 0),
                    script_sig: p2sh_true_spend_script_sig(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(REGTEST_SUBSIDY_SATS - 1 - 5_000),
                    script_pubkey: p2sh_true_output(),
                }],
                lock_time: LockTime::ZERO,
            };
            let child_txid = child.txid();

            let block =
                mine_regtest_block(&state, seed_tip_hash, SEED_BLOCKS + 1, vec![parent, child])?;
            let mined_hash = Hash256::from(block.block_hash());
            bitcoin_rs_node::reorg::invalidate_block(
                &state.chainstate(),
                &state.chain_followers(),
                mined_hash,
            )
            .map_err(|error| TestError::message(format!("invalidateblock failed: {error}")))?;

            let tip = current_tip(&state)?;
            assert_eq!(tip.height, SEED_BLOCKS, "the mined block must roll back");
            let mempool = state.mempool();
            let pool = mempool.read();
            assert!(
                pool.contains_txid(&parent_txid),
                "the deferred fence must re-admit the below-floor parent"
            );
            assert!(
                pool.contains_txid(&child_txid),
                "the child must re-enter once its parent is back"
            );
            Ok(())
        }

        #[test]
        fn submitblock_accepts_block_without_prior_mempool_admission() -> Result<()> {
            let (state, _guard) = open_regtest()?;
            apply_genesis(&state)?;
            let seed_tip_hash = seed_chain(&state, SEED_BLOCKS)?;

            let tx = seed_coinbase_spend();
            assert!(!state.mempool().read().contains_txid(&tx.txid()));

            let block = assemble_regtest_block(seed_tip_hash, SEED_BLOCKS + 1, vec![tx])?;
            let block_hex = consensus_bytes(&block).to_lower_hex_string();

            let handler = mining_handler(&state);
            let verdict = handler.dispatch("submitblock", &json!([block_hex]))?;
            assert!(
                verdict.is_null(),
                "submitblock must accept a valid block, got: {verdict}"
            );

            let tip = current_tip(&state)?;
            assert_eq!(tip.height, SEED_BLOCKS + 1, "tip must advance by one");
            assert_eq!(
                tip.hash,
                Hash256::from(block.block_hash()),
                "tip hash must equal the submitted block hash"
            );
            Ok(())
        }

        #[test]
        fn submitblock_rejects_stale_template_with_inconclusive_prevblk() -> Result<()> {
            let (state, _guard) = open_regtest()?;
            apply_genesis(&state)?;
            let old_tip = seed_chain(&state, SEED_BLOCKS)?;

            let tx = seed_coinbase_spend();
            admit_to_mempool(&state, &tx)?;

            let handler = mining_handler(&state);
            let template = handler.dispatch("getblocktemplate", &json!([{"rules": ["segwit"]}]))?;
            let template_txs = template
                .get("transactions")
                .and_then(|value| value.as_array())
                .map_or(&[][..], |entries| entries.as_slice());
            let accepted = assemble_from_template(&template, template_txs)?;
            let accepted_hex = consensus_bytes(&accepted).to_lower_hex_string();
            let verdict = handler.dispatch("submitblock", &json!([accepted_hex]))?;
            assert!(
                verdict.is_null(),
                "first block must be accepted, got: {verdict}"
            );

            let stale_block = assemble_regtest_block(old_tip, SEED_BLOCKS + 1, Vec::new())?;
            let stale_hex = consensus_bytes(&stale_block).to_lower_hex_string();
            let reject = handler.dispatch("submitblock", &json!([stale_hex]))?;
            let reason = reject
                .as_str()
                .ok_or_else(|| TestError::message("submitblock"))?;
            assert!(
                reason.contains("inconclusive-not-best-prevblk"),
                "stale template must be rejected with PrevHashMismatch: {reason}"
            );

            Ok(())
        }

        #[test]
        fn post_connect_template_pool_and_estimator_observables() -> Result<()> {
            let (state, _guard) = open_regtest()?;
            apply_genesis(&state)?;
            let _seed_tip_hash = seed_chain(&state, SEED_BLOCKS)?;

            let handler = mining_handler(&state);
            let before = handler.dispatch("estimatesmartfee", &json!([1, "conservative"]))?;
            assert!(
                before.get("feerate").is_none(),
                "empty estimator omits feerate"
            );
            let before_errors = before
                .get("errors")
                .and_then(|value| value.as_array())
                .map_or(&[][..], |entries| entries.as_slice());
            assert!(
                before_errors.iter().any(|value| {
                    value
                        .as_str()
                        .is_some_and(|text| text.contains("Insufficient data"))
                }),
                "empty estimator reports insufficient data: {before}"
            );

            let parent = seed_coinbase_spend();
            let parent_txid = parent.txid();
            let child = Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(parent_txid, 0),
                    script_sig: p2sh_true_spend_script_sig(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(REGTEST_SUBSIDY_SATS - 2 * MEMPOOL_TX_FEE_SATS),
                    script_pubkey: p2sh_true_output(),
                }],
                lock_time: LockTime::ZERO,
            };
            admit_to_mempool(&state, &parent)?;
            admit_to_mempool(&state, &child)?;

            let template = handler.dispatch("getblocktemplate", &json!([{"rules": ["segwit"]}]))?;
            let template_txs = template
                .get("transactions")
                .and_then(|value| value.as_array())
                .map_or(&[][..], |entries| entries.as_slice());
            let block = assemble_from_template(&template, template_txs)?;
            let block_hex = consensus_bytes(&block).to_lower_hex_string();
            let verdict = handler.dispatch("submitblock", &json!([block_hex]))?;
            assert!(
                verdict.is_null(),
                "submitblock must accept the block: {verdict}"
            );

            let next = handler.dispatch("getblocktemplate", &json!([{"rules": ["segwit"]}]))?;
            let next_txs = next
                .get("transactions")
                .and_then(|value| value.as_array())
                .map_or(&[][..], |entries| entries.as_slice());
            assert!(
                next_txs.is_empty(),
                "next template must have no transactions after connect"
            );
            assert_eq!(
                required_str(&next, "previousblockhash")?,
                block.block_hash().to_string(),
                "next template must build on the accepted block"
            );

            let mempool_info = handler.dispatch("getmempoolinfo", &json!([]))?;
            assert_eq!(
                required_u64(&mempool_info, "size")?,
                0,
                "mempool must be empty after block connect"
            );

            let raw_mempool = handler.dispatch("getrawmempool", &json!([]))?;
            let raw_mempool_array = raw_mempool
                .as_array()
                .map_or(&[][..], |entries| entries.as_slice());
            assert!(
                raw_mempool_array.is_empty(),
                "getrawmempool must return no txids"
            );

            let after = handler.dispatch("estimatesmartfee", &json!([1, "conservative"]))?;
            assert!(
                after.get("errors").is_none(),
                "estimate with data has no errors: {after}"
            );
            let feerate = after
                .get("feerate")
                .and_then(sonic_rs::JsonValueTrait::as_f64)
                .ok_or_else(|| TestError::message("estimatesmartfee must report feerate"))?;
            assert!(feerate > 0.0, "confirmed fee rate must be positive");
            assert_eq!(
                required_u64(&after, "blocks")?,
                1_u64,
                "one-block conf target estimates within one block"
            );

            Ok(())
        }

        #[test]
        fn prioritisetransaction_reorders_the_rpc_template_and_moves_only_the_fee_component()
        -> Result<()> {
            let fx = priority_fixture()?;
            let before = fx.template()?;
            assert_eq!(before.txids, txid_strings(&[&fx.high, &fx.low]));

            fx.prioritise(&fx.low, PRIORITY_DELTA_SATS)?;
            let raised = fx.template()?;
            assert_eq!(
                raised.txids,
                txid_strings(&[&fx.low, &fx.high]),
                "the prioritised transaction must lead the next template"
            );
            assert_eq!(
                raised.fees.iter().rev().copied().collect::<Vec<_>>(),
                before.fees,
                "prioritisation reorders; it never changes the fee a transaction pays"
            );
            assert_eq!(raised.coinbase_value, before.coinbase_value);
            let (before_id, raised_id) = (before.id()?, raised.id()?);
            assert_eq!(raised_id.tip, before_id.tip);
            assert_eq!(raised_id.mempool_sequence, before_id.mempool_sequence);
            assert_ne!(raised_id.fee_delta_sequence, before_id.fee_delta_sequence);
            assert_eq!(raised.long_poll_id, live_long_poll_id(&fx.state)?);

            fx.prioritise(&fx.low, -PRIORITY_DELTA_SATS)?;
            let restored = fx.template()?;
            assert_eq!(
                restored.txids, before.txids,
                "removing the delta restores the order"
            );
            assert_ne!(
                restored.long_poll_id, raised.long_poll_id,
                "the fee component only moves forward; a generation never repeats"
            );
            assert_ne!(restored.long_poll_id, before.long_poll_id);
            Ok(())
        }

        #[test]
        fn getblocktemplate_accepts_the_legacy_longpollid_shape_as_fee_zero() -> Result<()> {
            let fx = priority_fixture()?;
            let current = fx.template()?;
            assert!(
                !current.long_poll_id.contains(':'),
                "precondition: the live id {:?} carries no fee suffix",
                current.long_poll_id
            );
            fx.prioritise(&fx.low, PRIORITY_DELTA_SATS)?;
            let legacy = current.long_poll_id;
            let answered = fx.poll(&legacy).collect(PROMPT)??;
            assert_ne!(
                answered.long_poll_id, legacy,
                "a legacy id must resolve against the fee-zero generation, not fail as malformed"
            );
            assert_eq!(
                answered.txids,
                txid_strings(&[&fx.low, &fx.high]),
                "the stale legacy id must be answered with the reordered template"
            );
            Ok(())
        }
    }

    mod preparation_barrier {
        use std::sync::{Arc, Condvar, Mutex, MutexGuard};
        use std::time::Duration;

        use bitcoin_rs_node::test_support::TestError;

        type Result<T, E = TestError> = core::result::Result<T, E>;
        use bitcoin_rs_chain::chain::regtest_fixture::{self, REGTEST_BITS};
        use bitcoin_rs_consensus::primitives::{
            Amount, Block, BlockBodyMetadata, BlockHash, CompactTarget, Hash256, Header, LockTime,
            OutPoint, Script, Sequence, Tx, TxIn, TxOut, Witness, unix_time_secs,
        };
        use bitcoin_rs_consensus::script::push_int;
        use bitcoin_rs_node::{Network, NodeConfig, state::NodeState};
        use bitcoin_rs_storage::block_body::{BlockBodyReader, BlockBodyStore};
        use bitcoin_rs_storage::{BlockFilePosition, BodyExtent, BoundedReadError, StorageError};

        use super::support::current_tip;

        const BARRIER_BOUND: Duration = Duration::from_secs(10);

        struct GateState {
            armed: bool,
            entered: bool,
            released: bool,
        }

        pub(crate) struct SyncGate {
            state: Mutex<GateState>,
            cvar: Condvar,
        }

        impl SyncGate {
            fn new() -> Arc<Self> {
                Arc::new(Self {
                    state: Mutex::new(GateState {
                        armed: false,
                        entered: false,
                        released: false,
                    }),
                    cvar: Condvar::new(),
                })
            }

            fn lock_state(&self) -> MutexGuard<'_, GateState> {
                self.state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
            }

            pub(crate) fn arm(&self) {
                let mut state = self.lock_state();
                state.armed = true;
                state.entered = false;
                state.released = false;
            }

            fn hold(&self) {
                let mut state = self.lock_state();
                if !state.armed {
                    return;
                }
                state.armed = false;
                state.entered = true;
                self.cvar.notify_all();
                while !state.released {
                    state = self
                        .cvar
                        .wait(state)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                }
            }

            pub(crate) fn wait_entered(&self, timeout: Duration) -> bool {
                let (state, _) = self
                    .cvar
                    .wait_timeout_while(self.lock_state(), timeout, |state| !state.entered)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                state.entered
            }

            pub(crate) fn release(&self) {
                let mut state = self.lock_state();
                state.released = true;
                self.cvar.notify_all();
            }

            pub(crate) fn release_guard(&self) -> ReleaseGuard<'_> {
                ReleaseGuard { gate: self }
            }
        }

        pub(crate) struct ReleaseGuard<'a> {
            gate: &'a SyncGate,
        }

        impl Drop for ReleaseGuard<'_> {
            fn drop(&mut self) {
                self.gate.release();
            }
        }

        pub(crate) struct BarrierBodies {
            inner: Arc<dyn BlockBodyStore>,
            gate: Arc<SyncGate>,
        }

        impl BlockBodyStore for BarrierBodies {
            fn load_staged_body(
                &self,
                height: u32,
                hash: Hash256,
                position: Option<BlockFilePosition>,
            ) -> Result<Option<Vec<u8>>, StorageError> {
                self.inner.load_staged_body(height, hash, position)
            }

            fn stage_block_body(
                &self,
                height: u32,
                hash: Hash256,
                body: &[u8],
            ) -> Result<Option<BlockFilePosition>, StorageError> {
                self.inner.stage_block_body(height, hash, body)
            }

            fn persist_block_body(
                &self,
                height: u32,
                hash: Hash256,
                body: &[u8],
            ) -> Result<(), StorageError> {
                self.inner.persist_block_body(height, hash, body)
            }

            fn persist_block_body_value(
                &self,
                height: u32,
                hash: Hash256,
                body: bytes::Bytes,
            ) -> Result<(), StorageError> {
                self.inner.persist_block_body_value(height, hash, body)
            }

            fn load_block_body(
                &self,
                height: u32,
                hash: Hash256,
            ) -> Result<Option<Vec<u8>>, StorageError> {
                self.inner.load_block_body(height, hash)
            }

            fn load_block_body_for_verification(
                &self,
                height: u32,
                hash: Hash256,
            ) -> Result<Option<Vec<u8>>, StorageError> {
                self.inner.load_block_body_for_verification(height, hash)
            }

            fn load_block_body_bounded(
                &self,
                height: u32,
                hash: Hash256,
                max_bytes: usize,
            ) -> Result<Option<Vec<u8>>, BoundedReadError> {
                self.inner.load_block_body_bounded(height, hash, max_bytes)
            }

            fn load_block_body_for_verification_bounded(
                &self,
                height: u32,
                hash: Hash256,
                max_bytes: usize,
            ) -> Result<Option<Vec<u8>>, BoundedReadError> {
                self.inner
                    .load_block_body_for_verification_bounded(height, hash, max_bytes)
            }

            fn reader(&self) -> Result<Box<dyn BlockBodyReader + '_>, StorageError> {
                self.inner.reader()
            }

            fn undo_record(
                &self,
                height: u32,
                hash: Hash256,
            ) -> Result<Option<Vec<u8>>, StorageError> {
                self.inner.undo_record(height, hash)
            }

            fn load_block_body_range(
                &self,
                height: u32,
                hash: Hash256,
                offset: u32,
                len: u32,
            ) -> Result<Option<Vec<u8>>, StorageError> {
                self.inner.load_block_body_range(height, hash, offset, len)
            }

            fn block_body_metadata(
                &self,
                height: u32,
                hash: Hash256,
            ) -> Result<Option<BlockBodyMetadata>, StorageError> {
                self.inner.block_body_metadata(height, hash)
            }

            fn append_cursor(&self) -> Option<BodyExtent> {
                self.inner.append_cursor()
            }

            fn block_position(
                &self,
                height: u32,
                hash: Hash256,
            ) -> Result<Option<BlockFilePosition>, StorageError> {
                self.inner.block_position(height, hash)
            }

            fn disk_usage(&self) -> Option<u64> {
                self.inner.disk_usage()
            }

            fn sync(&self) -> Result<(), StorageError> {
                self.gate.hold();
                self.inner.sync()
            }

            fn flush_index(&self) -> Result<(), StorageError> {
                self.inner.flush_index()
            }
        }

        pub(crate) struct BarrierNode {
            pub(crate) state: NodeState,
            pub(crate) gate: Arc<SyncGate>,
            _dir: tempfile::TempDir,
        }

        pub(crate) fn open_barrier_node() -> Result<BarrierNode> {
            let dir = tempfile::tempdir()?;
            let mut config = NodeConfig::default_for_network(Network::Regtest);
            config.data_dir = dir.path().join("node");
            config.p2p.listen.clear();
            let gate = SyncGate::new();
            let hold = Arc::clone(&gate);
            let state = NodeState::open_with_body_store(config, None, move |store| {
                let wrapped: Arc<dyn BlockBodyStore> = Arc::new(BarrierBodies {
                    inner: store,
                    gate: hold,
                });
                wrapped
            })?;
            Ok(BarrierNode {
                state,
                gate,
                _dir: dir,
            })
        }

        pub(crate) fn fresh_child(
            prev: Hash256,
            height: u32,
            time: u32,
            txs: Vec<Tx>,
        ) -> Result<Block> {
            let coinbase = Tx {
                version: 2,
                lock_time: LockTime::ZERO,
                inputs: vec![TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: Script::from_bytes(
                        [push_int(i64::from(height)), push_int(0)].concat(),
                    ),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(super::support::REGTEST_SUBSIDY_SATS),
                    script_pubkey: super::support::p2sh_true_output(),
                }],
            };
            let mut block = Block {
                header: Header {
                    version: 0x2000_0000,
                    prev_blockhash: BlockHash::from(prev),
                    merkle_root: Hash256::from_le_bytes(&[0_u8; 32]),
                    time,
                    bits: CompactTarget::from_consensus(REGTEST_BITS),
                    nonce: 0,
                },
                txs: std::iter::once(coinbase).chain(txs).collect(),
            };
            block.header.merkle_root = regtest_fixture::merkle_root(&block.txs)
                .ok_or_else(|| TestError::message("fresh child must have a merkle root"))?;
            regtest_fixture::mine_block_to_declared_target(&mut block).map_err(|error| {
                TestError::message(format!("fresh child mining failed: {error}"))
            })?;
            Ok(block)
        }

        pub(crate) fn wall_time() -> Result<u32> {
            u32::try_from(unix_time_secs()).map_err(|_| {
                TestError::message(format!("wall clock {} out of u32 range", unix_time_secs()))
            })
        }

        pub(crate) fn fresh_tip_child(state: &NodeState, txs: Vec<Tx>) -> Result<Block> {
            let tip = current_tip(state)?;
            fresh_child(tip.hash, tip.height + 1, wall_time()?, txs)
        }

        pub(crate) fn seed_fresh_chain(state: &NodeState, count: u32) -> Result<Hash256> {
            if state.chainstate().applied_tip_snapshot().is_none() {
                let genesis = Network::Regtest.genesis_block();
                state
                    .apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                        genesis,
                    ))
                    .map_err(|error| {
                        TestError::message(format!("genesis apply failed: {error}"))
                    })?;
            }
            let now = u64::from(wall_time()?);
            let mut tip = current_tip(state)?;
            for index in 1..=count {
                let height = tip.height + 1;
                let time = u32::try_from(now.saturating_sub(u64::from(count - index) * 600))
                    .map_err(|_| TestError::message("fresh seed time out of u32 range"))?;
                let block = fresh_child(tip.hash, height, time, Vec::new())?;
                state
                    .apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                        block,
                    ))
                    .map_err(|error| {
                        TestError::message(format!("fresh seed block {height} failed: {error}"))
                    })?;
                tip = current_tip(state)?;
                if tip.height != height {
                    return Err(TestError::message(format!(
                        "fresh seed block did not become the tip at height {height}"
                    )));
                }
            }
            Ok(tip.hash)
        }

        pub(crate) fn barrier_bound() -> Duration {
            BARRIER_BOUND
        }

        struct DivergentBodies {
            plain: Vec<u8>,
            verified: Vec<u8>,
        }

        impl BlockBodyStore for DivergentBodies {
            fn persist_block_body(&self, _: u32, _: Hash256, _: &[u8]) -> Result<(), StorageError> {
                Ok(())
            }

            fn load_block_body(&self, _: u32, _: Hash256) -> Result<Option<Vec<u8>>, StorageError> {
                Ok(Some(self.plain.clone()))
            }

            fn load_block_body_for_verification(
                &self,
                _: u32,
                _: Hash256,
            ) -> Result<Option<Vec<u8>>, StorageError> {
                Ok(Some(self.verified.clone()))
            }

            fn sync(&self) -> Result<(), StorageError> {
                Ok(())
            }
        }

        #[test]
        fn barrier_bodies_verification_read_uses_the_inner_verification_path() -> Result<()> {
            let bodies = BarrierBodies {
                inner: Arc::new(DivergentBodies {
                    plain: vec![1],
                    verified: vec![2],
                }),
                gate: SyncGate::new(),
            };
            let hash = Hash256::from_le_bytes(&[0x11; 32]);
            assert_eq!(bodies.load_block_body(7, hash)?, Some(vec![1]));
            assert_eq!(
                bodies.load_block_body_for_verification(7, hash)?,
                Some(vec![2])
            );
            Ok(())
        }

        #[test]
        fn barrier_preserves_inner_verification_corruption() {
            struct CorruptInner;
            impl BlockBodyStore for CorruptInner {
                fn persist_block_body(
                    &self,
                    _: u32,
                    _: Hash256,
                    _: &[u8],
                ) -> Result<(), StorageError> {
                    Ok(())
                }
                fn load_block_body(
                    &self,
                    _: u32,
                    _: Hash256,
                ) -> Result<Option<Vec<u8>>, StorageError> {
                    Ok(None)
                }
                fn sync(&self) -> Result<(), StorageError> {
                    Ok(())
                }
                fn load_block_body_for_verification(
                    &self,
                    _: u32,
                    _: Hash256,
                ) -> Result<Option<Vec<u8>>, StorageError> {
                    Err(StorageError::CorruptBlockFrame("frame"))
                }
            }
            let wrapped = BarrierBodies {
                inner: Arc::new(CorruptInner),
                gate: SyncGate::new(),
            };
            let hash = Hash256::from_le_bytes(&[0xB4; 32]);
            assert!(
                matches!(
                    wrapped.load_block_body_for_verification(1, hash),
                    Err(StorageError::CorruptBlockFrame(_))
                ),
                "the barrier must preserve verification corruption like the inner store"
            );
        }
    }

    mod submission {
        use std::thread;

        use bitcoin_rs_node::test_support::TestError;

        type Result<T, E = TestError> = core::result::Result<T, E>;
        use bitcoin_rs_chain::chain::regtest_fixture;
        use bitcoin_rs_chain::chain::{NodeStatus, compact_is_met_by};
        use bitcoin_rs_consensus::primitives::{
            Amount, Block, BlockHash, BlockImage, CompactTarget, Hash256, Header, LockTime,
            OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
        };
        use bitcoin_rs_node::Network;
        use bitcoin_rs_wire::mining::{
            BlockTemplateMode, BlockTemplateRequest, BlockTemplateResult, BlockValidationResult,
            MiningControl, MiningControlError,
        };

        use super::support::{
            WITNESS_COMMITMENT_PREFIX, WITNESS_RESERVED, coordinator, disconnect_applied,
            excess_coinbase_child, is_witness_commitment, mined_child, mined_child_labeled,
            mined_regtest_header, open_at_genesis, open_network, propose_block, regtest_mining,
            solved_template_block,
        };

        #[test]
        fn proposal_has_no_side_effects() -> Result<()> {
            let (state, mining) = regtest_mining()?;
            mining.publish_generation();
            let before = state
                .chainstate()
                .applied_tip_snapshot()
                .unwrap_or_else(|| panic!("applied tip missing before proposal"));
            let before_seq = state.mempool().read().sequence_number();
            let before_blocks = state.block_log_reader().read().len();

            let genesis = Network::Regtest.genesis_block();
            let child = mined_child(genesis.block_hash())?;
            let result = mining.get_block_template(BlockTemplateRequest {
                mode: BlockTemplateMode::Proposal(child),
                capabilities: Vec::new(),
                rules: Vec::new(),
                long_poll_id: None,
                coinbase_budget: None,
            })?;
            match result {
                BlockTemplateResult::Proposal(BlockValidationResult::Accepted) => {}
                other => panic!("valid proposal must be accepted, got {other:?}"),
            }

            let after = state
                .chainstate()
                .applied_tip_snapshot()
                .unwrap_or_else(|| panic!("applied tip missing after proposal"));
            assert_eq!(before.hash, after.hash);
            assert_eq!(before_seq, state.mempool().read().sequence_number());
            assert_eq!(before_blocks, state.block_log_reader().read().len());
            Ok(())
        }

        #[test]
        fn proposal_rejects_excess_coinbase_without_side_effects() -> Result<()> {
            let (state, mining) = regtest_mining()?;
            mining.publish_generation();
            let before = state
                .chainstate()
                .applied_tip_snapshot()
                .unwrap_or_else(|| panic!("applied tip missing before proposal"));
            let before_seq = state.mempool().read().sequence_number();
            let before_blocks = state.block_log_reader().read().len();

            let genesis = Network::Regtest.genesis_block();
            let child = excess_coinbase_child(genesis.block_hash())?;
            let result = mining.get_block_template(BlockTemplateRequest {
                mode: BlockTemplateMode::Proposal(child),
                capabilities: Vec::new(),
                rules: Vec::new(),
                long_poll_id: None,
                coinbase_budget: None,
            })?;
            match result {
                BlockTemplateResult::Proposal(BlockValidationResult::Rejected(reason)) => {
                    assert_eq!(reason.as_str(), "bad-cb-amount");
                }
                other => panic!("expected bad-cb-amount proposal rejection, got {other:?}"),
            }

            let after = state
                .chainstate()
                .applied_tip_snapshot()
                .unwrap_or_else(|| panic!("applied tip missing after proposal"));
            assert_eq!(before.hash, after.hash);
            assert_eq!(before_seq, state.mempool().read().sequence_number());
            assert_eq!(before_blocks, state.block_log_reader().read().len());
            Ok(())
        }

        #[test]
        fn proposal_without_coinbase_is_bad_cb_missing() -> Result<()> {
            let (_state, mining) = regtest_mining()?;
            mining.publish_generation();
            let genesis = Network::Regtest.genesis_block();
            let mut block = mined_child(genesis.block_hash())?;
            let Some(input) = block.txs.first_mut().and_then(|tx| tx.inputs.first_mut()) else {
                panic!("child missing coinbase input");
            };
            input.previous_output = OutPoint::new(Txid(Hash256::from_le_bytes(&[0x11; 32])), 0);
            block.header.merkle_root = regtest_fixture::merkle_root(&block.txs)
                .ok_or_else(|| TestError::message("test block has no merkle root"))?;
            match propose_block(&mining, block)? {
                BlockValidationResult::Rejected(reason) => {
                    assert_eq!(reason.as_str(), "bad-cb-missing");
                }
                other => panic!("expected bad-cb-missing, got {other:?}"),
            }
            Ok(())
        }

        #[test]
        fn proposal_merkle_mismatch_is_bad_txnmrklroot() -> Result<()> {
            let (_state, mining) = regtest_mining()?;
            mining.publish_generation();
            let genesis = Network::Regtest.genesis_block();
            let mut block = mined_child(genesis.block_hash())?;
            block.header.merkle_root = Hash256::from_le_bytes(&[0x11; 32]);
            match propose_block(&mining, block)? {
                BlockValidationResult::Rejected(reason) => {
                    assert_eq!(reason.as_str(), "bad-txnmrklroot");
                }
                other => panic!("expected bad-txnmrklroot, got {other:?}"),
            }
            Ok(())
        }

        fn signet_child_without_signet_section() -> Result<Block> {
            let commitment =
                bitcoin_rs_consensus::primitives::encode::double_sha256(&[0_u8; 64]).to_le_bytes();
            let mut commitment_script = WITNESS_COMMITMENT_PREFIX.to_vec();
            commitment_script.extend_from_slice(&commitment);
            let genesis = Network::Signet.genesis_block();
            let coinbase = Tx {
                version: 2,
                lock_time: LockTime::ZERO,
                inputs: vec![TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: Script::from_bytes(vec![0x51, 0x00]),
                    sequence: Sequence::MAX,
                    witness: Witness::from_stack(vec![WITNESS_RESERVED.to_vec()]),
                }],
                outputs: vec![
                    TxOut {
                        value: Amount::from_sat(50 * 100_000_000),
                        script_pubkey: Script::from_bytes(vec![0x51]),
                    },
                    TxOut {
                        value: Amount::from_sat(0),
                        script_pubkey: Script::from_bytes(commitment_script),
                    },
                ],
            };
            let mut block = Block {
                header: Header {
                    version: 0x2000_0000,
                    prev_blockhash: genesis.block_hash(),
                    merkle_root: Hash256::default(),
                    time: genesis.header.time + 600,
                    bits: genesis.header.bits,
                    nonce: 0,
                },
                txs: vec![coinbase],
            };
            block.header.merkle_root = block.txs[0].txid().into();
            regtest_fixture::mine_block_to_declared_target(&mut block)?;
            Ok(block)
        }

        #[test]
        fn signet_submit_reports_bad_signet_blksig_and_proposal_skips_the_solution() -> Result<()> {
            let fixture = open_at_genesis(Network::Signet)?;
            let mining = coordinator(&fixture);
            mining.publish_generation();
            let block = signet_child_without_signet_section()?;

            assert_eq!(
                propose_block(&mining, block.clone())?,
                BlockValidationResult::Accepted
            );

            match mining.submit_block(BlockImage::from_local(block))? {
                BlockValidationResult::Rejected(reason) => {
                    assert_eq!(reason.as_str(), "bad-signet-blksig");
                }
                other => panic!("expected bad-signet-blksig, got {other:?}"),
            }

            let tip = fixture
                .chainstate()
                .applied_tip_snapshot()
                .unwrap_or_else(|| panic!("applied tip missing"));
            assert_eq!(
                tip.hash,
                Hash256::from(Network::Signet.genesis_block().block_hash())
            );
            assert!(
                fixture.mempool_gateway().stable_generation().is_some(),
                "a clean block rejection must settle the chain generation"
            );
            Ok(())
        }

        // API-21
        #[test]
        fn proposal_commitment_without_witness_nonce_is_bad_witness_nonce_size() -> Result<()> {
            let (_state, mining) = regtest_mining()?;
            mining.publish_generation();
            let mut block = solved_template_block(&mining)?;
            {
                let Some(input) = block.txs.first_mut().and_then(|tx| tx.inputs.first_mut()) else {
                    panic!("solved candidate missing coinbase input");
                };
                assert!(
                    !input.witness.is_empty(),
                    "assembled candidate must carry the reserved nonce"
                );
                input.witness.clear();
            }
            assert!(
                block.txs.first().is_some_and(|tx| tx
                    .outputs
                    .iter()
                    .any(|output| is_witness_commitment(&output.script_pubkey))),
                "assembled candidate must carry a BIP141 commitment"
            );
            match propose_block(&mining, block)? {
                BlockValidationResult::Rejected(reason) => {
                    assert_eq!(reason.as_str(), "bad-witness-nonce-size");
                }
                other => panic!("expected bad-witness-nonce-size, got {other:?}"),
            }
            Ok(())
        }

        // API-21
        #[test]
        fn proposal_witness_without_commitment_is_unexpected_witness() -> Result<()> {
            let (_state, mining) = regtest_mining()?;
            mining.publish_generation();
            let mut block = solved_template_block(&mining)?;
            {
                let Some(coinbase) = block.txs.first_mut() else {
                    panic!("solved candidate missing coinbase");
                };
                assert!(
                    coinbase
                        .inputs
                        .first()
                        .is_some_and(|input| !input.witness.is_empty()),
                    "assembled candidate must carry the reserved nonce"
                );
                coinbase
                    .outputs
                    .retain(|output| !is_witness_commitment(&output.script_pubkey));
                assert!(
                    !coinbase.outputs.is_empty(),
                    "coinbase must keep a payout output after stripping the commitment"
                );
            }
            block.header.merkle_root = regtest_fixture::merkle_root(&block.txs)
                .ok_or_else(|| TestError::message("test block has no merkle root"))?;
            regtest_fixture::mine_block_to_declared_target(&mut block)?;
            match propose_block(&mining, block)? {
                BlockValidationResult::Rejected(reason) => {
                    assert_eq!(reason.as_str(), "unexpected-witness");
                }
                other => panic!("expected unexpected-witness, got {other:?}"),
            }
            Ok(())
        }

        // API-21
        #[test]
        fn proposal_wrong_witness_commitment_is_bad_witness_merkle_match() -> Result<()> {
            let (_state, mining) = regtest_mining()?;
            mining.publish_generation();
            let mut block = solved_template_block(&mining)?;
            {
                let Some(output) = block.txs.first_mut().and_then(|tx| {
                    tx.outputs
                        .iter_mut()
                        .rev()
                        .find(|output| is_witness_commitment(&output.script_pubkey))
                }) else {
                    panic!("solved candidate missing BIP141 commitment");
                };
                output.script_pubkey[6] ^= 0xff;
            }
            block.header.merkle_root = regtest_fixture::merkle_root(&block.txs)
                .ok_or_else(|| TestError::message("test block has no merkle root"))?;
            regtest_fixture::mine_block_to_declared_target(&mut block)?;
            match propose_block(&mining, block)? {
                BlockValidationResult::Rejected(reason) => {
                    assert_eq!(reason.as_str(), "bad-witness-merkle-match");
                }
                other => panic!("expected bad-witness-merkle-match, got {other:?}"),
            }
            Ok(())
        }

        #[test]
        fn accepted_submission_is_visible_before_return() -> Result<()> {
            let (state, mining) = regtest_mining()?;
            mining.publish_generation();
            let genesis = Network::Regtest.genesis_block();
            let child = mined_child(genesis.block_hash())?;
            let child_hash = child.block_hash();
            let result = mining.submit_block(BlockImage::from_local(child))?;
            assert_eq!(result, BlockValidationResult::Accepted);
            let tip = state
                .chainstate()
                .applied_tip_snapshot()
                .unwrap_or_else(|| panic!("applied tip missing after submit"));
            assert_eq!(tip.hash, Hash256::from(child_hash));
            assert_eq!(tip.height, 1);
            Ok(())
        }

        #[test]
        fn truncated_payload_bytes_fail_construction_before_submit() -> Result<()> {
            use bitcoin_rs_consensus::primitives::{BlockImage, DecodeError, consensus_bytes};
            use bytes::Bytes;
            let (_state, mining) = regtest_mining()?;
            mining.publish_generation();
            let genesis = Network::Regtest.genesis_block();
            let block = mined_child(genesis.block_hash())?;
            let raw = consensus_bytes(&block);
            let truncated = Bytes::from(raw[..raw.len() - 1].to_vec());
            assert!(matches!(
                BlockImage::from_raw(truncated.clone()),
                Err(DecodeError::EndOfData { .. })
            ));
            assert!(matches!(
                BlockImage::from_prefix(truncated),
                Err(DecodeError::EndOfData { .. })
            ));
            assert!(matches!(
                BlockImage::from_raw(Bytes::new()),
                Err(DecodeError::EndOfData { .. })
            ));
            let payload = BlockImage::from_raw(Bytes::from(raw.clone()))?;
            assert_eq!(payload.bytes().len(), raw.len());
            assert_eq!(&payload.materialize(), &block);
            assert_eq!(
                mining.submit_block(payload)?,
                BlockValidationResult::Accepted
            );
            Ok(())
        }

        #[test]
        fn foreign_valid_bytes_apply_as_their_own_block() -> Result<()> {
            use bitcoin_rs_consensus::primitives::{BlockImage, consensus_bytes};
            use bytes::Bytes;
            let (state, mining) = regtest_mining()?;
            mining.publish_generation();
            let genesis = Network::Regtest.genesis_block();
            let other = mined_child_labeled(genesis.block_hash(), 2)?;
            let other_hash = Hash256::from(other.block_hash());
            let foreign = BlockImage::from_raw(Bytes::from(consensus_bytes(&other)))?;
            assert_eq!(&foreign.materialize(), &other);
            assert_eq!(
                mining.submit_block(foreign)?,
                BlockValidationResult::Accepted
            );
            let tip = state
                .chainstate()
                .applied_tip_snapshot()
                .unwrap_or_else(|| panic!("applied tip missing after foreign submit"));
            assert_eq!(tip.hash, other_hash);
            assert_eq!(tip.height, 1);
            Ok(())
        }

        // API-17
        #[test]
        fn submit_block_fills_omitted_coinbase_witness() -> Result<()> {
            let (state, mining) = regtest_mining()?;
            mining.publish_generation();
            let mut block = solved_template_block(&mining)?;
            let Some(input) = block.txs.first_mut().and_then(|tx| tx.inputs.first_mut()) else {
                panic!("solved candidate missing coinbase input");
            };
            assert!(
                !input.witness.is_empty(),
                "assembled candidate must carry the reserved nonce"
            );
            input.witness.clear();
            let has_commitment = block.txs[0]
                .outputs
                .iter()
                .any(|output| is_witness_commitment(&output.script_pubkey));
            assert!(
                has_commitment,
                "assembled candidate must carry a BIP141 commitment"
            );
            let block_hash = block.block_hash();
            assert_eq!(
                mining.submit_block(BlockImage::from_local(block))?,
                BlockValidationResult::Accepted
            );
            let tip = state
                .chainstate()
                .applied_tip_snapshot()
                .unwrap_or_else(|| panic!("applied tip missing after submit"));
            assert_eq!(tip.hash, Hash256::from(block_hash));
            Ok(())
        }

        #[test]
        fn submit_block_accepts_prefill_image_when_fill_applies() -> Result<()> {
            use bitcoin_rs_consensus::primitives::{BlockImage, consensus_bytes};
            use bytes::Bytes;
            let (state, mining) = regtest_mining()?;
            mining.publish_generation();
            let mut block = solved_template_block(&mining)?;
            let Some(input) = block.txs.first_mut().and_then(|tx| tx.inputs.first_mut()) else {
                panic!("solved candidate missing coinbase input");
            };
            assert!(
                !input.witness.is_empty(),
                "assembled candidate must carry the reserved nonce"
            );
            input.witness.clear();
            let has_commitment = block.txs[0]
                .outputs
                .iter()
                .any(|output| is_witness_commitment(&output.script_pubkey));
            assert!(
                has_commitment,
                "assembled candidate must carry a BIP141 commitment"
            );
            let image = Bytes::from(consensus_bytes(&block));
            let payload = BlockImage::from_raw(image.clone())?;
            assert_eq!(payload.bytes(), &image);
            let block_hash = Hash256::from(block.block_hash());
            assert_eq!(
                mining.submit_block(payload)?,
                BlockValidationResult::Accepted
            );
            let tip = state
                .chainstate()
                .applied_tip_snapshot()
                .unwrap_or_else(|| panic!("applied tip missing after prefill submit"));
            assert_eq!(tip.hash, block_hash);
            Ok(())
        }

        // API-13
        #[test]
        fn submit_header_admits_a_mined_child_and_is_idempotent() -> Result<()> {
            let (state, mining) = regtest_mining()?;
            let genesis = Network::Regtest.genesis_block();
            let child = mined_child(genesis.block_hash())?;
            let child_hash = Hash256::from(child.block_hash());
            mining.submit_header(child.header)?;
            mining.submit_header(child.header)?;
            assert!(
                state
                    .chainstate()
                    .block_tree_reader()
                    .read()
                    .lookup(child_hash)
                    .is_some(),
                "submitted header must be in the tree"
            );
            let tip = state
                .chainstate()
                .applied_tip_snapshot()
                .unwrap_or_else(|| panic!("applied tip missing"));
            assert_eq!(
                tip.hash,
                Hash256::from(genesis.block_hash()),
                "header submission must not apply the block"
            );
            Ok(())
        }

        #[test]
        fn submit_header_accepts_genesis_before_and_after_bootstrap() -> Result<()> {
            let state = open_network(Network::Regtest)?;
            let mining = coordinator(&state);
            let genesis = Network::Regtest.genesis_block();
            mining.submit_header(genesis.header)?;
            assert_eq!(
                state.chainstate().header_tip().map(|tip| tip.hash),
                Some(genesis.block_hash().into())
            );
            assert!(state.chainstate().applied_tip_snapshot().is_none());

            let _ =
                state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                    Network::Regtest.genesis_block(),
                ))?;
            let before = state.chainstate().snapshot();

            mining.submit_header(genesis.header)?;
            mining.submit_header(genesis.header)?;

            let after = state.chainstate().snapshot();
            assert_eq!(after.chain_tx_count, before.chain_tx_count);
            assert_eq!(
                after.applied.map(|tip| tip.hash),
                Some(genesis.block_hash().into())
            );
            Ok(())
        }

        #[test]
        fn submit_header_rejects_an_invalid_parent_without_inserting_child() -> Result<()> {
            let (state, mining) = regtest_mining()?;
            let genesis = Network::Regtest.genesis_block();
            let invalid = mined_child(genesis.block_hash())?;
            let child = mined_child(invalid.block_hash())?;
            let tree = state.chainstate().block_tree_reader();
            {
                let mut tree = tree.write();
                let genesis_id = tree
                    .lookup(genesis.block_hash().into())
                    .ok_or_else(|| TestError::message("missing genesis"))?;
                tree.insert_node(
                    Some(genesis_id),
                    invalid.header,
                    bitcoin_rs_chain::chain::NodeStatus::Invalid,
                )?;
            }

            match mining.submit_header(child.header) {
                Err(MiningControlError::Rejected(reason)) => {
                    assert_eq!(reason.as_str(), "bad-prevblk")
                }
                other => panic!("expected invalid-parent rejection, got {other:?}"),
            }
            assert!(tree.read().lookup(child.block_hash().into()).is_none());
            Ok(())
        }

        // API-13
        #[test]
        fn submit_header_requires_the_previous_header() -> Result<()> {
            let (_state, mining) = regtest_mining()?;
            let orphan = mined_child(BlockHash::from(Hash256::from_le_bytes(&[0x11; 32])))?;
            for bits in [orphan.header.bits, CompactTarget::from_consensus(0)] {
                let header = Header {
                    bits,
                    ..orphan.header
                };
                match mining.submit_header(header) {
                    Err(MiningControlError::Rejected(reason)) => {
                        assert_eq!(
                            reason,
                            format!(
                                "Must submit previous header ({}) first",
                                header.prev_blockhash
                            ),
                            "missing-parent rejection must precede proof-of-work validation"
                        );
                    }
                    other => panic!("expected missing-prev rejection, got {other:?}"),
                }
            }
            Ok(())
        }

        #[test]
        fn submit_header_rejects_bad_diffbits() -> Result<()> {
            let (_state, mining) = regtest_mining()?;
            let genesis = Network::Regtest.genesis_block();
            let mut child = mined_child(genesis.block_hash())?;
            child.header.bits = CompactTarget::from_consensus(0x207f_fffe);
            regtest_fixture::mine_block_to_declared_target(&mut child)?;
            match mining.submit_header(child.header) {
                Err(MiningControlError::Rejected(reason)) => {
                    assert_eq!(reason.as_str(), "bad-diffbits");
                }
                other => panic!("expected bad-diffbits, got {other:?}"),
            }
            Ok(())
        }

        #[test]
        fn overflowed_nbits_answers_high_hash_on_submitheader_and_submitblock() -> Result<()> {
            let (_state, mining) = regtest_mining()?;
            let genesis = Network::Regtest.genesis_block();
            let mut child = mined_child(genesis.block_hash())?;
            child.header.bits = CompactTarget::from_consensus(0x2300_0001);
            match mining.submit_header(child.header) {
                Err(MiningControlError::Rejected(reason)) => {
                    assert_eq!(reason.as_str(), "high-hash");
                }
                other => panic!("expected submitheader high-hash, got {other:?}"),
            }
            match mining.submit_block(BlockImage::from_local(child))? {
                BlockValidationResult::Rejected(reason) => {
                    assert_eq!(reason.as_str(), "high-hash");
                }
                other => panic!("expected submitblock high-hash, got {other:?}"),
            }
            Ok(())
        }

        #[test]
        fn submit_header_rejects_time_too_new() -> Result<()> {
            let (_state, mining) = regtest_mining()?;
            let genesis = Network::Regtest.genesis_block();
            let mut child = mined_child(genesis.block_hash())?;
            child.header.time = u32::MAX;
            regtest_fixture::mine_block_to_declared_target(&mut child)?;
            match mining.submit_header(child.header) {
                Err(MiningControlError::Rejected(reason)) => {
                    assert_eq!(reason.as_str(), "time-too-new");
                }
                other => panic!("expected time-too-new, got {other:?}"),
            }
            Ok(())
        }

        #[test]
        fn submit_header_rejects_bad_version_after_bip34_activation() -> Result<()> {
            let (_state, mining) = regtest_mining()?;
            let genesis = Network::Regtest.genesis_block();
            let base_time = genesis.header.time;
            let mut prev = genesis.block_hash();
            for height in 1..=499_u32 {
                let header = mined_regtest_header(prev, base_time + height * 600, 1);
                mining.submit_header(header)?;
                prev = header.compute_hash();
            }
            let rejected = mined_regtest_header(prev, base_time + 500 * 600, 1);
            match mining.submit_header(rejected) {
                Err(MiningControlError::Rejected(reason)) => {
                    assert_eq!(reason.as_str(), "bad-version(0x00000001)");
                }
                other => panic!("expected bad-version rejection, got {other:?}"),
            }
            let accepted = mined_regtest_header(prev, base_time + 500 * 600, 2);
            mining.submit_header(accepted)?;
            Ok(())
        }

        #[test]
        fn rejection_mapping_for_bad_prev_hash() -> Result<()> {
            let (_state, mining) = regtest_mining()?;
            let mut block = mined_child(BlockHash::from(Hash256::from_le_bytes(&[0x11; 32])))?;
            block.header.merkle_root = regtest_fixture::merkle_root(&block.txs)
                .ok_or_else(|| TestError::message("test block has no merkle root"))?;
            block.header.nonce = 0;
            regtest_fixture::mine_block_to_declared_target(&mut block)?;
            let result = mining.submit_block(BlockImage::from_local(block))?;
            match result {
                BlockValidationResult::Rejected(reason) => {
                    assert!(
                        reason.contains("inconclusive-not-best-prevblk") || reason.contains("prev"),
                        "unexpected rejection reason: {reason}"
                    );
                }
                other => panic!("expected rejection, got {other:?}"),
            }
            Ok(())
        }

        #[test]
        fn concurrent_duplicate_submissions_leave_admission_open() -> Result<()> {
            let (state, mining) = regtest_mining()?;
            let child = mined_child(Network::Regtest.genesis_block().block_hash())?;
            let start = std::sync::Barrier::new(3);
            let outcomes = thread::scope(|scope| {
                let submit = || {
                    start.wait();
                    mining.submit_block(BlockImage::from_local(child.clone()))
                };
                let first = scope.spawn(submit);
                let second = scope.spawn(submit);
                start.wait();
                [
                    first
                        .join()
                        .unwrap_or_else(|error| std::panic::resume_unwind(error)),
                    second
                        .join()
                        .unwrap_or_else(|error| std::panic::resume_unwind(error)),
                ]
            });
            let [first, second] = outcomes;
            let results = [first?, second?];
            assert!(results.contains(&BlockValidationResult::Accepted));
            assert!(results.contains(&BlockValidationResult::Duplicate));
            assert!(state.mempool_gateway().stable_generation().is_some());
            assert_eq!(state.chainstate().chain_snapshot().tip_height, 1);
            let mut next = mined_child_labeled(child.block_hash(), 2)?;
            next.header.time = child.header.time + 1;
            regtest_fixture::mine_block_to_declared_target(&mut next)?;
            assert_eq!(
                mining.submit_block(BlockImage::from_local(next))?,
                BlockValidationResult::Accepted,
                "a racing duplicate must not poison the next valid submission"
            );
            Ok(())
        }

        #[test]
        fn unsolved_pow_is_rejected_by_proposal_and_submit() -> Result<()> {
            let (state, mining) = regtest_mining()?;
            mining.publish_generation();
            let genesis = Network::Regtest.genesis_block();
            let mut block = mined_child(genesis.block_hash())?;
            while compact_is_met_by(block.header.bits, block.block_hash().into()) {
                block.header.nonce =
                    block.header.nonce.checked_add(1).ok_or_else(|| {
                        TestError::message("nonce exhausted while invalidating PoW")
                    })?;
            }
            let proposal = mining.get_block_template(BlockTemplateRequest {
                mode: BlockTemplateMode::Proposal(block.clone()),
                capabilities: Vec::new(),
                rules: Vec::new(),
                long_poll_id: None,
                coinbase_budget: None,
            })?;
            match proposal {
                BlockTemplateResult::Proposal(BlockValidationResult::Accepted) => {}
                other => panic!("BIP22 proposal must omit unsolved PoW, got {other:?}"),
            }
            match mining.submit_block(BlockImage::from_local(block))? {
                BlockValidationResult::Rejected(reason) => {
                    assert!(reason.contains("high-hash"), "submit reason: {reason}");
                }
                other => panic!("expected submit high-hash, got {other:?}"),
            }
            assert!(
                state.mempool_gateway().stable_generation().is_some(),
                "a clean block rejection must settle the chain generation"
            );
            assert!(!state.chainstate().shutdown_reader().is_triggered());
            Ok(())
        }

        #[test]
        fn duplicate_solved_submission_is_idempotent() -> Result<()> {
            let (state, mining) = regtest_mining()?;
            mining.publish_generation();
            let genesis = Network::Regtest.genesis_block();
            let child = mined_child(genesis.block_hash())?;
            assert_eq!(
                mining.submit_block(BlockImage::from_local(child.clone()))?,
                BlockValidationResult::Accepted
            );
            let height = state
                .chainstate()
                .applied_tip_snapshot()
                .map_or(0, |tip| tip.height);
            assert_eq!(
                mining.submit_block(BlockImage::from_local(child))?,
                BlockValidationResult::Duplicate
            );
            assert_eq!(
                state
                    .chainstate()
                    .applied_tip_snapshot()
                    .map_or(0, |tip| tip.height),
                height,
                "duplicate solved submission must not reapply"
            );
            Ok(())
        }

        // API-18
        #[test]
        fn proposal_of_an_applied_block_is_duplicate() -> Result<()> {
            let (_state, mining) = regtest_mining()?;
            mining.publish_generation();
            let genesis = Network::Regtest.genesis_block();
            assert_eq!(
                propose_block(&mining, genesis)?,
                BlockValidationResult::Duplicate
            );
            Ok(())
        }

        // API-18
        #[test]
        fn proposal_of_an_invalid_header_is_duplicate_invalid() -> Result<()> {
            let (state, mining) = regtest_mining()?;
            mining.publish_generation();
            let genesis = Network::Regtest.genesis_block();
            let genesis_hash = genesis.block_hash();
            let invalid = mined_child_labeled(genesis.block_hash(), 2)?;
            {
                let tree = state.chainstate().block_tree_reader();
                let genesis_id = tree
                    .read()
                    .lookup(Hash256::from(genesis_hash))
                    .ok_or_else(|| TestError::message("missing genesis"))?;
                tree.write()
                    .insert_node(Some(genesis_id), invalid.header, NodeStatus::Invalid)?;
            }
            assert_eq!(
                propose_block(&mining, invalid)?,
                BlockValidationResult::DuplicateInvalid
            );
            Ok(())
        }

        // API-18
        #[test]
        fn proposal_of_a_header_only_block_is_duplicate_inconclusive() -> Result<()> {
            let (state, mining) = regtest_mining()?;
            mining.publish_generation();
            let genesis = Network::Regtest.genesis_block();
            let genesis_hash = Hash256::from_le_bytes(genesis.block_hash().as_bytes());
            let side = mined_child_labeled(genesis.block_hash(), 3)?;
            {
                let tree = state.chainstate().block_tree_reader();
                let genesis_id = tree
                    .read()
                    .lookup(genesis_hash)
                    .ok_or_else(|| TestError::message("missing genesis"))?;
                tree.write()
                    .insert_node(Some(genesis_id), side.header, NodeStatus::HeaderValid)?;
            }
            assert_eq!(
                propose_block(&mining, side)?,
                BlockValidationResult::DuplicateInconclusive
            );
            Ok(())
        }

        #[test]
        fn proposal_of_a_disconnected_scripts_valid_block_is_duplicate() -> Result<()> {
            let (state, mining) = regtest_mining()?;
            mining.publish_generation();
            let genesis = Network::Regtest.genesis_block();
            let child = mined_child(genesis.block_hash())?;
            let child_hash = Hash256::from(child.block_hash());
            assert_eq!(
                mining.submit_block(BlockImage::from_local(child.clone()))?,
                BlockValidationResult::Accepted
            );
            disconnect_applied(&state, &child)?;
            let chain_tx_count = {
                let tree = state.chainstate().block_tree_reader();
                tree.read()
                    .node_by_hash(child_hash)
                    .ok_or_else(|| TestError::message("disconnected child missing from tree"))?
                    .chain_tx_count
            };
            assert_eq!(
                chain_tx_count.get(),
                Some(2),
                "disconnect must keep the scripts-valid chain_tx_count"
            );
            let tip = state
                .chainstate()
                .applied_tip_snapshot()
                .unwrap_or_else(|| panic!("applied tip missing after disconnect"));
            assert_eq!(tip.hash, Hash256::from(genesis.block_hash()));
            assert_eq!(
                propose_block(&mining, child)?,
                BlockValidationResult::Duplicate
            );
            Ok(())
        }

        #[test]
        fn submit_of_a_disconnected_scripts_valid_block_is_duplicate() -> Result<()> {
            let (state, mining) = regtest_mining()?;
            mining.publish_generation();
            let genesis = Network::Regtest.genesis_block();
            let genesis_hash = Hash256::from(genesis.block_hash());
            let child = mined_child(genesis.block_hash())?;
            assert_eq!(
                mining.submit_block(BlockImage::from_local(child.clone()))?,
                BlockValidationResult::Accepted
            );
            disconnect_applied(&state, &child)?;
            assert_eq!(
                mining.submit_block(BlockImage::from_local(child))?,
                BlockValidationResult::Duplicate
            );
            let tip = state
                .chainstate()
                .applied_tip_snapshot()
                .unwrap_or_else(|| panic!("applied tip missing after duplicate submit"));
            assert_eq!(tip.hash, genesis_hash);
            Ok(())
        }

        #[test]
        fn applied_ancestor_with_unset_chain_tx_count_is_duplicate() -> Result<()> {
            let (state, mining) = regtest_mining()?;
            mining.publish_generation();
            let genesis = Network::Regtest.genesis_block();
            let genesis_hash = Hash256::from(genesis.block_hash());
            let child = mined_child(genesis.block_hash())?;
            assert_eq!(
                mining.submit_block(BlockImage::from_local(child))?,
                BlockValidationResult::Accepted
            );
            {
                let tree = state.chainstate().block_tree_reader();
                let mut tree = tree.write();
                let genesis_id = tree
                    .lookup(genesis_hash)
                    .ok_or_else(|| TestError::message("missing genesis"))?;
                tree.restore_chain_tx_count(
                    genesis_id,
                    bitcoin_rs_chain::chain::ChainTxCount::UNKNOWN,
                )?;
            }
            assert_eq!(
                propose_block(&mining, genesis.clone())?,
                BlockValidationResult::Duplicate
            );
            assert_eq!(
                mining.submit_block(BlockImage::from_local(genesis))?,
                BlockValidationResult::Duplicate
            );
            Ok(())
        }

        #[test]
        fn submit_block_applies_a_header_already_in_the_tree() -> Result<()> {
            let (state, mining) = regtest_mining()?;
            mining.publish_generation();
            let genesis = Network::Regtest.genesis_block();
            let child = mined_child(genesis.block_hash())?;
            let child_hash = Hash256::from(child.block_hash());
            mining.submit_header(child.header)?;
            assert_eq!(
                mining.submit_block(BlockImage::from_local(child))?,
                BlockValidationResult::Accepted
            );
            let tip = state
                .chainstate()
                .applied_tip_snapshot()
                .unwrap_or_else(|| panic!("applied tip missing after submit"));
            assert_eq!(tip.hash, child_hash);
            Ok(())
        }

        #[test]
        fn active_ancestor_submit_is_duplicate() -> Result<()> {
            let (_state, mining) = regtest_mining()?;
            mining.publish_generation();
            let genesis = Network::Regtest.genesis_block();
            let child = mined_child(genesis.block_hash())?;
            assert_eq!(
                mining.submit_block(BlockImage::from_local(child))?,
                BlockValidationResult::Accepted
            );
            assert_eq!(
                mining.submit_block(BlockImage::from_local(genesis))?,
                BlockValidationResult::Duplicate
            );
            Ok(())
        }
    }

    mod template {
        use bitcoin_rs_node::test_support::TestError;

        type Result<T, E = TestError> = core::result::Result<T, E>;
        use bitcoin_rs_consensus::primitives::Hash256;
        use bitcoin_rs_node::Network;
        use bitcoin_rs_wire::mining::{
            BlockTemplateMode, BlockTemplateRequest, BlockValidationResult, CoinbaseBudget,
            MiningCapability, MiningControl, MiningControlError, TemplateId, solve_block,
        };

        use super::support::{
            budgeted_template_request, coordinator, expect_template, open_at_genesis,
            propose_block, regtest_mining, template_request,
        };

        // API-20
        #[test]
        fn template_does_not_echo_client_capabilities() -> Result<()> {
            let (_state, mining) = regtest_mining()?;
            mining.publish_generation();
            let template = expect_template(mining.get_block_template(BlockTemplateRequest {
                mode: BlockTemplateMode::Template,
                capabilities: vec![
                    MiningCapability::new("coinbasetxn"),
                    MiningCapability::new("unknown-client-only"),
                    MiningCapability::new("proposal"),
                ],
                rules: Vec::new(),
                long_poll_id: None,
                coinbase_budget: None,
            })?);
            assert_eq!(
                template
                    .capabilities
                    .iter()
                    .map(MiningCapability::as_str)
                    .collect::<Vec<_>>(),
                vec!["proposal", "longpoll"]
            );
            assert_eq!(template.version_bits_required, 0);
            assert!(template.signet.is_none());
            Ok(())
        }

        #[test]
        fn signet_template_includes_challenge_and_signet_rule() -> Result<()> {
            let state = open_at_genesis(Network::Signet)?;
            let mining = coordinator(&state);
            mining.publish_generation();
            let template = expect_template(mining.get_block_template(template_request(None))?);
            assert!(template.rules.iter().any(|rule| rule.as_str() == "signet"));
            assert!(template.signet.is_some());
            Ok(())
        }

        #[test]
        fn budgeted_request_reaches_the_selector_and_yields_a_valid_block() -> Result<()> {
            let (state, mining) = regtest_mining()?;
            mining.publish_generation();
            let budget = CoinbaseBudget {
                additional_size: 4_000,
                additional_sigops: 100,
            };
            let budgeted =
                expect_template(mining.get_block_template(budgeted_template_request(budget))?);
            budgeted.candidate.admits(budget)?;

            let ordinary = expect_template(mining.get_block_template(template_request(None))?);
            let genesis_hash = Hash256::from(Network::Regtest.genesis_block().block_hash());
            let sequence = state.mempool().read().sequence_number();
            assert_eq!(
                ordinary.candidate.template_id,
                TemplateId::new(&genesis_hash, sequence)
            );
            assert_ne!(
                budgeted.candidate.template_id,
                ordinary.candidate.template_id
            );
            assert!(
                budgeted
                    .candidate
                    .template_id
                    .as_str()
                    .starts_with(ordinary.candidate.template_id.as_str())
            );

            let mut block = budgeted.candidate.into_unsolved_block()?;
            solve_block(&mut block, 1_000_000)?;
            assert_eq!(
                propose_block(&mining, block)?,
                BlockValidationResult::Accepted
            );
            Ok(())
        }

        #[test]
        fn unsatisfiable_budget_is_the_existing_failed_error_and_ordinary_templates_keep_working()
        -> Result<()> {
            let (_state, mining) = regtest_mining()?;
            mining.publish_generation();
            let impossible = CoinbaseBudget {
                additional_size: u32::MAX,
                additional_sigops: u16::MAX,
            };
            let refused = mining.get_block_template(budgeted_template_request(impossible));
            assert!(
                matches!(
                    &refused,
                    Err(MiningControlError::Failed(message))
                        if message.contains("exhausts the weight limit")
                ),
                "{refused:?}"
            );
            expect_template(mining.get_block_template(template_request(None))?);
            Ok(())
        }
    }
}
mod overhaul_durable_head {
    use std::sync::Arc;

    use bitcoin_rs_node::test_support::TestError;

    type Result<T, E = TestError> = core::result::Result<T, E>;

    use bitcoin_rs_chain::chain::regtest_fixture;
    use bitcoin_rs_node::{Network, NodeConfig, state::NodeState};

    use bitcoin_rs_consensus::primitives::{BlockHash, Hash256};

    use bitcoin_rs_storage::block_body::{BlockBodyStore, IndexedBlockBodyStore};
    use bitcoin_rs_storage::durable_head::{DURABLE_HEAD_FORMAT_VERSION, DURABLE_HEAD_KEY};
    use bitcoin_rs_storage::pruning::block_undo_key;
    use bitcoin_rs_storage::undo::UndoStore;
    use bitcoin_rs_storage::{
        ColumnFamily, DurableHead, DurableHeadStore, FlatFileBlockStore, KvDurableHeadStore,
        KvStore, KvUndoStore, PersistFault,
    };

    const ALL_FAULTS: &[PersistFault] = &[
        PersistFault::FailApply,
        PersistFault::LostApply,
        PersistFault::PartialApply,
        PersistFault::FailSync,
        PersistFault::LostSync,
        PersistFault::FailFlush,
        PersistFault::LostFlush,
    ];

    struct ChainFamily {
        store: Arc<bitcoin_rs_storage::RocksDbStore>,
        _files: Arc<FlatFileBlockStore>,
        bodies: Arc<IndexedBlockBodyStore<bitcoin_rs_storage::RocksDbStore>>,
        undo: KvUndoStore<bitcoin_rs_storage::RocksDbStore>,
        head: KvDurableHeadStore<bitcoin_rs_storage::RocksDbStore>,
        authority: bitcoin_rs_storage::CommitAuthority,
    }

    fn open_family(data_dir: &std::path::Path) -> Result<ChainFamily> {
        let store = Arc::new(bitcoin_rs_storage::RocksDbStore::open_with_cache(
            data_dir.join("chainstate"),
            0,
        )?);
        let head = KvDurableHeadStore::new(Arc::clone(&store));
        let files = Arc::new(match head.load()?.and_then(|head| head.body_extent) {
            Some(extent) => FlatFileBlockStore::open_with_committed_extent(data_dir, extent)?,
            None => FlatFileBlockStore::open(data_dir)?,
        });
        let bodies = Arc::new(IndexedBlockBodyStore::new(
            Arc::clone(&store),
            Arc::clone(&files),
        ));
        let undo = KvUndoStore::new(Arc::clone(&store));
        let dyn_store: Arc<dyn KvStore> = store.clone();
        let coins = Arc::new(bitcoin_rs_storage::CoinStore::open(
            Arc::clone(&dyn_store),
            1024 * 1024,
        ));
        let authority = bitcoin_rs_storage::CommitAuthority::new(dyn_store, coins);
        Ok(ChainFamily {
            store,
            _files: files,
            bodies,
            undo,
            head,
            authority,
        })
    }

    fn hash_of(seed: u8) -> Hash256 {
        Hash256::from_le_bytes(&[seed; 32])
    }

    fn assert_whole_state(
        data_dir: &std::path::Path,
        old_head: &DurableHead,
        new_head: &DurableHead,
        batch_rows: &[(ColumnFamily, Vec<u8>, bool)],
        context: &str,
    ) -> Result<()> {
        let family = open_family(data_dir)?;
        let stored = family
            .head
            .load()?
            .ok_or_else(|| TestError::message(format!("{context}: head row vanished")))?;
        if stored != *old_head && stored != *new_head {
            return Err(TestError::message(format!(
                "{context}: head is neither the old nor the new state: {stored:?}"
            )));
        }
        let rolled_forward = stored == *new_head;
        for (cf, key, present_in_new_state) in batch_rows {
            let present = family.store.get(*cf, key)?.is_some();
            let expected = if rolled_forward {
                *present_in_new_state
            } else {
                !*present_in_new_state
            };
            assert_eq!(
                present, expected,
                "{context}: batch row presence {present} disagrees with head rolled_forward={rolled_forward}"
            );
        }
        Ok(())
    }

    #[test]
    fn connect_batch_faults_leave_old_or_new_across_families() -> Result<()> {
        for fault in ALL_FAULTS {
            let temp = tempfile::tempdir()?;
            let data_dir = temp.path().to_path_buf();
            let family = open_family(&data_dir)?;

            let body_one = b"body-one";
            family.bodies.persist_block_body(1, hash_of(1), body_one)?;
            let position_one = family
                .bodies
                .block_position(1, hash_of(1))?
                .ok_or_else(|| TestError::message("family lost its own locator"))?;
            let old_head = DurableHead {
                assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
                commit_id: 1,
                height: 1,
                tip: hash_of(1),
                chain_tx_count: 1,
                body_extent: family.bodies.append_cursor(),
                undo_extent: Some((1, hash_of(1))),
            };
            let undo_one = vec![1_u8; 8];
            family
                .authority
                .commit_prefix(bitcoin_rs_storage::AcceptedPrefix {
                    expected_head: None,
                    next_head: old_head,
                    undo_rows: vec![(1, hash_of(1), bytes::Bytes::from(undo_one.clone()))],
                    body_rows: vec![(1, hash_of(1), position_one)],
                    attestation: None,
                    coin_delta: bitcoin_rs_storage::WindowDelta::default(),
                })
                .map_err(|error| TestError::message(error.to_string()))?;

            let body_two = b"body-two";
            family.bodies.persist_block_body(2, hash_of(2), body_two)?;
            let position_two = family
                .bodies
                .block_position(2, hash_of(2))?
                .ok_or_else(|| TestError::message("family lost its own locator"))?;
            let new_head = DurableHead {
                assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
                commit_id: 2,
                height: 2,
                tip: hash_of(2),
                chain_tx_count: 2,
                body_extent: family.bodies.append_cursor(),
                undo_extent: Some((2, hash_of(2))),
            };
            let undo_two = vec![2_u8; 8];
            family.store.arm_persist_fault(*fault);
            let outcome = family
                .authority
                .commit_prefix(bitcoin_rs_storage::AcceptedPrefix {
                    expected_head: Some(old_head),
                    next_head: new_head,
                    undo_rows: vec![(2, hash_of(2), bytes::Bytes::from(undo_two.clone()))],
                    body_rows: vec![(2, hash_of(2), position_two)],
                    attestation: None,
                    coin_delta: bitcoin_rs_storage::WindowDelta::default(),
                });
            drop(family);

            let _ = outcome;
            assert_whole_state(
                &data_dir,
                &old_head,
                &new_head,
                &[(
                    ColumnFamily::UndoData,
                    block_undo_key(2, hash_of(2)).to_vec(),
                    true,
                )],
                &format!("fault {fault:?}"),
            )?;
        }
        Ok(())
    }

    #[test]
    fn disconnect_batch_faults_leave_old_or_new_across_families() -> Result<()> {
        for fault in ALL_FAULTS {
            let temp = tempfile::tempdir()?;
            let data_dir = temp.path().to_path_buf();
            let family = open_family(&data_dir)?;
            family
                .bodies
                .persist_block_body(1, hash_of(1), b"committed-body")?;
            family.bodies.sync()?;
            let committed = DurableHead {
                assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
                commit_id: 1,
                height: 1,
                tip: hash_of(1),
                chain_tx_count: 1,
                body_extent: family.bodies.append_cursor(),
                undo_extent: Some((1, hash_of(1))),
            };
            let coin_key = bitcoin_rs_storage::CoinKey([0x42_u8; 32]);
            let mut created = bitcoin_rs_storage::WindowDelta::default();
            created.push_final(coin_key, Some(bytes::Bytes::from_static(b"coin-row")));
            family
                .authority
                .commit_prefix(bitcoin_rs_storage::AcceptedPrefix {
                    expected_head: None,
                    next_head: committed,
                    undo_rows: Vec::new(),
                    body_rows: Vec::new(),
                    attestation: None,
                    coin_delta: created,
                })
                .map_err(|error| TestError::message(error.to_string()))?;

            let parent = DurableHead {
                assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
                commit_id: committed.commit_id + 1,
                height: 0,
                tip: Hash256::from_le_bytes(&[0_u8; 32]),
                chain_tx_count: committed.chain_tx_count,
                body_extent: committed.body_extent,
                undo_extent: committed.undo_extent,
            };
            let mut removed = bitcoin_rs_storage::WindowDelta::default();
            removed.push_final(coin_key, None);
            family.store.arm_persist_fault(*fault);
            let outcome = family
                .authority
                .commit_disconnect(&committed, &parent, removed);
            drop(family);

            match fault {
                PersistFault::FailApply
                | PersistFault::LostApply
                | PersistFault::PartialApply
                | PersistFault::FailSync
                | PersistFault::LostSync => match outcome {
                    Err(bitcoin_rs_storage::CommitError::Storage(
                        bitcoin_rs_storage::StorageError::Io(_),
                    )) => {}
                    Err(other) => {
                        panic!(
                            "fault {fault:?}: expected the injected StorageError::Io, got {other:?}"
                        )
                    }
                    Ok(receipt) => panic!(
                        "fault {fault:?}: armed fault was not consumed at the commit boundary; \
                         commit succeeded with receipt {receipt:?}"
                    ),
                },
                PersistFault::FailFlush | PersistFault::LostFlush => {
                    let receipt = outcome.unwrap_or_else(|error| {
                        panic!(
                            "fault {fault:?}: disconnect commit must complete despite an armed \
                         flush-boundary fault; got {error:?}"
                        )
                    });
                    assert_eq!(receipt.commit_id(), parent.commit_id);
                    assert_eq!(receipt.tip(), parent.tip);
                    assert_eq!(receipt.height(), parent.height);
                }
            }
            assert_whole_state(
                &data_dir,
                &committed,
                &parent,
                &[(ColumnFamily::Coins, coin_key.as_bytes().to_vec(), false)],
                &format!("disconnect fault {fault:?}"),
            )?;
        }
        Ok(())
    }

    fn test_config(data_dir: std::path::PathBuf) -> NodeConfig {
        let mut config = NodeConfig::default_for_network(Network::Regtest);
        config.data_dir = data_dir;
        config.p2p.listen.clear();
        config
    }

    #[test]
    fn durable_head_precedes_publication_and_survives_restart() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let data_dir = temp.path().join("protocol-node");
        let genesis = Network::Regtest.genesis_block();

        let state = NodeState::open(test_config(data_dir.clone()), None)?;
        let mut tip = state.apply_block(
            &bitcoin_rs_consensus::primitives::BlockImage::from_local(genesis),
        )?;
        let mut blocks = Vec::new();
        for height in 1..=3_u32 {
            let block = regtest_fixture::mined_regtest_child_at(BlockHash(tip.hash), height)?;
            tip = state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                block.clone(),
            ))?;
            blocks.push(block);
        }
        let _ = state.publish_checkpoint()?;
        drop(state);

        let family = open_family(&data_dir)?;
        let head = family
            .head
            .load()?
            .ok_or_else(|| TestError::message("a committed chain must leave a durable head"))?;
        assert_eq!(head.height, 3);
        assert_eq!(head.tip, tip.hash);
        assert_eq!(head.commit_id, 4, "genesis plus three blocks advance 1..=4");
        assert_eq!(head.chain_tx_count, 4, "genesis plus three coinbases");
        assert_eq!(head.undo_extent, Some((3, tip.hash)));
        assert!(head.body_extent.is_some(), "flat files back the head");
        for (index, block) in blocks.iter().enumerate() {
            let height = u32::try_from(index + 1)?;
            let block_hash = Hash256::from(block.block_hash());
            let stored_undo = family.undo.load_undo(height, block_hash)?;
            assert!(
                stored_undo.is_some(),
                "undo row for height {height} missing"
            );
            let stored_body = family.bodies.load_block_body(height, block_hash)?;
            assert_eq!(
                stored_body.as_deref(),
                Some(bitcoin_rs_consensus::primitives::consensus_bytes(block).as_slice()),
                "committed body bytes must be reachable through the block files"
            );
        }
        drop(family);

        let resumed = NodeState::open(test_config(data_dir.clone()), None)?;
        let restored = resumed
            .chainstate()
            .applied_tip_snapshot()
            .ok_or_else(|| TestError::message("restart must restore an applied tip"))?;
        assert_eq!(restored.hash, tip.hash);
        let block4 = regtest_fixture::mined_regtest_child_at(BlockHash(restored.hash), 4)?;
        let new_tip = resumed.apply_block(
            &bitcoin_rs_consensus::primitives::BlockImage::from_local(block4),
        )?;
        assert_eq!(new_tip.height, 4);
        drop(resumed);

        let family = open_family(&data_dir)?;
        let head = family
            .head
            .load()?
            .ok_or_else(|| TestError::message("head vanished"))?;
        assert_eq!(head.commit_id, 5, "commit ids continue across restarts");
        assert_eq!(head.tip, new_tip.hash);
        Ok(())
    }

    #[test]
    fn corrupt_head_rows_fail_startup_fail_closed() -> Result<()> {
        for corruption in ["truncate", "flip-payload-bit", "wrong-version"] {
            let temp = tempfile::tempdir()?;
            let data_dir = temp.path().join("corrupt-node");
            let genesis = Network::Regtest.genesis_block();
            let state = NodeState::open(test_config(data_dir.clone()), None)?;
            state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                genesis,
            ))?;
            drop(state);

            let raw = Arc::new(bitcoin_rs_storage::RocksDbStore::open_with_cache(
                data_dir.join("chainstate"),
                0,
            )?);
            let frame = raw
                .get(ColumnFamily::UtxoMeta, DURABLE_HEAD_KEY)?
                .ok_or_else(|| TestError::message("head row must exist"))?;
            let corrupted = match corruption {
                "truncate" => frame[..frame.len() - 1].to_vec(),
                "flip-payload-bit" => {
                    let mut frame = frame;
                    let last = frame.len() - 1;
                    frame[last] ^= 0x80;
                    frame
                }
                "wrong-version" => {
                    let mut frame = frame;
                    frame[4] = DURABLE_HEAD_FORMAT_VERSION + 1;
                    frame
                }
                other => return Err(TestError::message(format!("unknown corruption {other}"))),
            };
            raw.put(ColumnFamily::UtxoMeta, DURABLE_HEAD_KEY, &corrupted)?;
            drop(raw);

            let block_path = data_dir.join("blocks/blk00000.dat");
            let mut block_bytes = std::fs::read(&block_path)?;
            block_bytes.extend_from_slice(b"BR");
            std::fs::write(&block_path, &block_bytes)?;
            let reopened = NodeState::open(test_config(data_dir), None);
            assert!(
                reopened.is_err(),
                "corruption {corruption} must fail startup, got a node"
            );
            assert_eq!(std::fs::read(&block_path)?, block_bytes);
        }
        Ok(())
    }
}
mod overhaul_fee_history {
    #![expect(clippy::expect_used, reason = "test assertions")]

    use std::sync::Arc;

    use bitcoin_rs_node::test_support::TestError;

    type Result<T, E = TestError> = core::result::Result<T, E>;

    use crate::support::{p2sh_true_output, p2sh_true_spend_script_sig, parent_txid};
    use bitcoin_rs_chain::chain::regtest_fixture::{self, REGTEST_BITS};
    use bitcoin_rs_consensus::primitives::{
        Amount, Block, CompactTarget, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn,
        TxOut, Txid, Witness, unix_time_secs,
    };
    use bitcoin_rs_consensus::script::push_int;
    use bitcoin_rs_mempool::{AdmissionOrigin, FeeEstimator, SubmitOutcome};
    use bitcoin_rs_node::state::NodeState;
    use bitcoin_rs_node::{Network, NodeConfig};
    use bitcoin_rs_storage::utxo::contract::{BlockChanges, UtxoAdd};
    use bitcoin_rs_wire::context::ChainAdmissionView;

    const BASE_TIME: u32 = 1_296_688_603;
    const BLOCK_INTERVAL: u32 = 600;
    const REGTEST_SUBSIDY_SATS: u64 = 50 * 100_000_000;
    const PARENT_VALUE_SATS: u64 = 50_000;
    const HIGH_FEE_SATS: u64 = 30_000;
    const LOW_FEE_SATS: u64 = 500;
    const REPLACEMENT_FEE_SATS: u64 = 30_000;
    const EVICT_THRESHOLD_SAT_PER_KVB: u64 = 10_000;
    const HISTORY_FILE: &str = "fee-estimator-history.dat";

    fn open_regtest() -> Result<(NodeState, tempfile::TempDir)> {
        let dir = tempfile::tempdir()?;
        let mut config = NodeConfig::default_for_network(Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p.listen.clear();
        let state = NodeState::open(config, None)?;
        Ok((state, dir))
    }

    fn reopen(config: NodeConfig) -> Result<NodeState> {
        Ok(NodeState::open(config, None)?)
    }

    fn apply_genesis(state: &NodeState) -> Result<()> {
        state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
            Network::Regtest.genesis_block(),
        ))?;
        Ok(())
    }

    fn fund_utxo(state: &NodeState, parent: Txid, value: u64) -> Result<()> {
        let mut changes = BlockChanges::with_capacity(1, 0);
        changes.add(UtxoAdd::new(
            OutPoint::new(parent, 0),
            TxOut {
                value: Amount::from_sat(value),
                script_pubkey: p2sh_true_output(),
            },
            false,
            0,
        ));
        bitcoin_rs_storage::utxo::contract::populate_block_changes(
            state.chainstate().coins(),
            &changes,
        )
        .map_err(|error| TestError::message(format!("utxo commit failed: {error}")))
    }

    fn spending_tx(parent: Txid, fee_sats: u64, sequence: u32) -> Tx {
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(parent, 0),
                script_sig: p2sh_true_spend_script_sig(),
                sequence: Sequence::from_consensus(sequence),
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(PARENT_VALUE_SATS - fee_sats),
                script_pubkey: Script::from_bytes(vec![0x6A, 0x04, 0xAA, 0xBB, 0xCC, 0xDD]),
            }],
            lock_time: LockTime::ZERO,
        }
    }

    fn admit(state: &NodeState, tx: Tx) -> Result<SubmitOutcome> {
        let view = ChainAdmissionView::new(
            state.chainstate().utxo_reader(),
            state.chainstate().applied_tip_reader(),
            state.chainstate().block_tree_reader(),
            Network::Regtest,
        );
        state
            .mempool_gateway()
            .submit_transaction(
                Arc::new(tx),
                AdmissionOrigin::Rpc,
                None,
                unix_time_secs(),
                &view,
            )
            .map_err(|error| TestError::message(format!("admission failed: {error}")))
    }

    fn mine_and_apply(
        state: &NodeState,
        prev: Hash256,
        height: u32,
        time_salt: u32,
        txs: Vec<Tx>,
    ) -> Result<Block> {
        let coinbase = Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes([push_int(i64::from(height)), push_int(0)].concat()),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(REGTEST_SUBSIDY_SATS),
                script_pubkey: p2sh_true_output(),
            }],
            lock_time: LockTime::ZERO,
        };
        let mut block = Block {
            header: bitcoin_rs_consensus::primitives::Header {
                version: 0x2000_0000,
                prev_blockhash: bitcoin_rs_consensus::primitives::BlockHash::from(prev),
                merkle_root: Hash256::from_le_bytes(&[0_u8; 32]),
                time: BASE_TIME
                    .saturating_add(BLOCK_INTERVAL.saturating_mul(height))
                    .saturating_add(time_salt),
                bits: CompactTarget::from_consensus(REGTEST_BITS),
                nonce: 0,
            },
            txs: std::iter::once(coinbase).chain(txs).collect(),
        };
        block.header.merkle_root = regtest_fixture::merkle_root(&block.txs)
            .ok_or_else(|| TestError::message("block must have a merkle root"))?;
        regtest_fixture::mine_block_to_declared_target(&mut block)?;
        state
            .apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                block.clone(),
            ))
            .map_err(|error| {
                TestError::message(format!("apply failed at height {height}: {error}"))
            })?;
        Ok(block)
    }

    fn assert_matches_declared_semantics(state: &NodeState, shadow: &FeeEstimator) {
        let pool = state.mempool();
        let guard = pool.read();
        assert_eq!(
            guard.estimator_history(),
            shadow.to_history_bytes(),
            "pool estimator state must byte-match the declared-semantics mirror"
        );
        for target in [1_u32, 2, 3, 10, 25] {
            assert_eq!(
                guard.estimate_fee_rate(target),
                shadow.estimate(target),
                "estimate disagreement at target {target}"
            );
        }
    }

    fn seed_replayable_history(state: &NodeState) -> Result<()> {
        let first = mine_and_apply(state, applied_tip_hash(state)?, 1, 0, Vec::new())?;
        let mut tip = first.block_hash().0;
        for height in 2..=100 {
            tip = mine_and_apply(state, tip, height, 0, Vec::new())?
                .block_hash()
                .0;
        }
        let mut funding = spending_tx(first.txs[0].txid(), 0, u32::MAX);
        funding.outputs = vec![
            TxOut {
                value: Amount::from_sat(PARENT_VALUE_SATS),
                script_pubkey: p2sh_true_output(),
            };
            2
        ];
        let parent = funding.txid();
        let funded = mine_and_apply(state, tip, 101, 0, vec![funding])?;
        let txs = [0, 1].map(|vout| {
            let mut tx = spending_tx(parent, HIGH_FEE_SATS, u32::MAX);
            tx.inputs[0].previous_output = OutPoint::new(parent, vout);
            tx
        });
        for tx in &txs {
            admit(state, tx.clone())?;
        }
        mine_and_apply(state, funded.block_hash().0, 102, 0, txs.to_vec())?;
        Ok(())
    }

    fn mirror_admitted(shadow: &mut FeeEstimator, state: &NodeState, txid: Txid) {
        let pool = state.mempool();
        let guard = pool.read();
        let entry = guard
            .entry_by_txid(&txid)
            .expect("admitted tx must have a pool entry");
        shadow.tx_entered(txid, entry.fee_rate, entry.height);
    }

    #[test]
    fn empty_or_thin_history_answers_insufficient_data() -> Result<()> {
        let (state, _guard) = open_regtest()?;
        apply_genesis(&state)?;

        let pool = state.mempool();
        assert_eq!(
            pool.read().estimate_fee_rate(1),
            None,
            "no history: target 1 must refuse"
        );
        assert_eq!(
            pool.read().estimate_fee_rate(1008),
            None,
            "no history: beyond-horizon target must refuse"
        );
        assert_eq!(
            pool.read().estimator_last_decayed_height(),
            Some(0),
            "genesis connect must age the estimator to height 0"
        );

        fund_utxo(&state, parent_txid(0x01), PARENT_VALUE_SATS)?;
        let tx = spending_tx(parent_txid(0x01), HIGH_FEE_SATS, 0xffff_ffff);
        admit(&state, tx.clone())?;
        assert!(pool.read().contains_txid(&tx.txid()), "tx must be pooled");
        assert_eq!(
            pool.read().estimate_fee_rate(1),
            None,
            "pending admission alone must not produce an estimate"
        );

        let tip = applied_tip_hash(&state)?;
        mine_and_apply(&state, tip, 1, 0, Vec::new())?;
        assert_eq!(
            pool.read().estimate_fee_rate(1),
            None,
            "one miss must stay insufficient data"
        );
        Ok(())
    }

    #[test]
    fn real_confirmations_qualify_the_estimate() -> Result<()> {
        let (state, _guard) = open_regtest()?;
        apply_genesis(&state)?;
        let pool = state.mempool();

        fund_utxo(&state, parent_txid(0x11), PARENT_VALUE_SATS)?;
        fund_utxo(&state, parent_txid(0x12), PARENT_VALUE_SATS)?;
        fund_utxo(&state, parent_txid(0x13), PARENT_VALUE_SATS)?;
        fund_utxo(&state, parent_txid(0x14), PARENT_VALUE_SATS)?;
        let high = [
            spending_tx(parent_txid(0x11), HIGH_FEE_SATS, 0xffff_ffff),
            spending_tx(parent_txid(0x12), HIGH_FEE_SATS, 0xffff_ffff),
        ];
        let low = [
            spending_tx(parent_txid(0x13), LOW_FEE_SATS, 0xffff_ffff),
            spending_tx(parent_txid(0x14), LOW_FEE_SATS, 0xffff_ffff),
        ];

        let mut shadow = FeeEstimator::new();
        shadow.block_connected(&[], 0);
        for tx in high.iter().chain(low.iter()) {
            let txid = tx.txid();
            admit(&state, tx.clone())?;
            mirror_admitted(&mut shadow, &state, txid);
        }
        assert_eq!(pool.read().len(), 4, "all four admissions must be pooled");
        let high_rate = pool
            .read()
            .entry_by_txid(&high[0].txid())
            .expect("high tier must be pooled")
            .fee_rate;
        let low_rate = pool
            .read()
            .entry_by_txid(&low[0].txid())
            .expect("low tier must be pooled")
            .fee_rate;
        assert_matches_declared_semantics(&state, &shadow);

        let tip = applied_tip_hash(&state)?;
        mine_and_apply(&state, tip, 1, 0, high.to_vec())?;
        shadow.block_connected(&txids(&high), 1);
        assert_matches_declared_semantics(&state, &shadow);

        let estimate_short = pool
            .read()
            .estimate_fee_rate(1)
            .expect("two one-block confirmations must qualify target 1");
        assert!(
            estimate_short.as_sat_per_kvb() > low_rate
                && estimate_short.as_sat_per_kvb() <= high_rate,
            "target 1 must sit in the high tier's bucket, got {} sat/kvB \
         (low {low_rate}, high {high_rate})",
            estimate_short.as_sat_per_kvb()
        );
        let estimate_long = pool
            .read()
            .estimate_fee_rate(2)
            .expect("confirmed-in-one history must qualify target 2");
        assert!(
            estimate_long < estimate_short,
            "longer horizon must demand a lower rate: {} vs {}",
            estimate_long.as_sat_per_kvb(),
            estimate_short.as_sat_per_kvb()
        );
        assert_eq!(
            pool.read().estimator_last_decayed_height(),
            Some(1),
            "block 1 must age the estimator"
        );

        let tip = applied_tip_hash(&state)?;
        mine_and_apply(&state, tip, 2, 0, low.to_vec())?;
        shadow.block_connected(&txids(&low), 2);
        assert_matches_declared_semantics(&state, &shadow);
        assert_eq!(pool.read().len(), 0, "both tiers must be confirmed out");
        assert_eq!(
            pool.read().estimator_last_decayed_height(),
            Some(2),
            "block 2 must age the estimator"
        );
        assert_eq!(
            pool.read().estimate_fee_rate(1),
            Some(estimate_short),
            "target 1 must keep requiring the high tier"
        );
        Ok(())
    }

    #[test]
    fn replacement_untracks_victim_without_false_confirmation() -> Result<()> {
        let (state, _guard) = open_regtest()?;
        apply_genesis(&state)?;
        let pool = state.mempool();

        fund_utxo(&state, parent_txid(0x21), PARENT_VALUE_SATS)?;
        let victim = spending_tx(parent_txid(0x21), LOW_FEE_SATS, 0xffff_fffd);
        let replacement = spending_tx(parent_txid(0x21), REPLACEMENT_FEE_SATS, 0xffff_fffd);

        let mut shadow = FeeEstimator::new();
        shadow.block_connected(&[], 0);
        admit(&state, victim.clone())?;
        mirror_admitted(&mut shadow, &state, victim.txid());
        assert!(
            pool.read().contains_txid(&victim.txid()),
            "victim must pool"
        );

        admit(&state, replacement.clone())?;
        mirror_admitted(&mut shadow, &state, replacement.txid());
        shadow.tx_left(&victim.txid());
        assert_matches_declared_semantics(&state, &shadow);
        assert!(
            !pool.read().contains_txid(&victim.txid()),
            "victim must leave the pool on replacement"
        );
        assert!(
            pool.read().contains_txid(&replacement.txid()),
            "replacement must pool"
        );

        let tip = applied_tip_hash(&state)?;
        mine_and_apply(&state, tip, 1, 0, vec![replacement.clone()])?;
        shadow.block_connected(&[replacement.txid()], 1);
        assert_matches_declared_semantics(&state, &shadow);
        assert!(
            pool.read().estimate_fee_rate(1).is_none(),
            "one confirmation is below the decayed-observation floor"
        );
        Ok(())
    }

    #[test]
    fn eviction_untracks_without_false_confirmation() -> Result<()> {
        let (state, _guard) = open_regtest()?;
        apply_genesis(&state)?;
        let pool = state.mempool();

        fund_utxo(&state, parent_txid(0x31), PARENT_VALUE_SATS)?;
        fund_utxo(&state, parent_txid(0x32), PARENT_VALUE_SATS)?;
        let evicted = spending_tx(parent_txid(0x31), LOW_FEE_SATS, 0xffff_ffff);
        let kept = spending_tx(parent_txid(0x32), HIGH_FEE_SATS, 0xffff_ffff);

        let mut shadow = FeeEstimator::new();
        shadow.block_connected(&[], 0);
        admit(&state, evicted.clone())?;
        mirror_admitted(&mut shadow, &state, evicted.txid());
        admit(&state, kept.clone())?;
        mirror_admitted(&mut shadow, &state, kept.txid());

        let _ = state
            .mempool_gateway()
            .evict_below_fee_rate(AdmissionOrigin::Rpc, EVICT_THRESHOLD_SAT_PER_KVB);
        shadow.tx_left(&evicted.txid());
        assert_matches_declared_semantics(&state, &shadow);
        assert!(
            !pool.read().contains_txid(&evicted.txid()),
            "low-tier tx must be evicted"
        );
        assert!(
            pool.read().contains_txid(&kept.txid()),
            "high-tier tx must stay"
        );

        let tip = applied_tip_hash(&state)?;
        mine_and_apply(&state, tip, 1, 0, vec![kept.clone()])?;
        shadow.block_connected(&[kept.txid()], 1);
        assert_matches_declared_semantics(&state, &shadow);
        assert!(
            pool.read().estimate_fee_rate(1).is_none(),
            "one confirmation is below the decayed-observation floor"
        );
        Ok(())
    }

    #[test]
    fn reorg_reconfirm_records_exactly_one_observation() -> Result<()> {
        let (state, _guard) = open_regtest()?;
        apply_genesis(&state)?;
        let pool = state.mempool();

        fund_utxo(&state, parent_txid(0x41), PARENT_VALUE_SATS)?;
        fund_utxo(&state, parent_txid(0x42), PARENT_VALUE_SATS)?;
        let txs = [
            spending_tx(parent_txid(0x41), HIGH_FEE_SATS, 0xffff_ffff),
            spending_tx(parent_txid(0x42), HIGH_FEE_SATS, 0xffff_ffff),
        ];
        for tx in &txs {
            admit(&state, tx.clone())?;
        }

        let genesis = applied_tip_hash(&state)?;
        let block1 = mine_and_apply(&state, genesis, 1, 0, txs.to_vec())?;
        let estimate_before = pool
            .read()
            .estimate_fee_rate(1)
            .expect("two same-bucket confirmations must qualify target 1");
        let bytes_before = pool.read().estimator_history();

        bitcoin_rs_node::reorg::invalidate_block(
            &state.chainstate(),
            &state.chain_followers(),
            Hash256::from(block1.block_hash()),
        )
        .map_err(|error| TestError::message(format!("invalidate_block failed: {error}")))?;
        for tx in &txs {
            assert!(
                pool.read().contains_txid(&tx.txid()),
                "reconsideration must re-admit {}",
                tx.txid()
            );
        }
        assert_eq!(
            pool.read().estimate_fee_rate(1),
            Some(estimate_before),
            "reorg must preserve recorded confirmations, not wipe them"
        );

        let sibling = mine_and_apply(&state, genesis, 1, 1, txs.to_vec())?;
        assert_ne!(
            sibling.block_hash(),
            block1.block_hash(),
            "sibling block must be a distinct block"
        );
        assert_eq!(pool.read().len(), 0, "re-confirmed txs must leave the pool");
        assert_eq!(
            pool.read().estimate_fee_rate(1),
            Some(estimate_before),
            "re-confirm must not change the estimate: one observation, not two"
        );
        assert_eq!(
            pool.read().estimator_history(),
            bytes_before,
            "re-confirm must leave the estimator state byte-identical"
        );
        Ok(())
    }

    #[test]
    fn restart_adopts_persisted_estimator_history() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = NodeConfig::default_for_network(Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p.listen.clear();

        let state = NodeState::open(config.clone(), None)?;
        apply_genesis(&state)?;
        seed_replayable_history(&state)?;
        let pool = state.mempool();

        let estimate_before = pool
            .read()
            .estimate_fee_rate(1)
            .expect("seeded confirmations must qualify target 1");
        let bytes_before = pool.read().estimator_history();
        let decayed_before = pool.read().estimator_last_decayed_height();

        let history_path = config.data_dir.join(HISTORY_FILE);
        std::fs::write(&history_path, &bytes_before)?;

        drop(state);
        let reopened = reopen(config)?;
        let pool = reopened.mempool();
        assert_eq!(
            pool.read().estimate_fee_rate(1),
            Some(estimate_before),
            "reopened node must answer with the persisted estimate"
        );
        assert_eq!(
            pool.read().estimator_last_decayed_height(),
            decayed_before,
            "reopened node must restore the decayed height"
        );
        assert_eq!(
            pool.read().estimator_history(),
            bytes_before,
            "reopened estimator state must be byte-identical (no decay while idle)"
        );
        Ok(())
    }

    #[test]
    fn corrupt_history_file_degrades_to_insufficient_data() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = NodeConfig::default_for_network(Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p.listen.clear();

        let state = NodeState::open(config.clone(), None)?;
        apply_genesis(&state)?;
        seed_replayable_history(&state)?;
        let pool = state.mempool();
        assert!(pool.read().estimate_fee_rate(1).is_some());
        drop(state);

        let history_path = config.data_dir.join(HISTORY_FILE);
        let corrupt: Vec<u8> = std::iter::repeat_n(0xFF_u8, 128).collect();
        std::fs::write(&history_path, &corrupt)?;

        let reopened = reopen(config)?;
        let pool = reopened.mempool();
        assert_eq!(
            pool.read().estimate_fee_rate(1),
            None,
            "corrupt history must degrade to insufficient data"
        );
        assert_eq!(
            std::fs::read(&history_path)?,
            corrupt,
            "a rejected payload must stay in place for its owner"
        );
        fund_utxo(&reopened, parent_txid(0x63), PARENT_VALUE_SATS)?;
        let fresh = spending_tx(parent_txid(0x63), HIGH_FEE_SATS, 0xffff_ffff);
        admit(&reopened, fresh.clone())?;
        assert!(
            pool.read().contains_txid(&fresh.txid()),
            "degraded node must keep admitting"
        );
        Ok(())
    }

    fn txids(txs: &[Tx]) -> Vec<Txid> {
        txs.iter().map(Tx::txid).collect()
    }

    fn applied_tip_hash(state: &NodeState) -> Result<Hash256> {
        state
            .chainstate()
            .applied_tip_snapshot()
            .map(|tip| tip.hash)
            .ok_or_else(|| TestError::message("applied tip must exist"))
    }
}
mod reorg_durable_head {
    use bitcoin_rs_node::test_support::TestError;

    type Result<T, E = TestError> = core::result::Result<T, E>;

    use bitcoin_rs_chain::chain::regtest_fixture;
    use bitcoin_rs_node::{Network, NodeConfig, state::NodeState};

    use bitcoin_rs_consensus::primitives::{BlockHash, Hash256};

    fn stable_utxo_hash(
        view: &bitcoin_rs_storage::utxo::UtxoSetView<'_>,
    ) -> Result<Hash256, bitcoin_rs_storage::utxo::UtxoError> {
        view.hash_serialized_3()
    }

    #[test]
    fn disconnect_rewrites_durable_head_before_restart() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = NodeConfig::default_for_network(Network::Regtest);
        config.data_dir = dir.path().join("reorg-node");
        config.p2p.listen.clear();

        let genesis = Network::Regtest.genesis_block();
        let initial = NodeState::open(config.clone(), None)?;
        initial.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
            genesis.clone(),
        ))?;
        let _ = initial.publish_checkpoint()?;
        drop(initial);

        let state = NodeState::open(config.clone(), None)?;
        let block1 = regtest_fixture::mined_regtest_child_at(genesis.block_hash(), 1)?;
        let tip1 = state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
            block1,
        ))?;
        let block2 = regtest_fixture::mined_regtest_child_at(BlockHash(tip1.hash), 2)?;
        state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
            block2.clone(),
        ))?;
        state.chainstate().disconnect_block(&block2)?;
        let expected_utxo = state
            .chainstate()
            .utxo_reader()
            .with_stable_view(stable_utxo_hash)??;
        let expected_stats = state.chainstate().coin_stats_handle().snapshot();
        drop(state);

        let resumed = NodeState::open(config.clone(), None)?;
        let resumed_tip = resumed
            .chainstate()
            .applied_tip_snapshot()
            .ok_or_else(|| std::io::Error::other("reorg replay did not publish a tip"))?;
        assert_eq!(resumed_tip.as_ref(), &tip1);
        assert_eq!(
            resumed
                .chainstate()
                .utxo_reader()
                .with_stable_view(stable_utxo_hash)??,
            expected_utxo
        );
        assert_semantic_coin_stats_eq(
            &resumed.chainstate().coin_stats_handle().snapshot(),
            &expected_stats,
        );

        let mut replacement = regtest_fixture::mined_regtest_child_at(BlockHash(tip1.hash), 2)?;
        replacement.header.time = replacement.header.time.saturating_add(1);
        replacement.header.nonce = 0;
        regtest_fixture::mine_block_to_declared_target(&mut replacement)?;
        assert_ne!(replacement.block_hash(), block2.block_hash());
        let replacement_tip = resumed.apply_block(
            &bitcoin_rs_consensus::primitives::BlockImage::from_local(replacement),
        )?;
        drop(resumed);

        let replaced = NodeState::open(config, None)?;
        let persisted_tip = replaced
            .chainstate()
            .applied_tip_snapshot()
            .ok_or_else(|| std::io::Error::other("replacement durable head tip missing"))?;
        assert_eq!(persisted_tip.as_ref(), &replacement_tip);
        Ok(())
    }

    #[test]
    fn disconnect_below_checkpoint_base_forces_full_validation() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = NodeConfig::default_for_network(Network::Regtest);
        config.data_dir = dir.path().join("deep-reorg-node");
        config.p2p.listen.clear();

        let genesis = Network::Regtest.genesis_block();
        let block1 = regtest_fixture::mined_regtest_child_at(genesis.block_hash(), 1)?;
        let initial = NodeState::open(config.clone(), None)?;
        let genesis_tip = initial.apply_block(
            &bitcoin_rs_consensus::primitives::BlockImage::from_local(genesis),
        )?;
        initial.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
            block1.clone(),
        ))?;
        let _ = initial.publish_checkpoint()?;
        drop(initial);

        let state = NodeState::open(config.clone(), None)?;
        state.chainstate().disconnect_block(&block1)?;
        drop(state);

        let resumed = NodeState::open(config.clone(), None)?;
        let resumed_tip = resumed
            .chainstate()
            .applied_tip_snapshot()
            .ok_or_else(|| std::io::Error::other("durable head replay did not publish a tip"))?;
        assert_eq!(
            resumed_tip.as_ref(),
            &genesis_tip,
            "a checkpoint above the fork must not be trusted; the node resumes on the durable head"
        );
        drop(resumed);

        let resumed_again = NodeState::open(config.clone(), None)?;
        let resumed_again_tip = resumed_again
            .chainstate()
            .applied_tip_snapshot()
            .ok_or_else(|| std::io::Error::other("durable head replay did not publish a tip"))?;
        assert_eq!(
            resumed_again_tip.as_ref(),
            &genesis_tip,
            "full validation must remain sticky until a replacement checkpoint"
        );
        let replacement_tip = resumed_again.apply_block(
            &bitcoin_rs_consensus::primitives::BlockImage::from_local(block1),
        )?;
        let _ = resumed_again.publish_checkpoint()?;
        drop(resumed_again);

        let recovered = NodeState::open(config, None)?;
        let recovered_tip = recovered
            .chainstate()
            .applied_tip_snapshot()
            .ok_or_else(|| std::io::Error::other("replacement checkpoint was ignored"))?;
        assert_eq!(recovered_tip.as_ref(), &replacement_tip);
        Ok(())
    }

    // SYNC-05
    #[test]
    fn recovery_publication_keeps_committed_coin_stats_across_restart() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = NodeConfig::default_for_network(Network::Regtest);
        config.data_dir = dir.path().join("recovery-stats-node");
        config.p2p.listen.clear();

        let genesis = Network::Regtest.genesis_block();
        let block1 = regtest_fixture::mined_regtest_child_at(genesis.block_hash(), 1)?;
        let block2 = regtest_fixture::mined_regtest_child_at(block1.block_hash(), 2)?;

        let base = NodeState::open(config.clone(), None)?;
        base.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
            genesis.clone(),
        ))?;
        base.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
            block1.clone(),
        ))?;
        let _ = base.publish_checkpoint()?;
        drop(base);

        let state = NodeState::open(config.clone(), None)?;
        state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
            block2.clone(),
        ))?;
        state
            .undo_store()
            .arm_disconnect(2, block2.block_hash().0)?;
        drop(state);

        let recovered = NodeState::open(config.clone(), None)?;
        drop(recovered);

        let resumed = NodeState::open(config, None)?;
        let tip = resumed
            .chainstate()
            .applied_tip_snapshot()
            .ok_or_else(|| std::io::Error::other("recovery replay did not publish a tip"))?;
        let expected = resumed
            .chainstate()
            .utxo_reader()
            .with_stable_view(|view| {
                bitcoin_rs_storage::utxo::stats::scan_coin_stats(view, tip.height, true)
            })??;
        let served = resumed.chainstate().coin_stats_handle().snapshot();
        assert_eq!(
            served.height, expected.height,
            "listener height must equal the committed tip height"
        );
        assert_eq!(
            served.total_amount, expected.total_amount,
            "listener amount must equal a full scan of the committed coin set"
        );
        assert_eq!(
            served.bogo_size, expected.bogo_size,
            "listener bogo_size must equal a full scan of the committed coin set"
        );
        assert_eq!(
            served.utxo_count, expected.utxo_count,
            "listener output count must equal a full scan of the committed coin set"
        );
        assert_eq!(
            served.muhash.finalize_hash(),
            expected.muhash.finalize_hash(),
            "listener MuHash must equal a full scan of the committed coin set"
        );
        Ok(())
    }

    fn assert_semantic_coin_stats_eq(
        left: &bitcoin_rs_storage::utxo::stats::CoinStats,
        right: &bitcoin_rs_storage::utxo::stats::CoinStats,
    ) {
        assert_eq!(left.height, right.height);
        assert_eq!(left.total_amount, right.total_amount);
        assert_eq!(left.bogo_size, right.bogo_size);
        assert_eq!(left.tx_count, right.tx_count);
        assert_eq!(left.utxo_count, right.utxo_count);
        assert_eq!(left.muhash.finalize_hash(), right.muhash.finalize_hash());
    }
}
mod shutdown {
    use crate::support::block_on;
    use bitcoin_rs_node::test_support::TestError;
    use bitcoin_rs_node::{Auth, Network, NodeConfig, RuntimeInputs, run};
    use crossbeam_channel::bounded;
    use std::net::SocketAddr;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn run_exits_cleanly_after_fast_shutdown_signal() -> Result<(), TestError> {
        let temp = tempfile::tempdir()?;
        let (shutdown_tx, shutdown_rx) = bounded(1);
        let (done_tx, done_rx) = bounded(1);

        let mut config = NodeConfig::default_for_network(Network::Regtest);
        config.data_dir = temp.path().join("node");
        config.storage.backend = test_storage_backend();
        config.rpc.bind = loopback(0);
        config.rpc.auth = Auth::basic("user", "password");
        config.indexes.script_index = bitcoin_rs_node::config::ScriptIndexMode::Disabled;
        config.p2p.listen.clear();
        config.observability.metrics_bind = None;
        let runtime = RuntimeInputs::default().with_shutdown(shutdown_rx);

        thread::spawn(move || {
            let result = run(config, runtime);
            let _ignored = done_tx.send(result.map_err(|error| error.to_string()));
        });

        shutdown_tx
            .send(())
            .map_err(|_| TestError::message("failed to send shutdown signal"))?;
        let result = done_rx
            .recv_timeout(Duration::from_secs(6))
            .map_err(|_| TestError::message("node did not stop within shutdown deadline"))?;
        result.map_err(TestError::message)?;
        Ok(())
    }

    fn loopback(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn test_storage_backend() -> bitcoin_rs_storage::StorageBackend {
        bitcoin_rs_storage::StorageBackend::RocksDb
    }

    #[test]
    fn shutdown_signal_before_startup_exits_cleanly() -> Result<(), TestError> {
        let temp = tempfile::tempdir()?;
        let (shutdown_tx, shutdown_rx) = bounded(1);
        let (done_tx, done_rx) = bounded(1);

        let mut config = NodeConfig::default_for_network(Network::Regtest);
        config.data_dir = temp.path().join("node-pre-shutdown");
        config.storage.backend = test_storage_backend();
        config.rpc.bind = loopback(0);
        config.rpc.auth = Auth::basic("user", "password");
        config.indexes.script_index = bitcoin_rs_node::config::ScriptIndexMode::Disabled;
        config.p2p.listen.clear();
        config.observability.metrics_bind = None;

        shutdown_tx
            .send(())
            .map_err(|_| TestError::message("failed to pre-send shutdown signal"))?;

        let runtime = RuntimeInputs::default().with_shutdown(shutdown_rx);

        thread::spawn(move || {
            let result = run(config, runtime);
            let _ignored = done_tx.send(result.map_err(|error| error.to_string()));
        });

        let result = done_rx
            .recv_timeout(Duration::from_secs(6))
            .map_err(|_| TestError::message("pre-shutdown node did not exit within deadline"))?;
        result.map_err(TestError::message)?;
        Ok(())
    }

    #[test]
    fn subscribe_and_use_after_shutdown_are_refused() -> Result<(), TestError> {
        use bitcoin_rs_node::{Node, NodeError};

        let temp = tempfile::tempdir()?;
        let mut config = NodeConfig::default_for_network(Network::Regtest);
        config.data_dir = temp.path().join("node-sub-shutdown");
        config.storage.backend = test_storage_backend();
        config.rpc.bind = loopback(0);
        config.rpc.auth = Auth::basic("user", "password");
        config.indexes.script_index = bitcoin_rs_node::config::ScriptIndexMode::Disabled;
        config.p2p.listen.clear();
        config.observability.metrics_bind = None;

        let (shutdown_tx, shutdown_rx) = bounded(2);
        let runtime = RuntimeInputs::default().with_shutdown(shutdown_rx);
        let node = block_on(Node::start(config, runtime))
            .map_err(|error| TestError::message(error.to_string()))?;

        let mut sub = node
            .subscribe_chain()
            .map_err(|error| TestError::message(error.to_string()))?;

        shutdown_tx
            .send(())
            .map_err(|_| TestError::message("failed to send first shutdown signal"))?;
        match shutdown_tx.try_send(()) {
            Ok(()) | Err(crossbeam_channel::TrySendError::Disconnected(_)) => {}
            Err(crossbeam_channel::TrySendError::Full(_)) => {
                panic!("the shutdown channel has room for a repeated signal")
            }
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while node.subscribe_chain().is_ok() {
            assert!(
                std::time::Instant::now() < deadline,
                "shutdown must become observable"
            );
            thread::sleep(Duration::from_millis(5));
        }

        let sub_after = node.subscribe_chain();
        assert!(
            matches!(&sub_after, Err(NodeError::Unavailable(msg)) if msg.contains("shutting down")),
            "subscribe after shutdown must return Unavailable"
        );

        let poll_after = node.poll_chain(&mut sub);
        assert!(
            matches!(&poll_after, Err(NodeError::Unavailable(msg)) if msg.contains("shutting down")),
            "poll after shutdown must return Unavailable"
        );

        let pin_after = node.pin_chain();
        assert!(
            matches!(&pin_after, Err(NodeError::Unavailable(msg)) if msg.contains("shutting down")),
            "pin after shutdown must return Unavailable"
        );

        let settled_after = node.settled_snapshot();
        assert!(
            matches!(&settled_after, Err(NodeError::Unavailable(msg)) if msg.contains("shutting down")),
            "settled_snapshot after shutdown must return Unavailable"
        );

        block_on(node.shutdown()).map_err(|error| TestError::message(error.to_string()))?;
        Ok(())
    }
}
mod state_storage {
    use std::sync::Arc;

    use hashbrown::HashMap;
    use parking_lot::Mutex;

    use bitcoin_rs_node::test_support::TestError;

    type Result<T, E = TestError> = core::result::Result<T, E>;
    use bitcoin_rs_node::{Network, NodeConfig, ScriptIndexMode, state::NodeState};
    use bitcoin_rs_storage::{Bytes, COIN_KEY_LEN, CoinKey, budget::BudgetOwner};
    use metrics::{
        Counter, Gauge, GaugeFn, Histogram, HistogramFn, Key, KeyName, Metadata, Recorder,
        SharedString, Unit,
    };

    #[test]
    fn opens_storage_backend() -> Result<()> {
        assert_backend_opens("rocksdb")?;
        Ok(())
    }

    fn assert_backend_opens(backend: &str) -> Result<()> {
        let temp = tempfile::tempdir()?;
        let mut config = NodeConfig::default_for_network(Network::Regtest);
        config.data_dir = temp.path().join(backend);
        config.storage.backend = backend.parse().map_err(TestError::message)?;
        config.p2p.listen.clear();

        let state = NodeState::open(config, None)?;

        assert_eq!(state.storage_kind(), backend);
        assert!(state.data_dir().join("chainstate").is_dir());
        Ok(())
    }

    const ROW_BYTES: usize = 64 * 1024;
    const ROW_COUNT: usize = 192;

    struct ExpectedCacheAllocation {
        coin_allowance_bytes: u64,
        engine_capacity_bytes: u64,
    }

    // BUD-06
    #[test]
    fn opened_coin_cache_enforces_no_txindex_coin_share() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let mut config = NodeConfig::default_for_network(Network::Regtest);
        config.data_dir = temp.path().join("rocksdb");
        config.storage.backend = "rocksdb".parse().map_err(TestError::message)?;
        config.storage.dbcache_mb = 16;
        config.indexes.txindex = false;
        config.indexes.blockfilterindex = false;
        config.indexes.script_index = ScriptIndexMode::Disabled;
        config.p2p.listen.clear();
        assert_opened_cache_pressure(
            config,
            ExpectedCacheAllocation {
                coin_allowance_bytes: 8_388_608,
                engine_capacity_bytes: 8_388_608,
            },
        )
    }

    // BUD-06
    #[test]
    fn opened_coin_cache_enforces_txindex_coin_share() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let mut config = NodeConfig::default_for_network(Network::Regtest);
        config.data_dir = temp.path().join("rocksdb");
        config.storage.backend = "rocksdb".parse().map_err(TestError::message)?;
        config.storage.dbcache_mb = 16;
        config.indexes.txindex = true;
        config.indexes.blockfilterindex = false;
        config.indexes.script_index = ScriptIndexMode::Disabled;
        config.p2p.listen.clear();
        assert_opened_cache_pressure(
            config,
            ExpectedCacheAllocation {
                coin_allowance_bytes: 6_710_887,
                engine_capacity_bytes: 6_710_886,
            },
        )
    }

    fn assert_opened_cache_pressure(
        config: NodeConfig,
        expected: ExpectedCacheAllocation,
    ) -> Result<()> {
        let gauges = GaugeSpy::default();
        let state = metrics::with_local_recorder(&gauges, || NodeState::open(config, None))?;
        let chainstate = state.chainstate();
        let coins = chainstate.coins();

        let row_count =
            u64::try_from(ROW_COUNT).map_err(|_| TestError::Missing("row count exceeds u64"))?;
        let keys: Vec<CoinKey> = (0..row_count).map(coin_key).collect();
        let values: Vec<Bytes> = (0..row_count).map(coin_value).collect();
        coins.ingest_sorted(keys.iter().copied().zip(values.iter().cloned()))?;
        assert_eq!(
            coins.cache().resident_bytes(),
            0,
            "ingest_sorted must leave the coin cache cold"
        );

        for (key, value) in keys.iter().zip(&values) {
            let read = coins
                .get(key)?
                .ok_or(TestError::Missing("ingested coin row must be readable"))?;
            assert_eq!(&read, value, "coin row must round-trip unchanged");
        }

        let resident = coins.cache().resident_bytes();
        let row_len =
            u64::try_from(ROW_BYTES).map_err(|_| TestError::Missing("row size exceeds u64"))?;
        let total = u64::try_from(ROW_COUNT * ROW_BYTES)
            .map_err(|_| TestError::Missing("row total exceeds u64"))?;
        assert!(
            resident <= expected.coin_allowance_bytes,
            "coin cache resident {resident} exceeds policy allowance {}",
            expected.coin_allowance_bytes
        );
        assert!(
            resident >= expected.coin_allowance_bytes.saturating_sub(2 * row_len),
            "coin cache resident {resident} stayed far below allowance {}",
            expected.coin_allowance_bytes
        );
        assert!(
            resident < total,
            "coin cache resident {resident} retained every row without eviction"
        );
        assert!(
            keys.iter().any(|key| coins.cache().lookup(key).is_none()),
            "at least one supplied row must have been evicted under the coin allowance"
        );
        let retained = coins
            .cache()
            .lookup(
                keys.last()
                    .ok_or(TestError::Missing("rows are non-empty"))?,
            )
            .ok_or(TestError::Missing("latest row must stay cached"))?;
        let last_value = values
            .last()
            .ok_or(TestError::Missing("rows are non-empty"))?;
        assert_eq!(
            &retained, last_value,
            "latest row must stay readable and intact"
        );

        let caps = state.budget().caps();
        assert_eq!(
            caps.owner_cap(BudgetOwner::EngineCache),
            expected.engine_capacity_bytes,
            "the opened node ledger must cap EngineCache at its post-index share"
        );
        assert_eq!(
            caps.owner_cap(BudgetOwner::CoinCache),
            expected.coin_allowance_bytes,
            "the opened node ledger must cap CoinCache at its post-index share"
        );
        assert_capacity_eq(
            &gauges,
            "storage.cache_capacity_bytes{backend=\"rocksdb\"}",
            expected.engine_capacity_bytes,
        );
        drop(state);
        Ok(())
    }

    fn coin_key(index: u64) -> CoinKey {
        let mut key = [0_u8; COIN_KEY_LEN];
        key[0] = 1;
        key[1..9].copy_from_slice(&index.to_be_bytes());
        CoinKey(key)
    }

    fn coin_value(index: u64) -> Bytes {
        let mut value = vec![0_u8; ROW_BYTES];
        value[0..8].copy_from_slice(&index.to_be_bytes());
        Bytes::from(value)
    }

    #[expect(
        clippy::cast_precision_loss,
        reason = "byte counts < 2^31, lossless in f64"
    )]
    #[expect(clippy::as_conversions, reason = "byte counts < 2^31, lossless in f64")]
    fn assert_capacity_eq(gauges: &GaugeSpy, key: &str, expected: u64) {
        let actual = gauges.get(key);
        assert!(
            actual.is_some_and(|value| (value - expected as f64).abs() < 1.0),
            "{key}: expected {expected}, published {actual:?}"
        );
    }

    #[derive(Clone, Default)]
    struct GaugeSpy {
        gauges: Arc<Mutex<HashMap<String, f64>>>,
    }

    impl GaugeSpy {
        fn key(key: &Key) -> String {
            let labels = key
                .labels()
                .map(|label| format!("{}=\"{}\"", label.key(), label.value()))
                .collect::<Vec<_>>()
                .join(",");
            if labels.is_empty() {
                key.name().to_owned()
            } else {
                format!("{}{{{}}}", key.name(), labels)
            }
        }

        fn get(&self, key: &str) -> Option<f64> {
            self.gauges.lock().get(key).copied()
        }
    }

    impl Recorder for GaugeSpy {
        fn describe_counter(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {
        }
        fn describe_gauge(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}
        fn describe_histogram(
            &self,
            _key: KeyName,
            _unit: Option<Unit>,
            _description: SharedString,
        ) {
        }

        fn register_counter(&self, _key: &Key, _metadata: &Metadata<'_>) -> Counter {
            Counter::noop()
        }

        fn register_gauge(&self, key: &Key, _metadata: &Metadata<'_>) -> Gauge {
            Gauge::from_arc(Arc::new(GaugeCell {
                gauges: Arc::clone(&self.gauges),
                name: Self::key(key),
            }))
        }

        fn register_histogram(&self, _key: &Key, _metadata: &Metadata<'_>) -> Histogram {
            Histogram::from_arc(Arc::new(DiscardHistogram))
        }
    }

    struct GaugeCell {
        gauges: Arc<Mutex<HashMap<String, f64>>>,
        name: String,
    }

    impl GaugeFn for GaugeCell {
        fn increment(&self, value: f64) {
            *self.gauges.lock().entry(self.name.clone()).or_insert(0.0) += value;
        }

        fn decrement(&self, value: f64) {
            self.increment(-value);
        }

        fn set(&self, value: f64) {
            self.gauges.lock().insert(self.name.clone(), value);
        }
    }

    struct DiscardHistogram;

    impl HistogramFn for DiscardHistogram {
        fn record(&self, _value: f64) {}
    }
}
mod support {
    use std::task::{Context, Poll, Waker};

    use bitcoin_rs_consensus::primitives::{Hash256, Script, Txid};

    pub(crate) fn block_on<F: Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        loop {
            match future.as_mut().poll(&mut cx) {
                Poll::Ready(output) => return output,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    pub(crate) fn p2sh_true_output() -> Script {
        let redeem = bitcoin::ScriptBuf::from_bytes(vec![0x51]);
        Script::from_bytes(redeem.to_p2sh().into_bytes())
    }

    pub(crate) fn p2sh_true_spend_script_sig() -> Script {
        Script::from_bytes(vec![0x01, 0x51])
    }

    pub(crate) fn parent_txid(marker: u8) -> Txid {
        Txid::from(Hash256::from_le_bytes(&[marker; 32]))
    }
}
mod sync_smoke {
    use hashbrown::HashMap;
    use std::sync::Arc;

    use arc_swap::ArcSwapOption;
    use bitcoin::hex::FromHex;
    use bitcoin_rs_chain::Chainstate;
    use bitcoin_rs_chain::chain::{BlockTree, TipSnapshot, regtest_fixture};
    use bitcoin_rs_consensus::primitives::{
        Amount, Block, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Witness, deserialize,
    };
    use bitcoin_rs_node::Network;
    use bitcoin_rs_node::test_support::TestError;
    use bitcoin_rs_storage::utxo::UtxoSet;
    use bitcoin_rs_storage::utxo::stats::{CoinStats, CoinStatsListener};
    use crossbeam_channel::unbounded;
    use parking_lot::RwLock;

    const REGTEST_GENESIS_HEX: &str = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff7f20020000000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";

    // SYNC-02
    #[test]
    fn tick_buffers_out_of_order_blocks_until_parent_arrives() -> Result<(), TestError> {
        let genesis = regtest_genesis_block()?;
        let block_one = child_coinbase_block(&genesis, 1)?;
        let block_two = child_coinbase_block(&block_one, 2)?;

        let block_tree = Arc::new(RwLock::new(BlockTree::new()));
        let chain_tip = block_tree.write().tip_handle();
        let applied_tip: Arc<ArcSwapOption<TipSnapshot>> = Arc::new(ArcSwapOption::empty());
        let peer_table = Arc::new(bitcoin_rs_p2p::PeerTable::new());
        let (inbound_headers_tx, inbound_headers_rx) =
            unbounded::<bitcoin_rs_p2p::InboundHeaders>();
        let (inbound_blocks_tx, inbound_blocks_rx) = unbounded::<bitcoin_rs_p2p::InboundBlock>();
        let (handles, coin_stats) = apply_handles_with_coin_stats(
            Network::Regtest,
            Arc::clone(&chain_tip),
            Arc::clone(&applied_tip),
            Arc::clone(&block_tree),
        );
        let handles = Arc::new(handles);
        let ibd = handles.ibd_latch();
        let sync = bitcoin_rs_node::sync::block_sync(bitcoin_rs_node::sync::BlockSyncInputs {
            handles: Arc::clone(&handles),
            followers: bitcoin_rs_node::ChainFollowers::noop(),
            peer_table,
            inbound_headers_rx,
            inbound_blocks_rx,
            ibd,
            assumeutxo: None,
            budget: Arc::new(
                bitcoin_rs_node::budget::NodeBudget::from_chainstate_cache_budget(
                    bitcoin_rs_storage::split_chainstate_cache_budget(16),
                    1,
                ),
            ),
        });

        inbound_headers_tx
            .send(bitcoin_rs_p2p::InboundHeaders {
                headers: vec![genesis.header, block_one.header, block_two.header],
                source: None,
                wire_response: true,
            })
            .map_err(|_| TestError::message("send headers failed"))?;
        inbound_blocks_tx
            .send(bitcoin_rs_p2p::InboundBlock::from_local(block_two.clone()))
            .map_err(|_| TestError::message("send block failed"))?;
        inbound_blocks_tx
            .send(bitcoin_rs_p2p::InboundBlock::from_local(block_one.clone()))
            .map_err(|_| TestError::message("send block failed"))?;

        sync.tick();

        let applied = applied_tip
            .load_full()
            .ok_or_else(|| std::io::Error::other("missing applied tip"))?;
        assert_eq!(applied.height, 2);
        assert_eq!(applied.hash, block_two.block_hash().0);
        let expected_stats = expected_coin_stats(&[&genesis, &block_one, &block_two])?;
        assert_engine_coin_stats(&handles, &coin_stats.snapshot(), &expected_stats)?;
        assert_eq!(block_tree.read().len(), 3);
        Ok(())
    }

    // SYNC-01, SYNC-02, SYNC-05
    #[test]
    fn tick_recovers_rejected_frontier_without_publishing_unapplied_blocks() -> Result<(), TestError>
    {
        let genesis = regtest_genesis_block()?;
        let block_one = child_coinbase_block(&genesis, 1)?;
        let block_two = child_coinbase_block(&block_one, 2)?;
        let mut malformed = block_one.clone();
        malformed.txs[0].outputs[0].value = Amount::from_sat(1);
        assert_eq!(malformed.block_hash(), block_one.block_hash());

        let block_tree = Arc::new(RwLock::new(BlockTree::new()));
        let chain_tip = block_tree.write().tip_handle();
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let (inbound_headers_tx, inbound_headers_rx) = unbounded();
        let (inbound_blocks_tx, inbound_blocks_rx) = unbounded();
        let (handles, coin_stats, _utxo) = apply_handles_with_coin_stats_and_utxo(
            Network::Regtest,
            chain_tip,
            applied_tip,
            Arc::clone(&block_tree),
        );
        let handles = Arc::new(handles);
        let followers = bitcoin_rs_node::ChainFollowers::noop();
        let block_log = followers.block_log_reader();
        let sync = bitcoin_rs_node::sync::block_sync(bitcoin_rs_node::sync::BlockSyncInputs {
            handles: Arc::clone(&handles),
            followers,
            peer_table: Arc::new(bitcoin_rs_p2p::PeerTable::new()),
            inbound_headers_rx,
            inbound_blocks_rx,
            ibd: handles.ibd_latch(),
            assumeutxo: None,
            budget: Arc::new(
                bitcoin_rs_node::budget::NodeBudget::from_chainstate_cache_budget(
                    bitcoin_rs_storage::split_chainstate_cache_budget(16),
                    1,
                ),
            ),
        });
        sync.tick();
        let before = handles.chain_snapshot();
        assert_eq!(
            (before.tip_height, before.tip_hash),
            (0, genesis.block_hash().0)
        );
        let genesis_stats = expected_coin_stats(&[&genesis])?;

        inbound_headers_tx
            .send(bitcoin_rs_p2p::InboundHeaders {
                headers: vec![block_one.header, block_two.header],
                source: None,
                wire_response: true,
            })
            .map_err(|_| TestError::message("send headers failed"))?;
        for bodies in [vec![], vec![malformed, block_two.clone()]] {
            for block in bodies {
                inbound_blocks_tx
                    .send(bitcoin_rs_p2p::InboundBlock::from_local(block))
                    .map_err(|_| TestError::message("send block failed"))?;
            }
            sync.tick();
            let header = handles
                .header_tip()
                .ok_or_else(|| TestError::message("missing header tip"))?;
            assert_eq!((header.height, header.hash), (2, block_two.block_hash().0));
            let applied = handles
                .applied_tip_snapshot()
                .ok_or_else(|| TestError::message("missing applied tip"))?;
            assert_eq!((applied.height, applied.hash), (0, genesis.block_hash().0));
            assert_eq!(handles.chain_snapshot(), before);
            assert_engine_coin_stats(&handles, &coin_stats.snapshot(), &genesis_stats)?;
            assert!(
                handles
                    .utxo_reader()
                    .get(&OutPoint::new(block_one.txs[0].txid(), 0))?
                    .is_none()
                    && handles
                        .utxo_reader()
                        .get(&OutPoint::new(block_two.txs[0].txid(), 0))?
                        .is_none(),
                "unapplied bodies must not create coins",
            );
            let log = block_log.read();
            assert_eq!(log.len(), 1, "unapplied blocks must not reach the RPC log");
            assert_eq!(log[0].hash, genesis.block_hash());
            drop(log);
            let tree = block_tree.read();
            for block in [&block_one, &block_two] {
                let id = tree
                    .lookup(block.block_hash().0)
                    .ok_or_else(|| TestError::message("missing admitted header"))?;
                assert_ne!(
                    tree.node(id)?.status,
                    bitcoin_rs_chain::chain::NodeStatus::Invalid
                );
            }
        }

        inbound_blocks_tx
            .send(bitcoin_rs_p2p::InboundBlock::from_local(block_one.clone()))
            .map_err(|_| TestError::message("send block failed"))?;
        for _ in 0..16 {
            sync.tick();
            if handles
                .applied_tip_snapshot()
                .is_some_and(|tip| tip.hash == block_two.block_hash().0)
            {
                break;
            }
        }

        let applied = handles
            .applied_tip_snapshot()
            .ok_or_else(|| TestError::message("missing applied tip"))?;
        assert_eq!(
            (applied.height, applied.hash),
            (2, block_two.block_hash().0)
        );
        let after = handles.chain_snapshot();
        assert_eq!(
            (after.tip_height, after.tip_hash),
            (applied.height, applied.hash)
        );
        assert_eq!(after.epoch, before.epoch);
        assert_eq!(after.sequence, before.sequence + 2);
        let expected_stats = expected_coin_stats(&[&genesis, &block_one, &block_two])?;
        assert_engine_coin_stats(&handles, &coin_stats.snapshot(), &expected_stats)?;
        for (height, block) in [&block_one, &block_two].iter().enumerate() {
            assert_eq!(
                handles
                    .utxo_reader()
                    .get(&OutPoint::new(block.txs[0].txid(), 0))?,
                Some(block.txs[0].outputs[0].clone()),
                "coinbase output at height {} must be live in the engine coin store",
                height + 1,
            );
        }
        let log = block_log.read();
        assert_eq!(
            log.iter()
                .map(|record| (record.height, record.hash))
                .collect::<Vec<_>>(),
            vec![
                (0, genesis.block_hash()),
                (1, block_one.block_hash()),
                (2, block_two.block_hash())
            ]
        );
        Ok(())
    }

    #[test]
    fn tick_applies_non_coinbase_spend_and_updates_utxo_and_coinstats() -> Result<(), TestError> {
        let fixture = non_coinbase_spend_chain()?;

        let block_tree = Arc::new(RwLock::new(BlockTree::new()));
        let chain_tip = block_tree.write().tip_handle();
        let applied_tip: Arc<ArcSwapOption<TipSnapshot>> = Arc::new(ArcSwapOption::empty());
        let peer_table = Arc::new(bitcoin_rs_p2p::PeerTable::new());
        let (inbound_headers_tx, inbound_headers_rx) =
            unbounded::<bitcoin_rs_p2p::InboundHeaders>();
        let (inbound_blocks_tx, inbound_blocks_rx) = unbounded::<bitcoin_rs_p2p::InboundBlock>();
        let (handles, coin_stats, _utxo) = apply_handles_with_coin_stats_and_utxo(
            Network::Regtest,
            Arc::clone(&chain_tip),
            Arc::clone(&applied_tip),
            Arc::clone(&block_tree),
        );
        let handles = Arc::new(handles);
        let ibd = handles.ibd_latch();
        let sync = bitcoin_rs_node::sync::block_sync(bitcoin_rs_node::sync::BlockSyncInputs {
            handles: Arc::clone(&handles),
            followers: bitcoin_rs_node::ChainFollowers::noop(),
            peer_table,
            inbound_headers_rx,
            inbound_blocks_rx,
            ibd,
            assumeutxo: None,
            budget: Arc::new(
                bitcoin_rs_node::budget::NodeBudget::from_chainstate_cache_budget(
                    bitcoin_rs_storage::split_chainstate_cache_budget(16),
                    1,
                ),
            ),
        });

        inbound_headers_tx
            .send(bitcoin_rs_p2p::InboundHeaders {
                headers: fixture.blocks.iter().map(|block| block.header).collect(),
                source: None,
                wire_response: true,
            })
            .map_err(|_| TestError::message("send headers failed"))?;
        for block in fixture.blocks.iter().skip(1) {
            inbound_blocks_tx
                .send(bitcoin_rs_p2p::InboundBlock::from_local(block.clone()))
                .map_err(|_| TestError::message("send block failed"))?;
        }

        sync.tick();

        let applied = applied_tip
            .load_full()
            .ok_or_else(|| std::io::Error::other("missing applied tip"))?;
        assert_eq!(applied.height, 102);
        assert_eq!(
            applied.hash,
            fixture
                .blocks
                .last()
                .ok_or_else(|| std::io::Error::other("missing final block"))?
                .block_hash()
                .0
        );
        assert!(
            handles
                .utxo_reader()
                .get(&fixture.mature_coinbase_outpoint)?
                .is_none(),
            "mature coinbase prevout must be removed by the height-101 spend",
        );
        assert!(
            handles
                .utxo_reader()
                .get(&fixture.funding_outpoint)?
                .is_none(),
            "funding prevout must be removed by the height-102 spend",
        );
        assert!(
            handles
                .utxo_reader()
                .get(&fixture.spend_outpoint)?
                .is_some(),
            "height-102 spend output must remain live",
        );

        let block_refs: Vec<&Block> = fixture.blocks.iter().collect();
        let expected_stats = expected_coin_stats(&block_refs)?;
        assert_engine_coin_stats(&handles, &coin_stats.snapshot(), &expected_stats)?;
        Ok(())
    }

    struct SpendChainFixture {
        blocks: Vec<Block>,
        mature_coinbase_outpoint: OutPoint,
        funding_outpoint: OutPoint,
        spend_outpoint: OutPoint,
    }

    fn non_coinbase_spend_chain() -> Result<SpendChainFixture, TestError> {
        let mut blocks = vec![regtest_genesis_block()?];
        let spendable_script = op_true_script();
        for height in 1_u8..=100 {
            let parent = blocks
                .last()
                .ok_or_else(|| std::io::Error::other("missing chain parent"))?;
            blocks.push(child_coinbase_block_with_script(
                parent,
                height,
                spendable_script.clone(),
            )?);
        }

        let mature_coinbase_outpoint = OutPoint::new(blocks[1].txs[0].txid(), 0);
        let mature_coinbase_txout = blocks[1].txs[0].outputs[0].clone();
        let funding_tx =
            spend_to_op_true(mature_coinbase_outpoint, mature_coinbase_txout.value, 1_000)?;
        let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);
        let funding_txout = funding_tx.outputs[0].clone();
        let funding_block = child_block_with_transactions(
            blocks
                .last()
                .ok_or_else(|| std::io::Error::other("missing funding parent"))?,
            101,
            vec![funding_tx],
        )?;
        blocks.push(funding_block);

        let spend_tx = spend_to_op_true(funding_outpoint, funding_txout.value, 1_000)?;
        let spend_outpoint = OutPoint::new(spend_tx.txid(), 0);
        let spend_block = child_block_with_transactions(
            blocks
                .last()
                .ok_or_else(|| std::io::Error::other("missing spend parent"))?,
            102,
            vec![spend_tx],
        )?;
        blocks.push(spend_block);

        Ok(SpendChainFixture {
            blocks,
            mature_coinbase_outpoint,
            funding_outpoint,
            spend_outpoint,
        })
    }

    fn expected_coin_stats(blocks: &[&Block]) -> Result<CoinStats, TestError> {
        let mut stats = CoinStats::default();
        let mut live_outputs = HashMap::<OutPoint, (TxOut, u32, bool)>::new();
        for (height, block) in blocks.iter().enumerate() {
            let height = u32::try_from(height)?;
            if height == 0 {
                stats.finish_block(height, u64::try_from(block.txs.len())?);
                continue;
            }
            for tx in &block.txs {
                let txid = tx.txid();
                for (vout, txout) in tx.outputs.iter().enumerate() {
                    let outpoint = OutPoint::new(txid, u32::try_from(vout)?);
                    stats.insert_utxo(&outpoint, txout, height, tx.is_coinbase());
                    live_outputs.insert(outpoint, (txout.clone(), height, tx.is_coinbase()));
                }
                if tx.is_coinbase() {
                    continue;
                }
                for input in &tx.inputs {
                    let outpoint = input.previous_output;
                    let Some((txout, output_height, coinbase)) = live_outputs.remove(&outpoint)
                    else {
                        return Err(std::io::Error::other(format!(
                            "missing expected prevout {outpoint:?}"
                        ))
                        .into());
                    };
                    stats.remove_utxo(&outpoint, &txout, output_height, coinbase);
                }
            }
            stats.finish_block(height, u64::try_from(block.txs.len())?);
        }
        Ok(stats)
    }

    /// Asserts coin statistics from the engine coin store, the coin authority
    /// under the storage engine, against an independently computed expectation.
    /// MuHash accumulators compare through `finalize_hash`, the canonical
    /// coinstats identity: `scan_coin_stats` and incremental insert/remove
    /// bookkeeping carry removals in different internal accumulator fields, so
    /// raw-struct equality is not the identity.
    fn assert_engine_coin_stats(
        handles: &Chainstate,
        listener: &CoinStats,
        expected: &CoinStats,
    ) -> Result<(), TestError> {
        let reader = handles.utxo_reader();
        let snapshot = reader.scan_coin_snapshot()?;
        let coins = UtxoSet::new();
        for row in snapshot.iter_prefix(bitcoin_rs_storage::ColumnFamily::Coins, &[])? {
            let (_key, value) = row?;
            coins.insert_parsed_record(
                bitcoin_rs_storage::utxo::UtxoRecord::from_encoded(value.into_boxed_slice())
                    .map_err(TestError::Utxo)?,
            );
        }
        let scanned = coins.with_stable_view(|view| {
            bitcoin_rs_storage::utxo::stats::scan_coin_stats(view, expected.height, true)
        })?;
        assert_eq!(
            handles
                .applied_tip_snapshot()
                .ok_or_else(|| TestError::message("missing applied tip"))?
                .chain_tx_count
                .to_wire(),
            expected.tx_count,
        );
        assert_eq!(scanned.height, expected.height);
        assert_eq!(scanned.total_amount, expected.total_amount);
        assert_eq!(scanned.bogo_size, expected.bogo_size);
        assert_eq!(scanned.utxo_count, expected.utxo_count);
        assert_eq!(listener.tx_count, expected.tx_count);
        assert_eq!(
            scanned.muhash.finalize_hash(),
            expected.muhash.finalize_hash(),
            "engine coin set must match the independently computed set",
        );
        Ok(())
    }

    fn apply_handles_with_coin_stats(
        network: Network,
        chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
        applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
        block_tree: Arc<RwLock<BlockTree>>,
    ) -> (Chainstate, Arc<CoinStatsListener>) {
        let (handles, coin_stats, _utxo) =
            apply_handles_with_coin_stats_and_utxo(network, chain_tip, applied_tip, block_tree);
        (handles, coin_stats)
    }

    fn apply_handles_with_coin_stats_and_utxo(
        network: Network,
        chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
        applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
        block_tree: Arc<RwLock<BlockTree>>,
    ) -> (Chainstate, Arc<CoinStatsListener>, Arc<UtxoSet>) {
        let coin_stats = Arc::new(CoinStatsListener::new(CoinStats::default()));
        let mut utxo = UtxoSet::new();
        utxo.track_coin_stats((*coin_stats).clone());
        let utxo = Arc::new(utxo);
        let chain_events = bitcoin_rs_chain::events::ChainEventPublisher::detached(0);
        let handles = Chainstate::new(
            network,
            chain_tip,
            applied_tip,
            block_tree,
            Arc::clone(&utxo),
            Arc::clone(&coin_stats),
            Arc::new(chain_events),
        );
        (handles, coin_stats, utxo)
    }

    fn regtest_genesis_block() -> Result<Block, TestError> {
        let bytes = Vec::<u8>::from_hex(REGTEST_GENESIS_HEX)?;
        Ok(deserialize::<Block>(&bytes)?)
    }

    fn child_coinbase_block(parent: &Block, height: u8) -> Result<Block, TestError> {
        child_coinbase_block_with_script(
            parent,
            height,
            parent.txs[0].outputs[0].script_pubkey.clone(),
        )
    }

    fn child_coinbase_block_with_script(
        parent: &Block,
        height: u8,
        script_pubkey: Script,
    ) -> Result<Block, TestError> {
        let mut block = parent.clone();
        block.header.prev_blockhash = parent.block_hash();
        block.header.time = parent.header.time.saturating_add(1);
        block.txs.truncate(1);
        block.txs[0].inputs[0].script_sig = vec![1, height].into();
        block.txs[0].outputs[0].script_pubkey = script_pubkey;
        block.header.merkle_root = regtest_fixture::merkle_root(&block.txs)
            .ok_or_else(|| std::io::Error::other("child block should have merkle root"))?;
        regtest_fixture::mine_block_to_declared_target(&mut block)?;
        Ok(block)
    }

    fn child_block_with_transactions(
        parent: &Block,
        height: u8,
        transactions: Vec<Tx>,
    ) -> Result<Block, TestError> {
        let mut block = child_coinbase_block(parent, height)?;
        block.txs.extend(transactions);
        block.header.merkle_root = regtest_fixture::merkle_root(&block.txs)
            .ok_or_else(|| std::io::Error::other("child block should have merkle root"))?;
        regtest_fixture::mine_block_to_declared_target(&mut block)?;
        Ok(block)
    }

    fn spend_to_op_true(
        previous_output: OutPoint,
        previous_value: Amount,
        fee: u64,
    ) -> Result<Tx, TestError> {
        let value = previous_value
            .to_sat()
            .checked_sub(fee)
            .ok_or_else(|| std::io::Error::other("spend fee exceeds previous output value"))?;
        Ok(Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output,
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(value),
                script_pubkey: op_true_script(),
            }],
        })
    }

    fn op_true_script() -> Script {
        vec![0x51].into()
    }
}
mod tx_ingress_e2e {
    use std::io::ErrorKind;
    use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    use bitcoin_rs_node::test_support::TestError;

    type Result<T, E = TestError> = core::result::Result<T, E>;
    use crate::support::{p2sh_true_output, p2sh_true_spend_script_sig, parent_txid};
    use bitcoin::hashes::Hash as _;
    use bitcoin::p2p::Magic;
    use bitcoin::p2p::message_blockdata::Inventory;
    use bitcoin_rs_consensus::primitives::{
        Amount, BlockImage, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid,
        Witness,
    };
    use bitcoin_rs_mempool::MempoolGateway;
    use bitcoin_rs_node::p2p::{
        DEFAULT_TX_RELAY_QUEUE_CAPACITY, InboundBody, PeerRelaySink, TxRelayQueue,
        spawn_tx_relay_worker,
    };
    use bitcoin_rs_node::state::NodeState;
    use bitcoin_rs_node::tx_ingress::spawn_tx_ingress_consumer;
    use bitcoin_rs_node::{Network, NodeConfig};
    use bitcoin_rs_p2p::PeerRole;
    use bitcoin_rs_p2p::dispatch::dispatch_inbound_full;
    use bitcoin_rs_p2p::handshake::{run_inbound_handshake, version_message};
    use bitcoin_rs_p2p::wire::{PeerError, read_message, write_message};
    use bitcoin_rs_p2p::{InboundTx, Message, Peer, PeerLease};
    use bitcoin_rs_storage::utxo::contract::{BlockChanges, UtxoAdd};
    use bitcoin_rs_wire::mining::{
        BlockTemplateRequest, BlockTemplateResult, BlockValidationResult, FakeMiningControl,
        MiningControl, MiningControlError, MiningInfo,
    };
    use crossbeam_channel::Sender;

    const READ_POLL: Duration = Duration::from_millis(200);
    const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(10);
    const ABSENCE_WINDOW: Duration = Duration::from_millis(700);
    const RELAY_ABSENCE_WINDOW: Duration = Duration::from_secs(31);
    const OBSERVE_TIMEOUT: Duration = Duration::from_secs(35);
    const COLLECT_SLICE: Duration = Duration::from_millis(200);

    fn tx_inv(txid: &Txid) -> Message {
        Message::Inv(vec![Inventory::Transaction(
            bitcoin::hashes::Hash::from_byte_array(*txid.as_bytes()),
        )])
    }

    fn open_node() -> Result<(NodeState, tempfile::TempDir)> {
        let dir = tempfile::tempdir()?;
        let mut config = NodeConfig::default_for_network(Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p.listen.clear();
        let state = NodeState::open(config, None)?;
        Ok((state, dir))
    }

    fn fund_utxo(state: &NodeState, parent: Txid, value: u64) -> Result<()> {
        fund_utxo_script(state, parent, value, p2sh_true_output().as_bytes().to_vec())
    }

    fn fund_utxo_script(
        state: &NodeState,
        parent: Txid,
        value: u64,
        script_pubkey: Vec<u8>,
    ) -> Result<()> {
        let mut changes = BlockChanges::with_capacity(1, 0);
        changes.add(UtxoAdd::new(
            OutPoint::new(parent, 0),
            TxOut {
                value: Amount::from_sat(value),
                script_pubkey: Script::from_bytes(script_pubkey),
            },
            false,
            100,
        ));
        bitcoin_rs_storage::utxo::contract::populate_block_changes(
            state.chainstate().coins(),
            &changes,
        )
        .map_err(|error| TestError::message(format!("utxo commit failed: {error}")))
    }

    fn spending_tx(parent: Txid, output_value: u64) -> Tx {
        spending_tx_with_script(parent, output_value, p2sh_true_spend_script_sig())
    }

    fn spending_tx_with_script(parent: Txid, output_value: u64, script_sig: Script) -> Tx {
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(parent, 0),
                script_sig,
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(output_value),
                script_pubkey: Script::from_bytes(vec![0x6A, 0x04, 0xAA, 0xBB, 0xCC, 0xDD]),
            }],
            lock_time: LockTime::ZERO,
        }
    }

    #[derive(Default)]
    struct RecordingMining {
        publishes: AtomicU64,
    }

    impl RecordingMining {
        fn publish_count(&self) -> u64 {
            self.publishes.load(Ordering::Relaxed)
        }
    }

    impl MiningControl for RecordingMining {
        fn get_block_template(
            &self,
            _request: BlockTemplateRequest,
        ) -> Result<BlockTemplateResult, MiningControlError> {
            Err(MiningControlError::Failed(
                "not implemented".to_owned().into(),
            ))
        }

        fn mining_info(&self) -> Result<MiningInfo, MiningControlError> {
            Err(MiningControlError::Failed(
                "not implemented".to_owned().into(),
            ))
        }

        fn network_hash_ps(&self, _lookup: i64, _height: i64) -> Result<f64, MiningControlError> {
            Err(MiningControlError::Failed(
                "not implemented".to_owned().into(),
            ))
        }

        fn submit_block(
            &self,
            _payload: BlockImage,
        ) -> Result<BlockValidationResult, MiningControlError> {
            Err(MiningControlError::Failed(
                "not implemented".to_owned().into(),
            ))
        }

        fn submit_header(
            &self,
            _header: bitcoin_rs_consensus::primitives::Header,
        ) -> Result<(), MiningControlError> {
            Err(MiningControlError::Failed(
                "not implemented".to_owned().into(),
            ))
        }

        fn publish_generation(&self) {
            self.publishes.fetch_add(1, Ordering::Relaxed);
        }

        fn publish_fee_delta_generation(&self, _fee_delta_sequence: u64) {
            self.publishes.fetch_add(1, Ordering::Relaxed);
        }

        fn generate(
            &self,
            _request: bitcoin_rs_wire::mining::GenerateRequest,
        ) -> Result<Vec<bitcoin_rs_wire::mining::GeneratedBlock>, MiningControlError> {
            Err(MiningControlError::Failed(
                "not implemented".to_owned().into(),
            ))
        }
    }

    fn loopback_skip() -> Option<String> {
        match TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))) {
            Ok(listener) => {
                drop(listener);
                None
            }
            Err(error) => Some(format!("loopback TCP unavailable: {error}")),
        }
    }

    #[derive(Clone)]
    struct PeerWiring {
        magic: Magic,
        peer_table: Arc<bitcoin_rs_p2p::PeerTable>,
        tx_policy: Arc<bitcoin_rs_node::p2p::NodeTxPolicy>,
        ingress_tx: Sender<InboundBody>,
        stop: Arc<AtomicBool>,
    }

    struct LoopbackPeer {
        dialer: TcpStream,
        peer_table: Arc<bitcoin_rs_p2p::PeerTable>,
        peer_addr: SocketAddr,
        lease: PeerLease,
        pump: Option<std::thread::JoinHandle<()>>,
        service: Option<std::thread::JoinHandle<()>>,
    }

    impl LoopbackPeer {
        fn close(&mut self) -> bool {
            self.lease.cancel();
            let _ = self.dialer.shutdown(Shutdown::Both);
            self.peer_table.remove_current(
                bitcoin_rs_p2p::PeerEndpoint::Ip(self.peer_addr),
                &self.lease,
            );
            let service_ok = self
                .service
                .take()
                .is_none_or(|handle| handle.join().is_ok());
            let pump_ok = self.pump.take().is_none_or(|handle| handle.join().is_ok());
            service_ok && pump_ok
        }
    }

    impl Drop for LoopbackPeer {
        fn drop(&mut self) {
            let joined = self.close();
            if !std::thread::panicking() {
                assert!(joined, "loopback peer worker panicked");
            }
        }
    }

    fn open_loopback_peer(
        wiring: &PeerWiring,
        gateway: Arc<MempoolGateway>,
        name: &'static str,
    ) -> Result<LoopbackPeer> {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
        let dialer = TcpStream::connect(listener.local_addr()?)?;
        let (accepted, peer_addr) = listener.accept()?;

        let (outbound_tx, outbound_rx) =
            crossbeam_channel::unbounded::<bitcoin_rs_p2p::QueuedFrame>();
        let lease = PeerLease::new_inbound(outbound_tx);
        let mut wire_out = accepted.try_clone().map_err(|error| {
            TestError::message(format!("accepted stream clone failed: {error}"))
        })?;
        wire_out.set_write_timeout(Some(READ_POLL))?;
        let reader = accepted;
        let magic = wiring.magic;
        let mut peer = LoopbackPeer {
            dialer,
            peer_table: Arc::clone(&wiring.peer_table),
            peer_addr,
            lease: lease.clone(),
            pump: None,
            service: None,
        };
        wiring
            .peer_table
            .register(bitcoin_rs_p2p::PeerEndpoint::Ip(peer_addr), lease.clone());
        let pump_lease = lease.clone();
        peer.pump = Some(
            std::thread::Builder::new()
                .name(format!("ingress-e2e-pump-{name}"))
                .spawn(move || {
                    while !pump_lease.is_cancelled() {
                        match outbound_rx.recv_timeout(READ_POLL) {
                            Ok(frame) => {
                                if write_message(&mut wire_out, magic, frame.message()).is_err() {
                                    break;
                                }
                            }
                            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
                            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
                        }
                    }
                })?,
        );

        let wiring = wiring.clone();
        peer.service = Some(
            std::thread::Builder::new()
                .name(format!("ingress-e2e-node-{name}"))
                .spawn(move || {
                    serve_connection(reader, peer_addr, &lease, &gateway, &wiring);
                })?,
        );

        Ok(peer)
    }

    fn serve_connection(
        stream: TcpStream,
        peer_addr: SocketAddr,
        lease: &PeerLease,
        gateway: &Arc<MempoolGateway>,
        wiring: &PeerWiring,
    ) {
        let magic = wiring.magic;
        let stream = stream;
        if stream.set_read_timeout(Some(READ_POLL)).is_err() {
            return;
        }
        let mut peer = Peer::new(stream, magic);
        let deadline = Instant::now() + HANDSHAKE_DEADLINE;
        if run_inbound_handshake(
            &mut peer,
            1,
            0,
            bitcoin::p2p::ServiceFlags::NETWORK | bitcoin::p2p::ServiceFlags::WITNESS,
            bitcoin_rs_consensus::primitives::USER_AGENT,
            lease,
            deadline,
        )
        .is_err()
        {
            return;
        }
        let Some(version) = peer.remote_version.as_ref() else {
            return;
        };
        let Ok(addr_bind) = peer.stream.local_addr() else {
            return;
        };
        let mut info = bitcoin_rs_p2p::PeerInfo::inbound_from_version(
            peer_addr,
            addr_bind,
            version,
            0,
            0,
            Arc::new(bitcoin_rs_p2p::PeerCounters::default()),
        );
        info.wtxid_relay = peer.wtxid_relay.peer_supported();
        if !wiring
            .peer_table
            .publish_info(bitcoin_rs_p2p::PeerEndpoint::Ip(peer_addr), lease, info)
        {
            return;
        }
        let _ = peer.stream.set_read_timeout(Some(READ_POLL));
        loop {
            if wiring.stop.load(Ordering::Relaxed) {
                return;
            }
            let inventory = bitcoin_rs_node::p2p::RefTxInventory(gateway.as_ref());
            wiring.tx_policy.poll_transaction_requests(&inventory);
            match read_message(&mut peer.stream, magic) {
                Ok((message, _raw)) => {
                    if let Message::Tx(tx) = message {
                        let source = lease.source_ip(peer_addr);
                        let _ = wiring
                            .ingress_tx
                            .try_send(InboundBody::from(InboundTx::new(tx, source)));
                        continue;
                    }
                    let mut send = |response: Message| {
                        lease
                            .send(response)
                            .map_err(|_| PeerError::Protocol("outbound lease closed or saturated"))
                    };
                    let _ = dispatch_inbound_full(
                        &mut peer,
                        &message,
                        None,
                        Some(&inventory),
                        bitcoin_rs_p2p::listener::TxPolicyObserver::transaction_serving_sequence(
                            wiring.tx_policy.as_ref(),
                            lease.source_ip(peer_addr),
                        ),
                        &|| true,
                        &|| true,
                        &mut send,
                        &mut |_| {},
                        &mut |items| {
                            wiring
                                .tx_policy
                                .announce_transactions(lease.source_ip(peer_addr), &items);
                            wiring.tx_policy.poll_transaction_requests(&inventory);
                        },
                    );
                }
                Err(PeerError::Io(error))
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                Err(_) => return,
            }
        }
    }

    fn dial_handshake(dialer: &TcpStream, magic: Magic, wtxid_relay: bool) -> Result<()> {
        let mut stream = dialer
            .try_clone()
            .map_err(|error| TestError::message(format!("dialer clone failed: {error}")))?;
        stream.set_read_timeout(Some(HANDSHAKE_DEADLINE))?;
        write_message(
            &mut stream,
            magic,
            &Message::Version(version_message(
                7,
                0,
                PeerRole::FullRelay,
                bitcoin::p2p::ServiceFlags::NETWORK | bitcoin::p2p::ServiceFlags::WITNESS,
                bitcoin_rs_consensus::primitives::USER_AGENT,
            )),
        )?;
        loop {
            let (message, _raw) = read_message(&mut stream, magic)?;
            if matches!(message, Message::Verack) {
                break;
            }
        }
        if wtxid_relay {
            write_message(&mut stream, magic, &Message::WtxidRelay)?;
        }
        write_message(&mut stream, magic, &Message::Verack)?;
        Ok(())
    }

    fn write_frame(dialer: &TcpStream, magic: Magic, message: &Message) -> Result<()> {
        let mut stream = dialer
            .try_clone()
            .map_err(|error| TestError::message(format!("dialer clone failed: {error}")))?;
        write_message(&mut stream, magic, message)
            .map(|_| ())
            .map_err(|error| TestError::message(format!("dialer write failed: {error}")))
    }

    fn collect_frames(dialer: &TcpStream, magic: Magic, until: Instant) -> Result<Vec<Message>> {
        let mut stream = dialer
            .try_clone()
            .map_err(|error| TestError::message(format!("dialer clone failed: {error}")))?;
        stream.set_read_timeout(Some(READ_POLL))?;
        let mut frames = Vec::new();
        while Instant::now() < until {
            match read_message(&mut stream, magic) {
                Ok((message, _raw)) => frames.push(message),
                Err(PeerError::Io(error))
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                Err(error) => {
                    return Err(TestError::message(format!("dialer read failed: {error}")));
                }
            }
        }
        Ok(frames)
    }

    fn announces_tx(frames: &[Message], txid: &Txid) -> bool {
        frames.iter().any(|message| match message {
            Message::Inv(items) => items.iter().any(|item| match item {
                Inventory::Transaction(hash) => hash.as_byte_array() == txid.as_bytes(),
                _ => false,
            }),
            _ => false,
        })
    }

    fn requests_tx(frames: &[Message], txid: &Txid) -> bool {
        frames.iter().any(|message| match message {
            Message::GetData(items) => items.iter().any(|item| match item {
                Inventory::WitnessTransaction(hash) => hash.as_byte_array() == txid.as_bytes(),
                _ => false,
            }),
            _ => false,
        })
    }

    fn wait_for_tx_inv(
        dialer: &TcpStream,
        magic: Magic,
        txid: &Txid,
        timeout: Duration,
    ) -> Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            let slice = deadline.min(Instant::now() + COLLECT_SLICE);
            let frames = collect_frames(dialer, magic, slice)?;
            if announces_tx(&frames, txid) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(TestError::message(format!(
                    "relay inv for tx {txid} did not arrive within {timeout:?}"
                )));
            }
        }
    }

    fn wait_for_tx_getdata(
        dialer: &TcpStream,
        magic: Magic,
        txid: &Txid,
        timeout: Duration,
    ) -> Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            let slice = deadline.min(Instant::now() + COLLECT_SLICE);
            let frames = collect_frames(dialer, magic, slice)?;
            if requests_tx(&frames, txid) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(TestError::message(format!(
                    "getdata for tx {txid} did not arrive within {timeout:?}"
                )));
            }
        }
    }

    fn collect_until_inv(dialer: &TcpStream, magic: Magic) -> Result<Vec<Message>> {
        let deadline = Instant::now() + OBSERVE_TIMEOUT;
        loop {
            let frames =
                collect_frames(dialer, magic, deadline.min(Instant::now() + COLLECT_SLICE))?;
            if frames
                .iter()
                .any(|message| matches!(message, Message::Inv(_)))
            {
                return Ok(frames);
            }
            if Instant::now() >= deadline {
                return Err(TestError::message(
                    "delayed transaction inventory did not arrive",
                ));
            }
        }
    }

    fn wait_until(timeout: Duration, predicate: impl Fn() -> bool) -> Result<()> {
        let deadline = Instant::now() + timeout;
        while !predicate() {
            if Instant::now() >= deadline {
                return Err(TestError::message(format!(
                    "condition did not hold within {timeout:?}"
                )));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }

    struct Harness {
        state: NodeState,
        magic: Magic,
        gateway: Arc<MempoolGateway>,
        mining: Arc<FakeMiningControl>,
        shutdown: bitcoin_rs_consensus::latch::LatchWriter,
        stop: Arc<AtomicBool>,
        source: LoopbackPeer,
        bystander: LoopbackPeer,
        ingress: Option<std::thread::JoinHandle<()>>,
        relay: Option<std::thread::JoinHandle<()>>,
        relay_queue: TxRelayQueue,
        _dir: tempfile::TempDir,
    }

    impl Harness {
        fn build(source_marker: u8) -> Result<Self> {
            let (state, dir) = open_node()?;
            let magic = Magic::from_bytes(state.config().p2p.magic);
            let gateway = state.mempool_gateway();

            let ingress_tx = state.inbound_tx_sender();
            let ingress_rx = state
                .take_inbound_tx_receiver()
                .ok_or_else(|| TestError::message("inbound tx receiver already taken"))?;
            let (relay, relay_rx) = TxRelayQueue::new(DEFAULT_TX_RELAY_QUEUE_CAPACITY);
            let mining = FakeMiningControl::unavailable("not implemented");
            let mining_control: Arc<dyn MiningControl> = mining.clone();
            let shutdown = bitcoin_rs_consensus::latch::LatchWriter::new();

            let wiring = PeerWiring {
                magic,
                peer_table: state.peer_table(),
                tx_policy: Arc::clone(&state.tx_policy),
                ingress_tx,
                stop: Arc::new(AtomicBool::new(false)),
            };

            fund_utxo(&state, parent_txid(source_marker), 50_000)?;

            let source = open_loopback_peer(&wiring, Arc::clone(&gateway), "source")?;
            let bystander = open_loopback_peer(&wiring, Arc::clone(&gateway), "bystander")?;
            dial_handshake(&source.dialer, magic, false)?;
            dial_handshake(&bystander.dialer, magic, false)?;
            wait_until(OBSERVE_TIMEOUT, || {
                wiring
                    .peer_table
                    .ready_source(bitcoin_rs_p2p::PeerEndpoint::Ip(source.peer_addr))
                    .is_some()
                    && wiring
                        .peer_table
                        .ready_source(bitcoin_rs_p2p::PeerEndpoint::Ip(bystander.peer_addr))
                        .is_some()
            })?;

            let mut harness = Self {
                state,
                magic,
                gateway,
                mining,
                shutdown,
                stop: wiring.stop,
                source,
                bystander,
                ingress: None,
                relay: None,
                relay_queue: relay.clone(),
                _dir: dir,
            };
            harness.relay = Some(spawn_tx_relay_worker(
                PeerRelaySink::new(Arc::clone(&harness.state.tx_policy)),
                relay_rx,
                Arc::downgrade(&harness.gateway),
                harness.shutdown.reader(),
            )?);
            harness.ingress = Some(spawn_tx_ingress_consumer(
                &harness.state,
                Arc::clone(&harness.gateway),
                mining_control,
                harness.shutdown.reader(),
                ingress_rx,
                relay,
            )?);
            Ok(harness)
        }

        fn tx_in_mempool(&self, txid: &Txid) -> bool {
            self.state.mempool_gateway().read().contains_txid(txid)
        }

        fn connect_peer(&self, name: &'static str, wtxid_relay: bool) -> Result<LoopbackPeer> {
            let wiring = PeerWiring {
                magic: self.magic,
                peer_table: self.state.peer_table(),
                tx_policy: Arc::clone(&self.state.tx_policy),
                ingress_tx: self.state.inbound_tx_sender(),
                stop: Arc::clone(&self.stop),
            };
            let peer = open_loopback_peer(&wiring, Arc::clone(&self.gateway), name)?;
            dial_handshake(&peer.dialer, self.magic, wtxid_relay)?;
            wait_until(OBSERVE_TIMEOUT, || {
                wiring
                    .peer_table
                    .ready_source(bitcoin_rs_p2p::PeerEndpoint::Ip(peer.peer_addr))
                    .is_some()
            })?;
            Ok(peer)
        }
    }

    impl Drop for Harness {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            self.shutdown.trigger();
            let source_ok = self.source.close();
            let bystander_ok = self.bystander.close();
            let ingress_ok = self
                .ingress
                .take()
                .is_none_or(|handle| handle.join().is_ok());
            let relay_ok = self.relay.take().is_none_or(|handle| handle.join().is_ok());
            if !std::thread::panicking() {
                assert!(
                    source_ok && bystander_ok && ingress_ok && relay_ok,
                    "transaction ingress harness worker panicked"
                );
            }
        }
    }

    #[test]
    fn full_relay_queue_does_not_block_peer_admission_or_mining_wake() -> Result<()> {
        let (state, _dir) = open_node()?;
        fund_utxo(&state, parent_txid(0xDD), 50_000)?;
        let gateway = state.mempool_gateway();
        let (relay, _relay_rx) = TxRelayQueue::new(1);
        let pending = spending_tx(parent_txid(0xEE), 40_000);
        assert!(relay.announce(pending.txid(), pending.wtxid(), None, u64::MAX));
        let mining = Arc::new(RecordingMining::default());
        let mining_control: Arc<dyn MiningControl> = Arc::<RecordingMining>::clone(&mining);
        let shutdown = bitcoin_rs_consensus::latch::LatchWriter::new();
        let (ingress_tx, ingress_rx) = crossbeam_channel::bounded(1);
        let tx = spending_tx(parent_txid(0xDD), 40_000);
        let txid = tx.txid();
        let (outbound_tx, _outbound_rx) = crossbeam_channel::bounded(1);
        let source =
            PeerLease::new(outbound_tx).source_ip(SocketAddr::from((Ipv4Addr::LOCALHOST, 8333)));
        let ingress = spawn_tx_ingress_consumer(
            &state,
            Arc::clone(&gateway),
            mining_control,
            shutdown.reader(),
            ingress_rx,
            relay.clone(),
        )?;

        let observed = ingress_tx
            .try_send(InboundBody::from(InboundTx::new(tx, source)))
            .map_err(|error| {
                TestError::message(format!("failed to queue peer transaction: {error}"))
            })
            .and_then(|()| {
                wait_until(OBSERVE_TIMEOUT, || {
                    gateway.read().contains_txid(&txid) && mining.publish_count() >= 1
                })
            });
        shutdown.trigger();
        let joined = ingress.join();
        observed?;
        joined.map_err(|_| TestError::message("transaction ingress worker panicked"))?;
        assert_eq!(relay.enqueued(), 1);
        assert_eq!(relay.dropped(), 1);
        assert!(gateway.read().contains_txid(&txid));
        Ok(())
    }

    #[test]
    fn witness_transaction_relays_txid_and_wtxid_to_mixed_peers() -> Result<()> {
        if let Some(reason) = loopback_skip() {
            tracing::warn!(%reason, "skipping tx ingress e2e");
            return Ok(());
        }
        let harness = Harness::build(0xA1)?;
        let witness_peer = harness.connect_peer("wtxid", true)?;
        let parent = parent_txid(0xA2);
        let witness_script = vec![0x51];
        let mut locking_script = vec![0x00, 0x20];
        locking_script.extend_from_slice(
            bitcoin::hashes::sha256::Hash::hash(&witness_script).as_byte_array(),
        );
        fund_utxo_script(&harness.state, parent, 50_000, locking_script)?;
        let mut tx = spending_tx_with_script(parent, 40_000, Script::new());
        tx.inputs[0].witness = Witness::from_stack(vec![witness_script]);
        let txid = tx.txid();
        let wtxid = tx.wtxid();
        assert_ne!(txid.as_bytes(), wtxid.as_bytes());
        write_frame(&harness.source.dialer, harness.magic, &Message::Tx(tx))?;
        wait_until(OBSERVE_TIMEOUT, || harness.tx_in_mempool(&txid))?;

        let legacy_frames = collect_until_inv(&harness.bystander.dialer, harness.magic)?;
        let witness_frames = collect_until_inv(&witness_peer.dialer, harness.magic)?;

        let inventories = |frames: &[Message]| -> Vec<Inventory> {
            frames
                .iter()
                .filter_map(|message| match message {
                    Message::Inv(items) => Some(items.as_slice()),
                    _ => None,
                })
                .flatten()
                .copied()
                .collect()
        };
        assert_eq!(
            inventories(&legacy_frames),
            vec![Inventory::Transaction(bitcoin::Txid::from_byte_array(
                *txid.as_bytes()
            ),)]
        );
        assert_eq!(
            inventories(&witness_frames),
            vec![Inventory::WTx(bitcoin::Wtxid::from_byte_array(
                *wtxid.as_bytes()
            ),)]
        );
        let source_frames = collect_frames(
            &harness.source.dialer,
            harness.magic,
            Instant::now() + RELAY_ABSENCE_WINDOW,
        )?;
        assert_eq!(inventories(&source_frames), []);
        Ok(())
    }

    #[test]
    fn accepted_peer_tx_is_admitted_and_relayed_excluding_the_source() -> Result<()> {
        if let Some(reason) = loopback_skip() {
            tracing::warn!(%reason, "skipping tx ingress e2e");
            return Ok(());
        }
        let harness = Harness::build(0xAA)?;

        let tx = spending_tx(parent_txid(0xAA), 40_000);
        let txid = tx.txid();

        write_frame(&harness.source.dialer, harness.magic, &tx_inv(&txid))?;
        wait_for_tx_getdata(
            &harness.source.dialer,
            harness.magic,
            &txid,
            OBSERVE_TIMEOUT,
        )?;

        write_frame(&harness.source.dialer, harness.magic, &Message::Tx(tx))?;
        wait_until(OBSERVE_TIMEOUT, || harness.tx_in_mempool(&txid)).map_err(|_| {
            TestError::message("admitted tx never reached the shared mempool gateway")
        })?;

        wait_for_tx_inv(
            &harness.bystander.dialer,
            harness.magic,
            &txid,
            OBSERVE_TIMEOUT,
        )?;

        let source_frames = collect_frames(
            &harness.source.dialer,
            harness.magic,
            Instant::now() + RELAY_ABSENCE_WINDOW,
        )?;
        assert!(
            !announces_tx(&source_frames, &txid),
            "source peer must never receive the inv for its own transaction"
        );

        assert!(
            harness.mining.publish_count() >= 1,
            "accepted tx must wake the mining control"
        );
        assert!(
            harness.gateway.have_tx(Hash256::from(txid), false),
            "the admission inventory must report the mempool hold"
        );

        Ok(())
    }

    #[test]
    fn below_min_relay_tx_is_rejected_recorded_and_never_relayed() -> Result<()> {
        if let Some(reason) = loopback_skip() {
            tracing::warn!(%reason, "skipping tx ingress e2e");
            return Ok(());
        }
        let harness = Harness::build(0xCC)?;

        let tx = spending_tx(parent_txid(0xCC), 50_000);
        let txid = tx.txid();

        write_frame(&harness.source.dialer, harness.magic, &tx_inv(&txid))?;
        wait_for_tx_getdata(
            &harness.source.dialer,
            harness.magic,
            &txid,
            OBSERVE_TIMEOUT,
        )?;

        write_frame(&harness.source.dialer, harness.magic, &Message::Tx(tx))?;
        wait_until(OBSERVE_TIMEOUT, || {
            harness.gateway.is_rejected(Hash256::from(txid))
        })
        .map_err(|_| TestError::message("rejected tx never reached the recent-rejects cache"))?;
        assert!(
            !harness.tx_in_mempool(&txid),
            "a below-min-relay tx must not enter the mempool"
        );

        let bystander_frames = collect_frames(
            &harness.bystander.dialer,
            harness.magic,
            Instant::now() + ABSENCE_WINDOW,
        )?;
        assert!(
            !announces_tx(&bystander_frames, &txid),
            "a rejected tx must not be relayed"
        );
        assert_eq!(
            harness.mining.publish_count(),
            0,
            "a rejected tx must not wake the mining control"
        );

        write_frame(&harness.source.dialer, harness.magic, &tx_inv(&txid))?;
        let source_frames = collect_frames(
            &harness.source.dialer,
            harness.magic,
            Instant::now() + ABSENCE_WINDOW,
        )?;
        assert!(
            !requests_tx(&source_frames, &txid),
            "recent-rejects must suppress the follow-up getdata"
        );

        assert_eq!(
            harness.relay_queue.enqueued(),
            0,
            "rejected admission never queues delayed relay"
        );
        Ok(())
    }

    #[test]
    fn rejected_witness_keeps_an_honest_transaction_source() -> Result<()> {
        if let Some(reason) = loopback_skip() {
            tracing::warn!(%reason, "skipping tx ingress e2e");
            return Ok(());
        }
        let harness = Harness::build(0xB1)?;
        let parent = parent_txid(0xB2);
        let witness_script = vec![0x51];
        let mut locking_script = vec![0x00, 0x20];
        locking_script.extend_from_slice(
            bitcoin::hashes::sha256::Hash::hash(&witness_script).as_byte_array(),
        );
        fund_utxo_script(&harness.state, parent, 50_000, locking_script)?;
        let mut valid = spending_tx_with_script(parent, 40_000, Script::new());
        valid.inputs[0].witness = Witness::from_stack(vec![witness_script]);
        let mut invalid = valid.clone();
        invalid.inputs[0].witness = Witness::from_stack(vec![vec![0x00]]);
        let txid = valid.txid();
        let invalid_wtxid = invalid.wtxid();
        assert_eq!(invalid.txid(), txid);
        assert_ne!(invalid_wtxid, valid.wtxid());

        write_frame(&harness.source.dialer, harness.magic, &tx_inv(&txid))?;
        wait_for_tx_getdata(
            &harness.source.dialer,
            harness.magic,
            &txid,
            OBSERVE_TIMEOUT,
        )?;
        write_frame(&harness.bystander.dialer, harness.magic, &tx_inv(&txid))?;
        write_frame(
            &harness.bystander.dialer,
            harness.magic,
            &Message::Ping(771),
        )?;
        let frames = collect_frames(
            &harness.bystander.dialer,
            harness.magic,
            Instant::now() + ABSENCE_WINDOW,
        )?;
        assert!(
            frames.contains(&Message::Pong(771)),
            "alternate announcement was processed"
        );
        assert!(
            !requests_tx(&frames, &txid),
            "one source still owns the request"
        );
        write_frame(&harness.source.dialer, harness.magic, &Message::Tx(invalid))?;
        wait_until(OBSERVE_TIMEOUT, || {
            harness.gateway.have_tx(invalid_wtxid.0, true)
        })?;
        assert!(
            !harness.gateway.have_tx(txid.0, false),
            "witness rejection must not reject the txid"
        );
        wait_for_tx_getdata(
            &harness.bystander.dialer,
            harness.magic,
            &txid,
            OBSERVE_TIMEOUT,
        )?;
        write_frame(
            &harness.bystander.dialer,
            harness.magic,
            &Message::Tx(valid),
        )?;
        wait_until(OBSERVE_TIMEOUT, || harness.tx_in_mempool(&txid))?;
        Ok(())
    }

    #[test]
    fn orphan_parent_reuses_the_completed_childs_announcement_slot() -> Result<()> {
        if let Some(reason) = loopback_skip() {
            tracing::warn!(%reason, "skipping tx ingress e2e");
            return Ok(());
        }
        let harness = Harness::build(0xC1)?;
        let _witness_peer = harness.connect_peer("witness-delay", true)?;
        let parent = parent_txid(0xC2);
        let child = spending_tx(parent, 40_000);
        let child_txid = child.txid();
        write_frame(&harness.source.dialer, harness.magic, &tx_inv(&child_txid))?;
        wait_for_tx_getdata(
            &harness.source.dialer,
            harness.magic,
            &child_txid,
            OBSERVE_TIMEOUT,
        )?;
        let filler = (0u32..4_999)
            .map(|index| {
                let mut hash = [0xC3; 32];
                hash[..4].copy_from_slice(&index.to_le_bytes());
                Inventory::Transaction(bitcoin::Txid::from_byte_array(hash))
            })
            .collect();
        write_frame(&harness.source.dialer, harness.magic, &Message::Inv(filler))?;
        write_frame(&harness.source.dialer, harness.magic, &Message::Ping(772))?;
        let frames = collect_frames(
            &harness.source.dialer,
            harness.magic,
            Instant::now() + ABSENCE_WINDOW,
        )?;
        assert!(
            frames.contains(&Message::Pong(772)),
            "all 5,000 announcements were processed"
        );
        write_frame(&harness.source.dialer, harness.magic, &Message::Tx(child))?;
        wait_for_tx_getdata(
            &harness.source.dialer,
            harness.magic,
            &parent,
            OBSERVE_TIMEOUT,
        )?;
        assert!(!harness.tx_in_mempool(&child_txid));
        Ok(())
    }
}

mod winning_header_driver {
    use bitcoin::hashes::Hash;
    use bitcoin::p2p::message_blockdata::Inventory;
    use bitcoin_rs_chain::chain::regtest_fixture;
    use bitcoin_rs_consensus::primitives::{Block, BlockImage, Hash256};
    use bitcoin_rs_node::state::NodeState;
    use bitcoin_rs_node::test_support::TestError;
    use bitcoin_rs_node::{Network, NodeConfig};
    use bitcoin_rs_p2p::test_support::{
        MessageReceiver, message_channel, synthetic_peer, test_addr,
    };
    use bitcoin_rs_p2p::{InboundBlock, InboundHeaders, Message, PeerLease, PeerSource, PeerTable};
    use crossbeam_channel::{Sender, unbounded};
    use std::sync::Arc;

    struct HeaderPeer {
        source: PeerSource,
        peers: Arc<PeerTable>,
        outbound: MessageReceiver,
        headers: Sender<InboundHeaders>,
        blocks: Sender<InboundBlock>,
    }

    impl HeaderPeer {
        fn connect(
            state: &NodeState,
            height: i32,
        ) -> Result<(bitcoin_rs_node::BlockSync, Self), TestError> {
            let peers = Arc::new(PeerTable::new());
            let endpoint = test_addr(28421, 0)?;
            let (sender, outbound) = message_channel();
            let lease = PeerLease::new(sender);
            peers.register(endpoint, lease.clone());
            peers.publish_info(endpoint, &lease, synthetic_peer(endpoint, height));
            let source = lease.source(endpoint.endpoint());
            let (headers, inbound_headers_rx) = unbounded();
            let (blocks, inbound_blocks_rx) = unbounded();
            let sync = bitcoin_rs_node::sync::block_sync(bitcoin_rs_node::sync::BlockSyncInputs {
                handles: state.chainstate(),
                followers: state.chain_followers(),
                peer_table: Arc::clone(&peers),
                inbound_headers_rx,
                inbound_blocks_rx,
                ibd: state.chainstate().ibd_latch(),
                assumeutxo: None,
                budget: state.budget(),
            });
            let peer = Self {
                source,
                peers,
                outbound,
                headers,
                blocks,
            };
            Ok((sync, peer))
        }

        fn answer(
            &self,
            fork: &[Block],
            end: usize,
            body_floor: usize,
        ) -> Result<Vec<Hash256>, TestError> {
            let mut locators = Vec::new();
            for message in self.outbound.try_iter() {
                match message {
                    Message::GetHeaders(request) => {
                        let first = request.locator_hashes.first().ok_or("empty locator")?;
                        locators.push(Hash256::from_le_bytes(first.as_byte_array()));
                        let start = request
                            .locator_hashes
                            .iter()
                            .find_map(|hash| {
                                let hash = Hash256::from_le_bytes(hash.as_byte_array());
                                if hash == Network::Regtest.genesis_block_hash() {
                                    Some(0)
                                } else {
                                    fork.iter()
                                        .position(|block| block.block_hash().0 == hash)
                                        .map(|index| index + 1)
                                }
                            })
                            .ok_or("locator has no retained fork anchor")?;
                        assert!(start <= end && end <= fork.len());
                        self.headers
                            .send(InboundHeaders {
                                headers: fork[start..end]
                                    .iter()
                                    .map(|block| block.header)
                                    .collect(),
                                source: Some(self.source),
                                wire_response: true,
                            })
                            .map_err(|_| TestError::message("header response queue closed"))?;
                    }
                    Message::GetData(items) => {
                        for item in items {
                            let hash = match item {
                                Inventory::Block(hash) | Inventory::WitnessBlock(hash) => {
                                    Hash256::from_le_bytes(hash.as_byte_array())
                                }
                                _ => {
                                    return Err(TestError::message("unexpected body request type"));
                                }
                            };
                            let (index, block) = fork
                                .iter()
                                .enumerate()
                                .find(|(_, block)| block.block_hash().0 == hash)
                                .ok_or("requested body is outside the advertised fork")?;
                            if index + 1 < body_floor {
                                continue;
                            }
                            let mut inbound = InboundBlock::from_local(block.clone());
                            inbound.source = Some(self.source);
                            self.blocks
                                .send(inbound)
                                .map_err(|_| TestError::message("body response queue closed"))?;
                        }
                    }
                    _ => return Err(TestError::message("unexpected sync message")),
                }
            }
            Ok(locators)
        }
    }

    // P2P-10, SYNC-01, SYNC-02, SYNC-05
    #[test]
    fn winning_header_driver_applies_deep_fork_and_recovers_durable_tip() -> Result<(), TestError> {
        let directory = tempfile::tempdir()?;
        let mut config = NodeConfig::default_for_network(Network::Regtest);
        config.data_dir = directory.path().join("winning-header-node");
        config.p2p.listen.clear();
        let state = NodeState::open(config.clone(), None)?;
        let genesis = Network::Regtest.genesis_block();
        state.apply_block(&BlockImage::from_local(genesis.clone()))?;
        let mut main = Vec::new();
        let mut parent = genesis.block_hash();
        for height in 1..=32 {
            let block = regtest_fixture::mined_regtest_child_at(parent, height)?;
            parent = block.block_hash();
            state.apply_block(&BlockImage::from_local(block.clone()))?;
            main.push(block);
        }
        let _ = state.publish_checkpoint()?;
        state.chainstate().set_header_side_cache_limit(8);
        let original_tip = state
            .chainstate()
            .applied_tip_snapshot()
            .ok_or("missing main tip")?;
        let mut fork = Vec::new();
        let mut parent = genesis.block_hash();
        for height in 1..=35 {
            let mut block = regtest_fixture::mined_regtest_child_at(parent, height)?;
            block.header.time += 64;
            block.header.nonce = 0;
            regtest_fixture::mine_block_to_declared_target(&mut block)?;
            parent = block.block_hash();
            fork.push(block);
        }

        let (sync, peer) = HeaderPeer::connect(&state, 34)?;
        let source = peer.source;
        peer.headers
            .send(InboundHeaders {
                headers: fork[..33].iter().map(|block| block.header).collect(),
                source: Some(source),
                wire_response: true,
            })
            .map_err(|_| TestError::message("initial header queue closed"))?;
        sync.tick();
        assert_eq!(
            peer.answer(&fork, 33, 1)?,
            vec![fork[7].block_hash().0],
            "retention refusal must request its own retained fork anchor"
        );
        assert!(state.chainstate().block_tree_reader().read().len() <= 41);
        assert_eq!(
            state.chainstate().applied_tip_snapshot().as_deref(),
            Some(original_tip.as_ref())
        );

        sync.tick();
        assert_eq!(peer.answer(&fork, 33, 1)?, vec![fork[7].block_hash().0]);
        assert!(state.chainstate().block_tree_reader().read().len() <= 41);
        assert_eq!(
            state
                .chainstate()
                .header_tip()
                .ok_or("missing main header")?
                .hash,
            original_tip.hash
        );

        sync.tick();
        assert_eq!(
            state
                .chainstate()
                .header_tip()
                .ok_or("missing winning header")?
                .hash,
            fork[32].block_hash().0
        );
        assert_eq!(peer.answer(&fork, 34, 1)?, vec![fork[32].block_hash().0]);
        assert!(peer.peers.is_current(source));
        for _ in 0..128 {
            sync.tick();
            let _ = peer.answer(&fork, 34, 1)?;
            if state
                .chainstate()
                .applied_tip_snapshot()
                .is_some_and(|tip| tip.hash == fork[33].block_hash().0)
            {
                break;
            }
        }
        let applied = state
            .chainstate()
            .applied_tip_snapshot()
            .ok_or("missing applied fork")?;
        assert_eq!(
            (applied.height, applied.hash),
            (34, fork[33].block_hash().0)
        );
        sync.tick();
        assert!(state.chainstate().block_tree_reader().read().len() <= 43);
        let expected_utxo = state
            .chainstate()
            .utxo_reader()
            .with_stable_view(|view| view.hash_serialized_3())??;
        drop(sync);
        drop(peer);
        drop(state);

        let resumed = NodeState::open(config.clone(), None)?;
        let restored = resumed
            .chainstate()
            .applied_tip_snapshot()
            .ok_or("missing durable fork")?;
        assert_eq!(
            (restored.height, restored.hash),
            (34, fork[33].block_hash().0)
        );
        assert_eq!(
            resumed
                .chainstate()
                .header_tip()
                .ok_or("missing restored header")?
                .hash,
            restored.hash
        );
        assert_eq!(
            resumed
                .chainstate()
                .utxo_reader()
                .with_stable_view(|view| view.hash_serialized_3())??,
            expected_utxo
        );
        let _ = resumed.publish_checkpoint()?;
        resumed.apply_block(&BlockImage::from_local(fork[34].clone()))?;
        drop(resumed);
        let reopened = NodeState::open(config.clone(), None)?;
        assert_eq!(
            reopened
                .chainstate()
                .applied_tip_snapshot()
                .ok_or("missing continued fork")?
                .hash,
            fork[34].block_hash().0
        );
        reopened.chainstate().set_header_side_cache_limit(8);
        reopened
            .chainstate()
            .maintain_header_retention()
            .map_err(|error| TestError::message(error.to_string()))?;
        assert!(
            reopened
                .chainstate()
                .block_tree_reader()
                .read()
                .lookup(main[31].block_hash().0)
                .is_none(),
            "the old applied branch header must be evicted before body rediscovery"
        );
        let mut parent = main[31].block_hash();
        for height in 33..=36 {
            let block = regtest_fixture::mined_regtest_child_at(parent, height)?;
            parent = block.block_hash();
            main.push(block);
        }
        let (rediscovery_sync, rediscovery_peer) = HeaderPeer::connect(&reopened, 36)?;
        rediscovery_peer
            .headers
            .send(InboundHeaders {
                headers: main.iter().map(|block| block.header).collect(),
                source: Some(rediscovery_peer.source),
                wire_response: true,
            })
            .map_err(|_| TestError::message("rediscovery header queue closed"))?;
        for _ in 0..128 {
            rediscovery_sync.tick();
            let _ = rediscovery_peer.answer(&main, 36, 33)?;
            if reopened
                .chainstate()
                .applied_tip_snapshot()
                .is_some_and(|tip| tip.hash == main[35].block_hash().0)
            {
                break;
            }
        }
        let reused = reopened
            .chainstate()
            .applied_tip_snapshot()
            .ok_or("missing rediscovered main tip")?;
        assert_eq!(
            (reused.height, reused.hash),
            (36, main[35].block_hash().0),
            "revalidated evicted headers must reuse their retained body bytes"
        );
        let reused_utxo = reopened
            .chainstate()
            .utxo_reader()
            .with_stable_view(|view| view.hash_serialized_3())??;
        drop(rediscovery_sync);
        drop(rediscovery_peer);
        drop(reopened);
        let recovered = NodeState::open(config, None)?;
        assert_eq!(
            recovered
                .chainstate()
                .applied_tip_snapshot()
                .ok_or("missing durable rediscovered tip")?
                .hash,
            main[35].block_hash().0
        );
        assert_eq!(
            recovered
                .chainstate()
                .utxo_reader()
                .with_stable_view(|view| view.hash_serialized_3())??,
            reused_utxo
        );
        Ok(())
    }
}
