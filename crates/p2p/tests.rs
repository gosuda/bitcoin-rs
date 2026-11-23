mod core_compat {
    use bitcoin_rs_consensus::primitives::PeerEndpoint;
    use std::collections::BTreeSet;
    use std::io::Cursor;
    use std::net::{Ipv4Addr, TcpListener, TcpStream};
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::thread;
    use std::time::{Duration, Instant};

    use bitcoin::bip152::BlockTransactionsRequest;
    use bitcoin::consensus::encode as bitcoin_encode;
    use bitcoin::hashes::Hash as _;
    use bitcoin::hex::FromHex;
    use bitcoin::p2p::message::{CommandString, NetworkMessage, RawNetworkMessage};
    use bitcoin::p2p::message_blockdata::{GetBlocksMessage, GetHeadersMessage, Inventory};
    use bitcoin::p2p::{Magic, ServiceFlags};
    use bitcoin::{BlockHash, Txid};
    use bitcoin_rs_consensus::primitives::{
        Block, BlockHash as NativeBlockHash, BlockImage, CompactTarget, Hash256, Header,
        consensus_bytes, deserialize,
    };
    use bitcoin_rs_consensus::primitives::{Network, USER_AGENT};
    use bitcoin_rs_p2p::PeerRole;
    use bitcoin_rs_p2p::dispatch::{
        ChainQuery, InventoryServing, dispatch_inbound, dispatch_inbound_full,
    };
    use bitcoin_rs_p2p::handshake::{start, version_message};
    use bitcoin_rs_p2p::inv::MAX_INV_PER_MSG;
    use bitcoin_rs_p2p::listener::{
        ConnectionShared, bind_listener, serve, spawn_outbound_connection,
    };
    use bitcoin_rs_p2p::wire::{
        MAX_HEADERS_MESSAGE_COUNT, MAX_MESSAGE_PAYLOAD, PROTOCOL_VERSION, PeerError, read_message,
        write_message,
    };
    use bitcoin_rs_p2p::{
        BannedSubnet, COMMANDS, CORE_UNTYPED_COMMANDS, FEATURE_VERSION, InboundBlock,
        InboundHeaders, ListenerExtras, Message, NetworkActivity, Peer, PeerState, PeerTable,
    };
    use hashbrown::HashMap;

    const REGTEST_GENESIS_HEX: &str = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff7f20020000000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";

    #[derive(Debug, thiserror::Error)]
    enum TestError {
        #[error(transparent)]
        Hex(#[from] bitcoin::hex::HexToBytesError),
        #[error(transparent)]
        Decode(#[from] bitcoin_rs_consensus::primitives::DecodeError),
        #[error(transparent)]
        Io(#[from] std::io::Error),
        #[error(transparent)]
        Peer(#[from] PeerError),
        #[error(transparent)]
        Listener(#[from] bitcoin_rs_p2p::listener::ListenerError),
        #[error(transparent)]
        TryFromInt(#[from] std::num::TryFromIntError),
        #[error(transparent)]
        CommandString(#[from] bitcoin::p2p::message::CommandStringError),
        #[error("failure: {0}")]
        Failure(String),
    }

    impl From<&'static str> for TestError {
        fn from(msg: &'static str) -> Self {
            Self::Failure(msg.to_owned())
        }
    }

    impl From<String> for TestError {
        fn from(msg: String) -> Self {
            Self::Failure(msg)
        }
    }

    fn btc_bh(hash: NativeBlockHash) -> BlockHash {
        BlockHash::from_byte_array(*hash.as_bytes())
    }

    fn native_bh(hash: &BlockHash) -> NativeBlockHash {
        NativeBlockHash(Hash256::from_le_bytes(hash.as_byte_array()))
    }

    const NETWORK_TABLE: [(Network, Magic, u16); 5] = [
        (Network::Mainnet, Magic::BITCOIN, 8333),
        (Network::Testnet3, Magic::TESTNET3, 18333),
        (Network::Testnet4, Magic::TESTNET4, 48333),
        (Network::Signet, Magic::SIGNET, 38333),
        (Network::Regtest, Magic::REGTEST, 18444),
    ];

    fn genesis_block() -> Result<Block, TestError> {
        let bytes = Vec::<u8>::from_hex(REGTEST_GENESIS_HEX)?;
        Ok(deserialize::<Block>(&bytes)?)
    }

    fn child_headers(parent: &Header, count: usize) -> Vec<Header> {
        let mut headers = Vec::with_capacity(count);
        let mut current = *parent;
        for _ in 0..count {
            let next = Header {
                version: 1,
                prev_blockhash: current.compute_hash(),
                merkle_root: Hash256::default(),
                time: current.time + 1,
                bits: CompactTarget::from_consensus(0x207fffff),
                nonce: 0,
            };
            headers.push(next);
            current = next;
        }
        headers
    }

    fn headers_into_blocks(headers: &[Header]) -> HashMap<NativeBlockHash, Block> {
        headers
            .iter()
            .map(|header| {
                (
                    header.compute_hash(),
                    Block {
                        header: *header,
                        txs: Vec::new(),
                    },
                )
            })
            .collect()
    }

    struct FakeChain {
        active: Vec<Header>,
        bodies: HashMap<NativeBlockHash, Block>,
    }

    impl FakeChain {
        fn new(active: Vec<Header>, bodies: HashMap<NativeBlockHash, Block>) -> Self {
            Self { active, bodies }
        }

        fn active_height(&self, hash: &NativeBlockHash) -> Option<u32> {
            self.active
                .iter()
                .position(|header| header.compute_hash() == *hash)
                .and_then(|position| u32::try_from(position).ok())
        }

        fn header_at(&self, height: u32) -> Option<&Header> {
            let position = usize::try_from(height).ok()?;
            self.active.get(position)
        }
    }

    impl ChainQuery for FakeChain {
        fn stale_tip_announcement(
            &self,
            _tip: bitcoin_rs_consensus::primitives::Hash256,
            _peer_tips: &[bitcoin_rs_consensus::primitives::Hash256],
        ) -> Option<bitcoin_rs_p2p::StaleTipHeaders> {
            None
        }
        fn headers_after(
            &self,
            locator_hashes: &[NativeBlockHash],
            stop_hash: NativeBlockHash,
            limit: usize,
        ) -> Vec<Header> {
            if limit == 0 {
                return Vec::new();
            }

            if locator_hashes.is_empty() {
                let anchored = self
                    .active_height(&stop_hash)
                    .and_then(|height| self.header_at(height))
                    .filter(|header| header.compute_hash() == stop_hash);
                return anchored.map_or_else(Vec::new, |header| vec![*header]);
            }

            let tip_height = u32::try_from(self.active.len().saturating_sub(1)).unwrap_or(0);
            let mut height = locator_hashes
                .iter()
                .find_map(|hash| self.active_height(hash))
                .and_then(|height| height.checked_add(1))
                .unwrap_or(1);
            let has_stop = stop_hash != NativeBlockHash::default();
            let mut headers = Vec::new();
            while height <= tip_height && headers.len() < limit {
                let Some(header) = self.header_at(height) else {
                    break;
                };
                let reached_stop = has_stop && header.compute_hash() == stop_hash;
                headers.push(*header);
                if reached_stop {
                    break;
                }
                let Some(next) = height.checked_add(1) else {
                    break;
                };
                height = next;
            }
            headers
        }

        fn best_block_time(&self) -> Option<u32> {
            self.active.last().map(|header| header.time)
        }

        fn serve_inventory_blocks(
            &self,
            items: &[Inventory],
            _compact_version: Option<u64>,
            headroom: &dyn Fn() -> bool,
            serve: &mut dyn FnMut(Message) -> Result<(), PeerError>,
        ) -> Result<InventoryServing, PeerError> {
            let mut outcome = InventoryServing::default();
            for item in items {
                let Some(hash) = inventory_hash(item) else {
                    outcome.not_found.push(*item);
                    continue;
                };
                let native = native_bh(&hash);
                let known = self
                    .bodies
                    .get(&native)
                    .is_some_and(|block| block.block_hash() == native);
                if known {
                    if !headroom() {
                        outcome.halted = true;
                        return Ok(outcome);
                    }
                    serve(Message::BlockBytes(
                        consensus_bytes(&self.bodies[&native]).into(),
                    ))?;
                } else {
                    outcome.not_found.push(*item);
                }
            }
            Ok(outcome)
        }

        fn block_transactions(
            &self,
            _request: &BlockTransactionsRequest,
            _compact_version: Option<u64>,
            _headroom: &dyn Fn() -> bool,
        ) -> Result<Option<Message>, PeerError> {
            Ok(None)
        }
    }

    fn inventory_hash(item: &Inventory) -> Option<BlockHash> {
        match item {
            Inventory::Block(hash) | Inventory::WitnessBlock(hash) => Some(*hash),
            _ => None,
        }
    }

    fn dispatch_collect(
        peer: &mut Peer<Cursor<Vec<u8>>>,
        message: &Message,
        chain: Option<&dyn ChainQuery>,
    ) -> Result<Vec<Message>, PeerError> {
        let collected = std::cell::RefCell::new(Vec::new());
        dispatch_inbound_full(
            peer,
            message,
            chain,
            None,
            &|| true,
            &|| true,
            &mut |response| {
                collected.borrow_mut().push(response);
                Ok(())
            },
            &mut |_| {},
            &mut |items| collected.borrow_mut().push(Message::GetData(items)),
        )?;
        Ok(collected.into_inner())
    }

    fn ready_peer(magic: Magic) -> Result<Peer<Cursor<Vec<u8>>>, PeerError> {
        let mut peer = Peer::new(Cursor::new(Vec::new()), magic);
        let responses = dispatch_inbound(&mut peer, &version_for_handshake())?;
        assert_eq!(
            responses,
            vec![
                Message::WtxidRelay,
                Message::SendAddrV2,
                Message::SendHeaders,
                Message::Verack
            ],
            "inbound version is answered with the Core feature set then verack"
        );
        dispatch_inbound(&mut peer, &Message::Verack)?;
        assert_eq!(peer.state, PeerState::Ready);
        Ok(peer)
    }

    fn version_for_handshake() -> Message {
        Message::Version(version_message(
            1,
            0,
            PeerRole::FullRelay,
            ServiceFlags::NETWORK | ServiceFlags::WITNESS,
            USER_AGENT,
        ))
    }

    fn get_headers(locator: Vec<NativeBlockHash>, stop: NativeBlockHash) -> Message {
        Message::GetHeaders(GetHeadersMessage::new(
            locator.into_iter().map(btc_bh).collect(),
            btc_bh(stop),
        ))
    }

    fn locator_hashes(headers: &[Header]) -> Vec<NativeBlockHash> {
        headers.iter().map(Header::compute_hash).collect()
    }

    fn raw_frame(magic: Magic, command: &[u8; 12], payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(24 + payload.len());
        frame.extend_from_slice(&magic.to_bytes());
        frame.extend_from_slice(command);
        let length = u32::try_from(payload.len()).unwrap_or(u32::MAX);
        frame.extend_from_slice(&length.to_le_bytes());
        frame.extend_from_slice(&checksum(payload));
        frame.extend_from_slice(payload);
        frame
    }

    fn checksum(payload: &[u8]) -> [u8; 4] {
        use sha2::{Digest, Sha256};
        let first = Sha256::digest(payload);
        let second = Sha256::digest(first);
        let mut digest = [0u8; 4];
        digest.copy_from_slice(&second[..4]);
        digest
    }

    fn command_field(name: &str) -> Result<[u8; 12], TestError> {
        if name.len() > 12 {
            return Err(format!("command {name} exceeds the 12-byte v1 field").into());
        }
        let mut field = [0u8; 12];
        field
            .get_mut(..name.len())
            .ok_or("command field")?
            .copy_from_slice(name.as_bytes());
        Ok(field)
    }

    fn expect_protocol_error<T: std::fmt::Debug>(
        outcome: Result<T, PeerError>,
        why: &'static str,
    ) -> Result<PeerError, TestError> {
        match outcome {
            Err(error) => Ok(error),
            Ok(value) => Err(format!("{why}: unexpectedly succeeded with {value:?}").into()),
        }
    }

    fn rust_bitcoin_frame(payload: NetworkMessage) -> Vec<u8> {
        bitcoin_encode::serialize(&RawNetworkMessage::new(Magic::REGTEST, payload))
    }

    fn our_frame(message: &Message) -> Result<Vec<u8>, TestError> {
        let mut buffer = Vec::new();
        write_message(&mut buffer, Magic::REGTEST, message)?;
        Ok(buffer)
    }

    const CORE_31_1_PROTOCOL_VERSION: u32 = 70_016;

    const CORE_COMPAT_COMMANDS: [&str; 36] = [
        "version",
        "verack",
        "addr",
        "inv",
        "getdata",
        "notfound",
        "getblocks",
        "getheaders",
        "mempool",
        "tx",
        "block",
        "headers",
        "sendheaders",
        "getaddr",
        "ping",
        "pong",
        "merkleblock",
        "filterload",
        "filteradd",
        "filterclear",
        "getcfilters",
        "cfilter",
        "getcfheaders",
        "cfheaders",
        "getcfcheckpt",
        "cfcheckpt",
        "sendcmpct",
        "cmpctblock",
        "getblocktxn",
        "blocktxn",
        "reject",
        "alert",
        "feefilter",
        "wtxidrelay",
        "addrv2",
        "sendaddrv2",
    ];

    const EXTENSION_COMMANDS: [&str; 6] = [
        "feature",
        "sendpackages",
        "ancpkginfo",
        "getpkgtxns",
        "pkgtxns",
        "staletip",
    ];

    fn is_own_typed_empty_payload_outcome(
        command: &str,
        outcome: &Result<(Message, bytes::Bytes), PeerError>,
    ) -> bool {
        match (command, outcome) {
            ("feature", Err(PeerError::Feature(_)))
            | ("sendpackages" | "ancpkginfo" | "getpkgtxns", Err(PeerError::Package(_)))
            | ("staletip", Err(PeerError::StaleTip(_))) => true,
            ("pkgtxns", Ok((Message::PkgTxnsPayload(payload), _))) => payload.is_empty(),
            _ => false,
        }
    }

    // P2P-01
    #[test]
    fn command_inventory_is_the_core_compat_set_plus_the_declared_extensions() {
        let core: BTreeSet<&str> = CORE_COMPAT_COMMANDS.iter().copied().collect();
        let extensions: BTreeSet<&str> = EXTENSION_COMMANDS.iter().copied().collect();
        let typed: BTreeSet<&str> = COMMANDS.iter().copied().collect();

        assert_eq!(core.len(), CORE_COMPAT_COMMANDS.len());
        assert_eq!(extensions.len(), EXTENSION_COMMANDS.len());
        assert!(
            core.is_disjoint(&extensions),
            "a command is either Core-compatible or an extension"
        );
        assert_eq!(
            core.union(&extensions).copied().collect::<BTreeSet<_>>(),
            typed,
            "COMMANDS is exactly the Core-compatibility inventory plus the declared extensions"
        );
        assert_eq!(COMMANDS.len(), core.len() + extensions.len());
        for name in CORE_UNTYPED_COMMANDS {
            assert!(
                !typed.contains(name),
                "{name} is a Core command this node leaves untyped, not an extension"
            );
        }
    }

    #[test]
    fn listed_commands_type_and_core_untyped_commands_stay_unknown() -> Result<(), TestError> {
        let magic = Magic::REGTEST;
        for spec in COMMANDS {
            let frame = raw_frame(magic, &command_field(spec)?, &[]);
            let outcome = read_message(&mut Cursor::new(frame), magic);
            if let Ok((Message::Unknown { command, .. }, _)) = &outcome {
                return Err(
                    format!("{spec} is in COMMANDS but decoded as Unknown ({command})").into(),
                );
            }
            if EXTENSION_COMMANDS.contains(spec) {
                assert!(
                    is_own_typed_empty_payload_outcome(spec, &outcome),
                    "{spec}: an empty payload must give the extension's own typed outcome, got {outcome:?}"
                );
                continue;
            }
            match outcome {
                Ok(_)
                | Err(
                    PeerError::Encode(_)
                    | PeerError::Protocol(_)
                    | PeerError::Misbehavior(_)
                    | PeerError::NativeDecode(_)
                    | PeerError::Varint(_),
                ) => {}
                Err(error) => {
                    return Err(format!("{spec}: unexpected decode error {error}").into());
                }
            }
        }

        for name in CORE_UNTYPED_COMMANDS {
            let frame = raw_frame(magic, &command_field(name)?, &[0u8; 8]);
            let (decoded, _) = read_message(&mut Cursor::new(frame), magic)?;
            let Message::Unknown { command, .. } = decoded else {
                return Err(format!("{name} must decode as Unknown").into());
            };
            assert_eq!(command.to_string(), *name);
        }
        Ok(())
    }

    // P2P-01
    #[test]
    fn v1_envelope_matches_rust_bitcoin_for_core_handshake_and_inventory() -> Result<(), TestError>
    {
        let version = version_message(
            0xdead_beef,
            777,
            PeerRole::FullRelay,
            ServiceFlags::NETWORK | ServiceFlags::WITNESS,
            USER_AGENT,
        );
        let inv = vec![Inventory::Transaction(Txid::from_byte_array([9u8; 32]))];
        let cases = [
            (Message::Ping(42), NetworkMessage::Ping(42)),
            (Message::Pong(42), NetworkMessage::Pong(42)),
            (Message::Verack, NetworkMessage::Verack),
            (
                Message::Version(version.clone()),
                NetworkMessage::Version(version),
            ),
            (Message::WtxidRelay, NetworkMessage::WtxidRelay),
            (Message::SendAddrV2, NetworkMessage::SendAddrV2),
            (Message::SendHeaders, NetworkMessage::SendHeaders),
            (Message::Inv(inv.clone()), NetworkMessage::Inv(inv.clone())),
            (Message::GetData(inv.clone()), NetworkMessage::GetData(inv)),
            (Message::MemPool, NetworkMessage::MemPool),
            (Message::GetAddr, NetworkMessage::GetAddr),
            (Message::FeeFilter(1_000), NetworkMessage::FeeFilter(1_000)),
        ];
        for (ours, theirs) in cases {
            assert_eq!(
                our_frame(&ours)?,
                rust_bitcoin_frame(theirs),
                "v1 frame for {}",
                ours.command()
            );
        }
        Ok(())
    }

    // P2P-01
    #[test]
    fn v1_envelope_matches_rust_bitcoin_for_borrowed_payloads() -> Result<(), TestError> {
        use bitcoin::bip152::{
            BlockTransactions, HeaderAndShortIds, PrefilledTransaction, ShortId,
        };
        use bitcoin::bip158::{FilterHash, FilterHeader};
        use bitcoin::p2p::address::{AddrV2, AddrV2Message, Address};
        use bitcoin::p2p::message_bloom::{BloomFlags, FilterAdd, FilterLoad};
        use bitcoin::p2p::message_compact_blocks::{BlockTxn, CmpctBlock, GetBlockTxn, SendCmpct};
        use bitcoin::p2p::message_filter::{
            CFCheckpt, CFHeaders, CFilter, GetCFCheckpt, GetCFHeaders, GetCFilters,
        };
        use bitcoin::p2p::message_network::Reject;

        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let hash = block.block_hash();
        let mut transaction = block.txdata[0].clone();
        transaction.input[0].witness = bitcoin::Witness::from_slice(&[b"witness"]);
        let mut reject_payload = vec![2, b't', b'x', 0x10, 3, b'b', b'a', b'd'];
        reject_payload.extend_from_slice(&[7; 32]);
        let reject: Reject =
            bitcoin_encode::deserialize(&reject_payload).map_err(PeerError::from)?;
        let cases = [
            NetworkMessage::Addr(vec![(
                123,
                Address::new(
                    &std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, 18444)),
                    ServiceFlags::NETWORK,
                ),
            )]),
            NetworkMessage::NotFound(vec![Inventory::WitnessBlock(hash)]),
            NetworkMessage::GetBlocks(GetBlocksMessage::new(vec![hash], BlockHash::all_zeros())),
            NetworkMessage::GetHeaders(GetHeadersMessage::new(vec![hash], BlockHash::all_zeros())),
            NetworkMessage::MerkleBlock(
                bitcoin::merkle_tree::MerkleBlock::from_block_with_predicate(&block, |_| true),
            ),
            NetworkMessage::FilterLoad(FilterLoad {
                filter: vec![0x2a; 253],
                hash_funcs: 3,
                tweak: 7,
                flags: BloomFlags::All,
            }),
            NetworkMessage::FilterAdd(FilterAdd {
                data: vec![1, 2, 3],
            }),
            NetworkMessage::FilterClear,
            NetworkMessage::GetCFilters(GetCFilters {
                filter_type: 0,
                start_height: 3,
                stop_hash: hash,
            }),
            NetworkMessage::CFilter(CFilter {
                filter_type: 0,
                block_hash: hash,
                filter: vec![0x3c; 253],
            }),
            NetworkMessage::GetCFHeaders(GetCFHeaders {
                filter_type: 0,
                start_height: 3,
                stop_hash: hash,
            }),
            NetworkMessage::CFHeaders(CFHeaders {
                filter_type: 0,
                stop_hash: hash,
                previous_filter_header: FilterHeader::from_byte_array([4; 32]),
                filter_hashes: vec![FilterHash::from_byte_array([5; 32]); 2],
            }),
            NetworkMessage::GetCFCheckpt(GetCFCheckpt {
                filter_type: 0,
                stop_hash: hash,
            }),
            NetworkMessage::CFCheckpt(CFCheckpt {
                filter_type: 0,
                stop_hash: hash,
                filter_headers: vec![FilterHeader::from_byte_array([6; 32]); 2],
            }),
            NetworkMessage::SendCmpct(SendCmpct {
                send_compact: true,
                version: 2,
            }),
            NetworkMessage::CmpctBlock(CmpctBlock {
                compact_block: HeaderAndShortIds {
                    header: block.header,
                    nonce: 9,
                    short_ids: vec![ShortId::from([1; 6])],
                    prefilled_txs: vec![PrefilledTransaction {
                        idx: 0,
                        tx: transaction.clone(),
                    }],
                },
            }),
            NetworkMessage::GetBlockTxn(GetBlockTxn {
                txs_request: BlockTransactionsRequest {
                    block_hash: hash,
                    indexes: vec![1, 3, 9],
                },
            }),
            NetworkMessage::BlockTxn(BlockTxn {
                transactions: BlockTransactions {
                    block_hash: hash,
                    transactions: vec![transaction],
                },
            }),
            NetworkMessage::Alert(vec![0x5a; 253]),
            NetworkMessage::Reject(reject),
            NetworkMessage::AddrV2(vec![AddrV2Message {
                time: 123,
                services: ServiceFlags::NETWORK,
                addr: AddrV2::Ipv4(Ipv4Addr::LOCALHOST),
                port: 18444,
            }]),
            NetworkMessage::Unknown {
                command: "custom".parse()?,
                payload: vec![0x5a; 253],
            },
        ];

        for reference in cases {
            let command = reference.command();
            let expected = rust_bitcoin_frame(reference);
            let (message, _) = read_message(&mut Cursor::new(&expected), Magic::REGTEST)?;
            assert_eq!(message.command(), command);
            assert_eq!(our_frame(&message)?, expected, "v1 frame for {command}");
            assert_eq!(bitcoin_rs_p2p::wire::wire_len(&message)?, expected.len());
        }
        Ok(())
    }

    // P2P-01
    #[test]
    fn version_message_pins_core_31_handshake_fields() {
        let version = version_message(
            0xdead_beef,
            777,
            PeerRole::FullRelay,
            ServiceFlags::NETWORK | ServiceFlags::WITNESS,
            USER_AGENT,
        );

        assert_eq!(version.version, PROTOCOL_VERSION);
        assert_eq!(
            PROTOCOL_VERSION, FEATURE_VERSION,
            "documented deviation: we advertise the BIP434 feature-negotiation threshold"
        );
        assert_eq!(
            PROTOCOL_VERSION,
            CORE_31_1_PROTOCOL_VERSION + 1,
            "the one protocol version above Core 31.1's, and only that"
        );
        let expected_services = {
            let mut services = ServiceFlags::NETWORK;
            services.add(ServiceFlags::WITNESS);
            services
        };
        assert_eq!(
            version.services, expected_services,
            "we advertise NODE_NETWORK | NODE_WITNESS, like a Core default full node's core bits"
        );
        assert!(version.relay, "full-relay flag, like a Core default node");
        assert_eq!(version.user_agent, USER_AGENT);
        assert!(version.user_agent.starts_with("/bitcoin-rs:"));
        assert_eq!(version.nonce, 0xdead_beef);
        assert_eq!(version.start_height, 777);
        assert_eq!(version.receiver.services, expected_services);
        assert_eq!(version.sender.services, expected_services);
    }

    #[test]
    fn outbound_handshake_sends_version_then_core_feature_set() {
        let mut peer = Peer::new(Cursor::new(Vec::<u8>::new()), Magic::REGTEST);
        let messages = start(
            &mut peer,
            1,
            0,
            PeerRole::FullRelay,
            ServiceFlags::NETWORK | ServiceFlags::WITNESS,
            USER_AGENT,
        );

        assert_eq!(peer.state, PeerState::VersionExchange);
        assert_eq!(messages.len(), 4);
        assert!(matches!(messages.first(), Some(Message::Version(_))));
        assert_eq!(
            &messages[1..],
            &[
                Message::WtxidRelay,
                Message::SendAddrV2,
                Message::SendHeaders
            ],
            "BIP339 wtxidrelay, BIP155 sendaddrv2, BIP130 sendheaders — Core 31 order"
        );
    }

    #[test]
    fn remote_feature_messages_flip_negotiated_capabilities() -> Result<(), TestError> {
        let mut peer = Peer::new(Cursor::new(Vec::<u8>::new()), Magic::REGTEST);
        dispatch_inbound(&mut peer, &version_for_handshake())?;
        assert!(!peer.capabilities.send_headers);
        assert!(!peer.capabilities.addr_v2);

        dispatch_inbound(&mut peer, &Message::SendHeaders)?;
        dispatch_inbound(&mut peer, &Message::SendAddrV2)?;
        dispatch_inbound(&mut peer, &Message::WtxidRelay)?;

        assert!(peer.capabilities.send_headers);
        assert!(peer.capabilities.addr_v2);
        assert!(peer.wtxid_relay.peer_supported());
        dispatch_inbound(&mut peer, &Message::Verack)?;
        assert_eq!(peer.state, PeerState::Ready);
        Ok(())
    }

    #[test]
    fn late_wtxidrelay_is_ignored_after_verack() -> Result<(), TestError> {
        let mut peer = ready_peer(Magic::REGTEST)?;
        assert!(!peer.wtxid_relay.peer_supported());
        dispatch_inbound(&mut peer, &Message::WtxidRelay)?;
        assert!(!peer.wtxid_relay.peer_supported());
        assert_eq!(peer.state, PeerState::Ready);
        Ok(())
    }

    #[test]
    fn network_magic_and_default_ports_match_core() -> Result<(), TestError> {
        for (network, magic, port) in NETWORK_TABLE {
            assert_eq!(
                Magic::from_bytes(network.magic()),
                magic,
                "{network:?} magic"
            );
            assert_eq!(network.default_p2p_port(), port, "{network:?} default port");

            let mut cursor = Cursor::new(Vec::new());
            write_message(&mut cursor, magic, &Message::Ping(1))?;
            let bytes = cursor.into_inner();
            assert_eq!(
                &bytes[..4],
                &network.magic(),
                "{network:?} frame starts with its magic"
            );
        }
        Ok(())
    }

    #[test]
    fn foreign_network_frames_are_rejected_before_payload_decode() -> Result<(), TestError> {
        for (_, magic, _) in NETWORK_TABLE {
            let reader_magic = if magic == Magic::REGTEST {
                Magic::BITCOIN
            } else {
                Magic::REGTEST
            };
            let mut cursor = Cursor::new(Vec::new());
            write_message(&mut cursor, magic, &Message::Ping(1))?;
            cursor.set_position(0);

            let error = expect_protocol_error(
                read_message(&mut cursor, reader_magic),
                "cross-network frame",
            )?;
            let PeerError::WrongNetwork { expected, actual } = error else {
                return Err("expected WrongNetwork".into());
            };
            assert_eq!(expected, reader_magic);
            assert_eq!(actual, magic);
        }
        Ok(())
    }

    #[test]
    fn getheaders_serves_active_chain_with_stop_hash_and_limit() -> Result<(), TestError> {
        let genesis = genesis_block()?;
        let headers = child_headers(&genesis.header, 4);
        let chain = FakeChain::new(headers.clone(), HashMap::new());
        let mut peer = ready_peer(Magic::REGTEST)?;

        let response = dispatch_collect(
            &mut peer,
            &get_headers(vec![headers[0].compute_hash()], NativeBlockHash::default()),
            Some(&chain),
        )?;
        let [Message::Headers(served)] = response.as_slice() else {
            return Err("expected one headers response".into());
        };
        assert_eq!(served.len(), 3);
        assert_eq!(served[0].compute_hash(), headers[1].compute_hash());
        assert_eq!(served[2].compute_hash(), headers[3].compute_hash());

        let response = dispatch_collect(
            &mut peer,
            &get_headers(locator_hashes(&headers), headers[2].compute_hash()),
            Some(&chain),
        )?;
        let Some(Message::Headers(served)) = response.first() else {
            return Err("expected headers response".into());
        };
        assert_eq!(
            served.len(),
            2,
            "locator hit at height 1; serves heights 2..=3"
        );
        assert_eq!(
            served.last().map(Header::compute_hash),
            Some(headers[2].compute_hash())
        );

        let response = dispatch_collect(
            &mut peer,
            &get_headers(Vec::new(), headers[3].compute_hash()),
            Some(&chain),
        )?;
        let Some(Message::Headers(served)) = response.first() else {
            return Err("expected headers response".into());
        };
        assert_eq!(served.len(), 1);
        assert_eq!(served[0].compute_hash(), headers[3].compute_hash());

        let response = dispatch_collect(
            &mut peer,
            &get_headers(Vec::new(), NativeBlockHash::default()),
            Some(&chain),
        )?;
        let Some(Message::Headers(served)) = response.first() else {
            return Err("expected headers response".into());
        };
        assert_eq!(served.as_slice(), []);
        Ok(())
    }

    #[test]
    fn headers_responses_truncate_at_the_core_2000_limit() -> Result<(), TestError> {
        let genesis = genesis_block()?;
        let headers = child_headers(&genesis.header, MAX_HEADERS_MESSAGE_COUNT + 1);
        let chain = FakeChain::new(headers.clone(), HashMap::new());
        let mut peer = ready_peer(Magic::REGTEST)?;

        let response = dispatch_collect(
            &mut peer,
            &get_headers(locator_hashes(&headers[..101]), NativeBlockHash::default()),
            Some(&chain),
        )?;
        let Some(Message::Headers(served)) = response.first() else {
            return Err("expected headers response".into());
        };
        assert_eq!(served.len(), MAX_HEADERS_MESSAGE_COUNT);
        assert_eq!(served.len(), 2_000, "Core 31.1 max headers per message");
        Ok(())
    }

    #[test]
    fn inv_getdata_relay_round_trip_serves_blocks_and_notfounds_misses() -> Result<(), TestError> {
        let genesis = genesis_block()?;
        let mut active = vec![genesis.header];
        active.extend(child_headers(&genesis.header, 1));
        let mut bodies = HashMap::new();
        bodies.insert(genesis.block_hash(), genesis.clone());
        let chain = FakeChain::new(active, bodies);
        let mut peer = ready_peer(Magic::REGTEST)?;
        let txid = Txid::from_byte_array([9u8; 32]);
        let tx_inv = Inventory::Transaction(txid);
        let response = dispatch_collect(&mut peer, &Message::Inv(vec![tx_inv]), Some(&chain))?;
        assert_eq!(
            response,
            vec![Message::GetData(vec![Inventory::WitnessTransaction(txid)])],
        );

        let genesis_hash = genesis.block_hash();
        let known = Inventory::Block(btc_bh(genesis_hash));
        let mut missing_hash = *genesis_hash.as_bytes();
        missing_hash[0] ^= 0xff;
        let missing = Inventory::Block(BlockHash::from_byte_array(missing_hash));
        let response = dispatch_collect(
            &mut peer,
            &Message::GetData(vec![known, missing]),
            Some(&chain),
        )?;
        let (served, not_found) = match response.as_slice() {
            [Message::BlockBytes(payload), Message::NotFound(items)] => {
                (deserialize::<Block>(payload)?, items)
            }
            other => return Err(format!("unexpected relay response {other:?}").into()),
        };
        assert_eq!(served.block_hash(), genesis.block_hash());
        assert_eq!(not_found, &vec![missing]);

        let mut wire = Cursor::new(Vec::new());
        write_message(
            &mut wire,
            Magic::REGTEST,
            response.first().ok_or("empty relay response")?,
        )?;
        wire.set_position(0);
        let (decoded, raw) = read_message(&mut wire, Magic::REGTEST)?;
        let Message::Block(payload) = decoded else {
            return Err("expected block on the wire".into());
        };
        assert_eq!(payload.block_hash(), genesis.block_hash());
        assert_eq!(
            payload.bytes().as_ref(),
            consensus_bytes(&genesis).as_slice()
        );
        assert_eq!(raw.as_ref(), payload.bytes().as_ref());
        Ok(())
    }

    #[test]
    fn getdata_bound_of_50k_vectors_matches_core_max_inv() -> Result<(), TestError> {
        assert_eq!(MAX_INV_PER_MSG, 50_000, "Core MAX_INV_SZ");

        let genesis = genesis_block()?;
        let headers = child_headers(&genesis.header, 1);
        let chain = FakeChain::new(headers, HashMap::new());
        let mut peer = ready_peer(Magic::REGTEST)?;
        let items =
            vec![Inventory::Transaction(Txid::from_byte_array([1u8; 32])); MAX_INV_PER_MSG + 1];

        let error = expect_protocol_error(
            dispatch_collect(&mut peer, &Message::GetData(items), Some(&chain)),
            "Core disconnects oversized getdata",
        )?;
        assert!(matches!(
            error,
            PeerError::Misbehavior("getdata inventory too large")
        ));
        Ok(())
    }

    #[test]
    fn inbound_block_and_tx_messages_decode_and_leave_no_response() -> Result<(), TestError> {
        let genesis = genesis_block()?;
        let mut peer = ready_peer(Magic::REGTEST)?;

        let responses = dispatch_inbound(
            &mut peer,
            &Message::Block(BlockImage::from_local(genesis.clone())),
        )?;
        assert_eq!(responses, []);

        let coinbase = genesis
            .txs
            .first()
            .ok_or("genesis carries a coinbase transaction")?
            .clone();
        let responses = dispatch_inbound(&mut peer, &Message::Tx(coinbase))?;
        assert!(
            responses.is_empty(),
            "inbound tx relay is decode-accepted, not processed yet"
        );
        assert_eq!(peer.state, PeerState::Ready);
        Ok(())
    }

    #[test]
    fn block_relay_only_dial_is_prohibited_from_transaction_relay() -> Result<(), TestError> {
        let magic = Magic::BITCOIN;
        let listener = TcpListener::bind(
            PeerEndpoint::from((Ipv4Addr::LOCALHOST, 0))
                .socket_addr()
                .unwrap_or_else(|| panic!("expected IP fixture")),
        )?;
        let addr = listener.local_addr()?;
        let (headers_tx, headers_rx) = crossbeam_channel::unbounded::<InboundHeaders>();
        let (blocks_tx, _blocks_rx) = crossbeam_channel::unbounded::<InboundBlock>();
        let shared = ConnectionShared::new(
            Arc::new(PeerTable::new()),
            Arc::new(parking_lot::RwLock::new(Vec::<BannedSubnet>::new())),
            Arc::new(NetworkActivity::from_shared(Arc::new(AtomicBool::new(
                true,
            )))),
            bitcoin_rs_consensus::latch::LatchReader::fixture_never(),
            None,
            magic,
            headers_tx,
            blocks_tx,
            None,
            None,
            ListenerExtras::default(),
        );
        let dial = spawn_outbound_connection(addr.into(), shared, PeerRole::BlockRelayOnly);

        let (mut server, _) = listener.accept()?;
        server.set_read_timeout(Some(Duration::from_secs(5)))?;
        server.set_write_timeout(Some(Duration::from_secs(5)))?;

        let Ok((Message::Version(version), _)) = read_message(&mut server, magic) else {
            return Err("the dial opens with a version message".into());
        };
        assert!(
            !version.relay,
            "a block-relay-only dial advertises no transaction relay"
        );

        write_message(&mut server, magic, &version_for_handshake())?;
        write_message(&mut server, magic, &Message::Verack)?;
        let mut completed = false;
        let deadline = Instant::now() + Duration::from_secs(5);
        while !completed && Instant::now() < deadline {
            let message = match read_message(&mut server, magic) {
                Ok((message, _)) => message,
                Err(PeerError::Io(error))
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            completed = matches!(message, Message::Verack);
        }
        assert!(completed, "the block-relay handshake completes");

        let genesis = genesis_block()?;
        write_message(&mut server, magic, &Message::Addr(Vec::new()))?;
        write_message(
            &mut server,
            magic,
            &Message::Block(BlockImage::from_local(genesis.clone())),
        )?;
        let Ok(announced) = headers_rx.recv_timeout(Duration::from_secs(5)) else {
            return Err("a block must reach the scheduler on a block-relay connection".into());
        };
        assert!(
            !announced.headers.is_empty(),
            "the block header is forwarded"
        );

        let Some(coinbase) = genesis.txs.first() else {
            return Err("genesis carries a coinbase transaction".into());
        };
        write_message(&mut server, magic, &Message::Tx(coinbase.clone()))?;
        let enforcement_deadline = Instant::now() + Duration::from_secs(5);
        while !dial.is_finished() && Instant::now() < enforcement_deadline {
            thread::sleep(Duration::from_millis(10));
        }
        if !dial.is_finished() {
            let _ = server.shutdown(std::net::Shutdown::Both);
            drop(server);
        }
        let Ok(outcome) = dial.join() else {
            return Err("the dial thread panicked".into());
        };
        let Err(error) = outcome else {
            return Err("a transaction on a block-relay connection must end it".into());
        };
        assert!(
            matches!(&error, PeerError::Protocol(reason)
            if *reason == "transaction sent in violation of protocol"),
            "unexpected connection end: {error:?}"
        );
        Ok(())
    }

    #[test]
    fn malformed_frames_reject_with_typed_errors() -> Result<(), TestError> {
        let magic = Magic::REGTEST;

        let mut frame = raw_frame(magic, b"ping\0\0\0\0\0\0\0\0", &7u64.to_le_bytes());
        let last = frame.len() - 1;
        frame[last] ^= 0xff;
        assert!(matches!(
            read_message(&mut Cursor::new(frame), magic),
            Err(PeerError::BadChecksum)
        ));

        assert_eq!(
            MAX_MESSAGE_PAYLOAD, 4_000_000,
            "Core MAX_PROTOCOL_MESSAGE_LENGTH"
        );
        let mut oversized = Vec::new();
        oversized.extend_from_slice(&magic.to_bytes());
        oversized.extend_from_slice(b"ping\0\0\0\0\0\0\0\0");
        oversized.extend_from_slice(&u32::try_from(MAX_MESSAGE_PAYLOAD + 1)?.to_le_bytes());
        oversized.extend_from_slice(&[0u8; 4]);
        assert!(matches!(
            read_message(&mut Cursor::new(oversized), magic),
            Err(PeerError::PayloadTooLarge(_))
        ));

        let mut command = [0u8; 12];
        command[..4].copy_from_slice(b"inv\0");
        command[4..].copy_from_slice(b"garbage!");
        let frame = raw_frame(magic, &command, &[]);
        assert!(matches!(
            read_message(&mut Cursor::new(frame), magic),
            Err(PeerError::InvalidCommand(_))
        ));

        let frame = raw_frame(magic, b"ping\0\0\0\0\0\0\0\0", &[1u8, 2, 3, 4]);
        assert!(matches!(
            read_message(&mut Cursor::new(frame), magic),
            Err(PeerError::Encode(_))
        ));
        Ok(())
    }

    #[test]
    fn messages_before_handshake_disconnect_like_core() -> Result<(), TestError> {
        let mut fresh = Peer::new(Cursor::new(Vec::<u8>::new()), Magic::REGTEST);
        let error = expect_protocol_error(
            dispatch_inbound(&mut fresh, &Message::Ping(7)),
            "Core drops non-handshake traffic pre-verack",
        )?;
        assert!(matches!(
            error,
            PeerError::Misbehavior("message received before handshake completed")
        ));

        let mut fresh = Peer::new(Cursor::new(Vec::<u8>::new()), Magic::REGTEST);
        let error = expect_protocol_error(
            dispatch_inbound(&mut fresh, &Message::Verack),
            "verack must follow version",
        )?;
        assert!(matches!(
            error,
            PeerError::Misbehavior("verack received before version")
        ));

        let mut ready = ready_peer(Magic::REGTEST)?;
        let error = expect_protocol_error(
            dispatch_inbound(&mut ready, &version_for_handshake()),
            "duplicate version after ready",
        )?;
        assert!(matches!(
            error,
            PeerError::Misbehavior("duplicate version message")
        ));
        Ok(())
    }

    #[test]
    fn unknown_commands_are_ignored_once_ready_like_core() -> Result<(), TestError> {
        let mut peer = ready_peer(Magic::REGTEST)?;

        let command = "sendtxrcncl".parse::<CommandString>()?;
        let responses = dispatch_inbound(
            &mut peer,
            &Message::Unknown {
                command,
                payload: vec![0u8; 8],
            },
        )?;
        assert_eq!(responses, []);
        assert_eq!(
            peer.state,
            PeerState::Ready,
            "unknown commands never disconnect a ready peer"
        );
        Ok(())
    }

    #[test]
    fn decode_only_messages_are_accepted_silently_per_policy() -> Result<(), TestError> {
        let genesis = genesis_block()?;
        let headers = child_headers(&genesis.header, 1);
        let chain = FakeChain::new(headers, HashMap::new());
        let mut peer = ready_peer(Magic::REGTEST)?;

        let responses = dispatch_collect(
            &mut peer,
            &Message::GetBlocks(GetBlocksMessage::new(
                vec![btc_bh(genesis.block_hash())],
                BlockHash::all_zeros(),
            )),
            Some(&chain),
        )?;
        assert_eq!(responses, []);

        let responses = dispatch_inbound(&mut peer, &Message::MemPool)?;
        assert_eq!(responses, []);

        let responses = dispatch_inbound(&mut peer, &Message::GetAddr)?;
        assert_eq!(responses, []);

        let responses = dispatch_inbound(&mut peer, &Message::FeeFilter(1_000))?;
        assert_eq!(responses, []);

        assert_eq!(peer.state, PeerState::Ready);
        Ok(())
    }

    type ForkBranches = (Vec<Header>, Vec<Header>, Vec<Header>);

    fn fork_fixture() -> Result<ForkBranches, TestError> {
        let genesis = genesis_block()?;
        let shared = child_headers(&genesis.header, 2);
        let fork_point = shared.last().ok_or("shared prefix must not be empty")?;
        let branch_a = child_headers(fork_point, 2);
        let branch_b = child_headers(fork_point, 2)
            .into_iter()
            .enumerate()
            .map(|(index, mut header)| {
                header.time += u32::try_from(index).unwrap_or(0) + 7;
                header
            })
            .collect::<Vec<_>>();
        Ok((shared, branch_a, branch_b))
    }

    #[test]
    fn reorg_switches_which_chain_a_peer_sees() -> Result<(), TestError> {
        let (shared, branch_a, branch_b) = fork_fixture()?;
        let mut active = shared.clone();
        active.extend(branch_a.iter().copied());

        let mut bodies = headers_into_blocks(&shared);
        bodies.extend(headers_into_blocks(&branch_a));
        bodies.extend(headers_into_blocks(&branch_b));

        let mut state = FakeChain::new(active.clone(), bodies);
        let mut peer = ready_peer(Magic::REGTEST)?;

        let stale_tip = branch_a.last().ok_or("branch A tip")?.compute_hash();
        let fork_point = shared.last().ok_or("shared prefix")?.compute_hash();
        let locator = vec![stale_tip, fork_point];
        let response = dispatch_collect(
            &mut peer,
            &get_headers(locator.clone(), NativeBlockHash::default()),
            Some(&state),
        )?;
        let Some(Message::Headers(served)) = response.first() else {
            return Err("expected headers response".into());
        };
        assert!(
            served.is_empty(),
            "locator at the active tip has nothing newer to serve"
        );

        let mut active_b = shared;
        active_b.extend(branch_b.iter().copied());
        state = FakeChain::new(active_b, state.bodies);

        let response = dispatch_collect(
            &mut peer,
            &get_headers(locator, NativeBlockHash::default()),
            Some(&state),
        )?;
        let Some(Message::Headers(served)) = response.first() else {
            return Err("expected headers response".into());
        };
        assert_eq!(served.len(), 2);
        assert_eq!(served[0].compute_hash(), branch_b[0].compute_hash());
        assert_eq!(served[1].compute_hash(), branch_b[1].compute_hash());

        let response = dispatch_collect(
            &mut peer,
            &Message::GetData(vec![
                Inventory::Block(btc_bh(branch_a[0].compute_hash())),
                Inventory::Block(btc_bh(branch_b[0].compute_hash())),
            ]),
            Some(&state),
        )?;
        let [Message::BlockBytes(stale), Message::BlockBytes(winner)] = response.as_slice() else {
            return Err(format!("unexpected post-reorg relay response {response:?}").into());
        };
        assert_eq!(
            deserialize::<Block>(stale)?.block_hash(),
            branch_a[0].compute_hash()
        );
        assert_eq!(
            deserialize::<Block>(winner)?.block_hash(),
            branch_b[0].compute_hash()
        );
        Ok(())
    }

    #[test]
    fn handshake_completes_over_tcp_for_every_network() -> Result<(), TestError> {
        for (network, magic, _) in NETWORK_TABLE {
            serve_and_handshake_over_tcp(network, magic)?;
        }
        Ok(())
    }

    fn serve_and_handshake_over_tcp(network: Network, magic: Magic) -> Result<(), TestError> {
        let listener = bind_listener(
            PeerEndpoint::from((Ipv4Addr::LOCALHOST, 0))
                .socket_addr()
                .unwrap_or_else(|| panic!("expected IP fixture")),
        )?;
        let addr = listener.local_addr()?;

        let shutdown = bitcoin_rs_consensus::latch::LatchWriter::new();
        let listener_shutdown = shutdown.reader();
        let (headers_tx, _headers_rx) = crossbeam_channel::unbounded::<InboundHeaders>();
        let (blocks_tx, _blocks_rx) = crossbeam_channel::unbounded::<InboundBlock>();
        let peer_table = Arc::new(PeerTable::new());
        let shared = ConnectionShared::new(
            Arc::clone(&peer_table),
            Arc::new(parking_lot::RwLock::new(Vec::<BannedSubnet>::new())),
            Arc::new(NetworkActivity::from_shared(Arc::new(AtomicBool::new(
                true,
            )))),
            bitcoin_rs_consensus::latch::LatchWriter::new().reader(),
            None,
            magic,
            headers_tx,
            blocks_tx,
            None,
            None,
            ListenerExtras::default(),
        );

        let handle = thread::spawn(move || serve(listener, listener_shutdown, shared));

        let client = match connect_with_retry(addr.into()) {
            Ok(client) => client,
            Err(error) => {
                shutdown.trigger();
                let _ = handle.join();
                return Err(error);
            }
        };
        let outcome = drive_handshake_as_core(client, magic, network);
        // Propagate the handshake result and the accounting check together, but
        // only after the unconditional listener shutdown and join below: an early
        // `?` here would leak the listener thread, and dropping the handshake
        // error would let a failed handshake pass the test.
        let result = outcome.and_then(|client| {
            // Hold the socket open while sampling: the peer row (and its
            // per-message counters) disappears as soon as the node sees EOF.
            let checked = assert_ping_pong_accounted(&peer_table);
            drop(client);
            checked
        });
        shutdown.trigger();
        let listener_result = handle.join().map_err(|_| "listener thread panicked")?;
        listener_result?;
        result
    }

    /// The live connection's per-message byte accounting must carry both ping
    /// directions at or above the 29-byte threshold Core v31.1's functional
    /// `connect_nodes` waits on in `bytesrecv_per_msg['pong']`
    /// (`test_framework.py`): the ping the peer sent with the pong this node
    /// answered, and the ping this node originated after the handshake with the
    /// pong the peer sent back.
    fn assert_ping_pong_accounted(peer_table: &PeerTable) -> Result<(), TestError> {
        // The writer thread charges a frame's bucket after the socket accepted
        // it, so poll briefly like the framework's wait_until instead of reading
        // once and racing the writer.
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let infos = peer_table.infos();
            let Some(info) = infos.first() else {
                return Err("handshake-complete peer never published its counters".into());
            };
            let per_message = |command: &str, table: Vec<(&'static str, u64)>| {
                table
                    .into_iter()
                    .find(|(known, _)| *known == command)
                    .map_or(0, |(_, bytes)| bytes)
            };
            let recv = |command: &str| per_message(command, info.counters.recv_per_message());
            let sent = |command: &str| per_message(command, info.counters.sent_per_message());
            match (recv("ping"), sent("pong"), sent("ping"), recv("pong")) {
                (recv_ping, sent_pong, sent_ping, recv_pong)
                    if recv_ping >= 29 && sent_pong >= 29 && sent_ping >= 29 && recv_pong >= 29 =>
                {
                    return Ok(());
                }
                state if Instant::now() < deadline => {
                    let _ = state;
                    thread::sleep(Duration::from_millis(10));
                }
                state => {
                    return Err(format!(
                        "per-message ping/pong accounting missing or below the wire threshold \
                     (recv ping, sent pong, sent ping, recv pong): {state:?}"
                    )
                    .into());
                }
            }
        }
    }

    fn connect_with_retry(addr: PeerEndpoint) -> Result<TcpStream, TestError> {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match TcpStream::connect_timeout(
                &addr
                    .socket_addr()
                    .unwrap_or_else(|| panic!("expected IP fixture")),
                Duration::from_millis(200),
            ) {
                Ok(stream) => return Ok(stream),
                Err(error) if Instant::now() < deadline => {
                    let _ = error;
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn drive_handshake_as_core(
        mut client: TcpStream,
        magic: Magic,
        network: Network,
    ) -> Result<TcpStream, TestError> {
        client.set_read_timeout(Some(Duration::from_millis(50)))?;

        write_message(&mut client, magic, &version_for_handshake())?;
        let mut saw_features = [false; 3];
        let mut saw_verack = false;
        let deadline = Instant::now() + Duration::from_secs(3);
        while !(saw_verack && saw_features.iter().all(|seen| *seen)) {
            if Instant::now() > deadline {
                return Err(format!("handshake from {network:?} never completed").into());
            }
            let (message, _) = match read_message(&mut client, magic) {
                Ok(pair) => pair,
                Err(PeerError::Io(error))
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            match message {
                Message::Version(version) => {
                    assert_eq!(version.version, PROTOCOL_VERSION);
                    assert_eq!(
                        version.services,
                        version_message(
                            0,
                            0,
                            PeerRole::FullRelay,
                            ServiceFlags::NETWORK | ServiceFlags::WITNESS,
                            USER_AGENT
                        )
                        .services
                    );
                }
                Message::WtxidRelay => saw_features[0] = true,
                Message::SendAddrV2 => saw_features[1] = true,
                Message::SendHeaders => saw_features[2] = true,
                Message::Verack => saw_verack = true,
                other => return Err(format!("unexpected handshake message {other:?}").into()),
            }
        }

        write_message(&mut client, magic, &Message::Verack)?;

        // Core v31.1 originates a ping on the first send pass after VERACK
        // (`MaybeSendPing`; a peer's `m_ping_start` initializes to the clock
        // epoch), so a Core-like peer receives one without asking. This side
        // both solicits a pong with its own ping and answers the node's
        // originated ping, so `assert_ping_pong_accounted` can check both
        // directions' wire accounting afterwards.
        write_message(&mut client, magic, &Message::Ping(0xfeed_face))?;
        let mut originated_ping = false;
        let mut ponged_our_ping = false;
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if Instant::now() > deadline {
                return Err(format!(
                "pong for ping never arrived on {network:?} (originated ping seen: {originated_ping})"
            )
            .into());
            }
            let (message, _) = match read_message(&mut client, magic) {
                Ok(pair) => pair,
                Err(PeerError::Io(error))
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            match message {
                Message::Pong(nonce) => {
                    assert_eq!(
                        nonce, 0xfeed_face,
                        "pong must echo the solicited ping nonce"
                    );
                    ponged_our_ping = true;
                }
                Message::Ping(nonce) => {
                    originated_ping = true;
                    write_message(&mut client, magic, &Message::Pong(nonce))?;
                }
                Message::SendCmpct(_) => {}
                other => return Err(format!("unexpected post-handshake message {other:?}").into()),
            }
            if originated_ping && ponged_our_ping {
                break;
            }
        }
        Ok(client)
    }

    fn outbound_shared(peer_table: Arc<PeerTable>, magic: Magic) -> ConnectionShared {
        let (headers_tx, _headers_rx) = crossbeam_channel::unbounded::<InboundHeaders>();
        let (blocks_tx, _blocks_rx) = crossbeam_channel::unbounded::<InboundBlock>();
        ConnectionShared::new(
            peer_table,
            Arc::new(parking_lot::RwLock::new(Vec::<BannedSubnet>::new())),
            Arc::new(NetworkActivity::from_shared(Arc::new(AtomicBool::new(
                true,
            )))),
            bitcoin_rs_consensus::latch::LatchReader::fixture_never(),
            None,
            magic,
            headers_tx,
            blocks_tx,
            None,
            None,
            ListenerExtras::default(),
        )
    }

    fn remote_version(services: ServiceFlags) -> Message {
        let mut version = version_message(
            1,
            0,
            PeerRole::FullRelay,
            ServiceFlags::NETWORK | ServiceFlags::WITNESS,
            USER_AGENT,
        );
        version.services = services;
        Message::Version(version)
    }

    // P2P-08
    #[test]
    fn desirable_service_policy_matches_core() {
        let network_witness = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
        let limited_witness = ServiceFlags::NETWORK_LIMITED | ServiceFlags::WITNESS;
        assert!(bitcoin_rs_p2p::listener::has_all_desirable_service_flags(
            network_witness,
            0
        ));
        assert!(bitcoin_rs_p2p::listener::has_all_desirable_service_flags(
            network_witness,
            u64::MAX
        ));
        assert!(bitcoin_rs_p2p::listener::has_all_desirable_service_flags(
            limited_witness,
            143
        ));
        assert!(!bitcoin_rs_p2p::listener::has_all_desirable_service_flags(
            limited_witness,
            144
        ));
        assert!(!bitcoin_rs_p2p::listener::has_all_desirable_service_flags(
            ServiceFlags::NETWORK_LIMITED,
            0
        ));
        assert!(!bitcoin_rs_p2p::listener::has_all_desirable_service_flags(
            ServiceFlags::WITNESS,
            0
        ));
        assert!(!bitcoin_rs_p2p::listener::has_all_desirable_service_flags(
            ServiceFlags::NETWORK,
            0
        ));
        assert!(!bitcoin_rs_p2p::listener::has_all_desirable_service_flags(
            ServiceFlags::NONE,
            0
        ));
    }

    #[test]
    fn outbound_peer_without_network_flag_disconnected() -> Result<(), TestError> {
        let magic = Magic::BITCOIN;
        let peer_table = Arc::new(PeerTable::new());
        let shared = outbound_shared(Arc::clone(&peer_table), magic);
        let listener = TcpListener::bind(
            PeerEndpoint::from((Ipv4Addr::LOCALHOST, 0))
                .socket_addr()
                .unwrap_or_else(|| panic!("expected IP fixture")),
        )?;
        let addr = listener.local_addr()?;
        let dial = spawn_outbound_connection(addr.into(), shared, PeerRole::FullRelay);

        let (mut server, _) = listener.accept()?;
        server.set_read_timeout(Some(Duration::from_secs(5)))?;
        server.set_write_timeout(Some(Duration::from_secs(5)))?;
        let Ok((Message::Version(_), _)) = read_message(&mut server, magic) else {
            return Err("the dial opens with a version message".into());
        };
        write_message(
            &mut server,
            magic,
            &remote_version(ServiceFlags::NETWORK_LIMITED),
        )?;

        let inner = match dial.join() {
            Ok(inner) => inner,
            Err(panic) => std::panic::resume_unwind(panic),
        };
        let Err(error) = inner else {
            return Err("a LIMITED-only peer without NETWORK must be refused".into());
        };
        assert!(
            matches!(&error, PeerError::Protocol(reason)
            if *reason == "outbound peer lacks desirable services"),
            "unexpected handshake error: {error}"
        );
        assert!(
            peer_table.live_sessions().is_empty(),
            "the refused peer leaves no live entry"
        );
        assert!(!peer_table.is_connected(bitcoin_rs_p2p::PeerEndpoint::Ip(addr)));
        Ok(())
    }

    #[test]
    fn outbound_peer_with_network_and_witness_is_accepted() -> Result<(), TestError> {
        let magic = Magic::BITCOIN;
        let peer_table = Arc::new(PeerTable::new());
        let shared = outbound_shared(Arc::clone(&peer_table), magic);
        let listener = TcpListener::bind(
            PeerEndpoint::from((Ipv4Addr::LOCALHOST, 0))
                .socket_addr()
                .unwrap_or_else(|| panic!("expected IP fixture")),
        )?;
        let addr = listener.local_addr()?;
        let dial = spawn_outbound_connection(addr.into(), shared, PeerRole::FullRelay);

        let (mut server, _) = listener.accept()?;
        server.set_read_timeout(Some(Duration::from_secs(5)))?;
        server.set_write_timeout(Some(Duration::from_secs(5)))?;
        let Ok((Message::Version(_), _)) = read_message(&mut server, magic) else {
            return Err("the dial opens with a version message".into());
        };
        write_message(
            &mut server,
            magic,
            &remote_version(ServiceFlags::NETWORK | ServiceFlags::WITNESS),
        )?;
        write_message(&mut server, magic, &Message::Verack)?;

        let deadline = Instant::now() + Duration::from_secs(5);
        while peer_table
            .ready_source(bitcoin_rs_p2p::PeerEndpoint::Ip(addr))
            .is_none()
            && Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            peer_table
                .ready_source(bitcoin_rs_p2p::PeerEndpoint::Ip(addr))
                .is_some(),
            "an eligible peer is published ready"
        );
        drop(server);
        drop(dial);
        Ok(())
    }

    #[test]
    fn outbound_near_tip_limited_peer_is_accepted() -> Result<(), TestError> {
        let magic = Magic::BITCOIN;
        let peer_table = Arc::new(PeerTable::new());
        let mut shared = outbound_shared(Arc::clone(&peer_table), magic);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let recent = Header {
            time: u32::try_from(now).unwrap_or(u32::MAX),
            ..genesis_block()?.header
        };
        shared.chain_query = Some(Arc::new(FakeChain::new(vec![recent], HashMap::new())));
        let listener = TcpListener::bind(
            PeerEndpoint::from((Ipv4Addr::LOCALHOST, 0))
                .socket_addr()
                .unwrap_or_else(|| panic!("expected IP fixture")),
        )?;
        let addr = listener.local_addr()?;
        let dial = spawn_outbound_connection(addr.into(), shared, PeerRole::FullRelay);

        let (mut server, _) = listener.accept()?;
        server.set_read_timeout(Some(Duration::from_secs(5)))?;
        server.set_write_timeout(Some(Duration::from_secs(5)))?;
        let Ok((Message::Version(_), _)) = read_message(&mut server, magic) else {
            return Err("the dial opens with a version message".into());
        };
        write_message(
            &mut server,
            magic,
            &remote_version(ServiceFlags::NETWORK_LIMITED | ServiceFlags::WITNESS),
        )?;
        write_message(&mut server, magic, &Message::Verack)?;

        let deadline = Instant::now() + Duration::from_secs(5);
        while peer_table
            .ready_source(bitcoin_rs_p2p::PeerEndpoint::Ip(addr))
            .is_none()
            && Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            peer_table
                .ready_source(bitcoin_rs_p2p::PeerEndpoint::Ip(addr))
                .is_some(),
            "a LIMITED peer near the local tip is desirable"
        );
        drop(server);
        drop(dial);
        Ok(())
    }

    #[test]
    fn pruned_version_message_advertises_network_limited_only() {
        let pruned = ServiceFlags::WITNESS | ServiceFlags::NETWORK_LIMITED;
        let version = version_message(1, 0, PeerRole::FullRelay, pruned, USER_AGENT);
        assert!(version.services.has(ServiceFlags::NETWORK_LIMITED));
        assert!(!version.services.has(ServiceFlags::NETWORK));
        assert!(version.services.has(ServiceFlags::WITNESS));
        assert_eq!(version.sender.services, pruned);
        assert_eq!(version.receiver.services, pruned);
    }
}
mod core_interop_live {
    #![cfg(unix)]

    use std::path::PathBuf;

    use bitcoin_rs_consensus::primitives::USER_AGENT;
    use sonic_rs::{JsonValueTrait, Value};

    const EVIDENCE_ENV: &str = "P2P_CORE_INTEROP_EVIDENCE";
    const SCHEMA: &str = "bitcoin-rs-core-differential-v4";

    #[derive(Debug, thiserror::Error)]
    enum LiveError {
        #[error(transparent)]
        Io(#[from] std::io::Error),
        #[error(transparent)]
        Sonic(#[from] sonic_rs::Error),
        #[error("{0}")]
        Message(String),
    }

    fn main_error(message: impl std::fmt::Display) -> LiveError {
        LiveError::Message(message.to_string())
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
        main_error(format!(
            "{EVIDENCE_ENV} must point at the evidence JSON from scripts/run-p2p-core-interop.sh"
        ))
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

    // CORE-02, CORE-03, CORE-05, CORE-06
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
}
mod handshake_roundtrip {
    use std::io::{Cursor, Read, Write};

    use bitcoin::p2p::message_compact_blocks::SendCmpct;
    use bitcoin::p2p::{Magic, ServiceFlags};
    use bitcoin_rs_consensus::primitives::USER_AGENT;
    use bitcoin_rs_p2p::CompactBlockNegotiation;
    use bitcoin_rs_p2p::compact_blocks::COMPACT_BLOCK_VERSION;
    use bitcoin_rs_p2p::dispatch::dispatch_inbound;
    use bitcoin_rs_p2p::handshake::start;
    use bitcoin_rs_p2p::wire::PROTOCOL_VERSION;
    use bitcoin_rs_p2p::{Message, Peer, PeerError, PeerRole, PeerState};

    fn handshake_cursors(
        left: &mut Peer<Cursor<Vec<u8>>>,
        right: &mut Peer<Cursor<Vec<u8>>>,
    ) -> Result<(), PeerError> {
        let unpruned = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
        let left_messages = start(left, 1, 0, PeerRole::FullRelay, unpruned, USER_AGENT);
        exchange(left, right, left_messages)?;
        let right_messages = start(right, 2, 0, PeerRole::FullRelay, unpruned, USER_AGENT);
        exchange(right, left, right_messages)?;
        exchange(left, right, vec![Message::Verack])?;
        exchange(right, left, vec![Message::Verack])?;
        let send_cmpct = Message::SendCmpct(SendCmpct {
            send_compact: false,
            version: COMPACT_BLOCK_VERSION,
        });
        exchange(left, right, vec![send_cmpct.clone()])?;
        exchange(right, left, vec![send_cmpct])?;
        Ok(())
    }

    fn exchange<A, B>(
        from: &mut Peer<A>,
        to: &mut Peer<B>,
        messages: Vec<Message>,
    ) -> Result<(), PeerError>
    where
        A: Read + Write,
        B: Read + Write,
    {
        for message in messages {
            from.send(&message)?;
            for response in dispatch_inbound(to, &message)? {
                to.send(&response)?;
            }
        }
        Ok(())
    }

    #[test]
    fn cursor_peers_reach_ready_after_version_verack_exchange() -> Result<(), PeerError> {
        let mut left = Peer::new(Cursor::new(Vec::new()), Magic::BITCOIN);
        let mut right = Peer::new(Cursor::new(Vec::new()), Magic::BITCOIN);

        handshake_cursors(&mut left, &mut right)?;

        assert_eq!(left.state, PeerState::Ready);
        assert_eq!(right.state, PeerState::Ready);
        assert!(left.capabilities.addr_v2);
        assert!(right.capabilities.addr_v2);
        assert!(left.wtxid_relay.peer_supported());
        assert!(right.wtxid_relay.peer_supported());
        Ok(())
    }

    #[test]
    fn cursor_handshake_advertises_the_pinned_wire_protocol_version() {
        let mut peer = Peer::new(Cursor::new(Vec::<u8>::new()), Magic::BITCOIN);
        let messages = start(
            &mut peer,
            1,
            0,
            PeerRole::FullRelay,
            ServiceFlags::NETWORK | ServiceFlags::WITNESS,
            USER_AGENT,
        );

        let [Message::Version(version), ..] = messages.as_slice() else {
            panic!("the first message is the version announcement");
        };
        assert_eq!(version.version, PROTOCOL_VERSION);
        assert_eq!(
            peer.compact_blocks,
            CompactBlockNegotiation::default(),
            "the local advertisement is recorded only after verack"
        );
    }

    #[test]
    fn cursor_handshake_records_the_remote_compact_block_advertisement() -> Result<(), PeerError> {
        let mut left = Peer::new(Cursor::new(Vec::new()), Magic::BITCOIN);
        let mut right = Peer::new(Cursor::new(Vec::new()), Magic::BITCOIN);

        handshake_cursors(&mut left, &mut right)?;

        assert_eq!(
            left.compact_blocks.remote_version,
            Some(COMPACT_BLOCK_VERSION)
        );
        assert_eq!(
            right.compact_blocks.remote_version,
            Some(COMPACT_BLOCK_VERSION)
        );
        assert_eq!(left.compact_blocks.remote_send_compact, Some(false));
        assert_eq!(right.compact_blocks.remote_send_compact, Some(false));
        Ok(())
    }
}
mod listener_ban {
    use bitcoin_rs_consensus::primitives::{PeerEndpoint, USER_AGENT};
    use std::io::{self, Read};
    use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::{Duration, Instant, SystemTime};

    use bitcoin::p2p::Magic;
    use bitcoin::p2p::ServiceFlags;
    use bitcoin_rs_p2p::PeerRole;
    use bitcoin_rs_p2p::handshake::version_message;
    use bitcoin_rs_p2p::listener::{
        ConnectionShared, bind_listener, serve, spawn_outbound_connection,
    };
    use bitcoin_rs_p2p::wire::{Message, read_message, write_message};
    use bitcoin_rs_p2p::{
        BannedSubnet, IpSubnet, ListenerExtras, NetworkActivity, PeerError, PeerTable,
    };
    use parking_lot::RwLock;

    #[derive(Debug, thiserror::Error)]
    enum TestError {
        #[error(transparent)]
        Io(#[from] io::Error),
        #[error(transparent)]
        Peer(#[from] PeerError),
        #[error(transparent)]
        Listener(#[from] bitcoin_rs_p2p::listener::ListenerError),
        #[error(transparent)]
        SubnetParse(#[from] bitcoin_rs_p2p::SubnetParseError),
    }

    #[test]
    fn outbound_ban_short_circuits_before_connect_with_typed_error() -> Result<(), TestError> {
        let helper = TcpListener::bind(
            PeerEndpoint::from((Ipv4Addr::LOCALHOST, 0))
                .socket_addr()
                .unwrap_or_else(|| panic!("expected IP fixture")),
        )?;
        helper.set_nonblocking(true)?;
        let addr = helper.local_addr()?;
        let accept_helper = helper.try_clone()?;
        accept_helper.set_nonblocking(true)?;
        let helper_shutdown = Arc::new(AtomicBool::new(false));
        let accept_shutdown = Arc::clone(&helper_shutdown);
        let accept_handle =
            thread::spawn(move || accept_one_connection(&accept_helper, &accept_shutdown));
        let shared = wiring(
            Arc::new(PeerTable::new()),
            Arc::new(RwLock::new(vec![ban(IpSubnet::from_ip(addr.ip()))])),
            Arc::new(AtomicBool::new(true)),
            bitcoin_rs_consensus::latch::LatchWriter::new().reader(),
        );

        let handle = spawn_outbound_connection(addr.into(), shared, PeerRole::FullRelay);
        let result = match handle.join() {
            Ok(result) => result,
            Err(error) => std::panic::resume_unwind(error),
        };
        helper_shutdown.store(true, Ordering::Relaxed);
        let accepted = join_accept(accept_handle)?;
        assert!(
            !accepted,
            "outbound ban should reject before opening a TCP connection"
        );

        match result {
            Err(PeerError::BannedDestination(ip)) => assert_eq!(ip.ip(), Some(addr.ip())),
            other => {
                return Err(io::Error::other(format!(
                    "expected banned destination error, got {other:?}"
                ))
                .into());
            }
        }

        Ok(())
    }

    #[test]
    fn inbound_ban_drops_connection_pre_handshake() -> Result<(), TestError> {
        let listener = bind_listener(
            PeerEndpoint::from((Ipv4Addr::LOCALHOST, 0))
                .socket_addr()
                .unwrap_or_else(|| panic!("expected IP fixture")),
        )?;
        let addr = listener.local_addr()?;

        let shutdown = bitcoin_rs_consensus::latch::LatchWriter::new();
        let peer_table = Arc::new(PeerTable::new());
        let banned = Arc::new(RwLock::new(vec![ban(IpSubnet::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)),
            8,
        )?)]));
        let shared = wiring(
            Arc::clone(&peer_table),
            banned,
            Arc::new(AtomicBool::new(true)),
            bitcoin_rs_consensus::latch::LatchWriter::new().reader(),
        );

        let listener_shutdown = shutdown.reader();
        let handle = thread::spawn(move || serve(listener, listener_shutdown, shared));

        let mut client = match connect_with_retry(addr.into(), Duration::from_secs(1)) {
            Ok(client) => client,
            Err(error) => {
                shutdown.trigger();
                join_listener(handle)?;
                return Err(error.into());
            }
        };

        wait_for_disconnect(&mut client, Duration::from_secs(1))?;
        assert!(peer_table.is_empty());

        shutdown.trigger();
        join_listener(handle)?;

        Ok(())
    }

    #[test]
    fn network_inactive_drops_inbound_pre_handshake() -> Result<(), TestError> {
        let listener = bind_listener(
            PeerEndpoint::from((Ipv4Addr::LOCALHOST, 0))
                .socket_addr()
                .unwrap_or_else(|| panic!("expected IP fixture")),
        )?;
        let addr = listener.local_addr()?;

        let shutdown = bitcoin_rs_consensus::latch::LatchWriter::new();
        let peer_table = Arc::new(PeerTable::new());
        let shared = wiring(
            Arc::clone(&peer_table),
            Arc::new(RwLock::new(Vec::new())),
            Arc::new(AtomicBool::new(false)),
            bitcoin_rs_consensus::latch::LatchWriter::new().reader(),
        );

        let listener_shutdown = shutdown.reader();
        let handle = thread::spawn(move || serve(listener, listener_shutdown, shared));

        let mut client = connect_with_retry(addr.into(), Duration::from_secs(1))?;
        wait_for_disconnect(&mut client, Duration::from_secs(1))?;
        assert!(peer_table.is_empty());

        shutdown.trigger();
        join_listener(handle)?;
        Ok(())
    }

    #[test]
    fn network_active_blocks_outbound_until_reenabled() -> Result<(), TestError> {
        let helper = TcpListener::bind(
            PeerEndpoint::from((Ipv4Addr::LOCALHOST, 0))
                .socket_addr()
                .unwrap_or_else(|| panic!("expected IP fixture")),
        )?;
        helper.set_nonblocking(true)?;
        let addr = helper.local_addr()?;
        let accept_helper = helper.try_clone()?;
        accept_helper.set_nonblocking(true)?;
        let accept_shutdown = Arc::new(AtomicBool::new(false));
        let accept_handle = thread::spawn({
            let accept_shutdown = Arc::clone(&accept_shutdown);
            move || accept_one_connection(&accept_helper, &accept_shutdown)
        });

        let network_active = Arc::new(AtomicBool::new(false));
        let shared = wiring(
            Arc::new(PeerTable::new()),
            Arc::new(RwLock::new(Vec::new())),
            Arc::clone(&network_active),
            bitcoin_rs_consensus::latch::LatchWriter::new().reader(),
        );

        let inactive = spawn_outbound_connection(addr.into(), shared.clone(), PeerRole::FullRelay);
        let inactive = inactive
            .join()
            .map_err(|_| io::Error::other("inactive outbound thread panicked"))?;
        assert!(
            matches!(inactive, Err(PeerError::Protocol("network inactive"))),
            "inactive outbound attempt must exit before TCP connect, got {inactive:?}"
        );
        thread::sleep(Duration::from_millis(100));
        assert!(
            !accept_handle.is_finished(),
            "inactive outbound attempt opened a TCP connection"
        );

        network_active.store(true, Ordering::Release);
        let active = spawn_outbound_connection(addr.into(), shared, PeerRole::FullRelay);
        assert!(join_accept(accept_handle)?);
        let _ = active
            .join()
            .map_err(|_| io::Error::other("active outbound thread panicked"))?;
        accept_shutdown.store(true, Ordering::Relaxed);
        Ok(())
    }

    #[test]
    fn cancelled_start_refuses_outbound_before_connect() -> Result<(), TestError> {
        let helper = TcpListener::bind(
            PeerEndpoint::from((Ipv4Addr::LOCALHOST, 0))
                .socket_addr()
                .unwrap_or_else(|| panic!("expected IP fixture")),
        )?;
        helper.set_nonblocking(true)?;
        let addr = helper.local_addr()?;
        let accept_helper = helper.try_clone()?;
        accept_helper.set_nonblocking(true)?;
        let accept_shutdown = Arc::new(AtomicBool::new(false));
        let accept_handle = thread::spawn({
            let accept_shutdown = Arc::clone(&accept_shutdown);
            move || accept_one_connection(&accept_helper, &accept_shutdown)
        });

        let peer_table = Arc::new(PeerTable::new());
        let cancelled = bitcoin_rs_consensus::latch::LatchWriter::new();
        cancelled.trigger();
        let shared = wiring(
            Arc::clone(&peer_table),
            Arc::new(RwLock::new(Vec::new())),
            Arc::new(AtomicBool::new(true)),
            cancelled.reader(),
        );

        let refused = spawn_outbound_connection(addr.into(), shared, PeerRole::FullRelay)
            .join()
            .map_err(|_| io::Error::other("cancelled outbound thread panicked"))?;
        assert!(
            matches!(refused, Err(PeerError::Protocol("p2p startup cancelled"))),
            "a cancelled start must refuse the dial, got {refused:?}"
        );
        thread::sleep(Duration::from_millis(100));
        accept_shutdown.store(true, Ordering::Relaxed);
        assert!(
            !join_accept(accept_handle)?,
            "a cancelled start must not open a TCP connection"
        );
        assert!(peer_table.is_empty());
        Ok(())
    }

    #[test]
    fn live_handshake_traffic_reaches_the_aggregate_ledger() -> Result<(), TestError> {
        let listener = TcpListener::bind(
            PeerEndpoint::from((Ipv4Addr::LOCALHOST, 0))
                .socket_addr()
                .unwrap_or_else(|| panic!("expected IP fixture")),
        )?;
        let addr = listener.local_addr()?;

        let peer_table = Arc::new(PeerTable::new());
        let shared = wiring(
            Arc::clone(&peer_table),
            Arc::new(RwLock::new(Vec::new())),
            Arc::new(AtomicBool::new(true)),
            bitcoin_rs_consensus::latch::LatchWriter::new().reader(),
        );
        let outbound_handle = spawn_outbound_connection(addr.into(), shared, PeerRole::FullRelay);

        let (mut server, _) = listener.accept()?;
        server.set_read_timeout(Some(Duration::from_secs(5)))?;
        server.set_write_timeout(Some(Duration::from_secs(5)))?;
        let Ok((Message::Version(_), _)) = read_message(&mut server, Magic::BITCOIN) else {
            return Err(io::Error::other("the dial opens with a version message").into());
        };
        write_message(
            &mut server,
            Magic::BITCOIN,
            &Message::Version(version_message(
                1,
                0,
                PeerRole::FullRelay,
                ServiceFlags::NETWORK | ServiceFlags::WITNESS,
                USER_AGENT,
            )),
        )?;
        write_message(&mut server, Magic::BITCOIN, &Message::Verack)?;

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let (received, sent) = peer_table.traffic_totals();
            if received > 0 && sent > 0 {
                break;
            }
            if Instant::now() >= deadline {
                return Err(io::Error::other(format!(
                    "handshake traffic never reached the aggregate ledger \
                 (received={received}, sent={sent})"
                ))
                .into());
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert_ne!(peer_table.len(), 0);

        drop(server);
        if outbound_handle.join().is_err() {
            return Err(io::Error::other("outbound thread panicked during teardown").into());
        }
        Ok(())
    }

    #[test]
    fn self_dial_is_refused_by_its_own_in_flight_nonce() -> Result<(), TestError> {
        let listener = bind_listener(
            PeerEndpoint::from((Ipv4Addr::LOCALHOST, 0))
                .socket_addr()
                .unwrap_or_else(|| panic!("expected IP fixture")),
        )?;
        let addr = listener.local_addr()?;

        let shutdown = bitcoin_rs_consensus::latch::LatchWriter::new();
        let session_cancel = Arc::new(bitcoin_rs_consensus::latch::LatchWriter::new());
        let peer_table = Arc::new(PeerTable::new());
        let shared = wiring(
            Arc::clone(&peer_table),
            Arc::new(RwLock::new(Vec::new())),
            Arc::new(AtomicBool::new(true)),
            session_cancel.reader(),
        );

        let listener_shutdown = shutdown.reader();
        let serve_shared = shared.clone();
        let serve_handle = thread::spawn(move || serve(listener, listener_shutdown, serve_shared));
        let outbound_handle = spawn_outbound_connection(addr.into(), shared, PeerRole::FullRelay);

        let deadline = Instant::now() + Duration::from_secs(5);
        while !outbound_handle.is_finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        let finished = outbound_handle.is_finished();

        session_cancel.trigger();
        peer_table.cancel_all();
        shutdown.trigger();
        join_listener(serve_handle)?;
        let joined = outbound_handle.join();
        assert!(
            finished,
            "a dial to our own listener must not stay connected"
        );
        match joined {
            Ok(Err(_)) => {}
            Ok(Ok(())) => {
                return Err(io::Error::other("a dial to our own listener completed").into());
            }
            Err(_) => return Err(io::Error::other("outbound thread panicked").into()),
        }
        assert!(
            peer_table.live_sessions().is_empty(),
            "a refused self-connection leaves no live session"
        );
        Ok(())
    }

    fn wiring(
        peer_table: Arc<PeerTable>,
        banned: Arc<RwLock<Vec<BannedSubnet>>>,
        network_active: Arc<AtomicBool>,
        session_cancel: bitcoin_rs_consensus::latch::LatchReader,
    ) -> ConnectionShared {
        let (headers_tx, _headers_rx) = crossbeam_channel::unbounded();
        let (blocks_tx, _blocks_rx) = crossbeam_channel::unbounded();
        ConnectionShared::new(
            peer_table,
            banned,
            Arc::new(NetworkActivity::from_shared(network_active)),
            session_cancel,
            None,
            Magic::BITCOIN,
            headers_tx,
            blocks_tx,
            None,
            None,
            ListenerExtras::default(),
        )
    }

    fn ban(subnet: IpSubnet) -> BannedSubnet {
        BannedSubnet {
            subnet,
            banned_until: None,
            ban_created: SystemTime::now(),
            reason: String::from("test ban"),
        }
    }

    fn connect_with_retry(addr: PeerEndpoint, timeout: Duration) -> io::Result<TcpStream> {
        let deadline = Instant::now() + timeout;
        loop {
            match TcpStream::connect(
                addr.socket_addr()
                    .unwrap_or_else(|| panic!("expected IP fixture")),
            ) {
                Ok(stream) => return Ok(stream),
                Err(error) => {
                    if Instant::now() >= deadline {
                        return Err(error);
                    }
                }
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn wait_for_disconnect(stream: &mut TcpStream, timeout: Duration) -> io::Result<()> {
        stream.set_read_timeout(Some(Duration::from_millis(20)))?;
        let deadline = Instant::now() + timeout;
        let mut byte = [0_u8; 1];

        loop {
            match stream.read(&mut byte) {
                Ok(0) => return Ok(()),
                Ok(_) => return Err(io::Error::other("banned inbound connection sent data")),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) => {}
                Err(_) => return Ok(()),
            }

            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "banned inbound connection stayed open",
                ));
            }
        }
    }

    fn accept_one_connection(
        listener: &TcpListener,
        shutdown: &Arc<AtomicBool>,
    ) -> io::Result<bool> {
        while !shutdown.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _peer_addr)) => {
                    drop(stream);
                    return Ok(true);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => return Err(error),
            }
        }

        Ok(false)
    }

    fn join_accept(handle: thread::JoinHandle<io::Result<bool>>) -> Result<bool, TestError> {
        match handle.join() {
            Ok(Ok(accepted)) => Ok(accepted),
            Ok(Err(error)) => Err(error.into()),
            Err(_) => Err(io::Error::other("helper accept thread panicked").into()),
        }
    }

    fn join_listener(
        handle: thread::JoinHandle<Result<(), bitcoin_rs_p2p::listener::ListenerError>>,
    ) -> Result<(), TestError> {
        match handle.join() {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(error.into()),
            Err(_) => Err(io::Error::other("listener thread panicked").into()),
        }
    }
}
mod listener_shutdown {
    use bitcoin::p2p::Magic;
    use bitcoin_rs_consensus::primitives::PeerEndpoint;
    use bitcoin_rs_p2p::listener::{ConnectionShared, ListenerError, bind_listener, serve};
    use bitcoin_rs_p2p::{ListenerExtras, NetworkActivity, PeerTable};
    use std::io;
    use std::net::{Ipv4Addr, TcpStream};
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    #[derive(Debug, thiserror::Error)]
    enum TestError {
        #[error(transparent)]
        Io(#[from] io::Error),
        #[error(transparent)]
        Listener(#[from] ListenerError),
        #[error(transparent)]
        RecvTimeout(#[from] mpsc::RecvTimeoutError),
    }

    struct ServeGuard {
        shutdown: Arc<bitcoin_rs_consensus::latch::LatchWriter>,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl ServeGuard {
        fn new(
            shutdown: &Arc<bitcoin_rs_consensus::latch::LatchWriter>,
            handle: thread::JoinHandle<()>,
        ) -> Self {
            Self {
                shutdown: Arc::clone(shutdown),
                handle: Some(handle),
            }
        }

        fn join(mut self) -> Result<(), TestError> {
            self.shutdown.trigger();
            match self.handle.take() {
                Some(handle) => handle
                    .join()
                    .map_err(|_| io::Error::other("listener thread panicked").into()),
                None => Ok(()),
            }
        }
    }

    impl Drop for ServeGuard {
        fn drop(&mut self) {
            self.shutdown.trigger();
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    #[test]
    fn serve_exits_when_flag_set() -> Result<(), TestError> {
        let listener = bind_listener(
            PeerEndpoint::from((Ipv4Addr::LOCALHOST, 0))
                .socket_addr()
                .unwrap_or_else(|| panic!("expected IP fixture")),
        )?;
        let addr = listener.local_addr()?;

        let shutdown = Arc::new(bitcoin_rs_consensus::latch::LatchWriter::new());
        let listener_shutdown = shutdown.reader();
        let (tx, rx) = mpsc::channel();
        let peer_table = Arc::new(PeerTable::new());
        let shared = wiring(Arc::clone(&peer_table));

        let handle = thread::spawn(move || {
            let result = serve(listener, listener_shutdown, shared);
            let _ = tx.send(result);
        });
        let guard = ServeGuard::new(&shutdown, handle);

        let client = TcpStream::connect(addr)?;
        let deadline = Instant::now() + Duration::from_secs(5);
        while peer_table.is_empty() {
            match rx.try_recv() {
                Ok(listener_result) => {
                    listener_result?;
                    return Err(io::Error::other("listener exited before shutdown").into());
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    return Err(io::Error::other("listener thread exited early").into());
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
            if Instant::now() >= deadline {
                return Err(io::Error::other("listener never accepted the connection").into());
            }
            thread::sleep(Duration::from_millis(5));
        }

        drop(client);

        shutdown.trigger();
        let result = rx.recv_timeout(Duration::from_secs(5))?;
        guard.join()?;

        result?;
        let deadline = Instant::now() + Duration::from_secs(5);
        while !peer_table.is_empty() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert!(peer_table.is_empty());
        Ok(())
    }

    #[test]
    fn serve_returns_without_accepting_when_flag_preset() -> Result<(), TestError> {
        let listener = bind_listener(
            PeerEndpoint::from((Ipv4Addr::LOCALHOST, 0))
                .socket_addr()
                .unwrap_or_else(|| panic!("expected IP fixture")),
        )?;

        let shutdown = Arc::new(bitcoin_rs_consensus::latch::LatchWriter::new());
        shutdown.trigger();
        let listener_shutdown = shutdown.reader();
        let (tx, rx) = mpsc::channel();
        let peer_table = Arc::new(PeerTable::new());
        let shared = wiring(Arc::clone(&peer_table));

        let handle = thread::spawn(move || {
            let result = serve(listener, listener_shutdown, shared);
            let _ = tx.send(result);
        });
        let guard = ServeGuard::new(&shutdown, handle);

        let result = rx.recv_timeout(Duration::from_secs(5))?;
        guard.join()?;

        result?;
        assert!(peer_table.is_empty());
        Ok(())
    }

    #[test]
    fn serve_unblocks_promptly_on_latch_trigger() -> Result<(), TestError> {
        let listener = bind_listener(
            PeerEndpoint::from((Ipv4Addr::LOCALHOST, 0))
                .socket_addr()
                .unwrap_or_else(|| panic!("expected IP fixture")),
        )?;
        let latch = bitcoin_rs_consensus::latch::LatchWriter::new();
        let reader = latch.reader();
        let peer_table = Arc::new(PeerTable::new());
        let shared = wiring(Arc::clone(&peer_table));
        let (tx, rx) = crossbeam_channel::bounded(1);
        let handle = thread::spawn(move || {
            let result = serve(listener, reader, shared);
            let _ = tx.send(result);
        });
        thread::sleep(Duration::from_millis(20));
        latch.trigger();
        let result = rx
            .recv_timeout(Duration::from_millis(50))
            .map_err(|_| io::Error::other("serve did not unblock promptly upon latch trigger"))?;
        result?;
        handle
            .join()
            .map_err(|_| io::Error::other("serve thread panicked"))?;
        Ok(())
    }

    fn wiring(peer_table: Arc<PeerTable>) -> ConnectionShared {
        let (headers_tx, _headers_rx) = crossbeam_channel::unbounded();
        let (blocks_tx, _blocks_rx) = crossbeam_channel::unbounded();
        ConnectionShared::new(
            peer_table,
            Arc::new(parking_lot::RwLock::new(Vec::new())),
            Arc::new(NetworkActivity::from_shared(Arc::new(AtomicBool::new(
                true,
            )))),
            bitcoin_rs_consensus::latch::LatchWriter::new().reader(),
            None,
            Magic::BITCOIN,
            headers_tx,
            blocks_tx,
            None,
            None,
            ListenerExtras::default(),
        )
    }
}
mod subnet {
    #![allow(clippy::expect_used)]

    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::time::{Duration, SystemTime};

    use bitcoin_rs_p2p::subnet::is_banned;
    use bitcoin_rs_p2p::{BannedSubnet, IpSubnet, SubnetParseError};

    #[test]
    fn ipv4_cidr_contains_only_same_network_family() {
        let subnet = parse_subnet("192.0.2.0/24");

        assert_eq!(subnet.to_string(), "192.0.2.0/24");
        assert!(subnet.contains(v4(192, 0, 2, 7)));
        assert!(!subnet.contains(v4(192, 0, 3, 1)));
        assert!(!subnet.contains(v6([0x2001, 0x0db8, 0, 0, 0, 0, 0, 1])));
    }

    #[test]
    fn bare_ipv4_parses_as_host_subnet() {
        let subnet = parse_subnet("127.0.0.1");

        assert_eq!(subnet.to_string(), "127.0.0.1/32");
        assert!(subnet.contains(v4(127, 0, 0, 1)));
        assert!(!subnet.contains(v4(127, 0, 0, 2)));
    }

    #[test]
    fn bare_ipv6_parses_as_host_subnet() {
        let subnet = parse_subnet("::1");

        assert_eq!(subnet.to_string(), "::1/128");
        assert!(subnet.contains(v6([0, 0, 0, 0, 0, 0, 0, 1])));
        assert!(!subnet.contains(v6([0, 0, 0, 0, 0, 0, 0, 2])));
    }

    #[test]
    fn ipv6_cidr_normalizes_host_bits() {
        let subnet = parse_subnet("2001:db8::beef/32");

        assert_eq!(subnet.to_string(), "2001:db8::/32");
        assert_eq!(subnet.base(), v6([0x2001, 0x0db8, 0, 0, 0, 0, 0, 0]));
        assert_eq!(subnet.prefix(), 32);
    }

    #[test]
    fn rejects_invalid_subnets() {
        assert_eq!(
            "192.0.2.1/33".parse::<IpSubnet>(),
            Err(SubnetParseError::PrefixTooLarge {
                width: 32,
                prefix: 33,
            })
        );
        assert_eq!(
            "2001:db8::1/129".parse::<IpSubnet>(),
            Err(SubnetParseError::PrefixTooLarge {
                width: 128,
                prefix: 129,
            })
        );
        assert_eq!(
            "192.0.2.1:8333".parse::<IpSubnet>(),
            Err(SubnetParseError::TrailingJunk)
        );
        assert_eq!(
            "[2001:db8::1]:8333".parse::<IpSubnet>(),
            Err(SubnetParseError::TrailingJunk)
        );
        assert_eq!(
            "not-an-ip".parse::<IpSubnet>(),
            Err(SubnetParseError::BadIp)
        );
    }

    #[test]
    fn zero_prefix_matches_entire_same_family_only() {
        let v4_subnet = parse_subnet("192.0.2.1/0");
        let v6_subnet = parse_subnet("2001:db8::1/0");

        assert_eq!(v4_subnet.to_string(), "0.0.0.0/0");
        assert!(v4_subnet.contains(v4(203, 0, 113, 1)));
        assert!(!v4_subnet.contains(v6([0x2001, 0x0db8, 0, 0, 0, 0, 0, 1])));

        assert_eq!(v6_subnet.to_string(), "::/0");
        assert!(v6_subnet.contains(v6([0x2001, 0x0db8, 0, 0, 0, 0, 0, 1])));
        assert!(!v6_subnet.contains(v4(203, 0, 113, 1)));
    }

    #[test]
    fn ipv4_mapped_ipv6_base_canonicalizes_to_ipv4_subnet() {
        let subnet = parse_subnet("::ffff:192.0.2.7");

        assert_eq!(subnet.to_string(), "192.0.2.7/32");
        assert!(subnet.contains(v4(192, 0, 2, 7)));
        assert!(
            subnet.contains(
                "::ffff:192.0.2.7"
                    .parse::<std::net::IpAddr>()
                    .expect("mapped v6 literal parses")
            )
        );
        assert!(!subnet.contains(v4(192, 0, 2, 8)));
    }

    #[test]
    fn ipv4_mapped_ipv6_prefix_validates_against_canonical_family() {
        assert_eq!(
            "::ffff:192.0.2.0/24"
                .parse::<IpSubnet>()
                .expect("mapped subnet with v4-width prefix parses")
                .to_string(),
            "192.0.2.0/24"
        );
        assert_eq!(
            "::ffff:192.0.2.0/120".parse::<IpSubnet>(),
            Err(SubnetParseError::PrefixTooLarge {
                width: 32,
                prefix: 120,
            })
        );
    }

    #[test]
    fn mapped_v4_query_matches_plain_v4_subnet() {
        let subnet = parse_subnet("192.0.2.0/24");
        let mapped: std::net::IpAddr = "::ffff:192.0.2.9"
            .parse()
            .expect("mapped v6 literal parses");

        assert!(subnet.contains(mapped));
    }

    #[test]
    fn is_banned_honors_permanent_future_and_past_entries() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let created = SystemTime::UNIX_EPOCH;
        let ip = v4(192, 0, 2, 7);
        let permanent = ban("192.0.2.0/24", None, created);
        let future = ban(
            "198.51.100.0/24",
            Some(now + Duration::from_secs(1)),
            created,
        );
        let expired = ban(
            "203.0.113.0/24",
            Some(now - Duration::from_secs(1)),
            created,
        );

        assert!(is_banned(&[permanent], ip, now));
        assert!(is_banned(&[future], v4(198, 51, 100, 7), now));
        assert!(!is_banned(&[expired], v4(203, 0, 113, 7), now));
        assert!(!is_banned(&[], ip, now));
    }

    fn ban(
        subnet: &str,
        banned_until: Option<SystemTime>,
        ban_created: SystemTime,
    ) -> BannedSubnet {
        BannedSubnet {
            subnet: parse_subnet(subnet),
            banned_until,
            ban_created,
            reason: String::from("test"),
        }
    }

    fn parse_subnet(input: &str) -> IpSubnet {
        match input.parse::<IpSubnet>() {
            Ok(subnet) => subnet,
            Err(error) => panic!("failed to parse subnet {input}: {error}"),
        }
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn v6(segments: [u16; 8]) -> IpAddr {
        IpAddr::V6(Ipv6Addr::from(segments))
    }
}
mod wire_codec {
    use std::io::Cursor;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    use bitcoin::TxMerkleNode;
    use bitcoin::Txid;
    use bitcoin::bip152::{
        BlockTransactions, BlockTransactionsRequest, HeaderAndShortIds, PrefilledTransaction,
        ShortId,
    };
    use bitcoin::block::BlockHash;
    use bitcoin::block::{Header, Version};
    use bitcoin::consensus::encode::{Encodable, VarInt};
    use bitcoin::hashes::Hash;
    use bitcoin::p2p::Magic;
    use bitcoin::p2p::ServiceFlags;
    use bitcoin::p2p::address::{AddrV2, AddrV2Message, Address};
    use bitcoin::p2p::message_blockdata::{GetHeadersMessage, Inventory};
    use bitcoin::p2p::message_compact_blocks::{BlockTxn, CmpctBlock, GetBlockTxn, SendCmpct};
    use bitcoin::pow::CompactTarget;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
    use bitcoin_rs_p2p::PeerRole;
    use bitcoin_rs_p2p::dispatch::dispatch_inbound;
    use bitcoin_rs_p2p::handshake::version_message;
    use bitcoin_rs_p2p::inv::MAX_INV_PER_MSG;
    use bitcoin_rs_p2p::wire::{
        MAX_ADDR_MESSAGE_COUNT, MAX_LOCATOR_HASHES, MAX_MESSAGE_PAYLOAD, Message, PeerError,
        read_message, write_message,
    };
    use bitcoin_rs_p2p::{Peer, PeerState};
    use sha2::{Digest, Sha256};

    #[test]
    fn round_trips_ping_pong_version_verack_inv_getheaders() -> Result<(), PeerError> {
        let messages = vec![
            Message::Ping(42),
            Message::Pong(42),
            Message::Version(version_message(
                99,
                123,
                PeerRole::FullRelay,
                bitcoin::p2p::ServiceFlags::NETWORK | bitcoin::p2p::ServiceFlags::WITNESS,
                bitcoin_rs_consensus::primitives::USER_AGENT,
            )),
            Message::Verack,
            Message::Inv(vec![Inventory::Transaction(Txid::from_byte_array(
                [7u8; 32],
            ))]),
            Message::GetHeaders(GetHeadersMessage::new(
                vec![BlockHash::all_zeros()],
                BlockHash::all_zeros(),
            )),
        ];

        for message in messages {
            let mut cursor = Cursor::new(Vec::new());
            write_message(&mut cursor, Magic::BITCOIN, &message)?;
            cursor.set_position(0);
            let (decoded, _) = read_message(&mut cursor, Magic::BITCOIN)?;
            assert_eq!(decoded, message);
        }

        Ok(())
    }

    type FrameBuilder = fn(usize) -> Result<Vec<u8>, PeerError>;

    #[test]
    fn count_capped_messages_accept_the_cap_and_refuse_one_more() -> Result<(), PeerError> {
        let cases: [(&str, FrameBuilder, usize, &str); 8] = [
            (
                "inv",
                |n| inventory_frame(b"inv", n),
                MAX_INV_PER_MSG,
                "inventory count too large",
            ),
            (
                "getdata",
                |n| inventory_frame(b"getdata", n),
                MAX_INV_PER_MSG,
                "inventory count too large",
            ),
            (
                "notfound",
                |n| inventory_frame(b"notfound", n),
                MAX_INV_PER_MSG,
                "inventory count too large",
            ),
            (
                "addr",
                addr_frame,
                MAX_ADDR_MESSAGE_COUNT,
                "addr count too large",
            ),
            (
                "addrv2",
                addrv2_frame,
                MAX_ADDR_MESSAGE_COUNT,
                "addrv2 count too large",
            ),
            (
                "getheaders",
                |n| locator_frame(b"getheaders", n),
                MAX_LOCATOR_HASHES,
                "getheaders locator too large",
            ),
            (
                "getblocks",
                |n| locator_frame(b"getblocks", n),
                MAX_LOCATOR_HASHES,
                "getblocks locator too large",
            ),
            ("headers", headers_frame, 2_000, "headers count too large"),
        ];

        for (command, frame, cap, refusal) in cases {
            let (decoded, _) = read_message(&mut Cursor::new(frame(cap)?), Magic::BITCOIN)?;
            assert_eq!(
                decoded.command().as_ref(),
                command,
                "decode must keep the command"
            );
            let decoded_len = match decoded {
                Message::Inv(items) | Message::GetData(items) | Message::NotFound(items) => {
                    items.len()
                }
                Message::Addr(addresses) => addresses.len(),
                Message::AddrV2(addresses) => addresses.len(),
                Message::GetHeaders(request) => request.locator_hashes.len(),
                Message::GetBlocks(request) => request.locator_hashes.len(),
                Message::Headers(headers) => headers.len(),
                other => panic!("{command} frame decoded as {}", other.command()),
            };
            assert_eq!(
                decoded_len, cap,
                "{command} at the cap must keep every entry"
            );

            match read_message(&mut Cursor::new(frame(cap + 1)?), Magic::BITCOIN) {
                Err(PeerError::Misbehavior(message)) => assert_eq!(message, refusal, "{command}"),
                other => panic!("{command} above the cap must be refused, got {other:?}"),
            }
        }
        Ok(())
    }

    #[test]
    fn round_trips_compact_block_messages() -> Result<(), PeerError> {
        let block_hash = BlockHash::from_byte_array([3u8; 32]);
        let transaction = compact_block_transaction();
        let messages = vec![
            Message::SendCmpct(SendCmpct {
                send_compact: false,
                version: 1,
            }),
            Message::SendCmpct(SendCmpct {
                send_compact: true,
                version: 2,
            }),
            Message::CmpctBlock(CmpctBlock {
                compact_block: HeaderAndShortIds {
                    header: compact_block_header(),
                    nonce: 99,
                    short_ids: vec![ShortId::default()],
                    prefilled_txs: vec![PrefilledTransaction {
                        idx: 0,
                        tx: transaction.clone(),
                    }],
                },
            }),
            Message::GetBlockTxn(GetBlockTxn {
                txs_request: BlockTransactionsRequest {
                    block_hash,
                    indexes: vec![1, 3],
                },
            }),
            Message::BlockTxn(BlockTxn {
                transactions: BlockTransactions {
                    block_hash,
                    transactions: vec![transaction],
                },
            }),
        ];

        for message in messages {
            let mut cursor = Cursor::new(Vec::new());
            write_message(&mut cursor, Magic::BITCOIN, &message)?;
            cursor.set_position(0);
            let (decoded, _) = read_message(&mut cursor, Magic::BITCOIN)?;
            assert_eq!(decoded, message);
        }

        Ok(())
    }

    fn getblocktxn_frame(deltas: &[u64]) -> Result<Vec<u8>, PeerError> {
        let mut payload =
            bitcoin::consensus::encode::serialize(&BlockHash::from_byte_array([3u8; 32]));
        let count =
            u64::try_from(deltas.len()).map_err(|_| PeerError::PayloadTooLarge(deltas.len()))?;
        payload.extend_from_slice(&bitcoin::consensus::encode::serialize(&VarInt(count)));
        for delta in deltas {
            payload.extend_from_slice(&bitcoin::consensus::encode::serialize(&VarInt(*delta)));
        }
        message_frame(b"getblocktxn", &payload)
    }

    fn decoded_getblocktxn(deltas: &[u64]) -> Result<Vec<u64>, PeerError> {
        let mut cursor = Cursor::new(getblocktxn_frame(deltas)?);
        let (decoded, _) = read_message(&mut cursor, Magic::BITCOIN)?;
        let Message::GetBlockTxn(request) = decoded else {
            panic!("a getblocktxn frame must decode as getblocktxn");
        };
        Ok(request.txs_request.indexes)
    }

    #[test]
    fn getblocktxn_differential_indexes_decode_to_absolute_order() -> Result<(), PeerError> {
        assert_eq!(decoded_getblocktxn(&[1, 0, 0])?, vec![1, 2, 3]);
        assert_eq!(decoded_getblocktxn(&[])?, Vec::<u64>::new());

        let mut cursor = Cursor::new(getblocktxn_frame(&[0, u64::MAX])?);
        assert!(
            read_message(&mut cursor, Magic::BITCOIN).is_err(),
            "an overflowing index delta must not decode"
        );
        Ok(())
    }

    fn inventory_frame(command: &[u8], count: usize) -> Result<Vec<u8>, PeerError> {
        let count_u64 = u64::try_from(count).map_err(|_| PeerError::PayloadTooLarge(count))?;
        let mut payload = Vec::new();
        VarInt(count_u64)
            .consensus_encode(&mut payload)
            .map_err(|error| PeerError::Io(std::io::Error::other(error.to_string())))?;
        let inventory = Inventory::Transaction(Txid::from_byte_array([9u8; 32]));
        for _ in 0..count {
            inventory
                .consensus_encode(&mut payload)
                .map_err(|error| PeerError::Io(std::io::Error::other(error.to_string())))?;
        }

        message_frame(command, &payload)
    }

    fn addr_frame(count: usize) -> Result<Vec<u8>, PeerError> {
        let count_u64 = u64::try_from(count).map_err(|_| PeerError::PayloadTooLarge(count))?;
        let mut payload = Vec::new();
        VarInt(count_u64)
            .consensus_encode(&mut payload)
            .map_err(|error| PeerError::Io(std::io::Error::other(error.to_string())))?;
        let socket = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8333));
        let address = (0_u32, Address::new(&socket, ServiceFlags::NETWORK));
        for _ in 0..count {
            address
                .consensus_encode(&mut payload)
                .map_err(|error| PeerError::Io(std::io::Error::other(error.to_string())))?;
        }

        message_frame(b"addr", &payload)
    }

    fn addrv2_frame(count: usize) -> Result<Vec<u8>, PeerError> {
        let count_u64 = u64::try_from(count).map_err(|_| PeerError::PayloadTooLarge(count))?;
        let mut payload = Vec::new();
        VarInt(count_u64)
            .consensus_encode(&mut payload)
            .map_err(|error| PeerError::Io(std::io::Error::other(error.to_string())))?;
        let address = AddrV2Message {
            time: 0,
            services: ServiceFlags::NETWORK,
            addr: AddrV2::Ipv4(Ipv4Addr::LOCALHOST),
            port: 8333,
        };
        for _ in 0..count {
            address
                .consensus_encode(&mut payload)
                .map_err(|error| PeerError::Io(std::io::Error::other(error.to_string())))?;
        }

        message_frame(b"addrv2", &payload)
    }

    fn locator_frame(command: &[u8], count: usize) -> Result<Vec<u8>, PeerError> {
        let count_u64 = u64::try_from(count).map_err(|_| PeerError::PayloadTooLarge(count))?;
        let mut payload = Vec::new();
        bitcoin::p2p::PROTOCOL_VERSION
            .consensus_encode(&mut payload)
            .map_err(|error| PeerError::Io(std::io::Error::other(error.to_string())))?;
        VarInt(count_u64)
            .consensus_encode(&mut payload)
            .map_err(|error| PeerError::Io(std::io::Error::other(error.to_string())))?;
        let locator = BlockHash::from_byte_array([8u8; 32]);
        for _ in 0..count {
            locator
                .consensus_encode(&mut payload)
                .map_err(|error| PeerError::Io(std::io::Error::other(error.to_string())))?;
        }
        BlockHash::all_zeros()
            .consensus_encode(&mut payload)
            .map_err(|error| PeerError::Io(std::io::Error::other(error.to_string())))?;

        message_frame(command, &payload)
    }

    fn headers_frame(count: usize) -> Result<Vec<u8>, PeerError> {
        let count_u64 = u64::try_from(count).map_err(|_| PeerError::PayloadTooLarge(count))?;
        let mut payload = Vec::new();
        VarInt(count_u64)
            .consensus_encode(&mut payload)
            .map_err(|error| PeerError::Io(std::io::Error::other(error.to_string())))?;
        let header = compact_block_header();
        for _ in 0..count {
            header
                .consensus_encode(&mut payload)
                .map_err(|error| PeerError::Io(std::io::Error::other(error.to_string())))?;
            payload.push(0);
        }

        message_frame(b"headers", &payload)
    }

    fn message_frame(command: &[u8], payload: &[u8]) -> Result<Vec<u8>, PeerError> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&Magic::BITCOIN.to_bytes());
        frame.extend_from_slice(command);
        frame.resize(16, 0);
        let payload_len =
            u32::try_from(payload.len()).map_err(|_| PeerError::PayloadTooLarge(payload.len()))?;
        frame.extend_from_slice(&payload_len.to_le_bytes());
        frame.extend_from_slice(&checksum(payload));
        frame.extend_from_slice(payload);
        Ok(frame)
    }

    fn checksum(payload: &[u8]) -> [u8; 4] {
        let first = Sha256::digest(payload);
        let second = Sha256::digest(first);
        [second[0], second[1], second[2], second[3]]
    }

    fn compact_block_header() -> Header {
        Header {
            version: Version::ONE,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 0,
            bits: CompactTarget::from_consensus(0x207fffff),
            nonce: 0,
        }
    }

    fn compact_block_transaction() -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    #[test]
    fn command_padding_rejects_non_ascii_control_and_dirty_padding() {
        let cases = [
            (
                &b"ping\0\0\0\0\0\0\0\x01"[..],
                "dirty padding after nul terminator",
            ),
            (&b"ping\n\0\0\0\0\0\0\0"[..], "control character in command"),
            (&b"ping\x1f\0\0\0\0\0\0\0"[..], "control byte below space"),
            (&b"ping\x7f\0\0\0\0\0\0\0"[..], "del byte in command"),
            (&b"ping\x80\0\0\0\0\0\0\0"[..], "non-ascii byte in command"),
            (&b"\0\0\0\0\0\0\0\0\0\0\0\0"[..], "empty command"),
        ];

        for (cmd, desc) in cases {
            let mut frame = Vec::new();
            frame.extend_from_slice(&Magic::BITCOIN.to_bytes());
            frame.extend_from_slice(cmd);
            frame.extend_from_slice(&0u32.to_le_bytes());
            frame.extend_from_slice(&checksum(&[]));

            let res = read_message(&mut Cursor::new(frame), Magic::BITCOIN);
            assert!(
                matches!(res, Err(PeerError::InvalidCommand(_))),
                "{desc} must fail with InvalidCommand, got {res:?}"
            );
        }
    }

    #[test]
    fn space_byte_in_command_name_is_a_valid_unknown_command() -> Result<(), PeerError> {
        let frame = message_frame(b"pi ng", &[])?;
        let (message, payload) = read_message(&mut Cursor::new(frame), Magic::BITCOIN)?;
        assert!(payload.is_empty());
        assert!(matches!(message, Message::Unknown { .. }));
        assert_eq!(message.command().as_ref(), "pi ng");

        let mut peer = Peer::new(Cursor::new(Vec::<u8>::new()), Magic::BITCOIN);
        let responses = dispatch_inbound(
            &mut peer,
            &Message::Version(version_message(
                1,
                0,
                PeerRole::FullRelay,
                ServiceFlags::NETWORK | ServiceFlags::WITNESS,
                bitcoin_rs_consensus::primitives::USER_AGENT,
            )),
        )?;
        assert_eq!(
            responses,
            vec![
                Message::WtxidRelay,
                Message::SendAddrV2,
                Message::SendHeaders,
                Message::Verack
            ]
        );
        dispatch_inbound(&mut peer, &Message::Verack)?;
        assert_eq!(peer.state, PeerState::Ready);

        let unknown = Message::Unknown {
            command: "pi ng"
                .parse()
                .map_err(|_| PeerError::InvalidCommand("pi ng".to_owned()))?,
            payload: Vec::new(),
        };
        let responses = dispatch_inbound(&mut peer, &unknown)?;
        assert_eq!(responses, []);
        assert_eq!(peer.state, PeerState::Ready);
        Ok(())
    }

    #[test]
    fn compact_block_counts_beyond_cores_sixteen_bit_limit_are_dropped() -> Result<(), PeerError> {
        let at_limit = u64::from(u16::MAX);

        let mut payload = Vec::new();
        compact_block_header()
            .consensus_encode(&mut payload)
            .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
        0u64.consensus_encode(&mut payload)
            .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
        VarInt(at_limit)
            .consensus_encode(&mut payload)
            .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
        for _ in 0..at_limit {
            ShortId::default()
                .consensus_encode(&mut payload)
                .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
        }
        VarInt(0)
            .consensus_encode(&mut payload)
            .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
        let frame = message_frame(b"cmpctblock", &payload)?;
        assert!(matches!(
            read_message(&mut Cursor::new(frame), Magic::BITCOIN),
            Ok((Message::CmpctBlock(_), _))
        ));

        let mut payload = Vec::new();
        compact_block_header()
            .consensus_encode(&mut payload)
            .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
        0u64.consensus_encode(&mut payload)
            .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
        VarInt(at_limit + 1)
            .consensus_encode(&mut payload)
            .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
        for _ in 0..=at_limit {
            ShortId::default()
                .consensus_encode(&mut payload)
                .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
        }
        VarInt(0)
            .consensus_encode(&mut payload)
            .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
        let frame = message_frame(b"cmpctblock", &payload)?;
        assert!(matches!(
            read_message(&mut Cursor::new(frame), Magic::BITCOIN),
            Ok((Message::Unknown { command, .. }, _)) if command.as_ref() == "cmpctblock"
        ));

        let mut payload = Vec::new();
        compact_block_header()
            .consensus_encode(&mut payload)
            .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
        0u64.consensus_encode(&mut payload)
            .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
        VarInt(0)
            .consensus_encode(&mut payload)
            .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
        VarInt(at_limit)
            .consensus_encode(&mut payload)
            .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
        let frame = message_frame(b"cmpctblock", &payload)?;
        assert!(matches!(
            read_message(&mut Cursor::new(frame), Magic::BITCOIN),
            Ok((Message::Unknown { command, .. }, _)) if command.as_ref() == "cmpctblock"
        ));

        Ok(())
    }

    #[test]
    fn compact_block_prefilled_index_beyond_the_wire_type_is_dropped() -> Result<(), PeerError> {
        let mut payload = Vec::new();
        compact_block_header()
            .consensus_encode(&mut payload)
            .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
        0u64.consensus_encode(&mut payload)
            .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
        VarInt(0)
            .consensus_encode(&mut payload)
            .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
        VarInt(1)
            .consensus_encode(&mut payload)
            .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
        VarInt(u64::from(u16::MAX) + 1)
            .consensus_encode(&mut payload)
            .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
        compact_block_transaction()
            .consensus_encode(&mut payload)
            .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
        let frame = message_frame(b"cmpctblock", &payload)?;
        assert!(matches!(
            read_message(&mut Cursor::new(frame), Magic::BITCOIN),
            Ok((Message::Unknown { command, .. }, _)) if command.as_ref() == "cmpctblock"
        ));

        Ok(())
    }

    #[test]
    fn compact_block_counts_beyond_the_payload_are_dropped() -> Result<(), PeerError> {
        let mut payload = Vec::new();
        BlockHash::all_zeros()
            .consensus_encode(&mut payload)
            .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
        VarInt(2)
            .consensus_encode(&mut payload)
            .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
        let frame = message_frame(b"blocktxn", &payload)?;
        assert!(matches!(
            read_message(&mut Cursor::new(frame), Magic::BITCOIN),
            Ok((Message::Unknown { command, .. }, _)) if command.as_ref() == "blocktxn"
        ));

        let mut payload = Vec::new();
        BlockHash::all_zeros()
            .consensus_encode(&mut payload)
            .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
        VarInt(2)
            .consensus_encode(&mut payload)
            .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
        let frame = message_frame(b"getblocktxn", &payload)?;
        assert!(matches!(
            read_message(&mut Cursor::new(frame), Magic::BITCOIN),
            Ok((Message::Unknown { command, .. }, _)) if command.as_ref() == "getblocktxn"
        ));

        Ok(())
    }

    #[test]
    fn compact_block_trailing_bytes_decode_like_core() -> Result<(), PeerError> {
        let mut payload = Vec::new();
        compact_block_header()
            .consensus_encode(&mut payload)
            .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
        0u64.consensus_encode(&mut payload)
            .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
        VarInt(1)
            .consensus_encode(&mut payload)
            .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
        ShortId::default()
            .consensus_encode(&mut payload)
            .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
        VarInt(0)
            .consensus_encode(&mut payload)
            .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
        payload.push(0x42);
        let frame = message_frame(b"cmpctblock", &payload)?;
        let Ok((Message::CmpctBlock(compact), _)) =
            read_message(&mut Cursor::new(frame), Magic::BITCOIN)
        else {
            panic!("a cmpctblock with trailing bytes must decode");
        };
        assert_eq!(compact.compact_block.short_ids.len(), 1);
        assert!(compact.compact_block.prefilled_txs.is_empty());

        let mut payload = Vec::new();
        BlockHash::all_zeros()
            .consensus_encode(&mut payload)
            .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
        VarInt(0)
            .consensus_encode(&mut payload)
            .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
        payload.push(0x42);
        let frame = message_frame(b"blocktxn", &payload)?;
        let Ok((Message::BlockTxn(txn), _)) = read_message(&mut Cursor::new(frame), Magic::BITCOIN)
        else {
            panic!("a blocktxn with trailing bytes must decode");
        };
        assert!(txn.transactions.transactions.is_empty());
        assert_eq!(txn.transactions.block_hash, BlockHash::all_zeros());

        let mut payload = Vec::new();
        BlockHash::all_zeros()
            .consensus_encode(&mut payload)
            .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
        VarInt(0)
            .consensus_encode(&mut payload)
            .map_err(|e| PeerError::Io(std::io::Error::other(e.to_string())))?;
        payload.push(0x42);
        let frame = message_frame(b"getblocktxn", &payload)?;
        let Ok((Message::GetBlockTxn(request), _)) =
            read_message(&mut Cursor::new(frame), Magic::BITCOIN)
        else {
            panic!("a getblocktxn with trailing bytes must decode");
        };
        assert!(request.txs_request.indexes.is_empty());

        Ok(())
    }

    #[test]
    fn framing_attacks_magic_checksum_and_length_boundaries() -> Result<(), PeerError> {
        let mut frame = message_frame(b"ping", &[1; 8])?;
        frame[0] ^= 0xff;
        assert!(matches!(
            read_message(&mut Cursor::new(frame), Magic::BITCOIN),
            Err(PeerError::WrongNetwork { .. })
        ));

        let mut frame = message_frame(b"ping", &[1; 8])?;
        frame[20] ^= 1;
        assert!(matches!(
            read_message(&mut Cursor::new(frame), Magic::BITCOIN),
            Err(PeerError::BadChecksum)
        ));

        let mut frame = message_frame(b"ping", &[1; 8])?;
        frame[24] ^= 1;
        assert!(matches!(
            read_message(&mut Cursor::new(frame), Magic::BITCOIN),
            Err(PeerError::BadChecksum)
        ));

        let mut header_n_minus_1 = Vec::new();
        header_n_minus_1.extend_from_slice(&Magic::BITCOIN.to_bytes());
        header_n_minus_1.extend_from_slice(b"ping\0\0\0\0\0\0\0\0");
        let len_n_minus_1 = u32::try_from(MAX_MESSAGE_PAYLOAD - 1)
            .map_err(|_| PeerError::PayloadTooLarge(usize::MAX))?;
        header_n_minus_1.extend_from_slice(&len_n_minus_1.to_le_bytes());
        header_n_minus_1.extend_from_slice(&[0u8; 4]);
        assert!(matches!(
            read_message(&mut Cursor::new(header_n_minus_1), Magic::BITCOIN),
            Err(PeerError::Io(_))
        ));

        let mut header_n = Vec::new();
        header_n.extend_from_slice(&Magic::BITCOIN.to_bytes());
        header_n.extend_from_slice(b"ping\0\0\0\0\0\0\0\0");
        let len_n = u32::try_from(MAX_MESSAGE_PAYLOAD)
            .map_err(|_| PeerError::PayloadTooLarge(usize::MAX))?;
        header_n.extend_from_slice(&len_n.to_le_bytes());
        header_n.extend_from_slice(&[0u8; 4]);
        assert!(matches!(
            read_message(&mut Cursor::new(header_n), Magic::BITCOIN),
            Err(PeerError::Io(_))
        ));

        let mut header_n_plus_1 = Vec::new();
        header_n_plus_1.extend_from_slice(&Magic::BITCOIN.to_bytes());
        header_n_plus_1.extend_from_slice(b"ping\0\0\0\0\0\0\0\0");
        let len_n_plus_1 = u32::try_from(MAX_MESSAGE_PAYLOAD + 1)
            .map_err(|_| PeerError::PayloadTooLarge(usize::MAX))?;
        header_n_plus_1.extend_from_slice(&len_n_plus_1.to_le_bytes());
        header_n_plus_1.extend_from_slice(&[0u8; 4]);
        assert!(matches!(
            read_message(&mut Cursor::new(header_n_plus_1), Magic::BITCOIN),
            Err(PeerError::PayloadTooLarge(len)) if len == MAX_MESSAGE_PAYLOAD + 1
        ));

        let partial_header = vec![0u8; 12];
        assert!(matches!(
            read_message(&mut Cursor::new(partial_header), Magic::BITCOIN),
            Err(PeerError::Io(_))
        ));

        Ok(())
    }
}
