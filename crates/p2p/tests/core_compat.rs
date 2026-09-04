//! Deterministic Bitcoin Core 31.1 P2P compatibility contract tests.
//!
//! Every assertion here pins a row of the message table in
//! `docs/policies/p2p-compatibility.md`: the version/verack handshake shape,
//! per-network magic and service bits, getheaders/headers exchange bounds,
//! inv/getdata relay round-trips, the reject-or-ignore policy for malformed
//! and unsupported messages, and the peer-visible effect of a chain switch
//! (reorg) and restart at the [`ChainQuery`] seam the node implements.

use std::error::Error;
use std::io::Cursor;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use bitcoin::hashes::Hash as _;
use bitcoin::p2p::message::CommandString;
use bitcoin::p2p::message_blockdata::{GetBlocksMessage, GetHeadersMessage, Inventory};
use bitcoin::p2p::{Magic, ServiceFlags};
use bitcoin::{BlockHash, Txid};
use bitcoin_rs_p2p::Message;
use bitcoin_rs_p2p::dispatch::{
    ChainQuery, InventoryServing, MAX_HEADERS_RESPONSE, dispatch_inbound,
    dispatch_inbound_with_chain,
};
use bitcoin_rs_p2p::handshake::{feature_messages, start, version_message};
use bitcoin_rs_p2p::inv::MAX_INV_PER_MSG;
use bitcoin_rs_p2p::listener::serve_with_shutdown;
use bitcoin_rs_p2p::wire::{
    MAX_LOCATOR_HASHES, MAX_MESSAGE_PAYLOAD, PROTOCOL_VERSION, PeerError, read_message,
    write_message,
};
use bitcoin_rs_p2p::{BannedSubnet, InboundBlock, InboundHeaders, Peer, PeerState, PeerTable};
use bitcoin_rs_primitives::{
    Block, BlockHash as NativeBlockHash, Hash256, Header, consensus_bytes,
};
use bitcoin_rs_primitives::{Network, USER_AGENT};
use hashbrown::HashMap;

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

const REGTEST_GENESIS_HEX: &str = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff7f20020000000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";
/// Convert native `BlockHash` to bitcoin `BlockHash` for envelope types.
fn btc_bh(hash: NativeBlockHash) -> BlockHash {
    BlockHash::from_byte_array(*hash.as_bytes())
}

/// Convert bitcoin `BlockHash` to native `BlockHash` for payload lookups.
fn native_bh(hash: &BlockHash) -> NativeBlockHash {
    NativeBlockHash(Hash256::from_le_bytes(hash.as_byte_array()))
}

/// `(network, Core magic, Core default P2P port)` for every supported network.
const NETWORK_TABLE: [(Network, Magic, u16); 5] = [
    (Network::Mainnet, Magic::BITCOIN, 8333),
    (Network::Testnet3, Magic::TESTNET3, 18333),
    (Network::Testnet4, Magic::TESTNET4, 48333),
    (Network::Signet, Magic::SIGNET, 38333),
    (Network::Regtest, Magic::REGTEST, 18444),
];

fn genesis_block() -> Result<Block, Box<dyn Error>> {
    let bytes = hex_decode(REGTEST_GENESIS_HEX)?;
    Ok(Block::consensus_decode(&bytes)?)
}

fn hex_decode(hex: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut chunks = hex.as_bytes().chunks_exact(2);
    if !chunks.remainder().is_empty() {
        return Err("odd hex length".into());
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for pair in &mut chunks {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex_nibble(byte: u8) -> Result<u8, Box<dyn Error>> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err("invalid hex digit".into()),
    }
}

/// Chains `count` synthetic headers onto `parent`, deterministically.
fn child_headers(parent: &Header, count: usize) -> Vec<Header> {
    let mut headers = Vec::with_capacity(count);
    let mut current = *parent;
    for _ in 0..count {
        let next = Header {
            version: 1,
            prev_blockhash: current.compute_hash(),
            merkle_root: Hash256::default(),
            time: current.time + 1,
            bits: 0x207f_ffff,
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

/// Model of the node's active-chain view at the [`ChainQuery`] seam.
///
/// Semantics mirror `NodeP2pChainQuery` in `crates/node/src/p2p_chain.rs`:
/// the first locator hash on the active chain anchors the response walk, a
/// total miss anchors after genesis, an empty locator answers only the stop
/// header, and only active-chain bodies are served (`notfound` otherwise).
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

    fn serve_inventory_blocks(
        &self,
        items: &[Inventory],
        headroom: &dyn Fn() -> bool,
        serve: &mut dyn FnMut(Block) -> Result<(), PeerError>,
    ) -> Result<InventoryServing, PeerError> {
        let mut outcome = InventoryServing::default();
        for item in items {
            let Some(hash) = inventory_hash(item) else {
                outcome.not_found.push(*item);
                continue;
            };
            let native = native_bh(&hash);
            let active = self.active_height(&native).is_some();
            let known = self
                .bodies
                .get(&native)
                .is_some_and(|block| block.block_hash() == native);
            if active && known {
                if !headroom() {
                    outcome.halted = true;
                    return Ok(outcome);
                }
                serve(self.bodies[&native].clone())?;
            } else {
                outcome.not_found.push(*item);
            }
        }
        Ok(outcome)
    }
}

fn inventory_hash(item: &Inventory) -> Option<BlockHash> {
    match item {
        Inventory::Block(hash) | Inventory::WitnessBlock(hash) => Some(*hash),
        _ => None,
    }
}

/// Collecting-sink wrapper around the streamed dispatch: responses arrive in
/// the exact order the streaming send emits them.
fn dispatch_collect(
    peer: &mut Peer<Cursor<Vec<u8>>>,
    message: &Message,
    chain: Option<&dyn ChainQuery>,
) -> Result<Vec<Message>, PeerError> {
    let collected = std::cell::RefCell::new(Vec::new());
    dispatch_inbound_with_chain(peer, message, chain, &|| true, &mut |response| {
        collected.borrow_mut().push(response);
        Ok(())
    })?;
    Ok(collected.into_inner())
}

/// Collecting form of the streaming serve for expected/actual comparisons.
fn serve_collect(
    chain: &FakeChain,
    items: &[Inventory],
) -> Result<(Vec<Block>, Vec<Inventory>), PeerError> {
    let blocks = std::cell::RefCell::new(Vec::new());
    let outcome = chain.serve_inventory_blocks(items, &|| true, &mut |block| {
        blocks.borrow_mut().push(block);
        Ok(())
    })?;
    Ok((blocks.into_inner(), outcome.not_found))
}
/// Drives an outbound handshake as if the remote peer sent `version`.
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
    Message::Version(version_message(1, 0))
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

/// Builds one raw v1 frame (magic, command, length, checksum, payload).
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

/// Asserts an outcome is the typed protocol error, returning it for inspection.
fn expect_protocol_error<T: std::fmt::Debug>(
    outcome: Result<T, PeerError>,
    why: &'static str,
) -> Result<PeerError, Box<dyn Error>> {
    match outcome {
        Err(error) => Ok(error),
        Ok(value) => Err(format!("{why}: unexpectedly succeeded with {value:?}").into()),
    }
}

// ---------------------------------------------------------------------------
// Handshake: version fields, service bits, feature negotiation
// ---------------------------------------------------------------------------

#[test]
fn version_message_pins_core_31_handshake_fields() {
    let version = version_message(0xdead_beef, 777);

    assert_eq!(version.version, PROTOCOL_VERSION);
    assert_eq!(
        u64::from(PROTOCOL_VERSION),
        70_016,
        "pinned Core 31.1 protocol version"
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
    let messages = start(&mut peer, 1, 0);

    assert_eq!(peer.state, PeerState::VersionExchange);
    assert_eq!(messages.len(), 4);
    assert!(matches!(messages.first(), Some(Message::Version(_))));
    assert_eq!(
        &messages[1..],
        &feature_messages(),
        "BIP339 wtxidrelay, BIP155 sendaddrv2, BIP130 sendheaders — Core 31 order"
    );
}

#[test]
fn remote_feature_messages_flip_negotiated_capabilities() -> Result<(), Box<dyn Error>> {
    let mut peer = ready_peer(Magic::REGTEST)?;
    assert!(!peer.capabilities.send_headers);
    assert!(!peer.capabilities.addr_v2);

    dispatch_inbound(&mut peer, &Message::SendHeaders)?;
    dispatch_inbound(&mut peer, &Message::SendAddrV2)?;
    dispatch_inbound(&mut peer, &Message::WtxidRelay)?;

    assert!(peer.capabilities.send_headers);
    assert!(peer.capabilities.addr_v2);
    assert!(peer.wtxid_relay.peer_supported());
    assert_eq!(peer.state, PeerState::Ready);
    Ok(())
}

// ---------------------------------------------------------------------------
// Network identity: magic + ports + per-network framing
// ---------------------------------------------------------------------------

#[test]
fn network_magic_and_default_ports_match_core() -> Result<(), Box<dyn Error>> {
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
fn foreign_network_frames_are_rejected_before_payload_decode() -> Result<(), Box<dyn Error>> {
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

// ---------------------------------------------------------------------------
// getheaders / headers exchange
// ---------------------------------------------------------------------------

#[test]
fn getheaders_serves_active_chain_with_stop_hash_and_limit() -> Result<(), Box<dyn Error>> {
    let genesis = genesis_block()?;
    let headers = child_headers(&genesis.header, 4);
    let chain = FakeChain::new(headers.clone(), HashMap::new());
    let mut peer = ready_peer(Magic::REGTEST)?;

    // A locator hit at height 1 serves heights 2..=tip.
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

    // Stop hash truncates the walk inclusive, like Core's getheaders.
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

    // Empty locator + known stop answers exactly the stop header (node contract).
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

    // Empty locator + zero stop answers nothing.
    let response = dispatch_collect(
        &mut peer,
        &get_headers(Vec::new(), NativeBlockHash::default()),
        Some(&chain),
    )?;
    let Some(Message::Headers(served)) = response.first() else {
        return Err("expected headers response".into());
    };
    assert!(served.is_empty());
    Ok(())
}

#[test]
fn headers_responses_truncate_at_the_core_2000_limit() -> Result<(), Box<dyn Error>> {
    let genesis = genesis_block()?;
    let headers = child_headers(&genesis.header, MAX_HEADERS_RESPONSE + 1);
    let chain = FakeChain::new(headers.clone(), HashMap::new());
    let mut peer = ready_peer(Magic::REGTEST)?;

    // Core clients send at most 101 locator hashes even on long chains.
    let response = dispatch_collect(
        &mut peer,
        &get_headers(locator_hashes(&headers[..101]), NativeBlockHash::default()),
        Some(&chain),
    )?;
    let Some(Message::Headers(served)) = response.first() else {
        return Err("expected headers response".into());
    };
    assert_eq!(served.len(), MAX_HEADERS_RESPONSE);
    assert_eq!(served.len(), 2_000, "Core 31.1 max headers per message");
    Ok(())
}

#[test]
fn oversized_getheaders_locator_disconnects_before_state_mutation() -> Result<(), Box<dyn Error>> {
    let genesis = genesis_block()?;
    let headers = child_headers(&genesis.header, 2);
    let chain = FakeChain::new(headers.clone(), HashMap::new());
    let mut peer = ready_peer(Magic::REGTEST)?;
    let locator = vec![headers[0].compute_hash(); MAX_LOCATOR_HASHES + 1];

    let error = expect_protocol_error(
        dispatch_collect(
            &mut peer,
            &get_headers(locator, NativeBlockHash::default()),
            Some(&chain),
        ),
        "Core disconnects oversized locators",
    )?;

    assert!(matches!(
        error,
        PeerError::Protocol("getheaders locator too large")
    ));
    assert_eq!(peer.state, PeerState::Ready, "rejected before FSM mutation");
    Ok(())
}

// ---------------------------------------------------------------------------
// inv / getdata / tx / block relay round-trips
// ---------------------------------------------------------------------------

#[test]
fn inv_getdata_relay_round_trip_serves_blocks_and_notfounds_misses() -> Result<(), Box<dyn Error>> {
    let genesis = genesis_block()?;
    // The active chain is genesis plus one child; only the genesis body is
    // stored, so the child resolves to notfound.
    let mut active = vec![genesis.header];
    active.extend(child_headers(&genesis.header, 1));
    let mut bodies = HashMap::new();
    bodies.insert(genesis.block_hash(), genesis.clone());
    let chain = FakeChain::new(active, bodies);
    let mut peer = ready_peer(Magic::REGTEST)?;
    // Inbound inv announcements are answered with getdata echoing the items
    // verbatim (a wtxid-relay peer announces MSG_WTX and is asked for MSG_WTX).
    let tx_inv = Inventory::Transaction(Txid::from_byte_array([9u8; 32]));
    let response = dispatch_collect(&mut peer, &Message::Inv(vec![tx_inv]), Some(&chain))?;
    assert_eq!(response, vec![Message::GetData(vec![tx_inv])]);

    // getdata over known + missing inventory serves blocks and notfounds the rest.
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
        [Message::Block(block), Message::NotFound(items)] => (block, items),
        other => return Err(format!("unexpected relay response {other:?}").into()),
    };
    assert_eq!(served.block_hash(), genesis.block_hash());
    assert_eq!(not_found, &vec![missing]);

    // The served block round-trips the wire byte-identically.
    let mut wire = Cursor::new(Vec::new());
    write_message(
        &mut wire,
        Magic::REGTEST,
        response.first().ok_or("empty relay response")?,
    )?;
    wire.set_position(0);
    let (decoded, raw) = read_message(&mut wire, Magic::REGTEST)?;
    let Message::Block(decoded_block) = decoded else {
        return Err("expected block on the wire".into());
    };
    assert_eq!(decoded_block.block_hash(), genesis.block_hash());
    assert_eq!(raw.as_ref(), consensus_bytes(&genesis).as_slice());
    Ok(())
}

#[test]
fn getdata_bound_of_50k_vectors_matches_core_max_inv() -> Result<(), Box<dyn Error>> {
    assert_eq!(MAX_INV_PER_MSG, 50_000, "Core MAX_INV_SZ");

    let genesis = genesis_block()?;
    let headers = child_headers(&genesis.header, 1);
    let chain = FakeChain::new(headers, HashMap::new());
    let mut peer = ready_peer(Magic::REGTEST)?;
    let items = vec![Inventory::Transaction(Txid::from_byte_array([1u8; 32])); MAX_INV_PER_MSG + 1];

    let error = expect_protocol_error(
        dispatch_collect(&mut peer, &Message::GetData(items), Some(&chain)),
        "Core disconnects oversized getdata",
    )?;
    assert!(matches!(
        error,
        PeerError::Protocol("getdata inventory too large")
    ));
    Ok(())
}

#[test]
fn inbound_block_and_tx_messages_decode_and_leave_no_response() -> Result<(), Box<dyn Error>> {
    let genesis = genesis_block()?;
    let mut peer = ready_peer(Magic::REGTEST)?;

    let responses = dispatch_inbound(&mut peer, &Message::Block(genesis.clone()))?;
    assert!(responses.is_empty());

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

// ---------------------------------------------------------------------------
// Malformed / unsupported messages: reject-or-ignore policy
// ---------------------------------------------------------------------------

#[test]
fn malformed_frames_reject_with_typed_errors() -> Result<(), Box<dyn Error>> {
    let magic = Magic::REGTEST;

    // Corrupted checksum is a hard disconnect, like Core.
    let mut frame = raw_frame(magic, b"ping\0\0\0\0\0\0\0\0", &7u64.to_le_bytes());
    let last = frame.len() - 1;
    frame[last] ^= 0xff;
    assert!(matches!(
        read_message(&mut Cursor::new(frame), magic),
        Err(PeerError::BadChecksum)
    ));

    // Declared length beyond 32 MiB rejects before reading a payload.
    let mut oversized = Vec::new();
    oversized.extend_from_slice(&magic.to_bytes());
    oversized.extend_from_slice(b"ping\0\0\0\0\0\0\0\0");
    oversized.extend_from_slice(&u32::try_from(MAX_MESSAGE_PAYLOAD + 1)?.to_le_bytes());
    oversized.extend_from_slice(&[0u8; 4]);
    assert!(matches!(
        read_message(&mut Cursor::new(oversized), magic),
        Err(PeerError::PayloadTooLarge(_))
    ));

    // Garbage after the command NUL terminator rejects the header.
    let mut command = [0u8; 12];
    command[..4].copy_from_slice(b"inv\0");
    command[4..].copy_from_slice(b"garbage!");
    let frame = raw_frame(magic, &command, &[]);
    assert!(matches!(
        read_message(&mut Cursor::new(frame), magic),
        Err(PeerError::InvalidCommand(_))
    ));

    // Structurally malformed payload (truncated ping nonce) rejects the decode.
    let frame = raw_frame(magic, b"ping\0\0\0\0\0\0\0\0", &[1u8, 2, 3, 4]);
    assert!(matches!(
        read_message(&mut Cursor::new(frame), magic),
        Err(PeerError::Encode(_))
    ));
    Ok(())
}

#[test]
fn messages_before_handshake_disconnect_like_core() -> Result<(), Box<dyn Error>> {
    let mut fresh = Peer::new(Cursor::new(Vec::<u8>::new()), Magic::REGTEST);
    let error = expect_protocol_error(
        dispatch_inbound(&mut fresh, &Message::Ping(7)),
        "Core drops non-handshake traffic pre-verack",
    )?;
    assert!(matches!(
        error,
        PeerError::Protocol("message received before handshake completed")
    ));

    let mut fresh = Peer::new(Cursor::new(Vec::<u8>::new()), Magic::REGTEST);
    let error = expect_protocol_error(
        dispatch_inbound(&mut fresh, &Message::Verack),
        "verack must follow version",
    )?;
    assert!(matches!(
        error,
        PeerError::Protocol("verack received before version")
    ));

    let mut ready = ready_peer(Magic::REGTEST)?;
    let error = expect_protocol_error(
        dispatch_inbound(&mut ready, &version_for_handshake()),
        "duplicate version after ready",
    )?;
    assert!(matches!(
        error,
        PeerError::Protocol("duplicate version message")
    ));
    Ok(())
}

#[test]
fn unknown_commands_are_ignored_once_ready_like_core() -> Result<(), Box<dyn Error>> {
    let mut peer = ready_peer(Magic::REGTEST)?;

    // Core 31 may announce BIP330 sendtxrcncl; we have no decoder for it, so it
    // decodes as Unknown and is ignored while ready (Core ignores unknowns too).
    let command = "sendtxrcncl".parse::<CommandString>()?;
    let responses = dispatch_inbound(
        &mut peer,
        &Message::Unknown {
            command,
            payload: vec![0u8; 8],
        },
    )?;
    assert!(responses.is_empty());
    assert_eq!(
        peer.state,
        PeerState::Ready,
        "unknown commands never disconnect a ready peer"
    );
    Ok(())
}

#[test]
fn decode_only_messages_are_accepted_silently_per_policy() -> Result<(), Box<dyn Error>> {
    let genesis = genesis_block()?;
    let headers = child_headers(&genesis.header, 1);
    let chain = FakeChain::new(headers, HashMap::new());
    let mut peer = ready_peer(Magic::REGTEST)?;

    // getblocks: legacy locator request; Core answers with inv, we stay silent.
    let responses = dispatch_collect(
        &mut peer,
        &Message::GetBlocks(GetBlocksMessage::new(
            vec![btc_bh(genesis.block_hash())],
            BlockHash::all_zeros(),
        )),
        Some(&chain),
    )?;
    assert!(responses.is_empty());

    // BIP35 mempool snapshot request: accepted, unanswered (documented deviation).
    let responses = dispatch_inbound(&mut peer, &Message::MemPool)?;
    assert!(responses.is_empty());

    // getaddr: accepted, unanswered (no address gossip).
    let responses = dispatch_inbound(&mut peer, &Message::GetAddr)?;
    assert!(responses.is_empty());

    // BIP133 feefilter: accepted, never enforced or echoed.
    let responses = dispatch_inbound(&mut peer, &Message::FeeFilter(1_000))?;
    assert!(responses.is_empty());

    assert_eq!(peer.state, PeerState::Ready);
    Ok(())
}

// ---------------------------------------------------------------------------
// Reorg / restart peer-visible behavior at the ChainQuery seam
// ---------------------------------------------------------------------------

/// Shared prefix plus its two competing extensions.
type ForkBranches = (Vec<Header>, Vec<Header>, Vec<Header>);

/// Builds a shared prefix plus two competing extensions, like a node that has
/// stored headers from both fork attempts.
fn fork_fixture() -> Result<ForkBranches, Box<dyn Error>> {
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
fn reorg_switches_which_chain_a_peer_sees() -> Result<(), Box<dyn Error>> {
    let (shared, branch_a, branch_b) = fork_fixture()?;
    let mut active = shared.clone();
    active.extend(branch_a.iter().copied());

    let mut bodies = headers_into_blocks(&shared);
    bodies.extend(headers_into_blocks(&branch_a));
    bodies.extend(headers_into_blocks(&branch_b));

    let mut state = FakeChain::new(active.clone(), bodies);
    let mut peer = ready_peer(Magic::REGTEST)?;

    // Before the reorg: a locator anchored at the stale tip has nothing newer.
    // The fallback entry is the common ancestor (the fork point itself).
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

    // The reorg: the active branch flips to B over the same shared prefix.
    let mut active_b = shared;
    active_b.extend(branch_b.iter().copied());
    state = FakeChain::new(active_b, state.bodies);

    // The stale-fork locator misses; the shared-prefix entry anchors the walk,
    // so the peer now receives branch B's headers from the fork point.
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

    // Stale-fork bodies become notfound; new-chain bodies are served.
    // Responses emit served blocks first, then one notfound for the misses —
    // the same shape streamed serving produces for any getdata.
    let response = dispatch_collect(
        &mut peer,
        &Message::GetData(vec![
            Inventory::Block(btc_bh(branch_a[0].compute_hash())),
            Inventory::Block(btc_bh(branch_b[0].compute_hash())),
        ]),
        Some(&state),
    )?;
    match response.as_slice() {
        [Message::Block(block), Message::NotFound(items)] => {
            assert_eq!(block.block_hash(), branch_b[0].compute_hash());
            assert_eq!(
                items,
                &vec![Inventory::Block(btc_bh(branch_a[0].compute_hash()))]
            );
        }
        other => return Err(format!("unexpected post-reorg relay response {other:?}").into()),
    }
    Ok(())
}

#[test]
fn restart_rebuild_serves_identical_answers_to_peers() -> Result<(), Box<dyn Error>> {
    let genesis = genesis_block()?;
    let headers = child_headers(&genesis.header, 3);
    let mut bodies = headers_into_blocks(&headers);
    bodies.insert(genesis.block_hash(), genesis.clone());

    let before = FakeChain::new(headers.clone(), bodies.clone());
    let queries: [Vec<NativeBlockHash>; 3] = [
        vec![headers[0].compute_hash()],
        locator_hashes(&headers),
        Vec::new(),
    ];
    let stops = [NativeBlockHash::default(), headers[2].compute_hash()];

    let mut cases = Vec::new();
    for locator in &queries {
        for stop in stops {
            cases.push((locator.clone(), stop));
        }
    }
    let expected: Vec<(Vec<Header>, Vec<Header>)> = cases
        .iter()
        .map(|(locator, stop)| {
            (
                before.headers_after(locator, *stop, MAX_HEADERS_RESPONSE),
                before.headers_after(locator, *stop, 1),
            )
        })
        .collect();
    let inventory = vec![
        Inventory::Block(btc_bh(genesis.block_hash())),
        Inventory::Block(btc_bh(headers[1].compute_hash())),
        Inventory::Transaction(Txid::from_byte_array([3u8; 32])),
    ];
    let (expected_blocks, expected_missing) = serve_collect(&before, &inventory)?;

    // Restart: a fresh query rebuilt from the same persisted records must
    // answer identically — a peer cannot see the restart.
    let after = FakeChain::new(headers, bodies);
    for ((locator, stop), (wide, narrow)) in cases.iter().zip(&expected) {
        assert_eq!(
            after.headers_after(locator, *stop, MAX_HEADERS_RESPONSE),
            *wide
        );
        assert_eq!(after.headers_after(locator, *stop, 1), *narrow);
    }
    let (actual_blocks, actual_missing) = serve_collect(&after, &inventory)?;
    assert_eq!(actual_blocks, expected_blocks);
    assert_eq!(actual_missing, expected_missing);
    Ok(())
}

// ---------------------------------------------------------------------------
// Live listener: per-network handshake over real TCP
// ---------------------------------------------------------------------------

#[test]
fn handshake_completes_over_tcp_for_every_network() -> Result<(), Box<dyn Error>> {
    for (network, magic, _) in NETWORK_TABLE {
        serve_and_handshake_over_tcp(network, magic)?;
    }
    Ok(())
}

fn serve_and_handshake_over_tcp(network: Network, magic: Magic) -> Result<(), Box<dyn Error>> {
    let helper = std::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let addr = helper.local_addr()?;
    drop(helper);

    let shutdown = Arc::new(AtomicBool::new(false));
    let listener_shutdown = Arc::clone(&shutdown);
    let network_active = Arc::new(AtomicBool::new(true));
    let listener_network_active = Arc::clone(&network_active);
    let peer_table = Arc::new(PeerTable::new());
    let (headers_tx, _headers_rx) = crossbeam_channel::unbounded::<InboundHeaders>();
    let (blocks_tx, _blocks_rx) = crossbeam_channel::unbounded::<InboundBlock>();
    let banned = Arc::new(parking_lot::RwLock::new(Vec::<BannedSubnet>::new()));

    let handle = thread::spawn(move || {
        serve_with_shutdown(
            addr,
            listener_shutdown,
            listener_network_active,
            magic,
            peer_table,
            headers_tx,
            blocks_tx,
            banned,
        )
    });

    let client = match connect_with_retry(addr) {
        Ok(client) => client,
        Err(error) => {
            shutdown.store(true, Ordering::Relaxed);
            let _ = handle.join();
            return Err(error);
        }
    };
    let outcome = drive_handshake_as_core(client, magic, network);
    shutdown.store(true, Ordering::Relaxed);
    let listener_result = handle.join().map_err(|_| "listener thread panicked")?;
    listener_result?;
    outcome
}

fn connect_with_retry(addr: SocketAddr) -> Result<TcpStream, Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match TcpStream::connect_timeout(&addr, Duration::from_millis(200)) {
            Ok(stream) => return Ok(stream),
            Err(error) if Instant::now() < deadline => {
                let _ = error;
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error.into()),
        }
    }
}

/// Acts as a Core 31.1 client: sends `version`, consumes the negotiated
/// feature set + `verack`, completes the handshake, then pings.
fn drive_handshake_as_core(
    mut client: TcpStream,
    magic: Magic,
    network: Network,
) -> Result<(), Box<dyn Error>> {
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
                assert_eq!(version.services, version_message(0, 0).services);
            }
            Message::WtxidRelay => saw_features[0] = true,
            Message::SendAddrV2 => saw_features[1] = true,
            Message::SendHeaders => saw_features[2] = true,
            Message::Verack => saw_verack = true,
            other => return Err(format!("unexpected handshake message {other:?}").into()),
        }
    }

    write_message(&mut client, magic, &Message::Verack)?;

    // Post-handshake service: ping is answered with an echoing pong.
    write_message(&mut client, magic, &Message::Ping(0xfeed_face))?;
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if Instant::now() > deadline {
            return Err(format!("pong for ping never arrived on {network:?}").into());
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
                assert_eq!(nonce, 0xfeed_face);
                break;
            }
            Message::Ping(_) => continue,
            other => return Err(format!("unexpected post-handshake message {other:?}").into()),
        }
    }
    Ok(())
}
