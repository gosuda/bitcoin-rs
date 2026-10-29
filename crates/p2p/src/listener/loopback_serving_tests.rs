use bitcoin_rs_primitives::PeerEndpoint;
use std::io;
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use bitcoin::bip152::ShortId;
use bitcoin::blockdata::block::Block as RegistryBlock;
use bitcoin::hashes::Hash as _;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin_rs_chain::{
    BlockBodyReadError, BlockBodySource, BlockTree, BlockTreeReader, NodeStatus, TipReader,
};
use bitcoin_rs_primitives::{
    Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, Network, OutPoint,
    Sequence, Tx, TxIn, TxOut, Txid, Witness, consensus_bytes,
};
use parking_lot::RwLock;

use super::getdata_pause_tests::{FAILSAFE, MAGIC, TestResult, wait_until, wire_len_of};
use super::{
    ListenerError, bind_listener, configure_peer_stream, run_outbound_handshake, serve, test_shared,
};
use crate::connection::{Refusal, SHARED_OUTBOUND_QUEUE_MAX_BYTES, SharedOutboundBudget};
use crate::inv::{MAX_INV_PER_MSG, wire_block_hash};
use crate::{
    ActiveChainQuery, ChainQuery, Message, Peer, PeerCounters, PeerError, PeerLease, PeerSession,
    PeerTable, RecentBlockSlot,
};

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

type Frame = (Message, bytes::Bytes);

const HOG_OUTPUTS: usize = 30_000;

const QUIET_POLLS: u32 = 40;

fn coinbase(tag: u8, outputs: usize) -> Tx {
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: vec![tag, tag].into(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![
            TxOut {
                value: Amount::from_sat(0),
                script_pubkey: p2pkh(tag).into(),
            };
            outputs
        ],
        lock_time: LockTime::ZERO,
    }
}

fn payment(tag: u8) -> Tx {
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from(Hash256::from_le_bytes(&[tag; 32])),
                vout: 0,
            },
            script_sig: vec![tag].into(),
            sequence: Sequence::MAX,
            witness: Witness::from_stack(vec![vec![tag; 32]]),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: p2pkh(tag).into(),
        }],
        lock_time: LockTime::ZERO,
    }
}

fn p2pkh(tag: u8) -> Vec<u8> {
    let mut script = vec![0x76, 0xa9, 0x14];
    script.extend_from_slice(&[tag; 20]);
    script.extend_from_slice(&[0x88, 0xac]);
    script
}

fn registry_block(block: &Block) -> Result<RegistryBlock, bitcoin::consensus::encode::Error> {
    bitcoin::consensus::encode::deserialize::<RegistryBlock>(&consensus_bytes(block))
}

fn child_block(prev_blockhash: BlockHash, nonce: u32, txs: Vec<Tx>) -> Fallible<Block> {
    let mut leaves: Vec<[u8; 32]> = txs.iter().map(|tx| *tx.txid().as_bytes()).collect();
    let root = bitcoin_rs_consensus::compute_merkle_root(&mut leaves)
        .ok_or("a fixture block holds a transaction")?;
    let block = Block {
        header: Header {
            version: 1,
            prev_blockhash,
            merkle_root: Hash256::from_le_bytes(&root),
            time: nonce,
            bits: CompactTarget::from_consensus(bitcoin_rs_chain::regtest_fixture::REGTEST_BITS),
            nonce,
        },
        txs,
    };
    if !registry_block(&block)?.check_merkle_root() {
        return Err("the fixture's merkle root is not the wire decoder's".into());
    }
    Ok(block)
}

struct StoredBodies(Vec<(u32, BlockHash, Vec<u8>)>);

impl BlockBodySource for StoredBodies {
    fn block_body(
        &self,
        height: u32,
        hash: BlockHash,
    ) -> Result<Option<Vec<u8>>, BlockBodyReadError> {
        Ok(self
            .0
            .iter()
            .find(|(stored_height, stored_hash, _)| {
                *stored_height == height && *stored_hash == hash
            })
            .map(|(_, _, body)| body.clone()))
    }
}

fn chain_over(blocks: &[Block], recent: RecentBlockSlot) -> Fallible<ActiveChainQuery> {
    let mut tree = BlockTree::new();
    let mut parent = None;
    let mut bodies = Vec::with_capacity(blocks.len());
    for (height, block) in blocks.iter().enumerate() {
        parent = Some(tree.insert_node(parent, block.header, NodeStatus::Active)?);
        bodies.push((
            u32::try_from(height)?,
            block.block_hash(),
            consensus_bytes(block),
        ));
    }
    let block_tree = BlockTreeReader::new(Arc::new(RwLock::new(tree)));
    let applied_tip = TipReader::new(Arc::new(arc_swap::ArcSwapOption::empty()));
    applied_tip.store(block_tree.read().tip());
    Ok(
        ActiveChainQuery::new(block_tree, applied_tip, Network::Regtest)
            .with_block_body_source(Arc::new(StoredBodies(bodies)))
            .with_recent_block(recent),
    )
}

struct Node {
    addr: PeerEndpoint,
    table: Arc<PeerTable>,
    aggregate: Arc<SharedOutboundBudget>,
    shutdown: Arc<AtomicBool>,
    listener: Option<JoinHandle<Result<(), ListenerError>>>,
}

impl Node {
    fn start(chain: ActiveChainQuery) -> Fallible<Self> {
        let table = Arc::new(PeerTable::new());
        let mut shared = test_shared(
            Arc::clone(&table),
            crossbeam_channel::unbounded().0,
            crossbeam_channel::unbounded().0,
        );
        shared.chain_query = Some(Arc::new(chain));
        let aggregate = Arc::clone(&shared.shared_outbound);
        let listener = bind_listener(
            PeerEndpoint::from(([127, 0, 0, 1], 0))
                .socket_addr()
                .unwrap_or_else(|| panic!("expected IP fixture")),
        )?;
        let addr = listener.local_addr()?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&shutdown);
        let thread = std::thread::spawn(move || serve(listener, flag, shared));
        Ok(Self {
            addr: addr.into(),
            table,
            aggregate,
            shutdown,
            listener: Some(thread),
        })
    }

    fn request_stop(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.table.cancel_all();
    }

    fn join_listener(&mut self) -> TestResult {
        let Some(thread) = self.listener.take() else {
            return Ok(());
        };
        let deadline = Instant::now() + FAILSAFE;
        while !thread.is_finished() {
            if Instant::now() >= deadline {
                self.listener = Some(thread);
                return Err("the listener did not stop within the failsafe".into());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let served = thread.join().map_err(|_| "the listener thread panicked")?;
        served?;
        Ok(())
    }

    fn finish(mut self) -> TestResult {
        self.request_stop();
        self.join_listener()?;
        wait_until("every session to leave the peer table", || {
            self.table.sessions().is_empty()
        })
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.request_stop();
        let _ = self.join_listener();
    }
}

struct Client {
    peer: Peer<TcpStream>,
    local: PeerEndpoint,
    nonce: u64,
}

impl Client {
    fn connect(node: &Node) -> Fallible<Self> {
        let stream = TcpStream::connect(
            node.addr
                .socket_addr()
                .unwrap_or_else(|| panic!("expected IP fixture")),
        )?;
        configure_peer_stream(&stream)?;
        let local = stream.local_addr()?;
        let mut peer = Peer::new(stream, MAGIC);
        let lease = PeerLease::new(crossbeam_channel::unbounded().0);
        let own = test_shared(
            Arc::new(PeerTable::new()),
            crossbeam_channel::unbounded().0,
            crossbeam_channel::unbounded().0,
        );
        run_outbound_handshake(
            &mut peer,
            u64::from(local.port()),
            0,
            &lease,
            Instant::now() + FAILSAFE,
            node.addr,
            &own,
        )?;
        let mut client = Self {
            peer,
            local: local.into(),
            nonce: 0,
        };
        let barrier = client.ping()?;
        client.read_through_pong(barrier)?;
        Ok(client)
    }

    fn send(&mut self, message: &Message) -> Fallible<()> {
        self.peer.send(message)?;
        Ok(())
    }

    fn ping(&mut self) -> Fallible<u64> {
        self.nonce += 1;
        let nonce = self.nonce;
        self.send(&Message::Ping(nonce))?;
        Ok(nonce)
    }

    fn frame(&mut self, deadline: Instant) -> Fallible<Frame> {
        loop {
            if Instant::now() >= deadline {
                return Err("no message arrived before the failsafe deadline".into());
            }
            match self.peer.read_message() {
                Ok(Some(frame)) => return Ok(frame),
                Ok(None) => {}
                Err(PeerError::Io(error))
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) => {}
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn read_frames(&mut self, count: usize) -> Fallible<Vec<Frame>> {
        let deadline = Instant::now() + FAILSAFE;
        (0..count).map(|_| self.frame(deadline)).collect()
    }

    fn read_through_pong(&mut self, nonce: u64) -> Fallible<Vec<Frame>> {
        let deadline = Instant::now() + FAILSAFE;
        let mut before = Vec::new();
        loop {
            let frame = self.frame(deadline)?;
            if frame.0 == Message::Pong(nonce) {
                return Ok(before);
            }
            before.push(frame);
        }
    }

    fn request(&mut self, items: Vec<Inventory>) -> Fallible<Vec<Frame>> {
        self.send(&Message::GetData(items))?;
        let nonce = self.ping()?;
        self.read_through_pong(nonce)
    }
}

fn messages_of(frames: Vec<Frame>) -> Vec<Message> {
    frames.into_iter().map(|(message, _)| message).collect()
}

fn session_of(node: &Node, client: &Client) -> Fallible<PeerSession> {
    let mut found = None;
    wait_until("the node to publish the client's session", || {
        found = node.table.sessions().into_iter().find(|session| {
            session.addr == crate::PeerRemote::Endpoint(client.local) && session.info.is_some()
        });
        found.is_some()
    })?;
    found.ok_or_else(|| "the client's session vanished".into())
}

fn counters_of(session: &PeerSession) -> Fallible<Arc<PeerCounters>> {
    Ok(Arc::clone(
        &session
            .info
            .as_ref()
            .ok_or("the session published no metadata")?
            .counters,
    ))
}

#[test]
fn a_held_block_answers_a_negotiated_compact_getdata_over_a_real_socket() -> TestResult {
    let genesis = child_block(BlockHash::default(), 0, vec![coinbase(0, 1)])?;
    let tip = child_block(genesis.block_hash(), 1, vec![coinbase(1, 1), payment(1)])?;
    let held = Arc::new(child_block(
        tip.block_hash(),
        2,
        vec![coinbase(2, 1), payment(2)],
    )?);
    let held_hash = held.block_hash();
    let slot = RecentBlockSlot::default();
    slot.store(Hash256::from(held_hash), Arc::clone(&held));
    let chain = chain_over(&[genesis, tip], slot)?;
    assert_eq!(
        chain.active_height(held_hash),
        None,
        "the held block is in no tree node"
    );

    let node = Node::start(chain)?;
    let mut client = Client::connect(&node)?;

    let compact = Inventory::CompactBlock(wire_block_hash(held_hash));
    let messages = messages_of(client.request(vec![compact])?);
    let [Message::CmpctBlock(cmpct)] = messages.as_slice() else {
        return Err(format!(
            "a negotiated compact getdata for the held block must yield one cmpctblock \
             before the pong and no notfound, got {messages:?}"
        )
        .into());
    };

    let registry = registry_block(&held)?;
    assert_eq!(registry.block_hash(), wire_block_hash(held_hash));
    let sent = &cmpct.compact_block;
    assert_eq!(sent.header, registry.header, "the held block's header");
    let [coinbase_tx, payment_tx] = registry.txdata.as_slice() else {
        return Err("the held fixture holds a coinbase and one payment".into());
    };
    let [prefilled] = sent.prefilled_txs.as_slice() else {
        return Err("only the coinbase is prefilled".into());
    };
    assert_eq!(prefilled.idx, 0);
    assert_eq!(&prefilled.tx, coinbase_tx);
    assert_ne!(
        payment_tx.compute_txid().to_byte_array(),
        payment_tx.compute_wtxid().to_byte_array(),
        "the payment fixture carries a witness, so txid and wtxid must differ"
    );
    let keys = ShortId::calculate_siphash_keys(&sent.header, sent.nonce);
    assert_eq!(
        sent.short_ids,
        vec![ShortId::with_siphash_keys(
            &payment_tx.compute_wtxid().to_byte_array(),
            keys
        )],
        "version 2 short ids are keyed by wtxid"
    );

    for item in [
        Inventory::Block(wire_block_hash(held_hash)),
        Inventory::WitnessBlock(wire_block_hash(held_hash)),
    ] {
        let messages = messages_of(client.request(vec![item])?);
        assert_eq!(
            messages,
            vec![Message::NotFound(vec![item])],
            "a full request must not use the held body"
        );
    }

    let again = messages_of(client.request(vec![compact])?);
    assert!(
        matches!(again.as_slice(), [Message::CmpctBlock(_)]),
        "the held body answers again, got {again:?}"
    );

    drop(client);
    node.finish()
}

fn saturate(
    node: &Node,
    hog: &mut Client,
    hog_session: &PeerSession,
    victim_session: &PeerSession,
    frame_len: usize,
    item: Inventory,
) -> Fallible<(usize, usize)> {
    let requested = SHARED_OUTBOUND_QUEUE_MAX_BYTES.div_ceil(frame_len) * 2 + 1;
    if requested > MAX_INV_PER_MSG {
        return Err(format!("{requested} frames exceed one getdata").into());
    }
    let budget = hog_session.lease.budget_handle();
    let counters = counters_of(hog_session)?;
    hog.send(&Message::GetData(vec![item; requested]))?;

    let mut last = None;
    let mut quiet = 0_u32;
    let mut queued = (0, 0);
    wait_until("the hog's frames to saturate the node aggregate", || {
        let (messages, bytes) = budget.pending();
        let snapshot = (messages, bytes, counters.bytes_sent());
        let saturated = messages > 0
            && bytes == messages * frame_len
            && node.aggregate.pending() == bytes
            && victim_session.lease.try_reserve_production().err() == Some(Refusal::Shared);
        quiet = if saturated && last == Some(snapshot) {
            quiet + 1
        } else {
            0
        };
        last = saturated.then_some(snapshot);
        queued = (messages, bytes);
        quiet >= QUIET_POLLS
    })?;
    Ok(queued)
}

#[test]
fn getblocktxn_survives_shared_saturation_without_resending() -> TestResult {
    use bitcoin::bip152::BlockTransactionsRequest;
    use bitcoin::p2p::message_compact_blocks::GetBlockTxn;
    let genesis = child_block(BlockHash::default(), 0, vec![coinbase(0, 1)])?;
    let hog_block = child_block(genesis.block_hash(), 1, vec![coinbase(1, HOG_OUTPUTS)])?;
    let victim_block = child_block(hog_block.block_hash(), 2, vec![coinbase(2, 1), payment(2)])?;
    let frame_len = wire_len_of(&Message::BlockPayload(consensus_bytes(&hog_block).into()))?;
    let request = Message::GetBlockTxn(GetBlockTxn {
        txs_request: BlockTransactionsRequest {
            block_hash: wire_block_hash(victim_block.block_hash()),
            indexes: vec![1],
        },
    });
    let hog_item = Inventory::WitnessBlock(wire_block_hash(hog_block.block_hash()));
    let blocks = [genesis, hog_block, victim_block];
    let node = Node::start(chain_over(&blocks, RecentBlockSlot::default())?)?;
    let mut victim = Client::connect(&node)?;
    let victim_session = session_of(&node, &victim)?;
    victim.send(&request)?;
    let nonce = victim.ping()?;
    let baseline = victim.read_through_pong(nonce)?;
    assert!(matches!(baseline.as_slice(), [(Message::BlockTxn(_), _)]));
    let mut hog = Client::connect(&node)?;
    let hog_session = session_of(&node, &hog)?;
    wait_until("handshake credits returned", || {
        node.aggregate.pending() == 0
    })?;
    let queued = saturate(
        &node,
        &mut hog,
        &hog_session,
        &victim_session,
        frame_len,
        hog_item,
    )?;
    let budget = victim_session.lease.budget_handle();
    let before_refusals = budget.refusals();
    let started = Instant::now();
    victim.send(&request)?;
    wait_until("getblocktxn deferred on reservation refusal", || {
        budget.refusals() > before_refusals
    })?;
    println!(
        "C saturated queued={queued:?} shared={} victim_pending={:?} refusals={} elapsed_ms={}",
        node.aggregate.pending(),
        budget.pending(),
        budget.refusals(),
        started.elapsed().as_millis()
    );
    drop(hog);
    wait_until("hog credit returned", || {
        hog_session.lease.budget_handle().pending() == (0, 0)
    })?;
    let nonce = victim.ping()?;
    let received = victim.read_through_pong(nonce)?;
    println!(
        "C recovered replies={} elapsed_ms={} messages={:?}",
        received.len(),
        started.elapsed().as_millis(),
        messages_of(received.clone())
    );
    assert!(
        matches!(received.as_slice(), [(Message::BlockTxn(_), _)]),
        "the original request must be answered once after recovery"
    );
    drop(victim);
    node.finish()
}

#[test]
fn the_saturated_aggregate_refuses_a_second_connection_until_the_first_closes() -> TestResult {
    let genesis = child_block(BlockHash::default(), 0, vec![coinbase(0, 1)])?;
    let hog_block = child_block(genesis.block_hash(), 1, vec![coinbase(1, HOG_OUTPUTS)])?;
    let victim_block = child_block(hog_block.block_hash(), 2, vec![coinbase(2, 1), payment(2)])?;
    let hog_item = Inventory::WitnessBlock(wire_block_hash(hog_block.block_hash()));
    let victim_item = Inventory::WitnessBlock(wire_block_hash(victim_block.block_hash()));
    let missing = Inventory::WitnessBlock(bitcoin::BlockHash::from_byte_array([0xee; 32]));
    let frame_len = wire_len_of(&Message::BlockPayload(bytes::Bytes::from(consensus_bytes(
        &hog_block,
    ))))?;
    let victim_payload = consensus_bytes(&victim_block);
    let blocks = [genesis, hog_block, victim_block];
    let chain = chain_over(&blocks, RecentBlockSlot::default())?;

    let node = Node::start(chain)?;
    let mut victim = Client::connect(&node)?;
    let victim_session = session_of(&node, &victim)?;
    let mut hog = Client::connect(&node)?;
    let hog_session = session_of(&node, &hog)?;
    wait_until("the handshakes' frames to release the aggregate", || {
        node.aggregate.pending() == 0
    })?;

    let (hog_messages, hog_bytes) = saturate(
        &node,
        &mut hog,
        &hog_session,
        &victim_session,
        frame_len,
        hog_item,
    )?;
    assert!(hog_messages > 1, "the aggregate holds several real frames");

    let reserve = crate::wire::HEADER_LEN + crate::peer::MAX_BLOCK_SERIALIZED_SIZE_USIZE;
    let bulk_limit = SHARED_OUTBOUND_QUEUE_MAX_BYTES - reserve;
    let refusal_point = bulk_limit - reserve;
    assert!(
        hog_bytes > refusal_point && hog_bytes <= refusal_point + frame_len,
        "the hog's {hog_bytes} queued bytes are not the first fill past {refusal_point}"
    );

    let victim_counters = counters_of(&victim_session)?;
    let written_before = victim_counters.bytes_sent();
    victim.send(&Message::GetData(vec![missing, victim_item]))?;

    let first = messages_of(victim.read_frames(1)?);
    let miss_reply = Message::NotFound(vec![missing]);
    let missed_len = u64::try_from(wire_len_of(&miss_reply)?)?;
    assert_eq!(
        first,
        vec![miss_reply],
        "a refused body parks behind the miss instead of reaching the wire first"
    );
    assert_eq!(
        victim_session.lease.try_reserve_production().err(),
        Some(Refusal::Shared),
        "the victim's own reservation is refused by the aggregate, not by its empty queue"
    );
    wait_until("the victim's notfound to be counted as written", || {
        victim_counters.bytes_sent() >= written_before + missed_len
    })?;
    assert_eq!(
        victim_counters.bytes_sent(),
        written_before + missed_len,
        "only the notfound was written to the victim: its body waits for the aggregate"
    );
    assert!(
        !victim_session.lease.is_cancelled() && !hog_session.lease.is_cancelled(),
        "the aggregate's refusal never disconnects"
    );

    let nonce = victim.ping()?;

    let hog_budget = hog_session.lease.budget_handle();
    drop(hog);
    wait_until("the closed hog's writer to end", || {
        hog_budget.writer_dead()
    })?;
    wait_until("every frame credit of the closed hog to return", || {
        hog_budget.pending() == (0, 0)
    })?;

    let delivered = victim.read_through_pong(nonce)?;
    let [(Message::Block(block), raw)] = delivered.as_slice() else {
        let received: Vec<&Message> = delivered.iter().map(|(message, _)| message).collect();
        return Err(format!("the victim's body must precede its pong, got {received:?}").into());
    };
    assert_eq!(block.block(), &blocks[2]);
    assert_eq!(&raw[..], victim_payload.as_slice());
    wait_until("the aggregate to drain once the victim was served", || {
        node.aggregate.pending() == 0
    })?;
    assert!(!victim_session.lease.is_cancelled());

    drop(victim);
    node.finish()
}
