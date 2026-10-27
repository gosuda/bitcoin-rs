//! A saturated outbound queue parks a `getdata` tail instead of disconnecting
//! the peer: the session reads nothing until the writer drains, answers in
//! request order, and ends when the writer dies or the lease is cancelled.

use std::io::{self, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use bitcoin::bip152::BlockTransactionsRequest;
use bitcoin::hashes::Hash as _;
use bitcoin::p2p::Magic;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin_rs_primitives::{
    Amount, Block, BlockHash, Hash256, Header, LockTime, OutPoint, Sequence, Tx, TxIn, TxOut, Txid,
    Witness, Wtxid,
};
use crossbeam_channel::{Receiver, Sender};

use super::{
    ConnectionShared, Keepalive, ParkedStep, TIMEOUT_INTERVAL, WriterExit, configure_peer_stream,
    parked_tail_expired, run_message_loop, run_writer_loop, spawn_connection_writer,
    step_parked_getdata, test_shared,
};
use crate::connection::{OutboundBudget, SharedOutboundBudget};
use crate::transport::SendTransport;
use crate::{
    ChainQuery, InventoryServing, Message, Peer, PeerError, PeerLease, PeerState, PeerTable,
    TxInventory,
};

pub(super) type TestResult = Result<(), Box<dyn std::error::Error>>;

pub(super) const MAGIC: Magic = Magic::BITCOIN;

/// Longest any test waits for an event that must happen.
pub(super) const FAILSAFE: Duration = Duration::from_secs(20);

/// Serves the blocks it holds behind the production gate; every other
/// inventory vector is missing. A block's payload is whatever bytes the
/// test stored, so a flood test can share one large buffer.
pub(super) struct ScriptedChain {
    pub(super) blocks: Vec<([u8; 32], bytes::Bytes)>,
}

impl ChainQuery for ScriptedChain {
    fn headers_after(
        &self,
        _locator_hashes: &[BlockHash],
        _stop_hash: BlockHash,
        _limit: usize,
    ) -> Vec<Header> {
        Vec::new()
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
            let payload = match item {
                Inventory::Block(hash) | Inventory::WitnessBlock(hash) => self
                    .blocks
                    .iter()
                    .find(|(known, _)| *known == hash.to_byte_array())
                    .map(|(_, payload)| payload),
                _ => None,
            };
            let Some(payload) = payload else {
                outcome.not_found.push(*item);
                continue;
            };
            if !headroom() {
                outcome.halted = true;
                return Ok(outcome);
            }
            serve(Message::BlockPayload(payload.clone()))?;
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

/// A block that differs from its siblings only by header nonce.
pub(super) fn block(nonce: u32) -> Block {
    let mut block = Block::default();
    block.header.nonce = nonce;
    block
}

pub(super) fn hash_of(block: &Block) -> [u8; 32] {
    *block.block_hash().as_bytes()
}

pub(super) fn inventory_of(block: &Block) -> Inventory {
    Inventory::WitnessBlock(bitcoin::BlockHash::from_byte_array(hash_of(block)))
}

pub(super) fn scripted(block: &Block) -> ([u8; 32], bytes::Bytes) {
    (
        hash_of(block),
        bytes::Bytes::from(bitcoin_rs_primitives::consensus_bytes(block)),
    )
}

pub(super) fn wire_len_of(message: &Message) -> Result<usize, PeerError> {
    crate::wire::wire_len(message)
}

/// Serves the transactions it holds; every other transaction is missing.
struct ScriptedTxs {
    txs: Vec<Tx>,
}

impl TxInventory for ScriptedTxs {
    fn have_tx(&self, hash: Hash256, hash_is_wtxid: bool) -> bool {
        self.txs.iter().any(|tx| {
            let identity = if hash_is_wtxid {
                *tx.wtxid().as_bytes()
            } else {
                *tx.txid().as_bytes()
            };
            identity == *hash.as_byte_array()
        })
    }

    fn get_tx(&self, txid: Txid) -> Option<Tx> {
        self.txs
            .iter()
            .find(|tx| tx.txid().as_bytes() == txid.as_bytes())
            .cloned()
    }

    fn get_tx_by_wtxid(&self, wtxid: Wtxid) -> Option<Tx> {
        self.txs
            .iter()
            .find(|tx| tx.wtxid().as_bytes() == wtxid.as_bytes())
            .cloned()
    }
}

/// A transaction as small as the codec allows, distinct per `byte`.
fn tiny_tx(byte: u8) -> Tx {
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from(Hash256::from_le_bytes(&[byte; 32])),
                vout: 0,
            },
            script_sig: vec![byte].into(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: vec![0x6A].into(),
        }],
        lock_time: LockTime::ZERO,
    }
}

fn tx_inventory_of(tx: &Tx) -> Inventory {
    Inventory::WitnessTransaction(bitcoin::Txid::from_byte_array(*tx.txid().as_bytes()))
}

pub(super) fn shared_with(chain: ScriptedChain) -> ConnectionShared {
    shared_with_query(chain)
}

/// Wiring whose chain view is `chain`.
pub(super) fn shared_with_query(chain: impl ChainQuery + 'static) -> ConnectionShared {
    let mut shared = test_shared(
        Arc::new(PeerTable::new()),
        crossbeam_channel::unbounded().0,
        crossbeam_channel::unbounded().0,
    );
    shared.chain_query = Some(Arc::new(chain));
    shared
}

fn shared_with_txs(chain: ScriptedChain, txs: ScriptedTxs) -> ConnectionShared {
    let mut shared = shared_with(chain);
    shared.tx_inventory = Some(Arc::new(txs));
    shared
}

/// A socket writer whose writes wait for the gate: the budget stays charged
/// for whatever the writer has been handed while the gate is shut, as it is
/// behind a peer that has stopped draining. Dropping the gate's sender
/// opens it for good.
struct GatedSocketWriter {
    socket: TcpStream,
    gate: Receiver<()>,
}

impl Write for GatedSocketWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let _ = self.gate.recv();
        self.socket.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.socket.flush()
    }
}

/// Which writer drains the connection's queue.
pub(super) enum WriterKind {
    /// `run_writer_loop` over a [`GatedSocketWriter`].
    Gated,
    /// The production `spawn_connection_writer` over the socket, whose
    /// blocking writes time out after `write_timeout`.
    Production { write_timeout: Duration },
}

/// One served connection: the session loop and the writer on their own
/// threads over loopback sockets, and the client end of the socket.
///
/// Dropping it opens the gate, cancels the lease, closes the client, and
/// joins both threads, so every exit path cleans up.
pub(super) struct Served {
    pub(super) client: Peer<TcpStream>,
    pub(super) lease: PeerLease,
    pub(super) budget: Arc<OutboundBudget>,
    gate: Option<Sender<()>>,
    outcome: Receiver<Result<(), PeerError>>,
    session: Option<JoinHandle<()>>,
    writer: Option<JoinHandle<()>>,
}

impl Served {
    /// Starts a session over `shared` whose lease uses `budget`.
    ///
    /// Every fallible step precedes the first spawned thread, so a failure
    /// leaves nothing running.
    pub(super) fn start(
        shared: ConnectionShared,
        budget: OutboundBudget,
        writer: &WriterKind,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::start_on(shared, budget, None, writer)
    }

    /// [`Served::start`] with the lease also charging the node `aggregate`.
    pub(super) fn start_on(
        shared: ConnectionShared,
        budget: OutboundBudget,
        aggregate: Option<&Arc<SharedOutboundBudget>>,
        writer: &WriterKind,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))?;
        let client_stream = TcpStream::connect(listener.local_addr()?)?;
        let (server_stream, addr) = listener.accept()?;
        configure_peer_stream(&client_stream)?;
        configure_peer_stream(&server_stream)?;
        let writer_socket = server_stream.try_clone()?;
        if let WriterKind::Production { write_timeout } = writer {
            server_stream.set_write_timeout(Some(*write_timeout))?;
        }

        let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();
        let mut lease = PeerLease::new_with_budget(outbound_tx, true, budget);
        if let Some(aggregate) = aggregate {
            lease = lease.with_shared_budget(aggregate);
        }
        let handle = lease.budget_handle();
        let close = lease.close_signal();

        let (gate, writer_thread) = match writer {
            WriterKind::Gated => {
                let (gate_tx, gate_rx) = crossbeam_channel::bounded::<()>(0);
                let writer_budget = Arc::clone(&handle);
                let thread = std::thread::spawn(move || {
                    // The production writer's exit guard: marks the budget
                    // dead and drops every frame still queued.
                    let _exit = WriterExit {
                        budget: writer_budget,
                        outbound_rx: &outbound_rx,
                    };
                    let mut gated = GatedSocketWriter {
                        socket: writer_socket,
                        gate: gate_rx,
                    };
                    run_writer_loop(
                        &outbound_rx,
                        close,
                        &mut gated,
                        &mut SendTransport::V1(MAGIC),
                        None,
                    );
                    let _ = gated.socket.shutdown(Shutdown::Both);
                });
                (Some(gate_tx), thread)
            }
            WriterKind::Production { .. } => {
                let thread = spawn_connection_writer(
                    crate::CountingStream::new(
                        writer_socket,
                        Arc::new(crate::PeerCounters::default()),
                    ),
                    SendTransport::V1(MAGIC),
                    outbound_rx,
                    close,
                    Arc::clone(&handle),
                    addr,
                    None,
                )?;
                (None, thread)
            }
        };

        let mut peer = Peer::new(server_stream, MAGIC);
        peer.state = PeerState::Ready;
        let session_lease = lease.clone();
        let (outcome_tx, outcome) = crossbeam_channel::bounded(1);
        let session = std::thread::spawn(move || {
            let result = run_message_loop(&mut peer, addr, &session_lease, &shared, None);
            let _ = outcome_tx.send(result);
        });
        Ok(Self {
            client: Peer::new(client_stream, MAGIC),
            lease,
            budget: handle,
            gate,
            outcome,
            session: Some(session),
            writer: Some(writer_thread),
        })
    }

    /// Lets the gated writer write, now and for good.
    pub(super) fn open_gate(&mut self) {
        drop(self.gate.take());
    }

    /// Waits up to `within` for the session loop to return.
    pub(super) fn session_outcome(
        &self,
        within: Duration,
    ) -> Result<Result<(), PeerError>, String> {
        self.outcome
            .recv_timeout(within)
            .map_err(|_| format!("the session loop did not return within {within:?}"))
    }
}

impl Drop for Served {
    fn drop(&mut self) {
        self.open_gate();
        self.lease.cancel();
        let _ = self.client.stream.shutdown(Shutdown::Both);
        for thread in [self.session.take(), self.writer.take()]
            .into_iter()
            .flatten()
        {
            let _ = thread.join();
        }
    }
}

pub(super) fn wait_until(what: &str, mut condition: impl FnMut() -> bool) -> TestResult {
    let deadline = Instant::now() + FAILSAFE;
    while !condition() {
        if Instant::now() >= deadline {
            return Err(format!("timed out waiting for {what}").into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    Ok(())
}

/// Reads `count` messages from the client end, skipping v1 poll timeouts.
pub(super) fn read_messages(
    client: &mut Peer<TcpStream>,
    count: usize,
) -> Result<Vec<Message>, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + FAILSAFE;
    let mut received = Vec::new();
    while received.len() < count {
        if Instant::now() >= deadline {
            return Err(format!("only {received:?} arrived, wanted {count} messages").into());
        }
        match client.read_message() {
            Ok(Some((message, _))) => received.push(message),
            Ok(None) => {}
            Err(PeerError::Io(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(received)
}

/// Regression for the saturation disconnect: the second block does not fit
/// behind the first, so the tail parks. The queue is out of room for a
/// worst-case block but still admits a short message, so the miss that
/// preceded the halt goes out at once, as Core's does. The peer's next
/// request stays unread while parked, and once the writer drains the tail
/// follows the miss and the request that waited is answered last.
#[test]
fn saturated_getdata_parks_tail_and_serves_it_after_drain() -> TestResult {
    let (block_a, block_b) = (block(1), block(2));
    let (entry_a, entry_b) = (scripted(&block_a), scripted(&block_b));
    let unknown_tx = Inventory::Transaction(bitcoin::Txid::from_byte_array([7; 32]));
    let block_len = wire_len_of(&Message::BlockPayload(entry_a.1.clone()))?;
    let notfound_len = wire_len_of(&Message::NotFound(vec![unknown_tx]))?;
    // One queued block leaves no room for a second worst-case block (the
    // reserve is one block): a second load needs `2 * block_len`, one byte
    // more than the cap. A `notfound` and a `pong` still fit under it.
    let budget = OutboundBudget::with_block_reserve(100, 2 * block_len - 1, block_len);
    let chain = ScriptedChain {
        blocks: vec![entry_a, entry_b],
    };
    let mut served = Served::start(shared_with(chain), budget, &WriterKind::Gated)?;

    served.client.send(&Message::GetData(vec![
        unknown_tx,
        inventory_of(&block_a),
        inventory_of(&block_b),
    ]))?;
    served.client.send(&Message::Ping(7))?;

    // Block A and the miss's `notfound` wait behind the shut gate; block B
    // halts at the production gate and the ping is not read.
    let parked = (2, block_len + notfound_len);
    wait_until("block A and the notfound to be queued", || {
        served.budget.pending() == parked
    })?;
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        served.budget.pending(),
        parked,
        "a parked tail and an unread ping queue nothing more behind a saturated writer"
    );
    assert!(
        !served.lease.is_cancelled(),
        "saturation parks the peer instead of disconnecting it"
    );

    served.open_gate();
    let received = read_messages(&mut served.client, 4)?;
    assert_eq!(
        received,
        vec![
            Message::Block(block_a),
            Message::NotFound(vec![unknown_tx]),
            Message::Block(block_b),
            Message::Pong(7),
        ],
        "request order, the miss before the tail, and the waiting ping last"
    );
    assert!(!served.lease.is_cancelled());

    served.lease.cancel();
    let outcome = served.session_outcome(FAILSAFE)?;
    assert!(outcome.is_ok(), "{outcome:?}");
    Ok(())
}

/// A peer that stops reading stalls the writer's blocking socket write; the
/// short write timeout ends it, and the session parked on the full queue
/// wakes and returns instead of waiting out the tail's lifetime.
#[test]
fn paused_peer_that_never_reads_ends_on_write_timeout() -> TestResult {
    let flood = block(3);
    // One shared buffer stands for 256 distinct blocks; the client never
    // reads it, so it is never decoded. 256 MiB exceeds any loopback buffer
    // the kernel will grant a peer that does not read.
    let payload = bytes::Bytes::from(vec![0_u8; 1 << 20]);
    let block_len = wire_len_of(&Message::BlockPayload(payload.clone()))?;
    // Room to queue two blocks behind the one the writer is stuck on.
    let budget = OutboundBudget::with_block_reserve(100_000, 3 * block_len, block_len);
    let chain = ScriptedChain {
        blocks: vec![(hash_of(&flood), payload)],
    };
    let mut served = Served::start(
        shared_with(chain),
        budget,
        &WriterKind::Production {
            write_timeout: Duration::from_millis(500),
        },
    )?;

    served
        .client
        .send(&Message::GetData(vec![inventory_of(&flood); 256]))?;

    let outcome = served.session_outcome(FAILSAFE)?;
    assert!(
        outcome.is_ok(),
        "the writer's death ends the parked session cleanly: {outcome:?}"
    );
    assert!(served.budget.writer_dead());
    wait_until("the dead writer's queued frames to release", || {
        served.budget.pending() == (0, 0)
    })?;
    Ok(())
}

/// Cancelling the lease while a tail is parked and the writer is stuck ends
/// the session at its next bounded wake, with no help from the writer.
#[test]
fn lease_cancel_ends_a_parked_session() -> TestResult {
    let (block_a, block_b) = (block(4), block(5));
    let (entry_a, entry_b) = (scripted(&block_a), scripted(&block_b));
    let block_len = wire_len_of(&Message::BlockPayload(entry_a.1.clone()))?;
    let budget = OutboundBudget::with_block_reserve(100, 2 * block_len - 1, block_len);
    let chain = ScriptedChain {
        blocks: vec![entry_a, entry_b],
    };
    let mut served = Served::start(shared_with(chain), budget, &WriterKind::Gated)?;
    served.client.send(&Message::GetData(vec![
        inventory_of(&block_a),
        inventory_of(&block_b),
    ]))?;
    wait_until("block A to be queued", || {
        served.budget.pending() == (1, block_len)
    })?;
    std::thread::sleep(Duration::from_millis(200));

    let started = Instant::now();
    served.lease.cancel();
    let outcome = served.session_outcome(FAILSAFE)?;

    assert!(outcome.is_ok(), "{outcome:?}");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "a parked session wakes within its poll interval"
    );
    Ok(())
}

/// The item cap, not the byte cap, saturates the queue: tiny transactions
/// fill three slots of a megabyte of byte budget. The request parks at the
/// cap with nothing sent for the miss (the full queue cannot admit even a
/// short message), and the drain resumes the miss's `notfound` before the
/// remaining transactions. The ping that follows is sent only once the queue
/// is empty again: with a three-slot queue the pong has no spare slot while
/// the tail is still draining, and the session answers it without a gate.
#[test]
fn tiny_item_flood_pauses_at_the_item_cap_and_drains_in_order() -> TestResult {
    let txs: Vec<Tx> = (1..=5).map(tiny_tx).collect();
    let tx_len = wire_len_of(&Message::Tx(tiny_tx(1)))?;
    let budget = OutboundBudget::with_block_reserve(3, 1 << 20, tx_len);
    let shared = shared_with_txs(
        ScriptedChain { blocks: Vec::new() },
        ScriptedTxs { txs: txs.clone() },
    );
    let mut served = Served::start(shared, budget, &WriterKind::Gated)?;
    let unknown = Inventory::WitnessTransaction(bitcoin::Txid::from_byte_array([9; 32]));
    let mut items = vec![unknown];
    items.extend(txs.iter().map(tx_inventory_of));

    served.client.send(&Message::GetData(items))?;

    // Three transactions fill the item cap; the fourth load halts.
    let full = (3, 3 * tx_len);
    wait_until("three transactions to be queued", || {
        served.budget.pending() == full
    })?;
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        served.budget.pending(),
        full,
        "a full queue takes not even the parked miss's notfound"
    );
    assert!(
        !served.lease.is_cancelled(),
        "a queue full by item count parks the peer instead of disconnecting it"
    );

    served.open_gate();
    let received = read_messages(&mut served.client, 6)?;
    assert_eq!(
        received,
        vec![
            Message::Tx(txs[0].clone()),
            Message::Tx(txs[1].clone()),
            Message::Tx(txs[2].clone()),
            Message::NotFound(vec![unknown]),
            Message::Tx(txs[3].clone()),
            Message::Tx(txs[4].clone()),
        ],
        "request order, with the miss reported once the queue could take it"
    );
    wait_until("the writer to release every frame", || {
        served.budget.pending() == (0, 0)
    })?;
    served.client.send(&Message::Ping(9))?;
    assert_eq!(
        read_messages(&mut served.client, 1)?,
        vec![Message::Pong(9)],
        "the session reads again once the tail is served"
    );
    assert!(!served.lease.is_cancelled());

    served.lease.cancel();
    let outcome = served.session_outcome(FAILSAFE)?;
    assert!(outcome.is_ok(), "{outcome:?}");
    Ok(())
}

/// The boundary the live smoke found: the request's last served item takes the
/// queue's last slot, so the trailing `notfound` has nowhere to go, and the
/// peer's next request is already waiting. Neither may cancel a reader that is
/// draining: the `notfound` stays parked until the queue can admit it, and the
/// `ping` behind it is not read until the queue can admit its `pong`.
#[test]
fn a_getdata_that_fills_the_last_slot_parks_its_trailing_notfound_and_the_next_pong() -> TestResult
{
    let txs: Vec<Tx> = (1..=3).map(tiny_tx).collect();
    let tx_len = wire_len_of(&Message::Tx(tiny_tx(1)))?;
    let budget = OutboundBudget::with_block_reserve(3, 1 << 20, tx_len);
    let shared = shared_with_txs(
        ScriptedChain { blocks: Vec::new() },
        ScriptedTxs { txs: txs.clone() },
    );
    let mut served = Served::start(shared, budget, &WriterKind::Gated)?;
    let unknown = Inventory::WitnessTransaction(bitcoin::Txid::from_byte_array([9; 32]));

    // Three transactions take the three slots; the miss between them leaves
    // the trailing `notfound` with no slot, and the ping follows at once.
    served.client.send(&Message::GetData(vec![
        tx_inventory_of(&txs[0]),
        tx_inventory_of(&txs[1]),
        unknown,
        tx_inventory_of(&txs[2]),
    ]))?;
    served.client.send(&Message::Ping(11))?;

    let full = (3, 3 * tx_len);
    wait_until("three transactions to be queued", || {
        served.budget.pending() == full
    })?;
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        served.budget.pending(),
        full,
        "the full queue takes neither the trailing notfound nor the next pong"
    );
    assert!(
        !served.lease.is_cancelled(),
        "filling the last slot is not a reason to disconnect a reader"
    );

    served.open_gate();
    let received = read_messages(&mut served.client, 5)?;
    assert_eq!(
        received,
        vec![
            Message::Tx(txs[0].clone()),
            Message::Tx(txs[1].clone()),
            Message::Tx(txs[2].clone()),
            Message::NotFound(vec![unknown]),
            Message::Pong(11),
        ],
        "the notfound follows the transactions and the pong follows the notfound"
    );
    assert!(!served.lease.is_cancelled());

    served.lease.cancel();
    let outcome = served.session_outcome(FAILSAFE)?;
    assert!(outcome.is_ok(), "{outcome:?}");
    Ok(())
}

/// An answered `getdata` leaves the session holding reads while the queue
/// cannot admit one message, and releases them once it can.
#[test]
fn a_drained_getdata_holds_reads_until_the_queue_can_take_a_reply() -> TestResult {
    let (outbound_tx, outbound_rx) = crate::test_support::message_channel();
    let lease = PeerLease::new_with_budget(
        outbound_tx,
        true,
        OutboundBudget::with_block_reserve(1, 1 << 20, 1),
    );
    lease
        .send(Message::Ping(1))
        .map_err(|_| "a fresh queue admits its one message")?;
    let shared = shared_with(ScriptedChain { blocks: Vec::new() });
    let mut peer = parked_peer(Vec::new());
    let mut keepalive = Keepalive::starting(Instant::now());
    let mut parked_since = Some(Instant::now());

    let held = step_parked_getdata(
        &mut peer,
        &shared,
        &lease,
        &mut keepalive,
        &mut parked_since,
    )?;

    assert_eq!(held, ParkedStep::StillParked, "the one slot is taken");
    assert!(parked_since.is_some(), "the hold keeps its start");
    assert!(!lease.is_cancelled());

    assert_eq!(
        outbound_rx.try_recv(),
        Ok(Message::Ping(1)),
        "the writer takes the queued ping, and its slot returns"
    );
    let released = step_parked_getdata(
        &mut peer,
        &shared,
        &lease,
        &mut keepalive,
        &mut parked_since,
    )?;

    assert_eq!(released, ParkedStep::NotParked, "a slot is free again");
    assert_eq!(parked_since, None, "reads resume and the marker clears");
    assert!(outbound_rx.is_empty(), "the hold sends nothing");
    Ok(())
}

/// The production writer, not only the test's gated one, marks the budget
/// dead when a write fails: a peer that has gone away fails the second write.
#[test]
fn production_writer_marks_the_budget_dead_when_a_write_fails() -> TestResult {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))?;
    let client = TcpStream::connect(listener.local_addr()?)?;
    let (server, addr) = listener.accept()?;
    drop(client);
    let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();
    let lease = PeerLease::new(outbound_tx);
    let writer = spawn_connection_writer(
        crate::CountingStream::new(server, Arc::new(crate::PeerCounters::default())),
        SendTransport::V1(MAGIC),
        outbound_rx,
        lease.close_signal(),
        lease.budget_handle(),
        addr,
        None,
    )?;

    // The first write after the peer closed may be accepted; a later one
    // fails, the writer returns, and the budget learns it.
    let died = wait_until("the writer to die", || {
        let _ = lease.send(Message::Ping(1));
        lease.budget_handle().writer_dead()
    });
    // Unconditional cleanup: end and join the writer whether or not it died.
    lease.cancel();
    let _ = writer.join();
    died
}

/// A queue that is full cannot admit even a `notfound`, so the misses stay
/// parked, nothing is sent, and the lease stays live; the tail is untouched.
#[test]
fn a_full_queue_keeps_the_misses_and_sends_nothing() -> TestResult {
    let (outbound_tx, outbound_rx) = crate::test_support::message_channel();
    let lease = PeerLease::new_with_budget(
        outbound_tx,
        true,
        OutboundBudget::with_block_reserve(1, 1 << 20, 1),
    );
    lease
        .send(Message::Ping(1))
        .map_err(|_| "a fresh queue admits one message")?;
    let shared = shared_with(ScriptedChain { blocks: Vec::new() });
    let tail = vec![Inventory::WitnessBlock(
        bitcoin::BlockHash::from_byte_array([2; 32]),
    )];
    let miss = Inventory::Transaction(bitcoin::Txid::from_byte_array([3; 32]));
    let mut peer = parked_peer(tail.clone());
    peer.pending_notfound = vec![miss];
    let mut keepalive = Keepalive::starting(Instant::now());
    let mut parked_since = None;

    let step = step_parked_getdata(
        &mut peer,
        &shared,
        &lease,
        &mut keepalive,
        &mut parked_since,
    )?;

    assert_eq!(step, ParkedStep::StillParked);
    assert_eq!(
        outbound_rx.try_iter().collect::<Vec<_>>(),
        vec![Message::Ping(1)],
        "nothing was sent into the full queue"
    );
    assert_eq!(peer.pending_notfound, vec![miss]);
    assert_eq!(peer.pending_getdata, tail);
    assert!(!lease.is_cancelled());
    Ok(())
}

pub(super) fn parked_peer(tail: Vec<Inventory>) -> Peer<io::Cursor<Vec<u8>>> {
    let mut peer = Peer::new(io::Cursor::new(Vec::new()), MAGIC);
    peer.state = PeerState::Ready;
    peer.pending_getdata = tail;
    peer
}

#[test]
fn nothing_parked_clears_the_marker_and_reads_on() -> TestResult {
    let lease = PeerLease::new(crossbeam_channel::unbounded().0);
    let shared = shared_with(ScriptedChain { blocks: Vec::new() });
    let mut peer = parked_peer(Vec::new());
    let mut keepalive = Keepalive::starting(Instant::now());
    let mut parked_since = Some(Instant::now());

    let step = step_parked_getdata(
        &mut peer,
        &shared,
        &lease,
        &mut keepalive,
        &mut parked_since,
    )?;

    assert_eq!(step, ParkedStep::NotParked);
    assert_eq!(parked_since, None, "a drained tail forgets its start");
    Ok(())
}

#[test]
fn a_dead_writer_ends_a_parked_step_without_waiting() -> TestResult {
    let lease = PeerLease::new(crossbeam_channel::unbounded().0);
    lease.budget_handle().mark_writer_dead();
    let shared = shared_with(ScriptedChain { blocks: Vec::new() });
    let tail = vec![Inventory::WitnessBlock(
        bitcoin::BlockHash::from_byte_array([1; 32]),
    )];
    let mut peer = parked_peer(tail.clone());
    let mut keepalive = Keepalive::starting(Instant::now());
    let mut parked_since = None;

    let started = Instant::now();
    let step = step_parked_getdata(
        &mut peer,
        &shared,
        &lease,
        &mut keepalive,
        &mut parked_since,
    )?;

    assert_eq!(step, ParkedStep::Ended);
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(
        parked_since.is_some(),
        "the tail's age starts at its first park"
    );
    assert_eq!(
        peer.pending_getdata, tail,
        "ending the session drops nothing silently"
    );
    Ok(())
}

#[test]
fn a_tail_expires_only_after_the_timeout_interval() {
    let parked = Instant::now();
    assert!(!parked_tail_expired(parked, parked));
    assert!(!parked_tail_expired(parked, parked + TIMEOUT_INTERVAL));
    assert!(parked_tail_expired(
        parked,
        parked + TIMEOUT_INTERVAL + Duration::from_secs(1)
    ));
}

/// With headroom the step sends the deferred `notfound` first, then serves
/// the tail; a gate that closes again leaves exactly the unserved items.
#[test]
fn an_open_queue_resumes_notfound_first_and_reparks_what_the_gate_stops() -> TestResult {
    let (block_a, block_b) = (block(6), block(7));
    let (entry_a, entry_b) = (scripted(&block_a), scripted(&block_b));
    let block_len = wire_len_of(&Message::BlockPayload(entry_a.1.clone()))?;
    let (outbound_tx, outbound_rx) = crate::test_support::message_channel();
    // Room for the `notfound` and one block, not for a second block.
    let lease = PeerLease::new_with_budget(
        outbound_tx,
        true,
        OutboundBudget::with_block_reserve(100, 2 * block_len - 1, block_len),
    );
    let shared = shared_with(ScriptedChain {
        blocks: vec![entry_a.clone(), entry_b],
    });
    let miss = Inventory::Transaction(bitcoin::Txid::from_byte_array([8; 32]));
    let mut peer = parked_peer(vec![inventory_of(&block_a), inventory_of(&block_b)]);
    peer.pending_notfound = vec![miss];
    let mut keepalive = Keepalive::starting(Instant::now());
    let mut parked_since = None;

    let step = step_parked_getdata(
        &mut peer,
        &shared,
        &lease,
        &mut keepalive,
        &mut parked_since,
    )?;

    assert_eq!(step, ParkedStep::StillParked);
    assert_eq!(
        outbound_rx.try_iter().collect::<Vec<_>>(),
        vec![
            Message::NotFound(vec![miss]),
            Message::BlockPayload(entry_a.1),
        ],
        "the earlier miss is reported before any resumed item"
    );
    assert_eq!(peer.pending_getdata, vec![inventory_of(&block_b)]);
    assert_eq!(peer.pending_notfound, Vec::new());
    assert!(!lease.is_cancelled(), "re-parking is not a disconnect");
    Ok(())
}
