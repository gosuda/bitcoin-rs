//! ING-R9 e2e: peer transaction admission and source-excluding relay over a
//! real loopback socket pair.
//!
//! Each test binds real TCP listeners on 127.0.0.1 and drives the production
//! wire path end to end: a dialer peer frames `version`/`verack`/`inv`/`tx`
//! with `bitcoin_rs_p2p::wire`, the node side runs the real inbound handshake
//! and `dispatch_inbound_full` with the real [`MempoolGateway`] as the
//! `TxInventory` filter, the decoded transaction enters the real bounded
//! channel drained by [`spawn_tx_ingress_consumer`], admission commits through
//! the node's one shared `MempoolGateway`, and the real P2P relay worker
//! announces through `PeerRelaySink` over
//! `NodeState::peer_table`. The assertions read framed messages back off
//! the sockets: the bystander peer receives the `inv`, the source peer does
//! not.
//!
//! The production listener now forwards `Message::Tx` into the ingress
//! channel and dispatches through `TxInventory`. This harness still drives
//! its own loopback sockets so the assertions stay deterministic; it uses
//! the same consumer, admission, and relay worker `start_node` spawns.
//!
//! Skip gate: when loopback TCP is unavailable (sandboxed environment) the
//! tests return early with a `tracing::warn!` rather than failing.

use std::io::ErrorKind;
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail};
use bitcoin::hashes::Hash as _;
use bitcoin::p2p::Magic;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin_rs_mempool::MempoolGateway;
use bitcoin_rs_mining::{
    BlockTemplateRequest, BlockTemplateResult, BlockValidationResult, MiningControl,
    MiningControlError, MiningInfo,
};
use bitcoin_rs_node::state::NodeState;
use bitcoin_rs_node::tx_ingress::spawn_tx_ingress_consumer;
use bitcoin_rs_node::{Network, NodeConfig};
use bitcoin_rs_p2p::dispatch::dispatch_inbound_full;
use bitcoin_rs_p2p::handshake::{run_inbound_handshake, version_message};
use bitcoin_rs_p2p::wire::{PeerError, read_message, write_message};
use bitcoin_rs_p2p::{
    DEFAULT_TX_RELAY_QUEUE_CAPACITY, InboundTx, Message, Peer, PeerLease, PeerRelaySink,
    TxRelayQueue, spawn_tx_relay_worker,
};
use bitcoin_rs_primitives::{Amount, Block, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness};
use bitcoin_rs_utxo::{BlockChanges, UtxoAdd};
use crossbeam_channel::Sender;
use parking_lot::Mutex;

/// Node-side socket read poll while waiting for peer frames.
const READ_POLL: Duration = Duration::from_millis(200);
/// Bounded deadline for the inbound handshake.
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(10);
/// How long a socket is drained while asserting a message never arrives.
const ABSENCE_WINDOW: Duration = Duration::from_millis(700);
/// Upper bound for admission and relay to become observable.
const OBSERVE_TIMEOUT: Duration = Duration::from_secs(10);
/// Slice between deadline checks in the frame collectors.
const COLLECT_SLICE: Duration = Duration::from_millis(200);

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Parent outpoint funding the spending transactions.
fn parent_txid(marker: u8) -> Txid {
    Txid::from(Hash256::from_le_bytes(&[marker; 32]))
}

/// Builds the transaction-inventory vector for `txid`.
fn tx_inv(txid: &Txid) -> Message {
    Message::Inv(vec![Inventory::Transaction(
        bitcoin::hashes::Hash::from_byte_array(*txid.as_bytes()),
    )])
}

/// Opens an isolated regtest `NodeState`; the guard keeps the data directory
/// alive for the whole test body.
fn open_node() -> anyhow::Result<(NodeState, tempfile::TempDir)> {
    let dir = tempfile::tempdir()?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    let state = NodeState::open(config, None)?;
    Ok((state, dir))
}

/// Funds one spendable output directly in the node's real `UtxoSet` (the same
/// seam the apply path writes through), so the spend below passes the
/// missing-inputs check.
fn fund_utxo(state: &NodeState, parent: Txid, value: u64) -> anyhow::Result<()> {
    fund_utxo_script(state, parent, value, vec![0x51])
}

fn fund_utxo_script(
    state: &NodeState,
    parent: Txid,
    value: u64,
    script_pubkey: Vec<u8>,
) -> anyhow::Result<()> {
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
    state
        .utxo()
        .commit_block(&changes, &Hash256::from_le_bytes(&[0xBB; 32]))
        .map_err(|error| anyhow!("utxo commit failed: {error}"))
}

/// One-input spend of the funded output; `output_value` sets the fee
/// (`50_000 - output_value` sats).
fn spending_tx(parent: Txid, output_value: u64) -> Tx {
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(parent, 0),
            script_sig: Script::new(),
            sequence: Sequence::from_consensus(0xffff_ffff),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(output_value),
            script_pubkey: Script::from_bytes(vec![0x6A, 0x04, 0xAA, 0xBB, 0xCC, 0xDD]),
        }],
        lock_time: LockTime::from_consensus(0),
    }
}

/// Recording `MiningControl` counting accepted-path template wakes.
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

    fn submit_block(&self, _block: Block) -> Result<BlockValidationResult, MiningControlError> {
        Err(MiningControlError::Failed(
            "not implemented".to_owned().into(),
        ))
    }

    fn publish_generation(&self) {
        self.publishes.fetch_add(1, Ordering::Relaxed);
    }

    fn generate(
        &self,
        _request: bitcoin_rs_mining::GenerateRequest,
    ) -> Result<Vec<bitcoin_rs_mining::GeneratedBlock>, MiningControlError> {
        Err(MiningControlError::Failed(
            "not implemented".to_owned().into(),
        ))
    }
}

/// Returns `Some(reason)` when loopback TCP cannot be used and the test must
/// skip instead of failing on an environmental gate.
fn loopback_skip() -> Option<String> {
    match TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))) {
        Ok(listener) => {
            drop(listener);
            None
        }
        Err(error) => Some(format!("loopback TCP unavailable: {error}")),
    }
}

// ---------------------------------------------------------------------------
// Loopback peer: real socket pair around a real lease
// ---------------------------------------------------------------------------

/// Node-side wiring shared by every loopback peer of one test.
#[derive(Clone)]
struct PeerWiring {
    magic: Magic,
    peer_table: Arc<bitcoin_rs_p2p::PeerTable>,
    ingress_tx: Sender<InboundTx>,
    stop: Arc<AtomicBool>,
}

/// One connected peer. The dialer end is driven by the test; the accepted end
/// is owned by the node-side service thread, and the peer's lease is
/// registered in the node's shared `peer_table` exactly like the
/// production listener registers inbound connections.
struct LoopbackPeer {
    /// Test-held client end of the real TCP connection.
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
        self.peer_table.remove_current(self.peer_addr, &self.lease);
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

/// Dials one loopback connection and starts its node-side service thread:
/// real inbound handshake, then a dispatch loop that filters `inv` through
/// the real [`MempoolGateway`] and forwards decoded `tx` bodies into the real
/// ingress channel with the lease-stamped source.
fn open_loopback_peer(
    wiring: &PeerWiring,
    gateway: Arc<MempoolGateway>,
    name: &'static str,
) -> anyhow::Result<LoopbackPeer> {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let dialer = TcpStream::connect(listener.local_addr()?)?;
    let (accepted, peer_addr) = listener.accept()?;

    let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded::<Message>();
    let lease = PeerLease::new_inbound(outbound_tx);
    let mut wire_out = accepted
        .try_clone()
        .map_err(|error| anyhow!("accepted stream clone failed: {error}"))?;
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
    wiring.peer_table.register(peer_addr, lease.clone());
    let pump_lease = lease.clone();
    peer.pump = Some(
        std::thread::Builder::new()
            .name(format!("ingress-e2e-pump-{name}"))
            .spawn(move || {
                while !pump_lease.is_cancelled() {
                    match outbound_rx.recv_timeout(READ_POLL) {
                        Ok(message) => {
                            if write_message(&mut wire_out, magic, &message).is_err() {
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

/// Node-side half of one loopback connection: the production handshake, then
/// the production dispatch loop. `Message::Tx` is forwarded into the ingress
/// channel with the same lease-stamped source as the production listener.
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
    if run_inbound_handshake(&mut peer, 1, 0, lease, None, deadline).is_err() {
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
    if !wiring.peer_table.publish_info(peer_addr, lease, info) {
        return;
    }
    let _ = peer.stream.set_read_timeout(Some(READ_POLL));
    loop {
        if wiring.stop.load(Ordering::Relaxed) {
            return;
        }
        match read_message(&mut peer.stream, magic) {
            Ok((message, _raw)) => {
                if let Message::Tx(tx) = message {
                    let source = lease.source(peer_addr);
                    let _ = wiring.ingress_tx.try_send(InboundTx::new(tx, source));
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
                    Some(gateway.as_ref()),
                    &|| true,
                    &mut send,
                );
            }
            Err(PeerError::Io(error))
                if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(_) => return,
        }
    }
}

/// Completes the dialer half of the handshake against the node side.
fn dial_handshake(dialer: &TcpStream, magic: Magic, wtxid_relay: bool) -> anyhow::Result<()> {
    let mut stream = dialer
        .try_clone()
        .map_err(|error| anyhow!("dialer clone failed: {error}"))?;
    stream.set_read_timeout(Some(HANDSHAKE_DEADLINE))?;
    write_message(&mut stream, magic, &Message::Version(version_message(7, 0)))?;
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

/// Writes one framed message from the dialer end onto the wire.
fn write_frame(dialer: &TcpStream, magic: Magic, message: &Message) -> anyhow::Result<()> {
    let mut stream = dialer
        .try_clone()
        .map_err(|error| anyhow!("dialer clone failed: {error}"))?;
    write_message(&mut stream, magic, message)
        .map(|_| ())
        .map_err(|error| anyhow!("dialer write failed: {error}"))
}

/// Drains framed messages off the dialer end until `until`, tolerating the
/// poll timeout between frames.
fn collect_frames(
    dialer: &TcpStream,
    magic: Magic,
    until: Instant,
) -> anyhow::Result<Vec<Message>> {
    let mut stream = dialer
        .try_clone()
        .map_err(|error| anyhow!("dialer clone failed: {error}"))?;
    stream.set_read_timeout(Some(READ_POLL))?;
    let mut frames = Vec::new();
    while Instant::now() < until {
        match read_message(&mut stream, magic) {
            Ok((message, _raw)) => frames.push(message),
            Err(PeerError::Io(error))
                if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(error) => return Err(anyhow!("dialer read failed: {error}")),
        }
    }
    Ok(frames)
}

/// True when one of `frames` announces `txid` as transaction inventory.
fn announces_tx(frames: &[Message], txid: &Txid) -> bool {
    frames.iter().any(|message| match message {
        Message::Inv(items) => items.iter().any(|item| match item {
            Inventory::Transaction(hash) => hash.as_byte_array() == txid.as_bytes(),
            _ => false,
        }),
        _ => false,
    })
}

/// P2P-01 / BIP144: these dialers advertise `NODE_WITNESS`, so require
/// witness-serialized getdata rather than accepting the legacy request.
fn requests_tx(frames: &[Message], txid: &Txid) -> bool {
    frames.iter().any(|message| match message {
        Message::GetData(items) => items.iter().any(|item| match item {
            Inventory::WitnessTransaction(hash) => hash.as_byte_array() == txid.as_bytes(),
            _ => false,
        }),
        _ => false,
    })
}

/// Collects frames until `txid` is announced or `timeout` elapses.
fn wait_for_tx_inv(
    dialer: &TcpStream,
    magic: Magic,
    txid: &Txid,
    timeout: Duration,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let slice = deadline.min(Instant::now() + COLLECT_SLICE);
        let frames = collect_frames(dialer, magic, slice)?;
        if announces_tx(&frames, txid) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("relay inv for tx {txid} did not arrive within {timeout:?}");
        }
    }
}

/// Collects frames until `txid` is requested with getdata or `timeout`
/// elapses.
fn wait_for_tx_getdata(
    dialer: &TcpStream,
    magic: Magic,
    txid: &Txid,
    timeout: Duration,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let slice = deadline.min(Instant::now() + COLLECT_SLICE);
        let frames = collect_frames(dialer, magic, slice)?;
        if requests_tx(&frames, txid) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("getdata for tx {txid} did not arrive within {timeout:?}");
        }
    }
}

/// Polls `predicate` until it holds or `timeout` elapses.
fn wait_until(timeout: Duration, predicate: impl Fn() -> bool) -> anyhow::Result<()> {
    let deadline = Instant::now() + timeout;
    while !predicate() {
        if Instant::now() >= deadline {
            bail!("condition did not hold within {timeout:?}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// Full path under test: funded node state, the production ingress and P2P
/// relay workers, and a source + bystander
/// loopback peer pair with completed handshakes.
struct Harness {
    state: NodeState,
    magic: Magic,
    gateway: Arc<MempoolGateway>,
    mining: Arc<RecordingMining>,
    shutdown: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    source: LoopbackPeer,
    bystander: LoopbackPeer,
    ingress: Option<std::thread::JoinHandle<()>>,
    relay: Option<std::thread::JoinHandle<()>>,
    /// Dropped after state releases its storage handles.
    _dir: tempfile::TempDir,
}

impl Harness {
    /// Builds one harness. `source_marker`/`bystander` funding is keyed by
    /// marker so concurrent tests never share prevouts.
    fn build(source_marker: u8) -> anyhow::Result<Self> {
        let (state, dir) = open_node()?;
        let magic = Magic::from_bytes(state.config().p2p.magic);
        let gateway = state.mempool_gateway();

        let ingress_tx = state.inbound_tx_sender();
        let ingress_rx = state.inbound_tx_rx_handle();
        let (relay, relay_rx) = TxRelayQueue::new(DEFAULT_TX_RELAY_QUEUE_CAPACITY);
        let mining = Arc::new(RecordingMining::default());
        let mining_control: Arc<dyn MiningControl> = Arc::<RecordingMining>::clone(&mining);
        let shutdown = Arc::new(AtomicBool::new(false));

        let wiring = PeerWiring {
            magic,
            peer_table: state.peer_table(),
            ingress_tx,
            stop: Arc::new(AtomicBool::new(false)),
        };

        fund_utxo(&state, parent_txid(source_marker), 50_000)?;

        let source = open_loopback_peer(&wiring, Arc::clone(&gateway), "source")?;
        let bystander = open_loopback_peer(&wiring, Arc::clone(&gateway), "bystander")?;
        dial_handshake(&source.dialer, magic, false)?;
        dial_handshake(&bystander.dialer, magic, false)?;
        wait_until(OBSERVE_TIMEOUT, || {
            wiring.peer_table.ready_source(source.peer_addr).is_some()
                && wiring
                    .peer_table
                    .ready_source(bystander.peer_addr)
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
            _dir: dir,
        };
        // Register each handle as soon as its spawn succeeds so later setup
        // failure still closes the peers and joins every earlier worker.
        harness.relay = Some(spawn_tx_relay_worker(
            PeerRelaySink::new(harness.state.peer_table()),
            relay_rx,
            Arc::clone(&harness.shutdown),
        )?);
        harness.ingress = Some(spawn_tx_ingress_consumer(
            &harness.state,
            Arc::clone(&harness.gateway),
            mining_control,
            Arc::clone(&harness.shutdown),
            ingress_rx,
            relay,
        )?);
        Ok(harness)
    }

    fn tx_in_mempool(&self, txid: &Txid) -> bool {
        self.state.mempool_gateway().read().contains_txid(txid)
    }

    fn connect_peer(&self, name: &'static str, wtxid_relay: bool) -> anyhow::Result<LoopbackPeer> {
        let wiring = PeerWiring {
            magic: self.magic,
            peer_table: self.state.peer_table(),
            ingress_tx: self.state.inbound_tx_sender(),
            stop: Arc::clone(&self.stop),
        };
        let peer = open_loopback_peer(&wiring, Arc::clone(&self.gateway), name)?;
        dial_handshake(&peer.dialer, self.magic, wtxid_relay)?;
        wait_until(OBSERVE_TIMEOUT, || {
            wiring.peer_table.ready_source(peer.peer_addr).is_some()
        })?;
        Ok(peer)
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.shutdown.store(true, Ordering::Relaxed);
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn full_relay_queue_does_not_block_peer_admission_or_mining_wake() -> anyhow::Result<()> {
    let (state, _dir) = open_node()?;
    fund_utxo(&state, parent_txid(0xDD), 50_000)?;
    let gateway = state.mempool_gateway();
    let (relay, _relay_rx) = TxRelayQueue::new(1);
    let pending = spending_tx(parent_txid(0xEE), 40_000);
    assert!(relay.announce(pending.txid(), pending.wtxid(), None));
    let mining = Arc::new(RecordingMining::default());
    let mining_control: Arc<dyn MiningControl> = Arc::<RecordingMining>::clone(&mining);
    let shutdown = Arc::new(AtomicBool::new(false));
    let (ingress_tx, ingress_rx) = crossbeam_channel::bounded(1);
    let tx = spending_tx(parent_txid(0xDD), 40_000);
    let txid = tx.txid();
    let (outbound_tx, _outbound_rx) = crossbeam_channel::bounded(1);
    let source = PeerLease::new(outbound_tx).source(SocketAddr::from((Ipv4Addr::LOCALHOST, 8333)));
    let ingress = spawn_tx_ingress_consumer(
        &state,
        Arc::clone(&gateway),
        mining_control,
        Arc::clone(&shutdown),
        Arc::new(Mutex::new(ingress_rx)),
        relay.clone(),
    )?;

    let observed = ingress_tx
        .try_send(InboundTx::new(tx, source))
        .map_err(|error| anyhow!("failed to queue peer transaction: {error}"))
        .and_then(|()| {
            wait_until(OBSERVE_TIMEOUT, || {
                gateway.read().contains_txid(&txid) && mining.publish_count() >= 1
            })
        });
    shutdown.store(true, Ordering::Relaxed);
    let joined = ingress.join();
    observed?;
    joined.map_err(|_| anyhow!("transaction ingress worker panicked"))?;
    assert_eq!(relay.enqueued(), 1);
    assert_eq!(relay.dropped(), 1);
    assert!(gateway.read().contains_txid(&txid));
    Ok(())
}

#[test]
fn witness_transaction_relays_txid_and_wtxid_to_mixed_peers() -> anyhow::Result<()> {
    if let Some(reason) = loopback_skip() {
        tracing::warn!(%reason, "skipping tx ingress e2e");
        return Ok(());
    }
    let harness = Harness::build(0xA1)?;
    let witness_peer = harness.connect_peer("wtxid", true)?;
    let parent = parent_txid(0xA2);
    let witness_script = vec![0x51];
    let mut locking_script = vec![0x00, 0x20];
    locking_script
        .extend_from_slice(bitcoin::hashes::sha256::Hash::hash(&witness_script).as_byte_array());
    fund_utxo_script(&harness.state, parent, 50_000, locking_script)?;
    let mut tx = spending_tx(parent, 40_000);
    tx.inputs[0].witness = Witness::from_stack(vec![witness_script]);
    let txid = tx.txid();
    let wtxid = tx.wtxid();
    assert_ne!(txid.as_bytes(), wtxid.as_bytes());
    write_frame(&harness.source.dialer, harness.magic, &Message::Tx(tx))?;
    wait_until(OBSERVE_TIMEOUT, || harness.tx_in_mempool(&txid))?;

    let legacy_frames = collect_frames(
        &harness.bystander.dialer,
        harness.magic,
        Instant::now() + ABSENCE_WINDOW,
    )?;
    let witness_frames = collect_frames(
        &witness_peer.dialer,
        harness.magic,
        Instant::now() + ABSENCE_WINDOW,
    )?;
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
        Instant::now() + ABSENCE_WINDOW,
    )?;
    assert!(inventories(&source_frames).is_empty());
    Ok(())
}

/// R1–R8 over a real socket: the source peer announces `inv`, the node
/// requests the body with `getdata` (real dispatch + real admission filter),
/// the body arrives framed as `tx`, admission commits through the shared
/// gateway, and the relay worker announces the txid to the bystander peer —
/// never back to the source peer.
#[test]
fn accepted_peer_tx_is_admitted_and_relayed_excluding_the_source() -> anyhow::Result<()> {
    if let Some(reason) = loopback_skip() {
        tracing::warn!(%reason, "skipping tx ingress e2e");
        return Ok(());
    }
    let harness = Harness::build(0xAA)?;

    let tx = spending_tx(parent_txid(0xAA), 40_000);
    let txid = tx.txid();

    // The source announces; the node's dispatch + gateway inventory filter does not
    // know the tx and requests its body over the same socket.
    write_frame(&harness.source.dialer, harness.magic, &tx_inv(&txid))?;
    wait_for_tx_getdata(
        &harness.source.dialer,
        harness.magic,
        &txid,
        OBSERVE_TIMEOUT,
    )?;

    // The body arrives framed on the wire; the real consumer admits it
    // through the shared gateway.
    write_frame(&harness.source.dialer, harness.magic, &Message::Tx(tx))?;
    wait_until(OBSERVE_TIMEOUT, || harness.tx_in_mempool(&txid))
        .map_err(|_| anyhow!("admitted tx never reached the shared mempool gateway"))?;

    // Relay announces to the bystander…
    wait_for_tx_inv(
        &harness.bystander.dialer,
        harness.magic,
        &txid,
        OBSERVE_TIMEOUT,
    )?;

    // …and excludes the source: drain its socket for a full window and assert
    // no announcement for the delivered tx ever appears on it.
    let source_frames = collect_frames(
        &harness.source.dialer,
        harness.magic,
        Instant::now() + ABSENCE_WINDOW,
    )?;
    assert!(
        !announces_tx(&source_frames, &txid),
        "source peer must never receive the inv for its own transaction"
    );

    // The accepted-only mining wake fired exactly through the accepted
    // mutation, and the admission inventory now reports the mempool hold.
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

/// Negative control: a transaction below the min-relay floor is rejected,
/// recorded in the recent-rejects cache, never relayed to the bystander, and
/// its follow-up `inv` announcement is suppressed at the dispatch filter —
/// all observed over the same real sockets.
#[test]
fn below_min_relay_tx_is_rejected_recorded_and_never_relayed() -> anyhow::Result<()> {
    if let Some(reason) = loopback_skip() {
        tracing::warn!(%reason, "skipping tx ingress e2e");
        return Ok(());
    }
    let harness = Harness::build(0xCC)?;

    // Zero fee: 0 sat/kvB against the pool's 1_000 sat/kvB floor.
    let tx = spending_tx(parent_txid(0xCC), 50_000);
    let txid = tx.txid();

    // The unknown tx is requested…
    write_frame(&harness.source.dialer, harness.magic, &tx_inv(&txid))?;
    wait_for_tx_getdata(
        &harness.source.dialer,
        harness.magic,
        &txid,
        OBSERVE_TIMEOUT,
    )?;

    // …the body is delivered and rejected…
    write_frame(&harness.source.dialer, harness.magic, &Message::Tx(tx))?;
    wait_until(OBSERVE_TIMEOUT, || {
        harness.gateway.is_rejected(Hash256::from(txid))
    })
    .map_err(|_| anyhow!("rejected tx never reached the recent-rejects cache"))?;
    assert!(
        !harness.tx_in_mempool(&txid),
        "a below-min-relay tx must not enter the mempool"
    );

    // …never relayed to the bystander…
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

    // …and its next announcement is suppressed by the real dispatch filter.
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

    Ok(())
}
