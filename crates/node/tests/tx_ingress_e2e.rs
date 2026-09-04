//! ING-R9 e2e: peer transaction admission and source-excluding relay over a
//! real loopback socket pair.
//!
//! Each test binds real TCP listeners on 127.0.0.1 and drives the production
//! wire path end to end: a dialer peer frames `version`/`verack`/`inv`/`tx`
//! with `bitcoin_rs_p2p::wire`, the node side runs the real inbound handshake
//! and `dispatch_inbound_full` with the real [`TxAdmission`] as the
//! `TxInventory` filter, the decoded transaction enters the real bounded
//! channel drained by [`spawn_tx_ingress_consumer`], admission commits through
//! the node's one shared `MempoolGateway`, and the real relay worker (started
//! by that spawn) announces through `PeerRelaySink` over
//! `NodeState::peer_table`. The assertions read framed messages back off
//! the sockets: the bystander peer receives the `inv`, the source peer does
//! not.
//!
//! One seam is filled by the test's node-side thread: the production listener
//! (`crates/p2p/src/listener.rs::run_message_loop`) does not yet carry a
//! `Message::Tx` → `InboundTx` hand-off (`InboundSyncSinks` is
//! headers/blocks/wake only), so the stand-in forwards the decoded body with
//! the *real* lease-stamped [`PeerSource`]. Everything else — handshake FSM,
//! inv filter, admission, relay queue, relay worker, peer leases, wire
//! framing — is the production code under test.
//!
//! Skip gate: when loopback TCP is unavailable (sandboxed environment) the
//! tests return early with a `tracing::warn!` rather than failing.

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail};
use bitcoin::hashes::Hash as _;
use bitcoin::p2p::Magic;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin_rs_node::state::NodeState;
use bitcoin_rs_node::tx_admission::TxAdmission;
use bitcoin_rs_node::tx_ingress::spawn_tx_ingress_consumer;
use bitcoin_rs_node::{Network, NodeConfig};
use bitcoin_rs_p2p::TxInventory;
use bitcoin_rs_p2p::dispatch::dispatch_inbound_full;
use bitcoin_rs_p2p::handshake::{run_inbound_handshake, version_message};
use bitcoin_rs_p2p::wire::{PeerError, read_message, write_message};
use bitcoin_rs_p2p::{InboundTx, Message, Peer, PeerLease};
use bitcoin_rs_primitives::{Block, Hash256, OutPoint, Tx, TxIn, TxOut, Txid};
use bitcoin_rs_rpc::context::{
    BlockTemplateRequest, BlockTemplateResult, BlockValidationResult, MiningControl,
    MiningControlError, MiningInfo,
};
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
    config.p2p_listen.clear();
    let state = NodeState::open(config, None)?;
    Ok((state, dir))
}

/// Funds one spendable output directly in the node's real `UtxoSet` (the same
/// seam the apply path writes through), so the spend below passes the
/// missing-inputs check.
fn fund_utxo(state: &NodeState, parent: Txid, value: u64) -> anyhow::Result<()> {
    let mut changes = BlockChanges::with_capacity(1, 0);
    changes.add(UtxoAdd::new(
        OutPoint::new(parent, 0),
        TxOut {
            value,
            script_pubkey: Vec::new(),
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
            script_sig: vec![0x52, 0x02, 0xAA, 0xBB],
            sequence: 0xffff_ffff,
            witness: Vec::new(),
        }],
        outputs: vec![TxOut {
            value: output_value,
            script_pubkey: vec![0x6A],
        }],
        lock_time: 0,
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

    fn submit_block(&self, _block: Block) -> Result<BlockValidationResult, MiningControlError> {
        Err(MiningControlError::Failed(
            "not implemented".to_owned().into(),
        ))
    }

    fn publish_generation(&self) {
        self.publishes.fetch_add(1, Ordering::Relaxed);
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
}

/// Dials one loopback connection and starts its node-side service thread:
/// real inbound handshake, then a dispatch loop that filters `inv` through
/// the real [`TxAdmission`] and forwards decoded `tx` bodies into the real
/// ingress channel with the lease-stamped source.
fn open_loopback_peer(
    wiring: &PeerWiring,
    admission: Arc<TxAdmission>,
    name: &'static str,
) -> anyhow::Result<LoopbackPeer> {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let dialer = TcpStream::connect(listener.local_addr()?)?;
    let (accepted, peer_addr) = listener.accept()?;

    let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded::<Message>();
    let lease = PeerLease::new_inbound(outbound_tx);
    wiring.peer_table.register(peer_addr, lease.clone());

    let mut wire_out = accepted
        .try_clone()
        .map_err(|error| anyhow!("accepted stream clone failed: {error}"))?;
    let magic = wiring.magic;
    // Detached: both threads exit when the harness flags shut down, and the
    // pump's channel senders drop with the peer leases.
    std::thread::Builder::new()
        .name(format!("ingress-e2e-pump-{name}"))
        .spawn(move || {
            while let Ok(message) = outbound_rx.recv() {
                if write_message(&mut wire_out, magic, &message).is_err() {
                    break;
                }
            }
        })?;

    let reader = accepted
        .try_clone()
        .map_err(|error| anyhow!("accepted stream clone failed: {error}"))?;
    let ingress_tx = Sender::clone(&wiring.ingress_tx);
    let stop = Arc::clone(&wiring.stop);
    std::thread::Builder::new()
        .name(format!("ingress-e2e-node-{name}"))
        .spawn(move || {
            serve_connection(
                reader,
                peer_addr,
                &lease,
                &admission,
                &ingress_tx,
                &stop,
                magic,
            );
        })?;

    Ok(LoopbackPeer { dialer })
}

/// Node-side half of one loopback connection: the production handshake, then
/// the production dispatch loop. `Message::Tx` is forwarded into the ingress
/// channel with the real lease-stamped source — the one seam the production
/// listener has not wired yet (see the module docs).
fn serve_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    lease: &PeerLease,
    admission: &Arc<TxAdmission>,
    ingress_tx: &Sender<InboundTx>,
    stop: &Arc<AtomicBool>,
    magic: Magic,
) {
    let stream = stream;
    if stream.set_read_timeout(Some(READ_POLL)).is_err() {
        return;
    }
    let mut peer = Peer::new(stream, magic);
    let deadline = Instant::now() + HANDSHAKE_DEADLINE;
    if run_inbound_handshake(&mut peer, 1, 0, lease, None, deadline).is_err() {
        return;
    }
    let _ = peer.stream.set_read_timeout(Some(READ_POLL));
    loop {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        match read_message(&mut peer.stream, magic) {
            Ok((message, _raw)) => {
                if let Message::Tx(tx) = message {
                    let source = lease.source(peer_addr);
                    let _ = ingress_tx.try_send(InboundTx::new(tx, source));
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
                    Some(admission.as_ref()),
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
fn dial_handshake(dialer: &TcpStream, magic: Magic) -> anyhow::Result<()> {
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

/// True when one of `frames` requests `txid` with `getdata`.
fn requests_tx(frames: &[Message], txid: &Txid) -> bool {
    frames.iter().any(|message| match message {
        Message::GetData(items) => items.iter().any(|item| match item {
            Inventory::Transaction(hash) => hash.as_byte_array() == txid.as_bytes(),
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

/// Full path under test: funded node state, spawned ingress consumer (which
/// also starts the production relay worker), and a source + bystander
/// loopback peer pair with completed handshakes.
struct Harness {
    /// Kept alive for the whole test body: the node holds storage handles
    /// under this data directory.
    _dir: tempfile::TempDir,
    state: NodeState,
    magic: Magic,
    admission: Arc<TxAdmission>,
    mining: Arc<RecordingMining>,
    shutdown: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    source: LoopbackPeer,
    bystander: LoopbackPeer,
}

impl Harness {
    /// Builds one harness. `source_marker`/`bystander` funding is keyed by
    /// marker so concurrent tests never share prevouts.
    fn build(source_marker: u8) -> anyhow::Result<Self> {
        let (state, dir) = open_node()?;
        let magic = Magic::from_bytes(state.config().p2p_magic);
        let gateway = state.mempool_gateway();
        let admission = Arc::new(TxAdmission::new(Arc::clone(&gateway)));

        let (ingress_tx, ingress_rx) = crossbeam_channel::bounded::<InboundTx>(64);
        let mining = Arc::new(RecordingMining::default());
        let mining_control: Arc<dyn MiningControl> = Arc::<RecordingMining>::clone(&mining);
        let shutdown = Arc::new(AtomicBool::new(false));
        // Detached: the consumer exits when the shutdown flag rises or the
        // ingress channel disconnects.
        spawn_tx_ingress_consumer(
            &state,
            Arc::clone(&gateway),
            mining_control,
            Arc::clone(&shutdown),
            Arc::new(Mutex::new(ingress_rx)),
            Arc::clone(&admission),
        )?;

        let wiring = PeerWiring {
            magic,
            peer_table: state.peer_table(),
            ingress_tx,
            stop: Arc::new(AtomicBool::new(false)),
        };

        fund_utxo(&state, parent_txid(source_marker), 50_000)?;

        let source = open_loopback_peer(&wiring, Arc::clone(&admission), "source")?;
        let bystander = open_loopback_peer(&wiring, Arc::clone(&admission), "bystander")?;
        dial_handshake(&source.dialer, magic)?;
        dial_handshake(&bystander.dialer, magic)?;

        Ok(Self {
            _dir: dir,
            state,
            magic,
            admission,
            mining,
            shutdown,
            stop: wiring.stop,
            source,
            bystander,
        })
    }

    fn tx_in_mempool(&self, txid: &Txid) -> bool {
        self.state.mempool_gateway().read().contains_txid(txid)
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.shutdown.store(true, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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

    // The source announces; the node's dispatch + TxAdmission filter does not
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
        harness.admission.have_tx(Hash256::from(txid), false),
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
        harness.admission.is_rejected(Hash256::from(txid))
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
