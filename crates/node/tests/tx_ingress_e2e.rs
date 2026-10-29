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
    BlockTemplateRequest, BlockTemplateResult, BlockValidationResult, FakeMiningControl,
    MiningControl, MiningControlError, MiningInfo,
};
use bitcoin_rs_node::state::NodeState;
use bitcoin_rs_node::tx_ingress::spawn_tx_ingress_consumer;
use bitcoin_rs_node::{Network, NodeConfig};
use bitcoin_rs_p2p::PeerRole;
use bitcoin_rs_p2p::dispatch::dispatch_inbound_full;
use bitcoin_rs_p2p::handshake::{run_inbound_handshake, version_message};
use bitcoin_rs_p2p::wire::{PeerError, read_message, write_message};
use bitcoin_rs_p2p::{
    DEFAULT_TX_RELAY_QUEUE_CAPACITY, InboundBody, InboundTx, Message, Peer, PeerLease,
    PeerRelaySink, TxRelayQueue, spawn_tx_relay_worker,
};
use bitcoin_rs_primitives::{
    Amount, BlockPayload, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid,
    Witness,
};
use bitcoin_rs_utxo::contract::{BlockChanges, UtxoAdd};
use crossbeam_channel::Sender;

const READ_POLL: Duration = Duration::from_millis(200);
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(10);
const ABSENCE_WINDOW: Duration = Duration::from_millis(700);
const RELAY_ABSENCE_WINDOW: Duration = Duration::from_secs(31);
const OBSERVE_TIMEOUT: Duration = Duration::from_secs(35);
const COLLECT_SLICE: Duration = Duration::from_millis(200);

fn parent_txid(marker: u8) -> Txid {
    Txid::from(Hash256::from_le_bytes(&[marker; 32]))
}

fn tx_inv(txid: &Txid) -> Message {
    Message::Inv(vec![Inventory::Transaction(
        bitcoin::hashes::Hash::from_byte_array(*txid.as_bytes()),
    )])
}

fn open_node() -> anyhow::Result<(NodeState, tempfile::TempDir)> {
    let dir = tempfile::tempdir()?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    let state = NodeState::open(config, None)?;
    Ok((state, dir))
}

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
    bitcoin_rs_utxo::contract::commit_block_changes(
        &state.chainstate().utxo_handle(),
        &changes,
        &Hash256::from_le_bytes(&[0xBB; 32]),
    )
    .map_err(|error| anyhow!("utxo commit failed: {error}"))
}

fn spending_tx(parent: Txid, output_value: u64) -> Tx {
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(parent, 0),
            script_sig: Script::new(),
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
        _payload: BlockPayload,
    ) -> Result<BlockValidationResult, MiningControlError> {
        Err(MiningControlError::Failed(
            "not implemented".to_owned().into(),
        ))
    }

    fn submit_header(
        &self,
        _header: bitcoin_rs_primitives::Header,
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
        _request: bitcoin_rs_mining::GenerateRequest,
    ) -> Result<Vec<bitcoin_rs_mining::GeneratedBlock>, MiningControlError> {
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
) -> anyhow::Result<LoopbackPeer> {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let dialer = TcpStream::connect(listener.local_addr()?)?;
    let (accepted, peer_addr) = listener.accept()?;

    let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded::<bitcoin_rs_p2p::QueuedFrame>();
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
        wiring
            .peer_table
            .poll_transaction_requests(gateway.as_ref());
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
                    Some(gateway.as_ref()),
                    &|| true,
                    &|| true,
                    &mut send,
                    &mut |_| {},
                    &mut |items| {
                        wiring
                            .peer_table
                            .announce_transactions(lease.source_ip(peer_addr), &items);
                        wiring
                            .peer_table
                            .poll_transaction_requests(gateway.as_ref());
                    },
                );
            }
            Err(PeerError::Io(error))
                if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(_) => return,
        }
    }
}

fn dial_handshake(dialer: &TcpStream, magic: Magic, wtxid_relay: bool) -> anyhow::Result<()> {
    let mut stream = dialer
        .try_clone()
        .map_err(|error| anyhow!("dialer clone failed: {error}"))?;
    stream.set_read_timeout(Some(HANDSHAKE_DEADLINE))?;
    write_message(
        &mut stream,
        magic,
        &Message::Version(version_message(
            7,
            0,
            PeerRole::FullRelay,
            bitcoin::p2p::ServiceFlags::NETWORK | bitcoin::p2p::ServiceFlags::WITNESS,
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

fn write_frame(dialer: &TcpStream, magic: Magic, message: &Message) -> anyhow::Result<()> {
    let mut stream = dialer
        .try_clone()
        .map_err(|error| anyhow!("dialer clone failed: {error}"))?;
    write_message(&mut stream, magic, message)
        .map(|_| ())
        .map_err(|error| anyhow!("dialer write failed: {error}"))
}

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

fn collect_until_inv(dialer: &TcpStream, magic: Magic) -> anyhow::Result<Vec<Message>> {
    let deadline = Instant::now() + OBSERVE_TIMEOUT;
    loop {
        let frames = collect_frames(dialer, magic, deadline.min(Instant::now() + COLLECT_SLICE))?;
        if frames
            .iter()
            .any(|message| matches!(message, Message::Inv(_)))
        {
            return Ok(frames);
        }
        if Instant::now() >= deadline {
            bail!("delayed transaction inventory did not arrive");
        }
    }
}

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

struct Harness {
    state: NodeState,
    magic: Magic,
    gateway: Arc<MempoolGateway>,
    mining: Arc<FakeMiningControl>,
    shutdown: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    source: LoopbackPeer,
    bystander: LoopbackPeer,
    ingress: Option<std::thread::JoinHandle<()>>,
    relay: Option<std::thread::JoinHandle<()>>,
    relay_queue: TxRelayQueue,
    _dir: tempfile::TempDir,
}

impl Harness {
    fn build(source_marker: u8) -> anyhow::Result<Self> {
        let (state, dir) = open_node()?;
        let magic = Magic::from_bytes(state.config().p2p.magic);
        let gateway = state.mempool_gateway();

        let ingress_tx = state.inbound_tx_sender();
        let ingress_rx = state
            .take_inbound_tx_receiver()
            .ok_or_else(|| anyhow::anyhow!("inbound tx receiver already taken"))?;
        let (relay, relay_rx) = TxRelayQueue::new(DEFAULT_TX_RELAY_QUEUE_CAPACITY);
        let mining = FakeMiningControl::unavailable("not implemented");
        let mining_control: Arc<dyn MiningControl> = mining.clone();
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
            PeerRelaySink::new(harness.state.peer_table()),
            relay_rx,
            Arc::downgrade(&harness.gateway),
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

#[test]
fn full_relay_queue_does_not_block_peer_admission_or_mining_wake() -> anyhow::Result<()> {
    let (state, _dir) = open_node()?;
    fund_utxo(&state, parent_txid(0xDD), 50_000)?;
    let gateway = state.mempool_gateway();
    let (relay, _relay_rx) = TxRelayQueue::new(1);
    let pending = spending_tx(parent_txid(0xEE), 40_000);
    assert!(relay.announce(pending.txid(), pending.wtxid(), None, u64::MAX));
    let mining = Arc::new(RecordingMining::default());
    let mining_control: Arc<dyn MiningControl> = Arc::<RecordingMining>::clone(&mining);
    let shutdown = Arc::new(AtomicBool::new(false));
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
        Arc::clone(&shutdown),
        ingress_rx,
        relay.clone(),
    )?;

    let observed = ingress_tx
        .try_send(InboundBody::from(InboundTx::new(tx, source)))
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
fn accepted_peer_tx_is_admitted_and_relayed_excluding_the_source() -> anyhow::Result<()> {
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
    wait_until(OBSERVE_TIMEOUT, || harness.tx_in_mempool(&txid))
        .map_err(|_| anyhow!("admitted tx never reached the shared mempool gateway"))?;

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
fn below_min_relay_tx_is_rejected_recorded_and_never_relayed() -> anyhow::Result<()> {
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
    .map_err(|_| anyhow!("rejected tx never reached the recent-rejects cache"))?;
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
fn rejected_witness_keeps_an_honest_transaction_source() -> anyhow::Result<()> {
    if let Some(reason) = loopback_skip() {
        tracing::warn!(%reason, "skipping tx ingress e2e");
        return Ok(());
    }
    let harness = Harness::build(0xB1)?;
    let parent = parent_txid(0xB2);
    let witness_script = vec![0x51];
    let mut locking_script = vec![0x00, 0x20];
    locking_script
        .extend_from_slice(bitcoin::hashes::sha256::Hash::hash(&witness_script).as_byte_array());
    fund_utxo_script(&harness.state, parent, 50_000, locking_script)?;
    let mut valid = spending_tx(parent, 40_000);
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
fn orphan_parent_reuses_the_completed_childs_announcement_slot() -> anyhow::Result<()> {
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
