//! Header-presync admission gating over the real headers drain.
//!
//! A connection that is not synced can serve an endless chain of
//! valid-at-minimum-difficulty headers, and inserting it makes every later
//! reorganization cheaper than the honest chain. The drain therefore parks
//! a below-threshold batch in the connection's download-twice sync state
//! (`headerssync.h:57-149`, `headerssync.cpp:72-326`) and admits only
//! headers the committed phase has verified. These tests drive that path
//! end to end: inbound batches through the channel, outbound requests
//! through the peer lease.
//!
//! Every fixture chain is regtest-easy (`0x207fffff`), which mints exactly
//! two work units per header, so a floor of `2 * height + delta` places the
//! crossing on a chosen header.

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;

use super::behavior_5::deliver_headers;
use super::behavior_5::next_locator;
use bitcoin_rs_primitives::Hash256;

use crate::dispatch::MAX_HEADERS_RESPONSE;
use super::super::SyncBudget;
use super::super::default_sync_budget;
use super::super::headers_presync::HeadersSyncPhase;
use super::super::headers_presync::HeadersSyncState;
use super::*;

/// The wire page size a full `headers` message must fill to keep a
/// download-twice sync in its collection phase.
const PAGE: usize = MAX_HEADERS_RESPONSE;

/// Work units one regtest-easy header mints (measured, not assumed: see
/// the assertion in the first test).
const WORK_PER_HEADER: u64 = 2;

/// Mines one regtest-easy fixture header. Version 4: regtest raises the
/// minimum block version at heights 500, 1251, and 1351, and these fixture
/// chains are longer than all of them.
fn mine_header(prev_blockhash: BlockHash, height: u32) -> Header {
    use bitcoin_rs_primitives::CompactTarget;
    let mut merkle = [0_u8; 32];
    merkle[..4].copy_from_slice(&height.to_le_bytes());
    let mut header = Header {
        version: 4,
        prev_blockhash,
        merkle_root: Hash256::from_le_bytes(&merkle),
        time: GENESIS_TIME.saturating_add(height),
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce: height,
    };
    while !pow_met(
        header.bits.to_consensus(),
        Hash256::from(header.compute_hash()),
    ) {
        header.nonce = header.nonce.wrapping_add(1);
    }
    header
}

/// Mines a regtest-easy chain of `len` headers on `fork`, starting at
/// height `fork_height + 1`.
fn chain_on(fork: &Header, fork_height: u32, len: usize) -> Vec<Header> {
    let mut headers = Vec::with_capacity(len);
    let mut prev = fork.compute_hash();
    for index in 0..len {
        let offset = u32::try_from(index).unwrap_or(u32::MAX);
        let header = mine_header(prev, fork_height + offset + 1);
        prev = header.compute_hash();
        headers.push(header);
    }
    headers
}

/// The total proof-of-work a fixture chain carries.
fn chain_work(headers: &[Header]) -> ChainWork {
    headers.iter().fold(ChainWork::ZERO, |total, header| {
        total + bitcoin_rs_chain::block_work(header)
    })
}

/// One presync fixture: its fork header, the executor, its inbound-header
/// channel, and its peer table.
type PresyncFixture = (
    Header,
    BlockSync,
    crossbeam_channel::Sender<InboundHeaders>,
    Arc<PeerTable>,
);

/// A fixture whose committed-work floor is caller-chosen, draining through
/// the real header path.
fn presync_fixture(minimum_work: ChainWork) -> Result<PresyncFixture, Box<dyn std::error::Error>> {
    let mut tree = BlockTree::new();
    let genesis = genesis_header();
    tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
    let harness =
        SyncHarness::with_chain_work(tree, crate::sync::syncing_ibd_latch(), minimum_work);
    install_budget(
        &harness.sync,
        SyncBudget {
            max_pending_blocks: 0,
            ..default_sync_budget(Network::Regtest)
        },
    );
    Ok((
        genesis,
        harness.sync,
        harness.inbound_headers_tx,
        harness.peers,
    ))
}

/// A registered connection with a message sink.
fn connect(
    peers: &Arc<PeerTable>,
    port: u16,
    start_height: i32,
) -> (SocketAddr, PeerLease, crossbeam_channel::Receiver<Message>) {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let (tx, rx) = unbounded::<Message>();
    let lease = PeerLease::new(tx);
    peers.register(addr, lease.clone());
    peers.publish_info(addr, &lease, synthetic_peer(addr, start_height));
    (addr, lease, rx)
}

/// The number of nodes the block tree holds, so "nothing was admitted" is
/// a count, not a feeling: header admission inserts `HeaderValid` nodes and
/// never moves the applied tip.
fn tree_node_count(sync: &BlockSync) -> usize {
    sync.chain.block_tree().len()
}

/// The sync state a connection currently owns, if any.
fn with_sync_state<T>(
    sync: &BlockSync,
    source: PeerSource,
    read: impl FnOnce(&HeadersSyncState) -> T,
) -> Option<T> {
    sync.scheduler.lock().headers_sync.get(&source).map(read)
}

fn sync_phase(sync: &BlockSync, source: PeerSource) -> Option<HeadersSyncPhase> {
    with_sync_state(sync, source, HeadersSyncState::phase)
}

/// More headers than one wire page, so the second batch's fork point is a
/// header the sync state buffered — never the tree. A routing bug that
/// re-derives the anchor per batch shows up here as the honest peer being
/// re-requested from and the second batch falling into admission.
#[test]
fn low_work_headers_do_not_reach_block_tree() -> Result<(), Box<dyn std::error::Error>> {
    let floor = ChainWork::from(WORK_PER_HEADER * u64::try_from(4 * PAGE).unwrap_or(u64::MAX));
    let (genesis, sync, inbound_headers_tx, peers) = presync_fixture(floor)?;
    let (addr, lease, rx) = connect(&peers, 9701, 100_000);
    let source = current_source(&peers, addr);
    sync.tick();
    assert!(matches!(rx.try_recv()?, Message::GetHeaders(_)));

    let chain = chain_on(&genesis, 0, 2 * PAGE + 500);
    assert_eq!(
        bitcoin_rs_chain::block_work(&chain[0]),
        ChainWork::from(WORK_PER_HEADER),
        "the fixture's work-per-header constant must hold"
    );
    assert!(
        chain_work(&chain) < floor,
        "the fixture chain must stay below the assumed-work floor"
    );
    deliver_headers(&inbound_headers_tx, chain[..PAGE].to_vec(), source)?;
    sync.tick();

    assert_eq!(
        tree_node_count(&sync),
        1,
        "a full page below the floor must not reach the tree"
    );
    let locator = next_locator(&rx)
        .ok_or_else(|| std::io::Error::other("the presync continuation getheaders was not sent"))?;
    assert_eq!(
        locator.first().copied(),
        Some(Hash256::from(chain[PAGE - 1].compute_hash()).to_le_bytes()),
        "the continuation must resume from the collected cursor"
    );

    // The second page forks off buffered, uncommitted headers: it must
    // route into the live state, not into the tree-anchored admission path.
    deliver_headers(&inbound_headers_tx, chain[PAGE..2 * PAGE].to_vec(), source)?;
    sync.tick();

    assert_eq!(
        tree_node_count(&sync),
        1,
        "the continuation page must not reach the tree either"
    );
    assert_eq!(
        sync_phase(&sync, source),
        Some(HeadersSyncPhase::Presync),
        "a live collection must keep the state"
    );
    let cursor = with_sync_state(&sync, source, |state| state.next_locator()[0].to_le_bytes());
    assert_eq!(
        cursor,
        Some(Hash256::from(chain[2 * PAGE - 1].compute_hash()).to_le_bytes()),
        "the second page must extend the same state's cursor"
    );
    assert!(
        !lease.is_cancelled() && peers.is_connected(addr),
        "collecting a low-work chain must not blame the peer"
    );
    Ok(())
}

/// Crossing the assumed-work floor flips the sync to its second pass: the
/// chain is re-requested from the fork point, every header is checked
/// against the salted commitments, and only then does admission run — in
/// the order the wire delivered.
#[test]
fn sufficient_work_chain_syncs_presync_then_redownload() -> Result<(), Box<dyn std::error::Error>> {
    // One full page whose last header reaches the floor exactly: the sync
    // commits at the page boundary and the replay is that same page.
    let chain = chain_on(&genesis_header(), 0, PAGE);
    let threshold = ChainWork::from(WORK_PER_HEADER * u64::try_from(PAGE).unwrap_or(u64::MAX));
    assert_eq!(
        chain_work(&chain),
        threshold,
        "the floor must sit exactly on the page's last header"
    );
    let (genesis, sync, inbound_headers_tx, peers) = presync_fixture(threshold)?;
    let (addr, _lease, rx) = connect(&peers, 9702, 100_000);
    let source = current_source(&peers, addr);
    sync.tick();
    assert!(matches!(rx.try_recv()?, Message::GetHeaders(_)));

    deliver_headers(&inbound_headers_tx, chain.clone(), source)?;
    sync.tick();

    // The crossing header committed the sync: it now asks for the whole
    // chain again, from the fork point, and still admits nothing.
    assert_eq!(
        sync_phase(&sync, source),
        Some(HeadersSyncPhase::Redownload),
        "crossing must flip the sync to its second pass"
    );
    assert_eq!(
        tree_node_count(&sync),
        1,
        "crossing the floor must not admit the collected pass"
    );
    // The second pass restarts at the fork point, and the transition
    // request must reach the wire: Core retires the request this batch
    // answered and always sends the sync's own locator when the sync
    // wants more (`net_processing.cpp:2932-2943`). The phase transition
    // re-anchors at the fork — a locator identical to the one still
    // pending — and the dedup must not silence it against the pre-answer
    // deadline; otherwise no second pass is ever requested and expiry
    // later blames the connection that did respond.
    assert_eq!(
        next_locator(&rx).map(|locator| locator.first().copied()),
        Some(Some(Hash256::from(genesis.compute_hash()).to_le_bytes())),
        "the second pass must be requested on the wire from the fork point",
    );
    assert_eq!(
        with_sync_state(&sync, source, |state| state.next_locator()[0]),
        Some(Hash256::from(genesis.compute_hash())),
        "the second pass must restart at the fork point"
    );

    // Serve the second pass as the answer to that request: its last
    // header crosses the floor inside the state, which releases the whole
    // verified chain in wire order.
    let chain_last = chain[PAGE - 1].compute_hash();
    deliver_headers(&inbound_headers_tx, chain, source)?;
    sync.tick();
    let tree = sync.chain.block_tree();
    assert_eq!(
        tree.height_of_hash(Hash256::from(chain_last)),
        Some(u32::try_from(PAGE).unwrap_or(u32::MAX)),
        "the committed replay must admit the whole chain in wire order (len {})",
        tree.len(),
    );
    drop(tree);
    assert_eq!(
        sync_phase(&sync, source),
        None,
        "a spent sync state must be retired"
    );
    Ok(())
}

/// One substituted header must diverge from the salted commitments the
/// first pass collected, and the connection that served it is the faulty
/// one: disconnect, and nothing admitted.
#[test]
fn a_substituted_redownload_header_disconnects_the_connection()
-> Result<(), Box<dyn std::error::Error>> {
    // A page plus 500 headers whose floor crosses on the last of them:
    // the whole chain is committed at once and the replay restarts at the
    // fork point.
    let chain = chain_on(&genesis_header(), 0, PAGE + 500);
    let threshold = chain_work(&chain);
    let (_genesis, sync, inbound_headers_tx, peers) = presync_fixture(threshold)?;
    let (addr, lease, rx) = connect(&peers, 9703, 100_000);
    let source = current_source(&peers, addr);
    sync.tick();
    assert!(matches!(rx.try_recv()?, Message::GetHeaders(_)));

    deliver_headers(&inbound_headers_tx, chain[..PAGE].to_vec(), source)?;
    sync.tick();
    deliver_headers(&inbound_headers_tx, chain[PAGE..].to_vec(), source)?;
    sync.tick();
    assert_eq!(
        sync_phase(&sync, source),
        Some(HeadersSyncPhase::Redownload),
        "the fixture must reach its second pass"
    );

    // Replay with one valid-but-different header at a height that actually
    // carries a salted commitment, chosen from the state's own salt so the
    // substitution is guaranteed to be seen.
    let Some(commitment_height) =
        with_sync_state(&sync, source, |state| state.first_commitment_height(2))
    else {
        unreachable!("the sync state is live");
    };
    let chain_len = chain.len();
    let commitment_index = usize::try_from(commitment_height).unwrap_or(usize::MAX);
    assert!(commitment_index <= chain_len);
    let original_hash = chain[commitment_index - 1].compute_hash();
    let mut rogue = test_header(
        chain[commitment_index - 2].compute_hash(),
        commitment_height,
    );
    let original_bit = with_sync_state(&sync, source, |state| {
        state.commitment_bit(Hash256::from(original_hash))
    })
    .unwrap_or_else(|| unreachable!("the sync state is live"));
    loop {
        let hash = Hash256::from(rogue.compute_hash());
        let bit = with_sync_state(&sync, source, |state| state.commitment_bit(hash))
            .unwrap_or_else(|| unreachable!("the sync state is live"));
        if hash != Hash256::from(original_hash)
            && bit != original_bit
            && pow_met(rogue.bits.to_consensus(), hash)
        {
            break;
        }
        rogue.nonce = rogue.nonce.wrapping_add(1);
    }
    let mut substituted = chain;
    substituted[commitment_index - 1] = rogue;

    deliver_headers(&inbound_headers_tx, substituted, source)?;
    sync.tick();

    assert!(
        lease.is_cancelled() || !peers.is_connected(addr),
        "a salted-commitment divergence must cost the connection its lease"
    );
    assert_eq!(
        tree_node_count(&sync),
        1,
        "the mismatching batch must admit nothing"
    );
    assert_eq!(
        sync_phase(&sync, source),
        None,
        "the punished sync state must be retired"
    );
    Ok(())
}

/// A REDOWNLOAD release must continue from the state's own cursor. Core
/// sends the sync's locator whenever the sync wants more, independent of
/// whether the batch returned headers (`net_processing.cpp:2933-2943`).
/// The state's cursor sits up to `redownload_buffer_size` headers deeper
/// than the release point, so a continuation anchored at the release
/// point — where the tree stops — fails the state's continuity check and
/// restarts the whole sync. The fixture replays past one regtest buffer
/// page (7,017) so the release path is genuinely exercised.
#[test]
fn redownload_release_continues_from_the_state_cursor() -> Result<(), Box<dyn std::error::Error>> {
    // Five pages: the work floor crosses on the chain's last header, and
    // the replay overflows the regtest buffer on its fourth page — three
    // pages before the chain runs out, so the release is a buffer
    // overflow, not the completion.
    let chain = chain_on(&genesis_header(), 0, 5 * PAGE);
    let threshold = ChainWork::from(WORK_PER_HEADER * u64::try_from(5 * PAGE).unwrap_or(u64::MAX));
    assert_eq!(
        chain_work(&chain),
        threshold,
        "the floor must sit exactly on the chain's last header"
    );
    let (_genesis, sync, inbound_headers_tx, peers) = presync_fixture(threshold)?;
    let (addr, _lease, rx) = connect(&peers, 9704, 100_000);
    let source = current_source(&peers, addr);
    sync.tick();
    assert!(matches!(rx.try_recv()?, Message::GetHeaders(_)));

    for page in 0..5 {
        deliver_headers(
            &inbound_headers_tx,
            chain[page * PAGE..(page + 1) * PAGE].to_vec(),
            source,
        )?;
        sync.tick();
    }
    assert_eq!(
        sync_phase(&sync, source),
        Some(HeadersSyncPhase::Redownload),
        "the fixture must reach its second pass"
    );

    // Replay the same chain. The first three pages only fill the buffer;
    // the fourth overflows it and releases the retired prefix.
    for page in 0..3 {
        deliver_headers(
            &inbound_headers_tx,
            chain[page * PAGE..(page + 1) * PAGE].to_vec(),
            source,
        )?;
        sync.tick();
    }
    while rx.try_recv().is_ok() {}
    deliver_headers(
        &inbound_headers_tx,
        chain[3 * PAGE..4 * PAGE].to_vec(),
        source,
    )?;
    sync.tick();
    assert_eq!(
        tree_node_count(&sync),
        4 * PAGE - 7_017 + 1,
        "the overflow release must retire exactly the buffer's excess"
    );
    let locator = next_locator(&rx)
        .ok_or_else(|| std::io::Error::other("the release continuation getheaders was not sent"))?;
    assert_eq!(
        locator.first().copied(),
        Some(Hash256::from(chain[4 * PAGE - 1].compute_hash()).to_le_bytes()),
        "the continuation must leave from the state's redownload cursor, not the release point",
    );

    // The last page crosses the replay's own work floor: the state
    // releases everything left and retires.
    deliver_headers(
        &inbound_headers_tx,
        chain[4 * PAGE..5 * PAGE].to_vec(),
        source,
    )?;
    sync.tick();
    assert_eq!(
        sync_phase(&sync, source),
        None,
        "a completed second pass must retire the state"
    );
    assert_eq!(
        tree_node_count(&sync),
        5 * PAGE + 1,
        "the whole replayed chain must be admitted in wire order"
    );
    Ok(())
}

/// A batch that breaks continuity mid-way must be rejected whole: Core
/// checks every header of the batch against the running cursor
/// (`CheckHeadersAreContinuous`, `net_processing.cpp:2915-2924`), so a
/// batch whose tail forks elsewhere cannot sum its disconnected branch
/// work into the crossing decision.
#[test]
fn a_midbatch_continuity_break_spends_the_sync() -> Result<(), Box<dyn std::error::Error>> {
    let floor =
        ChainWork::from(WORK_PER_HEADER * u64::try_from(2 * PAGE + 500).unwrap_or(u64::MAX));
    let (genesis, sync, inbound_headers_tx, peers) = presync_fixture(floor)?;
    let (addr, lease, _rx) = connect(&peers, 9705, 100_000);
    let source = current_source(&peers, addr);

    let chain = chain_on(&genesis, 0, 2 * PAGE);
    deliver_headers(&inbound_headers_tx, chain[..PAGE].to_vec(), source)?;
    sync.tick();
    assert_eq!(
        sync_phase(&sync, source),
        Some(HeadersSyncPhase::Presync),
        "the fixture must collect below the floor"
    );

    // A full page whose last header chains onto nothing the cursor knows:
    // the batch head is honest, so only a per-header check can see it.
    let mut midbreak = chain[PAGE..2 * PAGE - 1].to_vec();
    midbreak.push(mine_header(
        BlockHash(Hash256::from_le_bytes(&[0xa5; 32])),
        u32::try_from(2 * PAGE).unwrap_or(u32::MAX),
    ));
    deliver_headers(&inbound_headers_tx, midbreak, source)?;
    sync.tick();

    assert_eq!(
        sync_phase(&sync, source),
        None,
        "a batch that breaks continuity mid-way must spend the sync"
    );
    assert_eq!(
        tree_node_count(&sync),
        1,
        "the disconnected branch must not reach the tree"
    );
    assert!(
        !lease.is_cancelled() && peers.is_connected(addr),
        "a lost continuation is possibly benign: the connection stays"
    );
    Ok(())
}

/// A header carried by a delivered body is not a wire `headers` message,
/// and Core feeds the download-twice state only from processed `headers`
/// messages (`net_processing.cpp:2915-2924`). A forwarded one-header page
/// must therefore leave a live state exactly as it found it: not
/// finalize it as a short page, not advance its cursor, not spend it on a
/// continuity break.
#[test]
fn a_forwarded_body_header_leaves_the_live_sync_state_alone()
-> Result<(), Box<dyn std::error::Error>> {
    let floor = ChainWork::from(WORK_PER_HEADER * u64::try_from(4 * PAGE).unwrap_or(u64::MAX));
    let (genesis, sync, inbound_headers_tx, peers) = presync_fixture(floor)?;
    let (addr, lease, rx) = connect(&peers, 9706, 100_000);
    let source = current_source(&peers, addr);

    let chain = chain_on(&genesis, 0, PAGE);
    deliver_headers(&inbound_headers_tx, chain[..PAGE].to_vec(), source)?;
    sync.tick();
    assert_eq!(
        sync_phase(&sync, source),
        Some(HeadersSyncPhase::Presync),
        "the fixture must collect below the floor"
    );
    let cursor = with_sync_state(&sync, source, |state| state.next_locator()[0].to_le_bytes());
    // The collection continuation from the setup page is expected; retire
    // it so the wire is quiet before the forwarded delivery.
    while rx.try_recv().is_ok() {}

    // The same connection delivers a body whose embedded header is
    // forwarded through the drain: one header, not a wire response,
    // chaining off the in-tree fork below the floor.
    inbound_headers_tx
        .send(InboundHeaders {
            headers: vec![mine_header(genesis.compute_hash(), 5_000)],
            source: Some(source),
            wire_response: false,
            body_fetch_owned: false,
        })
        .map_err(|err| std::io::Error::other(err.to_string()))?;
    sync.tick();

    assert_eq!(
        sync_phase(&sync, source),
        Some(HeadersSyncPhase::Presync),
        "a body-carried header must not touch the wire sync's state"
    );
    assert_eq!(
        with_sync_state(&sync, source, |state| state.next_locator()[0].to_le_bytes()),
        cursor,
        "the forwarded header must not advance the state's cursor"
    );
    assert_eq!(
        tree_node_count(&sync),
        1,
        "a header below the floor must not reach the tree through a body either"
    );
    assert!(
        rx.try_recv().is_err() && !lease.is_cancelled() && peers.is_connected(addr),
        "a forwarded header sends nothing and blames no one"
    );
    Ok(())
}
