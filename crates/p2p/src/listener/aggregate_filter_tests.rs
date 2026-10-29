//! A compact-filter request parked behind the node's aggregate outbound budget
//! over a real session. The aggregate's refusal is another connection's
//! traffic, so it is never charged to the request's five-second allowance; a
//! wait on the index, or on the connection's own queue, still is. The
//! listener decides which by recording why each pass stopped
//! (`ParkedFilter::last`), which only a session can show.

use bitcoin_rs_primitives::PeerEndpoint;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bitcoin::bip152::BlockTransactionsRequest;
use bitcoin::hashes::Hash as _;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::p2p::message_filter::{CFilter, GetCFilters};
use bitcoin_rs_primitives::{BlockHash, Header};

use super::getdata_pause_tests::{
    FAILSAFE, MAGIC, Served, TestResult, WriterKind, read_messages, shared_with_query,
};
use super::run_message_loop;
use crate::connection::{OutboundBudget, SharedOutboundBudget};
use crate::peer::{FilterHalt, ParkedFilter};
use crate::test_support::hog;
use crate::{
    ChainQuery, FilterRequest, FilterServing, InventoryServing, Message, Peer, PeerError,
    PeerLease, PeerState,
};

/// The block-production reserve of the test connections, in bytes.
const RESERVE: usize = 1_000;

/// Serves one `cfilter` behind the send-headroom gate once its range is
/// "published"; until then, and while the gate is closed, the request stays
/// pending and unchanged.
struct FilterChain {
    published: Arc<AtomicBool>,
    /// Closes this lease right after the gate refused, so a loop that read
    /// the request ends before its retry pass runs.
    cancel_after_refusal: Option<PeerLease>,
}

impl FilterChain {
    fn published() -> Self {
        Self {
            published: Arc::new(AtomicBool::new(true)),
            cancel_after_refusal: None,
        }
    }

    fn unpublished() -> Self {
        Self {
            published: Arc::new(AtomicBool::new(false)),
            cancel_after_refusal: None,
        }
    }
}

impl ChainQuery for FilterChain {
    fn stale_tip_announcement(
        &self,
        _: bitcoin_rs_primitives::Hash256,
        _: &[bitcoin_rs_primitives::Hash256],
    ) -> Option<crate::dispatch::StaleTipHeaders> {
        None
    }
    fn serve_compact_filters(
        &self,
        request: &FilterRequest,
        headroom: &dyn Fn() -> bool,
        send: &mut dyn FnMut(Message) -> Result<(), PeerError>,
    ) -> Result<FilterServing, PeerError> {
        if !headroom() {
            if let Some(lease) = &self.cancel_after_refusal {
                lease.cancel();
            }
            return Ok(FilterServing::Pending(request.clone()));
        }
        if !self.published.load(Ordering::Acquire) {
            return Ok(FilterServing::Pending(request.clone()));
        }
        send(Message::CFilter(CFilter {
            filter_type: 0,
            block_hash: bitcoin::BlockHash::all_zeros(),
            filter: vec![0],
        }))?;
        Ok(FilterServing::Done)
    }

    fn headers_after(&self, _: &[BlockHash], _: BlockHash, _: usize) -> Vec<Header> {
        Vec::new()
    }

    fn serve_inventory_blocks(
        &self,
        _: &[Inventory],
        _: Option<u64>,
        _: &dyn Fn() -> bool,
        _: &mut dyn FnMut(Message) -> Result<(), PeerError>,
    ) -> Result<InventoryServing, PeerError> {
        Ok(InventoryServing::default())
    }

    fn block_transactions(
        &self,
        _: &BlockTransactionsRequest,
        _: Option<u64>,
        _: &dyn Fn() -> bool,
    ) -> Result<Option<Message>, PeerError> {
        Ok(None)
    }
}

fn get_cfilters() -> Message {
    Message::GetCFilters(GetCFilters {
        filter_type: 0,
        start_height: 0,
        stop_hash: bitcoin::BlockHash::all_zeros(),
    })
}

/// An aggregate that refuses one production reservation once
/// [`refuse_reservations`] holds bytes in it.
fn small_aggregate() -> Arc<SharedOutboundBudget> {
    Arc::new(SharedOutboundBudget::with_limits(4 * RESERVE, 0))
}

fn local_budget() -> OutboundBudget {
    OutboundBudget::with_block_reserve(100, 1 << 20, RESERVE)
}

/// Fills the aggregate the way other connections' queued frames do, so that
/// one more reservation of [`RESERVE`] bytes is refused as `Shared`.
fn refuse_reservations(aggregate: &Arc<SharedOutboundBudget>) -> crate::connection::OutboundCredit {
    hog(aggregate, 3 * RESERVE + RESERVE / 2)
}

/// An aggregate refusal that outlasts the filter allowance is not charged:
/// the request keeps waiting, then is served once there is room.
///
/// Uses the real clock: the allowance is a constant of the request and the
/// session reads the monotonic clock itself, so no shorter wait can show it.
#[test]
fn a_filter_request_waits_out_an_aggregate_refusal_longer_than_its_allowance() -> TestResult {
    let aggregate = small_aggregate();
    let hold = refuse_reservations(&aggregate);
    let mut served = Served::start_on(
        shared_with_query(FilterChain::published()),
        local_budget(),
        Some(&aggregate),
        &WriterKind::Gated,
    )?;
    served.open_gate();

    served.client.send(&get_cfilters())?;
    std::thread::sleep(ParkedFilter::ALLOWANCE + Duration::from_secs(2));

    if let Ok(ended) = served.session_outcome(Duration::from_millis(50)) {
        return Err(format!("the session ended while the aggregate refused it: {ended:?}").into());
    }
    assert_eq!(
        served.budget.pending(),
        (0, 0),
        "nothing is reserved or queued while the aggregate refuses"
    );
    assert!(!served.lease.is_cancelled());

    drop(hold);
    let received = read_messages(&mut served.client, 1)?;
    assert!(
        matches!(&received[..], [Message::CFilter(_)]),
        "the parked request is served once there is room: {received:?}"
    );

    served.lease.cancel();
    let outcome = served.session_outcome(FAILSAFE)?;
    assert!(outcome.is_ok(), "{outcome:?}");
    Ok(())
}

/// After an aggregate refusal the request is charged again for a wait that is
/// not the aggregate's: here the index never publishes, so the five-second
/// allowance still ends the request. A request that kept the last refusal's
/// kind forever would wait for the index without limit.
#[test]
fn a_filter_request_waiting_on_the_index_after_an_aggregate_refusal_still_times_out() -> TestResult
{
    let aggregate = small_aggregate();
    let hold = refuse_reservations(&aggregate);
    let mut served = Served::start_on(
        shared_with_query(FilterChain::unpublished()),
        local_budget(),
        Some(&aggregate),
        &WriterKind::Gated,
    )?;
    served.open_gate();

    served.client.send(&get_cfilters())?;
    // At least two retry passes (one per socket poll) see the refusal.
    std::thread::sleep(Duration::from_millis(2_500));
    if let Ok(ended) = served.session_outcome(Duration::from_millis(50)) {
        return Err(format!("the session ended while the aggregate refused it: {ended:?}").into());
    }

    drop(hold);
    let outcome = served.session_outcome(FAILSAFE)?;
    assert!(
        matches!(&outcome, Err(PeerError::Io(error))
            if error.to_string().contains("publication timed out")),
        "{outcome:?}"
    );
    Ok(())
}

/// The pass that first parks the request records why it stopped, so even the
/// first interval is not charged when the aggregate refused it. The chain
/// closes the lease right after the refusal, which ends the loop before any
/// retry pass could record it instead.
#[test]
fn the_first_filter_pass_records_an_aggregate_refusal() -> TestResult {
    let aggregate = small_aggregate();
    let _hold = refuse_reservations(&aggregate);
    let (queue, _receiver) = crate::test_support::message_channel();
    let lease =
        PeerLease::new_with_budget(queue, true, local_budget()).with_shared_budget(&aggregate);
    let shared = shared_with_query(FilterChain {
        cancel_after_refusal: Some(lease.clone()),
        ..FilterChain::published()
    });
    let mut input = Vec::new();
    crate::wire::write_message(&mut input, MAGIC, &get_cfilters())?;
    let mut peer = Peer::new(io::Cursor::new(input), MAGIC);
    peer.state = PeerState::Ready;
    let addr = PeerEndpoint::from(([127, 0, 0, 1], 18_444));

    run_message_loop(
        &mut peer,
        addr,
        &lease,
        &shared,
        None,
    )?;

    assert!(lease.is_cancelled(), "the chain closed the lease");
    let parked = peer
        .pending_filter_request
        .as_ref()
        .ok_or("the refused request was not parked")?;
    assert_eq!(parked.last, FilterHalt::Shared);
    assert_eq!(parked.allowance, ParkedFilter::ALLOWANCE);
    Ok(())
}
