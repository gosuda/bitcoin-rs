use crate::{PeerInfo, PeerLease, PeerRemote, PeerSource, PeerTable};
use core::fmt::Display;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

pub(crate) trait OrFail<T> {
    #[track_caller]
    fn or_fail(self, context: &str) -> T;
}

impl<T, E: Display> OrFail<T> for Result<T, E> {
    fn or_fail(self, context: &str) -> T {
        match self {
            Ok(value) => value,
            Err(error) => panic!("{context}: {error}"),
        }
    }
}

impl<T> OrFail<T> for Option<T> {
    fn or_fail(self, context: &str) -> T {
        match self {
            Some(value) => value,
            None => panic!("{context}"),
        }
    }
}

pub(crate) type TestResult = Result<(), Box<dyn std::error::Error>>;

pub(crate) trait QueuedMessages {
    fn try_message(&self) -> Result<crate::Message, crossbeam_channel::TryRecvError>;

    fn drain_messages(&self) -> Vec<crate::Message> {
        std::iter::from_fn(|| self.try_message().ok()).collect()
    }
}

impl QueuedMessages for crossbeam_channel::Receiver<crate::QueuedFrame> {
    fn try_message(&self) -> Result<crate::Message, crossbeam_channel::TryRecvError> {
        self.try_recv().map(crate::QueuedFrame::into_message)
    }
}

pub(crate) struct MessageReceiver(crossbeam_channel::Receiver<crate::QueuedFrame>);

impl MessageReceiver {
    pub(crate) fn try_recv(&self) -> Result<crate::Message, crossbeam_channel::TryRecvError> {
        self.0.try_message()
    }

    pub(crate) fn try_iter(&self) -> impl Iterator<Item = crate::Message> {
        self.0.try_iter().map(crate::QueuedFrame::into_message)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

pub(crate) fn message_channel() -> (
    crossbeam_channel::Sender<crate::QueuedFrame>,
    MessageReceiver,
) {
    let (sender, receiver) = crossbeam_channel::unbounded();
    (sender, MessageReceiver(receiver))
}

pub(crate) fn hog(
    aggregate: &std::sync::Arc<crate::connection::SharedOutboundBudget>,
    bytes: usize,
) -> crate::connection::OutboundCredit {
    let (queue, _receiver) = message_channel();
    let other = crate::PeerLease::new(queue).with_shared_budget(aggregate);
    match other.try_reserve_reply(bytes) {
        Ok(credit) => credit,
        Err(refusal) => panic!("the hog's charge was refused: {refusal:?}"),
    }
}

pub(crate) fn message_channel_bounded(
    capacity: usize,
) -> (
    crossbeam_channel::Sender<crate::QueuedFrame>,
    MessageReceiver,
) {
    let (sender, receiver) = crossbeam_channel::bounded(capacity);
    (sender, MessageReceiver(receiver))
}

pub(crate) enum Inbound {
    Bytes(Vec<u8>),
    Stall(std::io::ErrorKind),
}

pub(crate) struct StallingStream {
    script: std::collections::VecDeque<Inbound>,
    pub(crate) written: Vec<u8>,
}

impl StallingStream {
    pub(crate) fn new(script: impl IntoIterator<Item = Inbound>) -> Self {
        Self {
            script: script.into_iter().collect(),
            written: Vec::new(),
        }
    }
}

impl std::io::Read for StallingStream {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        match self.script.pop_front() {
            None => Ok(0),
            Some(Inbound::Stall(kind)) => Err(kind.into()),
            Some(Inbound::Bytes(mut bytes)) => {
                let take = bytes.len().min(buffer.len());
                buffer[..take].copy_from_slice(&bytes[..take]);
                if take < bytes.len() {
                    self.script
                        .push_front(Inbound::Bytes(bytes.split_off(take)));
                }
                Ok(take)
            }
        }
    }
}

impl std::io::Write for StallingStream {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.written.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(crate) fn current_source(peer_table: &Arc<PeerTable>, addr: PeerRemote) -> PeerSource {
    peer_table.lease(addr).map_or_else(
        || panic!("test peer {addr} must be connected"),
        |lease| lease.source(addr.endpoint()),
    )
}

pub(crate) fn synthetic_peer(addr: PeerRemote, start_height: i32) -> PeerInfo {
    PeerInfo {
        addr,
        endpoint: addr.endpoint(),
        network: addr.network().into(),
        version: 70_016,
        wtxid_relay: false,
        relay_transactions: true,
        compact_block_relay: false,
        send_headers: false,
        services: bitcoin::p2p::ServiceFlags::NETWORK.to_u64()
            | bitcoin::p2p::ServiceFlags::WITNESS.to_u64(),
        user_agent: String::from("/test/"),
        start_height,
        best_known_height: start_height,
        conn_time: 0,
        inbound: false,
        addr_bind: crate::TransportRemote::new(
            addr.endpoint()
                .and_then(crate::PeerEndpoint::socket_addr)
                .unwrap_or_else(|| panic!("expected IP fixture")),
        ),
        time_offset: 0,
        counters: std::sync::Arc::new(crate::PeerCounters::default()),
        transport: crate::TransportProtocol::V1,
    }
}

pub(crate) fn test_addr(
    base_port: usize,
    idx: usize,
) -> Result<PeerRemote, Box<dyn std::error::Error>> {
    Ok(PeerRemote::Endpoint(crate::PeerEndpoint::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        u16::try_from(base_port + idx)?,
    )))
}

pub(crate) fn connect_peer(
    peer_table: &Arc<PeerTable>,
    info: PeerInfo,
) -> crate::test_support::MessageReceiver {
    let (tx, rx) = crate::test_support::message_channel();
    let lease = PeerLease::new(tx);
    let Some(endpoint) = info.endpoint else {
        panic!("identified peer endpoint");
    };
    peer_table.register(endpoint, lease.clone());
    peer_table.publish_info(endpoint, &lease, info);
    rx
}
