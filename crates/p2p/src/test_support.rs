//! Shared unit-test helpers.

use core::fmt::Display;

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

/// Reads a connection's outbound queue as plain messages.
///
/// The queue carries [`crate::QueuedFrame`]s: each frame owns its charge
/// against the connection and the node aggregate until it drops, so taking
/// a message out here also returns the charge, as the writer's drop does.
pub(crate) trait QueuedMessages {
    /// The next queued message, or why there is none.
    fn try_message(&self) -> Result<crate::Message, crossbeam_channel::TryRecvError>;

    /// Every message queued now, in order.
    fn drain_messages(&self) -> Vec<crate::Message> {
        std::iter::from_fn(|| self.try_message().ok()).collect()
    }
}

impl QueuedMessages for crossbeam_channel::Receiver<crate::QueuedFrame> {
    fn try_message(&self) -> Result<crate::Message, crossbeam_channel::TryRecvError> {
        self.try_recv().map(crate::QueuedFrame::into_message)
    }
}

/// A connection's outbound queue read as plain messages: the receiving end of
/// [`message_channel`].
///
/// Taking a message out drops its frame, which returns the frame's charge
/// exactly as the writer's drop does, so a test that reads here keeps the
/// budgets as a real writer would.
pub(crate) struct MessageReceiver(crossbeam_channel::Receiver<crate::QueuedFrame>);

impl MessageReceiver {
    /// The next queued message, or why there is none.
    pub(crate) fn try_recv(&self) -> Result<crate::Message, crossbeam_channel::TryRecvError> {
        self.0.try_message()
    }

    /// Every message queued now, in order.
    pub(crate) fn try_iter(&self) -> impl Iterator<Item = crate::Message> {
        self.0.try_iter().map(crate::QueuedFrame::into_message)
    }

    /// Whether nothing is queued.
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// An unbounded outbound queue for a [`crate::PeerLease`] whose receiving end
/// reads plain messages.
pub(crate) fn message_channel() -> (
    crossbeam_channel::Sender<crate::QueuedFrame>,
    MessageReceiver,
) {
    let (sender, receiver) = crossbeam_channel::unbounded();
    (sender, MessageReceiver(receiver))
}

/// Takes `bytes` of `aggregate` the way another connection's queued frames
/// do, and holds them until the returned credit drops.
///
/// PRE: `bytes` fits in the aggregate and in a fresh connection's own bounds.
/// POST: the aggregate's pending bytes rise by `bytes`; dropping the credit
/// returns them and wakes every session waiting on the aggregate.
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

/// A bounded outbound queue (`capacity` frames) whose receiving end reads
/// plain messages. A send into a full queue cancels the lease, as in
/// production.
pub(crate) fn message_channel_bounded(
    capacity: usize,
) -> (
    crossbeam_channel::Sender<crate::QueuedFrame>,
    MessageReceiver,
) {
    let (sender, receiver) = crossbeam_channel::bounded(capacity);
    (sender, MessageReceiver(receiver))
}

/// One scripted step of a [`StallingStream`].
pub(crate) enum Inbound {
    /// Bytes the peer has delivered; a short read leaves the rest queued.
    Bytes(Vec<u8>),
    /// A read that fails with this kind, as a socket poll timeout does.
    Stall(std::io::ErrorKind),
}

/// Serves scripted inbound bytes with stalls between them, the way a peer
/// socket reads when a frame stops arriving part-way; records writes.
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
