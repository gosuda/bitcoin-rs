//! Bitcoin Core `net:*` tracepoint payload mapping.
//!
//! [`inbound_message`] fires per checksum-valid wire message in the connection read
//! loop and during the handshake; [`outbound_message`] fires per write
//! attempt by the connection writer and during the handshake. Argument
//! positions and types follow Bitcoin Core's published ABI — see
//! `docs/tracing.md` and the node trace module's `probe_abi` table. Every
//! emitter no-ops unless the connection carries a [`NetTrace`], which only
//! the live inbound-accept and outbound-dial roots attach, and payload
//! preparation runs only while a consumer (bpftrace, BCC, DTrace) holds
//! the probe's semaphore, so an untraced or unattached run pays nothing.

use std::net::SocketAddr;

use crate::peer_info::PeerRole;
use crate::wire::Message;

/// Prepared arguments for the node-owned `net:*_message` probes.
pub type MessageTraceArgs = (i64, String, String, String, u64, *const u8);

/// Optional network instrumentation supplied by the composing node.
pub trait NetTraceSink: core::fmt::Debug + Send + Sync {
    /// Emits one inbound-message record, evaluating `prepare` only when needed.
    fn inbound_message(&self, prepare: &mut dyn FnMut() -> MessageTraceArgs);
    /// Emits one outbound-message record, evaluating `prepare` only when needed.
    fn outbound_message(&self, prepare: &mut dyn FnMut() -> MessageTraceArgs);
}

/// Per-connection identity for the `net:*` probe payloads.
///
/// Captured once where the connection direction and remote address are
/// known — the inbound accept path and the outbound dial — and carried by
/// the connection's [`crate::peer::Peer`] and writer thread. Probe-free
/// connections (tests, in-memory streams) carry none, keeping the probes
/// out of their binaries.
#[derive(Clone, Debug)]
pub(crate) struct NetTrace {
    sink: std::sync::Arc<dyn NetTraceSink>,
    /// Process-unique connection id (Core argument 1, `peerid`).
    node_id: u64,
    /// Remote address and port (Core argument 2).
    peer: SocketAddr,
    /// Core `ConnectionTypeAsString` label (Core argument 3).
    connection_type: &'static str,
}

impl NetTrace {
    /// Context for an accepted inbound connection.
    pub(crate) fn inbound(
        sink: std::sync::Arc<dyn NetTraceSink>,
        node_id: u64,
        peer: SocketAddr,
    ) -> Self {
        Self {
            sink,
            node_id,
            peer,
            connection_type: "inbound",
        }
    }

    /// Context for a dialed connection, labelled per Core's
    /// `ConnectionTypeAsString` for the dial kind and role.
    pub(crate) fn outbound(
        sink: std::sync::Arc<dyn NetTraceSink>,
        node_id: u64,
        peer: SocketAddr,
        role: PeerRole,
        manual: bool,
    ) -> Self {
        let connection_type = if manual {
            "manual"
        } else {
            match role {
                PeerRole::FullRelay => "outbound-full-relay",
                PeerRole::BlockRelayOnly => "block-relay-only",
            }
        };
        Self {
            sink,
            node_id,
            peer,
            connection_type,
        }
    }
}

/// Fires `net:inbound_message` for one checksum-valid wire message.
///
/// `payload` is the checksum-validated wire payload as read; it must
/// outlive this call, which the wire reader's buffer satisfies. A malformed
/// typed payload is still observable before decoding fails.
pub(crate) fn inbound_message(trace: Option<&NetTrace>, command: &str, payload: &[u8]) {
    if let Some(trace) = trace {
        trace
            .sink
            .inbound_message(&mut || message_args(trace, command, payload));
    }
}

/// Fires `net:outbound_message` for one write attempt.
///
/// Fires before the write so a write that fails afterwards still observes
/// the attempt, the way Core fires from its `SendMessages` queue. `payload`
/// is the encoded frame's payload — the same bytes the vectored write
/// emits, so each message encodes into a frame exactly once.
pub(crate) fn outbound_message(trace: Option<&NetTrace>, message: &Message, payload: &[u8]) {
    if let Some(trace) = trace {
        trace.sink.outbound_message(&mut || {
            let command = message.command();
            message_args(trace, command.as_ref(), payload)
        });
    }
}

/// Assembles Core's six-argument payload tuple for one message.
fn message_args(trace: &NetTrace, command: &str, payload: &[u8]) -> MessageTraceArgs {
    (
        node_id_i64(trace.node_id),
        trace.peer.to_string(),
        trace.connection_type.to_owned(),
        command.to_owned(),
        payload_len_u64(payload.len()),
        payload.as_ptr(),
    )
}

/// Node ids are `u64`; the ABI publishes Core's `int64` position, so ids
/// above `i64::MAX` clamp rather than wrap negative.
fn node_id_i64(node_id: u64) -> i64 {
    i64::try_from(node_id).unwrap_or(i64::MAX)
}

/// Payload lengths are `usize`; the ABI publishes `uint64`.
fn payload_len_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}
