//! Bitcoin Core `net:*` tracepoint payload mapping.
//!
//! [`inbound_message`] fires per checksum-valid wire message in the connection read
//! loop and during the handshake; [`outbound_message`] fires per write
//! attempt by the connection writer and during the handshake. Argument
//! positions and types follow Bitcoin Core's published ABI — see
//! `docs/tracing.md` and `bitcoin_rs_consensus`'s `probes.d` table. Every
//! emitter no-ops unless the connection carries a [`NetTrace`], which only
//! the live inbound-accept and outbound-dial roots attach, and payload
//! preparation runs only while a consumer (bpftrace, BCC, DTrace) holds
//! the probe's semaphore, so an untraced or unattached run pays nothing.

use std::net::SocketAddr;

use crate::peer_info::PeerRole;
use crate::wire::Message;

/// Per-connection identity for the `net:*` probe payloads.
///
/// Captured once where the connection direction and remote address are
/// known — the inbound accept path and the outbound dial — and carried by
/// the connection's [`crate::peer::Peer`] and writer thread. Probe-free
/// connections (tests, in-memory streams) carry none, keeping the probes
/// out of their binaries.
#[derive(Clone, Copy, Debug)]
pub(crate) struct NetTrace {
    /// Process-unique connection id (Core argument 1, `peerid`).
    node_id: u64,
    /// Remote address and port (Core argument 2).
    peer: SocketAddr,
    /// Core `ConnectionTypeAsString` label (Core argument 3).
    connection_type: &'static str,
}

impl NetTrace {
    /// Context for an accepted inbound connection.
    pub(crate) fn inbound(node_id: u64, peer: SocketAddr) -> Self {
        Self {
            node_id,
            peer,
            connection_type: "inbound",
        }
    }

    /// Context for a dialed connection, labelled per Core's
    /// `ConnectionTypeAsString` for the dial kind and role.
    pub(crate) fn outbound(node_id: u64, peer: SocketAddr, role: PeerRole, manual: bool) -> Self {
        let connection_type = if manual {
            "manual"
        } else {
            match role {
                PeerRole::FullRelay => "outbound-full-relay",
                PeerRole::BlockRelayOnly => "block-relay-only",
            }
        };
        Self {
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
        bitcoin_rs_consensus::trace::inbound_message(|| message_args(trace, command, payload));
    }
}

/// Fires `net:outbound_message` for one write attempt.
pub(crate) fn outbound_message(trace: Option<&NetTrace>, message: &Message, payload: &[u8]) {
    if let Some(trace) = trace {
        bitcoin_rs_consensus::trace::outbound_message(|| {
            let command = message.command();
            message_args(trace, command.as_ref(), payload)
        });
    }
}

/// Assembles Core's six-argument payload tuple for one message.
fn message_args(
    trace: &NetTrace,
    command: &str,
    payload: &[u8],
) -> bitcoin_rs_consensus::trace::MessageArgs {
    (
        node_id_i64(trace.node_id),
        trace.peer.to_string(),
        trace.connection_type.to_owned(),
        command.to_owned(),
        payload_len_u64(payload.len()),
        // A zero-length payload has no addressable bytes; hand the tracer a
        // null pointer rather than a dangling non-null one.
        if payload.is_empty() {
            std::ptr::null()
        } else {
            payload.as_ptr()
        },
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

#[cfg(test)]
mod tests {
    use super::*;

    fn loopback() -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 8333))
    }

    #[test]
    fn message_args_matches_core_abi_positions() {
        let trace = NetTrace::inbound(7, loopback());
        let payload: &[u8] = b"abc";

        let (node_id, addr, conn_type, msg_type, size, pointer) =
            message_args(&trace, "ping", payload);

        assert_eq!(node_id, 7);
        assert_eq!(addr, "127.0.0.1:8333");
        assert_eq!(conn_type, "inbound");
        assert_eq!(msg_type, "ping");
        assert_eq!(size, 3);
        assert_eq!(pointer, payload.as_ptr());
    }

    #[test]
    fn message_args_nulls_the_pointer_of_an_empty_payload() {
        let trace = NetTrace::inbound(1, loopback());

        let (_, _, _, _, size, pointer) = message_args(&trace, "ping", &[]);

        assert_eq!(size, 0);
        assert!(pointer.is_null());
    }

    #[test]
    fn node_ids_above_i64_max_clamp_instead_of_wrapping() {
        let max_i64 = i64::MAX.unsigned_abs();
        assert_eq!(node_id_i64(u64::MAX), i64::MAX);
        assert_eq!(node_id_i64(max_i64), i64::MAX);
        assert_eq!(node_id_i64(0), 0);
    }

    #[test]
    fn connection_types_follow_core_connection_type_as_string() {
        let addr = loopback();

        assert_eq!(NetTrace::inbound(1, addr).connection_type, "inbound");
        assert_eq!(
            NetTrace::outbound(1, addr, PeerRole::FullRelay, false).connection_type,
            "outbound-full-relay"
        );
        assert_eq!(
            NetTrace::outbound(1, addr, PeerRole::BlockRelayOnly, false).connection_type,
            "block-relay-only"
        );
        assert_eq!(
            NetTrace::outbound(1, addr, PeerRole::FullRelay, true).connection_type,
            "manual"
        );
    }
}
