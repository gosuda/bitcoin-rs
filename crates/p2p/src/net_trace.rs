//! Bitcoin Core `net:*` tracepoint payload mapping.

use crate::PeerRemote;

use crate::peer_info::PeerRole;
use crate::wire::Message;

#[derive(Clone, Copy, Debug)]
pub(crate) struct NetTrace {
    node_id: u64,
    peer: PeerRemote,
    connection_type: &'static str,
}

impl NetTrace {
    pub(crate) fn inbound(node_id: u64, peer: PeerRemote) -> Self {
        Self {
            node_id,
            peer,
            connection_type: "inbound",
        }
    }

    pub(crate) fn outbound(node_id: u64, peer: PeerRemote, role: PeerRole, manual: bool) -> Self {
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

pub(crate) fn inbound_message(trace: Option<&NetTrace>, command: &str, payload: &[u8]) {
    if let Some(trace) = trace {
        bitcoin_rs_consensus::trace::inbound_message(|| message_args(trace, command, payload));
    }
}

pub(crate) fn outbound_message(trace: Option<&NetTrace>, message: &Message, payload: &[u8]) {
    if let Some(trace) = trace {
        bitcoin_rs_consensus::trace::outbound_message(|| {
            let command = message.command();
            message_args(trace, command.as_ref(), payload)
        });
    }
}

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
        if payload.is_empty() {
            std::ptr::null()
        } else {
            payload.as_ptr()
        },
    )
}

fn node_id_i64(node_id: u64) -> i64 {
    i64::try_from(node_id).unwrap_or(i64::MAX)
}

fn payload_len_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loopback() -> PeerRemote {
        PeerRemote::from(([127, 0, 0, 1], 8333))
    }

    #[test]
    fn message_args_serve_a_live_consumer_read() {
        let trace = NetTrace::inbound(7, loopback());
        let payload: &[u8] = b"ping-payload";

        inbound_message(Some(&trace), "ping", payload);
        outbound_message(Some(&trace), &Message::Ping(42), payload);
        inbound_message(None, "ping", payload);

        let (node_id, addr, conn_type, msg_type, size, pointer) =
            message_args(&trace, "ping", payload);

        assert_eq!(node_id, 7);
        let peer: PeerRemote = addr
            .parse()
            .unwrap_or_else(|error| panic!("a consumer parses the addr back: {error}"));
        assert_eq!(peer, loopback());
        assert_eq!(conn_type, "inbound");
        assert_eq!(msg_type, "ping");
        assert_eq!(size, u64::try_from(payload.len()).unwrap_or(u64::MAX));
        assert_eq!(pointer, payload.as_ptr());
        // SAFETY: `pointer` is `payload.as_ptr()` built above, so it carries
        let seen = unsafe {
            std::slice::from_raw_parts(
                pointer,
                usize::try_from(size).unwrap_or_else(|error| panic!("size fits: {error}")),
            )
        };
        assert_eq!(seen, payload);
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
