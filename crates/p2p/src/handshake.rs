use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use bitcoin::p2p::ServiceFlags;
use bitcoin::p2p::address::Address;
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin_rs_primitives::USER_AGENT;

use crate::connection::PeerLease;
use crate::dispatch::dispatch_inbound;
use crate::feature::{FEATURE_VERSION, FeatureAnnouncement};
use crate::peer::{COMPACT_BLOCK_VERSION, Peer, PeerState};
use crate::peer_info::PeerRole;
use crate::wire::{Message, PROTOCOL_VERSION, PeerError};
use bitcoin::p2p::message_compact_blocks::SendCmpct;

pub fn version_message(
    nonce: u64,
    start_height: i32,
    role: PeerRole,
    local_services: ServiceFlags,
) -> VersionMessage {
    let socket = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
    let address = Address::new(&socket, local_services);
    VersionMessage {
        version: PROTOCOL_VERSION,
        services: local_services,
        timestamp: 0,
        receiver: address.clone(),
        sender: address,
        nonce,
        user_agent: USER_AGENT.to_owned(),
        start_height,
        relay: role.relays_transactions(),
    }
}

pub const fn feature_messages() -> [Message; 3] {
    [
        Message::WtxidRelay,
        Message::SendAddrV2,
        Message::SendHeaders,
    ]
}

pub(crate) fn negotiated_features<S>(
    peer: &Peer<S>,
    remote_version: u32,
) -> Vec<FeatureAnnouncement> {
    announceable_to(
        remote_version,
        peer.stale_tip_offer
            .map(FeatureAnnouncement::bip332)
            .into_iter()
            .collect(),
    )
}

fn announceable_to(
    remote_version: u32,
    local: Vec<FeatureAnnouncement>,
) -> Vec<FeatureAnnouncement> {
    if remote_version < FEATURE_VERSION {
        Vec::new()
    } else {
        local
    }
}

const fn post_verack_messages() -> [Message; 1] {
    [Message::SendCmpct(SendCmpct {
        send_compact: false,
        version: COMPACT_BLOCK_VERSION,
    })]
}

pub(crate) fn send_post_verack_messages<S: Read + Write>(
    peer: &mut Peer<S>,
) -> Result<(), PeerError> {
    for message in post_verack_messages() {
        peer.send(&message)?;
    }
    peer.compact_blocks
        .record_local_advertised(COMPACT_BLOCK_VERSION);
    Ok(())
}

pub fn start<S>(
    peer: &mut Peer<S>,
    nonce: u64,
    start_height: i32,
    role: PeerRole,
    local_services: ServiceFlags,
) -> Vec<Message> {
    peer.state = PeerState::VersionExchange;
    if !role.relays_transactions() {
        peer.package_relay.withdraw_offer();
    }
    let mut messages = Vec::with_capacity(4);
    messages.push(Message::Version(version_message(
        nonce,
        start_height,
        role,
        local_services,
    )));
    messages.extend(feature_messages());
    messages
}

pub fn run_inbound_handshake<S: Read + Write>(
    peer: &mut Peer<S>,
    our_nonce: u64,
    our_start_height: i32,
    local_services: ServiceFlags,
    lease: &PeerLease,
    deadline: Instant,
) -> Result<(), PeerError> {
    let (_, responses) = next_handshake_step(peer, lease, deadline)?;

    peer.state = PeerState::VersionExchange;
    peer.send(&Message::Version(version_message(
        our_nonce,
        our_start_height,
        PeerRole::FullRelay,
        local_services,
    )))?;
    for response in responses {
        peer.send(&response)?;
    }

    while peer.state != PeerState::Ready {
        let (_, responses) = next_handshake_step(peer, lease, deadline)?;
        for response in responses {
            peer.send(&response)?;
        }
    }
    send_post_verack_messages(peer)?;
    Ok(())
}

pub(crate) fn next_handshake_step<S: Read>(
    peer: &mut Peer<S>,
    lease: &PeerLease,
    deadline: Instant,
) -> Result<(Message, Vec<Message>), PeerError> {
    loop {
        let (message, _) = read_handshake_message(peer, lease, deadline)?;
        match dispatch_inbound(peer, &message) {
            Err(error) if lease.ignores_protocol_error(&error) => {
                tracing::debug!(node_id = lease.node_id(), %error, "protected peer protocol violation ignored");
            }
            result => return result.map(|responses| (message, responses)),
        }
    }
}

fn read_handshake_message<S: Read>(
    peer: &mut Peer<S>,
    lease: &PeerLease,
    deadline: Instant,
) -> Result<(Message, bytes::Bytes), PeerError> {
    loop {
        if lease.is_cancelled() {
            return Err(PeerError::Protocol("peer lease revoked during handshake"));
        }
        if Instant::now() >= deadline {
            return Err(PeerError::Io(std::io::Error::from(
                std::io::ErrorKind::TimedOut,
            )));
        }
        let state = peer.state;
        match peer.read_message_admitted(|command, _| {
            if crate::inbound::block_memory::expands_on_decode(command) {
                crate::fsm::require_ready(state)
            } else {
                Ok(())
            }
        }) {
            Err(error) if lease.ignores_protocol_error(&error) => {
                tracing::debug!(node_id = lease.node_id(), %error, "protected peer malformed handshake message ignored");
                continue;
            }
            Ok(Some((message, raw))) => {
                if matches!(message, Message::Version(_)) && peer.remote_version.is_none() {
                    peer.version_received_time = Some(
                        SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map_or(0, |duration| duration.as_secs()),
                    );
                }
                return Ok((message, raw));
            }
            Ok(None) => continue,
            Err(PeerError::Io(error))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests;
