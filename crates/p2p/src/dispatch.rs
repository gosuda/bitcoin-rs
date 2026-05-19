use crate::fsm::step;
use crate::handshake::feature_messages;
use crate::inv::request_inventory;
use crate::peer::{Peer, PeerState};
use crate::wire::{Message, PeerError};

/// Dispatch one inbound message and return protocol responses to send.
pub fn dispatch_inbound<S>(
    peer: &mut Peer<S>,
    message: &Message,
) -> Result<Vec<Message>, PeerError> {
    let mut responses = Vec::new();

    match message {
        Message::Version(_) => {
            step(peer, message)?;
            responses.extend(feature_messages());
            responses.push(Message::Verack);
        }
        Message::Ping(nonce) => {
            step(peer, message)?;
            responses.push(Message::Pong(*nonce));
        }
        Message::Inv(items) => {
            step(peer, message)?;
            if let Some(response) = request_inventory(items) {
                responses.push(response);
            }
        }
        _ => step(peer, message)?,
    }

    if peer.state == PeerState::Ready {
        tracing::trace!("peer handshake ready");
    }

    Ok(responses)
}
