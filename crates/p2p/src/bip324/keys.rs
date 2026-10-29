//! The BIP324 key schedule: the `ElligatorSwift` ECDH secret, its HKDF-SHA256
//! expansion, and the assignment of keys to one side of the connection.

use bitcoin::p2p::Magic;
use bitcoin::secp256k1::SecretKey;
use bitcoin::secp256k1::ellswift::{ElligatorSwift, ElligatorSwiftParty};
use hkdf::Hkdf;
use sha2::Sha256;

use super::packet::{RecvCipher, SendCipher};

/// Bytes in a garbage terminator.
pub(crate) const GARBAGE_TERMINATOR_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    Initiator,
    Responder,
}

pub(crate) fn shared_secret(
    secret_key: SecretKey,
    ours: ElligatorSwift,
    theirs: ElligatorSwift,
    role: Role,
) -> [u8; 32] {
    let secret = match role {
        Role::Initiator => {
            ElligatorSwift::shared_secret(ours, theirs, secret_key, ElligatorSwiftParty::A, None)
        }
        Role::Responder => {
            ElligatorSwift::shared_secret(theirs, ours, secret_key, ElligatorSwiftParty::B, None)
        }
    };
    secret.to_secret_bytes()
}

pub(crate) struct KeyMaterial {
    pub(crate) initiator_length: [u8; 32],
    pub(crate) initiator_packet: [u8; 32],
    pub(crate) responder_length: [u8; 32],
    pub(crate) responder_packet: [u8; 32],
    pub(crate) initiator_garbage_terminator: [u8; GARBAGE_TERMINATOR_LEN],
    pub(crate) responder_garbage_terminator: [u8; GARBAGE_TERMINATOR_LEN],
    pub(crate) session_id: [u8; 32],
}

impl KeyMaterial {
    /// HKDF-SHA256 over `shared_secret`, salted with `"bitcoin_v2_shared_secret" ||
    /// magic` and expanded once per BIP324 label.
    ///
    /// The magic binds the session to the network, custom magic included. Each output
    /// is 32 bytes, far below HKDF-SHA256's 8160-byte limit.
    pub(crate) fn derive(
        shared_secret: &[u8; 32],
        magic: Magic,
    ) -> Result<Self, hkdf::InvalidLength> {
        let mut salt = b"bitcoin_v2_shared_secret".to_vec();
        salt.extend_from_slice(&magic.to_bytes());
        let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
        let expand = |label: &[u8]| -> Result<[u8; 32], hkdf::InvalidLength> {
            let mut key = [0u8; 32];
            hkdf.expand(label, &mut key)?;
            Ok(key)
        };
        let terminators = expand(b"garbage_terminators")?;
        let mut initiator_garbage_terminator = [0u8; GARBAGE_TERMINATOR_LEN];
        let mut responder_garbage_terminator = [0u8; GARBAGE_TERMINATOR_LEN];
        initiator_garbage_terminator.copy_from_slice(&terminators[..GARBAGE_TERMINATOR_LEN]);
        responder_garbage_terminator.copy_from_slice(&terminators[GARBAGE_TERMINATOR_LEN..]);
        Ok(Self {
            initiator_length: expand(b"initiator_L")?,
            initiator_packet: expand(b"initiator_P")?,
            responder_length: expand(b"responder_L")?,
            responder_packet: expand(b"responder_P")?,
            initiator_garbage_terminator,
            responder_garbage_terminator,
            session_id: expand(b"session_id")?,
        })
    }
}

#[derive(Debug)]
pub(crate) struct Session {
    pub(crate) send: SendCipher,
    pub(crate) recv: RecvCipher,
    pub(crate) send_garbage_terminator: [u8; GARBAGE_TERMINATOR_LEN],
    pub(crate) recv_garbage_terminator: [u8; GARBAGE_TERMINATOR_LEN],
    pub(crate) session_id: [u8; 32],
}

impl Session {
    pub(crate) fn new(material: &KeyMaterial, role: Role) -> Self {
        let initiator = (
            material.initiator_length,
            material.initiator_packet,
            material.initiator_garbage_terminator,
        );
        let responder = (
            material.responder_length,
            material.responder_packet,
            material.responder_garbage_terminator,
        );
        let (sent, received) = match role {
            Role::Initiator => (initiator, responder),
            Role::Responder => (responder, initiator),
        };
        Self {
            send: SendCipher::new(sent.0, sent.1),
            recv: RecvCipher::new(received.0, received.1),
            send_garbage_terminator: sent.2,
            recv_garbage_terminator: received.2,
            session_id: material.session_id,
        }
    }
}
