//! Native Stratum V2 mining-pool adapter.

#![forbid(unsafe_code)]

mod session;

pub use mining_sv2::ERROR_CODE_SUBMIT_SHARES_STALE_SHARE;
pub use session::{
    AdmitError, AdmitUser, BlockSubmission, ChannelInfo, ChannelKind, CloseReason,
    ERROR_CODE_INVALID_SEQUENCE_NUMBER, ERROR_CODE_JOB_SHARE_CAPACITY, ERROR_CODE_POOL_BUSY,
    ERROR_CODE_RECONNECT_REQUESTED, ERROR_CODE_SHARE_NOT_RECORDED, Event,
    FLAG_REQUIRES_STANDARD_JOBS, FLAG_REQUIRES_VERSION_ROLLING, FLAG_REQUIRES_WORK_SELECTION,
    Limits, PendingBlock, ProtocolSession, SUCCESS_FLAG_REQUIRES_EXTENDED_CHANNELS,
    SUCCESS_FLAG_REQUIRES_FIXED_VERSION, ServerConfig, SessionError, ShareEvent, ShareTicket,
    target_difficulty,
};

use std::fmt;
use std::time::Duration;

use crate::pool::{Installed, JobBook, ShareTarget};
use codec_sv2::{
    Decoded, Decrypted, ENCRYPTED_SV2_FRAME_HEADER_SIZE, Handshake, NoiseDecoder, NoiseEncoder,
    SV2_FRAME_PLAINTEXT_CHUNK_SIZE, SerializedFrame, TransportDecryptState, TransportEncryptState,
};
use framing_sv2::SV2_FRAME_HEADER_SIZE;
use noise_sv2::{AEAD_MAC_LEN, ELLSWIFT_ENCODING_SIZE, Responder};
use thiserror::Error;
use zeroize::Zeroizing;

pub const SPEC_REVISION: &str = "025e2f76802d5942a10f6f3fea07941522b108ca";
pub const SRI_RELEASE: &str = "v1.12.0";
pub const PROTOCOL_VERSION: u16 = 2;
pub const U24_MAX: usize = 0x00ff_ffff;
/// Largest `B0_32` field: a standard channel's full extranonce must fit it.
pub const MAX_EXTRANONCE_WIRE_LEN: usize = 32;
pub const MAX_FEED_LEN: usize = 1 << 17;

/// One plaintext SV2 frame, decrypted (or about to be encrypted).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    pub extension_type: u16,
    pub msg_type: u8,
    pub channel_msg: bool,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoleStatus {
    Implemented,
    NotImplemented,
    NotApplicable,
}

#[derive(Clone, Copy, Debug)]
pub struct Role {
    pub name: &'static str,
    pub spec: &'static str,
    pub status: RoleStatus,
    pub detail: &'static str,
}

pub const ROLES: &[Role] = &[
    Role {
        name: "Noise_NX authenticated transport, responder",
        spec: "04 §4.5",
        status: RoleStatus::Implemented,
        detail: "noise_sv2 2.0.0 / codec_sv2 7.0.0; certificate signed by the pool authority key",
    },
    Role {
        name: "SetupConnection (mining protocol), Success, Error",
        spec: "03 §3.6.1-3.6.3, 05 §5.3.1",
        status: RoleStatus::Implemented,
        detail: "version 2 only; REQUIRES_STANDARD_JOBS honoured; REQUIRES_FIXED_VERSION set when the job owner has no version mask",
    },
    Role {
        name: "Standard channels",
        spec: "05 §5.2.1",
        status: RoleStatus::Implemented,
        detail: "pool-fixed extranonce; merkle root from bitcoin_rs_stratum::Job::merkle_root",
    },
    Role {
        name: "Extended channels",
        spec: "05 §5.2.2",
        status: RoleStatus::Implemented,
        detail: "extranonce_size is the owner's rolled length; min_extranonce_size larger than that is refused",
    },
    Role {
        name: "Group channels",
        spec: "05 §5.2.3",
        status: RoleStatus::Implemented,
        detail: "one group per connection holding every channel; group-addressed NewExtendedMiningJob, SetNewPrevHash, SetTarget and CloseChannel; SetGroupChannel (regrouping) is never sent",
    },
    Role {
        name: "Job and share lifecycle",
        spec: "05 §5.3.11-5.3.17, 5.3.21",
        status: RoleStatus::Implemented,
        detail: "NewMiningJob, NewExtendedMiningJob, SetNewPrevHash, SetTarget, SubmitShares*, UpdateChannel, CloseChannel; SubmitShares.Success is held until the host confirms the ledger record",
    },
    Role {
        name: "Reconnect",
        spec: "03 §3.6.5",
        status: RoleStatus::Implemented,
        detail: "request_reconnect sends Reconnect and refuses new channels afterwards",
    },
    Role {
        name: "SetExtranoncePrefix",
        spec: "05 §5.3.10",
        status: RoleStatus::NotImplemented,
        detail: "a session's extranonce prefix is fixed for its life; the owner reuses prefixes only after close_session",
    },
    Role {
        name: "ChannelEndpointChanged",
        spec: "03 §3.6.4",
        status: RoleStatus::NotApplicable,
        detail: "proxy-only message; a pool is the channel endpoint",
    },
    Role {
        name: "Work selection and custom jobs (SetCustomMiningJob)",
        spec: "05 §5.3.18-5.3.20",
        status: RoleStatus::NotImplemented,
        detail: "bitcoin_rs_stratum::JobBook::install accepts only a pool-built Candidate; a miner-declared job needs an owner-side install and validate path that does not exist, and a second one here would duplicate template and share validation",
    },
    Role {
        name: "Job Declaration server",
        spec: "06",
        status: RoleStatus::NotImplemented,
        detail: "same missing fact as custom jobs, plus declared-transaction validation against the mempool; SetupConnection for protocol 1 is refused with unsupported-protocol",
    },
    Role {
        name: "Template Distribution server (Template Provider)",
        spec: "07",
        status: RoleStatus::NotImplemented,
        detail: "serving templates to a remote job declarator is not part of a pool; SetupConnection for protocol 2 is refused with unsupported-protocol",
    },
    Role {
        name: "Template Distribution client",
        spec: "07",
        status: RoleStatus::NotApplicable,
        detail: "templates come from MiningControl in process, not from a Template Provider",
    },
    Role {
        name: "Extensions negotiation",
        spec: "03 §3.4, extensions/0x0001",
        status: RoleStatus::NotImplemented,
        detail: "frames with a non-zero extension_type are discarded and counted, as §3.4.1 requires for unknown extensions",
    },
];

/// Configuration refused before any connection state exists.
#[derive(Debug, Eq, Error, PartialEq)]
pub enum ConfigError {
    #[error("invalid limits: {0}")]
    Limits(&'static str),
    #[error("authority key pair rejected: {0}")]
    Authority(String),
    #[error("certificate validity must be between 1 second and u32::MAX seconds")]
    CertValidity,
    #[error("extranonce layout of {total} bytes exceeds the {max}-byte wire field")]
    ExtranonceTooLong { total: usize, max: usize },
}

/// Transport failures. All of them are fatal for the connection: after a
/// failed decryption the cipher nonce no longer matches the peer's.
#[derive(Debug, Error)]
pub enum TransportError {
    #[error("noise handshake failed: {0}")]
    Handshake(String),
    #[error("frame failed authentication or decoding: {0}")]
    Decrypt(String),
    #[error("frame needs more than {limit} payload bytes")]
    FrameTooLarge { limit: usize },
    #[error("read of {len} bytes exceeds the {max}-byte feed bound")]
    FeedTooLarge { len: usize, max: usize },
    #[error("decoder made no progress")]
    Stalled,
    #[error("cannot encode outbound frame: {0}")]
    Encode(String),
    #[error("outbound byte queue would exceed {limit}")]
    OutboxFull { limit: usize },
    #[error("transport is not open")]
    NotOpen,
    #[error("transport failed earlier")]
    Failed,
}

/// Any failure of a [`Connection`] call.
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error(transparent)]
    Session(#[from] SessionError),
    #[error("connection is closed")]
    Closed,
}

impl Error {
    #[must_use]
    pub fn is_fatal(&self) -> bool {
        match self {
            Self::Transport(_) | Self::Closed => true,
            Self::Session(error) => error.is_fatal(),
        }
    }
}

/// The pool authority key pair, as raw 32-byte x-only keys.
pub struct AuthorityKeypair {
    public: [u8; 32],
    secret: Zeroizing<[u8; 32]>,
}

impl AuthorityKeypair {
    #[must_use]
    pub fn from_bytes(public: [u8; 32], secret: Zeroizing<[u8; 32]>) -> Self {
        Self { public, secret }
    }

    #[must_use]
    pub fn public(&self) -> &[u8; 32] {
        &self.public
    }
}

impl fmt::Debug for AuthorityKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorityKeypair")
            .field("public", &self.public)
            .field("secret", &"<redacted>")
            .finish()
    }
}

enum Stage {
    Handshake(Option<Handshake<Responder>>),
    Open {
        enc: TransportEncryptState,
        dec: Option<TransportDecryptState>,
    },
    Failed,
}

/// Encrypted length of a frame whose plaintext payload is `payload` bytes:
/// the encrypted header, the payload, and one MAC per plaintext chunk.
fn encrypted_frame_len(payload: usize) -> usize {
    ENCRYPTED_SV2_FRAME_HEADER_SIZE
        + payload
        + payload.div_ceil(SV2_FRAME_PLAINTEXT_CHUNK_SIZE) * AEAD_MAC_LEN
}

fn frame_bytes(frame: &Frame) -> Result<Vec<u8>, TransportError> {
    let len = frame.payload.len();
    let len32 = u32::try_from(len)
        .ok()
        .filter(|_| len <= U24_MAX)
        .ok_or_else(|| TransportError::Encode(format!("payload of {len} bytes exceeds the U24")))?;
    let mut extension = frame.extension_type & 0x7fff;
    if frame.channel_msg {
        extension |= 0x8000;
    }
    let mut bytes = Vec::with_capacity(SV2_FRAME_HEADER_SIZE + len);
    bytes.extend_from_slice(&extension.to_le_bytes());
    bytes.push(frame.msg_type);
    bytes.extend_from_slice(&len32.to_le_bytes()[..3]);
    bytes.extend_from_slice(&frame.payload);
    Ok(bytes)
}

struct Transport {
    decoder: NoiseDecoder,
    encoder: NoiseEncoder,
    stage: Stage,
    inbuf: Vec<u8>,
    fed: usize,
    outbox: Vec<u8>,
    max_payload: usize,
    max_outbox: usize,
}

impl Transport {
    fn accept(
        authority: &AuthorityKeypair,
        validity: Duration,
        limits: &Limits,
    ) -> Result<Self, ConfigError> {
        if validity.as_secs() == 0 || validity.as_secs() > u64::from(u32::MAX) {
            return Err(ConfigError::CertValidity);
        }
        let responder =
            Responder::from_authority_kp(&authority.public, &authority.secret, validity)
                .map_err(|e| ConfigError::Authority(format!("{e:?}")))?;
        Ok(Self {
            decoder: NoiseDecoder::new(),
            encoder: NoiseEncoder::new(),
            stage: Stage::Handshake(Some(Handshake::responder(responder))),
            inbuf: Vec::new(),
            fed: 0,
            outbox: Vec::new(),
            max_payload: limits.max_frame_payload,
            max_outbox: limits.max_outbound_bytes,
        })
    }

    fn read_hint(&self) -> usize {
        self.decoder
            .writable_len()
            .saturating_sub(self.inbuf.len())
            .max(1)
    }

    fn ceiling(&self) -> usize {
        match self.stage {
            Stage::Handshake(_) => ELLSWIFT_ENCODING_SIZE,
            _ => encrypted_frame_len(self.max_payload),
        }
    }

    fn feed(&mut self, data: &[u8]) -> Result<Vec<Frame>, TransportError> {
        if matches!(self.stage, Stage::Failed) {
            return Err(TransportError::Failed);
        }
        if data.len() > MAX_FEED_LEN {
            return Err(TransportError::FeedTooLarge {
                len: data.len(),
                max: MAX_FEED_LEN,
            });
        }
        self.inbuf.extend_from_slice(data);
        match self.pump() {
            Ok(frames) => Ok(frames),
            Err(error) => {
                self.stage = Stage::Failed;
                self.inbuf.clear();
                Err(error)
            }
        }
    }

    fn pump(&mut self) -> Result<Vec<Frame>, TransportError> {
        let mut frames = Vec::new();
        let mut idle = 0_u8;
        loop {
            let want = self.decoder.writable_len();
            if self.inbuf.len() < want {
                break;
            }
            if want == 0 {
                idle += 1;
                if idle > 2 {
                    return Err(TransportError::Stalled);
                }
            } else {
                idle = 0;
            }
            if self.fed.saturating_add(want) > self.ceiling() {
                return Err(TransportError::FrameTooLarge {
                    limit: self.max_payload,
                });
            }
            if want > 0 {
                let window = self.decoder.writable();
                window.copy_from_slice(&self.inbuf[..want]);
                self.inbuf.drain(..want);
                self.fed += want;
            }
            if matches!(self.stage, Stage::Handshake(_)) {
                self.step_handshake()?;
            } else {
                self.step_transport(&mut frames)?;
            }
        }
        Ok(frames)
    }

    fn step_handshake(&mut self) -> Result<(), TransportError> {
        let message = match self
            .decoder
            .next_handshake_frame::<Responder>()
            .map_err(|e| TransportError::Handshake(e.to_string()))?
        {
            Decoded::Incomplete(_) => return Ok(()),
            Decoded::Frame(message) => message,
        };
        let initiator_key: [u8; ELLSWIFT_ENCODING_SIZE] = message
            .payload()
            .try_into()
            .map_err(|_| TransportError::Handshake("act 1 has the wrong length".to_owned()))?;
        let handshake = match &mut self.stage {
            Stage::Handshake(slot) => slot.take().ok_or(TransportError::Failed)?,
            _ => return Err(TransportError::Failed),
        };
        let (reply, transport) = handshake
            .step_1(initiator_key)
            .map_err(|e| TransportError::Handshake(e.to_string()))?;
        let encoded = self.encoder.encode_handshake(reply);
        let bytes: &[u8] = encoded.as_ref();
        if self.outbox.len() + bytes.len() > self.max_outbox {
            return Err(TransportError::OutboxFull {
                limit: self.max_outbox,
            });
        }
        self.outbox.extend_from_slice(bytes);
        let (enc, dec) = transport.split();
        self.stage = Stage::Open {
            enc,
            dec: Some(dec),
        };
        self.fed = 0;
        Ok(())
    }

    fn step_transport(&mut self, frames: &mut Vec<Frame>) -> Result<(), TransportError> {
        let state = match &mut self.stage {
            Stage::Open { dec, .. } => dec.take().ok_or(TransportError::Failed)?,
            _ => return Err(TransportError::NotOpen),
        };
        match self.decoder.next_transport_frame(state) {
            Ok(Decrypted::Frame(mut frame, state)) => {
                if let Stage::Open { dec, .. } = &mut self.stage {
                    *dec = Some(state);
                }
                self.fed = 0;
                let header = frame.header();
                let payload = frame.payload().to_vec();
                if payload.len() > self.max_payload {
                    return Err(TransportError::FrameTooLarge {
                        limit: self.max_payload,
                    });
                }
                frames.push(Frame {
                    extension_type: header.ext_type_without_channel_msg(),
                    msg_type: header.msg_type(),
                    channel_msg: header.channel_msg(),
                    payload,
                });
                Ok(())
            }
            Ok(Decrypted::Incomplete(_, state)) => {
                if let Stage::Open { dec, .. } = &mut self.stage {
                    *dec = Some(state);
                }
                Ok(())
            }
            Err(e) => Err(TransportError::Decrypt(e.to_string())),
        }
    }

    fn send(&mut self, frame: &Frame) -> Result<(), TransportError> {
        let bytes = frame_bytes(frame)?;
        let estimate = encrypted_frame_len(frame.payload.len());
        if self.outbox.len().saturating_add(estimate) > self.max_outbox {
            return Err(TransportError::OutboxFull {
                limit: self.max_outbox,
            });
        }
        let serialized = SerializedFrame::from_bytes(bytes)
            .map_err(|hint| TransportError::Encode(hint.to_string()))?;
        let result = match &mut self.stage {
            Stage::Open { enc, .. } => self.encoder.encode_transport(serialized, enc),
            _ => return Err(TransportError::NotOpen),
        };
        let encrypted = match result {
            Ok(encrypted) => encrypted,
            Err(e) => {
                self.stage = Stage::Failed;
                return Err(TransportError::Encode(e.to_string()));
            }
        };
        let slice: &[u8] = encrypted.as_ref();
        self.outbox.extend_from_slice(slice);
        Ok(())
    }
}

/// One authenticated pool connection: Noise transport plus protocol session.
pub struct Connection {
    transport: Transport,
    session: ProtocolSession,
    dead: bool,
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("session", &self.session)
            .field("dead", &self.dead)
            .finish_non_exhaustive()
    }
}

impl Connection {
    pub fn accept(
        authority: &AuthorityKeypair,
        cert_validity: Duration,
        config: ServerConfig,
        book: &JobBook,
    ) -> Result<Self, ConfigError> {
        let limits = config.limits;
        let session = ProtocolSession::new(config, book)?;
        let transport = Transport::accept(authority, cert_validity, &limits)?;
        Ok(Self {
            transport,
            session,
            dead: false,
        })
    }

    #[must_use]
    pub fn read_hint(&self) -> usize {
        self.transport.read_hint()
    }

    #[must_use]
    pub fn session(&self) -> &ProtocolSession {
        &self.session
    }

    pub fn session_mut(&mut self) -> &mut ProtocolSession {
        &mut self.session
    }

    #[must_use]
    pub fn is_closing(&self) -> bool {
        self.dead || self.session.is_closing()
    }

    fn flush(&mut self) -> Result<(), Error> {
        for frame in self.session.take_frames() {
            self.transport.send(&frame)?;
        }
        Ok(())
    }

    fn guard<T>(&mut self, op: impl FnOnce(&mut Self) -> Result<T, Error>) -> Result<T, Error> {
        if self.dead {
            return Err(Error::Closed);
        }
        let result = op(self);
        if let Err(error) = &result
            && error.is_fatal()
        {
            self.dead = true;
        }
        result
    }

    pub fn feed(&mut self, data: &[u8], book: &mut JobBook) -> Result<(), Error> {
        self.guard(|conn| {
            let frames = conn.transport.feed(data)?;
            for frame in frames {
                conn.session.handle(book, frame)?;
            }
            conn.flush()
        })
    }

    pub fn take_transmit(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.transport.outbox)
    }

    pub fn poll_event(&mut self) -> Option<Event> {
        self.session.poll_event()
    }

    pub fn announce(&mut self, installed: &Installed) -> Result<(), Error> {
        self.guard(|conn| {
            conn.session.announce(installed)?;
            conn.flush()
        })
    }

    pub fn confirm_share(&mut self, ticket: ShareTicket) -> Result<bool, Error> {
        self.guard(|conn| {
            let sent = conn.session.confirm_share(ticket)?;
            conn.flush()?;
            Ok(sent)
        })
    }

    pub fn confirm_block(&mut self, submission: &BlockSubmission) -> Result<bool, Error> {
        self.guard(|conn| {
            let sent = conn.session.confirm_block(submission)?;
            conn.flush()?;
            Ok(sent)
        })
    }

    pub fn reject_share(&mut self, ticket: ShareTicket, code: &'static str) -> Result<bool, Error> {
        self.guard(|conn| {
            let sent = conn.session.reject_share(ticket, code)?;
            conn.flush()?;
            Ok(sent)
        })
    }

    pub fn reject_block(
        &mut self,
        submission: &BlockSubmission,
        code: &'static str,
    ) -> Result<bool, Error> {
        self.guard(|conn| {
            let sent = conn.session.reject_block(submission, code)?;
            conn.flush()?;
            Ok(sent)
        })
    }

    pub fn set_target(&mut self, id: u32, target: ShareTarget) -> Result<(), Error> {
        self.guard(|conn| {
            conn.session.set_target(id, target)?;
            conn.flush()
        })
    }

    pub fn close_channel(
        &mut self,
        book: &mut JobBook,
        channel_id: u32,
        reason_code: &str,
    ) -> Result<(), Error> {
        self.guard(|conn| {
            conn.session.close_channel(book, channel_id, reason_code)?;
            conn.flush()
        })
    }

    pub fn request_reconnect(&mut self, new_host: &str, new_port: u16) -> Result<(), Error> {
        self.guard(|conn| {
            conn.session.request_reconnect(new_host, new_port)?;
            conn.flush()
        })
    }

    pub fn release(&mut self, book: &mut JobBook) {
        self.session.release(book);
        self.dead = true;
    }
}
