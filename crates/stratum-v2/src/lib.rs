//! Native Stratum V2 mining-pool adapter.
//!
//! A pool-side Stratum V2 server for `bitcoin-rs`, built from three layers:
//!
//! 1. **Authenticated transport** ([`Connection`]): the `Noise_NX_Secp256k1+
//!    EllSwift_ChaChaPoly_SHA256` responder of the Stratum V2 specification,
//!    run by the Stratum Reference Implementation's own `noise_sv2` and
//!    `codec_sv2` (never home-grown crypto). The pool authority key crosses
//!    this crate as 32 raw bytes ([`AuthorityKeypair`]), so no `secp256k1`
//!    type is shared with the repository's `secp256k1 0.29` graph:
//!    `noise_sv2 2.0.0` resolves its own `secp256k1 0.28.2` and the two meet
//!    only at the byte boundary.
//! 2. **Protocol session** ([`ProtocolSession`]): `SetupConnection`, standard,
//!    extended and group channels, `NewMiningJob` / `NewExtendedMiningJob` /
//!    `SetNewPrevHash` / `SetTarget` / `SubmitShares*`, `UpdateChannel`,
//!    `CloseChannel`, `Reconnect`, and the error and cancel semantics around
//!    them, using the official message layouts from `mining_sv2 12.0.0` and
//!    `common_messages_sv2 9.0.0`.
//! 3. **The one job and share owner**, [`bitcoin_rs_stratum::JobBook`]. This
//!    crate never assembles a template, never builds a coinbase, and never
//!    validates a share or a block: it passes the owner's `Job` to the wire
//!    and maps the owner's `ShareError` to an official error code.
//!
//! # What is real, and what is not
//!
//! Implemented and exercised by `tests/protocol.rs` with real Noise
//! handshakes, real encrypted frames and real regtest candidates: the Mining
//! Protocol server role. [`ROLES`] states every other role explicitly; none of
//! them is advertised in `SetupConnection`:
//!
//! - Job Declaration server and work selection (`SetCustomMiningJob`,
//!   `REQUIRES_WORK_SELECTION`) are not implemented: the owner exposes no way
//!   to install a miner-declared job (`JobBook::install` takes a pool-built
//!   `Candidate`), and adding one here would be a second template and
//!   validation path. `SetupConnection` for the Job Declaration protocol is
//!   refused with `unsupported-protocol`; the work-selection flag with
//!   `unsupported-feature-flags`; a stray `SetCustomMiningJob` with
//!   `jd-not-supported`.
//! - Template Distribution (serving or consuming) is not needed by a native
//!   pool, whose templates come from `MiningControl`, and is not implemented.
//! - Extension negotiation is not implemented; frames with a non-zero
//!   `extension_type` are discarded as §3.4.1 requires.
//!
//! Not run: a network daemon, a real key, a real funds path. Nothing in this
//! crate opens a socket: [`Connection`] is sans-IO (`feed` bytes in,
//! `take_transmit` bytes out).
//!
//! # Host loop
//!
//! ```text
//! let mut conn = Connection::accept(&authority, validity, config, &book)?;
//! loop {
//!     // read up to conn.read_hint().max(4096) bytes from the socket, then
//!     conn.feed(&bytes, &mut book)?;
//!     socket.write_all(&conn.take_transmit());
//!     while let Some(event) = conn.poll_event() {
//!         match event {
//!             Event::ShareAccepted(e) => {
//!                 ledger.record(&e.outcome);
//!                 conn.confirm_share(e.ticket)?;
//!             }
//!             Event::BlockFound(pending) => {
//!                 let submitted = pending.submit(&*mining_control)?;
//!                 // The pool service maps pending.found_block() plus
//!                 // submitted.receipt() into its ledger BlockFound record here.
//!                 conn.confirm_block(&submitted)?;
//!             }
//!             ...
//!         }
//!     }
//!     // when the node installs a job: conn.announce(&installed)?;
//! }
//! conn.release(&mut book); // always, on every exit path
//! ```

#![forbid(unsafe_code)]

mod session;

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

use bitcoin_rs_stratum::{Installed, JobBook, ShareTarget};
use codec_sv2::{
    Decoded, Decrypted, ENCRYPTED_SV2_FRAME_HEADER_SIZE, Handshake, NoiseDecoder, NoiseEncoder,
    SV2_FRAME_PLAINTEXT_CHUNK_SIZE, SerializedFrame, TransportDecryptState, TransportEncryptState,
};
use framing_sv2::SV2_FRAME_HEADER_SIZE;
use noise_sv2::{AEAD_MAC_LEN, ELLSWIFT_ENCODING_SIZE, Responder};
use thiserror::Error;
use zeroize::Zeroizing;

/// Stratum V2 specification revision this crate implements: the
/// `stratum-mining/sv2-spec` commit of 2026-10-15.
pub const SPEC_REVISION: &str = "025e2f76802d5942a10f6f3fea07941522b108ca";
/// Stratum Reference Implementation release whose crates.io line is used
/// (`stratum-core 0.6.0`, 2026-09-17).
pub const SRI_RELEASE: &str = "v1.12.0";
/// The only protocol version Stratum V2 defines (`SetupConnection` §3.6.1).
pub const PROTOCOL_VERSION: u16 = 2;
/// Largest value of the U24 `msg_length` frame field.
pub const U24_MAX: usize = 0x00ff_ffff;
/// Largest `B0_32` field: a standard channel's full extranonce must fit it.
pub const MAX_EXTRANONCE_WIRE_LEN: usize = 32;
/// Largest single `feed` the transport accepts; the pending input buffer is
/// therefore bounded by one decoder chunk plus this.
pub const MAX_FEED_LEN: usize = 1 << 17;

/// One plaintext SV2 frame, decrypted (or about to be encrypted).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    /// `extension_type` without the channel bit; 0 for every core message.
    pub extension_type: u16,
    /// Message type.
    pub msg_type: u8,
    /// The `channel_msg` bit.
    pub channel_msg: bool,
    /// Message payload, without the 6-byte header.
    pub payload: Vec<u8>,
}

/// Whether one protocol role is implemented by this crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoleStatus {
    /// Implemented and covered by `tests/protocol.rs`.
    Implemented,
    /// Not implemented; never advertised.
    NotImplemented,
    /// Not needed by a native pool.
    NotApplicable,
}

/// One row of the role matrix.
#[derive(Clone, Copy, Debug)]
pub struct Role {
    /// Role or capability.
    pub name: &'static str,
    /// Where the specification defines it.
    pub spec: &'static str,
    /// Whether this crate implements it.
    pub status: RoleStatus,
    /// Behaviour or the exact missing fact.
    pub detail: &'static str,
}

/// The full role matrix of this adapter. Anything not `Implemented` is a fact
/// about what is missing, not a claim of support.
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
    /// A resource limit is out of range.
    #[error("invalid limits: {0}")]
    Limits(&'static str),
    /// The pool authority key pair is not a valid matching pair.
    #[error("authority key pair rejected: {0}")]
    Authority(String),
    /// Certificate validity is zero or does not fit a U32 of seconds.
    #[error("certificate validity must be between 1 second and u32::MAX seconds")]
    CertValidity,
    /// The owner's extranonce layout cannot be carried by a `B0_32` field.
    #[error("extranonce layout of {total} bytes exceeds the {max}-byte wire field")]
    ExtranonceTooLong {
        /// `session_len + rolled_len`.
        total: usize,
        /// Wire maximum.
        max: usize,
    },
}

/// Transport failures. All of them are fatal for the connection: after a
/// failed decryption the cipher nonce no longer matches the peer's.
#[derive(Debug, Error)]
pub enum TransportError {
    /// The Noise handshake failed.
    #[error("noise handshake failed: {0}")]
    Handshake(String),
    /// A frame failed authentication (bad MAC) or decoding.
    #[error("frame failed authentication or decoding: {0}")]
    Decrypt(String),
    /// A frame declares more payload than the configured limit.
    #[error("frame needs more than {limit} payload bytes")]
    FrameTooLarge {
        /// Configured payload limit.
        limit: usize,
    },
    /// A single `feed` call exceeded the bound.
    #[error("read of {len} bytes exceeds the {max}-byte feed bound")]
    FeedTooLarge {
        /// Offered length.
        len: usize,
        /// Bound.
        max: usize,
    },
    /// The decoder asked for no input and produced no frame.
    #[error("decoder made no progress")]
    Stalled,
    /// An outbound frame could not be encoded.
    #[error("cannot encode outbound frame: {0}")]
    Encode(String),
    /// The peer is not draining output.
    #[error("outbound byte queue would exceed {limit}")]
    OutboxFull {
        /// Bound.
        limit: usize,
    },
    /// An application frame before the handshake completed.
    #[error("transport is not open")]
    NotOpen,
    /// The transport failed earlier.
    #[error("transport failed earlier")]
    Failed,
}

/// Any failure of a [`Connection`] call.
#[derive(Debug, Error)]
pub enum Error {
    /// The encrypted transport failed.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// The peer violated the protocol, or a host call was invalid.
    #[error(transparent)]
    Session(#[from] SessionError),
    /// The connection already failed; release it and drop the socket.
    #[error("connection is closed")]
    Closed,
}

impl Error {
    /// Whether the connection is unusable after this error.
    ///
    /// Transport failures and protocol violations are fatal. A host call that
    /// named an unknown channel, asked for a target above the miner's maximum,
    /// or passed a malformed error code is refused without touching the
    /// connection.
    #[must_use]
    pub fn is_fatal(&self) -> bool {
        match self {
            Self::Transport(_) | Self::Closed => true,
            Self::Session(error) => error.is_fatal(),
        }
    }
}

/// The pool authority key pair, as raw 32-byte x-only keys.
///
/// Raw bytes are the whole interface to `noise_sv2` on purpose: the secret
/// never becomes a `secp256k1` type of a version this crate does not control,
/// and it is wiped when dropped.
pub struct AuthorityKeypair {
    public: [u8; 32],
    secret: Zeroizing<[u8; 32]>,
}

impl AuthorityKeypair {
    /// Wraps the BIP340 x-only public key and an already-zeroizing 32-byte
    /// secret. [`Connection::accept`] verifies that the pair matches.
    ///
    /// Requiring [`Zeroizing`] at this boundary ensures the caller's secret
    /// buffer is wiped on drop rather than merely copying it into the
    /// authority object.
    #[must_use]
    pub fn from_bytes(public: [u8; 32], secret: Zeroizing<[u8; 32]>) -> Self {
        Self { public, secret }
    }

    /// The public key miners pin.
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

/// `Noise_NX` responder plus bounded `SV2` framing.
///
/// The decoder is fed exactly the byte count it asks for, and the number of
/// encrypted bytes fed for the current frame is checked against the ceiling
/// the configured payload limit implies *before* each read, so an oversized
/// declaration is refused after the encrypted header, never buffered.
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
            // The state is consumed with the error: the connection is over.
            Err(e) => Err(TransportError::Decrypt(e.to_string())),
        }
    }

    fn send(&mut self, frame: &Frame) -> Result<(), TransportError> {
        let bytes = frame_bytes(frame)?;
        // Refuse before encrypting: an encrypted frame that is then dropped
        // would leave the peer's nonce behind ours.
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
///
/// Sans-IO. Every method that can queue output leaves it in
/// [`Connection::take_transmit`]. After any `Err` the connection is dead:
/// drain `take_transmit` if you want a last message out, call
/// [`Connection::release`], and drop the socket.
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
    /// A server-side connection awaiting the miner's first handshake bytes.
    ///
    /// `book` is only read, to check that its extranonce layout fits the wire.
    /// `cert_validity` is how long the certificate this connection presents
    /// stays valid.
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

    /// How many more bytes would let the decoder make progress; read at least
    /// this much (reading more is always safe).
    #[must_use]
    pub fn read_hint(&self) -> usize {
        self.transport.read_hint()
    }

    /// The protocol session, for inspection.
    #[must_use]
    pub fn session(&self) -> &ProtocolSession {
        &self.session
    }

    /// True once the connection must be flushed and closed (a refused
    /// `SetupConnection`, a failure, or [`Connection::release`]).
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

    /// Feeds bytes read from the socket (any length up to [`MAX_FEED_LEN`]).
    ///
    /// Decrypts and decodes every complete frame, runs the protocol session on
    /// it against `book`, and queues the replies.
    pub fn feed(&mut self, data: &[u8], book: &mut JobBook) -> Result<(), Error> {
        self.guard(|conn| {
            let frames = conn.transport.feed(data)?;
            for frame in frames {
                conn.session.handle(book, frame)?;
            }
            conn.flush()
        })
    }

    /// Drains the encrypted bytes to write to the socket.
    pub fn take_transmit(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.transport.outbox)
    }

    /// Next host event, if any.
    pub fn poll_event(&mut self) -> Option<Event> {
        self.session.poll_event()
    }

    /// Announces a job the owner just installed; see [`ProtocolSession::announce`].
    pub fn announce(&mut self, installed: &Installed) -> Result<(), Error> {
        self.guard(|conn| {
            conn.session.announce(installed)?;
            conn.flush()
        })
    }

    /// The host recorded the share: send `SubmitShares.Success`.
    pub fn confirm_share(&mut self, ticket: ShareTicket) -> Result<bool, Error> {
        self.guard(|conn| {
            let sent = conn.session.confirm_share(ticket)?;
            conn.flush()?;
            Ok(sent)
        })
    }

    /// The host submitted and recorded a found block: send `SubmitShares.Success`.
    ///
    /// The token must come from [`PendingBlock::submit`] after the host
    /// called its authoritative [`MiningControl`] and recorded the receipt in the
    /// ledger.
    pub fn confirm_block(&mut self, submission: &BlockSubmission) -> Result<bool, Error> {
        self.guard(|conn| {
            let sent = conn.session.confirm_block(submission)?;
            conn.flush()?;
            Ok(sent)
        })
    }

    /// The host could not record the share: send `SubmitShares.Error`.
    pub fn reject_share(&mut self, ticket: ShareTicket, code: &'static str) -> Result<bool, Error> {
        self.guard(|conn| {
            let sent = conn.session.reject_share(ticket, code)?;
            conn.flush()?;
            Ok(sent)
        })
    }

    /// Retargets a channel or the group channel; see [`ProtocolSession::set_target`].
    pub fn set_target(&mut self, id: u32, target: ShareTarget) -> Result<(), Error> {
        self.guard(|conn| {
            conn.session.set_target(id, target)?;
            conn.flush()
        })
    }

    /// Closes a channel (or the whole group) and releases its owner sessions.
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

    /// Sends `Reconnect`; see [`ProtocolSession::request_reconnect`].
    pub fn request_reconnect(&mut self, new_host: &str, new_port: u16) -> Result<(), Error> {
        self.guard(|conn| {
            conn.session.request_reconnect(new_host, new_port)?;
            conn.flush()
        })
    }

    /// Releases every owner session. Call on every exit path; idempotent.
    pub fn release(&mut self, book: &mut JobBook) {
        self.session.release(book);
        self.dead = true;
    }
}
