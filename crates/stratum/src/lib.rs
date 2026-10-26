//! Native Stratum pool protocol and the shared job/share projection owner.
//!
//! [`JobBook`] is the single owner of projected jobs, extranonce allocation,
//! share validation, stale/duplicate state, and block assembly. The SV1
//! adapter is a sibling module over that owner; it does not hash headers,
//! build coinbases, or maintain a second share predicate.
#![forbid(unsafe_code)]

mod job;
mod sv1;

pub use job::{
    AcceptedShare, BIP320_VERSION_MASK, BlockReceipt, BlockStatus, Extranonce, ExtranonceLayout,
    FoundBlock, Installed, Job, JobBook, JobBookConfig, JobError, JobId,
    MAX_COINBASE_SCRIPT_SIG_LEN, MAX_NTIME_FORWARD_SECS, Session, SessionId, ShareClass,
    ShareError, ShareOutcome, ShareSubmission, ShareTarget, ShareWork, StaleReason, fetch_template,
};
pub use sv1::errors;
pub use sv1::{
    AccountResolver, AuthDenied, Authorize, ClientRequest, Configure, DecodeFailure, Difficulty,
    DifficultyError, DifficultyPolicy, FrameError, Incoming, InvalidAccount, LedgerUnavailable,
    LineBuffer, MAX_CONFIGURE_EXTENSIONS, MAX_DIFFICULTY_TEXT_LEN, MAX_EXTENSION_NAME_LEN,
    MAX_EXTRANONCE2_BYTES, MAX_ID_LEN, MAX_JOB_ID_LEN, MAX_JSON_DEPTH, MAX_LOGIN_LEN,
    MAX_METHOD_LEN, MAX_PARAMS, MAX_PASSWORD_LEN, MAX_USER_AGENT_LEN, Password, RecordOutcome,
    Request, RequestId, ShareLedger, StaticAccountResolver, Submit, Subscribe, WireError,
    WorkerIdentity, decode_hex, decode_line, encode_error, encode_hex, encode_notify,
    encode_reject, encode_result, encode_set_difficulty, json_string, parse_u32_hex,
    parse_wire_job_id, prevhash_from_wire, prevhash_to_wire, push_hex, swap_words, wire_job_id,
};
pub use sv1::{
    BlockOutcome, ConfigError, ConnectionLimiter, ConnectionPermit, Observer, PoolCore,
    RefreshError, Refreshed, RefusalReason, Server, ServerConfig, ServerDeps, ServerEvent,
    SessionEnd, ShutdownReport,
};
