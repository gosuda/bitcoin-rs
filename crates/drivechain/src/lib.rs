//! Native BIP300/301 protocol primitives and validation.
//!
//! This crate owns the Drivechain wire dialect. Node integration is compiled
//! only by the `drivechain` feature and has no registration side effect:
//! network identity and runtime configuration decide activation separately.

use bitcoin::{
    Block, Script,
    hashes::Hash as _,
    opcodes::{OP_TRUE, all::OP_RETURN},
    script::Instruction,
};
use thiserror::Error;

#[allow(missing_docs)]
mod state;

pub use state::{
    ActiveSidechain, Ctip, PendingBundle, Proposal, State, StateError, StateTransition, Thresholds,
};

/// Deployed BIP300 M1 sidechain-proposal tag.
pub const M1_TAG: [u8; 4] = [0xd5, 0xe0, 0xc4, 0xaf];
/// Deployed BIP300 M2 proposal-acknowledgement tag.
///
/// The draft BIP text currently spells the last byte `0xbf`; ECX and the
/// independent enforcer wire implementation use `0xdf`. Native ECX
/// compatibility follows the deployed byte sequence.
pub const M2_TAG: [u8; 4] = [0xd6, 0xe1, 0xc5, 0xdf];
/// Deployed BIP300 M3 withdrawal-bundle proposal tag.
pub const M3_TAG: [u8; 4] = [0xd4, 0x5a, 0xa9, 0x43];
/// Deployed BIP300 M4 withdrawal-bundle vote tag.
pub const M4_TAG: [u8; 4] = [0xd7, 0x7d, 0x17, 0x76];
/// BIP301 M7 BMM-accept tag.
pub const M7_TAG: [u8; 4] = [0xd1, 0x61, 0x73, 0x68];
/// BIP301 M8 BMM-request tag.
pub const M8_TAG: [u8; 3] = [0x00, 0xbf, 0x00];
/// Opcode redefined as `OP_DRIVECHAIN` by BIP300.
pub const OP_DRIVECHAIN: u8 = 0xb4;

/// A parsed coinbase commitment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoinbaseMessage<'a> {
    /// M1: propose a sidechain for `slot`.
    ProposeSidechain {
        /// Sidechain slot.
        slot: u8,
        /// Serialized sidechain description.
        description: &'a [u8],
    },
    /// M2: acknowledge a sidechain proposal.
    AckSidechain {
        /// Sidechain slot.
        slot: u8,
        /// `SHA256d` of the serialized proposal description, in wire order.
        description_hash: [u8; 32],
    },
    /// M3: propose a withdrawal bundle.
    ProposeBundle {
        /// Sidechain slot.
        slot: u8,
        /// Blinded withdrawal transaction id, in wire order.
        bundle_id: [u8; 32],
    },
    /// M4: vote on withdrawal bundles.
    AckBundles(BundleVotes<'a>),
    /// M7: accept one BMM request for a sidechain.
    BmmAccept {
        /// Sidechain slot.
        slot: u8,
        /// Sidechain block commitment.
        sidechain_block_hash: [u8; 32],
    },
}

/// M4 vote-vector encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BundleVotes<'a> {
    /// Version 0: repeat the preceding block's votes.
    RepeatPrevious,
    /// Version 1: one byte per active sidechain.
    OneByte(&'a [u8]),
    /// Version 2: little-endian `u16` values, one per active sidechain.
    TwoBytes(&'a [u8]),
    /// Version 3: vote for candidates leading their rivals by at least 50.
    LeadingBy50,
}

/// M8 request carried by a non-coinbase transaction output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BmmRequest {
    /// Sidechain slot.
    pub slot: u8,
    /// Requested sidechain block commitment.
    pub sidechain_block_hash: [u8; 32],
    /// Required preceding mainchain block hash, in wire order.
    pub previous_mainchain_block_hash: [u8; 32],
}

/// Version-0 sidechain declaration embedded in an M1 description.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SidechainDeclaration<'a> {
    /// Human-readable sidechain title.
    pub title: &'a str,
    /// Human-readable sidechain description.
    pub description: &'a str,
    /// Intended hash of the canonical sidechain software archive.
    pub hash_id_1: [u8; 32],
    /// Intended source revision identifier.
    pub hash_id_2: [u8; 20],
}

/// A script began with a known Drivechain tag but was not canonical.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum MessageError {
    /// The known message did not have its required exact payload shape.
    #[error("non-canonical {message} payload")]
    NonCanonical {
        /// Stable protocol message name.
        message: &'static str,
    },
    /// The M1 declaration uses an unsupported version.
    #[error("unsupported M1 declaration version {0}")]
    UnsupportedDeclarationVersion(u8),
    /// The M1 declaration is truncated or has an impossible field length.
    #[error("non-canonical M1 sidechain declaration")]
    NonCanonicalDeclaration,
    /// A human-readable M1 field is not UTF-8.
    #[error("M1 {field} is not valid UTF-8")]
    InvalidDeclarationUtf8 {
        /// Stable field name.
        field: &'static str,
    },
}

/// A BIP301 block-level M7/M8 rule violation.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum BmmBlockError {
    /// The block has no coinbase transaction to carry M7 commitments.
    #[error("block has no coinbase transaction")]
    MissingCoinbase,
    /// More than one M7 commitment selected a block for the same slot.
    #[error("multiple M7 BMM accepts for sidechain slot {slot}")]
    MultipleAccepts {
        /// Duplicated sidechain slot.
        slot: u8,
    },
    /// An M8 did not have a matching M7 in this block.
    #[error("M8 request for sidechain slot {slot} was not accepted by the coinbase")]
    RequestNotAccepted {
        /// Requested sidechain slot.
        slot: u8,
    },
    /// An M8 was tied to a different preceding mainchain block.
    #[error("M8 request for sidechain slot {slot} references an expired mainchain tip")]
    ExpiredRequest {
        /// Requested sidechain slot.
        slot: u8,
    },
    /// More than one valid M8 was included for one slot.
    #[error("multiple M8 BMM requests for sidechain slot {slot}")]
    MultipleRequests {
        /// Duplicated sidechain slot.
        slot: u8,
    },
}

/// Parses a canonical `OP_RETURN <push>` coinbase message.
///
/// Unknown and ordinary scripts return `Ok(None)`. Once a deployed tag is
/// recognized, malformed length, version, or trailing instructions are a
/// protocol error rather than silently becoming an ordinary output.
pub fn parse_coinbase_message(
    script: &Script,
) -> Result<Option<CoinbaseMessage<'_>>, MessageError> {
    let Some((payload, exact_script)) = op_return_payload(script) else {
        return Ok(None);
    };
    let Some(tag) = payload.get(..4) else {
        return Ok(None);
    };
    let body = &payload[4..];
    if tag == M1_TAG {
        if !exact_script {
            return Err(noncanonical("M1"));
        }
        let Some((&slot, description)) = body.split_first() else {
            return Err(noncanonical("M1"));
        };
        return Ok(Some(CoinbaseMessage::ProposeSidechain {
            slot,
            description,
        }));
    }
    if tag == M2_TAG {
        if !exact_script {
            return Err(noncanonical("M2"));
        }
        let (slot, value) = exact_slot_hash(body, "M2")?;
        return Ok(Some(CoinbaseMessage::AckSidechain {
            slot,
            description_hash: value,
        }));
    }
    if tag == M3_TAG {
        if !exact_script {
            return Err(noncanonical("M3"));
        }
        let (slot, value) = exact_slot_hash(body, "M3")?;
        return Ok(Some(CoinbaseMessage::ProposeBundle {
            slot,
            bundle_id: value,
        }));
    }
    if tag == M4_TAG {
        if !exact_script {
            return Err(noncanonical("M4"));
        }
        let Some((&version, votes)) = body.split_first() else {
            return Err(noncanonical("M4"));
        };
        let votes = match version {
            0 if votes.is_empty() => BundleVotes::RepeatPrevious,
            1 => BundleVotes::OneByte(votes),
            2 if votes.len().is_multiple_of(2) => BundleVotes::TwoBytes(votes),
            3 if votes.is_empty() => BundleVotes::LeadingBy50,
            _ => return Err(noncanonical("M4")),
        };
        return Ok(Some(CoinbaseMessage::AckBundles(votes)));
    }
    if tag == M7_TAG {
        if !exact_script {
            return Err(noncanonical("M7"));
        }
        let (slot, value) = exact_slot_hash(body, "M7")?;
        return Ok(Some(CoinbaseMessage::BmmAccept {
            slot,
            sidechain_block_hash: value,
        }));
    }
    Ok(None)
}

/// Parses a canonical BIP301 M8 request output.
pub fn parse_bmm_request(script: &Script) -> Result<Option<BmmRequest>, MessageError> {
    let Some((payload, exact_script)) = op_return_payload(script) else {
        return Ok(None);
    };
    if payload.get(..M8_TAG.len()) != Some(M8_TAG.as_slice()) {
        return Ok(None);
    }
    if !exact_script {
        return Err(noncanonical("M8"));
    }
    let body = &payload[M8_TAG.len()..];
    if body.len() != 65 {
        return Err(noncanonical("M8"));
    }
    let slot = body[0];
    let mut sidechain_block_hash = [0; 32];
    sidechain_block_hash.copy_from_slice(&body[1..33]);
    let mut previous_mainchain_block_hash = [0; 32];
    previous_mainchain_block_hash.copy_from_slice(&body[33..65]);
    Ok(Some(BmmRequest {
        slot,
        sidechain_block_hash,
        previous_mainchain_block_hash,
    }))
}

/// Parses the deployed version-0 M1 declaration serialization.
///
/// The description passed here is the bytes following the M1 slot. Its shape
/// is `version:u8, title_len:u8, title, description, hash_id_1:32,
/// hash_id_2:20`; the description occupies all bytes between the title and the
/// two fixed-size hashes.
pub fn parse_sidechain_declaration(value: &[u8]) -> Result<SidechainDeclaration<'_>, MessageError> {
    const HASH_BYTES: usize = 32 + 20;

    let Some((&version, rest)) = value.split_first() else {
        return Err(MessageError::NonCanonicalDeclaration);
    };
    if version != 0 {
        return Err(MessageError::UnsupportedDeclarationVersion(version));
    }
    let Some((&title_len, body)) = rest.split_first() else {
        return Err(MessageError::NonCanonicalDeclaration);
    };
    let title_len = usize::from(title_len);
    if body.len() < title_len + HASH_BYTES {
        return Err(MessageError::NonCanonicalDeclaration);
    }
    let (title, tail) = body.split_at(title_len);
    let description_len = tail.len() - HASH_BYTES;
    let (description, hashes) = tail.split_at(description_len);
    let title = core::str::from_utf8(title)
        .map_err(|_| MessageError::InvalidDeclarationUtf8 { field: "title" })?;
    let description =
        core::str::from_utf8(description).map_err(|_| MessageError::InvalidDeclarationUtf8 {
            field: "description",
        })?;
    let mut hash_id_1 = [0; 32];
    hash_id_1.copy_from_slice(&hashes[..32]);
    let mut hash_id_2 = [0; 20];
    hash_id_2.copy_from_slice(&hashes[32..]);
    Ok(SidechainDeclaration {
        title,
        description,
        hash_id_1,
        hash_id_2,
    })
}

/// Returns the sidechain slot for the exact four-byte BIP300 treasury script.
#[must_use]
pub fn parse_drivechain_script(script: &Script) -> Option<u8> {
    let bytes = script.as_bytes();
    (bytes.len() == 4 && bytes[0] == OP_DRIVECHAIN && bytes[1] == 1 && bytes[3] == OP_TRUE.to_u8())
        .then_some(bytes[2])
}

/// Validates the stateless BIP301 relationship between a block's M7 and M8
/// messages.
///
/// M7 messages are read from every coinbase output. An M8 is recognized only
/// in output zero of a non-coinbase transaction. Each request must match the
/// coinbase commitment for its slot, name the block's actual parent, and be the
/// only accepted request for that slot. Scripts that are not canonical messages
/// remain ordinary Bitcoin outputs.
pub fn validate_bmm_block(block: &Block) -> Result<(), BmmBlockError> {
    let Some((coinbase, transactions)) = block.txdata.split_first() else {
        return Err(BmmBlockError::MissingCoinbase);
    };
    let mut accepts = [None; 256];
    for output in &coinbase.output {
        let Ok(Some(CoinbaseMessage::BmmAccept {
            slot,
            sidechain_block_hash,
        })) = parse_coinbase_message(&output.script_pubkey)
        else {
            continue;
        };
        let entry = &mut accepts[usize::from(slot)];
        if entry.replace(sidechain_block_hash).is_some() {
            return Err(BmmBlockError::MultipleAccepts { slot });
        }
    }

    let parent = block.header.prev_blockhash.to_byte_array();
    let mut requested = [false; 256];
    for transaction in transactions {
        let Some(output) = transaction.output.first() else {
            continue;
        };
        let Ok(Some(request)) = parse_bmm_request(&output.script_pubkey) else {
            continue;
        };
        if accepts[usize::from(request.slot)] != Some(request.sidechain_block_hash) {
            return Err(BmmBlockError::RequestNotAccepted { slot: request.slot });
        }
        if request.previous_mainchain_block_hash != parent {
            return Err(BmmBlockError::ExpiredRequest { slot: request.slot });
        }
        if core::mem::replace(&mut requested[usize::from(request.slot)], true) {
            return Err(BmmBlockError::MultipleRequests { slot: request.slot });
        }
    }
    Ok(())
}

fn exact_slot_hash(body: &[u8], message: &'static str) -> Result<(u8, [u8; 32]), MessageError> {
    if body.len() != 33 {
        return Err(noncanonical(message));
    }
    let mut value = [0; 32];
    value.copy_from_slice(&body[1..]);
    Ok((body[0], value))
}

fn noncanonical(message: &'static str) -> MessageError {
    MessageError::NonCanonical { message }
}

fn op_return_payload(script: &Script) -> Option<(&[u8], bool)> {
    let mut instructions = script.instructions();
    if !matches!(instructions.next(), Some(Ok(Instruction::Op(opcode))) if opcode == OP_RETURN) {
        return None;
    }
    let Some(Ok(Instruction::PushBytes(payload))) = instructions.next() else {
        return None;
    };
    let exact_script = instructions.next().is_none();
    Some((payload.as_bytes(), exact_script))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use bitcoin::{
        Amount, BlockHash, CompactTarget, ScriptBuf, Transaction, TxIn, TxMerkleNode, TxOut,
        absolute::LockTime,
        block::{Header, Version},
        hashes::Hash as _,
        script::PushBytesBuf,
        transaction,
    };

    use super::*;

    fn op_return(payload: Vec<u8>) -> ScriptBuf {
        ScriptBuf::new_op_return(PushBytesBuf::try_from(payload).expect("bounded test payload"))
    }

    fn transaction_with_first_output(script_pubkey: ScriptBuf) -> Transaction {
        Transaction {
            version: transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey,
            }],
        }
    }

    fn bmm_block(
        parent: [u8; 32],
        coinbase_outputs: Vec<ScriptBuf>,
        transactions: Vec<Transaction>,
    ) -> Block {
        let coinbase = Transaction {
            version: transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: coinbase_outputs
                .into_iter()
                .map(|script_pubkey| TxOut {
                    value: Amount::ZERO,
                    script_pubkey,
                })
                .collect(),
        };
        Block {
            header: Header {
                version: Version::ONE,
                prev_blockhash: BlockHash::from_byte_array(parent),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0,
                bits: CompactTarget::from_consensus(0),
                nonce: 0,
            },
            txdata: core::iter::once(coinbase).chain(transactions).collect(),
        }
    }

    fn m7(slot: u8, commitment: [u8; 32]) -> ScriptBuf {
        op_return([M7_TAG.as_slice(), &[slot], &commitment].concat())
    }

    fn m8(slot: u8, commitment: [u8; 32], parent: [u8; 32]) -> Transaction {
        transaction_with_first_output(op_return(
            [M8_TAG.as_slice(), &[slot], &commitment, &parent].concat(),
        ))
    }

    #[test]
    fn parses_deployed_coinbase_messages() {
        let m1 = op_return([M1_TAG.as_slice(), &[7], b"description"].concat());
        assert_eq!(
            parse_coinbase_message(&m1),
            Ok(Some(CoinbaseMessage::ProposeSidechain {
                slot: 7,
                description: b"description",
            }))
        );

        for (tag, expected) in [
            (
                M2_TAG,
                CoinbaseMessage::AckSidechain {
                    slot: 8,
                    description_hash: [2; 32],
                },
            ),
            (
                M3_TAG,
                CoinbaseMessage::ProposeBundle {
                    slot: 8,
                    bundle_id: [2; 32],
                },
            ),
            (
                M7_TAG,
                CoinbaseMessage::BmmAccept {
                    slot: 8,
                    sidechain_block_hash: [2; 32],
                },
            ),
        ] {
            let script = op_return([tag.as_slice(), &[8], &[2; 32]].concat());
            assert_eq!(parse_coinbase_message(&script), Ok(Some(expected)));
        }
    }

    #[test]
    fn enforces_exact_fixed_message_lengths() {
        for tag in [M2_TAG, M3_TAG, M7_TAG] {
            let short = op_return([tag.as_slice(), &[0; 32]].concat());
            assert!(parse_coinbase_message(&short).is_err());
            let long = op_return([tag.as_slice(), &[0; 34]].concat());
            assert!(parse_coinbase_message(&long).is_err());
        }
    }

    #[test]
    fn parses_and_bounds_m4_versions() {
        let repeat = op_return([M4_TAG.as_slice(), &[0]].concat());
        assert_eq!(
            parse_coinbase_message(&repeat),
            Ok(Some(CoinbaseMessage::AckBundles(
                BundleVotes::RepeatPrevious
            )))
        );
        let wide = op_return([M4_TAG.as_slice(), &[2, 1, 0, 2, 0]].concat());
        assert_eq!(
            parse_coinbase_message(&wide),
            Ok(Some(CoinbaseMessage::AckBundles(BundleVotes::TwoBytes(&[
                1, 0, 2, 0
            ]))))
        );
        let odd_wide = op_return([M4_TAG.as_slice(), &[2, 1]].concat());
        assert!(parse_coinbase_message(&odd_wide).is_err());
        let trailing_repeat = op_return([M4_TAG.as_slice(), &[0, 1]].concat());
        assert!(parse_coinbase_message(&trailing_repeat).is_err());
    }

    #[test]
    fn parses_m8_and_rejects_trailing_bytes() {
        let canonical = op_return([M8_TAG.as_slice(), &[9], &[0x11; 32], &[0x22; 32]].concat());
        assert_eq!(
            parse_bmm_request(&canonical),
            Ok(Some(BmmRequest {
                slot: 9,
                sidechain_block_hash: [0x11; 32],
                previous_mainchain_block_hash: [0x22; 32],
            }))
        );
        let trailing =
            op_return([M8_TAG.as_slice(), &[9], &[0x11; 32], &[0x22; 32], &[0]].concat());
        assert!(parse_bmm_request(&trailing).is_err());
    }

    #[test]
    fn parses_deployed_m1_declaration() {
        let encoded = [
            &[0, 4][..],
            b"name",
            b"description",
            &[0x11; 32],
            &[0x22; 20],
        ]
        .concat();
        assert_eq!(
            parse_sidechain_declaration(&encoded),
            Ok(SidechainDeclaration {
                title: "name",
                description: "description",
                hash_id_1: [0x11; 32],
                hash_id_2: [0x22; 20],
            })
        );
    }

    #[test]
    fn rejects_malformed_m1_declarations() {
        assert_eq!(
            parse_sidechain_declaration(&[]),
            Err(MessageError::NonCanonicalDeclaration)
        );
        assert_eq!(
            parse_sidechain_declaration(&[1, 0]),
            Err(MessageError::UnsupportedDeclarationVersion(1))
        );
        assert_eq!(
            parse_sidechain_declaration(&[0, 10, 1, 2]),
            Err(MessageError::NonCanonicalDeclaration)
        );
        let invalid_title = [&[0, 1][..], &[0xff], &[0; 52]].concat();
        assert_eq!(
            parse_sidechain_declaration(&invalid_title),
            Err(MessageError::InvalidDeclarationUtf8 { field: "title" })
        );
    }

    #[test]
    fn drivechain_script_is_exact() {
        assert_eq!(
            parse_drivechain_script(Script::from_bytes(&[OP_DRIVECHAIN, 1, 255, 0x51])),
            Some(255)
        );
        assert_eq!(
            parse_drivechain_script(Script::from_bytes(&[OP_DRIVECHAIN, 0x51, 0x51])),
            None
        );
        assert_eq!(
            parse_drivechain_script(Script::from_bytes(&[OP_DRIVECHAIN, 1, 1, 0x51, 0])),
            None
        );
    }

    #[test]
    fn ordinary_and_unknown_op_returns_are_not_drivechain_messages() {
        assert_eq!(parse_coinbase_message(Script::new()), Ok(None));
        assert_eq!(
            parse_coinbase_message(&op_return(vec![1, 2, 3, 4])),
            Ok(None)
        );
        assert_eq!(parse_bmm_request(&op_return(vec![0, 1, 2])), Ok(None));
    }

    #[test]
    fn recognized_message_with_a_trailing_instruction_is_invalid() {
        let payload = PushBytesBuf::try_from([M7_TAG.as_slice(), &[0; 33]].concat())
            .expect("bounded test payload");
        let script = bitcoin::script::Builder::new()
            .push_opcode(OP_RETURN)
            .push_slice(&payload)
            .push_int(1)
            .into_script();
        assert_eq!(
            parse_coinbase_message(&script),
            Err(MessageError::NonCanonical { message: "M7" })
        );
    }

    #[test]
    fn validates_matching_m7_and_m8() {
        let parent = [0x31; 32];
        let commitment = [0x42; 32];
        let block = bmm_block(
            parent,
            vec![m7(7, commitment)],
            vec![m8(7, commitment, parent)],
        );
        assert_eq!(validate_bmm_block(&block), Ok(()));
    }

    #[test]
    fn rejects_unaccepted_expired_and_duplicate_requests() {
        let parent = [0x31; 32];
        let commitment = [0x42; 32];
        let unaccepted = bmm_block(parent, vec![], vec![m8(7, commitment, parent)]);
        assert_eq!(
            validate_bmm_block(&unaccepted),
            Err(BmmBlockError::RequestNotAccepted { slot: 7 })
        );

        let expired = bmm_block(
            parent,
            vec![m7(7, commitment)],
            vec![m8(7, commitment, [0x99; 32])],
        );
        assert_eq!(
            validate_bmm_block(&expired),
            Err(BmmBlockError::ExpiredRequest { slot: 7 })
        );

        let duplicate = bmm_block(
            parent,
            vec![m7(7, commitment)],
            vec![m8(7, commitment, parent), m8(7, commitment, parent)],
        );
        assert_eq!(
            validate_bmm_block(&duplicate),
            Err(BmmBlockError::MultipleRequests { slot: 7 })
        );
    }

    #[test]
    fn rejects_multiple_m7_accepts_for_one_slot() {
        let block = bmm_block([0x31; 32], vec![m7(7, [1; 32]), m7(7, [2; 32])], vec![]);
        assert_eq!(
            validate_bmm_block(&block),
            Err(BmmBlockError::MultipleAccepts { slot: 7 })
        );
    }

    #[test]
    fn only_output_zero_can_be_an_m8() {
        let parent = [0x31; 32];
        let commitment = [0x42; 32];
        let request = op_return([M8_TAG.as_slice(), &[7], &commitment, &parent].concat());
        let transaction = Transaction {
            version: transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![
                TxOut {
                    value: Amount::ZERO,
                    script_pubkey: ScriptBuf::new(),
                },
                TxOut {
                    value: Amount::ZERO,
                    script_pubkey: request,
                },
            ],
        };
        let block = bmm_block(parent, vec![], vec![transaction]);
        assert_eq!(validate_bmm_block(&block), Ok(()));
    }
}
