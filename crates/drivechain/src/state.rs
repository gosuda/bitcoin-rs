use std::collections::{BTreeMap, BTreeSet};

use bitcoin::{Block, OutPoint, Transaction, Txid, hashes::Hash as _};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    BundleVotes, CoinbaseMessage, parse_coinbase_message, parse_drivechain_script,
    parse_sidechain_declaration, validate_bmm_block,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Thresholds {
    pub withdrawal_bundle_max_age: u16,
    pub withdrawal_bundle_inclusion_threshold: u16,
    pub used_slot_proposal_max_age: u16,
    pub used_slot_activation_threshold: u16,
    pub unused_slot_proposal_max_age: u16,
    pub unused_slot_activation_threshold: u16,
}

impl Thresholds {
    pub const MAINNET: Self = Self {
        withdrawal_bundle_max_age: 26_300,
        withdrawal_bundle_inclusion_threshold: 13_150,
        used_slot_proposal_max_age: 26_300,
        used_slot_activation_threshold: 13_150,
        unused_slot_proposal_max_age: 2_016,
        unused_slot_activation_threshold: 1_815,
    };

    pub const REGTEST: Self = Self {
        withdrawal_bundle_max_age: 10,
        withdrawal_bundle_inclusion_threshold: 5,
        used_slot_proposal_max_age: 10,
        used_slot_activation_threshold: 5,
        unused_slot_proposal_max_age: 10,
        unused_slot_activation_threshold: 5,
    };

    pub const DRYNET4: Self = Self {
        withdrawal_bundle_max_age: 144,
        withdrawal_bundle_inclusion_threshold: 72,
        used_slot_proposal_max_age: 144,
        used_slot_activation_threshold: 72,
        unused_slot_proposal_max_age: 36,
        unused_slot_activation_threshold: 30,
    };
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Proposal {
    pub slot: u8,
    pub description: Vec<u8>,
    pub description_hash: [u8; 32],
    pub vote_count: u16,
    pub proposal_height: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Ctip {
    pub txid: [u8; 32],
    pub vout: u32,
    pub value_sat: u64,
    pub sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PendingBundle {
    pub id: [u8; 32],
    pub vote_count: u16,
    pub proposal_height: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ActiveSidechain {
    pub proposal: Proposal,
    pub activation_height: u32,
    pub ctip: Option<Ctip>,
    pub pending_bundles: Vec<PendingBundle>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum VoteAction {
    Upvote([u8; 32]),
    Alarm,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct State {
    version: u8,
    tip: Option<[u8; 32]>,
    height: Option<u32>,
    thresholds: Thresholds,
    activation_height: u32,
    // A vector is intentional: JSON object keys cannot losslessly represent
    // the `(slot, hash)` tuple, while insertion order is deterministic from
    // block order and therefore gives the durable encoding one owner.
    proposals: Vec<Proposal>,
    active: BTreeMap<u8, ActiveSidechain>,
    previous_votes: BTreeMap<u8, VoteAction>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateTransition {
    previous: State,
    next: State,
}

impl StateTransition {
    #[must_use]
    pub fn previous(&self) -> &State {
        &self.previous
    }
    #[must_use]
    pub fn next(&self) -> &State {
        &self.next
    }
    #[must_use]
    pub fn into_next(self) -> State {
        self.next
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum StateError {
    #[error("block parent does not match Drivechain tip")]
    ParentMismatch,
    #[error("block height does not follow Drivechain height")]
    HeightMismatch,
    #[error("block has no coinbase transaction")]
    MissingCoinbase,
    #[error("malformed {0} Drivechain message")]
    MalformedMessage(String),
    #[error("duplicate {message} for sidechain slot {slot}")]
    DuplicateMessage { message: &'static str, slot: u8 },
    #[error("more than one M4 message in a block")]
    DuplicateM4,
    #[error("M3 names inactive sidechain slot {0}")]
    InactiveBundleSlot(u8),
    #[error("withdrawal bundle is already pending for slot {0}")]
    BundleAlreadyPending(u8),
    #[error("M4 vote vector has {actual} entries; expected {expected}")]
    VoteVectorLength { expected: usize, actual: usize },
    #[error("M4 vote {index} is not a pending bundle for slot {slot}")]
    InvalidBundleVote { slot: u8, index: u16 },
    #[error("M4 two-byte encoding is non-canonical")]
    NonCanonicalTwoByteVotes,
    #[error("BIP301 validation failed: {0}")]
    Bmm(String),
    #[error("treasury for slot {0} was spent without a replacement")]
    TreasurySpentWithoutReplacement(u8),
    #[error("treasury output for slot {0} does not spend its previous CTIP")]
    OldTreasuryUnspent(u8),
    #[error("multiple treasury outputs for slot {0}")]
    MultipleTreasuryOutputs(u8),
    #[error("treasury value for slot {0} did not change")]
    ZeroTreasuryDelta(u8),
    #[error("deposit for slot {0} has no following OP_RETURN address")]
    MissingDepositAddress(u8),
    #[error("a transaction mixes deposits and withdrawals")]
    AmbiguousTreasuryTransaction,
    #[error("invalid withdrawal for slot {slot}: {reason}")]
    InvalidWithdrawal { slot: u8, reason: &'static str },
    #[error("Drivechain state serialization failed: {0}")]
    Serialization(String),
}

impl State {
    #[must_use]
    pub fn new(thresholds: Thresholds, activation_height: u32) -> Self {
        Self {
            version: 1,
            tip: None,
            height: None,
            thresholds,
            activation_height,
            proposals: Vec::new(),
            active: BTreeMap::new(),
            previous_votes: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn at_cursor(
        thresholds: Thresholds,
        activation_height: u32,
        cursor: Option<(u32, [u8; 32])>,
    ) -> Self {
        let mut state = Self::new(thresholds, activation_height);
        if let Some((height, tip)) = cursor {
            state.height = Some(height);
            state.tip = Some(tip);
        }
        state
    }

    #[must_use]
    pub const fn tip(&self) -> Option<[u8; 32]> {
        self.tip
    }
    #[must_use]
    pub const fn height(&self) -> Option<u32> {
        self.height
    }
    #[must_use]
    pub fn proposals(&self) -> &[Proposal] {
        &self.proposals
    }
    #[must_use]
    pub fn active_sidechains(&self) -> &BTreeMap<u8, ActiveSidechain> {
        &self.active
    }

    pub fn encode(&self) -> Result<Vec<u8>, StateError> {
        serde_json::to_vec(self).map_err(|error| StateError::Serialization(error.to_string()))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, StateError> {
        let state: Self = serde_json::from_slice(bytes)
            .map_err(|error| StateError::Serialization(error.to_string()))?;
        if state.version != 1 {
            return Err(StateError::Serialization(
                "unsupported state version".to_owned(),
            ));
        }
        Ok(state)
    }

    pub fn validate_block(
        &self,
        block: &Block,
        height: u32,
    ) -> Result<StateTransition, StateError> {
        let parent = block.header.prev_blockhash.to_byte_array();
        if self.tip.is_some_and(|tip| tip != parent) {
            return Err(StateError::ParentMismatch);
        }
        if self
            .height
            .is_some_and(|old| old.checked_add(1) != Some(height))
        {
            return Err(StateError::HeightMismatch);
        }
        let mut next = self.clone();
        next.tip = Some(block.block_hash().to_byte_array());
        next.height = Some(height);
        if height >= self.activation_height {
            next.apply_active_block(block, height)?;
        }
        Ok(StateTransition {
            previous: self.clone(),
            next,
        })
    }

    fn apply_active_block(&mut self, block: &Block, height: u32) -> Result<(), StateError> {
        validate_bmm_block(block).map_err(|error| StateError::Bmm(error.to_string()))?;
        let coinbase = block.txdata.first().ok_or(StateError::MissingCoinbase)?;
        let mut m1 = BTreeSet::new();
        let mut m2 = BTreeSet::new();
        let mut m7 = BTreeSet::new();
        let mut saw_m4 = false;
        let mut resolved_votes = None;
        for output in &coinbase.output {
            let message = match parse_coinbase_message(&output.script_pubkey) {
                Ok(Some(message)) => message,
                Ok(None) | Err(_) => continue,
            };
            match message {
                CoinbaseMessage::ProposeSidechain { slot, description } => {
                    let declaration = parse_sidechain_declaration(description)
                        .map_err(|error| StateError::MalformedMessage(error.to_string()))?;
                    let _ = declaration;
                    let hash = bitcoin::hashes::sha256d::Hash::hash(description).to_byte_array();
                    if !m1.insert((slot, hash)) {
                        return Err(StateError::DuplicateMessage {
                            message: "M1",
                            slot,
                        });
                    }
                    if !self
                        .proposals
                        .iter()
                        .any(|proposal| proposal.slot == slot && proposal.description_hash == hash)
                    {
                        self.proposals.push(Proposal {
                            slot,
                            description: description.to_vec(),
                            description_hash: hash,
                            vote_count: 0,
                            proposal_height: height,
                        });
                    }
                }
                CoinbaseMessage::AckSidechain {
                    slot,
                    description_hash,
                } => {
                    if !m2.insert(slot) {
                        return Err(StateError::DuplicateMessage {
                            message: "M2",
                            slot,
                        });
                    }
                    self.ack_proposal(slot, description_hash, height);
                }
                CoinbaseMessage::ProposeBundle { slot, bundle_id } => {
                    self.propose_bundle(slot, bundle_id, height)?;
                }
                CoinbaseMessage::AckBundles(votes) => {
                    if saw_m4 {
                        return Err(StateError::DuplicateM4);
                    }
                    saw_m4 = true;
                    resolved_votes = Some(self.resolve_votes(votes)?);
                }
                CoinbaseMessage::BmmAccept { slot, .. } => {
                    if !m7.insert(slot) {
                        return Err(StateError::DuplicateMessage {
                            message: "M7",
                            slot,
                        });
                    }
                }
            }
        }
        let votes = resolved_votes.unwrap_or_default();
        self.apply_votes(&votes);
        self.previous_votes = votes;
        self.expire(height);
        for transaction in &block.txdata[1..] {
            self.apply_treasury_transaction(transaction)?;
        }
        Ok(())
    }

    fn ack_proposal(&mut self, slot: u8, hash: [u8; 32], height: u32) {
        let Some(index) = self
            .proposals
            .iter()
            .position(|proposal| proposal.slot == slot && proposal.description_hash == hash)
        else {
            return;
        };
        let proposal = &mut self.proposals[index];
        if proposal.proposal_height == height {
            return;
        }
        proposal.vote_count = proposal.vote_count.saturating_add(1);
        let used = self.active.contains_key(&slot);
        let age = height.saturating_sub(proposal.proposal_height);
        let (max_age, threshold) = if used {
            (
                self.thresholds.used_slot_proposal_max_age,
                self.thresholds.used_slot_activation_threshold,
            )
        } else {
            (
                self.thresholds.unused_slot_proposal_max_age,
                self.thresholds.unused_slot_activation_threshold,
            )
        };
        if age <= u32::from(max_age) && proposal.vote_count > threshold {
            let activated = proposal.clone();
            self.active.insert(
                slot,
                ActiveSidechain {
                    proposal: activated,
                    activation_height: height,
                    ctip: None,
                    pending_bundles: Vec::new(),
                },
            );
            self.proposals.remove(index);
        }
    }

    fn propose_bundle(&mut self, slot: u8, id: [u8; 32], height: u32) -> Result<(), StateError> {
        let sidechain = self
            .active
            .get_mut(&slot)
            .ok_or(StateError::InactiveBundleSlot(slot))?;
        if sidechain
            .pending_bundles
            .iter()
            .any(|bundle| bundle.id == id)
        {
            return Err(StateError::BundleAlreadyPending(slot));
        }
        sidechain.pending_bundles.push(PendingBundle {
            id,
            vote_count: 1,
            proposal_height: height,
        });
        Ok(())
    }

    fn resolve_votes(
        &self,
        votes: BundleVotes<'_>,
    ) -> Result<BTreeMap<u8, VoteAction>, StateError> {
        match votes {
            BundleVotes::RepeatPrevious => Ok(self.previous_votes.clone()),
            BundleVotes::LeadingBy50 => {
                let mut result = BTreeMap::new();
                for (&slot, sidechain) in &self.active {
                    let mut ranked: Vec<_> = sidechain.pending_bundles.iter().collect();
                    ranked.sort_unstable_by_key(|bundle| std::cmp::Reverse(bundle.vote_count));
                    if let Some(leader) = ranked.first() {
                        let second = ranked.get(1).map_or(0, |bundle| bundle.vote_count);
                        if leader.vote_count.saturating_sub(second) >= 50
                            && leader.vote_count < u16::MAX
                        {
                            result.insert(slot, VoteAction::Upvote(leader.id));
                        }
                    }
                }
                Ok(result)
            }
            BundleVotes::OneByte(raw) => {
                let decoded: Vec<u16> = raw
                    .iter()
                    .map(|value| match value {
                        0xff => 0xffff,
                        0xfe => 0xfffe,
                        value => u16::from(*value),
                    })
                    .collect();
                self.resolve_index_votes(&decoded)
            }
            BundleVotes::TwoBytes(raw) => {
                let decoded: Vec<u16> = raw
                    .chunks_exact(2)
                    .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                    .collect();
                if decoded.iter().all(|vote| *vote <= 253) {
                    return Err(StateError::NonCanonicalTwoByteVotes);
                }
                self.resolve_index_votes(&decoded)
            }
        }
    }

    fn resolve_index_votes(&self, votes: &[u16]) -> Result<BTreeMap<u8, VoteAction>, StateError> {
        if votes.len() != self.active.len() {
            return Err(StateError::VoteVectorLength {
                expected: self.active.len(),
                actual: votes.len(),
            });
        }
        let mut result = BTreeMap::new();
        for ((&slot, sidechain), &vote) in self.active.iter().zip(votes) {
            match vote {
                0xffff => {}
                0xfffe => {
                    result.insert(slot, VoteAction::Alarm);
                }
                index => {
                    let bundle = sidechain
                        .pending_bundles
                        .get(usize::from(index))
                        .ok_or(StateError::InvalidBundleVote { slot, index })?;
                    if bundle.vote_count < u16::MAX {
                        result.insert(slot, VoteAction::Upvote(bundle.id));
                    }
                }
            }
        }
        Ok(result)
    }

    fn apply_votes(&mut self, votes: &BTreeMap<u8, VoteAction>) {
        for (&slot, action) in votes {
            let Some(sidechain) = self.active.get_mut(&slot) else {
                continue;
            };
            match action {
                VoteAction::Alarm => {
                    for bundle in &mut sidechain.pending_bundles {
                        bundle.vote_count = bundle.vote_count.saturating_sub(1);
                    }
                }
                VoteAction::Upvote(id) => {
                    for bundle in &mut sidechain.pending_bundles {
                        if bundle.id == *id {
                            bundle.vote_count = bundle.vote_count.saturating_add(1);
                        } else {
                            bundle.vote_count = bundle.vote_count.saturating_sub(1);
                        }
                    }
                }
            }
        }
    }

    fn expire(&mut self, height: u32) {
        self.proposals.retain(|proposal| {
            let used = self.active.contains_key(&proposal.slot);
            let (max_age, threshold) = if used {
                (
                    self.thresholds.used_slot_proposal_max_age,
                    self.thresholds.used_slot_activation_threshold,
                )
            } else {
                (
                    self.thresholds.unused_slot_proposal_max_age,
                    self.thresholds.unused_slot_activation_threshold,
                )
            };
            let age = height.saturating_sub(proposal.proposal_height);
            let failures = age.saturating_sub(u32::from(proposal.vote_count));
            let max_failures = u32::from(max_age.saturating_sub(threshold));
            age <= u32::from(max_age) && !(age > max_failures && failures >= max_failures)
        });
        for sidechain in self.active.values_mut() {
            sidechain.pending_bundles.retain(|bundle| {
                height.saturating_sub(bundle.proposal_height)
                    <= u32::from(self.thresholds.withdrawal_bundle_max_age)
            });
        }
    }

    #[allow(clippy::too_many_lines)]
    fn apply_treasury_transaction(&mut self, transaction: &Transaction) -> Result<(), StateError> {
        let spent: BTreeSet<(u8, [u8; 32], u32)> = self
            .active
            .iter()
            .filter_map(|(&slot, sidechain)| {
                sidechain
                    .ctip
                    .as_ref()
                    .map(|ctip| (slot, ctip.txid, ctip.vout))
            })
            .filter(|(_, txid, vout)| {
                transaction.input.iter().any(|input| {
                    input.previous_output
                        == OutPoint {
                            txid: Txid::from_byte_array(*txid),
                            vout: *vout,
                        }
                })
            })
            .collect();
        let txid = transaction.compute_txid().to_byte_array();
        let mut replacements = BTreeMap::new();
        for (vout, output) in transaction.output.iter().enumerate() {
            let Some(slot) = parse_drivechain_script(&output.script_pubkey) else {
                continue;
            };
            if !self.active.contains_key(&slot) {
                continue;
            }
            if replacements
                .insert(
                    slot,
                    (
                        u32::try_from(vout).unwrap_or(u32::MAX),
                        output.value.to_sat(),
                    ),
                )
                .is_some()
            {
                return Err(StateError::MultipleTreasuryOutputs(slot));
            }
        }
        for (slot, _, _) in &spent {
            if !replacements.contains_key(slot) {
                return Err(StateError::TreasurySpentWithoutReplacement(*slot));
            }
        }
        let mut kind = None;
        for (slot, (vout, value_sat)) in replacements {
            let Some(sidechain) = self.active.get_mut(&slot) else {
                continue;
            };
            let old_value = sidechain.ctip.as_ref().map_or(0, |ctip| ctip.value_sat);
            if sidechain.ctip.is_some()
                && !spent.iter().any(|(spent_slot, _, _)| *spent_slot == slot)
            {
                return Err(StateError::OldTreasuryUnspent(slot));
            }
            let is_withdrawal = value_sat < old_value;
            if value_sat == old_value {
                return Err(StateError::ZeroTreasuryDelta(slot));
            }
            if kind
                .replace(is_withdrawal)
                .is_some_and(|old| old != is_withdrawal)
            {
                return Err(StateError::AmbiguousTreasuryTransaction);
            }
            if is_withdrawal {
                if transaction.input.len() != 1 || vout != 0 {
                    return Err(StateError::InvalidWithdrawal {
                        slot,
                        reason: "withdrawal must have one input and treasury output zero",
                    });
                }
                let bundle_id = blinded_withdrawal_id(transaction, old_value)?;
                let Some(index) = sidechain.pending_bundles.iter().position(|bundle| {
                    bundle.id == bundle_id
                        && bundle.vote_count > self.thresholds.withdrawal_bundle_inclusion_threshold
                }) else {
                    return Err(StateError::InvalidWithdrawal {
                        slot,
                        reason: "bundle is not approved",
                    });
                };
                sidechain.pending_bundles.remove(index);
            } else if transaction
                .output
                .get(
                    usize::try_from(vout)
                        .unwrap_or(usize::MAX)
                        .saturating_add(1),
                )
                .and_then(|output| op_return_data(&output.script_pubkey))
                .is_none()
            {
                return Err(StateError::MissingDepositAddress(slot));
            }
            let sequence = sidechain
                .ctip
                .as_ref()
                .map_or(0, |ctip| ctip.sequence.saturating_add(1));
            sidechain.ctip = Some(Ctip {
                txid,
                vout,
                value_sat,
                sequence,
            });
        }
        Ok(())
    }
}

fn op_return_data(script: &bitcoin::Script) -> Option<&[u8]> {
    use bitcoin::{opcodes::all::OP_RETURN, script::Instruction};
    let mut instructions = script.instructions();
    if !matches!(instructions.next(), Some(Ok(Instruction::Op(op))) if op == OP_RETURN) {
        return None;
    }
    let Some(Ok(Instruction::PushBytes(bytes))) = instructions.next() else {
        return None;
    };
    instructions.next().is_none().then_some(bytes.as_bytes())
}

fn blinded_withdrawal_id(
    transaction: &Transaction,
    old_value: u64,
) -> Result<[u8; 32], StateError> {
    use bitcoin::{Amount, ScriptBuf, TxOut};
    let mut blinded = transaction.clone();
    let Some((treasury, payouts)) = blinded.output.split_first_mut() else {
        return Err(StateError::InvalidWithdrawal {
            slot: 0,
            reason: "missing treasury output",
        });
    };
    let payout_total = payouts
        .iter()
        .try_fold(0_u64, |sum, output| sum.checked_add(output.value.to_sat()))
        .ok_or(StateError::InvalidWithdrawal {
            slot: 0,
            reason: "output amount overflow",
        })?;
    let total =
        treasury
            .value
            .to_sat()
            .checked_add(payout_total)
            .ok_or(StateError::InvalidWithdrawal {
                slot: 0,
                reason: "output amount overflow",
            })?;
    let fee = old_value
        .checked_sub(total)
        .ok_or(StateError::InvalidWithdrawal {
            slot: 0,
            reason: "outputs exceed treasury",
        })?;
    blinded.input.clear();
    *treasury = TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::new_op_return(fee.to_be_bytes()),
    };
    Ok(blinded.compute_txid().to_byte_array())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use bitcoin::{
        Amount, BlockHash, CompactTarget, ScriptBuf, Transaction, TxIn, TxMerkleNode, TxOut,
        absolute::LockTime,
        block::{Header, Version},
        script::PushBytesBuf,
        transaction,
    };

    use super::*;
    use crate::{M1_TAG, M2_TAG};

    fn op_return(payload: Vec<u8>) -> ScriptBuf {
        ScriptBuf::new_op_return(PushBytesBuf::try_from(payload).expect("bounded test payload"))
    }

    fn block(parent: [u8; 32], messages: Vec<ScriptBuf>) -> Block {
        let coinbase = Transaction {
            version: transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: messages
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
            txdata: vec![coinbase],
        }
    }

    fn declaration() -> Vec<u8> {
        [&[0, 4][..], b"test", b"sidechain", &[0x11; 32], &[0x22; 20]].concat()
    }

    #[test]
    fn nonempty_state_has_a_lossless_deterministic_encoding() {
        let description = declaration();
        let candidate = block(
            [0; 32],
            vec![op_return([M1_TAG.as_slice(), &[7], &description].concat())],
        );
        let state = State::new(Thresholds::REGTEST, 0)
            .validate_block(&candidate, 0)
            .expect("valid proposal")
            .into_next();
        let encoded = state.encode().expect("state encoding");
        assert_eq!(State::decode(&encoded), Ok(state.clone()));
        assert_eq!(state.encode(), Ok(encoded));
        assert_eq!(state.proposals().len(), 1);
    }

    #[test]
    fn candidate_rejection_does_not_mutate_authoritative_state() {
        let state = State::new(Thresholds::REGTEST, 0);
        let description = declaration();
        let message = op_return([M1_TAG.as_slice(), &[7], &description].concat());
        let candidate = block([0; 32], vec![message.clone(), message]);
        let before = state.clone();
        assert!(matches!(
            state.validate_block(&candidate, 0),
            Err(StateError::DuplicateMessage {
                message: "M1",
                slot: 7
            })
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn proposal_activation_and_disconnect_are_deterministic() {
        let description = declaration();
        let description_hash = bitcoin::hashes::sha256d::Hash::hash(&description).to_byte_array();
        let proposal_block = block(
            [0; 32],
            vec![op_return([M1_TAG.as_slice(), &[7], &description].concat())],
        );
        let mut state = State::new(Thresholds::REGTEST, 0)
            .validate_block(&proposal_block, 0)
            .expect("valid proposal")
            .into_next();
        for height in 1..=6 {
            let candidate = block(
                state.tip().expect("connected tip"),
                vec![op_return(
                    [M2_TAG.as_slice(), &[7], &description_hash].concat(),
                )],
            );
            let transition = state
                .validate_block(&candidate, height)
                .expect("valid acknowledgement");
            let previous = transition.previous().clone();
            state = transition.into_next();
            if height == 6 {
                assert!(state.active_sidechains().contains_key(&7));
                assert_eq!(previous.active_sidechains().contains_key(&7), false);
                assert_eq!(
                    previous
                        .validate_block(&candidate, height)
                        .expect("replay is deterministic")
                        .into_next(),
                    state
                );
                state = previous;
                assert!(!state.active_sidechains().contains_key(&7));
            }
        }
    }
}
