//! Bounded ingress for BIP331 `pkgtxns` bodies, contained in the transaction policy
//! owner.
//!
//! The charge is a lower bound of the heap a decoded package owns, taken at the exact
//! capacities the decoder requests. It is not a physical heap ceiling: allocator
//! rounding is outside it, and no process allocator is made to refuse.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bitcoin_rs_mempool::package_heap_usage;
use bitcoin_rs_mempool::standardness::{MAX_PACKAGE_COUNT, MAX_PACKAGE_WEIGHT};
use bitcoin_rs_primitives::encode::double_sha256;
use bitcoin_rs_primitives::{
    Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness, Wtxid,
    varint,
};
use hashbrown::HashSet;
use parking_lot::Mutex;

use crate::packages::{MAX_GETPKGTXNS, combined_package_hash};
use crate::{InboundTx, PeerSource, PeerTable, TxInventory};

pub const MAX_DECODED_PACKAGES_PER_PEER: usize = 1;

const MIN_INPUT_LEN: u64 = 41;
const MIN_OUTPUT_LEN: u64 = 9;
const OUTPOINT_LEN: usize = 36;

fn wide(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

fn slot<T>() -> u64 {
    wide(core::mem::size_of::<T>())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PackageRefusal {
    #[error("pkgtxns payload is malformed")]
    Malformed,
    #[error("pkgtxns carries no transaction")]
    Empty,
    #[error("package exceeds the member bound")]
    OverCount,
    #[error("package exceeds the weight bound")]
    OverWeight,
    #[error("package does not match an outstanding request")]
    Unsolicited,
    #[error("package capacity exhausted")]
    Budget,
    #[error("connection already holds a package")]
    PeerHeld,
    #[error("package no longer matches its plan")]
    PlanMismatch,
    #[error("package allocation refused")]
    Allocation,
}

impl PackageRefusal {
    #[must_use]
    pub const fn is_peer_fault(self) -> bool {
        matches!(self, Self::Malformed | Self::Empty)
    }
}

#[derive(Debug)]
struct CapacityState {
    cap: u64,
    used: AtomicU64,
    held: Mutex<HashSet<PeerSource>>,
}

impl CapacityState {
    fn try_add(&self, bytes: u64) -> bool {
        self.used
            .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes).filter(|total| *total <= self.cap)
            })
            .is_ok()
    }

    fn release(&self, bytes: u64) {
        let released = self
            .used
            .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_sub(bytes)
            });
        debug_assert!(released.is_ok(), "released more package bytes than charged");
    }
}

#[derive(Clone, Debug)]
pub struct PackageCapacity {
    state: Arc<CapacityState>,
}

impl PackageCapacity {
    #[must_use]
    pub fn new(cap: u64) -> Self {
        Self {
            state: Arc::new(CapacityState {
                cap,
                used: AtomicU64::new(0),
                held: Mutex::new(HashSet::new()),
            }),
        }
    }

    #[must_use]
    pub fn cap(&self) -> u64 {
        self.state.cap
    }

    #[must_use]
    pub fn reserved(&self) -> u64 {
        self.state.used.load(Ordering::Acquire)
    }

    #[must_use]
    pub fn held(&self) -> usize {
        self.state.held.lock().len()
    }

    fn charge(
        &self,
        source: PeerSource,
        frame: u64,
        decoded: u64,
    ) -> Result<(PackageCharge, PackageCharge), PackageRefusal> {
        let total = frame.checked_add(decoded).ok_or(PackageRefusal::Budget)?;
        let mut held = self.state.held.lock();
        if held.contains(&source) {
            return Err(PackageRefusal::PeerHeld);
        }
        if !self.state.try_add(total) {
            return Err(PackageRefusal::Budget);
        }
        held.insert(source);
        drop(held);
        Ok((
            PackageCharge {
                state: Arc::clone(&self.state),
                bytes: frame,
                slot: None,
            },
            PackageCharge {
                state: Arc::clone(&self.state),
                bytes: decoded,
                slot: Some(source),
            },
        ))
    }

    fn nothing(&self) -> PackageCharge {
        PackageCharge {
            state: Arc::clone(&self.state),
            bytes: 0,
            slot: None,
        }
    }
}

#[derive(Debug)]
pub struct PackageCharge {
    state: Arc<CapacityState>,
    bytes: u64,
    slot: Option<PeerSource>,
}

impl PackageCharge {
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }

    fn top_up(&mut self, extra: u64) -> bool {
        if !self.state.try_add(extra) {
            return false;
        }
        self.bytes = self.bytes.saturating_add(extra);
        true
    }
}

impl Drop for PackageCharge {
    fn drop(&mut self) {
        if let Some(source) = self.slot.take() {
            self.state.held.lock().remove(&source);
        }
        self.state.release(self.bytes);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackagePlan {
    count: usize,
    wtxids: [Wtxid; MAX_PACKAGE_COUNT],
    weight: u64,
    decoded_bytes: u64,
}

impl PackagePlan {
    #[must_use]
    pub fn wtxids(&self) -> &[Wtxid] {
        self.wtxids.get(..self.count).unwrap_or(&[])
    }

    #[must_use]
    pub fn subject(&self) -> Wtxid {
        self.wtxids().last().copied().unwrap_or_default()
    }

    #[must_use]
    pub const fn weight(&self) -> u64 {
        self.weight
    }

    #[must_use]
    pub const fn decoded_bytes(&self) -> u64 {
        self.decoded_bytes
    }
}

struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    fn take_len(&mut self, len: usize) -> Result<&'a [u8], PackageRefusal> {
        let (head, tail) = self
            .rest
            .split_at_checked(len)
            .ok_or(PackageRefusal::Malformed)?;
        self.rest = tail;
        Ok(head)
    }

    fn take(&mut self, len: u64) -> Result<&'a [u8], PackageRefusal> {
        self.take_len(usize::try_from(len).map_err(|_| PackageRefusal::Malformed)?)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], PackageRefusal> {
        <[u8; N]>::try_from(self.take_len(N)?).map_err(|_| PackageRefusal::Malformed)
    }

    fn compact(&mut self) -> Result<u64, PackageRefusal> {
        let (value, used) = varint::decode(self.rest).map_err(|_| PackageRefusal::Malformed)?;
        self.rest = self.rest.get(used..).ok_or(PackageRefusal::Malformed)?;
        Ok(value)
    }

    fn require_count(&self, count: u64, minimum: u64) -> Result<(), PackageRefusal> {
        if count.saturating_mul(minimum) > wide(self.rest.len()) {
            return Err(PackageRefusal::Malformed);
        }
        Ok(())
    }

    const fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }
}

fn varint_len(value: u64) -> u64 {
    wide(varint::encoded_len(value))
}

struct TxScan {
    weight: u64,
    heap: u64,
    wtxid: Wtxid,
}

fn scan_tx(reader: &mut Reader<'_>) -> Result<TxScan, PackageRefusal> {
    let image = reader.rest;
    reader.take_len(4)?;
    let mut inputs = reader.compact()?;
    let mut segwit = false;
    let mut legacy_empty = false;
    if inputs == 0 {
        match reader.array::<1>()? {
            [0] => legacy_empty = true,
            [1] => {
                segwit = true;
                inputs = reader.compact()?;
            }
            _ => return Err(PackageRefusal::Malformed),
        }
    }
    reader.require_count(inputs, MIN_INPUT_LEN)?;

    let mut base = 8_u64.saturating_add(varint_len(inputs));
    let mut heap = 0_u64;
    for _ in 0..inputs {
        reader.take_len(OUTPOINT_LEN)?;
        let script = reader.compact()?;
        reader.take(script)?;
        reader.take_len(4)?;
        base = base
            .saturating_add(36 + 4)
            .saturating_add(varint_len(script))
            .saturating_add(script);
        heap = heap.saturating_add(script);
    }

    let outputs = if legacy_empty { 0 } else { reader.compact()? };
    reader.require_count(outputs, MIN_OUTPUT_LEN)?;
    base = base.saturating_add(varint_len(outputs));
    for _ in 0..outputs {
        reader.take_len(8)?;
        let script = reader.compact()?;
        reader.take(script)?;
        base = base
            .saturating_add(8)
            .saturating_add(varint_len(script))
            .saturating_add(script);
        heap = heap.saturating_add(script);
    }

    let mut witness = 0_u64;
    if segwit {
        witness = 2;
        let mut any_item = false;
        for _ in 0..inputs {
            let items = reader.compact()?;
            reader.require_count(items, 1)?;
            witness = witness.saturating_add(varint_len(items));
            heap = heap.saturating_add(items.saturating_mul(slot::<Vec<u8>>()));
            for _ in 0..items {
                let len = reader.compact()?;
                reader.take(len)?;
                witness = witness.saturating_add(varint_len(len)).saturating_add(len);
                heap = heap.saturating_add(len);
            }
            any_item |= items > 0;
        }
        if !any_item {
            return Err(PackageRefusal::Malformed);
        }
    }
    reader.take_len(4)?;

    let consumed = image
        .len()
        .checked_sub(reader.rest.len())
        .and_then(|consumed| image.get(..consumed))
        .ok_or(PackageRefusal::Malformed)?;
    let heap = heap
        .saturating_add(slot::<Tx>())
        .saturating_add(inputs.saturating_mul(slot::<TxIn>()))
        .saturating_add(outputs.saturating_mul(slot::<TxOut>()));
    Ok(TxScan {
        weight: base.saturating_mul(4).saturating_add(witness),
        heap,
        wtxid: Wtxid(double_sha256(consumed)),
    })
}

pub fn plan_package_charge(payload: &[u8]) -> Result<PackagePlan, PackageRefusal> {
    let mut reader = Reader::new(payload);
    let count = reader.compact()?;
    if count == 0 {
        return Err(PackageRefusal::Empty);
    }
    if count > wide(MAX_GETPKGTXNS) {
        return Err(PackageRefusal::Malformed);
    }
    let count = usize::try_from(count).map_err(|_| PackageRefusal::Malformed)?;
    if count > MAX_PACKAGE_COUNT {
        return Err(PackageRefusal::OverCount);
    }
    let mut plan = PackagePlan {
        count,
        wtxids: [Wtxid::default(); MAX_PACKAGE_COUNT],
        weight: 0,
        decoded_bytes: 0,
    };
    for index in 0..count {
        let scan = scan_tx(&mut reader)?;
        plan.weight = plan.weight.saturating_add(scan.weight);
        if count > 1 && plan.weight > MAX_PACKAGE_WEIGHT {
            return Err(PackageRefusal::OverWeight);
        }
        plan.decoded_bytes = plan.decoded_bytes.saturating_add(scan.heap);
        *plan
            .wtxids
            .get_mut(index)
            .ok_or(PackageRefusal::OverCount)? = scan.wtxid;
    }
    if !reader.is_empty() {
        return Err(PackageRefusal::Malformed);
    }
    Ok(plan)
}

fn oversized_subject(payload: &[u8]) -> Option<Wtxid> {
    let mut reader = Reader::new(payload);
    let count = reader.compact().ok()?;
    if count == 0 || count > wide(MAX_GETPKGTXNS) {
        return None;
    }
    let count = usize::try_from(count).ok()?;
    let mut last = None;
    for _ in 0..count {
        last = Some(scan_tx(&mut reader).ok()?.wtxid);
    }
    if !reader.is_empty() {
        return None;
    }
    last
}

fn reserve_exact<T>(len: usize) -> Result<Vec<T>, PackageRefusal> {
    let mut vec = Vec::new();
    vec.try_reserve_exact(len)
        .map_err(|_| PackageRefusal::Allocation)?;
    Ok(vec)
}

fn read_bytes(reader: &mut Reader<'_>) -> Result<Vec<u8>, PackageRefusal> {
    let len = reader.compact()?;
    let bytes = reader.take(len)?;
    let mut buffer = reserve_exact(bytes.len())?;
    buffer.extend_from_slice(bytes);
    Ok(buffer)
}

fn read_u32(reader: &mut Reader<'_>) -> Result<u32, PackageRefusal> {
    Ok(u32::from_le_bytes(reader.array::<4>()?))
}

fn decode_tx(reader: &mut Reader<'_>) -> Result<Tx, PackageRefusal> {
    let version = read_u32(reader)?;
    let mut input_count = reader.compact()?;
    let mut segwit = false;
    let mut legacy_empty = false;
    if input_count == 0 {
        match reader.array::<1>()? {
            [0] => legacy_empty = true,
            [1] => {
                segwit = true;
                input_count = reader.compact()?;
            }
            _ => return Err(PackageRefusal::PlanMismatch),
        }
    }
    let mut inputs = reserve_exact::<TxIn>(
        usize::try_from(input_count).map_err(|_| PackageRefusal::PlanMismatch)?,
    )?;
    for _ in 0..input_count {
        let txid = reader.array::<32>()?;
        let vout = read_u32(reader)?;
        let script_sig = read_bytes(reader)?;
        let sequence = read_u32(reader)?;
        inputs.push(TxIn {
            previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&txid)), vout),
            script_sig: Script::from_bytes(script_sig),
            sequence: Sequence::from_consensus(sequence),
            witness: Witness::new(),
        });
    }
    let output_count = if legacy_empty { 0 } else { reader.compact()? };
    let mut outputs = reserve_exact::<TxOut>(
        usize::try_from(output_count).map_err(|_| PackageRefusal::PlanMismatch)?,
    )?;
    for _ in 0..output_count {
        let value = u64::from_le_bytes(reader.array::<8>()?);
        outputs.push(TxOut {
            value: Amount::from_sat(value),
            script_pubkey: Script::from_bytes(read_bytes(reader)?),
        });
    }
    if segwit {
        for input in &mut inputs {
            let items = reader.compact()?;
            let mut stack = reserve_exact::<Vec<u8>>(
                usize::try_from(items).map_err(|_| PackageRefusal::PlanMismatch)?,
            )?;
            for _ in 0..items {
                stack.push(read_bytes(reader)?);
            }
            input.witness = Witness::from_stack(stack);
        }
    }
    Ok(Tx {
        version,
        inputs,
        outputs,
        lock_time: LockTime::from_consensus(read_u32(reader)?),
    })
}

fn decode_package(payload: &[u8], plan: &PackagePlan) -> Result<Vec<Tx>, PackageRefusal> {
    let mut reader = Reader::new(payload);
    if usize::try_from(reader.compact()?) != Ok(plan.count) {
        return Err(PackageRefusal::PlanMismatch);
    }
    let mut txs = reserve_exact::<Tx>(plan.count)?;
    for _ in 0..plan.count {
        txs.push(decode_tx(&mut reader)?);
    }
    if !reader.is_empty() {
        return Err(PackageRefusal::PlanMismatch);
    }
    Ok(txs)
}

#[derive(Debug)]
struct RawFrame {
    payload: bytes::Bytes,
    _charge: PackageCharge,
}

#[derive(Debug)]
#[must_use = "a package token must end in package_response_rejected or package_response_completed"]
pub struct PackageToken {
    source: PeerSource,
    subject: Wtxid,
    decoded: PackageCharge,
}

impl PackageToken {
    #[must_use]
    pub const fn source(&self) -> PeerSource {
        self.source
    }

    #[must_use]
    pub const fn subject(&self) -> Wtxid {
        self.subject
    }
}

#[derive(Debug)]
pub struct InboundPackage {
    token: PackageToken,
    frame: RawFrame,
    plan: PackagePlan,
}

impl InboundPackage {
    #[must_use]
    pub const fn source(&self) -> PeerSource {
        self.token.source
    }

    #[must_use]
    pub const fn subject(&self) -> Wtxid {
        self.token.subject
    }

    #[must_use]
    pub const fn plan(&self) -> &PackagePlan {
        &self.plan
    }

    pub fn into_token(self) -> PackageToken {
        self.token
    }

    pub fn open(self) -> PackageOpening {
        let Self {
            mut token,
            frame,
            plan,
        } = self;
        match plan_package_charge(&frame.payload) {
            Ok(replanned) if replanned == plan => {}
            _ => {
                return PackageOpening::Refused(PackageRejection {
                    token,
                    refusal: PackageRefusal::PlanMismatch,
                });
            }
        }
        let txs = match decode_package(&frame.payload, &plan) {
            Ok(txs) => txs,
            Err(refusal) => return PackageOpening::Refused(PackageRejection { token, refusal }),
        };
        drop(frame);
        let spare = txs.capacity().saturating_sub(txs.len());
        let overrun = package_heap_usage(&txs, spare).saturating_sub(plan.decoded_bytes);
        if overrun > 0 && !token.decoded.top_up(overrun) {
            return PackageOpening::Refused(PackageRejection {
                token,
                refusal: PackageRefusal::Budget,
            });
        }
        PackageOpening::Opened(OpenedPackage {
            token,
            txs,
            overrun,
        })
    }
}

#[derive(Debug)]
pub enum PackageOpening {
    Opened(OpenedPackage),
    Refused(PackageRejection),
}

#[derive(Debug)]
pub struct PackageRejection {
    pub token: PackageToken,
    pub refusal: PackageRefusal,
}

#[derive(Debug)]
pub struct OpenedPackage {
    token: PackageToken,
    txs: Vec<Tx>,
    overrun: u64,
}

impl OpenedPackage {
    #[must_use]
    pub const fn overrun(&self) -> u64 {
        self.overrun
    }

    #[must_use]
    pub const fn source(&self) -> PeerSource {
        self.token.source
    }

    #[must_use]
    pub fn txs(&self) -> &[Tx] {
        &self.txs
    }

    pub fn into_parts(self) -> (PackageToken, Vec<Tx>) {
        (self.token, self.txs)
    }
}

pub enum InboundBody {
    Tx(InboundTx),
    Package(Box<InboundPackage>),
}

impl core::fmt::Debug for InboundBody {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Tx(tx) => f
                .debug_struct("InboundBody::Tx")
                .field("source", &tx.source)
                .field("txid", &tx.tx.txid())
                .finish(),
            Self::Package(package) => f
                .debug_tuple("InboundBody::Package")
                .field(package)
                .finish(),
        }
    }
}

impl From<InboundTx> for InboundBody {
    fn from(tx: InboundTx) -> Self {
        Self::Tx(tx)
    }
}

impl From<InboundPackage> for InboundBody {
    fn from(package: InboundPackage) -> Self {
        Self::Package(Box::new(package))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackageTeardown {
    pub claims_cleared: usize,
    pub bytes_reserved: u64,
    pub held: usize,
}

impl PeerTable {
    pub fn admit_package(
        &self,
        capacity: &PackageCapacity,
        inventory: &dyn TxInventory,
        source: PeerSource,
        payload: bytes::Bytes,
    ) -> Result<InboundPackage, PackageRefusal> {
        let plan = match plan_package_charge(&payload) {
            Ok(plan) => plan,
            Err(refusal @ (PackageRefusal::OverCount | PackageRefusal::OverWeight)) => {
                Self::retire_oversized_solicitation(self, source, &payload);
                return Err(refusal);
            }
            Err(other) => return Err(other),
        };
        let subject = plan.subject();
        let combined = combined_package_hash(plan.wtxids());
        if !self.begin_package_resolution(source, subject, combined, plan.wtxids()) {
            return Err(PackageRefusal::Unsolicited);
        }
        match capacity.charge(source, wide(payload.len()), plan.decoded_bytes()) {
            Ok((frame, decoded)) => Ok(InboundPackage {
                token: PackageToken {
                    source,
                    subject,
                    decoded,
                },
                frame: RawFrame {
                    payload,
                    _charge: frame,
                },
                plan,
            }),
            Err(refusal) => {
                self.package_response_rejected(
                    PackageToken {
                        source,
                        subject,
                        decoded: capacity.nothing(),
                    },
                    inventory,
                );
                Err(refusal)
            }
        }
    }

    fn retire_oversized_solicitation(&self, source: PeerSource, payload: &[u8]) {
        let Some(subject) = oversized_subject(payload) else {
            return;
        };
        let key = super::Identity::Wtxid(subject.0);
        let now = std::time::Instant::now();
        let mut policy = self.tx_policy.lock();
        let awaiting = policy.requests.get(&key).is_some_and(|request| {
            request
                .package
                .as_ref()
                .is_some_and(|claim| claim.state == super::PackagePhase::Awaiting)
                && request.owner.is_some_and(|(owner, _)| owner == source)
        });
        if !awaiting {
            return;
        }
        let keys = policy.failed_with_parents(key, source, now);
        drop(policy);
        self.send_transaction_requests(now, None, Some(&keys), std::time::Instant::now);
    }

    pub fn package_response_rejected(&self, token: PackageToken, inventory: &dyn TxInventory) {
        self.release_token(token, inventory);
    }

    pub fn package_response_completed(&self, token: PackageToken, inventory: &dyn TxInventory) {
        self.release_token(token, inventory);
    }

    fn release_token(&self, token: PackageToken, inventory: &dyn TxInventory) {
        let PackageToken {
            source,
            subject,
            decoded,
        } = token;
        drop(decoded);
        self.release_package_claim(source, subject, inventory);
    }

    pub fn clear_package_claims(&self, capacity: &PackageCapacity) -> PackageTeardown {
        let claims_cleared = self
            .tx_policy
            .lock()
            .teardown_package_claims(std::time::Instant::now());
        PackageTeardown {
            claims_cleared,
            bytes_reserved: capacity.reserved(),
            held: capacity.held(),
        }
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests {
    use bitcoin_rs_primitives::encode::ConsensusEncode;

    use super::*;
    use crate::tx_policy::tests::{CountingInventory, registered_source, source};

    fn sample_tx(version: u32, prev_vout: u32, sat: u64) -> Tx {
        let prev_byte = u8::try_from(prev_vout).expect("fixture vout fits u8");
        Tx {
            version,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(
                    Txid(Hash256::from_le_bytes(&[prev_byte; 32])),
                    prev_vout,
                ),
                script_sig: Script::new(),
                sequence: Sequence::from_consensus(0xFFFF_FFFF),
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(sat),
                script_pubkey: Script::from_bytes(vec![0x51]),
            }],
            lock_time: LockTime::ZERO,
        }
    }

    fn sample_segwit_tx(version: u32, prev_vout: u32, sat: u64, item: Vec<u8>) -> Tx {
        let prev_byte = u8::try_from(prev_vout).expect("fixture vout fits u8");
        Tx {
            version,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(
                    Txid(Hash256::from_le_bytes(&[prev_byte; 32])),
                    prev_vout,
                ),
                script_sig: Script::new(),
                sequence: Sequence::from_consensus(0xFFFF_FFFF),
                witness: Witness::from_stack(vec![item]),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(sat),
                script_pubkey: Script::from_bytes(vec![0x51]),
            }],
            lock_time: LockTime::ZERO,
        }
    }

    fn make_payload(txs: &[Tx]) -> bytes::Bytes {
        let mut buf = Vec::new();
        let count = u64::try_from(txs.len()).expect("fixture tx count fits u64");
        buf.extend_from_slice(&varint::encode(count));
        for tx in txs {
            tx.consensus_encode(&mut buf);
        }
        bytes::Bytes::from(buf)
    }

    #[test]
    fn plan_charge_computes_exact_weights_and_reconciles_on_open() {
        let parent = sample_segwit_tx(2, 1, 50_000, vec![1, 2, 3]);
        let child = sample_tx(2, 2, 40_000);
        let txs = vec![parent.clone(), child.clone()];
        let payload = make_payload(&txs);

        let plan = plan_package_charge(&payload).expect("plan must succeed");
        assert_eq!(plan.count, 2);
        assert_eq!(plan.wtxids(), &[parent.wtxid(), child.wtxid()]);
        assert_eq!(plan.subject(), child.wtxid());
        assert_eq!(plan.weight(), parent.weight() + child.weight());
        assert!(plan.decoded_bytes() > 0);

        let decoded = decode_package(&payload, &plan).expect("decode must succeed");
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].wtxid(), parent.wtxid());
        assert_eq!(decoded[1].wtxid(), child.wtxid());
    }

    #[test]
    fn plan_refuses_empty_malformed_and_out_of_bounds_payloads() {
        assert_eq!(plan_package_charge(&[]), Err(PackageRefusal::Malformed));
        assert_eq!(plan_package_charge(&[0x00]), Err(PackageRefusal::Empty));

        let txs: Vec<Tx> = (0..26).map(|i| sample_tx(1, i, 1_000)).collect();
        let payload = make_payload(&txs);
        assert_eq!(
            plan_package_charge(&payload),
            Err(PackageRefusal::OverCount)
        );

        let over_wire = varint::encode(101);
        assert_eq!(
            plan_package_charge(&over_wire),
            Err(PackageRefusal::Malformed)
        );

        let mut superfluous = vec![1];
        superfluous.extend_from_slice(&1_u32.to_le_bytes());
        superfluous.push(0);
        superfluous.push(1);
        superfluous.push(1);
        superfluous.extend_from_slice(&[0; 36]);
        superfluous.push(0);
        superfluous.extend_from_slice(&[0xFF; 4]);
        superfluous.push(0);
        superfluous.push(0);
        superfluous.extend_from_slice(&0_u32.to_le_bytes());
        assert_eq!(
            plan_package_charge(&superfluous),
            Err(PackageRefusal::Malformed)
        );

        let mut trailing = make_payload(&[sample_tx(1, 1, 1_000)]).to_vec();
        trailing.push(0xFF);
        assert_eq!(
            plan_package_charge(&trailing),
            Err(PackageRefusal::Malformed)
        );
    }

    #[test]
    fn plan_refuses_overweight_package() {
        let tx1 = sample_segwit_tx(2, 1, 1_000, vec![0; 210_000]);
        let tx2 = sample_segwit_tx(2, 2, 1_000, vec![0; 210_000]);
        assert!(tx1.weight() <= 400_000 && tx2.weight() <= 400_000);
        assert!(tx1.weight() + tx2.weight() > MAX_PACKAGE_WEIGHT);
        let payload = make_payload(&[tx1, tx2]);
        assert_eq!(
            plan_package_charge(&payload),
            Err(PackageRefusal::OverWeight)
        );
    }

    #[test]
    fn capacity_bounds_memory_and_enforces_one_package_per_peer() {
        let cap = 1_000;
        let capacity = PackageCapacity::new(cap);
        let peer_a = source(1);
        let peer_b = source(2);

        let (frame_a, decoded_a) = capacity.charge(peer_a, 400, 200).expect("charge succeeds");
        assert_eq!(capacity.reserved(), 600);
        assert_eq!(capacity.held(), 1);

        assert!(matches!(
            capacity.charge(peer_a, 50, 50),
            Err(PackageRefusal::PeerHeld)
        ));

        assert!(matches!(
            capacity.charge(peer_b, 300, 200),
            Err(PackageRefusal::Budget)
        ));
        assert_eq!(capacity.reserved(), 600);

        drop(frame_a);
        assert_eq!(capacity.reserved(), 200);
        assert_eq!(capacity.held(), 1);

        let (frame_b, decoded_b) = capacity.charge(peer_b, 300, 200).expect("charge succeeds");
        assert_eq!(capacity.reserved(), 700);
        assert_eq!(capacity.held(), 2);

        drop(decoded_a);
        assert_eq!(capacity.reserved(), 500);
        assert_eq!(capacity.held(), 1);

        let (frame_a2, decoded_a2) = capacity
            .charge(peer_a, 100, 100)
            .expect("recharge succeeds");
        assert_eq!(capacity.reserved(), 700);
        assert_eq!(capacity.held(), 2);
        drop(frame_a2);
        drop(decoded_a2);
        drop(decoded_b);
        assert_eq!(capacity.reserved(), 300, "peer_b's frame is still held");
        assert_eq!(capacity.held(), 0);
        drop(frame_b);
        assert_eq!(capacity.reserved(), 0);
        assert_eq!(capacity.held(), 0);
    }

    #[test]
    fn foreign_and_unsolicited_bodies_are_refused_without_holding_capacity() {
        let table = PeerTable::new();
        let capacity = PackageCapacity::new(100_000);
        let inventory = CountingInventory::default();
        let peer = source(1);

        let tx = sample_tx(1, 1, 10_000);
        let payload = make_payload(&[tx]);

        let result = table.admit_package(&capacity, &inventory, peer, payload);
        assert_eq!(result.err(), Some(PackageRefusal::Unsolicited));
        assert_eq!(capacity.reserved(), 0);
        assert_eq!(capacity.held(), 0);
    }

    #[test]
    fn reordered_and_mismatched_sequence_is_refused_and_claim_stays_awaiting() {
        let table = PeerTable::new();
        let (peer, _rx) = registered_source(&table, 8333);
        let capacity = PackageCapacity::new(100_000);
        let inventory = CountingInventory::default();

        let parent = sample_tx(1, 1, 50_000);
        let child = sample_tx(1, 2, 40_000);
        let subject = child.wtxid();

        assert!(table.request_package_info(peer, subject, &[]));
        assert!(table.request_package_transactions(peer, subject, vec![parent.wtxid(), subject]));

        let reordered_payload = make_payload(&[child.clone(), parent.clone()]);
        let err = table.admit_package(&capacity, &inventory, peer, reordered_payload);
        assert_eq!(err.err(), Some(PackageRefusal::Unsolicited));
        assert_eq!(capacity.reserved(), 0);
        assert_eq!(capacity.held(), 0);

        let foreign = source(2);
        let matching_payload = make_payload(&[parent.clone(), child.clone()]);
        let foreign_err =
            table.admit_package(&capacity, &inventory, foreign, matching_payload.clone());
        assert_eq!(foreign_err.err(), Some(PackageRefusal::Unsolicited));

        let admitted = table
            .admit_package(&capacity, &inventory, peer, matching_payload)
            .expect("admit succeeds");
        assert_eq!(capacity.held(), 1);
        assert!(capacity.reserved() > 0);

        let duplicate_err =
            table.admit_package(&capacity, &inventory, peer, make_payload(&[parent, child]));
        assert!(matches!(
            duplicate_err.err(),
            Some(PackageRefusal::Unsolicited | PackageRefusal::PeerHeld)
        ));

        table.package_response_rejected(admitted.into_token(), &inventory);
        assert_eq!(capacity.reserved(), 0);
        assert_eq!(capacity.held(), 0);
        assert!(
            !table.release_package_claim(peer, subject, &inventory),
            "the claim was released exactly once"
        );
    }

    #[test]
    fn queued_package_survives_disconnect_and_releases_exactly_once() {
        let table = PeerTable::new();
        let (peer, _rx) = registered_source(&table, 8333);
        let capacity = PackageCapacity::new(100_000);
        let inventory = CountingInventory::default();

        let tx = sample_tx(1, 1, 10_000);
        let subject = tx.wtxid();

        assert!(table.request_package_info(peer, subject, &[]));
        assert!(table.request_package_transactions(peer, subject, vec![subject]));

        let payload = make_payload(std::slice::from_ref(&tx));
        let inbound = table
            .admit_package(&capacity, &inventory, peer, payload)
            .expect("admission succeeds");
        assert_eq!(capacity.held(), 1);

        table.transaction_peer_disconnected(peer, &inventory);
        assert_eq!(capacity.held(), 1);

        let replacement = PeerSource::for_test(std::net::SocketAddr::from(([127, 0, 0, 1], 8333)));
        let rep_payload = make_payload(&[tx]);
        let rep_err = table.admit_package(&capacity, &inventory, replacement, rep_payload);
        assert_eq!(rep_err.err(), Some(PackageRefusal::Unsolicited));
        assert!(
            !table.release_package_claim(replacement, subject, &inventory),
            "a replacement connection cannot release the queued claim"
        );

        let opening = inbound.open();
        let opened = match opening {
            PackageOpening::Opened(opened) => opened,
            PackageOpening::Refused(_) => panic!("opening must succeed"),
        };
        let (token, txs) = opened.into_parts();
        assert_eq!(txs.len(), 1);
        table.package_response_completed(token, &inventory);

        assert_eq!(capacity.reserved(), 0);
        assert_eq!(capacity.held(), 0);
        assert!(
            !table.release_package_claim(peer, subject, &inventory),
            "the claim was released exactly once"
        );

        let teardown = table.clear_package_claims(&capacity);
        assert_eq!(teardown.claims_cleared, 0);
        assert_eq!(teardown.bytes_reserved, 0);
        assert_eq!(teardown.held, 0);
    }

    #[test]
    fn teardown_clears_stranded_claims_and_reports_unreturned_bytes() {
        let table = PeerTable::new();
        let (peer, _rx) = registered_source(&table, 8333);
        let capacity = PackageCapacity::new(100_000);
        let inventory = CountingInventory::default();

        let stranded = sample_tx(1, 1, 10_000);
        let stranded_subject = stranded.wtxid();
        assert!(table.request_package_info(peer, stranded_subject, &[]));
        assert!(table.request_package_transactions(peer, stranded_subject, vec![stranded_subject]));

        let teardown = table.clear_package_claims(&capacity);
        assert_eq!(teardown.claims_cleared, 1);
        assert_eq!(teardown.bytes_reserved, 0);
        assert_eq!(teardown.held, 0);

        let queued = sample_tx(1, 2, 20_000);
        let queued_subject = queued.wtxid();
        assert!(table.request_package_info(peer, queued_subject, &[]));
        assert!(table.request_package_transactions(peer, queued_subject, vec![queued_subject]));
        let inbound = table
            .admit_package(&capacity, &inventory, peer, make_payload(&[queued]))
            .expect("admission succeeds");
        let charged = capacity.reserved();
        assert!(charged > 0);

        let teardown = table.clear_package_claims(&capacity);
        assert_eq!(teardown.claims_cleared, 1);
        assert_eq!(teardown.bytes_reserved, charged);
        assert_eq!(teardown.held, 1);
        assert!(
            !table.release_package_claim(peer, queued_subject, &inventory),
            "a cleared claim has nothing left to release"
        );

        drop(inbound);
        assert_eq!(capacity.reserved(), 0);
        assert_eq!(capacity.held(), 0);
    }

    #[test]
    fn capacity_refusal_after_the_claim_comparison_releases_the_claim_once() {
        let table = PeerTable::new();
        let (peer, _rx) = registered_source(&table, 8333);
        let starved = PackageCapacity::new(1);
        let ample = PackageCapacity::new(100_000);
        let inventory = CountingInventory::default();

        let tx = sample_tx(1, 1, 10_000);
        let subject = tx.wtxid();
        assert!(table.request_package_info(peer, subject, &[]));
        assert!(table.request_package_transactions(peer, subject, vec![subject]));

        let refused = table.admit_package(
            &starved,
            &inventory,
            peer,
            make_payload(std::slice::from_ref(&tx)),
        );
        assert_eq!(refused.err(), Some(PackageRefusal::Budget));
        assert_eq!(starved.reserved(), 0);
        assert_eq!(starved.held(), 0);

        assert!(
            !table.release_package_claim(peer, subject, &inventory),
            "the refusal already released the claim"
        );
        let replay = table.admit_package(
            &ample,
            &inventory,
            peer,
            make_payload(std::slice::from_ref(&tx)),
        );
        assert_eq!(replay.err(), Some(PackageRefusal::Unsolicited));
        assert_eq!(ample.reserved(), 0);
        assert_eq!(ample.held(), 0);

        assert!(
            table.request_package_info(peer, subject, &[]),
            "the retired solicitation frees its hash and in-flight slot"
        );
    }

    #[test]
    fn oversized_body_retires_awaiting_claim_but_not_ordinary_requests() {
        let table = PeerTable::new();
        let capacity = PackageCapacity::new(10_000_000);
        let inventory = CountingInventory::default();
        let (owner, _rx) = registered_source(&table, 8333);
        let (stranger, _) = registered_source(&table, 8334);

        let parent = sample_tx(1, 1, 50_000);
        let child = sample_tx(1, 2, 40_000);
        let subject = child.wtxid();
        assert!(table.request_package_info(owner, subject, &[]));
        assert!(table.request_package_transactions(owner, subject, vec![parent.wtxid(), subject]));

        let mut oversized: Vec<Tx> = (0..25u32).map(|i| sample_tx(3, i, 1_000)).collect();
        oversized.push(child.clone());
        let oversized_payload = make_payload(&oversized);
        assert_eq!(
            table
                .admit_package(&capacity, &inventory, owner, oversized_payload.clone())
                .err(),
            Some(PackageRefusal::OverCount)
        );
        let right_sized = make_payload(&[parent.clone(), child.clone()]);
        assert_eq!(
            table
                .admit_package(&capacity, &inventory, owner, right_sized)
                .err(),
            Some(PackageRefusal::Unsolicited)
        );

        assert!(table.request_package_info(owner, subject, &[]));
        assert!(table.request_package_transactions(owner, subject, vec![parent.wtxid(), subject]));
        assert_eq!(
            table
                .admit_package(&capacity, &inventory, stranger, oversized_payload)
                .err(),
            Some(PackageRefusal::OverCount)
        );
        let admitted = table
            .admit_package(&capacity, &inventory, owner, make_payload(&[parent, child]))
            .expect("owner claim survives a stranger oversized body");
        table.package_response_rejected(admitted.into_token(), &inventory);
    }
}
