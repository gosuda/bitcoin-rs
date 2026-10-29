//! BIP331 ancestor package relay: message codec and combined package hash.
//!
//! BIP331 adds four messages, all negotiated before `verack` through `sendpackages`:
//! Sources: BIP331 at bitcoin/bips `c0c5aea41e6a334d34db4ca87ae53bbfd7f268d1` and
//! Bitcoin Core's merged `GetPackageHash` at
//! `092c978a42e8f4a02291b994713505ba8aac8b28`.
//!
//! BIP331 publishes no test-vector section.

use bitcoin_rs_primitives::{
    ConsensusDecode, ConsensusEncode, DecodeError, Hash256, Tx, Wtxid, varint,
};
use sha2::{Digest, Sha256};

use crate::wire::MAX_MESSAGE_PAYLOAD;

pub const PKG_RELAY_PKGTXNS: u64 = 1 << 0;

pub const PKG_RELAY_ANC: u64 = 1 << 1;

/// Largest list any BIP331 list message carries on the wire.
/// BIP331 bounds `getpkgtxns` at 100 wtxids; `ancpkginfo` feeds `getpkgtxns`
/// and `pkgtxns` answers it, so all three share the bound.
pub const MAX_GETPKGTXNS: usize = 100;

pub const MSG_ANCPKGINFO: u32 = 0x7;

pub const MSG_PKGTXNS: u32 = 0x6;

const WTXID_LEN: usize = 32;

/// Errors from encoding or decoding a BIP331 message payload.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum PackageError {
    #[error("truncated package payload")]
    Truncated,
    #[error("non-canonical compact size")]
    NonCanonical,
    #[error("package list is empty")]
    Empty,
    #[error("package list count {count} exceeds bound {max}")]
    TooMany { count: u64, max: usize },
    /// An `ancpkginfo` repeated a wtxid, which BIP331 defines as malformed.
    #[error("ancpkginfo repeats a wtxid")]
    DuplicateWtxid,
    #[error("trailing {0} bytes after package payload")]
    Trailing(usize),
    #[error("package payload length {0} exceeds the frame bound")]
    PayloadTooLarge(usize),
    #[error("package transaction: {0}")]
    Transaction(#[from] DecodeError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendPackages {
    pub versions: u64,
}

impl SendPackages {
    #[must_use]
    pub const fn encode(self) -> [u8; 8] {
        self.versions.to_le_bytes()
    }

    pub fn decode(payload: &[u8]) -> Result<Self, PackageError> {
        let (versions, rest) = payload
            .split_first_chunk::<8>()
            .ok_or(PackageError::Truncated)?;
        if !rest.is_empty() {
            return Err(PackageError::Trailing(rest.len()));
        }
        Ok(Self {
            versions: u64::from_le_bytes(*versions),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AncPkgInfo {
    pub wtxids: Vec<Wtxid>,
}

impl AncPkgInfo {
    #[must_use]
    pub fn subject(&self) -> Option<Wtxid> {
        self.wtxids.last().copied()
    }

    pub fn encode(&self) -> Result<Vec<u8>, PackageError> {
        check_count(len_u64(self.wtxids.len()))?;
        if has_duplicates(&self.wtxids) {
            return Err(PackageError::DuplicateWtxid);
        }
        Ok(write_wtxids(&self.wtxids))
    }

    pub fn decode(payload: &[u8]) -> Result<Self, PackageError> {
        let wtxids = read_wtxids(payload)?;
        if has_duplicates(&wtxids) {
            return Err(PackageError::DuplicateWtxid);
        }
        Ok(Self { wtxids })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetPkgTxns {
    pub wtxids: Vec<Wtxid>,
}

impl GetPkgTxns {
    pub fn encode(&self) -> Result<Vec<u8>, PackageError> {
        check_count(len_u64(self.wtxids.len()))?;
        Ok(write_wtxids(&self.wtxids))
    }

    pub fn decode(payload: &[u8]) -> Result<Self, PackageError> {
        Ok(Self {
            wtxids: read_wtxids(payload)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PkgTxns {
    pub txs: Vec<Tx>,
}

impl PkgTxns {
    pub fn encode(&self) -> Result<Vec<u8>, PackageError> {
        let count = len_u64(self.txs.len());
        check_count(count)?;
        let mut total = varint::encoded_len(count);
        for tx in &self.txs {
            total = total.saturating_add(tx.consensus_size());
            if total > MAX_MESSAGE_PAYLOAD {
                return Err(PackageError::PayloadTooLarge(total));
            }
        }
        let mut payload = Vec::with_capacity(total);
        payload.extend_from_slice(&varint::encode(count));
        for tx in &self.txs {
            tx.consensus_encode(&mut payload);
        }
        Ok(payload)
    }

    pub fn decode(payload: &[u8]) -> Result<Self, PackageError> {
        if payload.len() > MAX_MESSAGE_PAYLOAD {
            return Err(PackageError::PayloadTooLarge(payload.len()));
        }
        let (count, mut reader) = read_count(payload)?;
        let mut txs = Vec::with_capacity(count);
        for _ in 0..count {
            txs.push(Tx::consensus_decode(&mut reader)?);
        }
        if !reader.is_empty() {
            return Err(PackageError::Trailing(reader.len()));
        }
        Ok(Self { txs })
    }
}

#[must_use]
pub fn combined_package_hash(wtxids: &[Wtxid]) -> [u8; 32] {
    let mut ordered: Vec<&[u8; WTXID_LEN]> = wtxids.iter().map(Wtxid::as_bytes).collect();
    ordered.sort_unstable_by(|a, b| a.iter().rev().cmp(b.iter().rev()));
    let mut engine = Sha256::new();
    for wtxid in ordered {
        engine.update(wtxid);
    }
    engine.finalize().into()
}

fn len_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

fn check_count(count: u64) -> Result<usize, PackageError> {
    if count == 0 {
        return Err(PackageError::Empty);
    }
    match usize::try_from(count) {
        Ok(count) if count <= MAX_GETPKGTXNS => Ok(count),
        _ => Err(PackageError::TooMany {
            count,
            max: MAX_GETPKGTXNS,
        }),
    }
}

/// The one reader for every BIP331 list payload: minimal encoding and a count
/// from `1` through [`MAX_GETPKGTXNS`] are decided here from the prefix alone.
pub fn read_count(payload: &[u8]) -> Result<(usize, &[u8]), PackageError> {
    let (count, consumed) = varint::decode(payload).map_err(|err| match err {
        varint::VarintError::Truncated { .. } => PackageError::Truncated,
        varint::VarintError::NonCanonical { .. } => PackageError::NonCanonical,
    })?;
    Ok((check_count(count)?, &payload[consumed..]))
}

fn read_wtxids(payload: &[u8]) -> Result<Vec<Wtxid>, PackageError> {
    let (count, body) = read_count(payload)?;
    let needed = count * WTXID_LEN;
    if body.len() < needed {
        return Err(PackageError::Truncated);
    }
    if body.len() > needed {
        return Err(PackageError::Trailing(body.len() - needed));
    }
    let (wtxids, _) = body.as_chunks::<WTXID_LEN>();
    Ok(wtxids
        .iter()
        .map(|bytes| Wtxid(Hash256::from_le_bytes(bytes)))
        .collect())
}

fn write_wtxids(wtxids: &[Wtxid]) -> Vec<u8> {
    let count = len_u64(wtxids.len());
    let mut payload = Vec::with_capacity(varint::encoded_len(count) + wtxids.len() * WTXID_LEN);
    payload.extend_from_slice(&varint::encode(count));
    for wtxid in wtxids {
        payload.extend_from_slice(wtxid.as_bytes());
    }
    payload
}

fn has_duplicates(wtxids: &[Wtxid]) -> bool {
    wtxids
        .iter()
        .enumerate()
        .any(|(index, wtxid)| wtxids[index + 1..].contains(wtxid))
}

#[cfg(test)]
mod tests {

    use super::*;
    use bitcoin_rs_primitives::{Script, TxOut, deserialize};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const TX_1: &str = "02000000000101964b8aa63509579ca6086e6012eeaa4c2f4dd1e283da29b67c8eea38b3c6fd220000000000fdffffff0294c618000000000017a9145afbbb42f4e83312666d0697f9e66259912ecde38768fa2c0000000000160014897388a0889390fd0e153a22bb2cf9d8f019faf50247304402200547406380719f84d68cf4e96cc3e4a1688309ef475b150be2b471c70ea562aa02206d255f5acc40fd95981874d77201d2eb07883657ce1c796513f32b6079545cdf0121023ae77335cefcb5ab4c1dc1fb0d2acfece184e593727d7d5906c78e564c7c11d125cf0c00";
    const TX_2: &str = "01000000010b26e9b7735eb6aabdf358bab62f9816a21ba9ebdb719d5299e88607d722c190000000008b4830450220070aca44506c5cef3a16ed519d7c3c39f8aab192c4e1c90d065f37b8a4af6141022100a8e160b856c2d43d27d8fba71e5aef6405b8643ac4cb7cb3c462aced7f14711a0141046d11fee51b0e60666d5049a9101a72741df480b96ee26488a4d3466b95c9a40ac5eeef87e10a5cd336c19a84565f80fa6c547957b7700ff4dfbdefe76036c339ffffffff021bff3d11000000001976a91404943fdd508053c75000106d3bc6e2754dbcff1988ac2f15de00000000001976a914a266436d2965547608b9e15d9032a7b9d64fa43188ac00000000";
    const TX_3: &str = "0200000000010177862801f77c2c068a70372b4c435ef8dd621291c36a64eb4dd491f02218f5324600000000fdffffff014a0100000000000022512035ea312034cfac01e956a269f3bf147f569c2fbb00180677421262da042290d803402be713325ff285e66b0380f53f2fae0d0fb4e16f378a440fed51ce835061437566729d4883bc917632f3cff474d6384bc8b989961a1d730d4a87ed38ad28bd337b20f1d658c6c138b1c312e072b4446f50f01ae0da03a42e6274f8788aae53416a7fac0063036f7264010118746578742f706c61696e3b636861727365743d7574662d3800357b2270223a226272632d3230222c226f70223a226d696e74222c227469636b223a224342414c222c22616d74223a2236393639227d6821c1f1d658c6c138b1c312e072b4446f50f01ae0da03a42e6274f8788aae53416a7f00000000";

    const TXS: [&str; 3] = [TX_1, TX_2, TX_3];

    const WTXIDS: [&str; 3] = [
        "85cd1a31eb38f74ed5742ec9cb546712ab5aaf747de28a9168b53e846cbda17f",
        "b4749f017444b051c44dfd2720e88f314ff94f3dd6d56d40ef65854fcd7fff6b",
        "e065bac15f62bb4e761d761db928ddee65a47296b2b776785abb912cdec474e3",
    ];

    const TXIDS: [&str; 3] = [
        "bd0f71c1d5e50589063e134fad22053cdae5ab2320db5bf5e540198b0b5a4e69",
        "b4749f017444b051c44dfd2720e88f314ff94f3dd6d56d40ef65854fcd7fff6b",
        "ee707be5201160e32c4fc715bec227d1aeea5940fb4295605e7373edce3b1a93",
    ];

    const COMBINED_ALL: &str = "0f076ece34c184294c64badd99a4444bb0140d0812f3c76baf466180db2e4fb0";
    const COMBINED_FIRST_TWO: &str =
        "10c5067764b8619bba5d55181233d54ba1742b0bcdd4a4416975888a50414e25";
    const COMBINED_FIRST: &str = "28e9c3a89feb2c9ecbd6d0c0abd7076bb0714ae3b627591effca0a3b1e24b959";

    fn unhex(hex: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
        (0..hex.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&hex[at..at + 2], 16))
            .collect()
    }

    fn internal_hex(displayed: &str) -> String {
        (0..displayed.len())
            .step_by(2)
            .rev()
            .map(|at| &displayed[at..at + 2])
            .collect()
    }

    fn displayed_hex(internal: &[u8; 32]) -> String {
        let mut displayed = String::with_capacity(64);
        for byte in internal.iter().rev() {
            displayed.push_str(&format!("{byte:02x}"));
        }
        displayed
    }

    fn too_many(count: u64) -> PackageError {
        PackageError::TooMany {
            count,
            max: MAX_GETPKGTXNS,
        }
    }

    fn wtxid_of(displayed: &str) -> Result<Wtxid, Box<dyn std::error::Error>> {
        let bytes: [u8; 32] = unhex(&internal_hex(displayed))?
            .try_into()
            .map_err(|_| "displayed hash is not 32 bytes")?;
        Ok(Wtxid(Hash256::from_le_bytes(&bytes)))
    }

    fn wtxids_of(displayed: &[&str]) -> Result<Vec<Wtxid>, Box<dyn std::error::Error>> {
        displayed.iter().map(|hash| wtxid_of(hash)).collect()
    }

    fn core_txs() -> Result<[Tx; 3], Box<dyn std::error::Error>> {
        Ok([
            deserialize(&unhex(TX_1)?)?,
            deserialize(&unhex(TX_2)?)?,
            deserialize(&unhex(TX_3)?)?,
        ])
    }

    fn synthetic_wtxids(count: usize) -> Vec<Wtxid> {
        (0..count)
            .map(|index| {
                let digest: [u8; 32] = Sha256::digest(index.to_le_bytes()).into();
                Wtxid(Hash256::from_le_bytes(&digest))
            })
            .collect()
    }

    fn oracle(displayed: &[&str]) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        let mut sorted = displayed.to_vec();
        sorted.sort_unstable();
        let mut engine = Sha256::new();
        for hash in sorted {
            engine.update(unhex(&internal_hex(hash))?);
        }
        Ok(engine.finalize().into())
    }

    fn sha256_of(parts: &[Vec<u8>]) -> [u8; 32] {
        let mut engine = Sha256::new();
        for part in parts {
            engine.update(part);
        }
        engine.finalize().into()
    }

    fn list_wire(displayed: &[&str]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut hex = format!("{:02x}", displayed.len());
        for hash in displayed {
            hex.push_str(&internal_hex(hash));
        }
        Ok(unhex(&hex)?)
    }

    fn pkgtxns_wire(order: &[usize]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut hex = format!("{:02x}", order.len());
        for &index in order {
            hex.push_str(TXS[index]);
        }
        Ok(unhex(&hex)?)
    }

    #[test]
    fn sendpackages_is_one_little_endian_u64() -> TestResult {
        let both = SendPackages {
            versions: PKG_RELAY_PKGTXNS | PKG_RELAY_ANC,
        };
        assert_eq!(both.encode().as_slice(), unhex("0300000000000000")?);
        assert_eq!(SendPackages::decode(&unhex("0300000000000000")?)?, both);

        let high = SendPackages {
            versions: (1 << 63) | PKG_RELAY_PKGTXNS,
        };
        assert_eq!(high.encode().as_slice(), unhex("0100000000000080")?);
        assert_eq!(SendPackages::decode(&high.encode())?, high);

        assert_eq!(SendPackages::decode(&[0; 8])?, SendPackages { versions: 0 });
        Ok(())
    }

    #[test]
    fn sendpackages_consumes_exactly_eight_bytes() {
        assert_eq!(SendPackages::decode(&[]), Err(PackageError::Truncated));
        assert_eq!(SendPackages::decode(&[0; 7]), Err(PackageError::Truncated));
        assert_eq!(
            SendPackages::decode(&[0; 9]),
            Err(PackageError::Trailing(1))
        );
    }

    #[test]
    fn combined_hash_matches_core_permutation_vectors() -> TestResult {
        let txs = core_txs()?;
        let wtxids: Vec<Wtxid> = txs.iter().map(Tx::wtxid).collect();
        for (wtxid, displayed) in wtxids.iter().zip(WTXIDS) {
            assert_eq!(wtxid, &wtxid_of(displayed)?, "fixture wtxid {displayed}");
        }
        let expected = unhex(COMBINED_ALL)?;
        assert_eq!(oracle(&WTXIDS)?.as_slice(), expected);

        for order in [
            [0, 1, 2],
            [0, 2, 1],
            [1, 2, 0],
            [1, 0, 2],
            [2, 0, 1],
            [2, 1, 0],
        ] {
            let permuted: Vec<Wtxid> = order.iter().map(|&index| wtxids[index]).collect();
            assert_eq!(
                combined_package_hash(&permuted).as_slice(),
                expected,
                "order {order:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn combined_hash_is_not_integer_order_txid_prefixed_or_double_hashed() -> TestResult {
        let wtxids = wtxids_of(&WTXIDS)?;
        let [first, second, third] = [wtxids[0], wtxids[1], wtxids[2]];

        assert!(WTXIDS[0] < WTXIDS[1] && WTXIDS[1] < WTXIDS[2]);
        assert!(second < first);
        assert!(second < third);

        let internal = |hashes: &[Wtxid]| -> Vec<Vec<u8>> {
            hashes.iter().map(|hash| hash.as_bytes().to_vec()).collect()
        };
        let combined = combined_package_hash(&wtxids);

        let integer_order = sha256_of(&internal(&[second, first, third]));
        assert_ne!(combined, integer_order);

        assert_ne!(combined, oracle(&TXIDS)?);

        let mut prefixed = vec![vec![3_u8]];
        prefixed.extend(internal(&wtxids));
        assert_ne!(combined, sha256_of(&prefixed));

        let once = sha256_of(&internal(&wtxids));
        let twice: [u8; 32] = Sha256::digest(once).into();
        assert_eq!(combined, once);
        assert_ne!(combined, twice);
        Ok(())
    }

    #[test]
    fn combined_hash_has_member_count_vectors() -> TestResult {
        let wtxids = wtxids_of(&WTXIDS)?;
        assert_eq!(
            combined_package_hash(&wtxids[..1]).as_slice(),
            unhex(COMBINED_FIRST)?
        );
        let pair = [wtxids[0], wtxids[1]];
        let reversed = [wtxids[1], wtxids[0]];
        assert_eq!(
            combined_package_hash(&pair).as_slice(),
            unhex(COMBINED_FIRST_TWO)?
        );
        assert_eq!(
            combined_package_hash(&reversed),
            combined_package_hash(&pair)
        );

        assert_ne!(
            combined_package_hash(&[wtxids[0], wtxids[0]]),
            combined_package_hash(&wtxids[..1])
        );
        Ok(())
    }

    #[test]
    fn combined_hash_sorts_a_full_package_by_displayed_order() -> TestResult {
        let ascending = synthetic_wtxids(25);
        let displayed: Vec<String> = ascending
            .iter()
            .map(|wtxid| displayed_hex(wtxid.as_bytes()))
            .collect();
        let displayed: Vec<&str> = displayed.iter().map(String::as_str).collect();

        let mut by_integer = ascending.clone();
        by_integer.sort_unstable();
        let mut by_display = ascending.clone();
        by_display.sort_unstable_by_key(|wtxid| displayed_hex(wtxid.as_bytes()));
        assert_ne!(by_integer, by_display);

        let mut descending = ascending.clone();
        descending.reverse();
        let expected = oracle(&displayed)?;
        assert_eq!(combined_package_hash(&ascending), expected);
        assert_eq!(combined_package_hash(&descending), expected);
        assert_eq!(combined_package_hash(&by_display), expected);
        Ok(())
    }

    #[test]
    fn ancpkginfo_wire_is_count_then_wtxids_with_subject_last() -> TestResult {
        let order = [WTXIDS[2], WTXIDS[0], WTXIDS[1]];
        let wire = list_wire(&order)?;
        assert_eq!(wire[0], 3);

        let info = AncPkgInfo::decode(&wire)?;
        assert_eq!(info.wtxids, wtxids_of(&order)?);
        assert_eq!(info.subject(), Some(wtxid_of(WTXIDS[1])?));
        assert_eq!(info.encode()?, wire);
        Ok(())
    }

    #[test]
    fn getpkgtxns_wire_preserves_request_order() -> TestResult {
        let order = [WTXIDS[1], WTXIDS[2], WTXIDS[0]];
        let wire = list_wire(&order)?;

        let request = GetPkgTxns::decode(&wire)?;
        assert_eq!(request.wtxids, wtxids_of(&order)?);
        assert_eq!(request.encode()?, wire);
        assert_eq!(
            combined_package_hash(&request.wtxids).as_slice(),
            unhex(COMBINED_ALL)?
        );
        Ok(())
    }

    #[test]
    fn getpkgtxns_keeps_a_repeated_wtxid_that_ancpkginfo_rejects() -> TestResult {
        let repeated = [WTXIDS[0], WTXIDS[1], WTXIDS[0]];
        let wire = list_wire(&repeated)?;

        let request = GetPkgTxns::decode(&wire)?;
        assert_eq!(request.wtxids, wtxids_of(&repeated)?);
        assert_eq!(request.encode()?, wire);

        assert_eq!(AncPkgInfo::decode(&wire), Err(PackageError::DuplicateWtxid));
        assert_eq!(
            AncPkgInfo {
                wtxids: wtxids_of(&repeated)?
            }
            .encode(),
            Err(PackageError::DuplicateWtxid)
        );
        Ok(())
    }

    #[test]
    fn pkgtxns_wire_is_count_then_witness_serialized_transactions_in_request_order() -> TestResult {
        let order = [2, 0, 1];
        let wire = pkgtxns_wire(&order)?;

        let package = PkgTxns::decode(&wire)?;
        let core = core_txs()?;
        let expected: Vec<Tx> = order.iter().map(|&index| core[index].clone()).collect();
        assert_eq!(package.txs, expected);
        let wtxids: Vec<Wtxid> = package.txs.iter().map(Tx::wtxid).collect();
        assert_eq!(wtxids, wtxids_of(&[WTXIDS[2], WTXIDS[0], WTXIDS[1]])?);
        assert_eq!(package.encode()?, wire);
        Ok(())
    }

    #[test]
    fn list_bounds_hold_at_the_limit_and_fail_one_past_it() -> TestResult {
        let at_limit = synthetic_wtxids(MAX_GETPKGTXNS);
        let past_limit = synthetic_wtxids(MAX_GETPKGTXNS + 1);

        let anc = AncPkgInfo {
            wtxids: at_limit.clone(),
        };
        assert_eq!(AncPkgInfo::decode(&anc.encode()?)?, anc);
        let get = GetPkgTxns { wtxids: at_limit };
        assert_eq!(GetPkgTxns::decode(&get.encode()?)?, get);
        let full = PkgTxns {
            txs: vec![core_txs()?[1].clone(); MAX_GETPKGTXNS],
        };
        assert_eq!(PkgTxns::decode(&full.encode()?)?, full);

        assert_eq!(
            AncPkgInfo {
                wtxids: past_limit.clone()
            }
            .encode(),
            Err(too_many(101))
        );
        assert_eq!(
            GetPkgTxns { wtxids: past_limit }.encode(),
            Err(too_many(101))
        );
        assert_eq!(
            PkgTxns {
                txs: vec![Tx::default(); MAX_GETPKGTXNS + 1]
            }
            .encode(),
            Err(too_many(101))
        );
        Ok(())
    }

    #[test]
    fn a_declared_count_over_the_bound_fails_before_the_body_is_read() {
        for count in [101_u64, 253, 65_536, 0x1_0000_0000, u64::MAX] {
            let prefix = varint::encode(count);
            assert_eq!(AncPkgInfo::decode(&prefix), Err(too_many(count)));
            assert_eq!(GetPkgTxns::decode(&prefix), Err(too_many(count)));
            assert_eq!(PkgTxns::decode(&prefix), Err(too_many(count)));
        }
    }

    #[test]
    fn empty_lists_are_rejected_on_both_sides() {
        assert_eq!(AncPkgInfo::decode(&[0]), Err(PackageError::Empty));
        assert_eq!(GetPkgTxns::decode(&[0]), Err(PackageError::Empty));
        assert_eq!(PkgTxns::decode(&[0]), Err(PackageError::Empty));
        assert_eq!(
            AncPkgInfo { wtxids: vec![] }.encode(),
            Err(PackageError::Empty)
        );
        assert_eq!(
            GetPkgTxns { wtxids: vec![] }.encode(),
            Err(PackageError::Empty)
        );
        assert_eq!(PkgTxns { txs: vec![] }.encode(), Err(PackageError::Empty));
    }

    #[test]
    fn compact_size_must_be_minimal() -> TestResult {
        let body = list_wire(&WTXIDS)?[1..].to_vec();
        let mut widened = vec![0xfd, 0x03, 0x00];
        widened.extend_from_slice(&body);
        assert_eq!(
            AncPkgInfo::decode(&widened),
            Err(PackageError::NonCanonical)
        );
        assert_eq!(
            GetPkgTxns::decode(&widened),
            Err(PackageError::NonCanonical)
        );
        assert_eq!(PkgTxns::decode(&widened), Err(PackageError::NonCanonical));

        let mut widest = vec![0xff, 0x03, 0, 0, 0, 0, 0, 0, 0];
        widest.extend_from_slice(&body);
        assert_eq!(GetPkgTxns::decode(&widest), Err(PackageError::NonCanonical));

        assert_eq!(GetPkgTxns::decode(&[]), Err(PackageError::Truncated));
        assert_eq!(GetPkgTxns::decode(&[0xfd]), Err(PackageError::Truncated));
        assert_eq!(
            GetPkgTxns::decode(&[0xfd, 0x64]),
            Err(PackageError::Truncated)
        );
        Ok(())
    }

    #[test]
    fn wtxid_lists_consume_their_payload_exactly() -> TestResult {
        let wire = list_wire(&WTXIDS)?;

        let mut short = wire.clone();
        short.pop();
        assert_eq!(AncPkgInfo::decode(&short), Err(PackageError::Truncated));
        assert_eq!(GetPkgTxns::decode(&short), Err(PackageError::Truncated));

        let mut long = wire;
        long.push(0);
        assert_eq!(AncPkgInfo::decode(&long), Err(PackageError::Trailing(1)));
        assert_eq!(GetPkgTxns::decode(&long), Err(PackageError::Trailing(1)));

        long.extend_from_slice(&[0; 40]);
        assert_eq!(GetPkgTxns::decode(&long), Err(PackageError::Trailing(41)));
        Ok(())
    }

    #[test]
    fn pkgtxns_consumes_its_payload_exactly_and_surfaces_transaction_errors() -> TestResult {
        let wire = pkgtxns_wire(&[0, 1, 2])?;

        let mut long = wire.clone();
        long.push(0);
        assert_eq!(PkgTxns::decode(&long), Err(PackageError::Trailing(1)));

        let mut missing = wire.clone();
        missing[0] = 4;
        assert!(matches!(
            PkgTxns::decode(&missing),
            Err(PackageError::Transaction(_))
        ));
        let cut = &wire[..=20];
        assert!(matches!(
            PkgTxns::decode(cut),
            Err(PackageError::Transaction(_))
        ));
        Ok(())
    }

    #[test]
    fn pkgtxns_is_bounded_by_the_transport_frame() {
        let oversized = vec![0_u8; MAX_MESSAGE_PAYLOAD + 1];
        assert_eq!(
            PkgTxns::decode(&oversized),
            Err(PackageError::PayloadTooLarge(MAX_MESSAGE_PAYLOAD + 1))
        );

        let huge = Tx {
            outputs: vec![TxOut {
                script_pubkey: Script::from_bytes(vec![0; MAX_MESSAGE_PAYLOAD]),
                ..TxOut::default()
            }],
            ..Tx::default()
        };
        assert!(matches!(
            PkgTxns { txs: vec![huge] }.encode(),
            Err(PackageError::PayloadTooLarge(size)) if size > MAX_MESSAGE_PAYLOAD
        ));
    }
}
