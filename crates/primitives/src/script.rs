//! Native script and witness byte stacks.

use core::ops::{Deref, DerefMut, Index};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Script(Vec<u8>);

impl Script {
    #[must_use]
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the heap bytes allocated for this script's byte buffer,
    /// including spare capacity.
    #[must_use]
    pub fn retained_heap_bytes(&self) -> usize {
        self.0.capacity()
    }
}

impl Deref for Script {
    type Target = Vec<u8>;

    fn deref(&self) -> &Vec<u8> {
        &self.0
    }
}

impl DerefMut for Script {
    fn deref_mut(&mut self) -> &mut Vec<u8> {
        &mut self.0
    }
}

impl From<Vec<u8>> for Script {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl PartialEq<Vec<u8>> for Script {
    fn eq(&self, other: &Vec<u8>) -> bool {
        &self.0 == other
    }
}

/// A BIP144 witness stack stored as one flat byte buffer.
///
/// `ends[i]` is the exclusive end offset of item `i` inside `bytes`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Witness {
    bytes: Vec<u8>,
    ends: Vec<u32>,
}

impl Witness {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bytes: Vec::new(),
            ends: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_capacity(items: usize, bytes: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(bytes),
            ends: Vec::with_capacity(items),
        }
    }

    #[must_use]
    pub fn from_stack(stack: Vec<Vec<u8>>) -> Self {
        let total = stack.iter().map(Vec::len).sum();
        let mut witness = Self::with_capacity(stack.len(), total);
        for item in stack {
            witness.push(&item);
        }
        witness
    }

    #[expect(
        clippy::expect_used,
        reason = "a witness stays below the 4_000_000 byte consensus block maximum"
    )]
    pub fn push(&mut self, item: &[u8]) {
        self.bytes.extend_from_slice(item);
        let end = u32::try_from(self.bytes.len())
            .expect("a witness stays below the 4_000_000 byte consensus block maximum");
        self.ends.push(end);
    }

    pub fn clear(&mut self) {
        self.bytes.clear();
        self.ends.clear();
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ends.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.ends.len()
    }

    #[must_use]
    pub fn get(&self, index: usize) -> Option<&[u8]> {
        let end = usize::try_from(*self.ends.get(index)?).ok()?;
        let start = match index.checked_sub(1) {
            None => 0,
            Some(previous) => usize::try_from(self.ends[previous]).ok()?,
        };
        self.bytes.get(start..end)
    }

    #[must_use]
    pub fn first(&self) -> Option<&[u8]> {
        self.get(0)
    }

    #[must_use]
    pub fn last(&self) -> Option<&[u8]> {
        self.get(self.len().checked_sub(1)?)
    }

    #[must_use]
    pub fn iter(&self) -> WitnessItems<'_> {
        WitnessItems {
            witness: self,
            front: 0,
            back: self.len(),
        }
    }

    /// Returns the heap bytes allocated for this witness stack: the flat
    /// item buffer and the item end offsets, including spare capacity.
    #[must_use]
    pub fn retained_heap_bytes(&self) -> usize {
        self.bytes.capacity().saturating_add(
            self.ends
                .capacity()
                .saturating_mul(core::mem::size_of::<u32>()),
        )
    }
}

impl Index<usize> for Witness {
    type Output = [u8];

    fn index(&self, index: usize) -> &[u8] {
        self.get(index)
            .unwrap_or_else(|| panic!("witness item {index} out of range for {} items", self.len()))
    }
}

impl From<Vec<Vec<u8>>> for Witness {
    fn from(stack: Vec<Vec<u8>>) -> Self {
        Self::from_stack(stack)
    }
}

impl PartialEq<Vec<Vec<u8>>> for Witness {
    fn eq(&self, other: &Vec<Vec<u8>>) -> bool {
        self.len() == other.len()
            && self
                .iter()
                .zip(other)
                .all(|(item, rhs)| item == rhs.as_slice())
    }
}

#[derive(Clone, Debug)]
pub struct WitnessItems<'a> {
    witness: &'a Witness,
    front: usize,
    back: usize,
}

impl<'a> Iterator for WitnessItems<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        if self.front == self.back {
            return None;
        }
        let item = self.witness.get(self.front);
        self.front += 1;
        item
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.back - self.front;
        (remaining, Some(remaining))
    }
}

impl DoubleEndedIterator for WitnessItems<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.front == self.back {
            return None;
        }
        self.back -= 1;
        self.witness.get(self.back)
    }
}

impl ExactSizeIterator for WitnessItems<'_> {}

impl<'a> IntoIterator for &'a Witness {
    type Item = &'a [u8];
    type IntoIter = WitnessItems<'a>;

    fn into_iter(self) -> WitnessItems<'a> {
        self.iter()
    }
}

#[cfg(kani)]
mod proofs;

#[cfg(test)]
mod tests {
    use super::{Script, Witness};

    #[test]
    fn script_retained_heap_bytes_tracks_capacity() {
        assert_eq!(Script::new().retained_heap_bytes(), 0);

        let mut raw = Vec::with_capacity(128);
        raw.extend_from_slice(&[0x51, 0x87]);
        let script = Script::from_bytes(raw);
        assert_eq!(script.retained_heap_bytes(), 128);
    }

    #[test]
    fn witness_retained_heap_bytes_tracks_buffer_and_offset_capacities() {
        assert_eq!(Witness::new().retained_heap_bytes(), 0);

        let reserved = Witness::with_capacity(7, 100);
        assert_eq!(reserved.retained_heap_bytes(), 100 + 7 * 4);

        let mut witness = Witness::with_capacity(4, 200);
        witness.push(&[0x01; 32]);
        witness.push(&[0x02; 64]);
        assert_eq!(witness.retained_heap_bytes(), 200 + 4 * 4);
    }

    mod roundtrip {
        use bitcoin::consensus::serialize;
        use proptest::collection::vec;
        use proptest::prelude::*;

        use crate::consensus_bytes;
        use crate::{Amount, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Witness};

        fn bitcoin_tx_with(stack: &[Vec<u8>]) -> bitcoin::Transaction {
            bitcoin::Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: vec![bitcoin::TxIn {
                    previous_output: bitcoin::OutPoint {
                        txid: bitcoin::hashes::Hash::all_zeros(),
                        vout: 0,
                    },
                    script_sig: bitcoin::ScriptBuf::new(),
                    sequence: bitcoin::Sequence::MAX,
                    witness: bitcoin::Witness::from_slice(stack),
                }],
                output: vec![bitcoin::TxOut {
                    value: bitcoin::Amount::ZERO,
                    script_pubkey: bitcoin::ScriptBuf::new(),
                }],
            }
        }

        proptest! {
            #[test]
            fn stacks_round_trip_and_encode_like_rust_bitcoin(
                stack in vec(vec(any::<u8>(), 0..300), 0..64)
            ) {
                let witness = Witness::from_stack(stack.clone());
                prop_assert_eq!(witness.len(), stack.len());
                let items: Vec<&[u8]> = witness.iter().collect();
                let expected: Vec<&[u8]> = stack.iter().map(Vec::as_slice).collect();
                prop_assert_eq!(items, expected);
                prop_assert_eq!(witness.iter().rev().count(), stack.len());

                let tx = Tx {
                    version: 2,
                    inputs: vec![TxIn {
                        previous_output: OutPoint::default(),
                        script_sig: Script::new(),
                        sequence: Sequence::MAX,
                        witness,
                    }],
                    outputs: vec![TxOut {
                        value: Amount::from_sat(0),
                        script_pubkey: Script::new(),
                    }],
                    lock_time: LockTime::ZERO,
                };
                let oracle = serialize(&bitcoin_tx_with(&stack));
                prop_assert_eq!(consensus_bytes(&tx), oracle);
            }
        }
    }
}
