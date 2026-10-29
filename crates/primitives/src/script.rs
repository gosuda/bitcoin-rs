//! Native script and witness byte stacks.

use core::ops::{Deref, DerefMut};

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

/// A BIP144 witness stack.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Witness(Vec<Vec<u8>>);

impl Witness {
    #[must_use]
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    #[must_use]
    pub fn from_stack(stack: Vec<Vec<u8>>) -> Self {
        Self(stack)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns the heap bytes allocated for this witness stack, including
    /// the outer stack allocation and all out-of-line item buffers with spare capacity.
    #[must_use]
    pub fn retained_heap_bytes(&self) -> usize {
        let mut total = self
            .0
            .capacity()
            .saturating_mul(core::mem::size_of::<Vec<u8>>());
        for item in &self.0 {
            total = total.saturating_add(item.capacity());
        }
        total
    }
}

impl Deref for Witness {
    type Target = Vec<Vec<u8>>;

    fn deref(&self) -> &Vec<Vec<u8>> {
        &self.0
    }
}

impl DerefMut for Witness {
    fn deref_mut(&mut self) -> &mut Vec<Vec<u8>> {
        &mut self.0
    }
}

impl From<Vec<Vec<u8>>> for Witness {
    fn from(stack: Vec<Vec<u8>>) -> Self {
        Self(stack)
    }
}

impl PartialEq<Vec<Vec<u8>>> for Witness {
    fn eq(&self, other: &Vec<Vec<u8>>) -> bool {
        &self.0 == other
    }
}

impl<'a> IntoIterator for &'a Witness {
    type Item = &'a Vec<u8>;
    type IntoIter = std::slice::Iter<'a, Vec<u8>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

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
    fn witness_retained_heap_bytes_tracks_outer_and_item_capacities() {
        assert_eq!(Witness::new().retained_heap_bytes(), 0);

        let empty_with_capacity = Witness::from_stack(Vec::with_capacity(7));
        assert_eq!(
            empty_with_capacity.retained_heap_bytes(),
            7 * core::mem::size_of::<Vec<u8>>()
        );

        let mut item1 = Vec::with_capacity(64);
        item1.extend_from_slice(&[0x01; 32]);
        let mut item2 = Vec::with_capacity(120);
        item2.extend_from_slice(&[0x02; 64]);

        let mut stack = Vec::with_capacity(4);
        stack.push(item1);
        stack.push(item2);
        let witness = Witness::from_stack(stack);

        let expected = 4 * core::mem::size_of::<Vec<u8>>() + 64 + 120;
        assert_eq!(witness.retained_heap_bytes(), expected);
    }
}
