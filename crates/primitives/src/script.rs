//! Native script and witness byte stacks.

use core::ops::{Deref, DerefMut};

/// A Bitcoin script (`scriptSig` or `scriptPubKey`) as owned consensus bytes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Script(Vec<u8>);

impl Script {
    /// An empty script.
    #[must_use]
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    /// Wraps already-decoded consensus script bytes.
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns the consensus script bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
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
    /// An empty witness stack.
    #[must_use]
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    /// Wraps already-decoded witness stack items.
    #[must_use]
    pub fn from_stack(stack: Vec<Vec<u8>>) -> Self {
        Self(stack)
    }

    /// Returns true when the stack is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of witness items.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
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
