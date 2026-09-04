//! Native script and witness byte stacks.

use core::ops::{Deref, DerefMut};

/// A Bitcoin script (`scriptSig` or `scriptPubKey`) as owned consensus bytes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
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

    /// Unwraps the consensus script bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Returns true when the script is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the script length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
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

impl From<Script> for Vec<u8> {
    fn from(script: Script) -> Self {
        script.0
    }
}

impl AsRef<[u8]> for Script {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl PartialEq<[u8]> for Script {
    fn eq(&self, other: &[u8]) -> bool {
        self.0 == other
    }
}

impl PartialEq<Vec<u8>> for Script {
    fn eq(&self, other: &Vec<u8>) -> bool {
        &self.0 == other
    }
}

impl PartialEq<Script> for [u8] {
    fn eq(&self, other: &Script) -> bool {
        self == other.0.as_slice()
    }
}

impl PartialEq<Script> for Vec<u8> {
    fn eq(&self, other: &Script) -> bool {
        self == &other.0
    }
}

impl IntoIterator for Script {
    type Item = u8;
    type IntoIter = std::vec::IntoIter<u8>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a Script {
    type Item = &'a u8;
    type IntoIter = std::slice::Iter<'a, u8>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<'a> IntoIterator for &'a mut Script {
    type Item = &'a mut u8;
    type IntoIter = std::slice::IterMut<'a, u8>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter_mut()
    }
}

/// A BIP144 witness stack.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
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

    /// Returns the witness items.
    #[must_use]
    pub fn as_stack(&self) -> &[Vec<u8>] {
        &self.0
    }

    /// Unwraps the witness items.
    #[must_use]
    pub fn into_stack(self) -> Vec<Vec<u8>> {
        self.0
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

impl From<Witness> for Vec<Vec<u8>> {
    fn from(witness: Witness) -> Self {
        witness.0
    }
}

impl PartialEq<[Vec<u8>]> for Witness {
    fn eq(&self, other: &[Vec<u8>]) -> bool {
        self.0 == other
    }
}

impl PartialEq<Vec<Vec<u8>>> for Witness {
    fn eq(&self, other: &Vec<Vec<u8>>) -> bool {
        &self.0 == other
    }
}

impl PartialEq<Witness> for [Vec<u8>] {
    fn eq(&self, other: &Witness) -> bool {
        self == other.0.as_slice()
    }
}

impl PartialEq<Witness> for Vec<Vec<u8>> {
    fn eq(&self, other: &Witness) -> bool {
        self == &other.0
    }
}

impl IntoIterator for Witness {
    type Item = Vec<u8>;
    type IntoIter = std::vec::IntoIter<Vec<u8>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a Witness {
    type Item = &'a Vec<u8>;
    type IntoIter = std::slice::Iter<'a, Vec<u8>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<'a> IntoIterator for &'a mut Witness {
    type Item = &'a mut Vec<u8>;
    type IntoIter = std::slice::IterMut<'a, Vec<u8>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::{Script, Witness};

    #[test]
    fn script_deref_exposes_bytes() {
        let script = Script::from_bytes(vec![0x51, 0x20]);
        assert_eq!(script.as_bytes(), &[0x51, 0x20]);
        assert_eq!(&script[..], &[0x51, 0x20]);
        assert!(!script.is_empty());
    }

    #[test]
    fn witness_deref_exposes_stack() {
        let mut witness = Witness::from_stack(vec![vec![0xaa], vec![0xbb, 0xcc]]);
        assert_eq!(witness.len(), 2);
        assert_eq!(witness[0], vec![0xaa]);
        witness.clear();
        assert!(witness.is_empty());
    }
}
