use smallvec::SmallVec;
use thiserror::Error;
use tinyvec::ArrayVec;

/// One stack item in the future hand-rolled interpreter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScriptItem {
    /// A minimally encoded script integer.
    Num(i64),
    /// A byte vector kept inline for common small pushes.
    Bytes(SmallVec<[u8; 32]>),
}

impl Default for ScriptItem {
    fn default() -> Self {
        Self::Bytes(SmallVec::new())
    }
}

/// Bounded script stack with Core's 1000-item maximum depth.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stack {
    items: ArrayVec<[ScriptItem; Self::MAX_DEPTH]>,
}

impl Stack {
    /// Maximum stack depth permitted by consensus script evaluation.
    pub const MAX_DEPTH: usize = 1000;

    /// Creates an empty stack.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Pushes one item, rejecting capacity overflow instead of panicking.
    pub fn push(&mut self, item: ScriptItem) -> Result<(), StackError> {
        match self.items.try_push(item) {
            Some(_) => Err(StackError::Overflow),
            None => Ok(()),
        }
    }

    /// Pops the top item.
    pub fn pop(&mut self) -> Result<ScriptItem, StackError> {
        self.items.pop().ok_or(StackError::Underflow)
    }

    /// Returns the top item without removing it.
    pub fn peek(&self) -> Result<&ScriptItem, StackError> {
        self.items.last().ok_or(StackError::Underflow)
    }

    /// Returns the number of stack items.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns true when the stack is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Removes all stack items.
    pub fn clear(&mut self) {
        self.items.clear();
    }
}

/// Errors returned by bounded stack operations.
#[derive(Copy, Clone, Debug, Error, PartialEq, Eq)]
pub enum StackError {
    /// Pushing would exceed the 1000-item consensus maximum.
    #[error("script stack overflow")]
    Overflow,
    /// Popping or peeking an empty stack was requested.
    #[error("script stack underflow")]
    Underflow,
}

#[cfg(test)]
mod tests {
    use super::{ScriptItem, Stack, StackError};

    #[test]
    fn stack_rejects_overflow_and_reports_underflow() {
        let mut stack = Stack::new();
        assert_eq!(stack.pop(), Err(StackError::Underflow));
        for value in 0..Stack::MAX_DEPTH {
            let num = i64::try_from(value)
                .unwrap_or_else(|error| panic!("stack test index should fit in i64: {error}"));
            assert_eq!(stack.push(ScriptItem::Num(num)), Ok(()));
        }
        assert_eq!(stack.len(), Stack::MAX_DEPTH);
        assert_eq!(stack.push(ScriptItem::Num(1)), Err(StackError::Overflow));
    }
}
