use smallvec::SmallVec;
use thiserror::Error;
use tinyvec::ArrayVec;

/// One stack item.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum ScriptItem {
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
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct Stack {
    items: ArrayVec<[ScriptItem; Self::MAX_DEPTH]>,
}

impl Stack {
    /// Maximum stack depth permitted by consensus script evaluation.
    pub(crate) const MAX_DEPTH: usize = 1000;

    /// Creates an empty stack.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Pushes one item, rejecting capacity overflow instead of panicking.
    pub(crate) fn push(&mut self, item: ScriptItem) -> Result<(), StackError> {
        match self.items.try_push(item) {
            Some(_) => Err(StackError::Overflow),
            None => Ok(()),
        }
    }

    /// Pops the top item.
    pub(crate) fn pop(&mut self) -> Result<ScriptItem, StackError> {
        self.items.pop().ok_or(StackError::Underflow)
    }

    /// Returns the top item without removing it.
    pub(crate) fn peek(&self) -> Result<&ScriptItem, StackError> {
        self.items.last().ok_or(StackError::Underflow)
    }

    /// Returns an item at `depth`, where zero is the top item.
    pub(crate) fn peek_at(&self, depth: usize) -> Result<&ScriptItem, StackError> {
        self.items
            .get(
                self.items
                    .len()
                    .checked_sub(depth)
                    .and_then(|index| index.checked_sub(1))
                    .ok_or(StackError::Underflow)?,
            )
            .ok_or(StackError::Underflow)
    }

    /// Removes and returns an item at `depth`, where zero is the top item.
    pub(crate) fn remove_at(&mut self, depth: usize) -> Result<ScriptItem, StackError> {
        let index = self
            .items
            .len()
            .checked_sub(depth)
            .and_then(|index| index.checked_sub(1))
            .ok_or(StackError::Underflow)?;
        Ok(self.items.remove(index))
    }

    /// Inserts an item at `depth`, where zero places it on top.
    pub(crate) fn insert_at(&mut self, depth: usize, item: ScriptItem) -> Result<(), StackError> {
        if depth > self.items.len() {
            return Err(StackError::Underflow);
        }
        if self.items.is_full() {
            return Err(StackError::Overflow);
        }
        let index = self.items.len() - depth;
        self.items.insert(index, item);
        Ok(())
    }

    /// Swaps the items at the given depths (0 = top, 1 = second-from-top, …).
    pub(crate) fn swap_at(&mut self, depth_a: usize, depth_b: usize) -> Result<(), StackError> {
        let len = self.items.len();
        if depth_a >= len || depth_b >= len {
            return Err(StackError::Underflow);
        }
        self.items.swap(len - 1 - depth_a, len - 1 - depth_b);
        Ok(())
    }

    /// Moves the item at `depth` to the top.
    pub(crate) fn roll(&mut self, depth: usize) -> Result<(), StackError> {
        let item = self.remove_at(depth)?;
        self.push(item)
    }

    /// Removes the top `count` items, preserving their stack order.
    pub(crate) fn drain(&mut self, count: usize) -> Result<Vec<ScriptItem>, StackError> {
        if count > self.items.len() {
            return Err(StackError::Underflow);
        }
        let start = self.items.len() - count;
        Ok(self.items.drain(start..).collect())
    }

    /// Returns the number of stack items.
    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns true when the stack is empty.
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Removes all stack items.
    pub(crate) fn clear(&mut self) {
        self.items.clear();
    }
}

/// Errors returned by bounded stack operations.
#[derive(Debug, Error, PartialEq)]
pub(crate) enum StackError {
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

    /// `peek_at`, `remove_at`, and `roll` use top-relative depth (`0` is the
    /// top); an out-of-range depth returns `StackError::Underflow` and leaves
    /// the stack unchanged.
    #[test]
    fn invalid_depths_return_underflow_without_mutating() -> Result<(), StackError> {
        for len in [0, 1, Stack::MAX_DEPTH] {
            let mut stack = Stack::new();
            for _ in 0..len {
                stack.push(ScriptItem::Num(7))?;
            }
            let before = stack.clone();
            for depth in [len, len + 1, usize::MAX] {
                assert_eq!(stack.peek_at(depth), Err(StackError::Underflow));
                assert_eq!(stack.remove_at(depth), Err(StackError::Underflow));
                assert_eq!(stack.roll(depth), Err(StackError::Underflow));
                assert_eq!(stack, before);
            }
        }
        Ok(())
    }

    #[test]
    fn valid_depths_preserve_top_relative_order() -> Result<(), StackError> {
        let mut stack = Stack::new();
        for value in [1, 2, 3] {
            stack.push(ScriptItem::Num(value))?;
        }
        assert_eq!(stack.peek_at(0), Ok(&ScriptItem::Num(3)));
        assert_eq!(stack.peek_at(2), Ok(&ScriptItem::Num(1)));
        assert_eq!(stack.remove_at(1), Ok(ScriptItem::Num(2)));
        stack.roll(1)?;
        assert_eq!(stack.pop(), Ok(ScriptItem::Num(1)));
        assert_eq!(stack.pop(), Ok(ScriptItem::Num(3)));
        assert!(stack.is_empty());
        Ok(())
    }
}
