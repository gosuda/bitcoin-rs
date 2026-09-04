use smallvec::SmallVec;
use thiserror::Error;
use tinyvec::ArrayVec;

/// One stack item.
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

    /// Returns an item at `depth`, where zero is the top item.
    pub fn peek_at(&self, depth: usize) -> Result<&ScriptItem, StackError> {
        self.items
            .get(
                self.items
                    .len()
                    .checked_sub(depth + 1)
                    .ok_or(StackError::Underflow)?,
            )
            .ok_or(StackError::Underflow)
    }

    /// Removes and returns an item at `depth`, where zero is the top item.
    pub fn remove_at(&mut self, depth: usize) -> Result<ScriptItem, StackError> {
        let index = self
            .items
            .len()
            .checked_sub(depth + 1)
            .ok_or(StackError::Underflow)?;
        Ok(self.items.remove(index))
    }

    /// Inserts an item at `depth`, where zero places it on top.
    pub fn insert_at(&mut self, depth: usize, item: ScriptItem) -> Result<(), StackError> {
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

    /// Swaps the top two items.
    pub fn swap(&mut self) -> Result<(), StackError> {
        if self.items.len() < 2 {
            return Err(StackError::Underflow);
        }
        let len = self.items.len();
        self.items.swap(len - 1, len - 2);
        Ok(())
    }

    /// Swaps the items at the given depths (0 = top, 1 = second-from-top, …).
    pub fn swap_at(&mut self, depth_a: usize, depth_b: usize) -> Result<(), StackError> {
        let len = self.items.len();
        if depth_a >= len || depth_b >= len {
            return Err(StackError::Underflow);
        }
        self.items.swap(len - 1 - depth_a, len - 1 - depth_b);
        Ok(())
    }

    /// Moves the item at `depth` to the top.
    pub fn roll(&mut self, depth: usize) -> Result<(), StackError> {
        let item = self.remove_at(depth)?;
        self.push(item)
    }

    /// Removes the top `count` items, preserving their stack order.
    pub fn drain(&mut self, count: usize) -> Result<Vec<ScriptItem>, StackError> {
        if count > self.items.len() {
            return Err(StackError::Underflow);
        }
        let start = self.items.len() - count;
        Ok(self.items.drain(start..).collect())
    }

    /// Moves the top item to another bounded stack.
    pub fn move_to(&mut self, destination: &mut Self) -> Result<(), StackError> {
        let item = self.pop()?;
        if let Err(error) = destination.push(item.clone()) {
            self.push(item)?;
            return Err(error);
        }
        Ok(())
    }

    /// Moves an item from another bounded stack onto this stack.
    pub fn move_from(&mut self, source: &mut Self) -> Result<(), StackError> {
        source.move_to(self)
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
