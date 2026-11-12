use smallvec::SmallVec;
use thiserror::Error;
use tinyvec::ArrayVec;

// SCR-02
#[derive(Clone, Debug)]
pub(crate) enum ScriptItem<'a> {
    Num(i64),
    Bytes(SmallVec<[u8; 32]>),
    Borrowed(&'a [u8]),
}

impl<'a> Default for ScriptItem<'a> {
    fn default() -> Self {
        Self::Bytes(SmallVec::new())
    }
}

impl<'a> PartialEq for ScriptItem<'a> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Num(a), Self::Num(b)) => a == b,
            (Self::Bytes(a), Self::Bytes(b)) => a.as_slice() == b.as_slice(),
            (Self::Borrowed(a), Self::Borrowed(b)) => *a == *b,
            (Self::Bytes(a), Self::Borrowed(b)) | (Self::Borrowed(b), Self::Bytes(a)) => {
                a.as_slice() == *b
            }
            _ => false,
        }
    }
}

impl<'a> Eq for ScriptItem<'a> {}

pub(crate) const MAX_STACK_DEPTH: usize = 1000;

#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct Stack<'a> {
    items: ArrayVec<[ScriptItem<'a>; MAX_STACK_DEPTH]>,
}

impl<'a> Stack<'a> {
    pub(crate) const MAX_DEPTH: usize = MAX_STACK_DEPTH;

    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn push(&mut self, item: ScriptItem<'a>) -> Result<(), StackError> {
        match self.items.try_push(item) {
            Some(_) => Err(StackError::Overflow),
            None => Ok(()),
        }
    }

    pub(crate) fn pop(&mut self) -> Result<ScriptItem<'a>, StackError> {
        self.items.pop().ok_or(StackError::Underflow)
    }

    pub(crate) fn peek(&self) -> Result<&ScriptItem<'a>, StackError> {
        self.items.last().ok_or(StackError::Underflow)
    }

    pub(crate) fn peek_at(&self, depth: usize) -> Result<&ScriptItem<'a>, StackError> {
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

    pub(crate) fn remove_at(&mut self, depth: usize) -> Result<ScriptItem<'a>, StackError> {
        let index = self
            .items
            .len()
            .checked_sub(depth)
            .and_then(|index| index.checked_sub(1))
            .ok_or(StackError::Underflow)?;
        Ok(self.items.remove(index))
    }

    pub(crate) fn insert_at(
        &mut self,
        depth: usize,
        item: ScriptItem<'a>,
    ) -> Result<(), StackError> {
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

    pub(crate) fn swap_at(&mut self, depth_a: usize, depth_b: usize) -> Result<(), StackError> {
        let len = self.items.len();
        if depth_a >= len || depth_b >= len {
            return Err(StackError::Underflow);
        }
        self.items.swap(len - 1 - depth_a, len - 1 - depth_b);
        Ok(())
    }

    pub(crate) fn roll(&mut self, depth: usize) -> Result<(), StackError> {
        let item = self.remove_at(depth)?;
        self.push(item)
    }

    pub(crate) fn drain(&mut self, count: usize) -> Result<Vec<ScriptItem<'a>>, StackError> {
        if count > self.items.len() {
            return Err(StackError::Underflow);
        }
        let start = self.items.len() - count;
        Ok(self.items.drain(start..).collect())
    }

    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.items.len()
    }

    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub(crate) fn clear(&mut self) {
        self.items.clear();
    }
}

#[derive(Debug, Error, PartialEq)]
pub(crate) enum StackError {
    #[error("script stack overflow")]
    Overflow,
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

    #[test]
    fn borrowed_and_bytes_items_compare_equal() {
        use smallvec::SmallVec;
        let bytes = SmallVec::<[u8; 32]>::from_slice(b"witness");
        let borrowed = ScriptItem::Borrowed(b"witness");
        let owned = ScriptItem::Bytes(bytes);
        assert_eq!(borrowed, owned);
        assert_eq!(owned, borrowed);
        assert_ne!(borrowed, ScriptItem::Borrowed(b"other"));
        assert_ne!(borrowed, ScriptItem::Num(0));
    }
}
