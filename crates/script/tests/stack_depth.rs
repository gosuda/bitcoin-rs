//! Checked depth arithmetic and mutation boundaries of the public script stack.
use bitcoin_rs_script::{ScriptItem, Stack, StackError};

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
