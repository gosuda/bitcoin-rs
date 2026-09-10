//! Ownership-preserving transfers between bounded script stacks.
use bitcoin_rs_script::{ScriptItem, Stack, StackError};
use smallvec::SmallVec;

#[test]
fn transfers_move_heap_backed_bytes_without_cloning() -> Result<(), StackError> {
    let mut source = Stack::new();
    let mut destination = Stack::new();
    let bytes = SmallVec::from_slice(&[0x5a; 520]);
    assert!(bytes.spilled());
    let allocation = bytes.as_ptr();
    source.push(ScriptItem::Bytes(bytes))?;
    destination.push(ScriptItem::Num(7))?;

    source.move_to(&mut destination)?;
    assert!(source.is_empty());
    assert_eq!(destination.len(), 2);
    let ScriptItem::Bytes(moved) = destination.peek()? else {
        panic!("transferred item must remain bytes");
    };
    assert_eq!(moved.as_ptr(), allocation);
    assert_eq!(moved.as_slice(), &[0x5a; 520]);

    source.move_from(&mut destination)?;
    assert_eq!(destination.pop(), Ok(ScriptItem::Num(7)));
    let ScriptItem::Bytes(restored) = source.peek()? else {
        panic!("returned item must remain bytes");
    };
    assert_eq!(restored.as_ptr(), allocation);
    assert_eq!(restored.as_slice(), &[0x5a; 520]);
    Ok(())
}

#[test]
fn transfers_preserve_error_precedence_and_capacity() -> Result<(), StackError> {
    for len in [0, 1, Stack::MAX_DEPTH - 1, Stack::MAX_DEPTH] {
        let mut source = Stack::new();
        let mut destination = Stack::new();
        for _ in 0..len {
            destination.push(ScriptItem::Num(7))?;
        }
        let before = destination.clone();
        assert_eq!(source.move_to(&mut destination), Err(StackError::Underflow));
        assert!(source.is_empty());
        assert_eq!(destination, before);

        source.push(ScriptItem::Num(9))?;
        if len == Stack::MAX_DEPTH {
            assert_eq!(source.move_to(&mut destination), Err(StackError::Overflow));
            assert_eq!(source.len(), 1);
            assert_eq!(source.peek(), Ok(&ScriptItem::Num(9)));
            assert_eq!(destination, before);
        } else {
            source.move_to(&mut destination)?;
            assert!(source.is_empty());
            assert_eq!(destination.len(), len + 1);
            assert_eq!(destination.pop(), Ok(ScriptItem::Num(9)));
            assert_eq!(destination, before);
        }
    }
    Ok(())
}
