use super::{VarintError, decode};

// QAC-05
#[kani::proof]
fn compact_size_rejects_every_non_minimal_encoding() {
    let width: u8 = kani::any();
    kani::assume(width < 3);
    let mut frame = [0_u8; 9];
    let value = match width {
        0 => {
            let value: u16 = kani::any();
            kani::assume(value < 0xfd);
            frame[0] = 0xfd;
            frame[1..3].copy_from_slice(&value.to_le_bytes());
            u64::from(value)
        }
        1 => {
            let value: u32 = kani::any();
            kani::assume(value <= 0xffff);
            frame[0] = 0xfe;
            frame[1..5].copy_from_slice(&value.to_le_bytes());
            u64::from(value)
        }
        _ => {
            let value: u64 = kani::any();
            kani::assume(value <= 0xffff_ffff);
            frame[0] = 0xff;
            frame[1..9].copy_from_slice(&value.to_le_bytes());
            value
        }
    };
    match decode(&frame) {
        Err(VarintError::NonCanonical { value: rejected }) => assert_eq!(rejected, value),
        other => panic!("a short value in a wider prefix must be refused: {other:?}"),
    }
}
