use bitcoin_rs_script::{opcode, push_data};

pub(crate) fn p2sh_true_script() -> Vec<u8> {
    [
        vec![opcode::OP_HASH160, 0x14],
        vec![
            0xda, 0x17, 0x45, 0xe9, 0xb5, 0x49, 0xbd, 0x0b, 0xfa, 0x1a, 0x56, 0x99, 0x71, 0xc7,
            0x7e, 0xba, 0x30, 0xcd, 0x5a, 0x4b,
        ],
        vec![opcode::OP_EQUAL],
    ]
    .concat()
}

pub(crate) fn true_redeem_script_sig() -> Vec<u8> {
    push_data(&[opcode::OP_PUSHNUM_1])
}
