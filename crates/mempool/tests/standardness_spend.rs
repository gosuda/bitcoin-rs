use bitcoin_rs_mempool::standardness::{StandardnessError, is_standard_spend};
use bitcoin_rs_primitives::{
    Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
};
use bitcoin_rs_script::{opcode, push_data};

const CORE_MAX_P2SH_SIGOPS: usize = 15;
const CORE_MAX_TX_LEGACY_SIGOPS: u32 = 2_500;
const CORE_MAX_P2WSH_STACK_ITEMS: usize = 100;
const CORE_MAX_P2WSH_STACK_ITEM_SIZE: usize = 80;
const CORE_MAX_TAPSCRIPT_STACK_ITEM_SIZE: usize = 80;
const CORE_MAX_P2WSH_SCRIPT_SIZE: usize = 3_600;

struct SpendInput {
    outpoint: OutPoint,
    script_sig: Vec<u8>,
    witness: Vec<Vec<u8>>,
    prevout_script: Vec<u8>,
}

fn outpoint(index: u8) -> OutPoint {
    OutPoint::new(Txid::from(Hash256::from_le_bytes(&[index; 32])), 0)
}

fn p2pkh_script() -> Vec<u8> {
    [
        vec![opcode::OP_DUP, opcode::OP_HASH160, 0x14],
        vec![7; 20],
        vec![opcode::OP_EQUALVERIFY, opcode::OP_CHECKSIG],
    ]
    .concat()
}

fn p2sh_script() -> Vec<u8> {
    [
        vec![opcode::OP_HASH160, 0x14],
        vec![9; 20],
        vec![opcode::OP_EQUAL],
    ]
    .concat()
}

fn p2wsh_script() -> Vec<u8> {
    [vec![opcode::OP_0, 0x20], vec![3; 32]].concat()
}

fn p2tr_script() -> Vec<u8> {
    [vec![opcode::OP_PUSHNUM_1, 0x20], vec![4; 32]].concat()
}

fn p2a_script() -> Vec<u8> {
    vec![opcode::OP_PUSHNUM_1, 0x02, 0x4e, 0x73]
}

fn hex_hash160_of_true() -> Vec<u8> {
    [
        0xda, 0x17, 0x45, 0xe9, 0xb5, 0x49, 0xbd, 0x0b, 0xfa, 0x1a, 0x56, 0x99, 0x71, 0xc7, 0x7e,
        0xba, 0x30, 0xcd, 0x5a, 0x4b,
    ]
    .to_vec()
}

fn witness_program(version: u8, program: &[u8]) -> Vec<u8> {
    let Ok(length) = u8::try_from(program.len()) else {
        panic!("a test witness program is at most 40 bytes");
    };
    let mut script = vec![version, length];
    script.extend_from_slice(program);
    script
}

fn multisig_16_of_16() -> Vec<u8> {
    let mut script = vec![opcode::OP_PUSHNUM_1];
    for _ in 0..16 {
        script.extend(push_data(&[0x02; 33]));
    }
    script.extend([opcode::OP_PUSHNUM_16, opcode::OP_CHECKMULTISIG]);
    script
}

fn spend(inputs: &[SpendInput]) -> (Tx, Vec<(OutPoint, TxOut)>) {
    let tx_inputs = inputs
        .iter()
        .map(|input| TxIn {
            previous_output: input.outpoint,
            script_sig: Script::from_bytes(input.script_sig.clone()),
            sequence: Sequence::MAX,
            witness: Witness::from_stack(input.witness.clone()),
        })
        .collect();
    let prevouts = inputs
        .iter()
        .map(|input| {
            (
                input.outpoint,
                TxOut {
                    value: Amount::from_sat(100_000),
                    script_pubkey: Script::from_bytes(input.prevout_script.clone()),
                },
            )
        })
        .collect();
    let tx = Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: tx_inputs,
        outputs: vec![TxOut {
            value: Amount::from_sat(90_000),
            script_pubkey: Script::from_bytes(p2pkh_script()),
        }],
    };
    (tx, prevouts)
}

fn single_input(
    prevout_script: Vec<u8>,
    extra: impl FnOnce(&mut SpendInput),
) -> (Tx, Vec<(OutPoint, TxOut)>) {
    let mut input = SpendInput {
        outpoint: outpoint(1),
        script_sig: Vec::new(),
        witness: Vec::new(),
        prevout_script,
    };
    extra(&mut input);
    spend(&[input])
}

#[test]
fn core_reason_strings_name_the_input_and_witness_rules() {
    assert_eq!(
        StandardnessError::NonStandardInput.to_string(),
        "bad-txns-nonstandard-inputs"
    );
    assert_eq!(
        StandardnessError::NonStandardWitness.to_string(),
        "bad-witness-nonstandard"
    );
}

// POL-07
#[test]
fn undefined_witness_program_input_is_not_standard() {
    for program in [
        witness_program(opcode::OP_PUSHNUM_1, &[3; 20]),
        witness_program(opcode::OP_0, &[3; 25]),
        witness_program(opcode::OP_PUSHNUM_1 + 1, &[3; 32]),
    ] {
        let (tx, prevouts) = single_input(program, |_| {});
        assert_eq!(
            is_standard_spend(&tx, &prevouts),
            Err(StandardnessError::NonStandardInput),
            "Core Solver classifies an undefined witness program as WITNESS_UNKNOWN or NONSTANDARD, so ValidateInputsStandardness rejects it"
        );
    }
}

// POL-07
#[test]
fn p2sh_redeem_script_sigop_limit_is_core_max_p2sh_sigops() {
    let redeem = |sigops: usize| vec![opcode::OP_CHECKSIG; sigops];
    let accepted = single_input(p2sh_script(), |input| {
        input.script_sig = push_data(&redeem(CORE_MAX_P2SH_SIGOPS));
    });
    assert_eq!(
        is_standard_spend(&accepted.0, &accepted.1),
        Ok(()),
        "Core MAX_P2SH_SIGOPS is inclusive at 15 accurate sigops"
    );
    let rejected = single_input(p2sh_script(), |input| {
        input.script_sig = push_data(&redeem(CORE_MAX_P2SH_SIGOPS + 1));
    });
    assert_eq!(
        is_standard_spend(&rejected.0, &rejected.1),
        Err(StandardnessError::NonStandardInput),
        "a redeem script above 15 sigops is bad-txns-nonstandard-inputs in Core"
    );
}

#[test]
fn bip54_legacy_sigop_limit_is_core_max_tx_legacy_sigops() {
    let spending = |count: usize| {
        let sigops_per_input = 16_u32;
        let inputs: Vec<SpendInput> = (0..count)
            .map(|index| {
                let Ok(index) = u8::try_from(index) else {
                    panic!("the test spends at most 256 inputs");
                };
                SpendInput {
                    outpoint: outpoint(index),
                    script_sig: Vec::new(),
                    witness: Vec::new(),
                    prevout_script: multisig_16_of_16(),
                }
            })
            .collect();
        let (tx, prevouts) = spend(&inputs);
        let total = sigops_per_input * u32::try_from(count).unwrap_or(u32::MAX);
        assert!(total <= CORE_MAX_TX_LEGACY_SIGOPS || count == 157);
        (tx, prevouts)
    };
    let accepted = spending(156);
    assert_eq!(
        is_standard_spend(&accepted.0, &accepted.1),
        Ok(()),
        "156 sixteen-key multisig spends reach 2,496 legacy sigops, below Core's 2,500 limit"
    );
    let rejected = spending(157);
    assert_eq!(
        is_standard_spend(&rejected.0, &rejected.1),
        Err(StandardnessError::NonStandardInput),
        "157 sixteen-key multisig spends reach 2,512 legacy sigops, above Core's BIP54 limit"
    );
}

// POL-07
#[test]
fn p2wsh_witness_script_limit_is_core_max_standard_p2wsh_script_size() {
    let with_script_size = |size: usize| {
        single_input(p2wsh_script(), |input| {
            input.witness = vec![vec![opcode::OP_CHECKSIG; size]];
        })
    };
    let accepted = with_script_size(CORE_MAX_P2WSH_SCRIPT_SIZE);
    assert_eq!(
        is_standard_spend(&accepted.0, &accepted.1),
        Ok(()),
        "Core MAX_STANDARD_P2WSH_SCRIPT_SIZE is inclusive at 3,600 bytes"
    );
    let rejected = with_script_size(CORE_MAX_P2WSH_SCRIPT_SIZE + 1);
    assert_eq!(
        is_standard_spend(&rejected.0, &rejected.1),
        Err(StandardnessError::NonStandardWitness),
        "a 3,601-byte witness script is bad-witness-nonstandard in Core"
    );
}

#[test]
fn p2wsh_stack_item_count_limit_is_core_max_standard_p2wsh_stack_items() {
    let with_stack_items = |items: usize| {
        single_input(p2wsh_script(), |input| {
            input.witness = vec![vec![0x01]; items];
            input.witness.push(vec![opcode::OP_CHECKSIG]);
        })
    };
    let accepted = with_stack_items(CORE_MAX_P2WSH_STACK_ITEMS);
    assert_eq!(
        is_standard_spend(&accepted.0, &accepted.1),
        Ok(()),
        "Core MAX_STANDARD_P2WSH_STACK_ITEMS is inclusive at 100 items below the witness script"
    );
    let rejected = with_stack_items(CORE_MAX_P2WSH_STACK_ITEMS + 1);
    assert_eq!(
        is_standard_spend(&rejected.0, &rejected.1),
        Err(StandardnessError::NonStandardWitness),
        "101 witness stack items are bad-witness-nonstandard in Core"
    );
}

#[test]
fn p2wsh_stack_item_size_limit_is_core_max_standard_p2wsh_stack_item_size() {
    let with_item_size = |size: usize| {
        single_input(p2wsh_script(), |input| {
            input.witness = vec![vec![0x01; size], vec![opcode::OP_CHECKSIG]];
        })
    };
    let accepted = with_item_size(CORE_MAX_P2WSH_STACK_ITEM_SIZE);
    assert_eq!(
        is_standard_spend(&accepted.0, &accepted.1),
        Ok(()),
        "Core MAX_STANDARD_P2WSH_STACK_ITEM_SIZE is inclusive at 80 bytes"
    );
    let rejected = with_item_size(CORE_MAX_P2WSH_STACK_ITEM_SIZE + 1);
    assert_eq!(
        is_standard_spend(&rejected.0, &rejected.1),
        Err(StandardnessError::NonStandardWitness),
        "an 81-byte P2WSH stack item is bad-witness-nonstandard in Core"
    );
}

#[test]
fn p2sh_wrapped_p2wsh_applies_the_witness_script_limits() {
    let (tx, prevouts) = single_input(p2sh_script(), |input| {
        input.script_sig = push_data(&p2wsh_script());
        input.witness = vec![vec![0x01]; CORE_MAX_P2WSH_STACK_ITEMS + 1];
        input.witness.push(vec![opcode::OP_CHECKSIG]);
    });
    assert_eq!(
        is_standard_spend(&tx, &prevouts),
        Err(StandardnessError::NonStandardWitness),
        "Core IsWitnessStandard reads the P2SH redeem script and applies the P2WSH limits to it"
    );
}

#[test]
fn tapscript_stack_item_size_limit_is_core_max_standard_tapscript_stack_item_size() {
    let control_block = |leaf: u8| {
        let mut block = vec![leaf];
        block.extend([0x05; 32]);
        block
    };
    let with_item_size = |size: usize| {
        single_input(p2tr_script(), |input| {
            input.witness = vec![
                vec![0x01; size],
                vec![opcode::OP_CHECKSIG],
                control_block(0xc0),
            ];
        })
    };
    let accepted = with_item_size(CORE_MAX_TAPSCRIPT_STACK_ITEM_SIZE);
    assert_eq!(
        is_standard_spend(&accepted.0, &accepted.1),
        Ok(()),
        "Core MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE is inclusive at 80 bytes"
    );
    let rejected = with_item_size(CORE_MAX_TAPSCRIPT_STACK_ITEM_SIZE + 1);
    assert_eq!(
        is_standard_spend(&rejected.0, &rejected.1),
        Err(StandardnessError::NonStandardWitness),
        "an 81-byte tapscript stack item is bad-witness-nonstandard in Core"
    );
    let non_tapscript_leaf = single_input(p2tr_script(), |input| {
        input.witness = vec![
            vec![0x01; CORE_MAX_TAPSCRIPT_STACK_ITEM_SIZE + 1],
            vec![opcode::OP_CHECKSIG],
            control_block(0xc2),
        ];
    });
    assert_eq!(
        is_standard_spend(&non_tapscript_leaf.0, &non_tapscript_leaf.1),
        Ok(()),
        "Core applies the tapscript item-size limit only to leaf version 0xc0"
    );
}

#[test]
fn tapscript_dense_empty_stack_stays_standard() {
    let (tx, prevouts) = single_input(p2tr_script(), |input| {
        input.witness = vec![Vec::new(); 1_000];
        input.witness.push(vec![opcode::OP_CHECKSIG]);
        input.witness.push(vec![0xc0; 33]);
    });
    assert_eq!(
        is_standard_spend(&tx, &prevouts),
        Ok(()),
        "Core caps the tapscript initial stack at 1,000 consensus items and sets no standard item count"
    );
}

#[test]
fn taproot_annex_is_not_standard() {
    let (tx, prevouts) = single_input(p2tr_script(), |input| {
        input.witness = vec![vec![0x07; 64], vec![0x50, 0x00]];
    });
    assert_eq!(
        is_standard_spend(&tx, &prevouts),
        Err(StandardnessError::NonStandardWitness),
        "Core rejects any non-empty witness item beginning with the 0x50 annex tag"
    );
    let key_path = single_input(p2tr_script(), |input| {
        input.witness = vec![vec![0x07; 64]];
    });
    assert_eq!(
        is_standard_spend(&key_path.0, &key_path.1),
        Ok(()),
        "a one-item taproot key-path witness has no annex and no stack script"
    );
}

#[test]
fn taproot_path_spend_with_empty_control_block_is_not_standard() {
    let (tx, prevouts) = single_input(p2tr_script(), |input| {
        input.witness = vec![vec![0x07; 64], vec![opcode::OP_CHECKSIG], Vec::new()];
    });
    assert_eq!(
        is_standard_spend(&tx, &prevouts),
        Err(StandardnessError::NonStandardWitness),
        "Core rejects a taproot path spend whose control block is empty"
    );
    let accepted = single_input(p2tr_script(), |input| {
        input.witness = vec![vec![0x07; 64], vec![opcode::OP_CHECKSIG], vec![0xc0]];
    });
    assert_eq!(
        is_standard_spend(&accepted.0, &accepted.1),
        Ok(()),
        "a non-empty tapscript control block passes when every stack item is within the size limit"
    );
}

#[test]
fn p2a_witness_spend_is_witness_stuffing() {
    let (tx, prevouts) = single_input(p2a_script(), |input| {
        input.witness = vec![vec![0x01]];
    });
    assert_eq!(
        is_standard_spend(&tx, &prevouts),
        Err(StandardnessError::NonStandardWitness),
        "Core IsWitnessStandard rejects any witness on a pay-to-anchor output"
    );
    let bare = single_input(p2a_script(), |_| {});
    assert_eq!(
        is_standard_spend(&bare.0, &bare.1),
        Ok(()),
        "a P2A output is a known Solver type, so spending it without a witness is standard"
    );
}

#[test]
fn witness_on_non_witness_prevout_is_not_standard() {
    let (tx, prevouts) = single_input(p2pkh_script(), |input| {
        input.witness = vec![vec![0x01]];
    });
    assert_eq!(
        is_standard_spend(&tx, &prevouts),
        Err(StandardnessError::NonStandardWitness),
        "Core requires a witness program, direct or P2SH wrapped, for any non-empty witness"
    );
}

#[test]
fn missing_prevout_fails_closed() {
    let (tx, _) = single_input(p2pkh_script(), |_| {});
    assert_eq!(
        is_standard_spend(&tx, &[]),
        Err(StandardnessError::NonStandardInput),
        "Core Solver classifies an unresolved coin's empty scriptPubKey as NONSTANDARD"
    );
}

#[test]
fn input_standardness_precedes_witness_standardness() {
    let (tx, prevouts) = spend(&[
        SpendInput {
            outpoint: outpoint(1),
            script_sig: Vec::new(),
            witness: vec![vec![0x01]],
            prevout_script: p2a_script(),
        },
        SpendInput {
            outpoint: outpoint(2),
            script_sig: Vec::new(),
            witness: Vec::new(),
            prevout_script: witness_program(opcode::OP_PUSHNUM_1 + 1, &[3; 32]),
        },
    ]);
    assert_eq!(
        is_standard_spend(&tx, &prevouts),
        Err(StandardnessError::NonStandardInput),
        "Core runs ValidateInputsStandardness before IsWitnessStandard, so the input reason wins"
    );
}

#[test]
fn p2sh_true_redeem_script_spend_is_standard() {
    let prevout_script = [
        vec![opcode::OP_HASH160, 0x14],
        hex_hash160_of_true(),
        vec![opcode::OP_EQUAL],
    ]
    .concat();
    let (tx, prevouts) = single_input(prevout_script, |input| {
        input.script_sig = push_data(&[opcode::OP_PUSHNUM_1]);
    });
    assert_eq!(
        is_standard_spend(&tx, &prevouts),
        Ok(()),
        "a P2SH outpoint with a one-byte OP_TRUE redeem script carries no sigops and is a known Solver type"
    );
}
