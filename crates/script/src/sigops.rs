use bitcoin::{Block, Script};

/// Counts legacy sigops in a script using Core's legacy multisig rule.
pub fn count_legacy(script: &Script) -> u32 {
    saturating_u32(script.count_sigops_legacy())
}

/// Counts segwit-v0 sigops for a witness program and witness stack.
pub fn count_segwit(script: &Script, witness: &[Vec<u8>]) -> u32 {
    if script.is_p2wpkh() {
        return 1;
    }
    if !script.is_p2wsh() {
        return 0;
    }
    witness.last().map_or(0, |witness_script| {
        saturating_u32(Script::from_bytes(witness_script).count_sigops())
    })
}

/// Counts taproot sigops under BIP342's per-input budget model.
///
/// Taproot does not contribute to the legacy per-block sigop cost. Tapscript's
/// `OP_CHECKSIG` and `OP_CHECKSIGADD` budget is enforced per input by the
/// delegated interpreter, so this block-level counter returns zero.
pub const fn count_taproot(_script: &Script, _witness: &[Vec<u8>]) -> u32 {
    0
}

/// Counts sigop cost visible without a UTXO set.
///
/// P2SH redeem-script and witness sigops that require previous outputs cannot be
/// counted from a bare block alone; callers with a UTXO view should use the
/// `bitcoin::Transaction::total_sigop_cost` closure shape directly.
pub fn count_block(block: &Block) -> u32 {
    block.txdata.iter().fold(0u32, |count, tx| {
        count.saturating_add(saturating_u32(tx.total_sigop_cost(|_| None)))
    })
}

fn saturating_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use bitcoin::blockdata::opcodes::all::{
        OP_CHECKMULTISIG, OP_CHECKSIG, OP_PUSHNUM_1, OP_PUSHNUM_3,
    };
    use bitcoin::script::Builder;

    use super::{count_legacy, count_segwit, count_taproot};

    #[test]
    fn legacy_count_matches_core_multisig_legacy_rule() {
        let script = Builder::new()
            .push_opcode(OP_PUSHNUM_1)
            .push_slice([3; 33])
            .push_slice([3; 33])
            .push_slice([3; 33])
            .push_opcode(OP_PUSHNUM_3)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script();
        assert_eq!(count_legacy(script.as_script()), 20);
        assert_eq!(script.count_sigops(), 3);
    }

    #[test]
    fn segwit_counts_p2wpkh_and_p2wsh_witness_script() {
        let p2wpkh = Builder::new().push_int(0).push_slice([7; 20]).into_script();
        assert_eq!(count_segwit(p2wpkh.as_script(), &[]), 1);

        let witness_script = Builder::new().push_opcode(OP_CHECKSIG).into_script();
        let p2wsh = Builder::new().push_int(0).push_slice([9; 32]).into_script();
        assert_eq!(
            count_segwit(p2wsh.as_script(), &[witness_script.as_bytes().to_vec()]),
            1
        );
    }

    #[test]
    fn taproot_has_no_legacy_block_sigop_charge() {
        let p2tr = Builder::new().push_int(1).push_slice([9; 32]).into_script();
        assert_eq!(count_taproot(p2tr.as_script(), &[]), 0);
    }
}
