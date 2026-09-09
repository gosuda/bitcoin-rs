//! Witness activation must agree across accounting and both script backends.
//!
//! Contract: BIP141, "Witness program" and "Sigops":
//! <https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki>
//! Core v31.1 counts witness sigops only with WITNESS enabled:
//! <https://github.com/bitcoin/bitcoin/blob/v31.1/src/script/interpreter.cpp#L2139-L2166>
//! `VerifyFlags::filled` owns this library's CLEANSTACK -> WITNESS -> P2SH
//! implications. The kernel must apply them before masking out policy bits.

use bitcoin::hashes::{Hash as _, sha256};
use bitcoin_rs_consensus::kernel::KernelBlock;
use bitcoin_rs_consensus::verify_tx::{
    BlockScriptChecks, prepare_block_script_checks, verify_prepared_units,
};
use bitcoin_rs_consensus::{
    BlockView, ConsensusError, MAX_BLOCK_SIGOPS_COST, UtxoView, transaction_sigop_cost,
    verify_transaction, verify_transaction_non_script,
};
use bitcoin_rs_primitives::{
    Block, BlockHash, Hash256, Header, OutPoint, Tx, TxIn, TxOut, Txid, consensus_bytes,
};
use bitcoin_rs_script::{VerifyFlags, opcode};

const BIP141_SIGOP_LIMIT: u32 = 80_000;
const SIGOPS_PER_INPUT: u32 = 199;

struct WitnessFixture {
    tx: Tx,
    prevouts: Vec<(OutPoint, TxOut)>,
}

impl WitnessFixture {
    /// `CHECKSIG` operations in an unexecuted branch still count under BIP141.
    /// Each script stays within 201 non-push opcodes (199 checks + IF + ENDIF)
    /// and succeeds without signatures, so a script failure cannot mask the
    /// sigop-limit verdict. Expected costs come from the BIP, not the counter.
    fn new(sigops: u32) -> Self {
        let mut inputs = Vec::new();
        let mut prevouts = Vec::new();
        for vout in 0..sigops.div_ceil(SIGOPS_PER_INPUT) {
            let mut script = vec![0x00, opcode::OP_IF];
            let input_sigops = (sigops - vout * SIGOPS_PER_INPUT).min(SIGOPS_PER_INPUT);
            script.extend((0..input_sigops).map(|_| opcode::OP_CHECKSIG));
            script.extend_from_slice(&[opcode::OP_ENDIF, opcode::OP_PUSHNUM_1]);
            let mut script_pubkey = vec![0x00, 0x20];
            script_pubkey.extend_from_slice(sha256::Hash::hash(&script).as_byte_array());
            let outpoint = OutPoint::new(Txid(Hash256::from_le_bytes(&[7; 32])), vout);
            inputs.push(TxIn {
                previous_output: outpoint,
                script_sig: Vec::new(),
                sequence: u32::MAX,
                witness: vec![script],
            });
            prevouts.push((
                outpoint,
                TxOut {
                    value: 1,
                    script_pubkey,
                },
            ));
        }
        Self {
            tx: Tx {
                version: 2,
                inputs,
                outputs: vec![TxOut {
                    value: 1,
                    script_pubkey: vec![opcode::OP_PUSHNUM_1],
                }],
                lock_time: 0,
            },
            prevouts,
        }
    }

    fn block(&self) -> Result<KernelBlock, ConsensusError> {
        let block = Block {
            header: Header {
                version: 1,
                prev_blockhash: BlockHash::default(),
                merkle_root: Hash256::default(),
                time: 0,
                bits: 0x2000_ffff,
                nonce: 0,
            },
            txs: vec![self.tx.clone()],
        };
        KernelBlock::parse(&consensus_bytes(&block))
    }

    fn prepare<'b>(
        &'b self,
        flags: VerifyFlags,
        block: &'b KernelBlock,
    ) -> Result<BlockScriptChecks<'b>, ConsensusError> {
        let mut view = BlockView::new(core::slice::from_ref(&self.tx), vec![self.tx.txid()]);
        let resolved = self
            .prevouts
            .iter()
            .map(|(_, coin)| Some(coin.clone()))
            .collect();
        view.set_resolved(vec![resolved]);
        prepare_block_script_checks(&mut view, 0, 0, flags, block)
    }
}

impl UtxoView for WitnessFixture {
    fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
        self.prevouts
            .iter()
            .find(|(candidate, _)| candidate == outpoint)
            .map(|(_, coin)| coin.clone())
    }
}

#[test]
fn implied_witness_flags_reach_standalone_and_prepared_scripts() -> Result<(), ConsensusError> {
    let mut fixture = WitnessFixture::new(1);
    // Keep the sigop count but invalidate the witness-program hash. Before
    // normalization at the kernel boundary, CLEANSTACK alone became NONE and
    // this spend incorrectly passed that backend's script checks.
    fixture.tx.inputs[0].witness[0].push(opcode::OP_PUSHNUM_1);
    let block = fixture.block()?;
    for (flags, witness_active) in [
        (VerifyFlags::NONE, false),
        (VerifyFlags::P2SH, false),
        (VerifyFlags::WITNESS, true),
        (VerifyFlags::CLEANSTACK, true),
        (VerifyFlags::MANDATORY, true),
        (VerifyFlags::STANDARD, true),
    ] {
        assert_eq!(
            transaction_sigop_cost(&fixture.tx, &fixture.prevouts, flags),
            u32::from(witness_active),
        );
        let unit = fixture.prepare(flags, &block)?;
        let single = verify_transaction(&fixture.tx, &fixture, 0, 0, flags);
        let batched =
            verify_prepared_units(core::slice::from_ref(&unit)).map_err(|failure| failure.error);
        for verdict in [single, batched] {
            if witness_active {
                assert!(matches!(
                    verdict,
                    Err(ConsensusError::Script { input_index: 0, .. })
                ));
            } else {
                assert_eq!(verdict, Ok(()));
            }
        }
        // Assume-valid skips witness execution, not flag-aware accounting.
        assert_eq!(
            verify_transaction_non_script(&fixture.tx, &fixture, 0, 0, flags),
            Ok(()),
        );
    }
    Ok(())
}

#[test]
fn valid_witness_scripts_enforce_the_inclusive_sigop_limit() -> Result<(), ConsensusError> {
    assert_eq!(MAX_BLOCK_SIGOPS_COST, BIP141_SIGOP_LIMIT);
    for cost in [BIP141_SIGOP_LIMIT, BIP141_SIGOP_LIMIT + 1] {
        let fixture = WitnessFixture::new(cost);
        let block = fixture.block()?;
        for (flags, witness_active) in [
            (VerifyFlags::P2SH, false),
            (VerifyFlags::WITNESS, true),
            (VerifyFlags::CLEANSTACK, true),
            (VerifyFlags::MANDATORY, true),
            (VerifyFlags::STANDARD, true),
        ] {
            let expected = if witness_active && cost > BIP141_SIGOP_LIMIT {
                Err(ConsensusError::SigopsLimit {
                    cost,
                    max: BIP141_SIGOP_LIMIT,
                })
            } else {
                Ok(())
            };
            assert_eq!(
                transaction_sigop_cost(&fixture.tx, &fixture.prevouts, flags),
                if witness_active { cost } else { 0 },
            );
            assert_eq!(
                verify_transaction_non_script(&fixture.tx, &fixture, 0, 0, flags),
                expected,
            );
            assert_eq!(
                verify_transaction(&fixture.tx, &fixture, 0, 0, flags),
                expected,
            );
            let unit = fixture.prepare(flags, &block)?;
            assert_eq!(
                verify_prepared_units(core::slice::from_ref(&unit))
                    .map_err(|failure| failure.error),
                expected,
            );
        }
    }
    Ok(())
}

#[test]
fn mixed_activation_units_keep_their_own_sigop_context() -> Result<(), ConsensusError> {
    let cost = BIP141_SIGOP_LIMIT + 1;
    let fixture = WitnessFixture::new(cost);
    let block = fixture.block()?;
    for active_index in [0, 1] {
        let inactive = fixture.prepare(VerifyFlags::P2SH, &block)?;
        let active = fixture.prepare(VerifyFlags::CLEANSTACK, &block)?;
        let mut units = [inactive, active];
        if active_index == 0 {
            units.swap(0, 1);
        }
        match verify_prepared_units(&units) {
            Err(failure) => {
                assert_eq!(failure.unit, active_index);
                assert_eq!(
                    failure.error,
                    ConsensusError::SigopsLimit {
                        cost,
                        max: BIP141_SIGOP_LIMIT,
                    },
                );
            }
            Ok(()) => panic!("the witness-active unit must reject cost {cost}"),
        }
    }
    Ok(())
}
