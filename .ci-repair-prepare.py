"""Temporary, identity-checked candidate construction. Not part of the candidate tree."""
from pathlib import Path
import hashlib
import re

root = Path.cwd()
p = root / 'crates/consensus/src/verify_block.rs'
legacy_path = p.with_name('verify_block_impl.rs')
wrapper = p.read_text()
legacy = legacy_path.read_text()
assert hashlib.sha256(wrapper.encode()).hexdigest() == 'ec8c8a3f3957930c38344031dc61365cd2152ec960e135b475f85781c0029700', 'verifier changed; rebase'
assert hashlib.sha256(legacy.encode()).hexdigest() == 'd129117a582d307161d37918b29c5aa9fbeab2905f376d36d79c0d029d2c2c9b', 'legacy verifier changed; rebase'
start = '/// Verifies non-contextual block rules that do not require a UTXO set.\n'
end = '/// Verifies the header Merkle root and rejects mutated Merkle trees.\n'
body = wrapper[wrapper.index(start):wrapper.index('/// Returns `true` for the one-input, null-prevout coinbase shape.')]
new = legacy[:legacy.index(start)] + body + legacy[legacy.index(end):]
new = '//! Block rule checks over shared parse-once facts.\n\n' + new
new = new.replace('use crate::ConsensusError;\n', 'use crate::ConsensusError;\nuse crate::block_view::BlockFacts;\n', 1)
old = '''        let wtxids: Vec<Wtxid> = block.txs.iter().map(Tx::wtxid).collect();
        let has_witness = block_has_witness(block);
        verify_block_rules_precomputed(block, context, &txids, &wtxids, has_witness)'''
replacement = '''        let mut facts = BlockFacts::from_txids(&block.txs, txids);
        if context.segwit_active && facts.has_witness() {
            facts.or_insert_wtxids_from(&block.txs);
        }
        verify_block_rules_precomputed(block, context, &facts)'''
assert new.count(old) == 1
new = new.replace(old, replacement, 1)
new = new.replace('        Block, BlockHash, Hash256, Header, OutPoint, Tx, TxIn, TxOut, Txid, Wtxid,', '        Block, BlockHash, Hash256, Header, OutPoint, Tx, TxIn, TxOut, Txid,', 1)
new = new.replace('        BlockRuleContext, WITNESS_COMMITMENT_PREFIX, block_has_witness,', '        BlockRuleContext, WITNESS_COMMITMENT_PREFIX,', 1)
new = new.replace('    use crate::ConsensusError;\n', '    use crate::ConsensusError;\n    use crate::block_view::BlockFacts;\n', 1)
assert new.count('#[test]') == legacy.count('#[test]') == 24
assert set(re.findall(r'fn (\w+)\(', new)) == set(re.findall(r'fn (\w+)\(', legacy))
extra = '''    #[test]
    fn precomputed_rules_reject_a_different_transaction_count() {
        let block = block_with_transactions(vec![coinbase_tx()]);
        let facts = BlockFacts::from_txids(&[], Vec::new());
        assert_eq!(
            verify_block_rules_precomputed(&block, BlockRuleContext::non_contextual(), &facts),
            Err(ConsensusError::MerkleRoot)
        );
    }

    #[test]
    fn precomputed_rules_require_cached_witness_ids() {
        let reserved = vec![0_u8; 32];
        let spend = witness_spend_tx();
        let commitment = compute_witness_commitment(&[coinbase_tx(), spend.clone()], &reserved);
        let mut coinbase = coinbase_tx();
        coinbase.inputs[0].witness = vec![reserved];
        coinbase.outputs.push(TxOut {
            value: 0,
            script_pubkey: commitment_script(&commitment),
        });
        let block = block_with_transactions(vec![coinbase, spend]);
        let txids = block.txs.iter().map(Tx::txid).collect();
        let mut facts = BlockFacts::from_txids(&block.txs, txids);
        let context = BlockRuleContext::non_contextual();

        assert!(facts.has_witness());
        assert!(facts.wtxids().is_none());
        assert_eq!(
            verify_block_rules_precomputed(&block, context, &facts),
            Err(ConsensusError::WitnessCommitment)
        );
        facts.or_insert_wtxids_from(&block.txs);
        assert_eq!(verify_block_rules_precomputed(&block, context, &facts), Ok(()));
    }

'''
anchor = '    // --- BIP141 witness commitment tests ---\n'
assert new.count(anchor) == 1
new = new.replace(anchor, extra + anchor, 1)
assert new.count('#[test]') == 26
p.write_text(new)
legacy_path.unlink()

p = root / 'docs/models/ChainAdmission.tla'
original = p.read_bytes()
old_hash = 'e82138365787f075f1ebe232e4c609cec47b515d29cd11d29fe7d35c6f522d83'
assert hashlib.sha256(original).hexdigest() == old_hash, 'ChainAdmission changed; rebase'
text = original.decode()
old = '''(*************************************************************************)
(* Next: one hoisted edge-observer conjunct over the whole union,       *)
(* equivalent to the former per-action form by distribution and         *)
(* identical on every [][Next]_vars behavior for each <<A>>_vars        *)
(* fairness occurrence.                                                 *)
(*************************************************************************)
Next == NextCore /\\ stepOK' = StepSafe

'''
assert text.count(old) == 1
text = text.replace(old, '', 1)
anchor = '          deadlineExp, compCredits, stepOK>>\n'
assert text.count(anchor) == 1
replacement = '''
(*************************************************************************)
(* Apalache consumes INIT/NEXT directly, not a SPECIFICATION containing *)
(* [][Next]_vars. Include that closure explicitly: every original action *)
(* still records StepSafe, while stutter preserves every variable,       *)
(* including the last edge verdict. A completed shutdown can therefore  *)
(* remain in Done instead of being reported as a deadlock.               *)
(* This adds no fairness assumption and removes no original transition. *)
(*************************************************************************)
Next ==
  \\/ (NextCore /\\ stepOK' = StepSafe)
  \\/ UNCHANGED vars
'''
text = text.replace(anchor, anchor + replacement, 1)
text = text.replace('(* Stutter is supplied by [][Next]_vars at the use sites; no fairness or   *)', '(* Next explicitly includes UNCHANGED vars for INIT/NEXT checking; no     *)', 1)
text = text.replace('(* priority occurs inside Next.  Weak fairness appears only inside the     *)', '(* fairness or priority occurs inside Next. Weak fairness is only in the   *)', 1)
text = text.replace('(* Stutter arises from [][Next]_vars at the use sites; no fairness or   *)', '(* Next adds the stutter closure explicitly; no fairness or             *)', 1)
text = text.replace('(* [][Next]_vars.                                                        *)', '(* the explicit UNCHANGED vars branch in Next.                           *)', 1)
p.write_text(text)
new_hash = hashlib.sha256(p.read_bytes()).hexdigest()
assert new_hash == '7d43768179d15e35ab548604082a614d775221644a05f295ea3b28cf55e83c92'
register = root / 'CONSTRAINTS.md'
old_register = register.read_text()
old_row = f'| ChainAdmission | {old_hash} |'
assert old_register.count(old_row) == 1
register_text = old_register.replace(old_row, f'| ChainAdmission | {new_hash} |', 1)
anchor = 'Model to implementer gates: ChainAdmission gates T08, T11, T18; PeerLeases\n'
assert register_text.count(anchor) == 1
register_text = register_text.replace(anchor, '''Before the six canonical invocations, G20 also checks the focused
`regressions/ChainAdmissionShutdown.tla` fixture: the four real shutdown
actions followed by the canonical `Next`, with the original constants and
`TypeOK,Safety,TransitionSafety,ReachedDone`. Its additional five-step
regression catches a missing terminal stutter. It neither replaces any
canonical invocation nor changes their K = 128 bound or proof denominator.
The fixture, imported canonical source, config, and checker output are
retained under `target/apalache/shutdown-regression/`.

''' + anchor, 1)
register.write_text(register_text)

fixture = root / 'docs/models/regressions/ChainAdmissionShutdown.tla'
assert not fixture.exists()
fixture.parent.mkdir(parents=True, exist_ok=True)
fixture.write_text(r'''---- MODULE ChainAdmissionShutdown ----
(* Additional regression, not a replacement for the full model check. *)
(* Follow four real shutdown actions, then require canonical Next to    *)
(* allow the terminal state to persist. Removing its stutter branch     *)
(* makes this check deadlock at step five. Constants remain unchanged.  *)
EXTENDS ChainAdmission

VARIABLE
  \* @type: Int;
  pc

ProbeInit == Init /\ pc' = 0

Prefix ==
  \/ /\ pc = 0 /\ CloseInput /\ pc' = 1
  \/ /\ pc = 1 /\ ChainFinish /\ pc' = 2
  \/ /\ pc = 2 /\ Settle /\ pc' = 3
  \/ /\ pc = 3 /\ EnterDone /\ pc' = 4

ProbeNext ==
  \/ /\ Prefix /\ stepOK' = StepSafe
  \/ /\ pc = 4 /\ Next /\ UNCHANGED pc

ReachedDone == pc = 4 => lifePhase = 3 /\ chainPhase = 11 /\ inputClosed
====
''')

p = root / 'bin/bitcoin-rs/tests/gates/g20_formal_models.rs'
s = p.read_text()
anchor = 'const LENGTH: &str = "--length=128";\n'
assert s.count(anchor) == 1
s = s.replace(anchor, anchor + '''// Additional deterministic shutdown regression; canonical proofs stay at 128.
const SHUTDOWN_MODEL: &str = "ChainAdmissionShutdown";
const SHUTDOWN_INV: &str = "--inv=TypeOK,Safety,TransitionSafety,ReachedDone";
const SHUTDOWN_LENGTH: &str = "--length=5";
''', 1)
old = '''    match kind {
        CheckKind::Safety => args.push(SAFETY_INV.to_string()),
        CheckKind::Temporal => args.push(TEMPORAL.to_string()),
    }
    args.push(LENGTH.to_string());'''
new = '''    let length = if model == SHUTDOWN_MODEL {
        assert_eq!(kind, CheckKind::Safety);
        args.extend([
            "--init=ProbeInit".to_string(),
            "--next=ProbeNext".to_string(),
            SHUTDOWN_INV.to_string(),
        ]);
        SHUTDOWN_LENGTH
    } else {
        match kind {
            CheckKind::Safety => args.push(SAFETY_INV.to_string()),
            CheckKind::Temporal => args.push(TEMPORAL.to_string()),
        }
        LENGTH
    };
    args.push(length.to_string());'''
assert s.count(old) == 1
s = s.replace(old, new, 1)
s = s.replace('args.iter().any(|a| a == SAFETY_INV || a == TEMPORAL)', 'args.iter().any(|a| a == SAFETY_INV || a == TEMPORAL || a == SHUTDOWN_INV)', 1)
s = s.replace('args.iter().any(|a| a == LENGTH),\n        "g20: argv missing --length=128"', 'args.iter().any(|a| a == length),\n        "g20: argv missing expected bound {length}"', 1)
anchor = '#[test]\nfn all_model_specs_check_with_apalache() {\n'
assert s.count(anchor) == 1
helper = '''/// Run serially with the canonical checks: a second concurrent 4 GiB JVM
/// would consume the test runner's memory budget. The copied inputs remain
/// in the existing formal-diagnostics artifact even when a later check fails.
fn check_shutdown_stutter(root: &Path, exe: &Path) {
    let regression = root.join("target/apalache/shutdown-regression");
    let models = regression.join("docs/models");
    fs::create_dir_all(&models).expect("create shutdown regression directory");
    fs::copy(root.join(CONSTRAINTS), regression.join(CONSTRAINTS))
        .expect("copy canonical checker configuration");
    fs::copy(
        root.join("docs/models/ChainAdmission.tla"),
        models.join("ChainAdmission.tla"),
    )
    .expect("copy pinned canonical model for regression");
    fs::copy(
        root.join("docs/models/ChainAdmission.cfg"),
        models.join(format!("{SHUTDOWN_MODEL}.cfg")),
    )
    .expect("copy unchanged canonical constants for regression");
    fs::copy(
        root.join(format!("docs/models/regressions/{SHUTDOWN_MODEL}.tla")),
        models.join(format!("{SHUTDOWN_MODEL}.tla")),
    )
    .expect("copy shutdown regression fixture");
    run_one(&regression, exe, SHUTDOWN_MODEL, CheckKind::Safety, 0);
}

'''
s = s.replace(anchor, helper + anchor, 1)
old = '''    let exe = apalache_executable(&home);

    for model in MODELS {'''
new = '''    let exe = apalache_executable(&home);

    check_shutdown_stutter(&root, &exe);
    for model in MODELS {'''
assert s.count(old) == 1
s = s.replace(old, new, 1)
assert 'const LENGTH: &str = "--length=128";' in s
assert 'run_one(&root, &exe, model, CheckKind::Safety, 1);' in s
assert 'run_one(&root, &exe, model, CheckKind::Temporal, 2);' in s
p.write_text(s)
print('Prepared: production verifier tests, terminal stutter, and additional shutdown regression')
