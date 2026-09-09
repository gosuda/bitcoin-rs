"""Prepare the #680 structural-rejection follow-up on an exact, reviewed base."""
from pathlib import Path
import subprocess
import sys

BASE = "de81e329c783247e1e57bf0402fdf5adf294001e"
EXPECTED = {
    "crates/consensus/src/verify_tx.rs": "51d0cedd50955672cb4d79036e064b0d54e59bf8",
    "crates/mempool/src/gateway.rs": "b56c138863c25fc4b1300828d82e3443ac25e1a4",
    "crates/mempool/src/admission.rs": "cdab21051fb0126ececae4d81b96e82340307d18",
    "docs/contracts/mempool-mutations.md": "71b375211742c068f9755e473ca1fe11ec110ccc",
}


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    if text.count(old) != 1:
        raise RuntimeError(f"expected exactly one preimage in {path}: {old[:90]!r}")
    p.write_text(text.replace(old, new, 1))


def append_tests(path: str, extra: str) -> None:
    p = Path(path)
    text = p.read_text()
    if not text.endswith("}\n"):
        raise RuntimeError(f"unexpected end of test module: {path}")
    p.write_text(text[:-2] + extra + "}\n")


ADMISSION_TESTS = r'''
    struct InputStructureChain {
        coins: Coins,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl AdmissionChain for InputStructureChain {
        fn snapshot(&self, tx: &Tx) -> Option<ChainAdmissionSnapshot> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.coins.snapshot(tx)
        }
    }

    fn assert_input_structure_rejection(mut tx: Tx, coins: Coins) {
        let gateway = gateway();
        let chain = InputStructureChain {
            coins,
            calls: std::sync::atomic::AtomicUsize::new(0),
        };
        tx.inputs[0].witness = vec![vec![1]];
        let tx = Arc::new(tx);
        let origin = AdmissionOrigin::Peer(source());
        assert_eq!(
            gateway.submit_transaction(Arc::clone(&tx), origin, None, 1, &chain),
            Err(SubmitError::Consensus)
        );
        assert_eq!(gateway.orphan_count(), 0);
        assert!(gateway.read().is_empty());
        assert_eq!(gateway.read().sequence_number(), 0);
        assert!(gateway.have_tx(Hash256::from(tx.txid()), false));
        assert!(gateway.get_tx(tx.txid()).is_none());

        let mut alternate = (*tx).clone();
        alternate.inputs[0].witness = vec![vec![2]];
        assert_eq!(alternate.txid(), tx.txid());
        assert_ne!(alternate.wtxid(), tx.wtxid());
        let alternate = Arc::new(alternate);
        assert_eq!(
            gateway.submit_transaction(Arc::clone(&alternate), origin, None, 2, &chain),
            Ok(SubmitOutcome::AlreadyKnown)
        );
        assert_eq!(chain.calls.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(gateway.orphan_count(), 0);
        assert_eq!(gateway.read().sequence_number(), 0);

        gateway.chain_changed(&[]);
        assert_eq!(
            gateway.submit_transaction(alternate, origin, None, 3, &chain),
            Err(SubmitError::Consensus)
        );
        assert_eq!(chain.calls.load(std::sync::atomic::Ordering::Relaxed), 2);
        assert_eq!(gateway.orphan_count(), 0);
        assert_eq!(gateway.read().sequence_number(), 0);
    }

    // MPL-04; Core v31.1 CheckTransaction rejects duplicate/null outpoints
    // independently of witness bytes and without requiring previous outputs:
    // https://github.com/bitcoin/bitcoin/blob/v31.1/src/consensus/tx_check.cpp
    #[test]
    fn input_structure_duplicate_rejection_is_shared_across_witnesses() {
        let outpoint = OutPoint::new(Txid(Hash256::from_le_bytes(&[91; 32])), 0);
        for resolved in [false, true] {
            let mut tx = standard_spend(outpoint, 3);
            tx.inputs.push(tx.inputs[0].clone());
            let coins = if resolved {
                vec![(outpoint, TxOut { value: 10_000, script_pubkey: vec![0x51] })]
            } else {
                vec![]
            };
            assert_input_structure_rejection(tx, Coins(coins));
        }
    }

    #[test]
    fn input_structure_null_rejection_is_shared_across_witnesses() {
        let outpoint = OutPoint::new(Txid(Hash256::from_le_bytes(&[92; 32])), 0);
        let mut tx = standard_spend(outpoint, 4);
        let mut null_input = tx.inputs[0].clone();
        null_input.previous_output = OutPoint::new(Txid::default(), u32::MAX);
        tx.inputs.push(null_input);
        assert_input_structure_rejection(tx, Coins(vec![]));
    }

    #[test]
    fn input_structure_rpc_rejection_does_not_populate_peer_caches() {
        let gateway = gateway();
        let mut tx = standard_spend(OutPoint::default(), 5);
        tx.inputs.push(tx.inputs[0].clone());
        tx.inputs[0].witness = vec![vec![1]];
        assert_eq!(
            gateway.submit_transaction(Arc::new(tx), AdmissionOrigin::Rpc, None, 1, &Coins(vec![])),
            Err(SubmitError::Consensus)
        );
        assert_eq!(gateway.recent_rejects_count(), 0);
        assert_eq!(gateway.orphan_count(), 0);
        assert!(gateway.read().is_empty());
        assert_eq!(gateway.read().sequence_number(), 0);
    }
'''

GATEWAY_TESTS = r'''
    #[test]
    fn input_structure_checks_follow_generation_and_sequence_guards() {
        let gateway = gateway_with(None);
        let mut candidate = standard_tx(93);
        candidate.inputs.push(candidate.inputs[0].clone());
        candidate.inputs[0].witness = vec![vec![1]];
        let origin = AdmissionOrigin::Peer(crate::PeerToken {
            addr: core::net::SocketAddr::from(([127, 0, 0, 1], 8333)),
            connection_id: 7,
        });
        let request = admit_request(&gateway, &candidate, origin);
        gateway.chain_generation.store(2, Ordering::Release);
        assert_eq!(gateway.admit_transaction(request), Err(AdmitError::GenerationChanged));
        assert_eq!(gateway.recent_rejects_count(), 0);

        let request = admit_request(&gateway, &candidate, origin);
        gateway.insert_entry(AdmissionOrigin::Rpc, entry(&tx(94))).expect("fixture insert");
        assert_eq!(gateway.admit_transaction(request), Err(AdmitError::MempoolChanged));
        assert_eq!(gateway.recent_rejects_count(), 0);
        assert_eq!(gateway.orphan_count(), 0);
        assert_eq!(gateway.read().sequence_number(), 1);
    }
'''

INPUT_LOOP = '''    let mut seen = HashSet::new();
    for (input_index, input) in tx.inputs.iter().enumerate() {
        if is_null_outpoint(&input.previous_output) {
            return Err(ConsensusError::NullPrevout { input_index });
        }
        if !seen.insert(input.previous_output) {
            return Err(ConsensusError::DuplicateInput { input_index });
        }
    }
'''

INPUT_HELPER = '''/// Checks non-coinbase input outpoints for null or repeated references.
///
/// This context-free subset of Core's `CheckTransaction` is shared with
/// mempool admission before missing-input policy can retain an orphan.
/// It does not resolve coins, execute scripts, or validate the other transaction
/// fields. The one-null-input coinbase shape is left to the caller's coinbase rules.
///
/// # Errors
///
/// Returns the first null or duplicate input in transaction order, preserving
/// the ordinary verifier's existing error precedence.
///
/// Reference: <https://github.com/bitcoin/bitcoin/blob/v31.1/src/consensus/tx_check.cpp>.
pub fn verify_transaction_input_outpoints(tx: &Tx) -> Result<(), ConsensusError> {
    if is_coinbase(tx) {
        return Ok(());
    }
''' + INPUT_LOOP + '''    Ok(())
}

'''


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in {"tests", "fix"}:
        raise SystemExit("usage: structural_rejection.py tests|fix")
    if subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() != BASE:
        raise RuntimeError("candidate must start at the reviewed main snapshot")
    if sys.argv[1] == "tests":
        for path, expected in EXPECTED.items():
            actual = subprocess.check_output(["git", "hash-object", path], text=True).strip()
            if actual != expected:
                raise RuntimeError(f"preimage mismatch: {path}: {actual} != {expected}")
        append_tests("crates/mempool/src/admission.rs", ADMISSION_TESTS)
        append_tests("crates/mempool/src/gateway.rs", GATEWAY_TESTS)
        return

    path = "crates/consensus/src/verify_tx.rs"
    replace_once(path, INPUT_LOOP, "    verify_transaction_input_outpoints(tx)?;\n")
    replace_once(path, "/// Runs a transaction's non-script pre-checks:", INPUT_HELPER + "/// Runs a transaction's non-script pre-checks:")
    path = "crates/mempool/src/gateway.rs"
    anchor = "        // Missing outputs of a resident parent are base-invalid, not orphans.\n"
    replace_once(path, anchor, '''        // These failures cannot be repaired by another witness or parent arrival.
        // Keep their one consensus-owned check ahead of missing-input policy,
        // but after every generation, sequence, and resident-claim guard.
        if bitcoin_rs_consensus::verify_tx::verify_transaction_input_outpoints(&request.tx)
            .is_err()
        {
            self.record_peer_failure(&pool, request, AdmitError::Consensus, RejectScope::Transaction);
            return Err(AdmitError::Consensus);
        }
''' + anchor)
    path = "docs/contracts/mempool-mutations.md"
    anchor = "- Recent rejects use one bounded FIFO with an identity scope for each hash.\n"
    replace_once(path, anchor, '''- Before missing-input policy can retain a peer body, the gateway runs the
  consensus-owned `verify_transaction_input_outpoints` check. Duplicate inputs
  and null outpoints in non-coinbase transactions reject as `Consensus` and
  use transaction-scoped caching even when witness data is present or coins
  are missing. Parent arrival or a different witness cannot repair these
  failures. State and resident-claim guards still precede classification;
  RPC failures do not populate peer caches. Coinbase policy remains separate.
''' + anchor)
    anchor = "- `crates/mempool/src/admission.rs` (inline tests):\n"
    replace_once(path, anchor, anchor + '''  `input_structure_duplicate_rejection_is_shared_across_witnesses`,
  `input_structure_null_rejection_is_shared_across_witnesses`,
  `input_structure_rpc_rejection_does_not_populate_peer_caches`,
''')
    anchor = "- `crates/mempool/src/gateway.rs` (inline tests):\n"
    replace_once(path, anchor, anchor + "  `input_structure_checks_follow_generation_and_sequence_guards`,\n")


if __name__ == "__main__":
    main()
