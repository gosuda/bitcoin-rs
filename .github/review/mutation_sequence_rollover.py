"""Prepare and test the focused mutation-sequence rollover correction."""
from pathlib import Path
import subprocess
import sys

BASE = "b9430763f80f0d7f193d80d094863789d2c84e4d"
EXPECTED = {
    "crates/mempool/src/pool.rs": "f45739921f96aa2e392f056ec08cf3012e401da8",
    "crates/mempool/src/mutation.rs": "301a0178192f120bed3ea0b265435ce8758a4199",
    "docs/contracts/mempool-mutations.md": "d7a4392cd081076c783ec518f2a22eb11f299751",
}

TEST = r'''

    // MPL-02: sequence assignment is modulo 2^64 across one committed batch.
    #[test]
    fn mutation_sequence_rolls_over_without_losing_in_batch_sequences() {
        let mut pool = Mempool::new(MempoolLimits::default());
        pool.mempool_sequence = u64::MAX - 1;
        let first = txid_of([0x71; 32]);
        let second = txid_of([0x72; 32]);
        let mut changes = Vec::new();
        pool.push_change(&mut changes, first, MutationOutcome::Accepted);
        pool.push_change(
            &mut changes,
            second,
            MutationOutcome::Removed(RemovalReason::Clear),
        );

        let result = pool.finish_mutation(changes);
        assert_eq!(pool.sequence_number(), 0);
        assert_eq!(result.sequence_base, u64::MAX);
        assert_eq!(result.sequence_of(0), Some(u64::MAX));
        assert_eq!(result.sequence_of(1), Some(0));
        assert_eq!(result.sequence_of(2), None);
    }
'''


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    if text.count(old) != 1:
        raise RuntimeError(f"expected one preimage in {path}: {old!r}; found {text.count(old)}")
    p.write_text(text.replace(old, new, 1))


def assert_base() -> None:
    if subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() != BASE:
        raise RuntimeError("candidate must start at the reviewed main snapshot")
    for path, blob in EXPECTED.items():
        actual = subprocess.check_output(["git", "hash-object", path], text=True).strip()
        if actual != blob:
            raise RuntimeError(f"preimage moved for {path}: {actual} != {blob}")


def add_test() -> None:
    assert_base()
    p = Path("crates/mempool/src/pool.rs")
    text = p.read_text()
    if not text.endswith("}\n"):
        raise RuntimeError("unexpected pool test-module ending")
    p.write_text(text[:-2] + TEST + "}\n")


def apply_fix() -> None:
    replace_once(
        "crates/mempool/src/pool.rs",
        ".map_or(0, |_| self.mempool_sequence - batch_len + 1);",
        ".map_or(0, |_| {\n                self.mempool_sequence\n                    .wrapping_sub(batch_len)\n                    .wrapping_add(1)\n            });",
    )
    replace_once(
        "crates/mempool/src/mutation.rs",
        "        self.sequence_base.checked_add(offset)\n",
        "        Some(self.sequence_base.wrapping_add(offset))\n",
    )
    replace_once(
        "crates/mempool/src/mutation.rs",
        "    /// the write lock, so a batch's sequences are contiguous.\n",
        "    /// the write lock, so a batch's sequences are contiguous modulo `2^64`.\n"
        "    /// A non-empty batch may therefore have sequence zero after rollover.\n",
    )
    replace_once(
        "docs/contracts/mempool-mutations.md",
        "- `Mempool::sequence_number` advances exactly once per emitted change while\n"
        "  the write lock is held. A failed insert, a no-op removal, and a clear of\n"
        "  an empty pool assign nothing.\n",
        "- `Mempool::sequence_number` advances exactly once per emitted change while\n"
        "  the write lock is held, wrapping modulo `2^64`. Batch-base reconstruction\n"
        "  and `MutationResult::sequence_of` use the same wrapping arithmetic, so a\n"
        "  batch crossing `u64::MAX -> 0` retains every assigned sequence. A failed\n"
        "  insert, a no-op removal, and a clear of an empty pool assign nothing.\n",
    )
    marker = "- `crates/mempool/src/gateway.rs` (inline tests):\n"
    p = Path("docs/contracts/mempool-mutations.md")
    text = p.read_text()
    if text.count(marker) != 1:
        raise RuntimeError("proof inventory marker moved")
    proof = (
        "- `crates/mempool/src/pool.rs` (inline tests):\n"
        "  `mutation_sequence_rolls_over_without_losing_in_batch_sequences`.\n"
    )
    p.write_text(text.replace(marker, proof + marker, 1))


def main() -> None:
    if sys.argv[1:] == ["tests"]:
        add_test()
    elif sys.argv[1:] == ["fix"]:
        apply_fix()
    else:
        raise SystemExit("usage: mutation_sequence_rollover.py tests|fix")


if __name__ == "__main__":
    main()
