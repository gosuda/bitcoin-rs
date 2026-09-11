#!/usr/bin/env python3
"""Validate post-split review and lint follow-ups on the latest main."""
from pathlib import Path
import os
import subprocess
import sys

PRODUCT = "docs/node-contract-traceability-20260911"


def run(*args, cwd):
    print("+", " ".join(args), flush=True)
    subprocess.run(args, cwd=cwd, check=True)


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text()
    if old not in text:
        raise RuntimeError(f"missing replacement target in {path}")
    path.write_text(text.replace(old, new, 1))


def prefix_once(path: Path, prefix: str) -> None:
    text = path.read_text()
    if text.startswith(prefix):
        return
    path.write_text(prefix + text)


def main() -> int:
    if os.environ.get("GITHUB_REPOSITORY") != "gosuda/bitcoin-rs":
        raise RuntimeError("unexpected repository")
    root = Path(os.environ["GITHUB_WORKSPACE"])
    base = subprocess.check_output(["git", "rev-parse", "origin/main"], cwd=root, text=True).strip()
    print("VALIDATION_BASE", base, flush=True)
    work = Path(os.environ["RUNNER_TEMP"]) / "node-contract-traceability"
    run("git", "worktree", "add", "--detach", str(work), base, cwd=root)

    replace_once(
        work / "crates/node/src/sync/requests.rs",
        "        let mut window = self.download_window.lock();\n",
        "        let window = self.download_window.lock();\n",
    )
    replace_once(
        work / "crates/node/src/checkpoint/tests/behavior_2.rs",
        "/// `crates/utxo/src/stats/coin_stats.rs`: MuHash numerator/denominator, then\n",
        "/// `crates/utxo/src/stats/coin_stats.rs`: `MuHash` numerator/denominator, then\n",
    )

    reporter = work / "crates/node/src/recovery_evidence/reporter.rs"
    replace_once(
        reporter,
        "//! Recovery event construction and warning publication after durable evidence succeeds.\n",
        "//! Recovery event construction, warning publication, and durable marker persistence.\n//!\n//! `RCV-12` requires warnings to become process-visible before the marker\n//! write is attempted. A marker failure is still returned to the caller; it\n//! does not erase the warning already exposed by this process.\n",
    )

    recovery = work / "docs/contracts/recovery.md"
    clause = '''### `RCV-12`: Recovery evidence warning and marker ordering

- `RecoveryReporter` is evidence publication, not chainstate authority. It
  reports a recovery fact only after the restored authoritative position is
  known; neither the warning store nor the marker may move chainstate.
- For checkpoint fallback and index-watermark-ahead evidence, the reporter
  first renders/logs the warning and updates the process-visible
  `WarningStore`, then attempts the atomic durable marker write.
- Marker persistence failure is returned to the caller and keeps the warning
  visible for the lifetime of that process. Callers that require durable
  evidence fail closed rather than pretending the marker succeeded.
- Marker and applied-tip-witness reads remain bounded; marker publication uses
  the owner-local atomic write/rename/directory-sync protocol. Corrupt or
  mismatched evidence is rejected instead of silently becoming authority.
- Tests for recovery evidence must cite this clause (and `RCV-04` where they
  exercise crash/failure behavior) so extracted test modules do not become an
  independent specification.

'''
    text = recovery.read_text()
    anchor = "## Proven by\n"
    if clause not in text:
        if text.count(anchor) != 1:
            raise RuntimeError("recovery contract anchor changed")
        recovery.write_text(text.replace(anchor, clause + anchor, 1))

    refs = {
        "crates/node/src/recovery_evidence/tests/validation_1.rs": "// CONTRACT: `docs/contracts/recovery.md#RCV-12` owns recovery-evidence\n// identity/codec and marker refusal semantics; `RCV-04` owns crash behavior.\n",
        "crates/node/src/recovery_evidence/tests/persistence_1.rs": "// CONTRACT: `docs/contracts/recovery.md#RCV-12` owns bounded evidence I/O,\n// atomic marker publication, and warning-before-marker failure semantics.\n",
        "crates/node/src/recovery_evidence/tests/behavior_1.rs": "// CONTRACT: `docs/contracts/recovery.md#RCV-12` owns process-visible recovery\n// warnings and durable marker ordering; these tests are proof, not policy.\n",
        "crates/node/src/tx_ingress/tests.rs": "// CONTRACT: `docs/contracts/mempool-mutations.md#MPL-04` owns peer admission,\n// orphan/reject lifecycle, connection attribution, generation fencing, and retries.\n",
    }
    for relative, prefix in refs.items():
        prefix_once(work / relative, prefix)

    run("cargo", "fmt", "-p", "bitcoin-rs-node", cwd=work)
    run(
        "cargo", "clippy", "--locked", "-p", "bitcoin-rs-node",
        "--all-targets", "--no-default-features", "--features", "fjall,zmq",
        "--", "-D", "warnings", cwd=work,
    )
    for test_filter in ("recovery_evidence::", "tx_ingress::", "checkpoint::", "sync::"):
        run(
            "cargo", "test", "--locked", "-p", "bitcoin-rs-node",
            "--no-default-features", "--features", "fjall,zmq", "--lib", test_filter,
            "--", "--test-threads=1", cwd=work,
        )
    run("cargo", "fmt", "-p", "bitcoin-rs-node", "--", "--check", cwd=work)
    run("git", "diff", "--check", cwd=work)

    paths = [
        "docs/contracts/recovery.md",
        "crates/node/src/recovery_evidence/reporter.rs",
        "crates/node/src/sync/requests.rs",
        "crates/node/src/checkpoint/tests/behavior_2.rs",
        *refs,
    ]
    run("git", "add", "--", *paths, cwd=work)
    changed = set(subprocess.check_output(["git", "diff", "--cached", "--name-only"], cwd=work, text=True).splitlines())
    if changed != set(paths):
        raise RuntimeError(f"unexpected staged paths: {sorted(changed)}")
    run("git", "config", "user.name", "github-actions[bot]", cwd=work)
    run("git", "config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com", cwd=work)
    run(
        "git", "commit", "-m", "chore(node): close post-split review and lint residue",
        "-m", "Follow up merged #914/#915 review with RCV-12/MPL-04 traceability and clean the two strict-Clippy residues left by merged checkpoint/sync splits.", cwd=work,
    )
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=work, text=True).strip()
    remote = subprocess.check_output(["git", "ls-remote", "--heads", "origin", f"refs/heads/{PRODUCT}"], cwd=work, text=True).strip()
    if remote:
        raise RuntimeError(f"refusing existing product branch: {remote}")
    run("git", "push", "origin", f"{head}:refs/heads/{PRODUCT}", cwd=work)
    print("PUBLISHED", PRODUCT, head, "BASE", base, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
