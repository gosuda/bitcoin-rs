#!/usr/bin/env python3
"""Validate and publish focused mining review fixes; never enters product history."""
from pathlib import Path
import os
import subprocess
import sys

BASE = "b4dd372bd407da06b1f5e62b67fc1bc3dd64cecd"
PRODUCT = "fix/mining-longpoll-singleflight-20260911"


def run(*args, cwd, env=None):
    print("+", " ".join(args), flush=True)
    subprocess.run(args, cwd=cwd, env=env, check=True)


def replace_exact(path: Path, old: str, new: str) -> None:
    text = path.read_text()
    if text.count(old) != 1:
        raise RuntimeError(f"expected one replacement in {path}: {old[:80]!r}")
    path.write_text(text.replace(old, new))


def main() -> int:
    if os.environ.get("GITHUB_REPOSITORY") != "gosuda/bitcoin-rs":
        raise RuntimeError("unexpected repository")
    root = Path(os.environ["GITHUB_WORKSPACE"])
    work = Path(os.environ["RUNNER_TEMP"]) / "mining-review-product"
    run("git", "worktree", "add", "--detach", str(work), BASE, cwd=root)

    long_poll = work / "crates/node/src/mining/long_poll.rs"
    replace_exact(
        long_poll,
        '''pub(super) fn parse_long_poll_id(id: &str) -> Option<GenerationKey> {
    if id.len() < 65 {
        return None;
    }
    let (hash_hex, sequence) = id.split_at(64);
    let tip_hash = Hash256::from_str_be(hash_hex).ok()?;
    let mempool_sequence = sequence.parse().ok()?;
''',
        '''pub(super) fn parse_long_poll_id(id: &str) -> Option<GenerationKey> {
    let hash_hex = id.get(..64)?;
    let sequence = id.get(64..)?;
    if sequence.is_empty() {
        return None;
    }
    let tip_hash = Hash256::from_str_be(hash_hex).ok()?;
    let mempool_sequence = sequence.parse().ok()?;
''',
    )

    candidate = work / "crates/node/src/mining/candidate.rs"
    replace_exact(
        candidate,
        '''use std::sync::atomic::Ordering;

impl MiningCoordinator {
''',
        '''use std::sync::atomic::Ordering;

/// Clears an abandoned single-flight slot if candidate assembly unwinds.
///
/// Release/quickstart builds abort on panic, but test, development, and other
/// unwind-enabled profiles must not leave same-key callers blocked behind a
/// permanently in-flight generation.
struct InFlightAssemblyGuard<'a> {
    coordinator: &'a MiningCoordinator,
    key: GenerationKey,
    armed: bool,
}

impl Drop for InFlightAssemblyGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut state = self.coordinator.state.lock();
        if state
            .in_flight
            .as_ref()
            .is_some_and(|flight| flight.key == self.key)
        {
            state.in_flight = None;
            drop(state);
            self.coordinator.wake.notify_all();
        }
    }
}

impl MiningCoordinator {
''',
    )
    replace_exact(
        candidate,
        '''        state.in_flight = Some(InFlight { key, result: None });
        drop(state);

        let assembled = self.assemble_for_key(key);
''',
        '''        state.in_flight = Some(InFlight { key, result: None });
        drop(state);
        let mut flight_guard = InFlightAssemblyGuard {
            coordinator: self,
            key,
            armed: true,
        };

        let assembled = self.assemble_for_key(key);
''',
    )
    replace_exact(
        candidate,
        '''        if state
            .in_flight
            .as_ref()
            .is_some_and(|flight| flight.key == key && flight.result.is_some())
        {
            state.in_flight = None;
        }
        returned
''',
        '''        if state
            .in_flight
            .as_ref()
            .is_some_and(|flight| flight.key == key && flight.result.is_some())
        {
            state.in_flight = None;
        }
        flight_guard.armed = false;
        returned
''',
    )

    generation_tests = work / "crates/node/src/mining/generation_key_tests.rs"
    text = generation_tests.read_text()
    prefix = '''// CONTRACT: `crates/mining/README.md` owns the node-facing BIP22/BIP23
// long-poll identity contract; `docs/contracts/external-api.md#API-11` owns
// the corresponding `getblocktemplate` long-poll surface.
'''
    if not text.startswith(prefix):
        generation_tests.write_text(prefix + text + '''
#[test]
fn long_poll_rejects_non_ascii_split_boundary_without_panicking() {
    // 63 ASCII bytes followed by a two-byte UTF-8 scalar makes byte 64 an
    // invalid character boundary. An external longpollid must fail closed,
    // never panic the panic=abort node process.
    let malformed = format!("{}é", "0".repeat(63));
    assert_eq!(malformed.len(), 65);
    assert!(parse_long_poll_id(&malformed).is_none());
}
''')

    refs = {
        "crates/node/src/mining/candidate_template_tests.rs": '''// CONTRACT: `docs/contracts/external-api.md#API-11` owns BIP22/BIP23
// template capabilities, submitold, signet projection, and template rules.
''',
        "crates/node/src/mining/generation_signal_tests.rs": '''// CONTRACT: `docs/contracts/architecture.md#ARCH-07` owns post-commit
// consumer ordering; `MiningGenerationSignal` is the mining wake projection.
''',
        "crates/node/src/mining/apply_error_tests.rs": '''// CONTRACT: `docs/contracts/external-api.md#API-05` and `#API-11` own
// mining validation/submission projection; `map_apply_error` is the in-code
// mapping contract from chainstate refusal to BIP22/BIP23 validation results.
''',
    }
    for relative, comment in refs.items():
        path = work / relative
        text = path.read_text()
        if not text.startswith(comment):
            path.write_text(comment + text)

    run("cargo", "+1.95.0", "fmt", "-p", "bitcoin-rs-node", cwd=work)
    run(
        "cargo", "+1.95.0", "clippy", "--locked", "-p", "bitcoin-rs-node",
        "--all-targets", "--no-default-features", "--features", "fjall,zmq",
        "--", "-D", "warnings", cwd=work,
    )
    run(
        "cargo", "+1.95.0", "test", "--locked", "-p", "bitcoin-rs-node",
        "--no-default-features", "--features", "fjall,zmq", "--lib", "mining::",
        "--", "--test-threads=1", cwd=work,
    )
    run("cargo", "+1.95.0", "fmt", "-p", "bitcoin-rs-node", "--", "--check", cwd=work)
    run("git", "diff", "--check", cwd=work)

    paths = [
        "crates/node/src/mining/long_poll.rs",
        "crates/node/src/mining/candidate.rs",
        "crates/node/src/mining/generation_key_tests.rs",
        "crates/node/src/mining/candidate_template_tests.rs",
        "crates/node/src/mining/generation_signal_tests.rs",
        "crates/node/src/mining/apply_error_tests.rs",
    ]
    run("git", "add", "--", *paths, cwd=work)
    changed = subprocess.check_output(["git", "diff", "--cached", "--name-only"], cwd=work, text=True).splitlines()
    if set(changed) != set(paths):
        raise RuntimeError(f"unexpected staged files: {changed}")
    run("git", "config", "user.name", "github-actions[bot]", cwd=work)
    run("git", "config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com", cwd=work)
    run(
        "git", "commit", "-m", "fix(mining): harden longpoll parsing and single-flight unwind",
        "-m", "Reject non-UTF-8 byte split boundaries without panicking, clear matching in-flight assembly on unwind, and attach permanent mining tests to current contracts. Follow-up to #912 review.", cwd=work,
    )
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=work, text=True).strip()
    remote = subprocess.check_output(["git", "ls-remote", "--heads", "origin", f"refs/heads/{PRODUCT}"], cwd=work, text=True).strip()
    if remote:
        current = remote.split()[0]
        if current != BASE:
            raise RuntimeError(f"refusing unexpected product branch head: {current}")
    run("git", "push", "origin", f"{head}:refs/heads/{PRODUCT}", cwd=work)
    print("PUBLISHED", PRODUCT, head, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
