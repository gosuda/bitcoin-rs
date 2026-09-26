#!/usr/bin/env python3
"""Run the pinned formal evidence lane, independently of Cargo tests.

Requires Python 3.11+, the pinned Apalache install, and its Java runtime.
Exit codes: 11 tool identity, 12 parse/type error, 13 counterexample,
14 unavailable/timeout/incomplete run, 15 model identity mismatch.
Only six complete successful checks constitute model evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import tomllib
from dataclasses import dataclass

ROOT = Path(__file__).resolve().parents[1]
MODELS = ("ChainAdmission", "PeerLeases", "ProjectionMining")
PROPERTIES = ("--inv=TypeOK,Safety,TransitionSafety", "--temporal=ConditionalProgress")


class EvidenceError(Exception):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Model:
    name: str
    tla_sha256: str
    cfg_sha256: str


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


# Apalache section headers; constants are recorded from the pinned cfg
# itself, not from the register's transcribed row.
CFG_SECTION = re.compile(
    r"^(INIT|NEXT|PROPERTY|PROPERTIES|INVARIANT|SPECIFICATION"
    r"|TEMPORAL PROPERTIES|CONSTANTS)(\s|$)"
)


def cfg_constants(path: Path) -> str:
    lines = path.read_text(encoding="utf-8").splitlines()
    for start, line in enumerate(lines):
        if line.strip() == "CONSTANTS":
            break
    else:
        return ""
    names: list[str] = []
    for line in lines[start + 1:]:
        if CFG_SECTION.match(line):
            break
        if name := line.strip():
            names.append(name)
    return ", ".join(names)


def models(root: Path) -> tuple[Model, ...]:
    try:
        register = (root / "CONSTRAINTS.md").read_text(encoding="utf-8")
    except (FileNotFoundError, PermissionError) as error:
        # A missing or unreadable custody register is a model-identity
        # failure on the inventory lane, not an unavailable run.
        raise EvidenceError(
            15, f"proof inventory register is unreadable: {error.filename or error}"
        ) from error
    inventory: dict[str, Model] = {}
    for line in register.splitlines():
        cells = [cell.strip() for cell in line.split("|")]
        if len(cells) < 10 or cells[1] not in MODELS:
            continue
        name, tla, cfg, _, bound = cells[1:6]
        if name in inventory or bound != "128":
            raise EvidenceError(15, f"{name}: duplicate inventory or incorrect bound")
        for suffix, expected in (("tla", tla), ("cfg", cfg)):
            path = root / "docs/models" / f"{name}.{suffix}"
            try:
                actual = sha256(path)
            except FileNotFoundError:
                actual = ""
            if not re.fullmatch(r"[0-9a-f]{64}", expected) or actual != expected:
                raise EvidenceError(15, f"{path}: model identity differs from proof inventory")
        inventory[name] = Model(name, tla, cfg)
    if set(inventory) != set(MODELS):
        raise EvidenceError(15, "proof inventory is incomplete")
    return tuple(inventory[name] for name in MODELS)


def tool(root: Path) -> Path:
    with (root / "crates/rpc/core-compat.toml").open("rb") as stream:
        identity = tomllib.load(stream)["reference"]["formal_tool"]
    if any(key not in identity for key in ("name", "version", "jar_sha256")):
        raise EvidenceError(11, "formal tool identity is malformed")
    name, version, jar_hash = (identity[key] for key in ("name", "version", "jar_sha256"))
    if name != "apalache-mc" or not isinstance(version, str) or not isinstance(jar_hash, str):
        raise EvidenceError(11, "formal tool identity is malformed")
    home = Path(os.environ.get("APALACHE_HOME") or root / "target/tools" / f"apalache-{version}")
    executable = (home / "bin" / name).resolve()
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise EvidenceError(11, f"missing executable: {executable}")
    jar = home / "lib/apalache.jar"
    if not jar.is_file() or sha256(jar) != jar_hash:
        raise EvidenceError(11, "Apalache JAR checksum mismatch")
    result = subprocess.run(
        [str(executable), "version"], capture_output=True, text=True, timeout=30, check=False
    )
    if result.returncode or not re.search(
        rf"(?<![\d.]){re.escape(version)}(?![\d.])", result.stdout + result.stderr
    ):
        raise EvidenceError(11, "Apalache version check failed")
    return executable


def run_model(root: Path, executable: Path, model: Model, property_arg: str, timeout: int) -> None:
    kind = "safety" if property_arg.startswith("--inv=") else "temporal"
    output = root / "target/apalache" / model.name / kind
    output.mkdir(parents=True, exist_ok=True)
    # A fresh per-invocation directory keeps stale success/counterexamples out
    # of the current run without deleting earlier diagnostic evidence.
    run_dir = Path(tempfile.mkdtemp(prefix="run-", dir=output))
    argv = [
        str(executable), "check", f"--config={root / 'docs/models' / (model.name + '.cfg')}",
        property_arg, "--length=128", "--smt-encoding=funArrays",
        f"--out-dir={run_dir}", str(root / "docs/models" / f"{model.name}.tla"),
    ]
    env = dict(os.environ)
    env.setdefault("JVM_ARGS", "-Xmx4096m")
    # Solver identity is part of the recorded evidence; an inherited
    # SMT_SOLVER would silently swap the pinned prover.
    env["SMT_SOLVER"] = "z3"
    metadata = {
        "argv": argv, "tla_sha256": model.tla_sha256, "cfg_sha256": model.cfg_sha256,
        "constants": cfg_constants(root / "docs/models" / f"{model.name}.cfg"),
        "reference_manifest_sha256": sha256(root / "crates/rpc/core-compat.toml"),
        "jvm_args": env["JVM_ARGS"], "solver": env["SMT_SOLVER"],
    }
    (run_dir / "identity.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    log = run_dir / "output.log"
    native: int | None = None
    with log.open("wb") as stream:
        with subprocess.Popen(argv, cwd=run_dir, env=env, stdout=stream, stderr=stream,
                              start_new_session=True) as process:
            try:
                native = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                # Stop the Java descendants too; killing just the launcher
                # can leave solver work alive after the lane has failed.
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
    code = {0: 0, 150: 12, 120: 12, 12: 13}.get(native, 14)
    if code == 0:
        with log.open("rb") as stream:
            stream.seek(max(0, log.stat().st_size - 1024 * 1024))
            tail = stream.read()
        if b"The outcome is: NoError" not in tail or b"EXITCODE: OK" not in tail:
            code = 14
    (run_dir / "result.json").write_text(
        json.dumps({"native_rc": native, "evidence_rc": code}) + "\n", encoding="utf-8"
    )
    print(f"{model.name} {kind}: native={native} evidence={code}; {run_dir}", flush=True)
    if code:
        raise EvidenceError(code, f"{model.name} {kind}: evidence is BLOCKED; see {log}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-only", action="store_true", help="check identities, not model properties")
    parser.add_argument("--timeout", type=int, default=3600, help="maximum seconds per solver invocation")
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    try:
        inventory = models(ROOT)
        executable = tool(ROOT)
        if args.check_only:
            print("Tool and model identities checked; model properties NOT evaluated.")
            return 0
        for property_arg in PROPERTIES:
            for model in inventory:
                run_model(ROOT, executable, model, property_arg, args.timeout)
        print("All six formal checks completed successfully.")
        return 0
    except EvidenceError as error:
        print(error, file=sys.stderr)
        return error.code
    except (OSError, KeyError, TypeError, tomllib.TOMLDecodeError, subprocess.SubprocessError) as error:
        print(f"Formal evidence unavailable: {error}", file=sys.stderr)
        return 14


if __name__ == "__main__":
    raise SystemExit(main())
