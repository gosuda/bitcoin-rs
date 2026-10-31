#!/usr/bin/env python3
"""Run the pinned formal evidence lane, independently of Cargo tests.

Requires Python 3.11+, the pinned Apalache install, and its Java runtime.
Every module in the proof inventory is checked at K = 128 first. Resource
exhaustion halves K until the module completes or K reaches 1, and the
largest attempt and its return code are recorded.
Exit codes: 11 tool identity, 12 parse/type error, 13 counterexample,
14 unavailable/timeout/incomplete run, 15 model identity mismatch.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import threading
import tomllib
from dataclasses import dataclass

PRINT_LOCK = threading.Lock()
ROOT = Path(__file__).resolve().parents[1]
FORMAL_CONTRACT = Path("docs/contracts/formal-verification.md")
MODEL_ROOT = Path("docs/models")
PROPERTIES = ("--inv=TypeOK", "--temporal=ConditionalProgress")
START_BOUND = 128
RESOURCE_CODE = 14


class EvidenceError(Exception):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Module:
    owner: str
    machine: str
    tla_sha256: str
    cfg_sha256: str

    @property
    def name(self) -> str:
        return f"{self.owner}/{self.machine}"

    @property
    def directory(self) -> Path:
        return MODEL_ROOT / self.owner

    def source(self, root: Path) -> Path:
        return root / self.directory / f"{self.machine}.tla"

    def config(self, root: Path) -> Path:
        return root / self.directory / f"{self.machine}.cfg"


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


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


def modules(root: Path) -> tuple[Module, ...]:
    try:
        register = (root / FORMAL_CONTRACT).read_text(encoding="utf-8")
    except (FileNotFoundError, PermissionError) as error:
        raise EvidenceError(
            15, f"formal verification contract is unreadable: {error.filename or error}"
        ) from error
    inventory: dict[str, Module] = {}
    for line in register.splitlines():
        cells = [cell.strip() for cell in line.split("|")]
        if (len(cells) != 10 or "/" not in cells[1]
                or not re.fullmatch(r"[0-9a-f]{64}", cells[2])):
            continue
        name = cells[1]
        tla, cfg, bound = cells[2], cells[3], cells[5]
        if name in inventory or not bound.isdigit():
            raise EvidenceError(15, f"{name}: duplicate inventory or malformed bound")
        owner, _, machine = name.partition("/")
        if not owner or not machine:
            raise EvidenceError(15, f"{name}: malformed module name")
        module = Module(owner, machine, tla, cfg)
        for path, expected in ((module.source(root), tla), (module.config(root), cfg)):
            try:
                actual = sha256(path)
            except FileNotFoundError:
                actual = ""
            if not re.fullmatch(r"[0-9a-f]{64}", expected) or actual != expected:
                raise EvidenceError(15, f"{path}: model identity differs from proof inventory")
        inventory[name] = module
    if not inventory:
        raise EvidenceError(15, "proof inventory is incomplete")
    on_disk = {
        f"{path.parent.name}/{path.stem}"
        for path in (root / MODEL_ROOT).glob("*/*.tla")
    }
    if on_disk != set(inventory):
        missing = sorted(on_disk - set(inventory))
        stale = sorted(set(inventory) - on_disk)
        raise EvidenceError(15, f"module inventory differs from proof inventory: {missing} {stale}")
    return tuple(inventory[name] for name in sorted(inventory))


def tool(root: Path) -> Path:
    with (root / "crates/rpc/core-compat.toml").open("rb") as stream:
        identity = tomllib.load(stream)["reference"]["formal_tool"]
    keys = ("name", "version", "archive_sha256", "jar_sha256")
    if any(key not in identity for key in keys):
        raise EvidenceError(11, "formal tool identity is malformed")
    name, version, archive_hash, jar_hash = (identity[key] for key in keys)
    if name != "apalache-mc" or not all(
        isinstance(value, str) for value in (version, archive_hash, jar_hash)
    ):
        raise EvidenceError(11, "formal tool identity is malformed")
    home = Path(os.environ.get("APALACHE_HOME") or root / "target/tools" / f"apalache-{version}")
    executable = (home / "bin" / name).resolve()
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise EvidenceError(11, f"missing executable: {executable}")
    archives = (home / f"apalache-{version}.zip",
                root / "target/ci-reference-downloads" / f"apalache-{version}.zip")
    if not any(path.is_file() and sha256(path) == archive_hash for path in archives):
        raise EvidenceError(11, "Apalache archive checksum mismatch")
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


def native_code(native: int | None) -> int:
    return {0: 0, 150: 12, 120: 12, 12: 13}.get(native, 14)


def run_once(root: Path, executable: Path, module: Module, property_arg: str, bound: int,
             timeout: int, out_dir: Path | None = None) -> tuple[int | None, int, Path]:
    kind = "safety" if property_arg.startswith("--inv=") else "temporal"
    base = out_dir if out_dir is not None else root / "target/apalache"
    output = base / module.owner / module.machine / kind / f"k{bound}"
    output.mkdir(parents=True, exist_ok=True)
    run_dir = Path(tempfile.mkdtemp(prefix="run-", dir=output))
    argv = [
        str(executable), "check", f"--config={module.config(root)}",
        property_arg, f"--length={bound}", "--smt-encoding=funArrays",
        f"--out-dir={run_dir}", str(module.source(root)),
    ]
    env = dict(os.environ)
    env.setdefault("JVM_ARGS", "-Xmx4096m")
    env["SMT_SOLVER"] = "z3"
    metadata = {
        "argv": argv, "tla_sha256": module.tla_sha256, "cfg_sha256": module.cfg_sha256,
        "constants": cfg_constants(module.config(root)),
        "reference_manifest_sha256": sha256(root / "crates/rpc/core-compat.toml"),
        "jvm_args": env["JVM_ARGS"], "solver": env["SMT_SOLVER"], "k": bound,
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
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
    code = native_code(native)
    if code == 0:
        with log.open("rb") as stream:
            stream.seek(max(0, log.stat().st_size - 1024 * 1024))
            tail = stream.read()
        if b"The outcome is: NoError" not in tail or b"EXITCODE: OK" not in tail:
            code = 14
    if not run_dir.is_dir():
        run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "result.json").write_text(
        json.dumps({"k": bound, "native_rc": native, "evidence_rc": code}) + "\n",
        encoding="utf-8",
    )
    with PRINT_LOCK:
        print(f"{module.name} {kind}: K={bound} native={native} evidence={code}; {run_dir}",
              flush=True)
    return native, code, run_dir


def run_module(root: Path, executable: Path, module: Module, property_arg: str, timeout: int,
               start: int = START_BOUND, out_dir: Path | None = None) -> dict[str, int | None]:
    bound = start
    while True:
        native, code, run_dir = run_once(root, executable, module, property_arg, bound, timeout,
                                         out_dir)
        if code != RESOURCE_CODE or bound == 1:
            return {"k": bound, "native_rc": native, "evidence_rc": code, "run": str(run_dir)}
        bound = max(1, bound // 2)


@dataclass(frozen=True)
class RunEnv:
    root: Path
    executable: Path
    timeout: int
    out_dir: Path


@dataclass(frozen=True)
class LaneJob:
    module: Module
    property_arg: str
    kind: str
    start_k: int


def tool_version(root: Path) -> str:
    manifest_path = root / "crates/rpc/core-compat.toml"
    with manifest_path.open("rb") as stream:
        manifest = tomllib.load(stream)
    return str(manifest["reference"]["formal_tool"]["version"])


def load_memo(path: Path) -> dict[str, dict[str, int | str]]:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
        return {}
    except (OSError, json.JSONDecodeError):
        return {}


def memo_bound(
    memo: dict[str, dict[str, int | str]],
    module: Module,
    kind: str,
    tool_ver: str,
) -> int | None:
    lane_key = f"{module.name}:{kind}"
    entry = memo.get(lane_key)
    if not isinstance(entry, dict):
        return None
    if entry.get("tla_sha256") != module.tla_sha256:
        return None
    if entry.get("tool_version") != tool_ver:
        return None
    bound = entry.get("k")
    if isinstance(bound, int) and bound > 0:
        return bound
    return None


def save_memo(path: Path, memo: dict[str, dict[str, int | str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    try:
        tmp_path.write_text(json.dumps(memo, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        tmp_path.replace(path)
    except OSError as error:
        with PRINT_LOCK:
            print(f"warning: failed to write memo: {error}", file=sys.stderr, flush=True)


def run_lane(env: RunEnv, job: LaneJob) -> tuple[Module, str, dict[str, int | str | None]]:
    try:
        record = run_module(
            env.root, env.executable, job.module, job.property_arg,
            env.timeout, job.start_k, env.out_dir,
        )
    except (OSError, subprocess.SubprocessError) as error:
        with PRINT_LOCK:
            print(f"{job.module.name} {job.kind}: artifact error: {error}",
                  file=sys.stderr, flush=True)
        record = {"k": job.start_k, "native_rc": None, "evidence_rc": 14, "run": ""}
    return job.module, job.kind, record


def build_jobs(
    inventory: tuple[Module, ...],
    explicit_k: int | None,
    memo: dict[str, dict[str, int | str]],
    tool_ver: str,
) -> list[LaneJob]:
    jobs: list[LaneJob] = []
    for module in inventory:
        for property_arg in PROPERTIES:
            kind = "safety" if property_arg.startswith("--inv=") else "temporal"
            if explicit_k is not None:
                start_k = explicit_k
            else:
                cached = memo_bound(memo, module, kind, tool_ver)
                start_k = cached if cached is not None else START_BOUND
            jobs.append(LaneJob(module, property_arg, kind, start_k))
    return jobs


def execute_jobs(
    root: Path,
    executable: Path,
    jobs: list[LaneJob],
    timeout: int,
    out_dir: Path,
    requested_jobs: int | None,
) -> dict[tuple[str, str], dict[str, int | str | None]]:
    cpus = os.cpu_count() or 1
    max_workers = requested_jobs if requested_jobs is not None else max(1, min(cpus, len(jobs)))
    env = RunEnv(root, executable, timeout, out_dir)
    results: dict[tuple[str, str], dict[str, int | str | None]] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(run_lane, env, job): (job.module.name, job.kind, job.start_k)
            for job in jobs
        }
        for future in as_completed(futures):
            mod_name, kind, start_k = futures[future]
            try:
                _, _, record = future.result()
            except Exception as err:
                with PRINT_LOCK:
                    print(f"{mod_name} {kind}: unexpected error: {err}",
                          file=sys.stderr, flush=True)
                record = {"k": start_k, "native_rc": None, "evidence_rc": 14, "run": ""}
            results[(mod_name, kind)] = record
    return results


def build_summary(
    inventory: tuple[Module, ...],
    results: dict[tuple[str, str], dict[str, int | str | None]],
) -> dict[str, dict[str, dict[str, int | str | None]]]:
    summary: dict[str, dict[str, dict[str, int | str | None]]] = {}
    for module in sorted(inventory, key=lambda item: item.name):
        summary[module.name] = {}
        for property_arg in PROPERTIES:
            kind = "safety" if property_arg.startswith("--inv=") else "temporal"
            if (module.name, kind) in results:
                summary[module.name][kind] = results[(module.name, kind)]
    return summary


def write_summary_report(
    out_dir: Path,
    summary: dict[str, dict[str, dict[str, int | str | None]]],
) -> None:
    report = out_dir / "summary.json"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(f"{'module':<28} {'lane':<9} {'K':>4} {'native':>7} {'evidence':>9}", flush=True)
    for name, lanes in summary.items():
        for kind, record in lanes.items():
            print(f"{name:<28} {kind:<9} {record['k']:>4} "
                  f"{str(record['native_rc']):>7} {str(record['evidence_rc']):>9}", flush=True)
    print(f"summary: {report}", flush=True)


def update_memo(
    memo: dict[str, dict[str, int | str]],
    jobs: list[LaneJob],
    summary: dict[str, dict[str, dict[str, int | str | None]]],
    tool_ver: str,
    memo_path: Path,
) -> None:
    for job in jobs:
        record = summary[job.module.name][job.kind]
        lane_key = f"{job.module.name}:{job.kind}"
        if record.get("evidence_rc") == 0 and record.get("k") is not None:
            memo[lane_key] = {
                "tla_sha256": job.module.tla_sha256,
                "tool_version": tool_ver,
                "k": int(record["k"]),
            }
        else:
            memo.pop(lane_key, None)
    save_memo(memo_path, memo)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-only", action="store_true",
                        help="check identities, not model properties")
    parser.add_argument("--timeout", type=int, default=3600,
                        help="maximum seconds per solver invocation")
    parser.add_argument("--k-start", type=int, default=None,
                        help=f"first step bound (default {START_BOUND} or memo)")
    parser.add_argument("--k-memo", default="target/apalache/k-memo.json",
                        help="path to K bound memo cache (default target/apalache/k-memo.json)")
    parser.add_argument("--jobs", "-j", type=int, default=None,
                        help="maximum concurrent lanes (default: min(cpu_count, lanes))")
    parser.add_argument("--module", action="append", default=None,
                        help="run only these Owner/Machine modules (repeatable)")
    parser.add_argument("--out-dir", default="target/apalache",
                        help="artifact root, relative to the repository (default target/apalache)")
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if args.k_start is not None and args.k_start <= 0:
        parser.error("--k-start must be positive")
    if args.jobs is not None and args.jobs <= 0:
        parser.error("--jobs must be positive")
    selected_modules = args.module if args.module is not None else []
    try:
        inventory = modules(ROOT)
        if selected_modules:
            unknown = sorted(set(selected_modules) - {module.name for module in inventory})
            if unknown:
                raise EvidenceError(15, f"unknown module: {', '.join(unknown)}")
            inventory = tuple(module for module in inventory if module.name in selected_modules)
        executable = tool(ROOT)
        if args.check_only:
            print(f"Tool and {len(inventory)} model identities checked; properties NOT evaluated.")
            return 0
        tool_ver = tool_version(ROOT)
        memo_path = Path(args.k_memo)
        if not memo_path.is_absolute():
            memo_path = ROOT / memo_path
        memo = load_memo(memo_path)
        jobs = build_jobs(inventory, args.k_start, memo, tool_ver)
        results = execute_jobs(ROOT, executable, jobs, args.timeout, ROOT / args.out_dir, args.jobs)
        summary = build_summary(inventory, results)
        write_summary_report(ROOT / args.out_dir, summary)
        update_memo(memo, jobs, summary, tool_ver, memo_path)
        worst = max(
            (int(record["evidence_rc"]) for lanes in summary.values()
             for record in lanes.values()),
            default=0,
        )
        return 0 if worst == 0 else worst
    except EvidenceError as error:
        print(error, file=sys.stderr, flush=True)
        return error.code
    except (OSError, KeyError, TypeError, tomllib.TOMLDecodeError, subprocess.SubprocessError) as error:
        print(f"Formal evidence unavailable: {error}", file=sys.stderr, flush=True)
        return 14

if __name__ == "__main__":
    raise SystemExit(main())
