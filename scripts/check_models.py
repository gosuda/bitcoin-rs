#!/usr/bin/env python3
"""Run the pinned formal evidence lane, independently of Cargo tests.

Requires Python 3.11+, the pinned formal toolchain, and its Java runtime.
Modules run under their configured checker engine (`tlc` or `apalache`),
selectable via `--checker {configured,apalache,tlc}`.
TLC executes exhaustive breadth-first graph exploration via tlc2.TLC from the
pinned Apalache JAR, covering both safety invariants and temporal properties,
projecting results into safety and temporal lanes with honest k=null and state counts.
Apalache runs bounded symbolic model checking starting at K = 128 or the row's
K floor, halving on resource exhaustion down to the floor.
Exit codes: 11 tool identity, 12 parse/type/config error, 13 counterexample,
14 unavailable/timeout/incomplete run, 15 model identity mismatch,
16 pass below the K floor.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import threading
import tomllib
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

PRINT_LOCK = threading.Lock()
ROOT = Path(__file__).resolve().parents[1]
FORMAL_CONTRACT = Path("docs/contracts/formal-verification.md")
MODEL_ROOT = Path("docs/models")
PROPERTIES = ("--inv=TypeOK,Safety", "--temporal=ConditionalProgress")
START_BOUND = 128
RESOURCE_CODE = 14
BOUND_CODE = 16
NON_RETRYABLE_NATIVE = frozenset({75, 255})
LIVE_SESSIONS: set[int] = set()
LIVE_SESSIONS_LOCK = threading.RLock()


@dataclass(frozen=True)
class Toolchain:
    executable: Path
    jar: Path
    jar_sha256: str

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
    bound: int
    checker: str
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
    lines = register.splitlines()
    in_registry_table = False
    for line in lines:
        stripped = line.strip()
        if not stripped.startswith("|"):
            if in_registry_table:
                break
            continue
        cells = [cell.strip() for cell in stripped.split("|")]
        if not in_registry_table:
            if len(cells) == 11 and cells[1].lower() == "module" and cells[9].lower() == "checker":
                in_registry_table = True
            continue
        if all(set(c).issubset({"-", ":", " "}) for c in cells[1:-1] if c):
            continue
        if len(cells) != 11:
            raise EvidenceError(
                15,
                f"{cells[1] or 'malformed row'}: malformed inventory row "
                f"(expected 11 columns, got {len(cells)})",
            )
        name = cells[1]
        if "/" not in name:
            raise EvidenceError(
                15, f"{name}: malformed module name (missing owner/machine separator)"
            )
        owner, _, machine = name.partition("/")
        if not owner or not machine:
            raise EvidenceError(15, f"{name}: malformed module name")
        tla = cells[2]
        cfg = cells[3]
        bound = cells[5]
        checker_token = cells[9].lower()
        if checker_token not in ("apalache", "tlc"):
            raise EvidenceError(
                15, f"{name}: unknown or missing checker {cells[9]!r} (must be 'apalache' or 'tlc')"
            )
        if name in inventory or not bound.isdigit() or int(bound) < 1:
            raise EvidenceError(15, f"{name}: duplicate inventory or malformed bound")
        module = Module(owner, machine, tla, cfg, int(bound), checker_token)
        for path, expected in ((module.source(root), tla), (module.config(root), cfg)):
            try:
                actual = sha256(path)
            except FileNotFoundError:
                actual = ""
            if not re.fullmatch(r"[0-9a-f]{64}", expected) or actual != expected:
                raise EvidenceError(15, f"{path}: model identity differs from proof inventory")
        inventory[name] = module
    if not in_registry_table or not inventory:
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

def tool(root: Path) -> Toolchain:
    with (root / "crates/serving/core-compat.toml").open("rb") as stream:
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
    executable = home / "bin" / name
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
    return Toolchain(executable=executable, jar=jar, jar_sha256=jar_hash)


def native_code(native: int | None) -> int:
    if native is None:
        return 14
    return {0: 0, 150: 12, 120: 12, 12: 13}.get(native, 14)

def register_session(pgid: int) -> None:
    with LIVE_SESSIONS_LOCK:
        LIVE_SESSIONS.add(pgid)


def unregister_session(pgid: int) -> None:
    with LIVE_SESSIONS_LOCK:
        LIVE_SESSIONS.discard(pgid)


def kill_session(pgid: int, sig: int = signal.SIGKILL) -> None:
    try:
        os.killpg(pgid, sig)
    except ProcessLookupError:
        return


def cleanup_all_sessions(sig: int = signal.SIGKILL) -> None:
    with LIVE_SESSIONS_LOCK:
        sessions = list(LIVE_SESSIONS)
        LIVE_SESSIONS.clear()
    for pgid in sessions:
        kill_session(pgid, sig)


def handle_termination_signal(signum: int, _frame: object) -> None:
    cleanup_all_sessions(signal.SIGKILL)
    signal.signal(signum, signal.SIG_DFL)
    os.kill(os.getpid(), signum)



TLC_RESTRICTING_SECTIONS = re.compile(
    r"^(ACTION[-_]CONSTRAINTS?|CONSTRAINTS?|VIEW|SYMMETRY|FAIRNESS|SIMULATION|SPECIFICATION|CHECK_DEADLOCK)\b",
    re.IGNORECASE,
)
TLC_PREEXISTING_PROPERTIES = re.compile(
    r"^(INVARIANT|INVARIANTS|PROPERTY|PROPERTIES)\b",
    re.IGNORECASE,
)


def validate_tlc_cfg(cfg_text: str, module_name: str) -> None:
    lines = [
        line.strip()
        for line in cfg_text.splitlines()
        if line.strip() and not line.strip().startswith(r"\*")
    ]
    has_init = any(re.match(r"^INIT\b", line) for line in lines)
    has_next = any(re.match(r"^NEXT\b", line) for line in lines)
    if not (has_init and has_next):
        raise EvidenceError(12, f"{module_name}: pinned cfg missing INIT or NEXT for TLC")
    for line in lines:
        if TLC_RESTRICTING_SECTIONS.match(line):
            raise EvidenceError(12, f"{module_name}: pinned cfg contains restricting section: {line}")
        if TLC_PREEXISTING_PROPERTIES.match(line):
            raise EvidenceError(12, f"{module_name}: pinned cfg contains pre-existing property/invariant: {line}")

def generate_tlc_cfg(pinned_cfg_text: str) -> str:
    body = pinned_cfg_text.rstrip()
    addition = (
        "\n\n\\* Auto-generated checker invariants and property\n"
        "INVARIANT TypeOK\n"
        "INVARIANT Safety\n"
        "PROPERTY ConditionalProgress\n"
    )
    return body + addition


def execute_process(
    argv: list[str],
    cwd: Path,
    env: dict[str, str],
    log: Path,
    timeout: int,
) -> int | None:
    with (
        log.open("wb") as stream,
        subprocess.Popen(
            argv,
            cwd=cwd,
            env=env,
            stdout=stream,
            stderr=stream,
            start_new_session=True,
        ) as process,
    ):
        register_session(process.pid)
        try:
            return process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            kill_session(process.pid, signal.SIGKILL)
            process.wait()
            return None
        except Exception:
            kill_session(process.pid, signal.SIGKILL)
            raise
        finally:
            unregister_session(process.pid)


@dataclass(frozen=True)
class TlcLogReport:
    log_text: str
    state_match: re.Match[str] | None
    queue_left: int | None
    distinct_states: int | None
    states_gen: int | None


def parse_tlc_log(log_path: Path) -> TlcLogReport:
    log_text = log_path.read_text(encoding="utf-8", errors="replace")
    state_matches = list(
        re.finditer(
            r"(\d+)\s+states generated,\s+(\d+)\s+distinct states found,\s+(\d+)\s+states left on queue",
            log_text,
        )
    )
    state_match = state_matches[-1] if state_matches else None
    states_gen = int(state_match.group(1)) if state_match else None
    distinct_states = int(state_match.group(2)) if state_match else None
    queue_left = int(state_match.group(3)) if state_match else None
    return TlcLogReport(
        log_text=log_text,
        state_match=state_match,
        queue_left=queue_left,
        distinct_states=distinct_states,
        states_gen=states_gen,
    )


TLC_STATE_BUDGETS: dict[str, int] = {
    "ProjectionMining/Projection": 26,
}


def map_tlc_return_codes(
    native: int | None,
    report: TlcLogReport,
    state_budget: int | None = None,
) -> tuple[int, int]:
    if native is None:
        return 14, 14

    if native in (10, 11, 12, 14):
        return 13, 14
    if native == 13:
        return 14, 13
    if native in (150, 151):
        return 12, 12
    if native != 0 or re.search(r"^Error:", report.log_text, re.MULTILINE):
        return 14, 14

    complete_graph = "Model checking completed. No error has been found." in report.log_text
    complete_stats = (
        report.state_match is not None
        and report.queue_left == 0
        and report.distinct_states is not None
        and report.distinct_states > 0
        and report.states_gen is not None
        and report.states_gen >= report.distinct_states
    )
    if state_budget is not None and report.distinct_states is not None and report.distinct_states > state_budget:
        return 14, 14
    if complete_graph and complete_stats:
        return 0, 0
    return 14, 14

def run_tlc_module(
    root: Path,
    toolchain: Toolchain,
    module: Module,
    timeout: int,
    out_dir: Path | None = None,
) -> dict[str, dict[str, int | str | None]]:
    pinned_cfg_text = module.config(root).read_text(encoding="utf-8")
    validate_tlc_cfg(pinned_cfg_text, module.name)
    gen_cfg_text = generate_tlc_cfg(pinned_cfg_text)
    if "PROPERTY ConditionalProgress" not in gen_cfg_text:
        raise EvidenceError(12, f"{module.name}: generated cfg missing PROPERTY ConditionalProgress")
    if "INVARIANT TypeOK" not in gen_cfg_text or "INVARIANT Safety" not in gen_cfg_text:
        raise EvidenceError(12, f"{module.name}: generated cfg missing required invariants")

    base = out_dir if out_dir is not None else root / "target/apalache"
    output = base / module.owner / module.machine / "tlc"
    output.mkdir(parents=True, exist_ok=True)
    run_dir = Path(tempfile.mkdtemp(prefix="run-", dir=output))
    (run_dir / "states").mkdir(parents=True, exist_ok=True)
    (run_dir / "te").mkdir(parents=True, exist_ok=True)

    gen_cfg_file = run_dir / f"{module.machine}_tlc.cfg"
    gen_cfg_file.write_text(gen_cfg_text, encoding="utf-8")
    gen_cfg_hash = sha256(gen_cfg_file)

    jar = toolchain.jar
    jar_hash = toolchain.jar_sha256
    java_cmd = os.environ.get("JAVA", "java")
    jvm_args = shlex.split(os.environ.get("JVM_ARGS", "-Xmx4096m"))
    argv = (
        [java_cmd]
        + jvm_args
        + [
            "-cp",
            str(jar),
            "tlc2.TLC",
            "-workers",
            "1",
            "-fp",
            "1",
            "-metadir",
            str(run_dir / "states"),
            "-noGenerateSpecTE",
            "-teSpecOutDir",
            str(run_dir / "te"),
            "-config",
            str(gen_cfg_file),
            str(module.source(root)),
        ]
    )

    metadata: dict[str, int | str | None | list[str]] = {
        "argv": argv,
        "checker": "tlc",
        "tool_name": "tlc2.TLC",
        "jar_sha256": jar_hash,
        "tla_sha256": module.tla_sha256,
        "input_cfg_sha256": module.cfg_sha256,
        "generated_cfg_sha256": gen_cfg_hash,
        "generated_cfg": str(gen_cfg_file),
        "constants": cfg_constants(module.config(root)),
        "reference_manifest_sha256": sha256(root / "crates/serving/core-compat.toml"),
        "jvm_args": os.environ.get("JVM_ARGS", "-Xmx4096m"),
        "k": None,
        "properties": ["TypeOK", "Safety", "ConditionalProgress"],
    }
    (run_dir / "identity.json").write_text(
        json.dumps(metadata, indent=2) + "\n", encoding="utf-8"
    )

    log = run_dir / "output.log"
    native = execute_process(argv, run_dir, dict(os.environ), log, timeout)

    report = parse_tlc_log(log)
    state_budget = TLC_STATE_BUDGETS.get(module.name)
    safety_rc, temporal_rc = map_tlc_return_codes(native, report, state_budget=state_budget)
    distinct_states = report.distinct_states
    states_gen = report.states_gen

    metadata["states_generated"] = states_gen
    metadata["distinct_states"] = distinct_states
    (run_dir / "identity.json").write_text(
        json.dumps(metadata, indent=2) + "\n", encoding="utf-8"
    )

    result_code = 13 if (safety_rc == 13 or temporal_rc == 13) else max(safety_rc, temporal_rc)
    (run_dir / "result.json").write_text(
        json.dumps({
            "k": None,
            "native_rc": native,
            "evidence_rc": result_code,
            "checker": "tlc",
            "distinct_states": distinct_states,
            "states_generated": states_gen,
        })
        + "\n",
        encoding="utf-8",
    )

    safety_record: dict[str, int | str | None] = {
        "k": None,
        "native_rc": native,
        "evidence_rc": safety_rc,
        "run": str(run_dir),
        "checker": "tlc",
        "distinct_states": distinct_states,
    }
    temporal_record: dict[str, int | str | None] = {
        "k": None,
        "native_rc": native,
        "evidence_rc": temporal_rc,
        "run": str(run_dir),
        "checker": "tlc",
        "distinct_states": distinct_states,
    }
    with PRINT_LOCK:
        print(
            f"{module.name} safety: K=- native={native} evidence={safety_rc}; "
            f"{run_dir} checker=tlc states={distinct_states}",
            flush=True,
        )
        print(
            f"{module.name} temporal: K=- native={native} evidence={temporal_rc}; "
            f"{run_dir} checker=tlc states={distinct_states}",
            flush=True,
        )
    return {"safety": safety_record, "temporal": temporal_record}


def lane_kind(property_arg: str) -> str:
    return "safety" if property_arg.startswith("--inv=") else "temporal"


def run_once(root: Path, toolchain: Toolchain, module: Module, property_arg: str, bound: int,
             timeout: int, out_dir: Path | None = None) -> tuple[int | None, int, Path]:
    kind = lane_kind(property_arg)
    base = out_dir if out_dir is not None else root / "target/apalache"
    output = base / module.owner / module.machine / kind / f"k{bound}"
    output.mkdir(parents=True, exist_ok=True)
    run_dir = Path(tempfile.mkdtemp(prefix="run-", dir=output))
    argv = [
        str(toolchain.executable), "check", f"--config={module.config(root)}",
        property_arg, f"--length={bound}", "--smt-encoding=funArrays",
        f"--out-dir={run_dir}", str(module.source(root)),
    ]
    env = dict(os.environ)
    env.setdefault("JVM_ARGS", "-Xmx4096m")
    env["SMT_SOLVER"] = "z3"
    metadata = {
        "argv": argv, "tla_sha256": module.tla_sha256, "cfg_sha256": module.cfg_sha256,
        "constants": cfg_constants(module.config(root)),
        "reference_manifest_sha256": sha256(root / "crates/serving/core-compat.toml"),
        "jvm_args": env["JVM_ARGS"], "solver": env["SMT_SOLVER"], "k": bound,
    }
    (run_dir / "identity.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    log = run_dir / "output.log"
    native = execute_process(argv, run_dir, env, log, timeout)
    code = native_code(native)
    if code == 0:
        with log.open("rb") as stream:
            stream.seek(max(0, log.stat().st_size - 1024 * 1024))
            tail = stream.read()
        if b"The outcome is: NoError" not in tail or b"EXITCODE: OK" not in tail:
            code = 14
    (run_dir / "result.json").write_text(
        json.dumps({"k": bound, "native_rc": native, "evidence_rc": code}) + "\n",
        encoding="utf-8",
    )
    with PRINT_LOCK:
        print(f"{module.name} {kind}: K={bound} native={native} evidence={code}; {run_dir}",
              flush=True)
    return native, code, run_dir


def run_module(root: Path, toolchain: Toolchain, module: Module, property_arg: str, timeout: int,
               start: int = START_BOUND, out_dir: Path | None = None) -> dict[str, int | str | None]:
    if module.checker == "tlc":
        records = run_tlc_module(root, toolchain, module, timeout, out_dir)
        return records[lane_kind(property_arg)]
    bound = start
    while True:
        native, code, run_dir = run_once(root, toolchain, module, property_arg, bound, timeout,
                                         out_dir)
        if code == RESOURCE_CODE and native not in NON_RETRYABLE_NATIVE and bound > module.bound:
            bound = max(module.bound, bound // 2)
            continue
        if code == 0 and bound < module.bound:
            code = BOUND_CODE
        return {"k": bound, "native_rc": native, "evidence_rc": code, "run": str(run_dir)}


@dataclass(frozen=True)
class RunEnv:
    root: Path
    toolchain: Toolchain
    timeout: int
    out_dir: Path

@dataclass(frozen=True)
class LaneJob:
    module: Module
    property_arg: str
    kind: str
    start_k: int


@dataclass(frozen=True)
class TlcJob:
    module: Module


Job = LaneJob | TlcJob


def run_lane(env: RunEnv, job: LaneJob) -> tuple[Module, str, dict[str, int | str | None]]:
    try:
        record = run_module(
            env.root, env.toolchain, job.module, job.property_arg,
            env.timeout, job.start_k, env.out_dir,
        )
    except (OSError, subprocess.SubprocessError) as error:
        with PRINT_LOCK:
            print(f"{job.module.name} {job.kind}: artifact error: {error}",
                  file=sys.stderr, flush=True)
        record = {"k": job.start_k, "native_rc": None, "evidence_rc": 14, "run": ""}
    return job.module, job.kind, record


def build_jobs(inventory: tuple[Module, ...], explicit_k: int | None) -> list[Job]:
    jobs: list[Job] = []
    for module in inventory:
        if module.checker == "tlc":
            jobs.append(TlcJob(module))
            continue
        for property_arg in PROPERTIES:
            kind = lane_kind(property_arg)
            start_k = explicit_k if explicit_k is not None else max(START_BOUND, module.bound)
            jobs.append(LaneJob(module, property_arg, kind, start_k))
    return jobs


def run_single_job(env: RunEnv, job: Job) -> list[tuple[str, str, dict[str, int | str | None]]]:
    if isinstance(job, TlcJob):
        try:
            records = run_tlc_module(env.root, env.toolchain, job.module, env.timeout, env.out_dir)
            return [
                (job.module.name, "safety", records["safety"]),
                (job.module.name, "temporal", records["temporal"]),
            ]
        except (OSError, subprocess.SubprocessError) as error:
            with PRINT_LOCK:
                print(f"{job.module.name} tlc: artifact error: {error}", file=sys.stderr, flush=True)
            err_rec: dict[str, int | str | None] = {
                "k": None, "native_rc": None, "evidence_rc": 14, "run": "", "checker": "tlc"
            }
            return [
                (job.module.name, "safety", err_rec),
                (job.module.name, "temporal", dict(err_rec)),
            ]
        except EvidenceError as error:
            with PRINT_LOCK:
                print(f"{job.module.name} tlc: evidence error: {error}", file=sys.stderr, flush=True)
            err_rec: dict[str, int | str | None] = {
                "k": None, "native_rc": None, "evidence_rc": error.code, "run": "", "checker": "tlc"
            }
            return [
                (job.module.name, "safety", err_rec),
                (job.module.name, "temporal", dict(err_rec)),
            ]
    _, _, record = run_lane(env, job)
    return [(job.module.name, job.kind, record)]


def execute_jobs(
    root: Path,
    toolchain: Toolchain,
    jobs: list[Job],
    timeout: int,
    out_dir: Path,
    requested_jobs: int | None,
) -> dict[tuple[str, str], dict[str, int | str | None]]:
    cpus = os.cpu_count() or 1
    max_workers = requested_jobs if requested_jobs is not None else max(1, min(cpus, len(jobs)))
    env = RunEnv(root, toolchain, timeout, out_dir)
    results: dict[tuple[str, str], dict[str, int | str | None]] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(run_single_job, env, job): job for job in jobs}
        for future in as_completed(futures):
            job = futures[future]
            try:
                items = future.result()
                for mod_name, kind, record in items:
                    results[(mod_name, kind)] = record
            except (OSError, subprocess.SubprocessError, KeyError, ValueError, TypeError, RuntimeError, EvidenceError) as err:
                with PRINT_LOCK:
                    print(f"{job.module.name}: unexpected error: {err}", file=sys.stderr, flush=True)
                if isinstance(job, TlcJob):
                    err_rec: dict[str, int | str | None] = {
                        "k": None, "native_rc": None, "evidence_rc": 14, "run": "", "checker": "tlc"
                    }
                    results[(job.module.name, "safety")] = err_rec
                    results[(job.module.name, "temporal")] = dict(err_rec)
                else:
                    results[(job.module.name, job.kind)] = {
                        "k": job.start_k, "native_rc": None, "evidence_rc": 14, "run": ""
                    }
    return results


def build_summary(
    inventory: tuple[Module, ...],
    results: dict[tuple[str, str], dict[str, int | str | None]],
) -> dict[str, dict[str, dict[str, int | str | None]]]:
    summary: dict[str, dict[str, dict[str, int | str | None]]] = {}
    for module in sorted(inventory, key=lambda item: item.name):
        summary[module.name] = {}
        for property_arg in PROPERTIES:
            kind = lane_kind(property_arg)
            if (module.name, kind) in results:
                summary[module.name][kind] = results[(module.name, kind)]
            else:
                summary[module.name][kind] = {
                    "k": None,
                    "native_rc": None,
                    "evidence_rc": 14,
                    "run": "",
                    "checker": module.checker,
                }
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
            k_val = record.get("k")
            k_str = "-" if k_val is None else str(k_val)
            print(f"{name:<28} {kind:<9} {k_str:>4} "
                  f"{record['native_rc']!s:>7} {record['evidence_rc']!s:>9}", flush=True)
    print(f"summary: {report}", flush=True)


class CliArgs:
    check_only: bool
    checker: str
    timeout: int
    k_start: int | None
    jobs: int | None
    module: list[str] | None
    out_dir: str


def main() -> int:
    signal.signal(signal.SIGTERM, handle_termination_signal)
    signal.signal(signal.SIGINT, handle_termination_signal)
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, handle_termination_signal)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-only", action="store_true",
                        help="check identities, not model properties")
    parser.add_argument("--checker", choices=("configured", "apalache", "tlc"), default="configured",
                        help="model checker engine to run (default: configured)")
    parser.add_argument("--timeout", type=int, default=3600,
                        help="maximum seconds per solver invocation")
    parser.add_argument("--k-start", type=int, default=None,
                        help=f"first step bound (default: the module K floor or {START_BOUND}, "
                             "whichever is larger)")
    parser.add_argument("--jobs", "-j", type=int, default=None,
                        help="maximum concurrent lanes (default: min(cpu_count, lanes))")
    parser.add_argument("--module", action="append", default=None,
                        help="run only these Owner/Machine modules (repeatable)")
    parser.add_argument("--out-dir", default="target/apalache",
                        help="artifact root, relative to the repository (default target/apalache)")
    args = CliArgs()
    parser.parse_args(namespace=args)
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if args.k_start is not None and args.k_start <= 0:
        parser.error("--k-start must be positive")
    if args.jobs is not None and args.jobs <= 0:
        parser.error("--jobs must be positive")
    selected_modules: list[str] = args.module if args.module is not None else []
    try:
        inventory = modules(ROOT)
        if selected_modules:
            known_names: set[str] = {module.name for module in inventory}
            unknown: list[str] = sorted(set(selected_modules) - known_names)
            if unknown:
                raise EvidenceError(15, f"unknown module: {', '.join(unknown)}")
            selected_set: set[str] = set(selected_modules)
            inventory = tuple(module for module in inventory if module.name in selected_set)
        if args.checker != "configured":
            inventory = tuple(
                dataclasses.replace(module, checker=args.checker)
                for module in inventory
            )
        toolchain = tool(ROOT)
        if args.check_only:
            print(f"Tool and {len(inventory)} model identities checked; properties NOT evaluated.")
            return 0
        jobs = build_jobs(inventory, args.k_start)
        results = execute_jobs(ROOT, toolchain, jobs, args.timeout, ROOT / args.out_dir, args.jobs)
        summary = build_summary(inventory, results)
        write_summary_report(ROOT / args.out_dir, summary)
        codes: list[int] = []
        for lanes in summary.values():
            for record in lanes.values():
                evidence_rc = record["evidence_rc"]
                if evidence_rc is not None:
                    codes.append(int(evidence_rc))
        worst = 13 if 13 in codes else max(codes, default=0)
        return 0 if worst == 0 else worst
    except EvidenceError as error:
        print(error, file=sys.stderr, flush=True)
        return error.code
    except (OSError, KeyError, TypeError, tomllib.TOMLDecodeError, subprocess.SubprocessError) as error:
        print(f"Formal evidence unavailable: {error}", file=sys.stderr, flush=True)
        return 14

if __name__ == "__main__":
    raise SystemExit(main())
