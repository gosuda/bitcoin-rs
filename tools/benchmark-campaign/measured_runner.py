#!/usr/bin/env python3
"""MRP campaign runner: validate / plan / run.

Implements the authorized new controlled bitcoin-rs performance campaign
harness. Local-only, stdlib only. Reads a real complete registration JSON
and refuses unregistered, missing, or incomplete inputs before any launch.

Mechanisms reused from the earlier matched-protocol runner (host state, strict
perf CSV parsing, process-group kill, incremental results). The campaign
contract is docs/benchmarks/measured-campaign.md.

Thresholds and gates live in measured_analyze.py, never here.
This runner collects raw data only and performs quality-shape checks
(counts, durations, hashes) needed to stop a broken run early.
Rows of kind `counted` bypass Criterion: the bench binary prints one warmup
plus ten measured ``MRP_COUNTED_SAMPLE <json>`` stdout lines, each
accumulating whole semantic units to the 1 s raw floor.
parse_counted_stdout()/counted_case_fields() parse them and
validate_counted_samples() is the one authoritative validator (the analyzer
reuses it on retained records). The shared sampler source
tools/benchmark-support/measured_samples.rs and the shared snapshot-order
source tools/benchmark-support/snapshot_order.rs are pinned in the bench
fingerprint inventory, identical across all five roots.

validate_registration() below is the static full-schema validator: exact
pinned row/role/kind/units/bench/argv tables, complete source-root/bench/lock
inventories, build-receipt-bound executables, typed baseline evidence and
identity pins. It never queries process affinity or the local CPU model, so
results never depend on the caller's own CPU binding. validate_live_registration()
adds the live affinity and observed-CPU-model checks for the validate/plan/run
CLIs. read_cpu_model() observes one /proc/cpuinfo processor block by number
and host_state() captures it per case; a missing model is a typed
RegistrationError with no echoed-label fallback. measured_analyze.py uses
the static validator (loaded only after verifying the registered runner
digest against the exact bytes read, and only after binding its own executing
analyzer path/digest) and binds each record's captured
CPU/model and taskset prefix instead of its own affinity. Metadata can verify
files and hashes; it cannot prove that a process ran (the parent owns run
honesty).

Subcommands:
  validate --registration REG   check everything, launch nothing
  plan --registration REG       validate (minus output-dir absence) and
                                print the canonical case schedule
  run --registration REG        validate fully, then execute serially

All three work without measurements except `run`, which is the only
subcommand that launches benchmark processes.
"""

import argparse
import hashlib
import itertools
import json
import math
import os
import re
import signal
import statistics
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypedDict


TARGET_ORDER: tuple[str, ...] = ("T1", "T2", "T3", "T4")
ZERO_VISITS: tuple[str, ...] = ("candidate", "zero", "zero", "candidate")
MEASURE_VISITS: tuple[str, ...] = ("candidate", "control", "control", "candidate")
BLOCKS_PER_TARGET: int = 4
PERF_EVENTS: str = "task-clock,cycles:u,instructions:u"
CRITERION_ENV: str = "CRITERION_HOME"
WARMUP_SAMPLES: int = 3
MEASURED_SAMPLES: int = 10
MIN_CRITERION_NS: float = 1_000_000_000.0
MIN_NODE_NS: int = 2_000_000_000
NODE_BENCHES: tuple[str, ...] = (
    "block_to_template_baseline",
    "template_render_baseline",
)
T2_COMPONENT_FIELDS: tuple[str, ...] = (
    "apply_call_to_reply_us",
    "durable_sync_us",
    "durable_commit_us",
    "on_connect_us",
    "assembly_us",
    "remainder_us",
)
T3_ARM_PREFIXES: tuple[str, ...] = (
    "rpc_miss",
    "service_hit",
    "service_hit2",
    "rpc_hit",
)
CORPUS_FIELDS: tuple[str, ...] = (
    "prefix_blocks",
    "tip_height",
    "funded_outputs",
    "background",
    "targets",
    "target_spends",
    "total_txs_per_target",
)
SCRIPT_UNITS_PER_ITER: int = 64
TREES: tuple[str, ...] = (
    "candidate",
    "control_T1",
    "control_T2",
    "control_T3",
    "control_T4",
)
ANALYZER_FILE: str = "measured_analyze.py"
BENCH_SOURCES: dict[str, str] = {
    "insert_fill": "crates/mempool/benches/insert_fill.rs",
    "candidate": "crates/mining/benches/candidate.rs",
    "sync_pipeline": "crates/node/benches/sync_pipeline.rs",
    "signature_verification": "crates/script/benches/signature_verification.rs",
}
# Shared counted-sampler module: pinned in the bench fingerprint inventory so
# every tree carries the identical sampler source.
MEASURED_SAMPLES_MODULE: str = "tools/benchmark-support/measured_samples.rs"
# Shared snapshot-order module: the deduplicated chunk-order fingerprint and
# topological assertion shared by the insert_fill and candidate benches.
SNAPSHOT_ORDER_MODULE: str = "tools/benchmark-support/snapshot_order.rs"
BENCH_FINGERPRINT_FILES: tuple[str, ...] = tuple(BENCH_SOURCES.values()) + (
    MEASURED_SAMPLES_MODULE,
    SNAPSHOT_ORDER_MODULE,
)
COUNTED_SAMPLE_PREFIX: str = "MRP_COUNTED_SAMPLE "
COUNTED_FLOOR_NS: int = 1_000_000_000
U64_MAX: int = 2**64 - 1
COUNTED_SAMPLE_KEYS: tuple[str, ...] = (
    "bench",
    "sample",
    "warmup",
    "unit_ns",
    "unit_count",
    "total_ns",
)
LOCK_GRAPHS: tuple[str, ...] = (
    "Cargo.lock",
    "fuzz/Cargo.lock",
    "tools/ldk/Cargo.lock",
    "tools/compact-filter-interop/Cargo.lock",
    "tools/stratum-sv2/template-provider/Cargo.lock",
)
BUILD_OUTPUT_NAMES: tuple[str, ...] = ("target", ".git")
RECEIPT_KIND: str = "rbitcoin-mrp-build-receipt"
EVIDENCE_KIND: str = "rbitcoin-mrp-baseline-evidence"
NATIVE_ENGINE: str = "native"
ENGINE_ENV_VAR: str = "BITCOIN_RS_VALIDATION_ENGINE"
GATED_ROLES: tuple[str, ...] = ("acceptance", "primary", "guard_keep", "connect_guard")
REGISTRATION_KEYS: tuple[str, ...] = (
    "status",
    "campaign_root",
    "host",
    "timeout_seconds",
    "scripts",
    "source_roots",
    "source_fingerprints",
    "bench_fingerprints",
    "lock_fingerprints",
    "binaries",
    "source_baseline_evidence",
    "dependency_baseline_evidence",
    "corpus",
    "node_identity",
    "targets",
    "schedule",
)


@dataclass(frozen=True)
class RowSpec:
    """One pinned campaign row: a Criterion ID, a counted-sampler ID, or a
    node workload name."""

    id: str
    kind: str
    role: str
    bench: str
    units: int


def _criterion(row_id: str, role: str, bench: str, units: int = 1) -> RowSpec:
    return RowSpec(row_id, "criterion", role, bench, units)


def _counted(row_id: str, role: str, bench: str) -> RowSpec:
    """Counted-sampler row: same ID/role/binary, ``--mrp-counted`` argv."""
    return RowSpec(row_id, "counted", role, bench, 1)


_POOL_SIZES: tuple[int, ...] = (0, 64, 512, 2048, 20000, 50000, 100000)

# Exact row inventory, in execution order, from the four common Rust benches
# (full Criterion IDs include the group names). Roles select frozen rules; the
# 50k/100k assembly rows are the only T1 keep rows. Rows with substantial
# untimed setup/teardown run the counted sampler (kind `counted`): same IDs,
# roles and binaries via `--mrp-counted`, with no duplicate Criterion
# registration.
PINNED_ROWS: dict[str, tuple[RowSpec, ...]] = {
    "T1": (
        *(
            _criterion(f"mempool_insert_entry/fill/{n}", "acceptance", "insert_fill")
            for n in (200, 800, 3200, 12800, 51200)
        ),
        _counted(
            "mempool_insert_entry/fill/63-member-cluster", "report_only", "insert_fill"
        ),
        *(
            _criterion(
                f"assemble_candidate/end_to_end/{n}",
                "guard_keep" if n in (50000, 100000) else "report_only",
                "candidate",
            )
            for n in _POOL_SIZES
        ),
        _criterion(
            "assemble_candidate/end_to_end/chains/depth-25", "report_only", "candidate"
        ),
        *(
            _counted(
                f"mining_snapshot_operation/mining_snapshot/{n}",
                "report_only",
                "candidate",
            )
            for n in _POOL_SIZES[1:]
        ),
        _counted(
            "mining_snapshot_operation/mining_snapshot/chains/depth-25",
            "report_only",
            "candidate",
        ),
        _counted(
            "indexed_selection_read_guard/read_guard/100000", "report_only", "candidate"
        ),
    ),
    "T2": (
        RowSpec("block_to_template_baseline", "node", "primary", "sync_pipeline", 1),
    ),
    "T3": (RowSpec("template_render_baseline", "node", "primary", "sync_pipeline", 1),),
    "T4": (
        _counted("connect_admission_throughput/flat", "primary", "sync_pipeline"),
        _counted(
            "connect_admitted_signed_spend_block/flat", "connect_guard", "sync_pipeline"
        ),
        _counted(
            "connect_unseen_signed_spend_block/flat", "connect_guard", "sync_pipeline"
        ),
        *(
            _criterion(
                f"signature_verification/{alg}/{mode}",
                "diagnostic",
                "signature_verification",
                SCRIPT_UNITS_PER_ITER,
            )
            for alg in ("ecdsa", "schnorr")
            for mode in ("hit", "miss")
        ),
    ),
}


def expected_row(target: str, spec: RowSpec) -> dict[str, Any]:
    """The only registration row that may stand for `spec` (exact invocation)."""
    row: dict[str, Any] = {
        "id": spec.id,
        "kind": spec.kind,
        "role": spec.role,
        "bench_target": spec.bench,
        "candidate_binary": f"candidate/{spec.bench}",
        "control_binary": f"control_{target}/{spec.bench}",
    }
    if spec.kind == "criterion":
        row["argv"] = ["--bench", "--noplot", "--exact", spec.id]
        row["samples"] = MEASURED_SAMPLES
        row["units_per_iter"] = spec.units
    elif spec.kind == "counted":
        row["argv"] = ["--mrp-counted", spec.id]
        row["samples"] = MEASURED_SAMPLES
        row["units_per_iter"] = 1
    else:
        row["argv"] = ["--bench", spec.id, "--nocapture"]
        row["node_bench"] = spec.id
    return row


class RegistrationError(Exception):
    """A registration document failed validation with collected reasons."""


class HostState(TypedDict):
    loadavg: str | None
    affinity: list[int]
    chosen_cpu: int
    chosen_cpu_model: str
    chosen_cpu_cur_freq: str | None
    chosen_cpu_governor: str | None
    cpufreq: dict[str, str]


class PerfCounters(TypedDict):
    task_clock_ms: float
    cycles_u: float
    instructions_u: float


class CaseRecord(TypedDict):
    case_index: int
    target: str
    block: int
    block_kind: str
    visit_index: int
    arm: str
    binary_key: str
    binary_path: str
    binary_sha256_before: str
    binary_sha256_after: str | None
    row: str
    row_kind: str
    label: str
    command: list[str]
    host_before: HostState
    host_after: HostState | None
    exit_code: int | None
    timed_out: bool
    cancelled: bool
    error: str | None
    case_dir: str
    stdout_path: str | None
    stderr_path: str | None
    perf_csv: str | None
    perf: PerfCounters | None
    criterion_sample_path: str | None
    sample_iters: list[float] | None
    sample_times_ns: list[float] | None
    normalized_ns: list[float] | None
    case_median_ns: float | None
    case_std_ns: float | None
    node_stdout_path: str | None
    node_warmups_seen: int | None
    node_samples: list[dict[str, Any]] | None
    node_corpus: dict[str, int] | None
    counted_stdout_path: str | None
    counted_warmups_seen: int | None
    counted_warmup_samples: list[dict[str, Any]] | None
    counted_samples: list[dict[str, Any]] | None


_HEX64 = re.compile(r"[0-9a-f]{64}")
_COMMIT_HEX = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


def _is_hex64(value: object) -> bool:
    return isinstance(value, str) and _HEX64.fullmatch(value) is not None


def _is_commit_hex(value: object) -> bool:
    return isinstance(value, str) and _COMMIT_HEX.fullmatch(value) is not None


def _is_positive_finite(value: object) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    as_float = float(value)
    return math.isfinite(as_float) and as_float > 0


def _is_nonnegative_finite(value: object) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    as_float = float(value)
    return math.isfinite(as_float) and as_float >= 0


def compute_sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def read_sysfs_string(path: Path) -> str | None:
    if not path.is_file():
        return None
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return None


def read_cpu_model(chosen_cpu: int) -> str:
    """Observed `model name` for one /proc/cpuinfo processor block.

    Linux x86 host only. The block whose `processor` equals `chosen_cpu`
    supplies the model; the first model line is never used as a fallback.
    Missing or unreadable data raises RegistrationError. This catches an
    accidentally stale registration label; it is not tamper-proof
    attestation.
    """
    if type(chosen_cpu) is not int or chosen_cpu < 0:
        raise RegistrationError(
            f"host.cpu_model cannot be read for cpu {chosen_cpu!r}: "
            "processor must be a non-negative int"
        )
    try:
        text = Path("/proc/cpuinfo").read_text(encoding="utf-8")
    except OSError as exc:
        raise RegistrationError(
            f"host.cpu_model cannot be read for cpu {chosen_cpu}: {exc}"
        ) from exc
    for block in re.split(r"\n[ \t]*\n", text):
        processor: int | None = None
        model: str | None = None
        for raw_line in block.splitlines():
            if ":" not in raw_line:
                continue
            key, _, value = raw_line.partition(":")
            key = key.strip()
            value = value.strip()
            if key == "processor":
                try:
                    processor = int(value.split()[0])
                except (ValueError, IndexError):
                    processor = None
            elif key == "model name" and model is None and value:
                model = value
        if processor == chosen_cpu:
            if model:
                return model
            raise RegistrationError(
                f"host.cpu_model cannot be read for cpu {chosen_cpu}: "
                f"processor {chosen_cpu} block has no model name"
            )
    raise RegistrationError(
        f"host.cpu_model cannot be read for cpu {chosen_cpu}: "
        f"processor {chosen_cpu} not found in /proc/cpuinfo"
    )


def host_state(chosen_cpu: int) -> HostState:
    cpu_model = read_cpu_model(chosen_cpu)
    loadavg = read_sysfs_string(Path("/proc/loadavg"))
    try:
        affinity = sorted(os.sched_getaffinity(0))
    except OSError:
        affinity = []
    chosen_dir = Path(f"/sys/devices/system/cpu/cpu{chosen_cpu}/cpufreq")
    freq_map: dict[str, str] = {}
    for cpu in affinity:
        cpu_dir = Path(f"/sys/devices/system/cpu/cpu{cpu}/cpufreq")
        for metric in ("scaling_governor", "scaling_cur_freq"):
            val = read_sysfs_string(cpu_dir / metric)
            if val is not None:
                freq_map[str(cpu_dir / metric)] = val
    return {
        "loadavg": loadavg,
        "affinity": affinity,
        "chosen_cpu": chosen_cpu,
        "chosen_cpu_model": cpu_model,
        "chosen_cpu_cur_freq": read_sysfs_string(chosen_dir / "scaling_cur_freq"),
        "chosen_cpu_governor": read_sysfs_string(chosen_dir / "scaling_governor"),
        "cpufreq": freq_map,
    }


def parse_perf_csv(path: Path) -> tuple[PerfCounters, str]:
    if not path.is_file():
        raise RegistrationError(f"{path}: perf.csv was not produced")
    content = path.read_text(encoding="utf-8")
    if not content.strip():
        raise RegistrationError(f"{path}: perf.csv is empty")
    raw_events: dict[str, float] = {}
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 3:
            raise RegistrationError(
                f"{path}: malformed perf line with fewer than 3 fields: {line!r}"
            )
        val_str, unit, event_name = parts[0], parts[1], parts[2]
        if event_name not in ("task-clock", "cycles:u", "instructions:u"):
            raise RegistrationError(
                f"{path}: unrecognized perf event {event_name!r} in line: {line!r}"
            )
        if event_name in raw_events:
            raise RegistrationError(f"{path}: duplicate event counter {event_name!r}")
        if event_name == "task-clock" and unit != "msec":
            raise RegistrationError(
                f"{path}: wrong unit {unit!r} for task-clock (expected 'msec')"
            )
        if event_name in ("cycles:u", "instructions:u") and unit != "":
            raise RegistrationError(
                f"{path}: nonempty unit {unit!r} for {event_name} (expected empty)"
            )
        try:
            val = float(val_str)
        except ValueError as exc:
            raise RegistrationError(
                f"{path}: event {event_name} has non-numeric value {val_str!r}"
            ) from exc
        if not math.isfinite(val) or val <= 0:
            raise RegistrationError(
                f"{path}: event {event_name} must be finite positive, got {val}"
            )
        raw_events[event_name] = val
    missing = [
        r for r in ("task-clock", "cycles:u", "instructions:u") if r not in raw_events
    ]
    if missing:
        raise RegistrationError(f"{path}: missing required perf events: {missing}")
    counters: PerfCounters = {
        "task_clock_ms": raw_events["task-clock"],
        "cycles_u": raw_events["cycles:u"],
        "instructions_u": raw_events["instructions:u"],
    }
    return counters, content


def load_registration(path: Path) -> tuple[dict[str, Any] | None, list[str]]:
    try:
        raw: object = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        return None, [f"cannot read registration file {path}: {exc}"]
    except json.JSONDecodeError as exc:
        return None, [f"registration file {path} is not valid JSON: {exc}"]
    if not isinstance(raw, dict):
        return None, [
            f"registration root must be a JSON object, got {type(raw).__name__}"
        ]
    return raw, []


def _exact_keys(
    obj: object, keys: tuple[str, ...], where: str, reasons: list[str]
) -> bool:
    if not isinstance(obj, dict):
        reasons.append(f"{where} must be an object")
        return False
    missing = [key for key in keys if key not in obj]
    surplus = sorted(str(key) for key in obj if key not in keys)
    if missing:
        reasons.append(f"{where}: missing required key(s) {missing}")
    if surplus:
        reasons.append(f"{where}: unrecognized key(s) {surplus}")
    return not missing and not surplus


def _same(got: object, want: object) -> bool:
    """Type-strict JSON equality (10.0 and True never stand for 10 or 1)."""
    if isinstance(want, list):
        return (
            isinstance(got, list)
            and len(got) == len(want)
            and all(_same(g, w) for g, w in zip(got, want))
        )
    return type(got) is type(want) and got == want


def identity_digest(files: dict[str, str]) -> str:
    """SHA-256 of the canonical JSON (sorted keys, compact) of a path->hash map."""
    canonical = json.dumps(files, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _tree_digest(reg: dict[str, Any], key: str, tree: str) -> str | None:
    inventory = reg.get(key)
    files = inventory.get(tree) if isinstance(inventory, dict) else None
    return identity_digest(files) if isinstance(files, dict) else None


def _load_json_object(
    path: Path, where: str, reasons: list[str]
) -> dict[str, Any] | None:
    try:
        doc: object = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        reasons.append(f"{where}: cannot read {path} as JSON: {exc}")
        return None
    if not isinstance(doc, dict):
        reasons.append(f"{where}: {path} must contain a JSON object")
        return None
    return doc


def _check_pinned_file(
    entry: object, extra: tuple[str, ...], where: str, reasons: list[str]
) -> Path | None:
    """`{path, sha256, *extra}` naming an existing absolute file with that hash."""
    if not _exact_keys(entry, ("path", "sha256", *extra), where, reasons):
        return None
    assert isinstance(entry, dict)
    path_value, digest = entry["path"], entry["sha256"]
    if not isinstance(path_value, str) or not Path(path_value).is_absolute():
        reasons.append(f"{where}.path must be an absolute path, got {path_value!r}")
        return None
    path = Path(path_value)
    if not path.is_file():
        reasons.append(f"{where}.path is not an existing file: {path_value}")
        return None
    if not _is_hex64(digest):
        reasons.append(f"{where}.sha256 must be lowercase 64-hex, got {digest!r}")
        return None
    try:
        actual = compute_sha256(path)
    except OSError as exc:
        reasons.append(f"{where}: cannot hash {path_value}: {exc}")
        return None
    if actual != digest:
        reasons.append(
            f"{where}: file hash {actual!r} != registered {digest!r} ({path_value})"
        )
        return None
    return path.resolve()


def _outside_roots(path: Path, roots: dict[str, Path]) -> bool:
    return all(root != path and root not in path.parents for root in roots.values())


def _hash_source_file(path: Path, real_root: Path) -> tuple[str | None, str | None]:
    """(sha256, problem) for one file of a source-only tree."""
    if path.name == ".git":
        return None, f"{path}: VCS marker in a source-only tree"
    if path.is_symlink():
        resolved = path.resolve()
        if real_root not in resolved.parents or not resolved.is_file():
            return None, f"{path}: symlink leaves the source root or is dangling"
    elif not path.is_file():
        return None, f"{path}: not a regular file"
    try:
        return compute_sha256(path), None
    except OSError as exc:
        return None, f"{path}: cannot hash: {exc}"


def _walkable_dirs(base: Path, dirnames: list[str], problems: list[str]) -> list[str]:
    kept: list[str] = []
    for name in sorted(dirnames):
        child = base / name
        if child.is_symlink():
            problems.append(f"{child}: symlinked directory cannot be inventoried")
        elif name in BUILD_OUTPUT_NAMES:
            problems.append(
                f"{child}: build-output/VCS directory in a source-only tree"
            )
        else:
            kept.append(name)
    return kept


def derive_source_files(root: Path) -> tuple[dict[str, str], list[str]]:
    """Every file of a source-only frozen tree as relpath -> SHA-256.

    Build-output/VCS directories, symlinked directories, symlinks that leave
    the tree and non-regular files are reported, never skipped silently.
    """
    problems: list[str] = []
    files: dict[str, str] = {}
    real_root = root.resolve()
    if "target" in real_root.parts:
        problems.append(f"{real_root}: build-output root (path contains 'target')")

    def note_unreadable(exc: OSError) -> None:
        problems.append(f"{exc.filename}: cannot list directory: {exc.strerror}")

    for dirpath, dirnames, filenames in os.walk(real_root, onerror=note_unreadable):
        base = Path(dirpath)
        dirnames[:] = _walkable_dirs(base, dirnames, problems)
        for name in sorted(filenames):
            path = base / name
            digest, problem = _hash_source_file(path, real_root)
            if problem is not None:
                problems.append(problem)
            elif digest is not None:
                files[path.relative_to(real_root).as_posix()] = digest
    return files, problems


def _check_host(host: object, reasons: list[str]) -> None:
    """Static host shape check only; never queries process affinity."""
    if not isinstance(host, dict):
        reasons.append("registration: host must be an object")
        return
    model = host.get("cpu_model")
    if not isinstance(model, str) or not model:
        reasons.append("registration: host.cpu_model must be a nonempty string")
    cpu = host.get("cpu")
    if type(cpu) is not int or cpu < 0:
        reasons.append(
            f"registration: host.cpu must be a non-negative int, got {cpu!r}"
        )


def _check_live_affinity(host: object, reasons: list[str]) -> None:
    """Live check that the registered CPU is usable by this process."""
    if not isinstance(host, dict):
        return
    cpu = host.get("cpu")
    if type(cpu) is not int or cpu < 0:
        return
    try:
        available = os.sched_getaffinity(0)
    except OSError as exc:
        reasons.append(f"registration: cannot query process affinity: {exc}")
        return
    if cpu not in available:
        reasons.append(
            f"registration: host.cpu {cpu} not in process affinity mask "
            f"{sorted(available)}"
        )


def _check_live_cpu_model(host: object, reasons: list[str]) -> None:
    """Live check that the observed CPU model matches the registration."""
    if not isinstance(host, dict):
        return
    cpu = host.get("cpu")
    if type(cpu) is not int or cpu < 0:
        return
    registered = host.get("cpu_model")
    if not isinstance(registered, str) or not registered:
        return
    try:
        observed = read_cpu_model(cpu)
    except RegistrationError as exc:
        reasons.append(str(exc))
        return
    if observed != registered:
        reasons.append(
            f"registration: host.cpu_model {registered!r} != observed cpu_model "
            f"{observed!r} for cpu {cpu}"
        )


def _check_run_settings(
    reg: dict[str, Any], check_output_absent: bool, reasons: list[str]
) -> None:
    if reg["status"] != "registered":
        reasons.append(
            "registration: status must be exactly 'registered' "
            f"(no measurements before registration), got {reg['status']!r}"
        )
    campaign_root = reg["campaign_root"]
    if not isinstance(campaign_root, str) or not Path(campaign_root).is_absolute():
        reasons.append("registration: campaign_root must be an absolute path string")
    elif check_output_absent and Path(campaign_root).exists():
        reasons.append(
            f"registration: campaign_root {campaign_root} already exists; "
            "refusing to overwrite, resume, or retry"
        )
    _check_host(reg["host"], reasons)
    timeout = reg["timeout_seconds"]
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        reasons.append(
            f"registration: timeout_seconds must be numeric, got {timeout!r}"
        )
    elif not math.isfinite(float(timeout)) or float(timeout) <= 0:
        reasons.append(
            f"registration: timeout_seconds must be finite positive, got {timeout!r}"
        )


def _check_scripts(reg: dict[str, Any], reasons: list[str]) -> None:
    scripts = reg["scripts"]
    where = "registration: scripts"
    if not _exact_keys(scripts, ("runner", "analyzer"), where, reasons):
        return
    here = Path(__file__).resolve()
    for name, expected in (
        ("runner", here),
        ("analyzer", here.with_name(ANALYZER_FILE)),
    ):
        path = _check_pinned_file(scripts[name], (), f"{where}[{name!r}]", reasons)
        if path is not None and path != expected:
            reasons.append(
                f"{where}[{name!r}].path {str(path)!r} is not the executing "
                f"{name} {str(expected)!r}"
            )


def _compare_whole_tree(
    where: str, files: dict[str, str], actual: dict[str, str], reasons: list[str]
) -> None:
    mismatched = sorted(k for k in set(files) & set(actual) if files[k] != actual[k])
    for label, names in (
        ("omits", sorted(set(actual) - set(files))),
        ("lists nonexistent", sorted(set(files) - set(actual))),
        ("pins wrong hashes for", mismatched),
    ):
        if names:
            reasons.append(
                f"{where} {label} {len(names)} file(s) of the source root, "
                f"first {names[:3]}"
            )


def _check_tree_inventory(
    files: object,
    where: str,
    required: tuple[str, ...] | None,
    actual: dict[str, str] | None,
    reasons: list[str],
) -> None:
    if not isinstance(files, dict) or not all(
        isinstance(k, str) and _is_hex64(v) for k, v in files.items()
    ):
        reasons.append(f"{where} must map paths to lowercase 64-hex SHA-256 digests")
        return
    if required is not None and set(files) != set(required):
        reasons.append(
            f"{where} must hold exactly {list(required)}, got {sorted(files)}"
        )
        return
    if actual is None:
        return
    if required is None:
        _compare_whole_tree(where, files, actual, reasons)
        return
    for rel in required:
        if actual.get(rel) != files[rel]:
            reasons.append(
                f"{where}[{rel!r}] {files[rel]!r} != file in source root "
                f"{actual.get(rel)!r}"
            )


def _check_inventory(
    inventory: object,
    name: str,
    required: tuple[str, ...] | None,
    derived: dict[str, dict[str, str]],
    reasons: list[str],
) -> None:
    """Exact per-tree path->hash map. `required` None means the whole tree."""
    where = f"registration: {name}"
    if not _exact_keys(inventory, TREES, where, reasons):
        return
    assert isinstance(inventory, dict)
    for tree in TREES:
        _check_tree_inventory(
            inventory[tree], f"{where}[{tree!r}]", required, derived.get(tree), reasons
        )
    if required is None:
        return
    for tree in TREES[1:]:
        if inventory[tree] != inventory["candidate"]:
            reasons.append(
                f"{where}[{tree!r}] differs from candidate: every tree must use "
                "identical harness sources and dependency tuples"
            )


def _check_frozen_identity(reg: dict[str, Any], reasons: list[str]) -> dict[str, Path]:
    roots: dict[str, Path] = {}
    raw_roots = reg["source_roots"]
    if not _exact_keys(raw_roots, TREES, "registration: source_roots", reasons):
        return roots
    for tree in TREES:
        value = raw_roots[tree]
        if (
            not isinstance(value, str)
            or not Path(value).is_absolute()
            or not Path(value).is_dir()
        ):
            reasons.append(
                f"registration: source_roots[{tree!r}] must be an absolute "
                f"existing directory, got {value!r}"
            )
        else:
            roots[tree] = Path(value).resolve()
    for first, second in itertools.combinations(roots, 2):
        a, b = roots[first], roots[second]
        if a == b or a in b.parents or b in a.parents:
            reasons.append(
                f"registration: source_roots {first!r} and {second!r} overlap"
            )
    derived: dict[str, dict[str, str]] = {}
    for tree, root in roots.items():
        files, problems = derive_source_files(root)
        derived[tree] = files
        reasons.extend(f"registration: source_roots[{tree!r}]: {p}" for p in problems)
    _check_inventory(
        reg["source_fingerprints"], "source_fingerprints", None, derived, reasons
    )
    _check_inventory(
        reg["bench_fingerprints"],
        "bench_fingerprints",
        BENCH_FINGERPRINT_FILES,
        derived,
        reasons,
    )
    _check_inventory(
        reg["lock_fingerprints"], "lock_fingerprints", LOCK_GRAPHS, derived, reasons
    )
    return roots


def _expected_binary_keys() -> tuple[str, ...]:
    keys: set[str] = set()
    for target, specs in PINNED_ROWS.items():
        for spec in specs:
            keys.add(f"candidate/{spec.bench}")
            keys.add(f"control_{target}/{spec.bench}")
    return tuple(sorted(keys))


def _check_receipt(
    reg: dict[str, Any], key: str, binary_sha: str, path: Path, reasons: list[str]
) -> None:
    tree, bench = key.split("/", 1)
    where = f"registration: binaries[{key!r}].receipt"
    doc = _load_json_object(path, where, reasons)
    if doc is None:
        return
    bench_files = reg["bench_fingerprints"]
    bench_sha = None
    if isinstance(bench_files, dict) and isinstance(bench_files.get(tree), dict):
        bench_sha = bench_files[tree].get(BENCH_SOURCES[bench])
    expected = {
        "kind": RECEIPT_KIND,
        "tree": tree,
        "bench_target": bench,
        "source_digest": _tree_digest(reg, "source_fingerprints", tree),
        "bench_source_sha256": bench_sha,
        "lock_digest": _tree_digest(reg, "lock_fingerprints", tree),
        "binary_sha256": binary_sha,
    }
    wrong = [
        field for field, want in expected.items() if not _same(doc.get(field), want)
    ]
    if wrong:
        reasons.append(
            f"{where}: field(s) {wrong} do not match the registered "
            "tree/bench-target/source/lock/binary identity"
        )
    _check_receipt_provenance(tree, doc, where, reasons)


def _check_receipt_provenance(
    tree: str, doc: dict[str, Any], where: str, reasons: list[str]
) -> None:
    """External source-commit provenance; content hashes stay authoritative.

    Frozen trees remain source-only with no .git; provenance lives here, not
    in the trees. Candidate (exact export) carries source_commit. Derived
    controls carry base_commit plus a nonempty transform derivation string
    and must never claim source_commit for transformed contents.
    """
    src = doc.get("source_commit")
    base = doc.get("base_commit")
    transform = doc.get("transform")
    if tree == "candidate":
        if not _is_commit_hex(src):
            reasons.append(
                f"{where}: source_commit must be lowercase 40- or 64-hex "
                f"git commit, got {src!r}"
            )
        if base is not None or transform is not None:
            reasons.append(
                f"{where}: candidate receipt must not carry "
                "base_commit/transform (exact export, not derived)"
            )
        return
    if src is not None:
        reasons.append(
            f"{where}: control receipt must not claim source_commit {src!r} "
            "for transformed contents; use base_commit plus transform"
        )
    if not _is_commit_hex(base):
        reasons.append(
            f"{where}: base_commit must be lowercase 40- or 64-hex git commit, "
            f"got {base!r}"
        )
    if not isinstance(transform, str) or not transform.strip():
        reasons.append(
            f"{where}: transform must be a nonempty single-lever derivation "
            f"string, got {transform!r}"
        )


def _check_provenance_consistency(
    receipt_docs: dict[str, dict[str, Any]], reasons: list[str]
) -> None:
    """Candidate source versus control base agreement across one registration."""
    candidates = sorted(k for k in receipt_docs if k.startswith("candidate/"))
    if not candidates:
        return
    commits = {str(receipt_docs[k].get("source_commit")) for k in candidates}
    if len(commits) != 1 or not _is_commit_hex(next(iter(commits))):
        reasons.append(
            "registration: candidate receipts disagree on source_commit; "
            "every candidate binary shares one exact source tree"
        )
        return
    candidate_commit = next(iter(commits))
    seen_transforms: dict[str, str] = {}
    for key in sorted(receipt_docs):
        if key.startswith("candidate/"):
            continue
        tree = key.split("/", 1)[0]
        doc = receipt_docs[key]
        if doc.get("base_commit") != candidate_commit:
            reasons.append(
                f"registration: binaries[{key!r}].receipt base_commit "
                f"{doc.get('base_commit')!r} != candidate source_commit "
                f"{candidate_commit!r}; controls derive from the candidate base"
            )
        transform = doc.get("transform")
        if isinstance(transform, str) and transform.strip():
            if tree in seen_transforms and seen_transforms[tree] != transform:
                reasons.append(
                    f"registration: binaries[{key!r}].receipt transform "
                    "disagrees within one control tree"
                )
            seen_transforms.setdefault(tree, transform)
    transforms = sorted(set(seen_transforms.values()))
    if len(transforms) != len(seen_transforms):
        reasons.append(
            "registration: control transforms must be distinct per control tree; "
            "identical derivations confound single-lever attribution"
        )


def _check_binaries(
    reg: dict[str, Any], roots: dict[str, Path], reasons: list[str]
) -> dict[str, str]:
    """Verify every pinned executable and its build receipt; return key->sha256."""
    shas: dict[str, str] = {}
    binaries = reg["binaries"]
    want = _expected_binary_keys()
    where = "registration: binaries"
    if not _exact_keys(binaries, want, where, reasons):
        return shas
    assert isinstance(binaries, dict)
    seen: dict[Path, str] = {}
    for key in want:
        bwhere = f"{where}[{key!r}]"
        path = _check_pinned_file(binaries[key], ("receipt",), bwhere, reasons)
        if path is None:
            continue
        if not os.access(path, os.X_OK):
            reasons.append(f"{bwhere}.path is not executable: {path}")
        if not _outside_roots(path, roots):
            reasons.append(f"{bwhere}.path lies inside a source root: {path}")
        if path in seen:
            reasons.append(
                f"{bwhere}.path is the same file as binaries[{seen[path]!r}]"
            )
        seen[path] = key
        entry = binaries[key]
        shas[key] = entry["sha256"]
        receipt = _check_pinned_file(entry["receipt"], (), f"{bwhere}.receipt", reasons)
        if receipt is None:
            continue
        if not _outside_roots(receipt, roots):
            reasons.append(f"{bwhere}.receipt lies inside a source root: {receipt}")
        if receipt in seen:
            reasons.append(
                f"{bwhere}.receipt is the same file as binaries[{seen[receipt]!r}]"
            )
        seen[receipt] = key
        _check_receipt(reg, key, entry["sha256"], receipt, reasons)
    _check_all_receipt_provenance(reg, reasons)
    return shas


def _check_all_receipt_provenance(reg: dict[str, Any], reasons: list[str]) -> None:
    binaries = reg.get("binaries")
    if not isinstance(binaries, dict):
        return
    docs: dict[str, dict[str, Any]] = {}
    for key, entry in binaries.items():
        if not isinstance(entry, dict):
            continue
        receipt = entry.get("receipt")
        if not isinstance(receipt, dict):
            continue
        raw_path = receipt.get("path")
        if not isinstance(raw_path, str):
            continue
        path = Path(raw_path)
        if not path.is_file():
            continue
        try:
            doc: object = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(doc, dict):
            docs[str(key)] = doc
    if docs:
        _check_provenance_consistency(docs, reasons)


def _check_gated_executables(shas: dict[str, str], reasons: list[str]) -> None:
    """Gated executables sharing one bench must be pairwise distinct."""
    reported: set[tuple[str, str]] = set()
    for target, specs in PINNED_ROWS.items():
        for spec in specs:
            cand = shas.get(f"candidate/{spec.bench}")
            ctrl = shas.get(f"control_{target}/{spec.bench}")
            if (
                spec.role in GATED_ROLES
                and cand is not None
                and cand == ctrl
                and (target, spec.bench) not in reported
            ):
                reported.add((target, spec.bench))
                reasons.append(
                    f"registration: gated target {target} bench {spec.bench}: "
                    "candidate and control executables are identical "
                    "(zero-delta control)"
                )
    gated_per_bench: dict[str, list[str]] = {}
    for target, specs in PINNED_ROWS.items():
        for spec in specs:
            if spec.role in GATED_ROLES:
                for key in (
                    f"candidate/{spec.bench}",
                    f"control_{target}/{spec.bench}",
                ):
                    if key not in gated_per_bench.setdefault(spec.bench, []):
                        gated_per_bench[spec.bench].append(key)
    for bench in sorted(gated_per_bench):
        _check_gated_bench(bench, gated_per_bench[bench], shas, reported, reasons)


def _check_gated_bench(
    bench: str,
    keys: list[str],
    shas: dict[str, str],
    reported: set[tuple[str, str]],
    reasons: list[str],
) -> None:
    """One bench's gated keys must all hash differently."""
    seen_sha: dict[str, str] = {}
    for key in keys:
        sha = shas.get(key)
        if sha is None or sha not in seen_sha:
            if sha is not None:
                seen_sha[sha] = key
            continue
        if _already_reported_pair(bench, seen_sha[sha], key, reported):
            continue
        reasons.append(
            f"registration: gated bench {bench}: executables for "
            f"{seen_sha[sha]!r} and {key!r} are not distinct "
            "(identical gated hash; every gated control needs "
            "its own build)"
        )


def _already_reported_pair(
    bench: str, first: str, second: str, reported: set[tuple[str, str]]
) -> bool:
    """True when a candidate/control duplicate already has its own reason."""
    pair = {first, second}
    if len(pair) != 2 or f"candidate/{bench}" not in pair:
        return False
    other = (pair - {f"candidate/{bench}"}).pop()
    if not other.startswith("control_"):
        return False
    return (other[len("control_") :], bench) in reported


def _check_source_tree_distinctness(reg: dict[str, Any], reasons: list[str]) -> None:
    """All five full source-tree digests must be pairwise distinct."""
    digests: dict[str, str | None] = {
        tree: _tree_digest(reg, "source_fingerprints", tree) for tree in TREES
    }
    if any(digest is None for digest in digests.values()):
        return
    seen: dict[str, str] = {}
    for tree in TREES:
        digest = digests[tree]
        if digest is None:
            continue
        if digest in seen:
            reasons.append(
                f"registration: source_fingerprints {seen[digest]!r} and "
                f"{tree!r} are not distinct (identical full source digest; "
                "every tree is a single-lever build)"
            )
        else:
            seen[digest] = tree


def _check_evidence(
    reg: dict[str, Any], key: str, role: str, reasons: list[str]
) -> None:
    entries = reg[key]
    where = f"registration: {key}"
    if not isinstance(entries, list) or not entries:
        reasons.append(f"{where} must be a nonempty list of {{path, sha256}}")
        return
    identity: dict[str, Any] = {
        "trees": {
            tree: _tree_digest(
                reg,
                "source_fingerprints" if role == "source" else "lock_fingerprints",
                tree,
            )
            for tree in TREES
        }
    }
    if role == "source":
        scripts = reg.get("scripts")
        identity["scripts"] = {
            name: scripts[name].get("sha256")
            if isinstance(scripts, dict) and isinstance(scripts.get(name), dict)
            else None
            for name in ("runner", "analyzer")
        }
    expected = {
        "kind": EVIDENCE_KIND,
        "role": role,
        "result": "passed",
        "frozen_identity": identity,
    }
    seen: set[Path] = set()
    for idx, entry in enumerate(entries):
        ewhere = f"{where}[{idx}]"
        path = _check_pinned_file(entry, (), ewhere, reasons)
        if path is None:
            continue
        if path in seen:
            reasons.append(f"{ewhere}: {path} listed twice")
        seen.add(path)
        doc = _load_json_object(path, ewhere, reasons)
        if doc is None:
            continue
        wrong = [
            field for field, want in expected.items() if not _same(doc.get(field), want)
        ]
        if wrong:
            reasons.append(
                f"{ewhere}: field(s) {wrong} are not a passed {role} baseline "
                "bound to the registered frozen identity"
            )


def _check_corpus(corpus: object, reasons: list[str]) -> None:
    if not _exact_keys(corpus, CORPUS_FIELDS, "registration: corpus", reasons):
        return
    assert isinstance(corpus, dict)
    for field in CORPUS_FIELDS:
        value = corpus[field]
        if type(value) is not int or value < 0:
            reasons.append(
                f"registration: corpus[{field!r}] must be a non-negative int, "
                f"got {value!r}"
            )


def _check_identity_field(
    where: str, field: str, value: object, reasons: list[str]
) -> None:
    if field == "tips":
        want_len = WARMUP_SAMPLES + MEASURED_SAMPLES
        if not (
            isinstance(value, list)
            and len(value) == want_len
            and all(map(_is_hex64, value))
            and len(set(value)) == want_len
        ):
            reasons.append(
                f"{where}.tips must be exactly {want_len} distinct lowercase "
                "64-hex tips (one per sample index; each sample connects its "
                f"own target block), got {value!r}"
            )
    elif field == "tip":
        if not _is_hex64(value):
            reasons.append(
                f"{where}.tip must be a lowercase 64-hex prefix tip (the tip "
                f"never connects), got {value!r}"
            )
    elif type(value) is not int or value < 0:
        reasons.append(f"{where}[{field!r}] must be a non-negative int, got {value!r}")


def _check_node_identity(node_identity: object, reasons: list[str]) -> None:
    where = "registration: node_identity"
    if not _exact_keys(node_identity, NODE_BENCHES, where, reasons):
        return
    assert isinstance(node_identity, dict)
    for bench, pins in (
        ("block_to_template_baseline", ("tips", *T2_IDENTITY_INTS)),
        ("template_render_baseline", ("tip", "tip_height", *T3_IDENTITY_INTS)),
    ):
        ident = node_identity[bench]
        iwhere = f"{where}[{bench!r}]"
        if not _exact_keys(ident, ("engine", *pins), iwhere, reasons):
            continue
        assert isinstance(ident, dict)
        if ident["engine"] != NATIVE_ENGINE:
            reasons.append(
                f"{iwhere}.engine must be exactly {NATIVE_ENGINE!r}, "
                f"got {ident['engine']!r}"
            )
        for field in pins:
            _check_identity_field(iwhere, field, ident[field], reasons)


def _check_row_fields(
    where: str, row: dict[str, Any], want: dict[str, Any], reasons: list[str]
) -> None:
    for field in sorted(set(want) | set(row)):
        if field not in want:
            reasons.append(f"{where} row {want['id']!r}: unrecognized key {field!r}")
        elif field not in row:
            reasons.append(f"{where} row {want['id']!r}: missing key {field!r}")
        elif not _same(row[field], want[field]):
            reasons.append(
                f"{where} row {want['id']!r}: {field} is {row[field]!r}, "
                f"pinned {want[field]!r}"
            )


def _check_rows(
    where: str, rows: list[Any], expected: list[dict[str, Any]], reasons: list[str]
) -> None:
    want_ids = [e["id"] for e in expected]
    got_ids = [r.get("id") if isinstance(r, dict) else None for r in rows]
    omitted = [i for i in want_ids if i not in got_ids]
    extra = [i for i in got_ids if i not in want_ids]
    dupes = sorted({str(i) for i in got_ids if got_ids.count(i) > 1})
    if omitted:
        reasons.append(f"{where}.rows omits mandatory row(s) {omitted}")
    if extra:
        reasons.append(f"{where}.rows registers unpinned row(s) {extra}")
    if dupes:
        reasons.append(f"{where}.rows duplicates row id(s) {dupes}")
    if not (omitted or extra or dupes) and got_ids != want_ids:
        reasons.append(f"{where}.rows must keep the pinned execution order")
    by_id = {
        r["id"]: r for r in rows if isinstance(r, dict) and r.get("id") in want_ids
    }
    for want in expected:
        if want["id"] in by_id:
            _check_row_fields(where, by_id[want["id"]], want, reasons)


def _check_targets(targets: object, reasons: list[str]) -> None:
    if not _exact_keys(targets, TARGET_ORDER, "registration: targets", reasons):
        return
    assert isinstance(targets, dict)
    for target in TARGET_ORDER:
        where = f"registration: targets[{target}]"
        spec = targets[target]
        if not _exact_keys(spec, ("control_tree", "rows"), where, reasons):
            continue
        assert isinstance(spec, dict)
        if spec["control_tree"] != f"control_{target}":
            reasons.append(
                f"{where}.control_tree must be exactly 'control_{target}' "
                f"(one single-lever control per target), got {spec['control_tree']!r}"
            )
        if not isinstance(spec["rows"], list):
            reasons.append(f"{where}.rows must be a list")
            continue
        expected = [expected_row(target, s) for s in PINNED_ROWS[target]]
        _check_rows(where, spec["rows"], expected, reasons)


def validate_registration(reg: object, check_output_absent: bool = True) -> list[str]:
    """The static full-schema registration validator (runner and analyzer).

    Verifies everything it can against the real files without querying the
    caller's own process affinity; it cannot prove that any process ran.
    """
    if not isinstance(reg, dict):
        return ["registration root must be a JSON object"]
    reasons: list[str] = []
    if not _exact_keys(reg, REGISTRATION_KEYS, "registration", reasons):
        return reasons
    _check_run_settings(reg, check_output_absent, reasons)
    _check_scripts(reg, reasons)
    roots = _check_frozen_identity(reg, reasons)
    _check_source_tree_distinctness(reg, reasons)
    campaign_root = reg["campaign_root"]
    if isinstance(campaign_root, str) and not _outside_roots(
        Path(campaign_root).resolve(), roots
    ):
        reasons.append("registration: campaign_root lies inside a source root")
    shas = _check_binaries(reg, roots, reasons)
    _check_gated_executables(shas, reasons)
    _check_evidence(reg, "source_baseline_evidence", "source", reasons)
    _check_evidence(reg, "dependency_baseline_evidence", "dependency", reasons)
    _check_corpus(reg["corpus"], reasons)
    _check_node_identity(reg["node_identity"], reasons)
    _check_targets(reg["targets"], reasons)
    _validate_schedule(reg, reasons)
    return reasons


def _validate_schedule(reg: dict[str, Any], reasons: list[str]) -> None:
    sched = reg.get("schedule")
    if not isinstance(sched, dict):
        reasons.append("registration: schedule must be an object")
        return
    if sched.get("target_order") != list(TARGET_ORDER):
        reasons.append(
            "registration: schedule.target_order must be "
            f"{list(TARGET_ORDER)} (T1->T4 serialized), "
            f"got {sched.get('target_order')!r}"
        )
    blocks = sched.get("blocks")
    expected: list[dict[str, str]] = []
    for target in TARGET_ORDER:
        expected.append({"target": target, "kind": "zero"})
        for _ in range(3):
            expected.append({"target": target, "kind": "measure"})
    if blocks != expected:
        reasons.append(
            "registration: schedule.blocks must be, per target in T1->T4 order, "
            "one zero block then three measure blocks "
            f"(got {blocks!r})"
        )


def derive_cases(reg: dict[str, Any]) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    case_index = 0
    for target in TARGET_ORDER:
        rows: list[dict[str, Any]] = reg["targets"][target]["rows"]
        for block in range(BLOCKS_PER_TARGET):
            kind = "zero" if block == 0 else "measure"
            visits = ZERO_VISITS if block == 0 else MEASURE_VISITS
            for visit_in_block, arm in enumerate(visits):
                visit_index = block * 4 + visit_in_block
                for row in rows:
                    binary_key = (
                        row["candidate_binary"]
                        if arm in ("candidate", "zero")
                        else row["control_binary"]
                    )
                    cases.append(
                        {
                            "case_index": case_index,
                            "target": target,
                            "block": block,
                            "block_kind": kind,
                            "visit_index": visit_index,
                            "arm": arm,
                            "binary_key": binary_key,
                            "row": row,
                        }
                    )
                    case_index += 1
    return cases


def _sanitize_row(row_id: str) -> str:
    return "".join(c if (c.isalnum() or c in ("-", "_", ".")) else "_" for c in row_id)


def validate_criterion_sample(
    path: Path, expected_samples: int, units_per_iter: int
) -> tuple[list[float], list[float], list[float], float, float]:
    try:
        data: object = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RegistrationError(f"{path}: cannot read sample.json: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise RegistrationError(
            f"{path}: sample.json is not valid JSON: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise RegistrationError(f"{path}: sample.json root must be an object")
    iters_raw = data.get("iters")
    times_raw = data.get("times")
    if not isinstance(iters_raw, list) or not isinstance(times_raw, list):
        raise RegistrationError(f"{path}: 'iters' and 'times' must be lists")
    if len(iters_raw) != expected_samples or len(times_raw) != expected_samples:
        raise RegistrationError(
            f"{path}: expected exactly {expected_samples} iters and times entries, "
            f"got {len(iters_raw)} and {len(times_raw)}"
        )
    iters: list[float] = []
    for idx, item in enumerate(iters_raw):
        if not _is_positive_finite(item):
            raise RegistrationError(f"{path}: iters[{idx}] must be finite positive")
        iters.append(float(item))  # type: ignore[arg-type]
    times: list[float] = []
    for idx, item in enumerate(times_raw):
        if not _is_positive_finite(item):
            raise RegistrationError(f"{path}: times[{idx}] must be finite positive")
        value = float(item)  # type: ignore[arg-type]
        if value < MIN_CRITERION_NS:
            raise RegistrationError(
                f"{path}: times[{idx}] = {value} ns is below the 1 s minimum "
                "raw-interval rule; record INCONCLUSIVE, do not retry"
            )
        times.append(value)
    normalized = [t / i / float(units_per_iter) for t, i in zip(times, iters)]
    median = float(statistics.median(normalized))
    std = float(statistics.stdev(normalized)) if len(normalized) >= 2 else 0.0
    return iters, times, normalized, median, std


def find_single_sample_json(criterion_home: Path) -> Path:
    found = sorted(criterion_home.glob("**/new/sample.json"))
    if len(found) != 1:
        raise RegistrationError(
            f"expected exactly one new/sample.json under {criterion_home}, "
            f"found {[str(p) for p in found]}"
        )
    return found[0]


class CountedFields(TypedDict):
    """Validated counted record fields for one case."""

    counted_stdout_path: str
    counted_warmups_seen: int
    counted_warmup_samples: list[dict[str, Any]]
    counted_samples: list[dict[str, Any]]
    sample_iters: list[float]
    sample_times_ns: list[float]
    normalized_ns: list[float]
    case_median_ns: float
    case_std_ns: float


def _check_counted_object(
    obj: dict[str, Any], row_id: str, where: str, expect_warmup: bool
) -> None:
    """Exact-key/type/sum/floor validation of one raw counted sample object."""
    missing = [key for key in COUNTED_SAMPLE_KEYS if key not in obj]
    unknown = sorted(set(obj) - set(COUNTED_SAMPLE_KEYS))
    if missing:
        raise RegistrationError(f"{where}: counted sample missing key(s) {missing}")
    if unknown:
        raise RegistrationError(f"{where}: counted sample unknown field(s) {unknown}")
    sample = obj["sample"]
    if type(sample) is not int or not 0 <= sample <= MEASURED_SAMPLES:
        raise RegistrationError(
            f"{where}: counted sample index must be an int in "
            f"0..{MEASURED_SAMPLES}, got {sample!r}"
        )
    if obj["bench"] != row_id:
        raise RegistrationError(
            f"{where}: counted sample {sample} bench {obj['bench']!r} != row {row_id!r}"
        )
    if not isinstance(obj["warmup"], bool):
        raise RegistrationError(
            f"{where}: counted sample {sample}: warmup must be a bool"
        )
    if expect_warmup:
        if sample != 0 or obj["warmup"] is not True:
            raise RegistrationError(
                f"{where}: counted warmup must be sample 0 with warmup=true, "
                f"got sample={sample!r} warmup={obj['warmup']!r}"
            )
    elif sample == 0 or obj["warmup"] is not False:
        raise RegistrationError(
            f"{where}: counted sample {sample}: measured samples must carry "
            "warmup=false and a nonzero sample index"
        )
    units = obj["unit_ns"]
    if not isinstance(units, list) or not units:
        raise RegistrationError(
            f"{where}: counted sample {sample}: unit_ns must be a nonempty list"
        )
    for entry in units:
        if type(entry) is not int or entry < 0 or entry > U64_MAX:
            raise RegistrationError(
                f"{where}: counted sample {sample}: unit_ns entries must be "
                "nonnegative u64 ints (zero is legal, never clamped)"
            )
    if type(obj["unit_count"]) is not int or obj["unit_count"] != len(units):
        raise RegistrationError(
            f"{where}: counted sample {sample}: unit_count {obj['unit_count']!r} "
            f"must equal len(unit_ns) ({len(units)})"
        )
    total = obj["total_ns"]
    if type(total) is not int or total != sum(units) or total > U64_MAX:
        raise RegistrationError(
            f"{where}: counted sample {sample}: total_ns {total!r} must equal "
            f"sum(unit_ns) exactly ({sum(units)}) and fit u64"
        )
    if total < COUNTED_FLOOR_NS:
        raise RegistrationError(
            f"{where}: counted sample {sample}: total_ns {total} is below the 1 s "
            f"measured-work floor ({COUNTED_FLOOR_NS} ns); warmup included"
        )
    # First-crossing stop rule: the sampler accumulates only while every
    # completed prefix sum stays below the floor, so sum(unit_ns[:-1]) --
    # the exact total minus the last unit -- must be strictly below it.
    # total >= floor above and the nonempty-unit check guarantee the final
    # unit is the crossing one.
    if total - units[-1] >= COUNTED_FLOOR_NS:
        raise RegistrationError(
            f"{where}: counted sample {sample}: reached the "
            f"{COUNTED_FLOOR_NS} ns floor before its final unit (sum of all "
            f"but the last unit is {total - units[-1]} ns); the sampler "
            "stops at the first whole unit reaching the floor, so "
            "over-collected units are invalid"
        )


def validate_counted_samples(
    warmups: list[dict[str, Any]],
    samples: list[dict[str, Any]],
    row_id: str,
    where: str | None = None,
) -> tuple[list[float], list[float], list[float], float, float]:
    """The one authoritative counted validator (runner and analyzer).

    Validates the retained raw objects -- exactly one warmup plus ten
    measured samples, exact MRP_COUNTED_SAMPLE keys, row identity, nonneg
    u64 unit_ns array, count == len(unit_ns), total_ns == exact sum, and the
    1 s floor on every sample including the warmup -- and derives the
    neutral numeric arrays and statistics: sample_iters from unit_count,
    sample_times_ns from total_ns, normalized_ns as the exact float
    total_ns/unit_count (units_per_iter is 1), plus median and sample stdev.
    Returns (sample_iters, sample_times_ns, normalized_ns, median, std).
    """
    label = where if where is not None else row_id
    if (
        not isinstance(warmups, list)
        or len(warmups) != 1
        or not all(isinstance(w, dict) for w in warmups)
    ):
        got = len(warmups) if isinstance(warmups, list) else type(warmups).__name__
        raise RegistrationError(
            f"{label}: counted row {row_id!r} must retain exactly 1 raw warmup "
            f"sample object, got {got}"
        )
    if (
        not isinstance(samples, list)
        or len(samples) != MEASURED_SAMPLES
        or not all(isinstance(s, dict) for s in samples)
    ):
        got = len(samples) if isinstance(samples, list) else type(samples).__name__
        raise RegistrationError(
            f"{label}: counted row {row_id!r} must retain exactly "
            f"{MEASURED_SAMPLES} raw measured sample objects, got {got}"
        )
    _check_counted_object(warmups[0], row_id, label, expect_warmup=True)
    indices: list[int] = []
    for obj in samples:
        _check_counted_object(obj, row_id, label, expect_warmup=False)
        indices.append(obj["sample"])
    if indices != list(range(1, MEASURED_SAMPLES + 1)):
        raise RegistrationError(
            f"{label}: counted row {row_id!r} measured sample indices must be "
            f"1..{MEASURED_SAMPLES} in order, got {indices}"
        )
    iters = [float(obj["unit_count"]) for obj in samples]
    times = [float(obj["total_ns"]) for obj in samples]
    normalized = [obj["total_ns"] / obj["unit_count"] for obj in samples]
    median = float(statistics.median(normalized))
    std = float(statistics.stdev(normalized)) if len(normalized) >= 2 else 0.0
    return iters, times, normalized, median, std


def parse_counted_stdout(
    stdout_path: Path, row_id: str
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Raw counted sample objects from one stdout log (warmups, measured).

    Sample lines are ``MRP_COUNTED_SAMPLE`` + one ASCII space + one JSON
    object; auxiliary diagnostics on other lines are ignored. The stream
    must be the warmup (sample 0) followed by measured samples 1..10 in
    order; malformed prefixed lines, wrong rows, duplicates, unknown fields,
    inconsistent counts/totals and sub-floor intervals (warmup included) are
    rejected via validate_counted_samples().
    """
    try:
        text = stdout_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RegistrationError(
            f"{stdout_path}: cannot read counted stdout: {exc}"
        ) from exc
    objs: list[dict[str, Any]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.startswith("MRP_COUNTED_SAMPLE"):
            continue
        if not line.startswith(COUNTED_SAMPLE_PREFIX):
            raise RegistrationError(
                f"{stdout_path}: line {lineno}: malformed MRP_COUNTED_SAMPLE line "
                "(prefix must be followed by one ASCII space)"
            )
        payload = line[len(COUNTED_SAMPLE_PREFIX) :]
        try:
            obj: object = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise RegistrationError(
                f"{stdout_path}: line {lineno}: malformed MRP_COUNTED_SAMPLE "
                f"JSON: {exc}"
            ) from exc
        if not isinstance(obj, dict):
            raise RegistrationError(
                f"{stdout_path}: line {lineno}: MRP_COUNTED_SAMPLE payload is "
                "not a JSON object"
            )
        objs.append(obj)
    if not objs:
        raise RegistrationError(
            f"{stdout_path}: no MRP_COUNTED_SAMPLE lines found for row {row_id!r}"
        )
    indices = [obj.get("sample") for obj in objs]
    if indices != list(range(MEASURED_SAMPLES + 1)):
        raise RegistrationError(
            f"{stdout_path}: counted sample stream must be warmup 0 then "
            f"measured 1..{MEASURED_SAMPLES} in order, got {indices}"
        )
    warmups = [objs[0]]
    measured = objs[1:]
    validate_counted_samples(warmups, measured, row_id, where=str(stdout_path))
    return warmups, measured


def counted_case_fields(stdout_path: Path, row: dict[str, Any]) -> CountedFields:
    """Validated raw counted data of one case (the runner's only counted parser)."""
    row_id = str(row["id"])
    warmups, measured = parse_counted_stdout(stdout_path, row_id)
    iters, times, normalized, median, std = validate_counted_samples(
        warmups, measured, row_id
    )
    return {
        "counted_stdout_path": str(stdout_path),
        "counted_warmups_seen": len(warmups),
        "counted_warmup_samples": [dict(w) for w in warmups],
        "counted_samples": [dict(s) for s in measured],
        "sample_iters": iters,
        "sample_times_ns": times,
        "normalized_ns": normalized,
        "case_median_ns": median,
        "case_std_ns": std,
    }


class NodeArmGroup(TypedDict):
    units: list[int]
    count: int
    total: int
    mean: float


class NodeSample(TypedDict):
    sample: int
    warmup: bool
    engine: str
    tip: str
    arms: dict[str, NodeArmGroup]
    components: dict[str, list[int]]
    identity: dict[str, str | int | bool]


def _narrow_sample_lines(
    text: str, node_bench: str, where: str
) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for lineno, line in enumerate(text.splitlines()):
        stripped = line.strip()
        if not stripped.startswith("{"):
            continue
        try:
            obj: object = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        if not all(k in obj for k in ("bench", "sample", "warmup")):
            continue
        if obj["bench"] != node_bench:
            raise RegistrationError(
                f"{where}: line {lineno} bench {obj['bench']!r} "
                f"is not the registered {node_bench!r}"
            )
        if not isinstance(obj["warmup"], bool):
            raise RegistrationError(f"{where}: line {lineno} warmup must be a bool")
        if type(obj["sample"]) is not int:
            raise RegistrationError(f"{where}: line {lineno} sample must be an int")
        found.append(obj)
    if not found:
        raise RegistrationError(f"{where}: no node sample lines on stdout")
    return found


_CORPUS_RE = re.compile(
    r"block_to_template corpus:\s*"
    r"prefix_blocks=(\d+)\s+"
    r"tip_height=(\d+)\s+"
    r"funded_outputs=(\d+)\s+"
    r"background=(\d+)\s+"
    r"targets=(\d+)x(\d+)\s+"
    r"total_txs_per_target=(\d+)"
)


def _parse_corpus_identity(text: str, where: str) -> dict[str, int]:
    matches = _CORPUS_RE.findall(text)
    if len(matches) != 1:
        raise RegistrationError(
            f"{where}: expected exactly one corpus identity line "
            f"('block_to_template corpus: ...'), found {len(matches)}"
        )
    groups = [int(g) for g in matches[0]]
    return {
        "prefix_blocks": groups[0],
        "tip_height": groups[1],
        "funded_outputs": groups[2],
        "background": groups[3],
        "targets": groups[4],
        "target_spends": groups[5],
        "total_txs_per_target": groups[6],
    }


def _check_corpus_pinned(
    seen: dict[str, int], pinned: dict[str, Any], where: str
) -> None:
    for field in CORPUS_FIELDS:
        want = pinned.get(field)
        if type(want) is not int:
            raise RegistrationError(
                f"{where}: pinned corpus[{field!r}] must be an int, got {want!r}"
            )
        if seen[field] != want:
            raise RegistrationError(
                f"{where}: corpus {field} {seen[field]} != pinned {want}"
            )


def _check_sample_identity(
    obj: dict[str, Any],
    ident: dict[str, Any],
    fields: tuple[str, ...],
    where: str,
    what: str,
) -> None:
    if not isinstance(ident.get("engine"), str) or not ident["engine"]:
        raise RegistrationError(f"{where}: pinned engine for {what} is missing")
    engine = obj.get("engine")
    if engine != ident["engine"]:
        raise RegistrationError(
            f"{where}: {what} engine {engine!r} != pinned {ident['engine']!r}"
        )
    for field in fields:
        want = ident.get(field)
        if type(want) is not int:
            raise RegistrationError(
                f"{where}: pinned identity {what}[{field!r}] must be an int, "
                f"got {want!r}"
            )
        got = obj.get(field)
        if type(got) is not int or got != want:
            raise RegistrationError(
                f"{where}: {what} {field} {got!r} != pinned {want!r}"
            )


def _narrow_arm_group(
    obj: dict[str, Any], keys: tuple[str, str, str], where: str, what: str
) -> NodeArmGroup:
    units_key, count_key, total_key = keys
    units = obj.get(units_key)
    count = obj.get(count_key)
    total = obj.get(total_key)
    if not isinstance(units, list) or not units:
        raise RegistrationError(f"{where}: {what} {units_key} must be a nonempty list")
    for entry in units:
        if type(entry) is not int or entry < 0:
            raise RegistrationError(
                f"{where}: {what} {units_key} entries must be nonnegative ints "
                "(zero is clock quantization, never clamped)"
            )
    if type(count) is not int or count != len(units):
        raise RegistrationError(
            f"{where}: {what} {count_key} must equal len({units_key})"
        )
    if type(total) is not int or total != sum(units):
        raise RegistrationError(
            f"{where}: {what} {total_key} must equal sum({units_key}) exactly"
        )
    if total <= 0:
        raise RegistrationError(
            f"{where}: {what} {total_key} must be positive (nonzero count "
            "with positive total required)"
        )
    for key in obj:
        if key == "mean" or key.endswith("_mean_us") or key.endswith("_mean_ns"):
            raise RegistrationError(
                f"{where}: {what} must not carry redundant mean field {key!r}; "
                "means are derived as total/count"
            )
    return {"units": units, "count": count, "total": total, "mean": total / len(units)}


def _base_node_sample(
    obj: dict[str, Any],
    where: str,
    arms: dict[str, NodeArmGroup],
    components: dict[str, list[int]],
    identity: dict[str, str | int | bool],
) -> NodeSample:
    engine = obj.get("engine")
    tip = obj.get("tip")
    if not isinstance(engine, str) or not engine:
        raise RegistrationError(f"{where}: sample engine must be a nonempty string")
    if not isinstance(tip, str) or not tip:
        raise RegistrationError(f"{where}: sample tip must be a nonempty string")
    return {
        "sample": obj["sample"],
        "warmup": obj["warmup"],
        "engine": engine,
        "tip": tip,
        "arms": arms,
        "components": components,
        "identity": identity,
    }


T2_IDENTITY_INTS: tuple[str, ...] = (
    "pool_txs",
    "background_txs",
    "pool_at_template",
    "block_txs",
    "block_noncoinbase",
)
T3_IDENTITY_INTS: tuple[str, ...] = (
    "pool_txs",
    "background_txs",
    "pool_at_template",
)


def _narrow_t2_sample(
    obj: dict[str, Any], where: str, ident: dict[str, Any]
) -> NodeSample:
    for old in ("unit_us", "total_us", "mean_us"):
        if old in obj:
            raise RegistrationError(
                f"{where}: tail must use unit_ns/unit_count/total_ns "
                f"(ns schema); found legacy {old!r}"
            )
    _check_sample_identity(obj, ident, T2_IDENTITY_INTS, where, "tail")
    tips = ident.get("tips")
    sample_idx = obj.get("sample")
    if not isinstance(tips, list) or not isinstance(sample_idx, int):
        raise RegistrationError(
            f"{where}: pinned tips list and integer sample index required "
            "to check the T2 tip"
        )
    if sample_idx < 0 or sample_idx >= len(tips):
        raise RegistrationError(
            f"{where}: sample index {sample_idx!r} outside pinned tips "
            f"(len {len(tips)})"
        )
    want_tip = tips[sample_idx]
    if not isinstance(want_tip, str) or not want_tip:
        raise RegistrationError(f"{where}: pinned tips[{sample_idx}] is not usable")
    tip = obj.get("tip")
    if tip != want_tip:
        raise RegistrationError(
            f"{where}: sample {sample_idx} tip {tip!r} != pinned "
            f"tips[{sample_idx}] {want_tip!r} (each sample connects its own "
            "distinct target block)"
        )
    group = _narrow_arm_group(obj, ("unit_ns", "unit_count", "total_ns"), where, "tail")
    components: dict[str, list[int]] = {}
    for field in T2_COMPONENT_FIELDS:
        arr = obj.get(field)
        if not isinstance(arr, list) or len(arr) != group["count"]:
            raise RegistrationError(
                f"{where}: {field} must be a list of len == unit_count"
            )
        for value in arr:
            if type(value) is not int or value < 0:
                raise RegistrationError(
                    f"{where}: {field} entries must be nonnegative ints"
                )
        components[field] = arr
    boundary = obj.get("boundary")
    if not isinstance(boundary, str) or not boundary:
        raise RegistrationError(f"{where}: boundary must be a nonempty string")
    identity: dict[str, str | int | bool] = {
        "engine": obj["engine"],
        "tip": obj["tip"],
        "pool_txs": obj["pool_txs"],
        "background_txs": obj["background_txs"],
        "pool_at_template": obj["pool_at_template"],
        "block_txs": obj["block_txs"],
        "block_noncoinbase": obj["block_noncoinbase"],
        "boundary": boundary,
    }
    return _base_node_sample(obj, where, {"tail_to_reply": group}, components, identity)


def _narrow_t3_sample(
    obj: dict[str, Any], where: str, ident: dict[str, Any]
) -> NodeSample:
    for prefix in T3_ARM_PREFIXES:
        for old in (f"{prefix}_us", f"{prefix}_total_us", f"{prefix}_mean_us"):
            if old in obj:
                raise RegistrationError(
                    f"{where}: {prefix} must use {prefix}_ns/{prefix}_count/"
                    f"{prefix}_total_ns (ns schema); found legacy {old!r}"
                )
    _check_sample_identity(obj, ident, T3_IDENTITY_INTS, where, "template_render")
    if not isinstance(ident.get("tip"), str) or not ident["tip"]:
        raise RegistrationError(f"{where}: pinned tip for template_render is missing")
    tip = obj.get("tip")
    if tip != ident["tip"]:
        raise RegistrationError(
            f"{where}: template_render tip {tip!r} != pinned prefix tip "
            f"{ident['tip']!r} (the tip never connects)"
        )
    tip_height = obj.get("tip_height")
    want_height = ident.get("tip_height")
    if type(want_height) is not int:
        raise RegistrationError(
            f"{where}: pinned identity template_render[tip_height] must be an int"
        )
    if tip_height != want_height:
        raise RegistrationError(
            f"{where}: tip_height {tip_height!r} != pinned {want_height!r}"
        )
    longpollid = obj.get("longpollid")
    if not isinstance(longpollid, str) or not longpollid:
        raise RegistrationError(f"{where}: longpollid must be a nonempty string")
    arms: dict[str, NodeArmGroup] = {}
    for prefix in T3_ARM_PREFIXES:
        arms[prefix] = _narrow_arm_group(
            obj,
            (
                f"{prefix}_ns",
                f"{prefix}_count",
                f"{prefix}_total_ns",
            ),
            where,
            prefix,
        )
    if obj.get("arc_reuse") is not True:
        raise RegistrationError(f"{where}: arc_reuse must be true")
    selected = obj.get("selected_txs")
    rpc_txs = obj.get("rpc_txs")
    if type(selected) is not int or selected <= 0:
        raise RegistrationError(f"{where}: selected_txs must be a positive int")
    if rpc_txs != selected:
        raise RegistrationError(
            f"{where}: rpc_txs {rpc_txs!r} must equal selected_txs {selected!r}"
        )
    for field in ("selected_weight", "rpc_data_bytes"):
        value = obj.get(field)
        if type(value) is not int or value < 0:
            raise RegistrationError(
                f"{where}: {field} must be a nonnegative int, got {value!r}"
            )
    for field in ("cold_curtime", "hit_curtime", "mintime"):
        value = obj.get(field)
        if type(value) is not int or value < 0:
            raise RegistrationError(
                f"{where}: {field} must be a nonnegative int, got {value!r}"
            )
    cold_cur = obj["cold_curtime"]
    hit_cur = obj["hit_curtime"]
    mintime = obj["mintime"]
    if not (hit_cur >= cold_cur >= mintime):
        raise RegistrationError(
            f"{where}: curtime order violated: "
            f"hit {hit_cur} >= cold {cold_cur} >= mintime {mintime} required"
        )
    for field in ("boundary_rpc_miss", "boundary_service_hit", "boundary_rpc_hit"):
        value = obj.get(field)
        if not isinstance(value, str) or not value:
            raise RegistrationError(f"{where}: {field} must be a nonempty string")
    identity: dict[str, str | int | bool] = {
        "engine": obj["engine"],
        "tip": obj["tip"],
        "pool_txs": obj["pool_txs"],
        "background_txs": obj["background_txs"],
        "pool_at_template": obj["pool_at_template"],
        "selected_txs": obj["selected_txs"],
        "selected_weight": obj["selected_weight"],
        "rpc_txs": obj["rpc_txs"],
        "rpc_data_bytes": obj["rpc_data_bytes"],
        "tip_height": obj["tip_height"],
        "longpollid": obj["longpollid"],
        "cold_curtime": obj["cold_curtime"],
        "hit_curtime": obj["hit_curtime"],
        "mintime": obj["mintime"],
        "arc_reuse": True,
    }
    return _base_node_sample(obj, where, arms, {}, identity)


def parse_node_stdout(
    stdout_path: Path,
    node_bench: str,
    node_identity: dict[str, Any],
    corpus: dict[str, Any],
) -> tuple[list[NodeSample], list[NodeSample], dict[str, int]]:
    try:
        text = stdout_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RegistrationError(f"{stdout_path}: cannot read stdout: {exc}") from exc
    where = str(stdout_path)
    seen_corpus = _parse_corpus_identity(text, where)
    _check_corpus_pinned(seen_corpus, corpus, where)
    ident = node_identity.get(node_bench)
    if not isinstance(ident, dict):
        raise RegistrationError(f"{where}: no pinned node_identity for {node_bench!r}")
    narrowed = [
        _narrow_t2_sample(obj, where, ident)
        if node_bench == "block_to_template_baseline"
        else _narrow_t3_sample(obj, where, ident)
        for obj in _narrow_sample_lines(text, node_bench, where)
    ]
    warmups = [s for s in narrowed if s["warmup"]]
    measured = [s for s in narrowed if not s["warmup"]]
    if len(warmups) != WARMUP_SAMPLES or len(measured) != MEASURED_SAMPLES:
        raise RegistrationError(
            f"{where}: expected {WARMUP_SAMPLES} warmup + {MEASURED_SAMPLES} "
            f"measured samples, got {len(warmups)} + {len(measured)}"
        )
    for kind_name, group, want in (
        ("warmup", warmups, [0, 1, 2]),
        ("measured", measured, list(range(3, 13))),
    ):
        indices = sorted(s["sample"] for s in group)
        if indices != want:
            raise RegistrationError(
                f"{where}: {kind_name} sample indices {indices} must be exactly {want}"
            )
    for sample in narrowed:
        for arm_name, arm in sample["arms"].items():
            if arm["total"] < MIN_NODE_NS:
                raise RegistrationError(
                    f"{where}: sample {sample['sample']} arm {arm_name} "
                    f"aggregates {arm['total']} ns, below the 2 s floor; "
                    "warmups use the identical accumulation rule"
                )
    measured.sort(key=lambda s: s["sample"])
    return warmups, measured, seen_corpus


class CriterionFields(TypedDict):
    criterion_sample_path: str
    sample_iters: list[float]
    sample_times_ns: list[float]
    normalized_ns: list[float]
    case_median_ns: float
    case_std_ns: float


class NodeFields(TypedDict):
    node_stdout_path: str
    node_warmups_seen: int
    node_samples: list[dict[str, Any]]
    node_corpus: dict[str, int]
    normalized_ns: list[float]
    case_median_ns: float
    case_std_ns: float


def criterion_case_fields(sample_path: Path, row: dict[str, Any]) -> CriterionFields:
    """Validated raw Criterion data of one case (the runner's only parser)."""
    iters, times, normalized, median, std = validate_criterion_sample(
        sample_path, int(row["samples"]), int(row["units_per_iter"])
    )
    return {
        "criterion_sample_path": str(sample_path),
        "sample_iters": iters,
        "sample_times_ns": times,
        "normalized_ns": normalized,
        "case_median_ns": median,
        "case_std_ns": std,
    }


def node_case_fields(
    stdout_path: Path, row: dict[str, Any], reg: dict[str, Any]
) -> NodeFields:
    """Validated node samples of one case (the runner's only parser)."""
    warmups, measured, seen_corpus = parse_node_stdout(
        stdout_path, str(row["node_bench"]), reg["node_identity"], reg["corpus"]
    )
    primary_arm = (
        "tail_to_reply"
        if row["node_bench"] == "block_to_template_baseline"
        else "rpc_hit"
    )
    means_ns = [float(sample["arms"][primary_arm]["mean"]) for sample in measured]
    return {
        "node_stdout_path": str(stdout_path),
        "node_warmups_seen": len(warmups),
        "node_samples": [dict(sample) for sample in measured],
        "node_corpus": dict(seen_corpus),
        "normalized_ns": means_ns,
        "case_median_ns": float(statistics.median(means_ns)),
        "case_std_ns": float(statistics.stdev(means_ns)),
    }


def _terminate_process_group(proc: subprocess.Popen[bytes] | None) -> None:
    if proc is None or getattr(proc, "_group_terminated", False):
        return
    setattr(proc, "_group_terminated", True)
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError as exc:
        print(f"warning: killpg failed for pid {proc.pid}: {exc}", file=sys.stderr)
    proc.wait()


def execute_case(
    case: dict[str, Any],
    reg: dict[str, Any],
    runs_dir: Path,
    cpu: int,
    timeout_seconds: float,
) -> CaseRecord:
    row: dict[str, Any] = case["row"]
    target = case["target"]
    arm = case["arm"]
    binary_key = case["binary_key"]
    binary_path = Path(reg["binaries"][binary_key]["path"])
    expected_sha = reg["binaries"][binary_key]["sha256"]
    label = f"{target}-b{case['block']}v{case['visit_index']:02d}-{arm}-{row['id']}"
    case_dir = (
        runs_dir
        / target
        / f"v{case['visit_index']:02d}-{arm}"
        / _sanitize_row(row["id"])
    )
    case_dir.mkdir(parents=True, exist_ok=False)
    stdout_path = case_dir / "stdout.log"
    stderr_path = case_dir / "stderr.log"
    perf_csv_path = case_dir / "perf.csv"
    criterion_home = case_dir / "criterion"

    command = [
        "taskset",
        "-c",
        str(cpu),
        "perf",
        "stat",
        "-x,",
        "-e",
        PERF_EVENTS,
        "-o",
        str(perf_csv_path),
        "--",
        str(binary_path),
    ] + list(row["argv"])
    record: CaseRecord = {
        "case_index": case["case_index"],
        "target": target,
        "block": case["block"],
        "block_kind": case["block_kind"],
        "visit_index": case["visit_index"],
        "arm": arm,
        "binary_key": binary_key,
        "binary_path": str(binary_path),
        "binary_sha256_before": "",
        "binary_sha256_after": None,
        "row": row["id"],
        "row_kind": row["kind"],
        "label": label,
        "command": command,
        "host_before": host_state(cpu),
        "host_after": None,
        "exit_code": None,
        "timed_out": False,
        "cancelled": False,
        "error": None,
        "case_dir": str(case_dir),
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "perf_csv": None,
        "perf": None,
        "criterion_sample_path": None,
        "sample_iters": None,
        "sample_times_ns": None,
        "normalized_ns": None,
        "case_median_ns": None,
        "case_std_ns": None,
        "node_stdout_path": None,
        "node_warmups_seen": None,
        "node_samples": None,
        "node_corpus": None,
        "counted_stdout_path": None,
        "counted_warmups_seen": None,
        "counted_warmup_samples": None,
        "counted_samples": None,
    }

    if not binary_path.is_file():
        record["error"] = f"binary {binary_key} not found at {binary_path}"
        record["host_after"] = host_state(cpu)
        return record
    try:
        pre_sha = compute_sha256(binary_path)
    except OSError as exc:
        record["error"] = f"cannot hash binary {binary_key} before launch: {exc}"
        record["host_after"] = host_state(cpu)
        return record
    if pre_sha != expected_sha:
        record["binary_sha256_before"] = pre_sha
        record["error"] = (
            f"binary {binary_key} SHA-256 mismatch before launch: "
            f"expected {expected_sha}, got {pre_sha}"
        )
        record["host_after"] = host_state(cpu)
        return record
    record["binary_sha256_before"] = pre_sha

    env = dict(os.environ)
    env[ENGINE_ENV_VAR] = NATIVE_ENGINE
    if row["kind"] == "criterion":
        criterion_home.mkdir(parents=True, exist_ok=True)
        env[CRITERION_ENV] = str(criterion_home)

    proc: subprocess.Popen[bytes] | None = None
    timed_out = False
    cancelled = False
    exit_code: int | None = None
    try:
        with stdout_path.open("w", encoding="utf-8") as out_f:
            with stderr_path.open("w", encoding="utf-8") as err_f:
                proc = subprocess.Popen(
                    command,
                    env=env,
                    stdout=out_f,
                    stderr=err_f,
                    start_new_session=True,
                )
                try:
                    exit_code = proc.wait(timeout=timeout_seconds)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    record["error"] = (
                        f"case timed out after {timeout_seconds}s; "
                        "process group killed, no retry"
                    )
                    _terminate_process_group(proc)
    except KeyboardInterrupt:
        cancelled = True
        record["error"] = "case cancelled; process group killed, no retry"
        _terminate_process_group(proc)
    except OSError as exc:
        record["error"] = f"case launch failed: {exc}"
        _terminate_process_group(proc)
    finally:
        _terminate_process_group(proc)
    record["timed_out"] = timed_out
    record["cancelled"] = cancelled
    record["exit_code"] = exit_code
    record["host_after"] = host_state(cpu)

    try:
        post_sha = compute_sha256(binary_path)
    except OSError as exc:
        record["error"] = (record["error"] or "") + (
            f"; cannot re-hash binary {binary_key} after case: {exc}"
        )
        return record
    record["binary_sha256_after"] = post_sha
    if post_sha != expected_sha:
        record["error"] = (record["error"] or "") + (
            f"; binary {binary_key} SHA-256 changed during case: "
            f"expected {expected_sha}, got {post_sha}"
        )
        return record

    if cancelled or timed_out or record["error"] is not None:
        return record
    if exit_code != 0:
        record["error"] = f"benchmark process exited with code {exit_code}"
        return record

    try:
        perf_counters, perf_csv_text = parse_perf_csv(perf_csv_path)
    except RegistrationError as exc:
        record["error"] = f"perf validation error: {exc}"
        return record
    except OSError as exc:
        record["error"] = f"cannot read perf.csv: {exc}"
        return record
    record["perf"] = perf_counters
    record["perf_csv"] = perf_csv_text

    try:
        if row["kind"] == "criterion":
            record.update(
                criterion_case_fields(find_single_sample_json(criterion_home), row)
            )
        elif row["kind"] == "counted":
            record.update(counted_case_fields(stdout_path, row))
        else:
            record.update(node_case_fields(stdout_path, row, reg))
    except RegistrationError as exc:
        record["error"] = f"{row['kind']} validation error: {exc}"
    return record


MANIFEST_RESERVED_NAMES: tuple[str, ...] = ("manifest.json", "manifest.sha256")


def runs_inventory(runs_dir: Path) -> tuple[list[str], list[str]]:
    """The one inventory rule of a campaign runs directory.

    Returns `(files, problems)`. `files` are the sorted canonical POSIX
    relative paths of every regular file, excluding only the reserved
    manifest and receipt at the runs root (the two files `write_manifest`
    generates; a regular `case/manifest.json` is an ordinary artifact and is
    inventoried). A symlink (even to a regular file, even a reserved
    name) and any entry that is neither a regular file nor a directory is
    a problem, never skipped and never recorded. `write_manifest` records
    exactly `files` and `measured_analyze.py` compares a manifest against
    the same function through the hash-verified runner module, so producer
    and consumer cannot disagree about what the inventory is.
    """
    files: list[str] = []
    problems: list[str] = []
    pending = [runs_dir]
    while pending:
        directory = pending.pop()
        for entry in sorted(directory.iterdir()):
            rel = entry.relative_to(runs_dir).as_posix()
            if entry.is_symlink():
                problems.append(
                    f"runs artifact {rel!r} is a symlink; the inventory covers "
                    "regular files only"
                )
            elif entry.is_dir():
                pending.append(entry)
            elif entry.is_file():
                if rel not in MANIFEST_RESERVED_NAMES:
                    files.append(rel)
            else:
                problems.append(
                    f"runs artifact {rel!r} is neither a regular file nor a directory"
                )
    return sorted(files), sorted(problems)


def write_manifest(runs_dir: Path) -> tuple[Path, Path]:
    files, problems = runs_inventory(runs_dir)
    if problems:
        raise RegistrationError(
            "refusing to anchor an unsound runs directory: " + "; ".join(problems)
        )
    entries = {rel: compute_sha256(runs_dir / rel) for rel in files}
    manifest_path = runs_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps({"algorithm": "sha256", "files": entries}, indent=2) + "\n",
        encoding="utf-8",
    )
    receipt_path = runs_dir / "manifest.sha256"
    receipt_path.write_text(compute_sha256(manifest_path) + "\n", encoding="utf-8")
    return manifest_path, receipt_path


def seal_manifest(runs_dir: Path) -> bool:
    """`write_manifest` that reports failure instead of raising.

    Stop and cancel paths must still return their own exit code (130 for an
    interruption), so a refused or unwritable inventory is reported on stderr
    and returned as `False`; the analyzer then finds no manifest and stays
    INCONCLUSIVE. Nothing is repaired or skipped.
    """
    try:
        write_manifest(runs_dir)
    except (OSError, RegistrationError) as exc:
        print(f"INVALID: manifest not written: {exc}", file=sys.stderr)
        return False
    return True


def validate_live_registration(
    reg: object, check_output_absent: bool = True
) -> list[str]:
    """Live launcher validation: static schema plus affinity and CPU model.

    The validate/plan/run CLIs use this; the analyzer uses the static
    validator and binds recorded host/command values instead. A wrong live
    model fails here while offline analysis of a differently labeled host
    stays possible. This catches an accidentally stale label; it is not
    tamper-proof attestation.
    """
    reasons = validate_registration(reg, check_output_absent)
    if isinstance(reg, dict):
        _check_live_affinity(reg.get("host"), reasons)
        _check_live_cpu_model(reg.get("host"), reasons)
    return reasons


def cmd_validate(reg_path: Path) -> int:
    reg, load_reasons = load_registration(reg_path)
    if reg is None:
        for reason in load_reasons:
            print(f"INVALID: {reason}", file=sys.stderr)
        return 1
    reasons = validate_live_registration(reg, check_output_absent=True)
    if reasons:
        for reason in reasons:
            print(f"INVALID: {reason}", file=sys.stderr)
        return 1
    cases = derive_cases(reg)
    print(
        f"VALID: status=registered, {len(cases)} cases, "
        f"campaign_root={reg['campaign_root']}"
    )
    return 0


def cmd_plan(reg_path: Path) -> int:
    reg, load_reasons = load_registration(reg_path)
    if reg is None:
        for reason in load_reasons:
            print(f"INVALID: {reason}", file=sys.stderr)
        return 1
    reasons = validate_live_registration(reg, check_output_absent=False)
    if reasons:
        for reason in reasons:
            print(f"INVALID: {reason}", file=sys.stderr)
        return 1
    cases = derive_cases(reg)
    current_target = ""
    for case in cases:
        if case["target"] != current_target:
            current_target = case["target"]
            print(
                f"target {current_target} "
                f"(control {reg['targets'][current_target]['control_tree']}):"
            )
        row: dict[str, Any] = case["row"]
        print(
            f"  case {case['case_index']:4d} block {case['block']} "
            f"({case['block_kind']:7s}) visit {case['visit_index']:02d} "
            f"arm {case['arm']:9s} row {row['id']} [{row['kind']}/{row['role']}] "
            f"-> {row['candidate_binary'] if case['arm'] in ('candidate', 'zero') else row['control_binary']}"
        )
    print(f"total {len(cases)} cases; one child alive at a time; T1->T4 serialized")
    return 0


def cmd_run(reg_path: Path) -> int:
    reg, load_reasons = load_registration(reg_path)
    if reg is None:
        for reason in load_reasons:
            print(f"INVALID: {reason}", file=sys.stderr)
        return 1
    reasons = validate_live_registration(reg, check_output_absent=True)
    if reasons:
        for reason in reasons:
            print(f"INVALID: {reason}", file=sys.stderr)
        return 1
    cpu: int = reg["host"]["cpu"]
    timeout_seconds = float(reg["timeout_seconds"])
    runs_dir = Path(reg["campaign_root"])
    runs_dir.mkdir(parents=True, exist_ok=False)
    results_path = runs_dir / "results.json"
    results_jl = runs_dir / "results.jsonl"
    cases = derive_cases(reg)
    records: list[CaseRecord] = []
    for case in cases:
        record = execute_case(case, reg, runs_dir, cpu, timeout_seconds)
        records.append(record)
        results_path.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
        with results_jl.open("a", encoding="utf-8") as jl_f:
            jl_f.write(json.dumps(record) + "\n")
        if record["cancelled"]:
            print(f"CANCELLED at {record['label']}", file=sys.stderr)
            seal_manifest(runs_dir)
            return 130
        if record["error"] is not None:
            print(f"STOP {record['label']}: {record['error']}", file=sys.stderr)
            seal_manifest(runs_dir)
            return 1
        print(
            f"[{record['case_index'] + 1}/{len(cases)}] {record['label']}: "
            f"case_median_ns={record['case_median_ns']}",
            flush=True,
        )
    if not seal_manifest(runs_dir):
        return 1
    print(
        f"Completed {len(records)} cases. Manifest {runs_dir / 'manifest.json'}, "
        f"receipt {runs_dir / 'manifest.sha256'}. No gate verdict here."
    )
    return 0


def parse_args(args: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="MRP campaign runner: validate, plan, or run a registered campaign",
        allow_abbrev=False,
    )
    sub = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (
        ("validate", "check registration completeness; launch nothing"),
        ("plan", "print the canonical case schedule; launch nothing"),
        ("run", "validate fully, then execute all cases serially"),
    ):
        child = sub.add_parser(name, help=help_text, allow_abbrev=False)
        child.add_argument(
            "--registration",
            type=Path,
            required=True,
            help="path to the registered campaign JSON (status must be 'registered')",
        )
    return parser.parse_args(args)


def main() -> int:
    args = parse_args()
    reg_path: Path = args.registration
    if not reg_path.is_file():
        print(f"INVALID: registration file not found: {reg_path}", file=sys.stderr)
        return 1
    if args.command == "validate":
        return cmd_validate(reg_path)
    if args.command == "plan":
        return cmd_plan(reg_path)
    if args.command == "run":
        return cmd_run(reg_path)
    print(f"INVALID: unknown command {args.command!r}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
