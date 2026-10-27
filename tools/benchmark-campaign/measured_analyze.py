#!/usr/bin/env python3
"""MRP campaign analyzer: completeness/identity/quality first, frozen gates after.

Reads a real complete registration JSON, the runner's results.json, and the
run manifest. Any completeness, identity, or quality failure yields
INCONCLUSIVE -- never a win and never a zero-value fallback.

Frozen rules implemented (thresholds are constants, not knobs):
  Populations: each visit holds 10 normalized sample estimates (criterion
      times[i]/iters[i]/units_per_iter from raw sample.json; counted
      total_ns/unit_count per retained MRP_COUNTED_SAMPLE object, validated
      with the runner's validate_counted_samples(); node total_ns/count
      derived per sample, never console means). The visit estimate is the
      median of its 10. Each measured arm holds 6 visit medians; M is their
      median and S their sample stdev. The zero block holds 4 same-binary
      visit medians. No outlier removal.
  T1  matched protocol per singleton acceptance row only: case
      stdev/median <= 0.20, visit-median max/min < 1.15, effective
      frequency difference <= 3% overall and per ABBA block; then
      REGRESSION iff M_cand - M_ctrl > S_cand + S_ctrl. Case medians are
      computed from retained raw normalized samples, never from
      estimates.json or console summaries. Cluster/report rows are
      descriptive. Assembly 50k/100k guard_keep rows: keep only at
      control/candidate >= 1.05 with the latency reduction
      (M_ctrl-M_cand)/M_ctrl above BOTH (S_cand+S_ctrl)/M_ctrl and the
      zero-block visit-median max/min-1, under the 5% quality rule below.
  5% quality rule (every gated row except T1 acceptance, measurement and
      zero blocks alike): every visit's 10 sample estimates within 5% of
      that visit's median AND every arm's visit medians within 5% of that
      arm's median. The T1 20% stdev / 1.15 spread checks belong only to
      T1 singleton acceptance and are never substituted here.
  Promotion (T1 guard_keep, T2/T3/T4 primaries): control/candidate >= 1.05
      AND latency reduction above BOTH observed bounds. Cold/service
      arms come from the same single T2/T3 standalone record per visit;
      no duplicate invocations.
  T2  tail primary; at-floor disposition (keep=false, not a win) when
      median(assembly_ns)/median(tail_ns) < 0.05 on the usable control
      arm (components stay *_us, converted explicitly); unusable baseline
      is INCONCLUSIVE. Components descriptive only, no per-component gate.
  T3  rpc-hit primary win >= 1.05 above both bounds; cold-miss
      non-regression (M_cand - M_ctrl <= S_cand + S_ctrl) from the same
      record's rpc_miss arm; service arms diagnostic.
  T4  admission primary win >= 1.05 above both bounds; connect guards
      <= 3% median and <= 5% p99 regression (p99 over all retained
      normalized sample estimates of that arm -- criterion normalized
      values or counted total_ns/unit_count objects, never raw units,
      linear interpolation at (n-1)*0.99; node raw-unit percentiles
      descriptive only); script rows diagnostic.
  All win/keep evaluations additionally require the 3% frequency control
      (gated roles, overall and per ABBA block). Percentile populations
      are named explicitly in every output.

Registration: this analyzer states no registration rule of its own. Before any
quality or keep evaluation it first binds its own executing analyzer
path/digest to reg scripts.analyzer (re-read and re-hashed every call, no
cache; malformed, relocated, or changed bytes are INCONCLUSIVE before any
runner load, catching accidental stale execution only, never tamper-proof
attestation) and then runs the runner's static
    validate_registration() (the registered runner script is hashed before
    anything is executed and the exact verified bytes are the only code loaded;
    the module is cached only under that verified digest plus its file path),
    which pins the exact
    row/role/argv tables (counted rows carry kind `counted` and the
    `--mrp-counted` argv; the shared sampler source
    tools/benchmark-support/measured_samples.rs and the shared snapshot-order
    source tools/benchmark-support/snapshot_order.rs are pinned in the bench
    fingerprint inventory), complete source/bench/lock inventories,
    receipt-bound executables, baseline evidence and identity pins against the
    real files. Recorded CPU/model and taskset values are then bound to the
registration per record. Metadata cannot prove that a process ran; run
honesty, raw-artifact replay and tamper-proofing stay the parent's
responsibility.

Usage:
  measured_analyze.py --registration REG --results RES --manifest MAN
"""

import argparse
import hashlib
import json
import math
import statistics
import sys
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Any, Literal


TARGET_ORDER: tuple[str, ...] = ("T1", "T2", "T3", "T4")
ZERO_VISITS: tuple[str, ...] = ("candidate", "zero", "zero", "candidate")
MEASURE_VISITS: tuple[str, ...] = ("candidate", "control", "control", "candidate")
MEASURE_BLOCKS: tuple[int, ...] = (1, 2, 3)

CASE_STDDEV_RATIO_MAX: float = 0.20
ARM_SPREAD_MAX: float = 1.15
FREQ_RATIO_MAX: float = 1.03
WIN_RATIO: float = 1.05
ARM_STABILITY_BAND: float = 0.05
GUARD_MEDIAN_MAX: float = 0.03
GUARD_P99_MAX: float = 0.05
AT_FLOOR_MAX: float = 0.05
ASSEMBLY_FIELD: str = "assembly_us"

AUTHORITIES: list[str] = [
    "docs/benchmarks/measured-campaign.md#registration",
    "docs/benchmarks/measured-campaign.md#statistics",
    "docs/benchmarks/measured-campaign.md#counted-samples",
    "docs/benchmarks/measured-campaign.md#control-trees",
    "docs/benchmarks/README.md:Acceptance rule",
    "docs/contracts/hot-path-attribution.md:HPA-13",
]

GATED_ROLES: tuple[str, ...] = (
    "acceptance",
    "primary",
    "cold",
    "guard_keep",
    "connect_guard",
)

VerdictKind = Literal[
    "INCONCLUSIVE", "REGRESSION", "NON_REGRESSION_EVIDENCED", "AT_FLOOR"
]


class AnalysisError(Exception):
    """Internal analysis failure; callers convert to INCONCLUSIVE reasons."""


_RUNNER: ModuleType | None = None
_RUNNER_DIGEST: str | None = None
_RUNNER_PATH: str | None = None


def _is_hex64(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(c in "0123456789abcdef" for c in value)
    )


def _check_executing_analyzer(reg: dict[str, Any]) -> None:
    """Bind the executing analyzer file to the registered analyzer entry.

    Re-reads and hashes the actual __file__ bytes on every call with no
    cache, before any runner module execution. Mismatches raise
    AnalysisError so callers return INCONCLUSIVE. This catches accidental
    stale or relocated analyzer execution; it is not tamper-proof
    attestation.
    """
    if not isinstance(reg, dict):
        raise AnalysisError("registration root must be a JSON object")
    scripts = reg.get("scripts")
    entry = scripts.get("analyzer") if isinstance(scripts, dict) else None
    if not isinstance(entry, dict):
        raise AnalysisError("registration scripts.analyzer entry is not an object")
    path_value, sha_value = entry.get("path"), entry.get("sha256")
    if not isinstance(path_value, str) or not Path(path_value).is_absolute():
        raise AnalysisError(
            "registration scripts.analyzer.path must be an absolute path, "
            f"got {path_value!r}"
        )
    if not isinstance(sha_value, str) or not _is_hex64(sha_value):
        raise AnalysisError(
            "registration scripts.analyzer.sha256 must be lowercase 64-hex, "
            f"got {sha_value!r}"
        )
    actual_path = Path(__file__).resolve()
    registered_path = Path(path_value).resolve()
    if actual_path != registered_path:
        raise AnalysisError(
            f"registered analyzer {str(registered_path)!r} is not the executing "
            f"analyzer {str(actual_path)!r}"
        )
    try:
        source = actual_path.read_bytes()
    except OSError as exc:
        raise AnalysisError(
            f"cannot read the executing analyzer script from {actual_path}: {exc}"
        ) from exc
    actual = hashlib.sha256(source).hexdigest()
    if actual != sha_value:
        raise AnalysisError(
            f"registered analyzer script hash {sha_value!r} != file hash "
            f"{actual!r} ({actual_path}); refusing to execute unverified bytes"
        )


def _runner(reg: dict[str, Any]) -> ModuleType:
    """The sibling runner module, verified against the registered digest.

    The expected `{path, sha256}` comes from `reg["scripts"]["runner"]`. The
    exact bytes at that path are read and hashed BEFORE any cache reuse,
    compile, or execution; a cached module is reused only when both its
    verified digest and its file path match the current registration, so
    stale, mismatched, or relocated runner bytes never execute.
    """
    global _RUNNER, _RUNNER_DIGEST, _RUNNER_PATH
    if not isinstance(reg, dict):
        raise AnalysisError("registration root must be a JSON object")
    scripts = reg.get("scripts")
    entry = scripts.get("runner") if isinstance(scripts, dict) else None
    if not isinstance(entry, dict):
        raise AnalysisError("registration scripts.runner entry is not an object")
    path_value, sha_value = entry.get("path"), entry.get("sha256")
    if not isinstance(path_value, str) or not Path(path_value).is_absolute():
        raise AnalysisError(
            "registration scripts.runner.path must be an absolute path, "
            f"got {path_value!r}"
        )
    if not isinstance(sha_value, str) or not _is_hex64(sha_value):
        raise AnalysisError(
            "registration scripts.runner.sha256 must be lowercase 64-hex, "
            f"got {sha_value!r}"
        )
    runner_path = Path(path_value)
    try:
        source = runner_path.read_bytes()
    except OSError as exc:
        raise AnalysisError(
            f"cannot read the registered runner script from {runner_path}: {exc}"
        ) from exc
    actual = hashlib.sha256(source).hexdigest()
    if actual != sha_value:
        raise AnalysisError(
            f"registered runner script hash {sha_value!r} != file hash "
            f"{actual!r} ({runner_path}); refusing to execute unverified "
            "bytes"
        )
    if (
        _RUNNER is not None
        and _RUNNER_DIGEST == actual
        and _RUNNER_PATH == str(runner_path)
    ):
        return _RUNNER
    module = ModuleType("rbitcoin_mrp_run_validator")
    module.__file__ = str(runner_path)
    previous = sys.modules.get(module.__name__)
    sys.modules[module.__name__] = module
    try:
        exec(compile(source, str(runner_path), "exec"), module.__dict__)
    except BaseException as exc:
        if previous is None:
            sys.modules.pop(module.__name__, None)
        else:
            sys.modules[module.__name__] = previous
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        raise AnalysisError(
            f"cannot load the registration validator from {runner_path}: {exc}"
        ) from exc
    _RUNNER = module
    _RUNNER_DIGEST = actual
    _RUNNER_PATH = str(runner_path)
    return _RUNNER


def _is_positive_finite(value: object) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    as_float = float(value)
    return math.isfinite(as_float) and as_float > 0


def _median(values: list[float]) -> float:
    return float(statistics.median(values))


def _stdev(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    return float(statistics.stdev(values))


def _freq_khz(record: dict[str, Any]) -> float:
    perf = record.get("perf")
    if not isinstance(perf, dict):
        return 0.0
    cycles = perf.get("cycles_u")
    clock_ms = perf.get("task_clock_ms")
    if not _is_positive_finite(cycles) or not _is_positive_finite(clock_ms):
        return 0.0
    return float(cycles) / float(clock_ms)  # type: ignore[arg-type]


def _freq_ratio(a: list[float], b: list[float]) -> float:
    med_a, med_b = _median(a), _median(b)
    lo, hi = min(med_a, med_b), max(med_a, med_b)
    if lo <= 0:
        return float("inf")
    return hi / lo


def _percentiles(values: list[float]) -> dict[str, float]:
    ordered = sorted(values)
    n = len(ordered)

    def pick(q: float) -> float:
        if n == 1:
            return ordered[0]
        pos = q * (n - 1)
        lo_idx = int(math.floor(pos))
        hi_idx = int(math.ceil(pos))
        frac = pos - lo_idx
        return ordered[lo_idx] * (1.0 - frac) + ordered[hi_idx] * frac

    return {
        "p50": pick(0.50),
        "p95": pick(0.95),
        "p99": pick(0.99),
        "max": ordered[-1],
        "n": float(n),
    }


def load_json_file(path: Path, what: str) -> tuple[Any | None, str | None]:
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except OSError as exc:
        return None, f"{what} cannot be read from {path}: {exc}"
    except json.JSONDecodeError as exc:
        return None, f"{what} at {path} is not valid JSON: {exc}"


def expected_label(target: str, block: int, visit: int, arm: str, row: str) -> str:
    return f"{target}-b{block}v{visit:02d}-{arm}-{row}"


def derive_expected_cases(reg: dict[str, Any]) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    case_index = 0
    for target in TARGET_ORDER:
        rows: list[dict[str, Any]] = reg["targets"][target]["rows"]
        for block in range(4):
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
                            "row_id": row["id"],
                            "row": row,
                        }
                    )
                    case_index += 1
    return cases


def case_median_ns(record: dict[str, Any], row: dict[str, Any]) -> float:
    if row["kind"] == "criterion":
        iters = record.get("sample_iters")
        times = record.get("sample_times_ns")
        samples = int(row["samples"])
        units = int(row["units_per_iter"])
        if (
            not isinstance(iters, list)
            or not isinstance(times, list)
            or len(iters) != samples
            or len(times) != samples
        ):
            raise AnalysisError(
                f"record {record.get('label')}: iters/times inventory mismatch"
            )
        normalized: list[float] = []
        for i, t in zip(iters, times):
            if not _is_positive_finite(i) or not _is_positive_finite(t):
                raise AnalysisError(
                    f"record {record.get('label')}: non-positive raw sample"
                )
            if float(t) < 1_000_000_000.0:  # type: ignore[arg-type]
                raise AnalysisError(
                    f"record {record.get('label')}: raw interval below 1 s"
                )
            normalized.append(float(t) / float(i) / float(units))  # type: ignore[arg-type]
        stored = record.get("normalized_ns")
        if (
            not isinstance(stored, list)
            or len(stored) != len(normalized)
            or any(
                not math.isclose(float(s), n, rel_tol=1e-12)  # type: ignore[arg-type]
                for s, n in zip(stored, normalized)
            )
        ):
            raise AnalysisError(
                f"record {record.get('label')}: stored normalized values "
                "do not match recomputation from raw iters/times"
            )
        return _median(normalized)
    if row["kind"] == "counted":
        _, _, normalized, median, _ = _counted_validated(record, row)
        return median
    return _node_primary_median_ns(record, row)


def _counted_validated(
    record: dict[str, Any], row: dict[str, Any]
) -> tuple[list[float], list[float], list[float], float, float]:
    """Validate a retained counted record through the runner's shared validator.

    The retained raw counted_warmup_samples/counted_samples objects are the
    statistics input; the stored derived arrays never stand alone. A missing,
    duplicated, reordered, or malformed raw object raises AnalysisError, so
    the caller reports INCONCLUSIVE.
    """
    runner = _RUNNER
    if runner is None:
        raise AnalysisError("runner module not verified; cannot validate counted data")
    warmups = record.get("counted_warmup_samples")
    samples = record.get("counted_samples")
    label = record.get("label")
    if (
        not isinstance(warmups, list)
        or not isinstance(samples, list)
        or not all(isinstance(obj, dict) for obj in warmups)
        or not all(isinstance(obj, dict) for obj in samples)
    ):
        raise AnalysisError(
            f"record {label}: counted raw warmup/measured objects missing"
        )
    try:
        iters, times, normalized, median, std = runner.validate_counted_samples(
            warmups, samples, str(row["id"]), str(label)
        )
    except runner.RegistrationError as exc:
        raise AnalysisError(f"record {label}: {exc}") from exc
    stored_median = record.get("case_median_ns")
    if not isinstance(stored_median, (int, float)) or isinstance(stored_median, bool):
        raise AnalysisError(f"record {label}: counted case_median_ns missing")
    if not math.isclose(float(stored_median), median, rel_tol=1e-9):
        raise AnalysisError(
            f"record {label}: stored counted median does not match "
            "recomputation from retained raw objects"
        )
    stored_std = record.get("case_std_ns")
    if not isinstance(stored_std, (int, float)) or isinstance(stored_std, bool):
        raise AnalysisError(f"record {label}: counted case_std_ns missing")
    if not math.isfinite(float(stored_std)) or float(stored_std) < 0:
        raise AnalysisError(f"record {label}: counted case_std_ns not finite/nonneg")
    if not math.isclose(float(stored_std), std, rel_tol=1e-9):
        raise AnalysisError(
            f"record {label}: stored counted std does not match "
            "recomputation from retained raw objects"
        )
    stored_iters = record.get("sample_iters")
    stored_times = record.get("sample_times_ns")
    if (
        not isinstance(stored_iters, list)
        or len(stored_iters) != len(iters)
        or not all(
            isinstance(v, (int, float))
            and not isinstance(v, bool)
            and math.isclose(float(v), w, rel_tol=1e-12)
            for v, w in zip(stored_iters, iters)
        )
    ):
        raise AnalysisError(
            f"record {label}: stored sample_iters do not match counted "
            "unit_count values"
        )
    if (
        not isinstance(stored_times, list)
        or len(stored_times) != len(times)
        or not all(
            isinstance(v, (int, float))
            and not isinstance(v, bool)
            and math.isclose(float(v), w, rel_tol=1e-12)
            for v, w in zip(stored_times, times)
        )
    ):
        raise AnalysisError(
            f"record {label}: stored sample_times_ns do not match counted "
            "total_ns values"
        )
    stored_norm = record.get("normalized_ns")
    if (
        not isinstance(stored_norm, list)
        or len(stored_norm) != len(normalized)
        or any(
            not isinstance(v, (int, float))
            or isinstance(v, bool)
            or not math.isclose(float(v), n, rel_tol=1e-12)
            for v, n in zip(stored_norm, normalized)
        )
    ):
        raise AnalysisError(
            f"record {label}: stored normalized_ns does not match recomputed "
            "total_ns/unit_count"
        )
    return iters, times, normalized, median, std


def _node_want_arms(node_bench: str) -> tuple[str, ...]:
    if node_bench == "block_to_template_baseline":
        return ("tail_to_reply",)
    return ("rpc_miss", "service_hit", "service_hit2", "rpc_hit")


def _node_primary_arm(node_bench: str) -> str:
    if node_bench == "block_to_template_baseline":
        return "tail_to_reply"
    return "rpc_hit"


def _checked_arm_mean_ns(label: object, sample: dict[str, Any], arm_name: str) -> float:
    arms = sample.get("arms")
    if not isinstance(arms, dict):
        raise AnalysisError(f"record {label}: node arms missing")
    arm = arms.get(arm_name)
    if not isinstance(arm, dict):
        raise AnalysisError(f"record {label}: node arm {arm_name!r} missing")
    units = arm.get("units")
    count = arm.get("count")
    total = arm.get("total")
    mean = arm.get("mean")
    if not isinstance(units, list) or not units:
        raise AnalysisError(f"record {label}: arm {arm_name} units invalid")
    for entry in units:
        if type(entry) is not int or entry < 0:
            raise AnalysisError(
                f"record {label}: arm {arm_name} units not nonnegative ints "
                "(zero is clock quantization, never clamped)"
            )
    if type(count) is not int or count != len(units):
        raise AnalysisError(f"record {label}: arm {arm_name} count mismatch")
    if type(total) is not int or total != sum(units):
        raise AnalysisError(f"record {label}: arm {arm_name} total != exact sum(units)")
    if total <= 0:
        raise AnalysisError(f"record {label}: arm {arm_name} total not positive")
    expect = total / len(units)
    if isinstance(mean, bool) or not isinstance(mean, (int, float)):
        raise AnalysisError(f"record {label}: arm {arm_name} mean not numeric")
    if not math.isclose(float(mean), expect, rel_tol=1e-9):
        raise AnalysisError(f"record {label}: arm {arm_name} mean inconsistent")
    if total < 2_000_000_000:
        raise AnalysisError(f"record {label}: arm {arm_name} aggregate below 2 s")
    return float(expect)


def _node_primary_median_ns(record: dict[str, Any], row: dict[str, Any]) -> float:
    label = record.get("label")
    samples = record.get("node_samples")
    if not isinstance(samples, list) or len(samples) != 10:
        raise AnalysisError(f"record {label}: node measured inventory mismatch")
    node_bench = str(row["node_bench"])
    primary = _node_primary_arm(node_bench)
    means: list[float] = []
    for sample in samples:
        if not isinstance(sample, dict):
            raise AnalysisError(f"record {label}: bad node sample")
        for arm_name in _node_want_arms(node_bench):
            _checked_arm_mean_ns(label, sample, arm_name)
        if node_bench == "block_to_template_baseline":
            components = sample.get("components")
            if not isinstance(components, dict):
                raise AnalysisError(f"record {label}: T2 components missing")
            for field in (
                "apply_call_to_reply_us",
                "durable_sync_us",
                "durable_commit_us",
                "on_connect_us",
                "assembly_us",
                "remainder_us",
            ):
                arr = components.get(field)
                if not isinstance(arr, list) or not arr:
                    raise AnalysisError(f"record {label}: component {field} invalid")
                for value in arr:
                    if type(value) is not int or value < 0:
                        raise AnalysisError(
                            f"record {label}: component {field} not nonnegative ints"
                        )
        means.append(_checked_arm_mean_ns(label, sample, primary))
    stored = record.get("normalized_ns")
    if (
        not isinstance(stored, list)
        or len(stored) != len(means)
        or any(
            not math.isclose(float(s), m, rel_tol=1e-12)  # type: ignore[arg-type]
            for s, m in zip(stored, means)
        )
    ):
        raise AnalysisError(
            f"record {label}: stored node means do not match raw arm data"
        )
    return _median(means)


def _case_std_ns(record: dict[str, Any], row: dict[str, Any]) -> float:
    """Sample stdev of the visit's validated raw estimates.

    Never trusts the stored scalar; the caller requires the stored
    `case_std_ns` to match this recomputation, so the T1 20% gate consumes
    values bound to raw data.
    """
    if row["kind"] == "criterion":
        return _criterion_std_ns(record, row)
    if row["kind"] == "counted":
        _, _, _, _, std = _counted_validated(record, row)
        return std
    return _node_std_ns(record, row)


def _criterion_std_ns(record: dict[str, Any], row: dict[str, Any]) -> float:
    label = record.get("label")
    iters = record.get("sample_iters")
    times = record.get("sample_times_ns")
    samples = int(row["samples"])
    units = int(row["units_per_iter"])
    if (
        not isinstance(iters, list)
        or not isinstance(times, list)
        or len(iters) != samples
        or len(times) != samples
    ):
        raise AnalysisError(f"record {label}: iters/times inventory mismatch")
    normalized: list[float] = []
    for i, t in zip(iters, times):
        if not _is_positive_finite(i) or not _is_positive_finite(t):
            raise AnalysisError(f"record {label}: non-positive raw sample")
        if float(t) < 1_000_000_000.0:  # type: ignore[arg-type]
            raise AnalysisError(f"record {label}: raw interval below 1 s")
        normalized.append(float(t) / float(i) / float(units))  # type: ignore[arg-type]
    return _stdev(normalized)


def _node_std_ns(record: dict[str, Any], row: dict[str, Any]) -> float:
    label = record.get("label")
    samples = record.get("node_samples")
    if not isinstance(samples, list) or len(samples) != 10:
        raise AnalysisError(f"record {label}: node measured inventory mismatch")
    node_bench = str(row["node_bench"])
    primary = _node_primary_arm(node_bench)
    means: list[float] = []
    for sample in samples:
        if not isinstance(sample, dict):
            raise AnalysisError(f"record {label}: bad node sample")
        for arm_name in _node_want_arms(node_bench):
            _checked_arm_mean_ns(label, sample, arm_name)
        means.append(_checked_arm_mean_ns(label, sample, primary))
    return _stdev(means)


def _node_arm_median_ns(record: dict[str, Any], row: dict[str, Any], arm: str) -> float:
    label = record.get("label")
    samples = record.get("node_samples")
    if not isinstance(samples, list) or len(samples) != 10:
        raise AnalysisError(f"record {label}: node measured inventory mismatch")
    return _median(
        [_checked_arm_mean_ns(label, s, arm) for s in samples if isinstance(s, dict)]
    )


def _node_pool_ns(
    records: list[dict[str, Any]], row: dict[str, Any], arm: str
) -> list[float]:
    pool: list[float] = []
    for record in records:
        samples = record.get("node_samples")
        if not isinstance(samples, list):
            raise AnalysisError(f"record {record.get('label')}: node samples missing")
        for sample in samples:
            if not isinstance(sample, dict):
                raise AnalysisError(f"record {record.get('label')}: bad node sample")
            arms = sample.get("arms")
            if not isinstance(arms, dict):
                raise AnalysisError(f"record {record.get('label')}: node arms missing")
            group = arms.get(arm)
            if not isinstance(group, dict):
                raise AnalysisError(f"record {record.get('label')}: arm {arm} missing")
            units = group.get("units")
            if not isinstance(units, list) or not units:
                raise AnalysisError(
                    f"record {record.get('label')}: arm {arm} units bad"
                )
            for u in units:
                if type(u) is not int or u < 0:
                    raise AnalysisError(
                        f"record {record.get('label')}: arm {arm} unit not "
                        "a nonnegative int"
                    )
            pool.extend(float(u) for u in units)  # type: ignore[arg-type]
    if not pool:
        raise AnalysisError("empty node pool")
    return pool


def _manifest_entry_error(rel: object, digest: object) -> str | None:
    if not isinstance(rel, str) or not rel or Path(rel).is_absolute():
        return f"manifest entry {rel!r} is malformed"
    if PurePosixPath(rel).as_posix() != rel:
        return (
            f"manifest entry {rel!r} is not the canonical POSIX relative "
            "spelling (no ./, .., duplicate or trailing separators)"
        )
    if ".." in PurePosixPath(rel).parts:
        return f"manifest entry {rel!r} escapes the runs directory"
    if not isinstance(digest, str) or not _is_hex64(digest):
        return f"manifest entry {rel!r} carries a malformed digest"
    return None


def _hash_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def _validate_manifest_files(
    runs_dir: Path, manifest_files: dict[str, str], reasons: list[str]
) -> None:
    for rel, digest in manifest_files.items():
        problem = _manifest_entry_error(rel, digest)
        if problem is not None:
            reasons.append(problem)
            continue
        full = runs_dir / rel
        try:
            full.resolve().relative_to(runs_dir.resolve())
        except (OSError, ValueError):
            reasons.append(f"manifest entry {rel!r} escapes the runs directory")
            continue
        if not full.is_file():
            reasons.append(f"manifest artifact missing: {rel}")
            continue
        try:
            actual = _hash_file(full)
        except OSError as exc:
            reasons.append(f"manifest artifact unreadable {rel}: {exc}")
            continue
        if actual != digest:
            reasons.append(f"manifest artifact hash mismatch: {rel}")


def _check_manifest_completeness(
    runner: ModuleType,
    runs_dir: Path,
    manifest_files: dict[str, str],
    reasons: list[str],
) -> None:
    """Compare the manifest with the runner's own `runs_inventory`.

    The producer (`write_manifest`) records exactly `runs_inventory`; the
    analyzer asks the same hash-verified function, so a symlink, a special
    file, or a reserved-name alias can never be inventoried differently on
    the two sides.
    """
    try:
        listed, problems = (
            runner.runs_inventory(runs_dir) if runs_dir.is_dir() else ([], [])
        )
    except OSError as exc:
        reasons.append(f"manifest inventory unreadable under {runs_dir}: {exc}")
        return
    actual_files = set(listed)
    reasons.extend(problems)
    for rel in sorted(actual_files - set(manifest_files.keys())):
        reasons.append(f"manifest omits runs artifact: {rel}")
    for rel in sorted(set(manifest_files.keys()) - actual_files):
        reasons.append(f"manifest lists non-inventory entry: {rel}")


def _check_manifest_receipt(runs_dir: Path, reasons: list[str]) -> None:
    receipt_path = runs_dir / "manifest.sha256"
    manifest_path = runs_dir / "manifest.json"
    if not (receipt_path.is_file() and manifest_path.is_file()):
        return
    try:
        receipt_text = receipt_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        reasons.append(f"manifest receipt unreadable: {exc}")
        return
    receipt = receipt_text.strip().split(" ", 1)[0].strip()
    if not receipt:
        reasons.append("manifest.sha256 receipt is empty")
        return
    try:
        if _hash_file(manifest_path) != receipt:
            reasons.append("manifest.sha256 receipt does not match manifest.json")
    except OSError as exc:
        reasons.append(f"manifest receipt unreadable: {exc}")


def _validate_manifest(
    runner: ModuleType, runs_dir: Path, manifest: Any, reasons: list[str]
) -> None:
    if not isinstance(manifest, dict):
        reasons.append("manifest is missing the files inventory")
        return
    if manifest.get("algorithm") != "sha256":
        reasons.append(
            f"manifest algorithm must be exactly 'sha256', got {manifest.get('algorithm')!r}"
        )
        return
    files = manifest.get("files")
    if not isinstance(files, dict):
        reasons.append("manifest is missing the files inventory")
        return
    if not files:
        reasons.append("manifest files inventory is empty; no artifact is anchored")
        return
    _validate_manifest_files(runs_dir, files, reasons)
    _check_manifest_completeness(runner, runs_dir, files, reasons)
    _check_manifest_receipt(runs_dir, reasons)


def validate_all(
    reg: dict[str, Any],
    records: Any,
    runs_dir: Path,
    manifest: Any,
) -> tuple[list[str], list[dict[str, Any]]]:
    reasons: list[str] = []
    try:
        _check_executing_analyzer(reg)
        runner = _runner(reg)
    except AnalysisError as exc:
        return ([str(exc)], [])
    registration_reasons = runner.validate_registration(reg, check_output_absent=False)
    if registration_reasons:
        return (registration_reasons, [])
    reg_host = reg.get("host")
    reg_cpu = reg_host.get("cpu") if isinstance(reg_host, dict) else None
    reg_model = reg_host.get("cpu_model") if isinstance(reg_host, dict) else None
    if not isinstance(records, list):
        return (["results payload is not a list"], [])
    expected = derive_expected_cases(reg)
    if len(records) != len(expected):
        return (
            [f"expected exactly {len(expected)} records, found {len(records)}"],
            [],
        )
    _validate_manifest(runner, runs_dir, manifest, reasons)
    typed: list[dict[str, Any]] = []
    for idx, (record, exp) in enumerate(zip(records, expected)):
        if not isinstance(record, dict):
            reasons.append(f"record at index {idx} is not an object")
            continue
        row: dict[str, Any] = exp["row"]
        exp_label = expected_label(
            exp["target"], exp["block"], exp["visit_index"], exp["arm"], exp["row_id"]
        )
        for key, want in (
            ("case_index", exp["case_index"]),
            ("target", exp["target"]),
            ("block", exp["block"]),
            ("block_kind", exp["block_kind"]),
            ("visit_index", exp["visit_index"]),
            ("arm", exp["arm"]),
            ("binary_key", exp["binary_key"]),
            ("row", exp["row_id"]),
            ("row_kind", row["kind"]),
            ("label", exp_label),
        ):
            if record.get(key) != want:
                reasons.append(
                    f"record {idx}: {key} is {record.get(key)!r}, expected {want!r}"
                )
        if record.get("exit_code") != 0:
            reasons.append(f"record {idx} ({exp_label}): exit_code is not 0")
        if record.get("error") is not None:
            reasons.append(
                f"record {idx} ({exp_label}): error is {record.get('error')!r}"
            )
        if record.get("timed_out") is not False:
            reasons.append(f"record {idx} ({exp_label}): timed_out flag set")
        if record.get("cancelled") is not False:
            reasons.append(f"record {idx} ({exp_label}): cancelled flag set")
        want_sha = reg["binaries"][exp["binary_key"]]["sha256"]
        for skey in ("binary_sha256_before", "binary_sha256_after"):
            if record.get(skey) != want_sha:
                reasons.append(
                    f"record {idx} ({exp_label}): {skey} does not match "
                    "registered binary fingerprint"
                )
        for hkey in ("host_before", "host_after"):
            hstate = record.get(hkey)
            if not isinstance(hstate, dict):
                reasons.append(
                    f"record {idx} ({exp_label}): {hkey} host capture missing"
                )
                continue
            if hstate.get("chosen_cpu") != reg_cpu:
                reasons.append(
                    f"record {idx} ({exp_label}): {hkey} chosen_cpu "
                    f"{hstate.get('chosen_cpu')!r} != registered host.cpu "
                    f"{reg_cpu!r}"
                )
            if hstate.get("chosen_cpu_model") != reg_model:
                reasons.append(
                    f"record {idx} ({exp_label}): {hkey} chosen_cpu_model "
                    f"{hstate.get('chosen_cpu_model')!r} != registered "
                    f"host.cpu_model {reg_model!r}"
                )
        command = record.get("command")
        want_prefix = ["taskset", "-c", str(reg_cpu)]
        got_prefix = command[:3] if isinstance(command, list) else command
        if not isinstance(command, list) or list(got_prefix) != want_prefix:
            reasons.append(
                f"record {idx} ({exp_label}): command taskset prefix "
                f"{got_prefix!r} != {want_prefix!r} (host cpu binding mismatch)"
            )
        perf = record.get("perf")
        if not isinstance(perf, dict) or not all(
            _is_positive_finite(perf.get(k))
            for k in ("task_clock_ms", "cycles_u", "instructions_u")
        ):
            reasons.append(f"record {idx} ({exp_label}): perf counters invalid")
        case_std = record.get("case_std_ns")
        if not isinstance(case_std, (int, float)) or isinstance(case_std, bool):
            reasons.append(f"record {idx} ({exp_label}): case_std_ns missing")
        else:
            try:
                median_check = case_median_ns(record, row)
                std_check = _case_std_ns(record, row)
            except AnalysisError as exc:
                reasons.append(f"record {idx} ({exp_label}): {exc}")
                continue
            stored_median = record.get("case_median_ns")
            if not isinstance(stored_median, (int, float)) or not math.isclose(
                float(stored_median), median_check, rel_tol=1e-9
            ):
                reasons.append(
                    f"record {idx} ({exp_label}): stored case median does not "
                    "match recomputation from raw data"
                )
            if not math.isfinite(float(case_std)) or float(case_std) < 0:
                reasons.append(
                    f"record {idx} ({exp_label}): case_std_ns {case_std!r} "
                    "is not finite/nonnegative"
                )
            elif not math.isclose(float(case_std), std_check, rel_tol=1e-9):
                reasons.append(
                    f"record {idx} ({exp_label}): stored case_std_ns does not "
                    "match recomputation from raw data"
                )
        if row["kind"] == "criterion":
            sample_path = record.get("criterion_sample_path")
            if not isinstance(sample_path, str) or not Path(sample_path).is_file():
                reasons.append(
                    f"record {idx} ({exp_label}): criterion sample file missing"
                )
        elif row["kind"] == "counted":
            stdout_path = record.get("counted_stdout_path")
            if not isinstance(stdout_path, str) or not Path(stdout_path).is_file():
                reasons.append(
                    f"record {idx} ({exp_label}): counted stdout file missing"
                )
            if record.get("counted_warmups_seen") != 1:
                reasons.append(f"record {idx} ({exp_label}): counted warmups seen != 1")
            warmups = record.get("counted_warmup_samples")
            if (
                not isinstance(warmups, list)
                or len(warmups) != 1
                or not all(isinstance(obj, dict) for obj in warmups)
            ):
                reasons.append(
                    f"record {idx} ({exp_label}): counted raw warmup object "
                    "not retained"
                )
            samples_seen = record.get("counted_samples")
            if (
                not isinstance(samples_seen, list)
                or len(samples_seen) != 10
                or not all(isinstance(obj, dict) for obj in samples_seen)
            ):
                reasons.append(
                    f"record {idx} ({exp_label}): counted raw measured sample "
                    "objects not retained"
                )
        else:
            stdout_path = record.get("node_stdout_path")
            if not isinstance(stdout_path, str) or not Path(stdout_path).is_file():
                reasons.append(f"record {idx} ({exp_label}): node stdout file missing")
            if record.get("node_warmups_seen") != 3:
                reasons.append(f"record {idx} ({exp_label}): node warmups seen != 3")
            node_corpus = record.get("node_corpus")
            reg_corpus = reg.get("corpus") if isinstance(reg, dict) else None
            if not isinstance(node_corpus, dict) or not isinstance(reg_corpus, dict):
                reasons.append(
                    f"record {idx} ({exp_label}): node corpus identity missing"
                )
            elif dict(node_corpus) != dict(reg_corpus):
                reasons.append(
                    f"record {idx} ({exp_label}): node corpus {dict(node_corpus)!r} "
                    f"!= pinned {dict(reg_corpus)!r}"
                )
            node_ident_reg = None
            reg_ident = reg.get("node_identity") if isinstance(reg, dict) else None
            if isinstance(reg_ident, dict):
                node_ident_reg = reg_ident.get(str(row.get("node_bench")))
            if not isinstance(node_ident_reg, dict):
                reasons.append(
                    f"record {idx} ({exp_label}): no pinned node_identity for "
                    f"{row.get('node_bench')!r}"
                )
            else:
                samples_seen = record.get("node_samples")
                if not isinstance(samples_seen, list) or len(samples_seen) != 10:
                    reasons.append(
                        f"record {idx} ({exp_label}): node samples not retained"
                    )
                else:
                    bench_name = str(row.get("node_bench"))
                    for sample in samples_seen:
                        if not isinstance(sample, dict):
                            reasons.append(
                                f"record {idx} ({exp_label}): bad node sample"
                            )
                            break
                        ident = sample.get("identity")
                        if not isinstance(ident, dict):
                            reasons.append(
                                f"record {idx} ({exp_label}): sample identity missing"
                            )
                            break
                        if ident.get("engine") != node_ident_reg.get("engine"):
                            reasons.append(
                                f"record {idx} ({exp_label}): sample engine "
                                f"{ident.get('engine')!r} != pinned "
                                f"{node_ident_reg.get('engine')!r}"
                            )
                        if bench_name == "block_to_template_baseline":
                            tips = node_ident_reg.get("tips")
                            sidx = sample.get("sample")
                            if (
                                not isinstance(tips, list)
                                or not isinstance(sidx, int)
                                or sidx < 0
                                or sidx >= len(tips)
                                or ident.get("tip") != tips[sidx]
                            ):
                                reasons.append(
                                    f"record {idx} ({exp_label}): sample {sidx} "
                                    f"tip {ident.get('tip')!r} != pinned "
                                    "tips[sidx] (distinct target block per sample)"
                                )
                        elif ident.get("tip") != node_ident_reg.get("tip"):
                            reasons.append(
                                f"record {idx} ({exp_label}): sample tip "
                                f"{ident.get('tip')!r} != pinned "
                                f"{node_ident_reg.get('tip')!r}"
                            )
                        for field in (
                            "pool_txs",
                            "background_txs",
                            "pool_at_template",
                            "block_txs",
                            "block_noncoinbase",
                            "tip_height",
                        ):
                            if field in node_ident_reg and ident.get(
                                field
                            ) != node_ident_reg.get(field):
                                reasons.append(
                                    f"record {idx} ({exp_label}): sample {field} "
                                    f"{ident.get(field)!r} != pinned "
                                    f"{node_ident_reg.get(field)!r}"
                                )
        typed.append(record)
    return reasons, typed


def _visit_medians(
    records: list[dict[str, Any]], row: dict[str, Any]
) -> dict[str, list[float]]:
    by_arm: dict[str, list[float]] = {"candidate": [], "control": [], "zero": []}
    order: dict[str, list[int]] = {"candidate": [], "control": [], "zero": []}
    for record in records:
        by_arm[str(record["arm"])].append(float(record["case_median_ns"]))  # type: ignore[arg-type]
        order[str(record["arm"])].append(int(record["visit_index"]))  # type: ignore[arg-type]
    for arm in by_arm:
        paired = sorted(zip(order[arm], by_arm[arm]))
        by_arm[arm] = [v for _, v in paired]
    return by_arm


def _zero_spread(zero_medians: list[float]) -> float:
    lo, hi = min(zero_medians), max(zero_medians)
    if lo <= 0:
        return float("inf")
    return hi / lo - 1.0


def _zero_freq_ok(
    records: list[dict[str, Any]], label: str, failures: list[str]
) -> float:
    cand = [_freq_khz(r) for r in records if r.get("arm") == "candidate"]
    zero = [_freq_khz(r) for r in records if r.get("arm") == "zero"]
    ratio = _freq_ratio(cand, zero)
    if ratio > FREQ_RATIO_MAX:
        failures.append(
            f"{label}: zero-block effective-frequency ratio {ratio:.6f} > 1.03"
        )
    return ratio


def _measure_freq_ok(
    records: list[dict[str, Any]], label: str, failures: list[str]
) -> None:
    cand = [_freq_khz(r) for r in records if r.get("arm") == "candidate"]
    ctrl = [_freq_khz(r) for r in records if r.get("arm") == "control"]
    overall = _freq_ratio(cand, ctrl)
    if overall > FREQ_RATIO_MAX:
        failures.append(
            f"{label}: overall effective-frequency ratio {overall:.6f} > 1.03"
        )
    for block in MEASURE_BLOCKS:
        c_block = [
            _freq_khz(r)
            for r in records
            if r.get("arm") == "candidate" and r.get("block") == block
        ]
        t_block = [
            _freq_khz(r)
            for r in records
            if r.get("arm") == "control" and r.get("block") == block
        ]
        if not c_block or not t_block:
            failures.append(f"{label}: block {block} missing arm data for frequency")
            continue
        ratio = _freq_ratio(c_block, t_block)
        if ratio > FREQ_RATIO_MAX:
            failures.append(
                f"{label}: block {block} effective-frequency ratio {ratio:.6f} > 1.03"
            )


def _case_stability_ok(
    records: list[dict[str, Any]], label: str, failures: list[str]
) -> None:
    for record in records:
        median = float(record["case_median_ns"])  # type: ignore[arg-type]
        std = float(record["case_std_ns"])  # type: ignore[arg-type]
        ratio = std / median if median > 0 else float("inf")
        if ratio > CASE_STDDEV_RATIO_MAX:
            failures.append(
                f"{label}: case {record.get('label')} std/median {ratio:.6f} > 0.20"
            )


def _spread_ok(
    medians: list[float], arm: str, label: str, failures: list[str]
) -> float:
    lo, hi = min(medians), max(medians)
    spread = hi / lo if lo > 0 else float("inf")
    if spread >= ARM_SPREAD_MAX:
        failures.append(f"{label}: arm {arm} visit-median spread {spread:.6f} >= 1.15")
    return spread


def _stability_ok(
    medians: list[float], arm: str, label: str, failures: list[str]
) -> None:
    center = _median(medians)
    worst = (
        max(abs(v - center) / center for v in medians) if center > 0 else float("inf")
    )
    if worst > ARM_STABILITY_BAND:
        failures.append(
            f"{label}: arm {arm} visit median deviates {worst:.6f} > 0.05 "
            "from its own median"
        )


def _visit_estimates(
    record: dict[str, Any], row: dict[str, Any], arm: str
) -> list[float]:
    if row["kind"] == "node":
        samples = record.get("node_samples")
        if not isinstance(samples, list) or len(samples) != 10:
            raise AnalysisError(
                f"record {record.get('label')}: node measured inventory mismatch"
            )
        return [_checked_arm_mean_ns(record.get("label"), s, arm) for s in samples]
    if row["kind"] == "counted":
        _, _, normalized, _, _ = _counted_validated(record, row)
        return normalized
    vals = record.get("normalized_ns")
    if not isinstance(vals, list) or len(vals) != 10:
        raise AnalysisError(
            f"record {record.get('label')}: expected 10 normalized sample "
            "estimates per visit"
        )
    out: list[float] = []
    for v in vals:
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            raise AnalysisError(
                f"record {record.get('label')}: non-numeric sample estimate"
            )
        out.append(float(v))
    return out


def _five_pct_visits_ok(
    records: list[dict[str, Any]],
    row: dict[str, Any],
    arm: str,
    scope: str,
    label: str,
    failures: list[str],
) -> None:
    for record in records:
        try:
            ests = _visit_estimates(record, row, arm)
        except AnalysisError as exc:
            failures.append(f"{label}: {exc}")
            continue
        center = _median(ests)
        if center <= 0:
            failures.append(
                f"{label}: {scope} visit {record.get('label')} has non-positive median"
            )
            continue
        worst = max(abs(v - center) / center for v in ests)
        if worst > ARM_STABILITY_BAND:
            failures.append(
                f"{label}: {scope} visit {record.get('label')} sample estimate "
                f"deviates {worst:.6f} > 0.05 from its visit median "
                "(10 estimates per visit)"
            )


def _five_pct_arm_ok(
    medians: list[float], arm: str, scope: str, label: str, failures: list[str]
) -> None:
    if not medians:
        failures.append(f"{label}: {scope} arm {arm} has no visit medians")
        return
    center = _median(medians)
    if center <= 0:
        failures.append(f"{label}: {scope} arm {arm} has non-positive median")
        return
    worst = max(abs(v - center) / center for v in medians)
    if worst > ARM_STABILITY_BAND:
        failures.append(
            f"{label}: {scope} arm {arm} visit median deviates {worst:.6f} "
            "> 0.05 from its arm median "
            f"({len(medians)} visit medians)"
        )


def _node_visit_medians(
    records: list[dict[str, Any]], row: dict[str, Any], arm_name: str
) -> dict[str, list[float]]:
    by_arm: dict[str, list[float]] = {"candidate": [], "control": [], "zero": []}
    for record in records:
        by_arm[str(record["arm"])].append(_node_arm_median_ns(record, row, arm_name))
    for arm in by_arm:
        by_arm[arm] = sorted(by_arm[arm])
    return by_arm


def _analyze_gated_row(
    target: str,
    row: dict[str, Any],
    records: list[dict[str, Any]],
    scalar_arm: str | None = None,
) -> dict[str, Any]:
    label = f"{target}/{row['id']}"
    zero = [r for r in records if r.get("block_kind") == "zero"]
    measure = [r for r in records if r.get("block_kind") == "measure"]
    failures: list[str] = []
    if row["kind"] == "node":
        arm = scalar_arm or _node_primary_arm(str(row["node_bench"]))
        medians = _node_visit_medians(measure, row, arm)
    else:
        arm = ""
        medians = _visit_medians(measure, row)
    if row["kind"] == "node":
        zero_meds = [_node_arm_median_ns(r, row, arm) for r in zero]
    else:
        zero_meds = [float(r["case_median_ns"]) for r in zero]  # type: ignore[arg-type]
    zero_noise = _zero_spread(zero_meds)
    _zero_freq_ok(zero, label, failures)
    _measure_freq_ok(measure, label, failures)
    role = str(row["role"])
    if role == "acceptance":
        _case_stability_ok(measure, label, failures)
        _case_stability_ok(zero, label, failures)
        spread_c = _spread_ok(medians["candidate"], "candidate", label, failures)
        spread_t = _spread_ok(medians["control"], "control", label, failures)
        zero_by_arm = (
            _visit_medians(zero, row)
            if row["kind"] != "node"
            else _node_visit_medians(zero, row, arm)
        )
        for zarm in ("candidate", "zero"):
            if zero_by_arm[zarm]:
                _spread_ok(zero_by_arm[zarm], f"zero-{zarm}", label, failures)
    else:
        _five_pct_visits_ok(measure, row, arm, "measured", label, failures)
        _five_pct_visits_ok(zero, row, arm, "zero", label, failures)
        _five_pct_arm_ok(medians["candidate"], "candidate", "measured", label, failures)
        _five_pct_arm_ok(medians["control"], "control", "measured", label, failures)
        _five_pct_arm_ok(zero_meds, "zero-combined", "zero", label, failures)
        spread_c = max(medians["candidate"]) / min(medians["candidate"])
        spread_t = max(medians["control"]) / min(medians["control"])
    m_cand = _median(medians["candidate"])
    m_ctrl = _median(medians["control"])
    s_cand = _stdev(medians["candidate"])
    s_ctrl = _stdev(medians["control"])
    regression = (m_cand - m_ctrl) > (s_cand + s_ctrl)
    ratio = m_ctrl / m_cand if m_cand > 0 else float("inf")
    if m_ctrl > 0 and math.isfinite(m_ctrl) and math.isfinite(m_cand):
        reduction = (m_ctrl - m_cand) / m_ctrl
        s_bound = (s_cand + s_ctrl) / m_ctrl
    else:
        reduction = float("-inf")
        s_bound = float("inf")
    above_zero = reduction > zero_noise if math.isfinite(reduction) else False
    above_s = reduction > s_bound if math.isfinite(reduction) else False
    above_noise = bool(above_zero and above_s)
    pooled: dict[str, dict[str, float]] = {}
    for arm_label in ("candidate", "control"):
        if row["kind"] == "node":
            pool = _node_pool_ns(
                [r for r in measure if r.get("arm") == arm_label], row, arm
            )
        else:
            pool = []
            for record in measure:
                if record.get("arm") == arm_label:
                    vals = record.get("normalized_ns")
                    if isinstance(vals, list):
                        pool.extend(float(v) for v in vals)  # type: ignore[arg-type]
        if not pool:
            raise AnalysisError(f"{label}: empty pooled values for arm {arm_label}")
        pooled[arm_label] = _percentiles(pool)
    row_out: dict[str, Any] = {
        "row": row["id"],
        "role": role,
        "population_visit_medians": (
            "6 visit medians per measured arm (candidate/control); each "
            "visit median is the median of that visit's 10 normalized "
            "sample estimates (criterion times[i]/iters[i]/units_per_iter; "
            "counted total_ns/unit_count per retained sample object; "
            "node total_ns/count per sample); sample-estimate distribution, "
            "not per-operation latencies; M is the median of the 6, S their "
            "sample stdev; zero block holds 4 same-binary visit medians"
        ),
        "population_pooled": (
            "node: pooled raw unit durations in ns across all measurement "
            "visits of one arm (the harness percentile population); "
            "descriptive only -- few samples cannot establish a trustworthy "
            "population p99, never a per-operation tail claim"
            if row["kind"] == "node"
            else "criterion/counted: pooled normalized per-iteration values "
            "(criterion times[i]/iters[i]/units_per_iter; counted "
            "total_ns/unit_count per retained sample object, never raw "
            "units) across all measurement visits of one arm; p99 by "
            "linear interpolation at (n-1)*0.99; descriptive -- few "
            "samples cannot establish a trustworthy population p99"
        ),
        "candidate_visit_medians_ns": medians["candidate"],
        "control_visit_medians_ns": medians["control"],
        "M_candidate_ns": m_cand,
        "M_control_ns": m_ctrl,
        "S_candidate_ns": s_cand,
        "S_control_ns": s_ctrl,
        "spread_candidate": spread_c,
        "spread_control": spread_t,
        "zero_spread": zero_noise,
        "win_ratio_control_over_candidate": ratio,
        "latency_reduction": reduction,
        "s_bound": s_bound,
        "above_zero_spread": above_zero,
        "above_s_bound": above_s,
        "above_zero_noise": above_noise,
        "regression": regression,
        "quality_failures": failures,
        "pooled": pooled,
    }
    return row_out


def _evaluate_t1(
    rows_out: dict[str, dict[str, Any]],
) -> tuple[VerdictKind, bool | None, list[str]]:
    quality: list[str] = []
    for row_id, rout in rows_out.items():
        if rout["role"] in ("acceptance", "guard_keep"):
            quality.extend(rout["quality_failures"])
    if quality:
        return "INCONCLUSIVE", None, quality
    regressions = [
        f"T1/{row_id}: regression evidenced "
        f"(M_cand - M_ctrl = {rout['M_candidate_ns'] - rout['M_control_ns']:.2f} ns "
        f"> S_cand + S_ctrl = {rout['S_candidate_ns'] + rout['S_control_ns']:.2f} ns)"
        for row_id, rout in rows_out.items()
        if rout["role"] == "acceptance" and rout["regression"]
    ]
    if regressions:
        return "REGRESSION", False, regressions
    keeps = {
        row_id: rout
        for row_id, rout in rows_out.items()
        if rout["role"] == "guard_keep"
    }
    if not keeps:
        return (
            "NON_REGRESSION_EVIDENCED",
            False,
            ["T1: no guard_keep rows registered; 50k/100k keep unevaluated"],
        )
    keep_reasons: list[str] = []
    keep_all = True
    for row_id, rout in keeps.items():
        ok = (
            rout["win_ratio_control_over_candidate"] >= WIN_RATIO
            and rout["above_zero_noise"]
        )
        keep_all = keep_all and ok
        keep_reasons.append(
            f"T1/{row_id}: keep={'yes' if ok else 'no'} "
            f"(control/candidate = "
            f"{rout['win_ratio_control_over_candidate']:.4f}, "
            f"above_zero_noise={rout['above_zero_noise']})"
        )
    return "NON_REGRESSION_EVIDENCED", keep_all, keep_reasons


def _t2_component_summary(
    records: list[dict[str, Any]],
) -> dict[str, dict[str, float]]:
    summary: dict[str, dict[str, float]] = {"candidate": {}, "control": {}}
    for arm in ("candidate", "control"):
        buckets: dict[str, list[float]] = {}
        for record in records:
            if record.get("arm") != arm:
                continue
            samples = record.get("node_samples")
            if not isinstance(samples, list):
                continue
            for sample in samples:
                if not isinstance(sample, dict):
                    continue
                components = sample.get("components")
                if not isinstance(components, dict):
                    continue
                for field, arr in components.items():
                    if (
                        isinstance(arr, list)
                        and arr
                        and all(type(v) is int for v in arr)
                    ):
                        buckets.setdefault(field, []).append(
                            sum(arr) / len(arr) * 1000.0
                        )
        for field, vals in buckets.items():
            summary[arm][field] = _median(vals)
    return summary


def _evaluate_t2(
    rows_out: dict[str, dict[str, Any]],
    records_by_row: dict[str, list[dict[str, Any]]],
) -> tuple[VerdictKind, bool | None, list[str]]:
    primaries = [r for r in rows_out.values() if r["role"] == "primary"]
    if len(primaries) != 1:
        return (
            "INCONCLUSIVE",
            None,
            [f"T2: expected exactly one primary row, found {len(primaries)}"],
        )
    prout = primaries[0]
    if prout["quality_failures"]:
        return "INCONCLUSIVE", None, list(prout["quality_failures"])
    prout["components_descriptive"] = _t2_component_summary(
        [r for r in records_by_row[prout["row"]] if r.get("block_kind") == "measure"]
    )
    prout["components_population"] = (
        "per-arm median of per-sample component means in ns; "
        "descriptive only, no per-component gate"
    )
    diff = prout["M_candidate_ns"] - prout["M_control_ns"]
    noise = prout["S_candidate_ns"] + prout["S_control_ns"]
    if diff > noise:
        return (
            "REGRESSION",
            False,
            [f"T2/{prout['row']}: regression evidenced ({diff:.2f} > {noise:.2f})"],
        )
    ctrl_records = [
        r
        for r in records_by_row[prout["row"]]
        if r.get("arm") == "control" and r.get("block_kind") == "measure"
    ]
    tail_vals: list[float] = []
    asm_vals: list[float] = []
    for record in ctrl_records:
        samples = record.get("node_samples")
        if not isinstance(samples, list) or len(samples) != 10:
            return "INCONCLUSIVE", None, ["T2: control node samples missing"]
        for sample in samples:
            if not isinstance(sample, dict):
                return "INCONCLUSIVE", None, ["T2: bad control sample"]
            components = sample.get("components")
            arms = sample.get("arms")
            if not isinstance(components, dict) or not isinstance(arms, dict):
                return "INCONCLUSIVE", None, ["T2: control arms/components missing"]
            asm_arr = components.get(ASSEMBLY_FIELD)
            tail_group = arms.get("tail_to_reply")
            if (
                not isinstance(asm_arr, list)
                or not asm_arr
                or not all(type(v) is int and v >= 0 for v in asm_arr)
                or not isinstance(tail_group, dict)
                or not _is_positive_finite(tail_group.get("mean"))
            ):
                return (
                    "INCONCLUSIVE",
                    None,
                    [f"T2: {ASSEMBLY_FIELD}/tail data invalid; fail closed"],
                )
            asm_vals.append(sum(asm_arr) / len(asm_arr) * 1000.0)
            tail_vals.append(float(tail_group["mean"]))  # type: ignore[arg-type]
    if not asm_vals or not tail_vals or _median(tail_vals) <= 0:
        return "INCONCLUSIVE", None, ["T2: control assembly/tail empty; fail closed"]
    share = _median(asm_vals) / _median(tail_vals)
    if share < AT_FLOOR_MAX:
        return (
            "AT_FLOOR",
            False,
            [
                f"T2: median(assembly_ns)/median(tail_ns) = {share:.4f} < 0.05 "
                "on the usable control arm (components explicitly us->ns); "
                "at floor, nothing to promote"
            ],
        )
    ok = (
        prout["win_ratio_control_over_candidate"] >= WIN_RATIO
        and prout["above_zero_noise"]
    )
    return (
        "NON_REGRESSION_EVIDENCED",
        ok,
        [
            f"T2/{prout['row']}: control/candidate = "
            f"{prout['win_ratio_control_over_candidate']:.4f}, "
            f"above_zero_noise={prout['above_zero_noise']} "
            f"(reduction above both zero spread and S-bound), "
            f"assembly_share={share:.4f}"
        ],
    )


def _evaluate_t3(
    rows_out: dict[str, dict[str, Any]],
    records_by_row: dict[str, list[dict[str, Any]]],
) -> tuple[VerdictKind, bool | None, list[str]]:
    primaries = [r for r in rows_out.values() if r["role"] == "primary"]
    colds = [r for r in rows_out.values() if r["role"] == "cold"]
    if len(primaries) != 1:
        return (
            "INCONCLUSIVE",
            None,
            [f"T3: expected exactly one primary row, found {len(primaries)}"],
        )
    if len(colds) != 1:
        return (
            "INCONCLUSIVE",
            None,
            [f"T3: expected the cold arm from the same record, found {len(colds)}"],
        )
    problems: list[str] = []
    for rout in primaries + colds:
        problems.extend(rout["quality_failures"])
    if problems:
        return "INCONCLUSIVE", None, problems
    prout = primaries[0]
    regressions: list[str] = []
    for rout in primaries + colds:
        diff = rout["M_candidate_ns"] - rout["M_control_ns"]
        noise = rout["S_candidate_ns"] + rout["S_control_ns"]
        if diff > noise:
            regressions.append(
                f"T3/{rout['row']}: regression evidenced ({diff:.2f} > {noise:.2f})"
            )
    if regressions:
        return "REGRESSION", False, regressions
    ok = (
        prout["win_ratio_control_over_candidate"] >= WIN_RATIO
        and prout["above_zero_noise"]
    )
    return (
        "NON_REGRESSION_EVIDENCED",
        ok,
        [
            f"T3/{prout['row']}: control/candidate = "
            f"{prout['win_ratio_control_over_candidate']:.4f}, "
            f"above_zero_noise={prout['above_zero_noise']} "
            f"(reduction above both zero spread and S-bound; cold from same record)"
        ],
    )


def _evaluate_t4(
    rows_out: dict[str, dict[str, Any]],
) -> tuple[VerdictKind, bool | None, list[str]]:
    primaries = [r for r in rows_out.values() if r["role"] == "primary"]
    guards = [r for r in rows_out.values() if r["role"] == "connect_guard"]
    if len(primaries) != 1:
        return (
            "INCONCLUSIVE",
            None,
            [f"T4: expected exactly one primary row, found {len(primaries)}"],
        )
    problems: list[str] = []
    for rout in primaries + guards:
        problems.extend(rout["quality_failures"])
    if problems:
        return "INCONCLUSIVE", None, problems
    prout = primaries[0]
    diff = prout["M_candidate_ns"] - prout["M_control_ns"]
    noise = prout["S_candidate_ns"] + prout["S_control_ns"]
    if diff > noise:
        return (
            "REGRESSION",
            False,
            [f"T4/{prout['row']}: regression evidenced ({diff:.2f} > {noise:.2f})"],
        )
    guard_hits: list[str] = []
    for rout in guards:
        med_reg = (rout["M_candidate_ns"] - rout["M_control_ns"]) / rout["M_control_ns"]
        p99_cand = rout["pooled"]["candidate"]["p99"]
        p99_ctrl = rout["pooled"]["control"]["p99"]
        p99_reg = (p99_cand - p99_ctrl) / p99_ctrl if p99_ctrl > 0 else float("inf")
        if med_reg > GUARD_MEDIAN_MAX:
            guard_hits.append(
                f"T4/{rout['row']}: connect median regression {med_reg:.4f} > 0.03"
            )
        if p99_reg > GUARD_P99_MAX:
            guard_hits.append(
                f"T4/{rout['row']}: connect p99 regression {p99_reg:.4f} > 0.05 "
                "(p99 over pooled normalized sample values; descriptive, "
                "few samples cannot establish a trustworthy population p99)"
            )
    if guard_hits:
        return "REGRESSION", False, guard_hits
    ok = (
        prout["win_ratio_control_over_candidate"] >= WIN_RATIO
        and prout["above_zero_noise"]
    )
    return (
        "NON_REGRESSION_EVIDENCED",
        ok,
        [
            f"T4/{prout['row']}: control/candidate = "
            f"{prout['win_ratio_control_over_candidate']:.4f}, "
            f"above_zero_noise={prout['above_zero_noise']}"
        ],
    )


def analyze(
    reg: dict[str, Any],
    records: Any,
    runs_dir: Path,
    manifest: Any,
) -> dict[str, Any]:
    try:
        reasons, typed = validate_all(reg, records, runs_dir, manifest)
    except (AnalysisError, KeyError, TypeError, AttributeError) as exc:
        reasons = [f"registration/results shape invalid: {exc}"]
        typed = []
    arm_hashes: dict[str, str] = {}
    binaries = reg.get("binaries") if isinstance(reg, dict) else {}
    if isinstance(binaries, dict):
        for key, entry in binaries.items():
            if isinstance(entry, dict) and isinstance(entry.get("sha256"), str):
                arm_hashes[key] = entry["sha256"]
    scripts = reg.get("scripts") if isinstance(reg, dict) else None
    script_hashes: dict[str, str] = {}
    if isinstance(scripts, dict):
        for name, entry in scripts.items():
            if isinstance(entry, dict) and isinstance(entry.get("sha256"), str):
                script_hashes[name] = entry["sha256"]
    base_meta = {
        "record_count": len(records) if isinstance(records, list) else 0,
        "binary_sha256": arm_hashes,
        "script_sha256": script_hashes,
        "validation_passed": not reasons,
        "authorities": AUTHORITIES,
    }
    if reasons:
        return {
            "verdict": "INCONCLUSIVE",
            "reasons": reasons,
            "targets": {},
            "metadata": base_meta,
        }
    targets_out: dict[str, Any] = {}
    overall: VerdictKind = "NON_REGRESSION_EVIDENCED"
    overall_reasons: list[str] = []
    for target in TARGET_ORDER:
        rows: list[dict[str, Any]] = reg["targets"][target]["rows"]
        rows_out: dict[str, dict[str, Any]] = {}
        records_by_row: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            recs = [
                r
                for r in typed
                if r.get("target") == target and r.get("row") == row["id"]
            ]
            records_by_row[row["id"]] = recs
            if row["role"] in GATED_ROLES:
                override = "rpc_miss" if row["role"] == "cold" else None
                try:
                    rows_out[row["id"]] = _analyze_gated_row(
                        target, row, recs, override
                    )
                except (AnalysisError, KeyError, TypeError) as exc:
                    rows_out[row["id"]] = {
                        "row": row["id"],
                        "role": row["role"],
                        "quality_failures": [f"{target}/{row['id']}: {exc}"],
                    }
                if (
                    target == "T3"
                    and row["role"] == "primary"
                    and row.get("kind") == "node"
                ):
                    try:
                        cold_out = _analyze_gated_row(target, row, recs, "rpc_miss")
                        cold_out["row"] = row["id"]
                        cold_out["role"] = "cold"
                        rows_out[row["id"] + ":cold"] = cold_out
                    except (AnalysisError, KeyError, TypeError) as exc:
                        rows_out[row["id"] + ":cold"] = {
                            "row": row["id"],
                            "role": "cold",
                            "quality_failures": [f"{target}/{row['id']}: {exc}"],
                        }
            else:
                medians = _visit_medians(
                    [r for r in recs if r.get("block_kind") == "measure"], row
                )
                rows_out[row["id"]] = {
                    "row": row["id"],
                    "role": row["role"],
                    "disposition": "descriptive only; no gate applied",
                    "population_visit_medians": (
                        "6 visit medians per measured arm; each visit median "
                        "is the median of that visit's 10 normalized sample "
                        "estimates (sample-estimate distribution, not "
                        "per-operation latencies)"
                    ),
                    "candidate_visit_medians_ns": medians["candidate"],
                    "control_visit_medians_ns": medians["control"],
                }
        if target == "T1":
            verdict, keep, treasons = _evaluate_t1(rows_out)
        elif target == "T2":
            verdict, keep, treasons = _evaluate_t2(rows_out, records_by_row)
        elif target == "T3":
            verdict, keep, treasons = _evaluate_t3(rows_out, records_by_row)
        else:
            verdict, keep, treasons = _evaluate_t4(rows_out)
        targets_out[target] = {
            "verdict": verdict,
            "keep": keep,
            "reasons": treasons,
            "rows": rows_out,
        }
        if verdict == "INCONCLUSIVE":
            overall = "INCONCLUSIVE"
            overall_reasons.extend(treasons)
        elif verdict == "REGRESSION" and overall != "INCONCLUSIVE":
            overall = "REGRESSION"
            overall_reasons.extend(treasons)
    if overall == "NON_REGRESSION_EVIDENCED":
        keeps = {t: targets_out[t]["keep"] for t in TARGET_ORDER}
        overall_reasons = [f"per-target keep flags: {keeps}"]
    return {
        "verdict": overall,
        "reasons": overall_reasons,
        "targets": targets_out,
        "metadata": base_meta,
    }


def parse_args(args: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="MRP campaign analyzer: fail-closed verdicts from raw data",
        allow_abbrev=False,
    )
    parser.add_argument("--registration", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    return parser.parse_args(args)


def main() -> int:
    args = parse_args()
    reg, reg_err = load_json_file(args.registration, "registration")
    results, res_err = load_json_file(args.results, "results")
    manifest, man_err = load_json_file(args.manifest, "manifest")
    fatal = [e for e in (reg_err, res_err, man_err) if e is not None]
    if fatal:
        print(
            json.dumps(
                {
                    "verdict": "INCONCLUSIVE",
                    "reasons": fatal,
                    "targets": {},
                    "metadata": {
                        "record_count": 0,
                        "binary_sha256": {},
                        "validation_passed": False,
                        "authorities": AUTHORITIES,
                    },
                },
                indent=2,
            )
        )
        return 0
    if not isinstance(reg, dict):
        print(
            json.dumps(
                {
                    "verdict": "INCONCLUSIVE",
                    "reasons": ["registration root must be a JSON object"],
                    "targets": {},
                    "metadata": {
                        "record_count": 0,
                        "binary_sha256": {},
                        "validation_passed": False,
                        "authorities": AUTHORITIES,
                    },
                },
                indent=2,
            )
        )
        return 0
    runs_dir = args.manifest.parent
    verdict = analyze(reg, results, runs_dir, manifest)
    print(json.dumps(verdict, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
