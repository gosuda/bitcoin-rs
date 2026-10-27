#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Adversarial smoke test for the measured-campaign runner and analyzer.

Usage (no arguments; both scripts default to the siblings of this file):
    uv run --offline --no-project --script \
        tools/benchmark-campaign/test_measured_campaign.py
    python3 tools/benchmark-campaign/test_measured_campaign.py
Optional overrides:
    --runner PATH/to/measured_runner.py \
        --analyzer PATH/to/measured_analyze.py

Both scripts must keep their canonical file names and live in one directory:
the analyzer loads the runner's validator from its registered path with digest-checked loading.

The probe requires Linux/x86 because it exercises the runner's
/proc/cpuinfo model lookup and sched_getaffinity.

It loads the two scripts under test (SUT) and exercises their REAL validation,
parsing and analysis functions plus their launch-nothing CLIs (`validate`,
`plan`, analyzer) on synthetic fixtures. It never launches a workload
process; the one `cmd_run` exit-code check below stubs `execute_case` with
synthetic records so no case process ever starts.

Everything is synthetic and explicitly NOT a campaign registration or sample:
source trees, benches, locks, "executables", receipts and evidence are stub
files hashed for real in a temp dir; raw values are invented constants chosen
to sit on contract boundaries. Node records come from synthetic stdout passed
through the SUT's real `node_case_fields`/`parse_node_stdout`, Criterion
records from synthetic `sample.json` through `criterion_case_fields`, and
counted records (row kind `counted`, the measured-work stopping correction)
from synthetic `MRP_COUNTED_SAMPLE` stdout through the SUT's real
`parse_counted_stdout`/`counted_case_fields` — never a fabricated normalized
record. The counted warmup object is retained raw and its absence or forgery
is refused. T4 p99 stays the percentile of pooled normalized sample
estimates; the probe proves raw-unit percentiles cannot substitute.

Order: the positive phase (complete registration, CLIs, parsers, a full
synthetic campaign analysis) must pass before any adversary result counts.
Exit code 0 iff every check passes; failures are listed as FAIL lines.
"""

import argparse
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
import statistics
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType

# SUT modules and JSON documents are dynamic by nature: the one localized Any.
from typing import Any

Json = dict[str, Any]

RUNNER_FILE = "measured_runner.py"
ANALYZER_FILE = "measured_analyze.py"

RESULTS: list[tuple[str, bool, str]] = []


def check_case(name: str, ok: bool, detail: str) -> None:
    RESULTS.append((name, ok, detail))
    print(
        f"{'PASS' if ok else 'FAIL'} {name}" + ("" if ok else f": {detail}"), flush=True
    )


def load_sut(path: Path, module_name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise SystemExit(
            f"probe prerequisite missing: cannot load {module_name} from {path}"
        )
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


@dataclass(frozen=True)
class Sut:
    run: ModuleType
    ana: ModuleType
    runner_path: Path
    analyzer_path: Path


# --------------------------------------------------------------------------
# Independent pinned inventory (written out from the four common Rust benches;
# deliberately NOT derived from the SUT tables)
# --------------------------------------------------------------------------

TREES = ["candidate", "control_T1", "control_T2", "control_T3", "control_T4"]
BENCH_FILES = {
    "insert_fill": "crates/mempool/benches/insert_fill.rs",
    "candidate": "crates/mining/benches/candidate.rs",
    "sync_pipeline": "crates/node/benches/sync_pipeline.rs",
    "signature_verification": "crates/script/benches/signature_verification.rs",
    # Shared counted sampler (decision contract): one std-only module copied
    # identically into every control and included by a relative #[path] from
    # the three owning bench files. Part of the exact bench-source
    # fingerprint inventory; identical hash across all five roots.
    "measured_samples": "tools/benchmark-support/measured_samples.rs",
    # Shared snapshot-order module: deduplicated chunk-order fingerprint and
    # topological assertion shared by insert_fill and candidate. Same
    # identical-bytes inclusion and fingerprint membership as the sampler.
    "snapshot_order": "tools/benchmark-support/snapshot_order.rs",
}
LOCK_FILES = [
    "Cargo.lock",
    "fuzz/Cargo.lock",
    "tools/ldk/Cargo.lock",
    "tools/compact-filter-interop/Cargo.lock",
    "tools/stratum-sv2/template-provider/Cargo.lock",
]
# (id, kind, role, bench target, semantic units per iteration)
RowSpec = tuple[str, str, str, str, int]
# Kind `counted` marks the measured-work stopping correction rows
# (docs/benchmarks/measured-campaign.md#counted-samples): argv
# [--mrp-counted, full ID], samples=10, units_per_iter=1, one warmup sample
# excluded from statistics.
# Roles are unchanged; row and visit totals are unchanged.
ROWS: dict[str, list[RowSpec]] = {
    "T1": [
        ("mempool_insert_entry/fill/200", "criterion", "acceptance", "insert_fill", 1),
        ("mempool_insert_entry/fill/800", "criterion", "acceptance", "insert_fill", 1),
        ("mempool_insert_entry/fill/3200", "criterion", "acceptance", "insert_fill", 1),
        (
            "mempool_insert_entry/fill/12800",
            "criterion",
            "acceptance",
            "insert_fill",
            1,
        ),
        (
            "mempool_insert_entry/fill/51200",
            "criterion",
            "acceptance",
            "insert_fill",
            1,
        ),
        (
            "mempool_insert_entry/fill/63-member-cluster",
            "counted",
            "report_only",
            "insert_fill",
            1,
        ),
        ("assemble_candidate/end_to_end/0", "criterion", "report_only", "candidate", 1),
        (
            "assemble_candidate/end_to_end/64",
            "criterion",
            "report_only",
            "candidate",
            1,
        ),
        (
            "assemble_candidate/end_to_end/512",
            "criterion",
            "report_only",
            "candidate",
            1,
        ),
        (
            "assemble_candidate/end_to_end/2048",
            "criterion",
            "report_only",
            "candidate",
            1,
        ),
        (
            "assemble_candidate/end_to_end/20000",
            "criterion",
            "report_only",
            "candidate",
            1,
        ),
        (
            "assemble_candidate/end_to_end/50000",
            "criterion",
            "guard_keep",
            "candidate",
            1,
        ),
        (
            "assemble_candidate/end_to_end/100000",
            "criterion",
            "guard_keep",
            "candidate",
            1,
        ),
        (
            "assemble_candidate/end_to_end/chains/depth-25",
            "criterion",
            "report_only",
            "candidate",
            1,
        ),
        (
            "mining_snapshot_operation/mining_snapshot/64",
            "counted",
            "report_only",
            "candidate",
            1,
        ),
        (
            "mining_snapshot_operation/mining_snapshot/512",
            "counted",
            "report_only",
            "candidate",
            1,
        ),
        (
            "mining_snapshot_operation/mining_snapshot/2048",
            "counted",
            "report_only",
            "candidate",
            1,
        ),
        (
            "mining_snapshot_operation/mining_snapshot/20000",
            "counted",
            "report_only",
            "candidate",
            1,
        ),
        (
            "mining_snapshot_operation/mining_snapshot/50000",
            "counted",
            "report_only",
            "candidate",
            1,
        ),
        (
            "mining_snapshot_operation/mining_snapshot/100000",
            "counted",
            "report_only",
            "candidate",
            1,
        ),
        (
            "mining_snapshot_operation/mining_snapshot/chains/depth-25",
            "counted",
            "report_only",
            "candidate",
            1,
        ),
        (
            "indexed_selection_read_guard/read_guard/100000",
            "counted",
            "report_only",
            "candidate",
            1,
        ),
    ],
    "T2": [
        ("block_to_template_baseline", "node", "primary", "sync_pipeline", 1),
    ],
    "T3": [
        ("template_render_baseline", "node", "primary", "sync_pipeline", 1),
    ],
    "T4": [
        (
            "connect_admission_throughput/flat",
            "counted",
            "primary",
            "sync_pipeline",
            1,
        ),
        (
            "connect_admitted_signed_spend_block/flat",
            "counted",
            "connect_guard",
            "sync_pipeline",
            1,
        ),
        (
            "connect_unseen_signed_spend_block/flat",
            "counted",
            "connect_guard",
            "sync_pipeline",
            1,
        ),
        (
            "signature_verification/ecdsa/hit",
            "criterion",
            "diagnostic",
            "signature_verification",
            64,
        ),
        (
            "signature_verification/ecdsa/miss",
            "criterion",
            "diagnostic",
            "signature_verification",
            64,
        ),
        (
            "signature_verification/schnorr/hit",
            "criterion",
            "diagnostic",
            "signature_verification",
            64,
        ),
        (
            "signature_verification/schnorr/miss",
            "criterion",
            "diagnostic",
            "signature_verification",
            64,
        ),
    ],
}
ALL_ROWS = [(t, spec) for t in ("T1", "T2", "T3", "T4") for spec in ROWS[t]]
GATED_PAIRS = [
    ("T1", "insert_fill"),
    ("T1", "candidate"),
    ("T2", "sync_pipeline"),
    ("T3", "sync_pipeline"),
    ("T4", "sync_pipeline"),
]
A_ADMISSION = "connect_admission_throughput/flat"
A_GUARD = "connect_admitted_signed_spend_block/flat"
T2_ROW = "block_to_template_baseline"
T3_ROW = "template_render_baseline"

CORPUS = {
    "prefix_blocks": 10,
    "tip_height": 110,
    "funded_outputs": 40,
    "background": 500,
    "targets": 4,
    "target_spends": 3,
    "total_txs_per_target": 12,
}
T2_IDENTITY: Json = {
    "engine": "native",
    "tips": [f"{i + 1:064x}" for i in range(13)],
    "pool_txs": 500,
    "background_txs": 500,
    "pool_at_template": 480,
    "block_txs": 12,
    "block_noncoinbase": 11,
}
T3_IDENTITY: Json = {
    "engine": "native",
    "tip": "ab" * 32,
    "pool_txs": 500,
    "background_txs": 500,
    "pool_at_template": 480,
    "tip_height": 110,
}
T2_COMPONENTS = (
    "apply_call_to_reply_us",
    "durable_sync_us",
    "durable_commit_us",
    "on_connect_us",
    "assembly_us",
    "remainder_us",
)
T3_IDENTITY_KEYS = {
    "engine",
    "tip",
    "pool_txs",
    "background_txs",
    "pool_at_template",
    "selected_txs",
    "selected_weight",
    "rpc_txs",
    "rpc_data_bytes",
    "tip_height",
    "longpollid",
    "cold_curtime",
    "hit_curtime",
    "mintime",
    "arc_reuse",
}


def sha_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def digest_of(files: dict[str, str]) -> str:
    """Documented identity digest: sha256 of sorted-key compact JSON."""
    return hashlib.sha256(
        json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def reg_row(target: str, spec: RowSpec) -> Json:
    row_id, kind, role, bench, units = spec
    row: Json = {
        "id": row_id,
        "kind": kind,
        "role": role,
        "bench_target": bench,
        "candidate_binary": f"candidate/{bench}",
        "control_binary": f"control_{target}/{bench}",
    }
    if kind == "criterion":
        row["argv"] = ["--bench", "--noplot", "--exact", row_id]
        row["samples"] = 10
        row["units_per_iter"] = units
    elif kind == "counted":
        row["argv"] = ["--mrp-counted", row_id]
        row["samples"] = 10
        row["units_per_iter"] = 1
    else:
        row["argv"] = ["--bench", row_id, "--nocapture"]
        row["node_bench"] = row_id
    return row


# --------------------------------------------------------------------------
# Synthetic stdout / sample builders (NOT measurements)
# --------------------------------------------------------------------------

# Exact key set of one MRP_COUNTED_SAMPLE JSON object (decision contract).
# Typed once so the probe builders, the good-baseline generator and the
# adversary mutations all share one closed shape.
COUNTED_SAMPLE_KEYS = (
    "bench",
    "sample",
    "warmup",
    "unit_ns",
    "unit_count",
    "total_ns",
)
CountedSample = dict  # JSON object with exactly COUNTED_SAMPLE_KEYS above

# Synthetic per-unit duration on the measured floor boundary: five units of
# 200 ms = exactly 1_000_000_000 ns = the 1 s raw floor. Warmup uses the same
# measured-work rule. Zero individual units are legal (positive total only).
COUNTED_WARM_UNITS: list[int] = [150_000_000, 200_000_000, 250_000_000, 400_000_000]
COUNTED_MEASURE_UNITS: list[int] = [200_000_000] * 5
COUNTED_FLOOR_NS = 1_000_000_000
# Campaign case fixtures multiply the visit value by this factor so five
# units cross the floor. The smallest value_fn multiplier is 0.96 (noise
# blocks), so the scale must satisfy 0.96 * scale * 5 >= 1e9: scale 250
# gives 1.2e9 minimum total (BASE 1e6 -> 2.5e8 per unit -> 1.25e9 total).
COUNTED_VALUE_SCALE = 250


def make_counted_obj(
    row_id: str, sample: int, warmup: bool, units: list[int]
) -> CountedSample:
    """One synthetic counted sample object (exact keys, exact sum)."""
    obj: CountedSample = {
        "bench": row_id,
        "sample": sample,
        "warmup": warmup,
        "unit_ns": list(units),
        "unit_count": len(units),
        "total_ns": sum(units),
    }
    if set(obj) != set(COUNTED_SAMPLE_KEYS):
        raise ValueError("counted fixture object drifted from the pinned key set")
    return obj


def good_counted_objs(row_id: str) -> list[CountedSample]:
    """One warmup (index 0, excluded from statistics) + ten measured samples."""
    objs = [make_counted_obj(row_id, 0, True, COUNTED_WARM_UNITS)]
    objs += [
        make_counted_obj(row_id, s, False, COUNTED_MEASURE_UNITS) for s in range(1, 11)
    ]
    return objs


def counted_line(obj: CountedSample) -> str:
    """The wire format: prefix, one ASCII space, compact JSON, newline."""
    return "MRP_COUNTED_SAMPLE " + json.dumps(obj, separators=(",", ":"))


def write_counted_stdout(path: Path, objs: list[CountedSample]) -> None:
    """Auxiliary fixture diagnostics on other lines are legal and ignored."""
    lines = [
        "mrp-counted: synthetic fixture diagnostics (ignored line)",
        *(counted_line(o) for o in objs),
        "mrp-verify: unrelated trailing line retained but ignored",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def corpus_line(c: dict[str, int]) -> str:
    return (
        "block_to_template corpus: "
        f"prefix_blocks={c['prefix_blocks']} tip_height={c['tip_height']} "
        f"funded_outputs={c['funded_outputs']} background={c['background']} "
        f"targets={c['targets']}x{c['target_spends']} "
        f"total_txs_per_target={c['total_txs_per_target']}"
    )


def make_t2_obj(
    sample: int,
    warmup: bool,
    tail_units: list[int],
    asm_units_us: list[int],
    ident: Json,
) -> Json:
    count = len(tail_units)
    obj: Json = {
        "bench": T2_ROW,
        "sample": sample,
        "warmup": warmup,
        "engine": ident["engine"],
        "pool_txs": ident["pool_txs"],
        "background_txs": ident["background_txs"],
        "pool_at_template": ident["pool_at_template"],
        "block_txs": ident["block_txs"],
        "block_noncoinbase": ident["block_noncoinbase"],
        "tip": ident["tips"][sample],
        "unit_ns": list(tail_units),
        "unit_count": count,
        "total_ns": sum(tail_units),
        "boundary": "probe-boundary",
    }
    for field in T2_COMPONENTS:
        obj[field] = list(asm_units_us) if field == "assembly_us" else [1000] * count
    return obj


def make_t3_obj(
    sample: int, warmup: bool, arm_mean_ns: dict[str, int], ident: Json
) -> Json:
    obj: Json = {
        "bench": T3_ROW,
        "sample": sample,
        "warmup": warmup,
        "engine": ident["engine"],
        "pool_txs": ident["pool_txs"],
        "background_txs": ident["background_txs"],
        "pool_at_template": ident["pool_at_template"],
        "selected_txs": 10,
        "selected_weight": 4000,
        "rpc_txs": 10,
        "rpc_data_bytes": 2500,
        "tip": ident["tip"],
        "tip_height": ident["tip_height"],
        "longpollid": f"lp-{sample}",
        "cold_curtime": 100,
        "hit_curtime": 200,
        "mintime": 50,
        "arc_reuse": True,
        "boundary_rpc_miss": "b1",
        "boundary_service_hit": "b2",
        "boundary_rpc_hit": "b3",
    }
    for arm, mean in arm_mean_ns.items():
        units = [mean, mean]
        obj[f"{arm}_ns"] = units
        obj[f"{arm}_count"] = 2
        obj[f"{arm}_total_ns"] = sum(units)
    return obj


def write_stdout(path: Path, objs: list[Json]) -> None:
    """Corpus line, ignored noise lines, then one JSON line per sample."""
    lines = [corpus_line(CORPUS), "mrp-verify: unrelated line retained but ignored"]
    lines += [json.dumps(o) for o in objs]
    lines.append(json.dumps({"percentile": "unrelated", "p50": 1}))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


T2_WARM_UNITS = [1_250_000_000, 1_250_000_000]
T3_WARM_MEANS = {
    "rpc_miss": 1_500_000_000,
    "service_hit": 1_500_000_000,
    "service_hit2": 1_500_000_000,
    "rpc_hit": 1_500_000_000,
}


def good_t2_objs(measured_units: list[int] | None = None) -> list[Json]:
    units = (
        measured_units if measured_units is not None else [1_250_000_000, 1_250_000_000]
    )
    objs = [
        make_t2_obj(s, True, list(T2_WARM_UNITS), [250000, 250000], T2_IDENTITY)
        for s in (0, 1, 2)
    ]
    objs += [
        make_t2_obj(s, False, list(units), [250000, 250000], T2_IDENTITY)
        for s in range(3, 13)
    ]
    return objs


def good_t3_objs() -> list[Json]:
    return [make_t3_obj(s, s < 3, dict(T3_WARM_MEANS), T3_IDENTITY) for s in range(13)]


# --------------------------------------------------------------------------
# Complete synthetic frozen-world fixture (real files, real hashes)
# --------------------------------------------------------------------------


def tree_files(tree: str, extras: dict[str, bytes]) -> dict[str, bytes]:
    files = {
        "Cargo.toml": b"# synthetic stub workspace, not a campaign tree\n",
        "crates/stub/src/lib.rs": f"// synthetic lever stub for {tree}\n".encode(),
    }
    for rel in BENCH_FILES.values():
        files[rel] = f"// synthetic common bench stub {rel}\n".encode()
    for rel in LOCK_FILES:
        files[rel] = f"# synthetic lock stub {rel}\n".encode()
    files.update(extras)
    return files


def walk_hashes(root: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for dirpath, _dirs, filenames in os.walk(root):
        for name in filenames:
            path = Path(dirpath) / name
            out[path.relative_to(root).as_posix()] = sha_of(path)
    return out


def binary_bytes(
    tree: str, bench: str, same_as_candidate: set[tuple[str, str]]
) -> bytes:
    if bench == "signature_verification" and tree in ("candidate", "control_T4"):
        return b"synthetic executable: unchanged script diagnostics build\n"
    if tree == "candidate" or (tree, bench) in same_as_candidate:
        return f"synthetic executable candidate {bench}\n".encode()
    return f"synthetic executable {tree} {bench}\n".encode()


def write_doc(path: Path, doc: Json) -> dict[str, str]:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return {"path": str(path), "sha256": sha_of(path)}


def build_fixture(
    base: Path,
    sut: Sut,
    extras: dict[str, dict[str, bytes]] | None = None,
    symlinks: tuple[tuple[str, str, Path], ...] = (),
    same_as_candidate: frozenset[tuple[str, str]] = frozenset(),
) -> Json:
    """A complete registration over real stub files. Synthetic; nothing runs."""
    extras = extras or {}
    base.mkdir(parents=True, exist_ok=True)
    roots: dict[str, str] = {}
    source_fp: dict[str, dict[str, str]] = {}
    bench_fp: dict[str, dict[str, str]] = {}
    lock_fp: dict[str, dict[str, str]] = {}
    for tree in TREES:
        root = base / "trees" / tree
        for rel, data in tree_files(tree, extras.get(tree, {})).items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        for link_tree, rel, target in symlinks:
            if link_tree == tree:
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                (root / rel).symlink_to(target)
        roots[tree] = str(root)
        source_fp[tree] = walk_hashes(root)
        bench_fp[tree] = {rel: source_fp[tree][rel] for rel in BENCH_FILES.values()}
        lock_fp[tree] = {rel: source_fp[tree][rel] for rel in LOCK_FILES}
    binaries: Json = {}
    keys = sorted(
        {f"candidate/{s[3]}" for _t, s in ALL_ROWS}
        | {f"control_{t}/{s[3]}" for t, s in ALL_ROWS}
    )
    candidate_commit = "a" * 40
    control_transforms = {
        "control_T1": (
            "synthetic single-lever control_T1: disable maintained "
            "cluster-order upkeep"
        ),
        "control_T2": (
            "synthetic single-lever control_T2: neutralize staged-tip "
            "preparation closure"
        ),
        "control_T3": (
            "synthetic single-lever control_T3: empty data_hex plus "
            "uncached signalling"
        ),
        "control_T4": (
            "synthetic single-lever control_T4: omit per-admission "
            "SignatureCache"
        ),
    }
    for key in keys:
        tree, bench = key.split("/")
        exe = base / "bin" / f"{tree}__{bench}"
        exe.parent.mkdir(parents=True, exist_ok=True)
        exe.write_bytes(binary_bytes(tree, bench, set(same_as_candidate)))
        exe.chmod(0o755)
        receipt_doc: Json = {
            "kind": "rbitcoin-mrp-build-receipt",
            "tree": tree,
            "bench_target": bench,
            "source_digest": digest_of(source_fp[tree]),
            "bench_source_sha256": bench_fp[tree][BENCH_FILES[bench]],
            "lock_digest": digest_of(lock_fp[tree]),
            "binary_sha256": sha_of(exe),
            "synthetic": True,
        }
        if tree == "candidate":
            receipt_doc["source_commit"] = candidate_commit
        else:
            receipt_doc["base_commit"] = candidate_commit
            receipt_doc["transform"] = control_transforms[tree]
        receipt = write_doc(
            base / "receipts" / f"{tree}__{bench}.json",
            receipt_doc,
        )
        binaries[key] = {"path": str(exe), "sha256": sha_of(exe), "receipt": receipt}
    scripts = {
        "runner": {"path": str(sut.runner_path), "sha256": sha_of(sut.runner_path)},
        "analyzer": {
            "path": str(sut.analyzer_path),
            "sha256": sha_of(sut.analyzer_path),
        },
    }
    source_evidence = write_doc(
        base / "evidence" / "source.json",
        {
            "kind": "rbitcoin-mrp-baseline-evidence",
            "role": "source",
            "result": "passed",
            "frozen_identity": {
                "trees": {t: digest_of(source_fp[t]) for t in TREES},
                "scripts": {
                    "runner": scripts["runner"]["sha256"],
                    "analyzer": scripts["analyzer"]["sha256"],
                },
            },
            "synthetic": True,
        },
    )
    dependency_evidence = write_doc(
        base / "evidence" / "dependency.json",
        {
            "kind": "rbitcoin-mrp-baseline-evidence",
            "role": "dependency",
            "result": "passed",
            "frozen_identity": {"trees": {t: digest_of(lock_fp[t]) for t in TREES}},
            "synthetic": True,
        },
    )
    try:
        cpu = sorted(os.sched_getaffinity(0))[0]
    except OSError:
        cpu = 0
    # Live-positive fixture uses the observed local CPU model so the real
    # validate/plan live path is meaningful; never an echoed label or mock.
    observed_model = sut.run.read_cpu_model(cpu)
    blocks: list[dict[str, str]] = []
    for target in ("T1", "T2", "T3", "T4"):
        blocks.append({"target": target, "kind": "zero"})
        blocks.extend([{"target": target, "kind": "measure"}] * 3)
    return {
        "status": "registered",
        "campaign_root": str(base / "campaign_absent"),
        "host": {"cpu": cpu, "cpu_model": observed_model},
        "timeout_seconds": 60,
        "scripts": scripts,
        "source_roots": roots,
        "source_fingerprints": source_fp,
        "bench_fingerprints": bench_fp,
        "lock_fingerprints": lock_fp,
        "binaries": binaries,
        "source_baseline_evidence": [source_evidence],
        "dependency_baseline_evidence": [dependency_evidence],
        "corpus": dict(CORPUS),
        "node_identity": {
            T2_ROW: copy.deepcopy(T2_IDENTITY),
            T3_ROW: copy.deepcopy(T3_IDENTITY),
        },
        "targets": {
            t: {
                "control_tree": f"control_{t}",
                "rows": [reg_row(t, spec) for spec in ROWS[t]],
            }
            for t in ("T1", "T2", "T3", "T4")
        },
        "schedule": {"target_order": ["T1", "T2", "T3", "T4"], "blocks": blocks},
    }


# --------------------------------------------------------------------------
# Synthetic campaign records via the SUT's own parsers
# --------------------------------------------------------------------------

PERF = {"task_clock_ms": 1000.0, "cycles_u": 3.0e9, "instructions_u": 2.0e9}
NODE_ROWS = {T2_ROW, T3_ROW}
ValueFn = Callable[[str, str, str, int, int], float]


def split_value(crit: tuple[float, float], node: tuple[float, float]) -> ValueFn:
    def fn(_target: str, row: str, arm: str, _visit: int, _sample: int) -> float:
        cand, ctrl = node if row in NODE_ROWS else crit
        return ctrl if arm == "control" else cand

    return fn


BASE_FN = split_value((1_000_000.0, 1_100_000.0), (2_500_000_000.0, 2_750_000_000.0))
BASE_COLD = split_value((0.0, 0.0), (2_000_000_000.0, 2_000_000_000.0))
INV_FN = split_value((1_100_000.0, 1_000_000.0), (2_750_000_000.0, 2_500_000_000.0))


def build_campaign(
    sut: Sut,
    reg: Json,
    tmp: Path,
    tag: str,
    value_fn: ValueFn,
    cold_fn: ValueFn = BASE_COLD,
    asm_fn: Callable[[str, str, int], int] | None = None,
) -> list[Json]:
    """Per-case records assembled from synthetic files and the SUT's parsers."""
    files = tmp / "synth" / tag
    files.mkdir(parents=True, exist_ok=True)
    records: list[Json] = []
    host_cpu = int(reg["host"]["cpu"])
    host_model = str(reg["host"]["cpu_model"])
    for case in sut.run.derive_cases(reg):
        target, row, arm = case["target"], case["row"], case["arm"]
        visit, block = case["visit_index"], case["block"]
        binary_key = case["binary_key"]
        digest = reg["binaries"][binary_key]["sha256"]
        label = sut.ana.expected_label(target, block, visit, arm, row["id"])
        # Recorded host/taskset binding mirrors execute_case: the pinned
        # taskset prefix plus the captured cpu/model the analyzer binds
        # against the registration (synthetic values, real shape).
        host_capture: Json = {
            "affinity": [host_cpu],
            "chosen_cpu": host_cpu,
            "chosen_cpu_model": host_model,
        }
        record: Json = {
            "case_index": case["case_index"],
            "target": target,
            "block": block,
            "block_kind": case["block_kind"],
            "visit_index": visit,
            "arm": arm,
            "binary_key": binary_key,
            "binary_sha256_before": digest,
            "binary_sha256_after": digest,
            "row": row["id"],
            "row_kind": row["kind"],
            "label": label,
            "command": ["taskset", "-c", str(host_cpu), "synthetic-workload"],
            "host_before": dict(host_capture),
            "host_after": dict(host_capture),
            "exit_code": 0,
            "error": None,
            "timed_out": False,
            "cancelled": False,
            "perf": dict(PERF),
        }
        case_dir = files / f"{case['case_index']:04d}"
        case_dir.mkdir()
        vals = [float(value_fn(target, row["id"], arm, visit, j)) for j in range(10)]
        if row["kind"] == "criterion":
            units = int(row["units_per_iter"])
            payload = json.dumps(
                {
                    "synthetic": True,
                    "iters": [2000.0] * 10,
                    "times": [v * 2000.0 * units for v in vals],
                }
            )
            criterion_home = case_dir / "criterion"
            row_dir = criterion_home / str(row["id"])
            new_sample = row_dir / "new" / "sample.json"
            base_sample = row_dir / "base" / "sample.json"
            new_sample.parent.mkdir(parents=True, exist_ok=True)
            base_sample.parent.mkdir(parents=True, exist_ok=True)
            new_sample.write_text(payload, encoding="utf-8")
            base_sample.write_text(payload, encoding="utf-8")
            found = sut.run.find_single_sample_json(criterion_home)
            if found != new_sample:
                raise SystemExit(
                    "probe prerequisite violated: find_single_sample_json did not "
                    f"select new/sample.json for {row['id']}; got {found}"
                )
            record.update(sut.run.criterion_case_fields(found, row))
        elif row["kind"] == "counted":
            write_counted_case_stdout(sut, case_dir, row, vals, record)
        else:
            stdout = case_dir / "stdout.log"
            write_stdout(
                stdout, node_objs(reg, row, arm, target, visit, vals, cold_fn, asm_fn)
            )
            record.update(sut.run.node_case_fields(stdout, row, reg))
        records.append(record)
    return records


def counted_unit_ns(value: float) -> list[int]:
    """Equal whole-unit durations crossing the floor on the final unit.

    The synthetic visit value (ns, from the value functions) is multiplied
    by COUNTED_VALUE_SCALE, then repeated exactly ceil(floor / per_unit)
    times: the prefix sum stays strictly below the 1 s floor and only the
    last unit reaches it, matching the sampler's first-crossing stopping
    rule (synthetic fixture construction, not a workload multiplier or
    threshold adjustment).
    """
    per_unit = int(round(value * COUNTED_VALUE_SCALE))
    unit_count = (COUNTED_FLOOR_NS + per_unit - 1) // per_unit
    return [per_unit] * unit_count


def write_counted_case_stdout(
    sut: Sut, case_dir: Path, row: Json, vals: list[float], record: Json
) -> None:
    """Emit counted stdout for one synthetic case and parse it via the SUT.

    Each measured sample carries its own value (vals[j]), so candidate and
    control visits produce genuinely different normalized estimates; the
    warmup reuses the visit's first value under the same floor rule.
    """
    stdout = case_dir / "stdout.log"
    objs = [make_counted_obj(row["id"], 0, True, counted_unit_ns(vals[0]))]
    objs += [
        make_counted_obj(row["id"], 1 + j, False, counted_unit_ns(v))
        for j, v in enumerate(vals)
    ]
    write_counted_stdout(stdout, objs)
    record.update(counted_case_fields_via_sut(sut, stdout, row))


def counted_case_fields_via_sut(sut: Sut, stdout: Path, row: Json) -> Json:
    """The counted record fields through the SUT's real counted seam.

    Mirrors the runner's own call shape: parse_counted_stdout + the shared
    validator (validate_counted_samples) + the single counted_case_fields
    entry point. Never fabricates a normalized record.
    """
    row_id = str(row["id"])
    warmups, measured = sut.run.parse_counted_stdout(stdout, row_id)
    fields = sut.run.counted_case_fields(stdout, row)
    wanted = {
        "counted_stdout_path",
        "counted_warmups_seen",
        "counted_warmup_samples",
        "counted_samples",
        "sample_iters",
        "sample_times_ns",
        "normalized_ns",
        "case_median_ns",
        "case_std_ns",
    }
    missing = wanted - set(fields)
    if missing:
        raise SystemExit(
            "probe prerequisite missing: counted_case_fields did not return "
            f"{sorted(missing)} for {row_id}; got keys {sorted(fields)}"
        )
    criterion_leak = [k for k in fields if k.startswith("criterion_")]
    if criterion_leak:
        raise SystemExit(
            "probe prerequisite violated: counted record carries Criterion "
            f"artifact keys {criterion_leak}"
        )
    iters, times, normalized, median, std = sut.run.validate_counted_samples(
        warmups, measured, row_id
    )
    agrees = (
        fields["sample_iters"] == iters
        and fields["sample_times_ns"] == times
        and fields["normalized_ns"] == normalized
        and fields["case_median_ns"] == median
        and fields["case_std_ns"] == std
    )
    if not agrees:
        raise SystemExit(
            "probe prerequisite violated: counted_case_fields disagrees "
            f"with validate_counted_samples for {row_id}"
        )
    return fields


def node_objs(
    reg: Json,
    row: Json,
    arm: str,
    target: str,
    visit: int,
    vals: list[float],
    cold_fn: ValueFn,
    asm_fn: Callable[[str, str, int], int] | None,
) -> list[Json]:
    if row["node_bench"] == T2_ROW:
        asm = asm_fn(target, arm, visit) if asm_fn else 250000
        ident = reg["node_identity"][T2_ROW]
        objs = [
            make_t2_obj(s, True, list(T2_WARM_UNITS), [asm, asm], ident)
            for s in (0, 1, 2)
        ]
        objs += [
            make_t2_obj(3 + j, False, [int(v), int(v)], [asm, asm], ident)
            for j, v in enumerate(vals)
        ]
        return objs
    ident = reg["node_identity"][T3_ROW]
    objs = [make_t3_obj(s, True, dict(T3_WARM_MEANS), ident) for s in (0, 1, 2)]
    for j, v in enumerate(vals):
        cold = cold_fn(target, row["id"], arm, visit, j)
        arms = {
            "rpc_miss": int(cold),
            "service_hit": int(v),
            "service_hit2": int(v),
            "rpc_hit": int(v),
        }
        objs.append(make_t3_obj(3 + j, False, arms, ident))
    return objs


# --------------------------------------------------------------------------
# Check helpers
# --------------------------------------------------------------------------


def run_cli(script: Path, *argv: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(script), *argv],
        capture_output=True,
        text=True,
        timeout=300,
    )


def reject(
    sut: Sut, name: str, reg: Json, mutate: Callable[[Json], None], hint: str
) -> None:
    """Static-path rejection: the offline schema validator must refuse."""
    bad = copy.deepcopy(reg)
    mutate(bad)
    reasons = sut.run.validate_registration(bad, False)
    hit = any(hint in r for r in reasons)
    check_case(
        f"reject-{name}",
        bool(reasons) and hit,
        "accepted an invalid registration"
        if not reasons
        else f"rejected without expected reason {hint!r}: {reasons[:3]}",
    )


def reject_live(
    sut: Sut, name: str, reg: Json, mutate: Callable[[Json], None], hint: str
) -> None:
    """Live-path rejection: validate_live_registration must refuse."""
    bad = copy.deepcopy(reg)
    mutate(bad)
    reasons = sut.run.validate_live_registration(bad, False)
    hit = any(hint in r for r in reasons)
    check_case(
        f"reject-live-{name}",
        bool(reasons) and hit,
        "accepted an invalid registration"
        if not reasons
        else f"rejected without expected reason {hint!r}: {reasons[:3]}",
    )


def row_of(reg: Json, target: str, row_id: str) -> Json:
    for row in reg["targets"][target]["rows"]:
        if row["id"] == row_id:
            return row
    raise KeyError(row_id)


# --------------------------------------------------------------------------
# Phases
# --------------------------------------------------------------------------


def positive_phase(sut: Sut, tmp: Path) -> tuple[Json, list[Json]]:
    run_mod = sut.run
    reg = build_fixture(tmp / "fx", sut)

    reasons = run_mod.validate_registration(copy.deepcopy(reg), True)
    check_case(
        "positive-registration-complete",
        reasons == [],
        f"complete synthetic registration rejected: {reasons[:4]}",
    )
    live_reasons = run_mod.validate_live_registration(copy.deepcopy(reg), True)
    check_case(
        "positive-live-registration-complete",
        live_reasons == [],
        f"complete synthetic registration rejected by live path: {live_reasons[:4]}",
    )
    reg_file = tmp / "reg.json"
    reg_file.write_text(json.dumps(reg), encoding="utf-8")
    for sub in ("validate", "plan"):
        proc = run_cli(sut.runner_path, sub, "--registration", str(reg_file))
        check_case(
            f"positive-cli-{sub}",
            proc.returncode == 0,
            f"exit={proc.returncode} stderr={proc.stderr.strip()[:400]}",
        )

    cases = run_mod.derive_cases(reg)
    rows_total = sum(len(v) for v in ROWS.values())
    counted_specs = {spec[0]: spec for _, spec in ALL_ROWS if spec[1] == "counted"}
    check_case(
        "positive-case-count",
        len(cases) == rows_total * 16,
        f"{len(cases)} != {rows_total * 16}",
    )
    check_case(
        "positive-zero-uses-candidate-executable",
        all(
            c["binary_key"] == c["row"]["candidate_binary"]
            for c in cases
            if c["arm"] == "zero"
        )
        and not any("zero" in k for k in reg["binaries"]),
        "zero block does not resolve to the row's candidate executable",
    )
    per_visit = {
        (c["target"], c["block"], c["visit_index"])
        for c in cases
        if c["target"] in ("T2", "T3")
    }
    check_case(
        "positive-one-T2-T3-workload-per-visit",
        all(
            sum(1 for c in cases if (c["target"], c["block"], c["visit_index"]) == v)
            == 1
            for v in per_visit
        ),
        "T2/T3 do not run exactly one workload per visit",
    )
    counted_cases = [c for c in cases if c["row"]["kind"] == "counted"]
    check_case(
        "positive-counted-case-count",
        len(counted_cases) == len(counted_specs) * 16,
        f"{len(counted_cases)} counted cases != {len(counted_specs) * 16}",
    )

    samp = tmp / "sample_ok.json"
    samp.write_text(
        json.dumps({"iters": [100.0] * 10, "times": [1.5e9] * 10}), encoding="utf-8"
    )
    try:
        _, _, norm, _, _ = run_mod.validate_criterion_sample(samp, 10, 1)
        check_case(
            "positive-parser-criterion-exact",
            all(abs(v - 1.5e7) < 1.0 for v in norm),
            f"normalized={norm[:3]}",
        )
    except Exception as exc:  # noqa: BLE001 - probe reports any SUT failure
        check_case("positive-parser-criterion-exact", False, f"raised {exc!r}")

    node_ok = tmp / "node_ok.log"
    write_stdout(node_ok, good_t2_objs([0, 2_500_000_000]))  # zero unit = clock quantum
    try:
        warm, meas, _ = run_mod.parse_node_stdout(
            node_ok, T2_ROW, {T2_ROW: T2_IDENTITY}, dict(CORPUS)
        )
        check_case(
            "positive-parser-T2-exact-sum-zero-allowed",
            len(warm) == 3
            and len(meas) == 10
            and meas[0]["arms"]["tail_to_reply"]["total"] == 2_500_000_000,
            f"warm={len(warm)} meas={len(meas)}",
        )
    except Exception as exc:  # noqa: BLE001
        check_case(
            "positive-parser-T2-exact-sum-zero-allowed", False, f"raised {exc!r}"
        )
    t3_ok = tmp / "t3_ok.log"
    write_stdout(t3_ok, good_t3_objs())
    try:
        warm3, meas3, _ = run_mod.parse_node_stdout(
            t3_ok, T3_ROW, {T3_ROW: T3_IDENTITY}, dict(CORPUS)
        )
        ident = meas3[0]["identity"]
        check_case(
            "positive-parser-T3-exact-arms-and-full-identity",
            len(warm3) == 3
            and len(meas3) == 10
            and meas3[0]["arms"]["rpc_hit"]["total"] == 3_000_000_000
            and set(ident) == T3_IDENTITY_KEYS
            and ident["tip_height"] == T3_IDENTITY["tip_height"],
            f"identity keys={sorted(ident)}",
        )
    except Exception as exc:  # noqa: BLE001
        check_case(
            "positive-parser-T3-exact-arms-and-full-identity", False, f"raised {exc!r}"
        )

    # Counted parser positive: real counted stdout -> real seam -> neutral
    # numeric arrays and statistics. Zero individual units stay legal.
    counted_ok = tmp / "counted_ok.log"
    zero_unit_objs = good_counted_objs(A_ADMISSION)
    zero_unit_objs[3] = make_counted_obj(A_ADMISSION, 3, False, [0, 1_000_000_000])
    write_counted_stdout(counted_ok, zero_unit_objs)
    try:
        cwarm, cmeas = run_mod.parse_counted_stdout(counted_ok, A_ADMISSION)
        counted_row = reg_row("T4", counted_specs[A_ADMISSION])
        fields = run_mod.counted_case_fields(counted_ok, counted_row)
        norm_ok = all(
            abs(n - t / i) < 1e-9
            for n, t, i in zip(
                fields["normalized_ns"],
                fields["sample_times_ns"],
                fields["sample_iters"],
            )
        )
        measured_objs = zero_unit_objs[1:]
        want_iters = [float(o["unit_count"]) for o in measured_objs]
        want_times = [float(o["total_ns"]) for o in measured_objs]
        check_case(
            "positive-parser-counted-exact",
            len(cwarm) == 1
            and len(cmeas) == 10
            and fields["counted_warmups_seen"] == 1
            and len(fields["counted_warmup_samples"]) == 1
            and len(fields["counted_samples"]) == 10
            and fields["counted_warmup_samples"][0]["warmup"] is True
            and fields["counted_samples"][0]["warmup"] is False
            and fields["sample_iters"] == want_iters
            and fields["sample_times_ns"] == want_times
            and want_iters[2] == 2.0
            and want_times[2] == COUNTED_FLOOR_NS
            and all(t >= COUNTED_FLOOR_NS for t in want_times)
            and norm_ok
            and not any(k.startswith("criterion_") for k in fields),
            f"warm={len(cwarm)} meas={len(cmeas)} "
            f"iters={fields['sample_iters'][:2]} times={fields['sample_times_ns'][:2]}",
        )
    except Exception as exc:  # noqa: BLE001
        check_case("positive-parser-counted-exact", False, f"raised {exc!r}")

    records = build_campaign(sut, reg, tmp, "valid", BASE_FN)
    verdict = analyze_with(sut, reg, records)
    keeps = {
        t: verdict["targets"].get(t, {}).get("keep") for t in ("T1", "T2", "T3", "T4")
    }
    check_case(
        "positive-stats-valid-campaign",
        verdict["verdict"] == "NON_REGRESSION_EVIDENCED"
        and all(v is True for v in keeps.values())
        and verdict["metadata"]["validation_passed"] is True,
        f"verdict={verdict['verdict']} keeps={keeps} "
        f"reasons={verdict.get('reasons', [])[:3]}",
    )
    camp = tmp / "synth_cli"
    camp.mkdir()
    (camp / "results.json").write_text(json.dumps(records), encoding="utf-8")
    cli_reg = copy.deepcopy(reg)
    cli_reg["campaign_root"] = str(camp)
    (camp / "reg.json").write_text(json.dumps(cli_reg), encoding="utf-8")
    (camp / "manifest.json").write_text(
        json.dumps(manifest_for_dir(camp), indent=2) + "\n", encoding="utf-8"
    )
    proc = run_cli(
        sut.analyzer_path,
        "--registration",
        str(camp / "reg.json"),
        "--results",
        str(camp / "results.json"),
        "--manifest",
        str(camp / "manifest.json"),
    )
    try:
        out = json.loads(proc.stdout) if proc.stdout.strip() else None
    except json.JSONDecodeError:
        out = None
    check_case(
        "positive-cli-analyzer-valid-campaign",
        proc.returncode == 0
        and isinstance(out, dict)
        and out.get("verdict") == "NON_REGRESSION_EVIDENCED",
        f"exit={proc.returncode} stderr={proc.stderr.strip()[:300]} "
        f"verdict={out.get('verdict') if isinstance(out, dict) else out!r}",
    )
    return reg, records


def manifest_for_dir(runs_dir: Path) -> Json:
    entries: dict[str, str] = {}
    for path in sorted(runs_dir.rglob("*")):
        rel = path.relative_to(runs_dir).as_posix()
        if path.is_file() and rel not in ("manifest.json", "manifest.sha256"):
            entries[rel] = sha_of(path)
    return {"algorithm": "sha256", "files": entries}


def analyze_with(sut: Sut, reg: Json, records: list[Json]) -> Json:
    runs_dir = Path(reg["campaign_root"]).parent
    manifest = manifest_for_dir(runs_dir)
    return sut.ana.analyze(
        copy.deepcopy(reg),
        copy.deepcopy(records),
        runs_dir,
        manifest,
    )


def row_adversaries(sut: Sut, reg: Json) -> None:
    """Every mandatory row: omission, role, workload, scaling, kind, binding."""
    other_role = {
        "acceptance": "report_only",
        "primary": "diagnostic",
        "guard_keep": "report_only",
        "connect_guard": "diagnostic",
        "report_only": "guard_keep",
        "diagnostic": "connect_guard",
    }
    for target, spec in ALL_ROWS:
        row_id, kind, role, bench, units = spec
        siblings = reg["targets"][target]["rows"]
        index = next(i for i, r in enumerate(siblings) if r["id"] == row_id)
        if len(siblings) > 1:
            foreign_argv = siblings[(index + 1) % len(siblings)]["argv"]
        else:
            foreign = "T3" if target == "T2" else "T2"
            foreign_argv = reg["targets"][foreign]["rows"][0]["argv"]
        other_control = next(
            k
            for k in sorted(reg["binaries"])
            if k.startswith("control_") and not k.startswith(f"control_{target}/")
        )
        tag = f"{target}/{row_id}"

        def omit(bad: Json, t: str = target, r: str = row_id) -> None:
            rows = bad["targets"][t]["rows"]
            bad["targets"][t]["rows"] = [x for x in rows if x["id"] != r]

        def setf(
            field: str, value: Any, t: str = target, r: str = row_id
        ) -> Callable[[Json], None]:
            def apply(bad: Json) -> None:
                row_of(bad, t, r)[field] = value

            return apply

        def rename(bad: Json, t: str = target, r: str = row_id) -> None:
            row = row_of(bad, t, r)
            row["id"] = r.split("/")[-1] if "/" in r else f"{r}_renamed"
            if row["kind"] == "criterion":
                row["argv"] = ["--bench", "--noplot", "--exact", row["id"]]
            elif row["kind"] == "counted":
                row["argv"] = ["--mrp-counted", row["id"]]

        reject(sut, f"omit-row {tag}", reg, omit, "omits mandatory row")
        reject(
            sut, f"role-reassign {tag}", reg, setf("role", other_role[role]), "role is"
        )
        reject(
            sut,
            f"wrong-workload-argv {tag}",
            reg,
            setf("argv", list(foreign_argv)),
            "argv is",
        )
        reject(
            sut,
            f"sampling-override-argv {tag}",
            reg,
            setf("argv", list(reg_row(target, spec)["argv"]) + ["--sample-size", "99"]),
            "argv is",
        )
        reject(sut, f"rename-without-group {tag}", reg, rename, "omits mandatory row")
        wrong_kind = {
            "criterion": "counted",
            "counted": "criterion",
            "node": "criterion",
        }[kind]
        reject(
            sut,
            f"wrong-kind {tag}",
            reg,
            setf("kind", wrong_kind),
            "kind is",
        )
        reject(
            sut,
            f"wrong-bench-target {tag}",
            reg,
            setf(
                "bench_target", "insert_fill" if bench != "insert_fill" else "candidate"
            ),
            "bench_target is",
        )
        reject(
            sut,
            f"control-is-candidate {tag}",
            reg,
            setf("control_binary", f"candidate/{bench}"),
            "control_binary is",
        )
        reject(
            sut,
            f"control-from-other-lever {tag}",
            reg,
            setf("control_binary", other_control),
            "control_binary is",
        )
        if kind == "counted":
            reject(
                sut,
                f"unit-scaling {tag}",
                reg,
                setf("units_per_iter", 64),
                "units_per_iter is",
            )
            reject(sut, f"sample-count {tag}", reg, setf("samples", 9), "samples is")
            reject(
                sut,
                f"wrong-counted-argv {tag}",
                reg,
                setf("argv", ["--bench", "--noplot", "--exact", row_id]),
                "argv is",
            )
            reject(
                sut,
                f"list-counted-argv {tag}",
                reg,
                setf("argv", ["--mrp-list-counted", row_id]),
                "argv is",
            )
            reject(
                sut,
                f"verify-counted-argv {tag}",
                reg,
                setf("argv", ["--mrp-verify-counted", row_id]),
                "argv is",
            )
        elif kind == "criterion":
            reject(
                sut,
                f"unit-scaling {tag}",
                reg,
                setf("units_per_iter", 64 if units == 1 else 1),
                "units_per_iter is",
            )
            reject(sut, f"sample-count {tag}", reg, setf("samples", 9), "samples is")
            reject(
                sut,
                f"criterion-counted-argv {tag}",
                reg,
                setf("argv", ["--mrp-counted", row_id]),
                "argv is",
            )
        else:
            reject(
                sut,
                f"surplus-units-key {tag}",
                reg,
                setf("units_per_iter", 1),
                "unrecognized key",
            )
        # The analyzer must refuse the same tampered registration (shared validator).
        for label, mutate in (("omit", omit), ("role", setf("role", other_role[role]))):
            bad = copy.deepcopy(reg)
            mutate(bad)
            verdict = analyze_with(
                sut, bad, []
            )  # registration is refused before any record
            check_case(
                f"analyzer-refuses-{label} {tag}",
                verdict["verdict"] == "INCONCLUSIVE"
                and verdict["metadata"]["validation_passed"] is False
                and any(str(x).startswith("registration:") for x in verdict["reasons"])
                and not verdict["targets"],
                f"verdict={verdict['verdict']} reasons={verdict['reasons'][:2]}",
            )
    for target in ("T1", "T2", "T3", "T4"):
        if len(reg["targets"][target]["rows"]) > 1:
            reject(
                sut,
                f"row-order {target}",
                reg,
                lambda bad, t=target: bad["targets"][t]["rows"].reverse(),
                "pinned execution order",
            )
    reject(
        sut,
        "duplicate-T3-invocation",
        reg,
        lambda bad: bad["targets"]["T3"]["rows"].append(
            copy.deepcopy(bad["targets"]["T3"]["rows"][0])
        ),
        "duplicates row id",
    )
    reject(
        sut,
        "composite-control-tree",
        reg,
        lambda bad: bad["targets"]["T1"].update(control_tree="control_all"),
        "control_tree",
    )


def freeze_adversaries(sut: Sut, reg: Json, tmp: Path) -> None:
    # Missing, surplus and wrong-hash entries for every tree / bench / lock.
    for tree in TREES:
        first = next(
            rel
            for rel in sorted(reg["source_fingerprints"][tree])
            if rel not in BENCH_FILES.values() and rel not in LOCK_FILES
        )
        reject(
            sut,
            f"source-omits-file {tree}",
            reg,
            lambda b, t=tree, f=first: b["source_fingerprints"][t].pop(f),
            "omits",
        )
        reject(
            sut,
            f"source-surplus-entry {tree}",
            reg,
            lambda b, t=tree: b["source_fingerprints"][t].update(
                {"ghost.rs": "a" * 64}
            ),
            "lists nonexistent",
        )
        reject(
            sut,
            f"source-wrong-hash {tree}",
            reg,
            lambda b, t=tree, f=first: b["source_fingerprints"][t].update(
                {f: "0" * 64}
            ),
            "pins wrong hashes",
        )
        reject(
            sut,
            f"source-missing-tree-key {tree}",
            reg,
            lambda b, t=tree: b["source_fingerprints"].pop(t),
            "missing required key",
        )
        reject(
            sut,
            f"source-root-nonexistent {tree}",
            reg,
            lambda b, t=tree: b["source_roots"].update({t: str(tmp / "nowhere")}),
            "existing directory",
        )
        reject(
            sut,
            f"source-root-relative {tree}",
            reg,
            lambda b, t=tree: b["source_roots"].update({t: "relative/dir"}),
            "existing directory",
        )
        for bench, rel in BENCH_FILES.items():
            reject(
                sut,
                f"bench-omitted {tree}/{bench}",
                reg,
                lambda b, t=tree, r=rel: b["bench_fingerprints"][t].pop(r),
                "must hold exactly",
            )
            reject(
                sut,
                f"bench-wrong-hash {tree}/{bench}",
                reg,
                lambda b, t=tree, r=rel: b["bench_fingerprints"][t].update(
                    {r: "1" * 64}
                ),
                "!= file in source root",
            )
        reject(
            sut,
            f"bench-surplus {tree}",
            reg,
            lambda b, t=tree: b["bench_fingerprints"][t].update({"x.rs": "2" * 64}),
            "must hold exactly",
        )
        for rel in LOCK_FILES:
            reject(
                sut,
                f"lock-omitted {tree}/{rel}",
                reg,
                lambda b, t=tree, r=rel: b["lock_fingerprints"][t].pop(r),
                "must hold exactly",
            )
            reject(
                sut,
                f"lock-wrong-hash {tree}/{rel}",
                reg,
                lambda b, t=tree, r=rel: b["lock_fingerprints"][t].update(
                    {r: "3" * 64}
                ),
                "!= file in source root",
            )
    for kind in (
        "bench_fingerprints",
        "lock_fingerprints",
        "source_fingerprints",
        "source_roots",
    ):
        reject(
            sut,
            f"inventory-missing {kind}",
            reg,
            lambda b, k=kind: b.pop(k),
            "missing required key",
        )
    reject(
        sut,
        "source-roots-overlap",
        reg,
        lambda b: b["source_roots"].update(control_T1=b["source_roots"]["candidate"]),
        "overlap",
    )
    reject(
        sut,
        "legacy-binary-fingerprints-key",
        reg,
        lambda b: b.update(binary_fingerprints={"zero": "4" * 64}),
        "unrecognized key",
    )
    reject(
        sut,
        "campaign-root-in-source-root",
        reg,
        lambda b: b.update(
            campaign_root=str(Path(b["source_roots"]["candidate"]) / "out")
        ),
        "inside a source root",
    )
    existing = copy.deepcopy(reg)
    existing["campaign_root"] = str(tmp)
    reasons = sut.run.validate_registration(existing, True)
    check_case(
        "reject-campaign-root-exists",
        any("already exists" in r for r in reasons),
        f"existing campaign_root accepted by run-time validation: {reasons[:3]}",
    )

    # Real-disk variants: every rule must fire on its own (inventories are honest).
    outside_file = tmp / "outside.txt"
    outside_file.write_text("outside\n", encoding="utf-8")
    outside_dir = tmp / "outside_dir"
    outside_dir.mkdir()
    (outside_dir / "x").write_text("x\n", encoding="utf-8")
    variants: list[
        tuple[str, dict[str, dict[str, bytes]], tuple[tuple[str, str, Path], ...], str]
    ] = [
        (
            "build-output-dir",
            {"candidate": {"target/debug/out.bin": b"x"}},
            (),
            "build-output",
        ),
        ("vcs-dir", {"control_T2": {".git/HEAD": b"ref"}}, (), "build-output"),
        ("vcs-file", {"control_T3": {".git": b"gitdir: x"}}, (), "VCS marker"),
        (
            "escaping-symlink",
            {},
            (("control_T3", "crates/stub/escape.txt", outside_file),),
            "leaves the source root",
        ),
        (
            "symlinked-directory",
            {},
            (("control_T4", "crates/stub/linkdir", outside_dir),),
            "symlinked directory",
        ),
    ]
    for name, extras, links, hint in variants:
        bad = build_fixture(tmp / f"variant-{name}", sut, extras=extras, symlinks=links)
        reasons = sut.run.validate_registration(bad, False)
        check_case(
            f"reject-source-root-{name}",
            any(hint in r for r in reasons),
            f"expected {hint!r}, got {reasons[:3]}",
        )
    for tree in TREES:
        base = tmp / f"disk-{tree}"
        fx = build_fixture(base, sut)
        root = Path(fx["source_roots"][tree])
        extra = root / "crates/stub/untracked.rs"
        extra.write_text("// not registered\n", encoding="utf-8")
        reasons = sut.run.validate_registration(fx, False)
        check_case(
            f"reject-untracked-disk-file {tree}",
            any("omits" in r for r in reasons),
            f"untracked file accepted: {reasons[:3]}",
        )
        extra.unlink()
        lib = root / "crates/stub/src/lib.rs"
        original = lib.read_bytes()
        lib.write_bytes(original + b"// tampered after freeze\n")
        reasons = sut.run.validate_registration(fx, False)
        check_case(
            f"reject-mutated-disk-file {tree}",
            any("pins wrong hashes" in r for r in reasons),
            f"mutated file accepted: {reasons[:3]}",
        )
        lib.write_bytes(original)
        again = sut.run.validate_registration(fx, False)
        check_case(f"restored-disk-file-accepted {tree}", again == [], f"{again[:3]}")
    # A harness bench or lock that differs in one tree only, registered consistently.
    for tree in TREES[1:]:
        for kind, rel in (
            ("bench_fingerprints", BENCH_FILES["sync_pipeline"]),
            ("lock_fingerprints", LOCK_FILES[0]),
        ):
            fx = build_fixture(tmp / f"drift-{tree}-{kind}", sut)
            path = Path(fx["source_roots"][tree]) / rel
            path.write_bytes(path.read_bytes() + b"// drift\n")
            fx["source_fingerprints"][tree][rel] = sha_of(path)
            fx[kind][tree][rel] = sha_of(path)
            reasons = sut.run.validate_registration(fx, False)
            check_case(
                f"reject-{kind}-tree-drift {tree}",
                any("differs from candidate" in r for r in reasons),
                f"cross-tree drift accepted: {reasons[:3]}",
            )


def script_and_evidence_adversaries(sut: Sut, reg: Json, tmp: Path) -> None:
    mutdir = tmp / "mut"
    counter = [0]

    def swap_doc(entry: Json, doc: Json) -> None:
        counter[0] += 1
        entry.update(write_doc(mutdir / f"doc-{counter[0]}.json", doc))

    for name in ("runner", "analyzer"):
        reject(
            sut,
            f"scripts-missing-{name}",
            reg,
            lambda b, n=name: b["scripts"].pop(n),
            "missing required key",
        )
        reject(
            sut,
            f"scripts-wrong-hash-{name}",
            reg,
            lambda b, n=name: b["scripts"][n].update(sha256="5" * 64),
            "file hash",
        )
        reject(
            sut,
            f"scripts-extra-key-{name}",
            reg,
            lambda b, n=name: b["scripts"][n].update(note="x"),
            "unrecognized key",
        )
    reject(
        sut,
        "scripts-runner-path-is-analyzer",
        reg,
        lambda b: b["scripts"]["runner"].update(b["scripts"]["analyzer"]),
        "not the executing runner",
    )
    reject(
        sut,
        "scripts-analyzer-path-is-runner",
        reg,
        lambda b: b["scripts"]["analyzer"].update(b["scripts"]["runner"]),
        "not the executing analyzer",
    )

    mutdir.mkdir(parents=True, exist_ok=True)
    not_json = mutdir / "not-json-receipt.txt"
    not_json.write_text("this is not JSON: {oops\n", encoding="utf-8")
    not_json_sha = sha_of(not_json)
    for key in sorted(reg["binaries"]):
        entry = reg["binaries"][key]
        reject(
            sut,
            f"binary-omitted {key}",
            reg,
            lambda b, k=key: b["binaries"].pop(k),
            "missing required key",
        )
        reject(
            sut,
            f"binary-wrong-hash {key}",
            reg,
            lambda b, k=key: b["binaries"][k].update(sha256="6" * 64),
            "file hash",
        )
        reject(
            sut,
            f"binary-nonexistent {key}",
            reg,
            lambda b, k=key: b["binaries"][k].update(path="/nonexistent/exe"),
            "not an existing file",
        )
        reject(
            sut,
            f"binary-without-receipt {key}",
            reg,
            lambda b, k=key: b["binaries"][k].pop("receipt"),
            "missing required key",
        )
        reject(
            sut,
            f"binary-receipt-missing-file {key}",
            reg,
            lambda b, k=key: b["binaries"][k]["receipt"].update(
                path="/nonexistent/r.json"
            ),
            "not an existing file",
        )
        reject(
            sut,
            f"binary-receipt-wrong-hash {key}",
            reg,
            lambda b, k=key: b["binaries"][k]["receipt"].update(sha256="7" * 64),
            "file hash",
        )
        other = next(k for k in sorted(reg["binaries"]) if k != key)
        reject(
            sut,
            f"binary-same-file-as-{other} {key}",
            reg,
            lambda b, k=key, o=other: b["binaries"][k].update(
                path=b["binaries"][o]["path"], sha256=b["binaries"][o]["sha256"]
            ),
            "same file as",
        )
        receipt_doc = json.loads(
            Path(entry["receipt"]["path"]).read_text(encoding="utf-8")
        )
        tree, bench = key.split("/")
        wrong_values = {
            "kind": "not-a-receipt",
            "tree": "control_T1" if tree != "control_T1" else "candidate",
            "bench_target": "candidate" if bench != "candidate" else "insert_fill",
            "source_digest": "8" * 64,
            "bench_source_sha256": "9" * 64,
            "lock_digest": "a" * 64,
            "binary_sha256": "b" * 64,
        }
        for field, wrong in wrong_values.items():

            def tamper(
                b: Json,
                k: str = key,
                f: str = field,
                w: str = wrong,
                d: Json = receipt_doc,
            ) -> None:
                swap_doc(b["binaries"][k]["receipt"], {**d, f: w})

            reject(
                sut,
                f"receipt-{field}-mismatch {key}",
                reg,
                tamper,
                "do not match the registered",
            )

        def drop_field(b: Json, k: str = key, d: Json = receipt_doc) -> None:
            swap_doc(
                b["binaries"][k]["receipt"],
                {f: v for f, v in d.items() if f != "source_digest"},
            )

        reject(
            sut,
            f"receipt-field-missing {key}",
            reg,
            drop_field,
            "do not match the registered",
        )
        # Malformed receipt lives outside every source root (mutdir) with its
        # real sha pinned, so only the JSON-shape check can fire.
        reject(
            sut,
            f"receipt-not-json {key}",
            reg,
            lambda b, k=key: b["binaries"][k]["receipt"].update(
                path=str(not_json), sha256=not_json_sha
            ),
            "as JSON",
        )
    reject(
        sut,
        "binary-surplus-zero-key",
        reg,
        lambda b: b["binaries"].update(
            zero=copy.deepcopy(b["binaries"]["candidate/insert_fill"])
        ),
        "unrecognized key",
    )
    exe = Path(reg["binaries"]["control_T2/sync_pipeline"]["path"])
    exe.chmod(0o644)
    reasons = sut.run.validate_registration(copy.deepcopy(reg), False)
    check_case(
        "reject-binary-not-executable",
        any("not executable" in r for r in reasons),
        f"non-executable binary accepted: {reasons[:3]}",
    )
    exe.chmod(0o755)

    # Gated lever executables must differ; unchanged diagnostics may be identical.
    for target, bench in GATED_PAIRS:
        tree = f"control_{target}"
        bad = build_fixture(
            tmp / f"same-{tree}-{bench}",
            sut,
            same_as_candidate=frozenset({(tree, bench)}),
        )
        reasons = sut.run.validate_registration(bad, False)
        check_case(
            f"reject-gated-control-identical {target}/{bench}",
            any("identical" in r and target in r for r in reasons),
            f"zero-delta gated control accepted: {reasons[:3]}",
        )

    # Baseline evidence: explicit roles, hashes and frozen identities.
    for key, role in (
        ("source_baseline_evidence", "source"),
        ("dependency_baseline_evidence", "dependency"),
    ):
        good = json.loads(Path(reg[key][0]["path"]).read_text(encoding="utf-8"))
        reject(
            sut,
            f"evidence-missing-list {role}",
            reg,
            lambda b, k=key: b.pop(k),
            "missing required key",
        )
        reject(
            sut,
            f"evidence-empty-list {role}",
            reg,
            lambda b, k=key: b.update({k: []}),
            "nonempty list",
        )
        reject(
            sut,
            f"evidence-nonexistent {role}",
            reg,
            lambda b, k=key: b[k][0].update(path="/nonexistent/e.json"),
            "not an existing file",
        )
        reject(
            sut,
            f"evidence-wrong-hash {role}",
            reg,
            lambda b, k=key: b[k][0].update(sha256="c" * 64),
            "file hash",
        )
        reject(
            sut,
            f"evidence-duplicate {role}",
            reg,
            lambda b, k=key: b[k].append(copy.deepcopy(b[k][0])),
            "listed twice",
        )
        note = tmp / f"note-{role}.txt"
        note.write_text("arbitrary note, not a baseline\n", encoding="utf-8")
        reject(
            sut,
            f"evidence-arbitrary-note {role}",
            reg,
            lambda b, k=key, n=note: b[k][0].update(path=str(n), sha256=sha_of(n)),
            "cannot read",
        )
        tampered: dict[str, Json] = {
            "kind": {"kind": "x"},
            "role": {"role": "dependency" if role == "source" else "source"},
            "result": {"result": "failed"},
            "frozen_identity": {
                "frozen_identity": {"trees": {t: "d" * 64 for t in TREES}}
            },
        }
        for field, patch in tampered.items():

            def mutate(b: Json, k: str = key, p: Json = patch, g: Json = good) -> None:
                swap_doc(b[k][0], {**g, **p})

            reject(sut, f"evidence-{field} {role}", reg, mutate, "not a passed")

        def drop_identity(b: Json, k: str = key, g: Json = good) -> None:
            swap_doc(b[k][0], {f: v for f, v in g.items() if f != "frozen_identity"})

        reject(
            sut, f"evidence-identity-missing {role}", reg, drop_identity, "not a passed"
        )
        for tree in TREES:

            def stale_tree(
                b: Json, k: str = key, t: str = tree, g: Json = good
            ) -> None:
                identity = copy.deepcopy(g["frozen_identity"])
                identity["trees"][t] = "e" * 64
                swap_doc(b[k][0], {**g, "frozen_identity": identity})

            reject(
                sut,
                f"evidence-stale-identity-{tree} {role}",
                reg,
                stale_tree,
                "not a passed",
            )
    other_role_doc = json.loads(
        Path(reg["dependency_baseline_evidence"][0]["path"]).read_text()
    )
    reject(
        sut,
        "evidence-dependency-doc-in-source-list",
        reg,
        lambda b: swap_doc(b["source_baseline_evidence"][0], other_role_doc),
        "not a passed",
    )

    def stale_script(b: Json) -> None:
        doc = json.loads(Path(b["source_baseline_evidence"][0]["path"]).read_text())
        doc["frozen_identity"]["scripts"]["analyzer"] = "f" * 64
        swap_doc(b["source_baseline_evidence"][0], doc)

    reject(sut, "evidence-stale-script-identity", reg, stale_script, "not a passed")


def identity_adversaries(sut: Sut, reg: Json) -> None:
    def t2(field: str, value: Any) -> Callable[[Json], None]:
        return lambda b: b["node_identity"][T2_ROW].update({field: value})

    def t3(field: str, value: Any) -> Callable[[Json], None]:
        return lambda b: b["node_identity"][T3_ROW].update({field: value})

    good_tips = [f"{i + 1:064x}" for i in range(13)]
    for name, tips in (
        ("short-list", good_tips[:12]),
        ("long-list", good_tips + ["f" * 64]),
        ("duplicate", good_tips[:12] + [good_tips[0]]),
        ("non-hex-x", good_tips[:12] + ["x"]),
        ("short-hex", good_tips[:12] + ["ab"]),
        ("uppercase", good_tips[:12] + ["AB" * 32]),
        ("non-hex-64", good_tips[:12] + ["g" * 64]),
        ("empty-string", good_tips[:12] + [""]),
    ):
        reject(sut, f"T2-tips-{name}", reg, t2("tips", tips), ".tips must be exactly")
    for name, tip in (
        ("x", "x"),
        ("short", "ab" * 31),
        ("uppercase", "AB" * 32),
        ("non-hex", "zz" * 32),
        ("empty", ""),
        ("int", 7),
    ):
        reject(sut, f"T3-tip-{name}", reg, t3("tip", tip), ".tip must be")
    for engine in ("kernel", "", "Native", "fjall", 1):
        reject(
            sut, f"T2-engine-{engine!r}", reg, t2("engine", engine), "engine must be"
        )
        reject(
            sut, f"T3-engine-{engine!r}", reg, t3("engine", engine), "engine must be"
        )
    for field in (
        "pool_txs",
        "background_txs",
        "pool_at_template",
        "block_txs",
        "block_noncoinbase",
    ):
        reject(sut, f"T2-{field}-not-int", reg, t2(field, "5"), "non-negative int")
        reject(
            sut,
            f"T2-{field}-missing",
            reg,
            lambda b, f=field: b["node_identity"][T2_ROW].pop(f),
            "missing required key",
        )
    for field in ("pool_txs", "background_txs", "pool_at_template", "tip_height"):
        reject(sut, f"T3-{field}-not-int", reg, t3(field, 1.5), "non-negative int")
        reject(
            sut,
            f"T3-{field}-missing",
            reg,
            lambda b, f=field: b["node_identity"][T3_ROW].pop(f),
            "missing required key",
        )
    reject(sut, "T2-single-tip-key", reg, t2("tip", "ab" * 32), "unrecognized key")
    reject(
        sut,
        "unused-node-workload",
        reg,
        lambda b: b["node_identity"].update(extra_bench={"engine": "native"}),
        "unrecognized key",
    )
    reject(
        sut,
        "missing-T3-identity",
        reg,
        lambda b: b["node_identity"].pop(T3_ROW),
        "missing required key",
    )
    reject(
        sut,
        "corpus-extra-field",
        reg,
        lambda b: b["corpus"].update(extra=1),
        "unrecognized key",
    )
    reject(
        sut,
        "corpus-negative",
        reg,
        lambda b: b["corpus"].update(tip_height=-1),
        "non-negative int",
    )
    reject(
        sut,
        "corpus-missing",
        reg,
        lambda b: b["corpus"].pop("targets"),
        "missing required key",
    )
    reject(
        sut,
        "unregistered-status",
        reg,
        lambda b: b.update(status="draft"),
        "status must",
    )
    reject(
        sut,
        "schedule-tamper",
        reg,
        lambda b: b["schedule"].update(blocks=b["schedule"]["blocks"][:-1]),
        "schedule.blocks",
    )
    reject(
        sut,
        "schedule-order",
        reg,
        lambda b: b["schedule"].update(target_order=["T4", "T3", "T2", "T1"]),
        "target_order",
    )
    # Affinity binds the live path only: static validation stays offline-usable
    # (the analyzer path), live validation refuses an unpinned cpu.
    static_bad = copy.deepcopy(reg)
    static_bad["host"].update(cpu=10**6)
    check_case(
        "static-host-cpu-outside-affinity-offline",
        sut.run.validate_registration(static_bad, False) == [],
        "static validator binds current affinity; offline analysis would break",
    )
    reject_live(
        sut,
        "host-cpu-outside-affinity",
        reg,
        lambda b: b["host"].update(cpu=10**6),
        "affinity mask",
    )
    # Observed model binds the live path only; static stays offline-usable
    # (the analyzer path) so a wrong model passes static but fails live.
    static_model = copy.deepcopy(reg)
    static_model["host"].update(cpu_model="wrong-model-probe")
    check_case(
        "static-host-model-mismatch-offline",
        sut.run.validate_registration(static_model, False) == [],
        "static validator binds observed model; offline analysis would break",
    )
    reject_live(
        sut,
        "host-model-observed-mismatch",
        reg,
        lambda b: b["host"].update(cpu_model="wrong-model-probe"),
        "cpu_model",
    )
    reject(
        sut,
        "timeout-nonpositive",
        reg,
        lambda b: b.update(timeout_seconds=0),
        "timeout_seconds",
    )
    reject(
        sut,
        "unknown-top-level-key",
        reg,
        lambda b: b.update(note="x"),
        "unrecognized key",
    )


def distinctness_and_loader_adversaries(sut: Sut, reg: Json, tmp: Path) -> None:
    """F2 pairwise distinctness and F5 pre-execution runner-hash binding."""
    xctrl = build_fixture(tmp / "fx-xctrl", sut)
    src = Path(xctrl["binaries"]["control_T2/sync_pipeline"]["path"]).read_bytes()
    dst = Path(xctrl["binaries"]["control_T3/sync_pipeline"]["path"])
    dst.write_bytes(src)
    dst_sha = sha_of(dst)
    xctrl["binaries"]["control_T3/sync_pipeline"]["sha256"] = dst_sha
    receipt_path = Path(
        xctrl["binaries"]["control_T3/sync_pipeline"]["receipt"]["path"]
    )
    doc = json.loads(receipt_path.read_text(encoding="utf-8"))
    doc["binary_sha256"] = dst_sha
    receipt_path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    xctrl["binaries"]["control_T3/sync_pipeline"]["receipt"]["sha256"] = sha_of(
        receipt_path
    )
    xctrl_reasons = sut.run.validate_registration(xctrl, False)
    xctrl_hit = any("not distinct" in r or "identical" in r for r in xctrl_reasons)
    check_case(
        "reject-cross-control-gated-duplicate",
        bool(xctrl_reasons) and xctrl_hit,
        f"shared cross-control gated hash accepted: {xctrl_reasons[:3]}",
    )

    xdup = build_fixture(tmp / "fx-xdup", sut)
    t1_stub = (
        Path(xdup["source_roots"]["control_T1"]) / "crates/stub/src/lib.rs"
    ).read_bytes()
    (Path(xdup["source_roots"]["control_T2"]) / "crates/stub/src/lib.rs").write_bytes(
        t1_stub
    )
    t2_root = Path(xdup["source_roots"]["control_T2"])
    fresh_fp = walk_hashes(t2_root)
    xdup["source_fingerprints"]["control_T2"] = fresh_fp
    xdup["bench_fingerprints"]["control_T2"] = {
        rel: fresh_fp[rel] for rel in BENCH_FILES.values()
    }
    xdup["lock_fingerprints"]["control_T2"] = {rel: fresh_fp[rel] for rel in LOCK_FILES}
    t2_digest = digest_of(fresh_fp)
    for key in [k for k in xdup["binaries"] if k.startswith("control_T2/")]:
        rpath = Path(xdup["binaries"][key]["receipt"]["path"])
        rdoc = json.loads(rpath.read_text(encoding="utf-8"))
        rdoc["source_digest"] = t2_digest
        rpath.write_text(json.dumps(rdoc, indent=2), encoding="utf-8")
        xdup["binaries"][key]["receipt"]["sha256"] = sha_of(rpath)
    for ekey in ("source_baseline_evidence", "dependency_baseline_evidence"):
        epath = Path(xdup[ekey][0]["path"])
        edoc = json.loads(epath.read_text(encoding="utf-8"))
        trees = edoc["frozen_identity"]["trees"]
        trees["control_T2"] = (
            t2_digest
            if ekey == "source_baseline_evidence"
            else digest_of(xdup["lock_fingerprints"]["control_T2"])
        )
        epath.write_text(json.dumps(edoc, indent=2), encoding="utf-8")
        xdup[ekey][0]["sha256"] = sha_of(epath)
    xdup_reasons = sut.run.validate_registration(xdup, False)
    xdup_hit = any("not distinct" in r or "identical" in r for r in xdup_reasons)
    check_case(
        "reject-identical-full-tree-digest",
        bool(xdup_reasons) and xdup_hit,
        f"duplicated full source tree accepted: {xdup_reasons[:3]}",
    )

    iso = tmp / "iso-loader"
    iso.mkdir(parents=True, exist_ok=True)
    iso_analyzer = iso / ANALYZER_FILE
    iso_analyzer.write_bytes(Path(sut.analyzer_path).read_bytes())
    iso_runner = iso / RUNNER_FILE
    clean_runner = Path(sut.runner_path).read_bytes()
    sentinel = iso / "exec-sentinel.txt"
    marker = (
        b"\n# probe execution marker: module level, runs iff these bytes execute.\n"
        b"# Safe by construction: inert unless MRP_PROBE_EXEC_SENTINEL names a\n"
        b"# file; the probe points it at a tmp sentinel and asserts absence.\n"
        b"import os as _mrp_probe_os\n"
        b"from pathlib import Path as _MrpProbePath\n"
        b'_mrp_probe_sentinel = _mrp_probe_os.environ.get("MRP_PROBE_EXEC_SENTINEL", "")\n'
        b"if _mrp_probe_sentinel:\n"
        b'    _MrpProbePath(_mrp_probe_sentinel).write_bytes(b"executed")\n'
    )
    marked = clean_runner + marker
    iso_runner.write_bytes(marked)
    marked_sha = sha_of(iso_runner)
    good_iso = copy.deepcopy(reg)
    good_iso["scripts"]["runner"] = {"path": str(iso_runner), "sha256": marked_sha}
    good_iso["scripts"]["analyzer"] = {
        "path": str(iso_analyzer),
        "sha256": sha_of(iso_analyzer),
    }
    stale = copy.deepcopy(reg)
    stale["scripts"]["runner"] = {
        "path": str(iso_runner),
        "sha256": sha_of(Path(sut.runner_path)),
    }
    stale["scripts"]["analyzer"] = dict(good_iso["scripts"]["analyzer"])
    stale_reasons = sut.run.validate_registration(stale, False)
    check_case(
        "reject-stale-runner-bytes-before-execution",
        bool(stale_reasons) and any("file hash" in r for r in stale_reasons),
        f"unverified runner bytes accepted: {stale_reasons[:3]}",
    )
    spec = importlib.util.spec_from_file_location(
        "mrp_iso_analyzer_loader", iso_analyzer
    )
    if spec is None or spec.loader is None:
        check_case(
            "loader-cold-refuses-before-execution",
            False,
            "cannot load isolated analyzer copy",
        )
        return
    loader_mod = importlib.util.module_from_spec(spec)
    sys.modules["mrp_iso_analyzer_loader"] = loader_mod
    spec.loader.exec_module(loader_mod)
    os.environ["MRP_PROBE_EXEC_SENTINEL"] = str(sentinel)
    try:
        cold_exc: Exception | None = None
        try:
            loader_mod._runner(copy.deepcopy(stale))
        except Exception as exc:  # noqa: BLE001 - any exec-path failure is evidence
            cold_exc = exc
    finally:
        os.environ.pop("MRP_PROBE_EXEC_SENTINEL", None)
    check_case(
        "loader-cold-refuses-before-execution",
        cold_exc is not None
        and "file hash" in str(cold_exc)
        and "refusing to execute unverified" in str(cold_exc)
        and not sentinel.exists(),
        f"exc={cold_exc!r} sentinel={sentinel.exists()}",
    )
    first = loader_mod._runner(copy.deepcopy(good_iso))
    second = loader_mod._runner(copy.deepcopy(good_iso))
    check_case(
        "loader-warm-reuses-verified-cache",
        first is second,
        "verified cache not reused",
    )
    iso_runner.write_bytes(marked + b"\n# drift\n")
    os.environ["MRP_PROBE_EXEC_SENTINEL"] = str(sentinel)
    try:
        warm_exc: Exception | None = None
        try:
            loader_mod._runner(copy.deepcopy(good_iso))
        except Exception as exc:  # noqa: BLE001 - any exec-path failure is evidence
            warm_exc = exc
    finally:
        os.environ.pop("MRP_PROBE_EXEC_SENTINEL", None)
    check_case(
        "loader-rehashes-before-cache-reuse",
        warm_exc is not None
        and "file hash" in str(warm_exc)
        and "refusing to execute unverified" in str(warm_exc)
        and not sentinel.exists(),
        f"exc={warm_exc!r} sentinel={sentinel.exists()}",
    )
    os.environ["MRP_PROBE_EXEC_SENTINEL"] = str(sentinel)
    try:
        stale_verdict = loader_mod.analyze(
            copy.deepcopy(stale),
            [],
            tmp / "iso-runs",
            {"algorithm": "sha256", "files": {}},
        )
    finally:
        os.environ.pop("MRP_PROBE_EXEC_SENTINEL", None)
    stale_blob = " ".join(str(r) for r in stale_verdict.get("reasons", []))
    check_case(
        "analyzer-refuses-stale-runner-bytes",
        stale_verdict["verdict"] == "INCONCLUSIVE"
        and stale_verdict["metadata"]["validation_passed"] is False
        and "file hash" in stale_blob
        and not sentinel.exists(),
        f"verdict={stale_verdict['verdict']} reasons={stale_verdict['reasons'][:2]} "
        f"sentinel={sentinel.exists()}",
    )


def analyzer_self_binding_adversaries(sut: Sut, reg: Json, tmp: Path) -> None:
    """Analyzer self-binding: executing analyzer bytes vs registered analyzer.

    Catches accidental stale analyzer execution; not tamper-proof attestation.
    Each copy is imported as a real module and analyzed with real files; no
    source-text assertions. Canonical scripts are never touched.
    """
    canonical_bytes = Path(sut.analyzer_path).read_bytes()

    def load_copy(name: str, path: Path) -> ModuleType:
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise AssertionError(f"cannot load {name} from {path}")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
        return mod

    # Relocated identical bytes: path must still refuse while pinned to original.
    rel_dir = tmp / "analyzer-relocated"
    rel_dir.mkdir(parents=True, exist_ok=True)
    rel_path = rel_dir / ANALYZER_FILE
    rel_path.write_bytes(canonical_bytes)
    rel_mod = load_copy("mrp_relocated_analyzer", rel_path)
    rel_verdict = rel_mod.analyze(
        copy.deepcopy(reg), [], tmp / "rel-runs", {"algorithm": "sha256", "files": {}}
    )
    rel_blob = " ".join(str(r) for r in rel_verdict.get("reasons", []))
    check_case(
        "analyzer-refuses-relocated-execution",
        rel_verdict["verdict"] == "INCONCLUSIVE"
        and rel_verdict["metadata"]["validation_passed"] is False
        and not rel_verdict["targets"]
        and "analyzer" in rel_blob
        and "not the executing analyzer" in rel_blob,
        f"verdict={rel_verdict['verdict']} reasons={rel_verdict.get('reasons', [])[:2]}",
    )
    # Altered bytes at another path: still INCONCLUSIVE with an analyzer-specific
    # path/hash reason while pinned to the original.
    alt_dir = tmp / "analyzer-altered"
    alt_dir.mkdir(parents=True, exist_ok=True)
    alt_path = alt_dir / ANALYZER_FILE
    alt_path.write_bytes(canonical_bytes + b"\n# probe analyzer drift\n")
    alt_mod = load_copy("mrp_altered_analyzer", alt_path)
    alt_verdict = alt_mod.analyze(
        copy.deepcopy(reg), [], tmp / "alt-runs", {"algorithm": "sha256", "files": {}}
    )
    alt_blob = " ".join(str(r) for r in alt_verdict.get("reasons", []))
    check_case(
        "analyzer-refuses-altered-relocated-bytes",
        alt_verdict["verdict"] == "INCONCLUSIVE"
        and alt_verdict["metadata"]["validation_passed"] is False
        and not alt_verdict["targets"]
        and "analyzer" in alt_blob
        and ("not the executing analyzer" in alt_blob or "file hash" in alt_blob),
        f"verdict={alt_verdict['verdict']} reasons={alt_verdict.get('reasons', [])[:2]}",
    )
    # Same-path drift: pin the pre-drift hash, drift bytes after import; the
    # per-call rehash must fire without touching canonical scripts.
    drift_dir = tmp / "analyzer-same-path-drift"
    drift_dir.mkdir(parents=True, exist_ok=True)
    drift_path = drift_dir / ANALYZER_FILE
    drift_path.write_bytes(canonical_bytes)
    drift_hash = sha_of(drift_path)
    drift_mod = load_copy("mrp_drift_analyzer", drift_path)
    drift_reg = copy.deepcopy(reg)
    drift_reg["scripts"]["analyzer"] = {"path": str(drift_path), "sha256": drift_hash}
    drift_path.write_bytes(canonical_bytes + b"\n# same-path drift\n")
    drift_verdict = drift_mod.analyze(
        drift_reg, [], tmp / "drift-runs", {"algorithm": "sha256", "files": {}}
    )
    drift_blob = " ".join(str(r) for r in drift_verdict.get("reasons", []))
    check_case(
        "analyzer-rehashes-before-reuse",
        drift_verdict["verdict"] == "INCONCLUSIVE"
        and drift_verdict["metadata"]["validation_passed"] is False
        and not drift_verdict["targets"]
        and "analyzer" in drift_blob
        and "file hash" in drift_blob,
        f"verdict={drift_verdict['verdict']} reasons={drift_verdict.get('reasons', [])[:2]}",
    )


def host_binding_adversaries(sut: Sut, reg: Json, tmp: Path) -> None:
    """F3 recorded CPU/model/taskset binding against the registration."""
    off = copy.deepcopy(reg)
    off["host"].update(cpu=10**6)
    off_verdict = analyze_with(
        sut, off, build_campaign(sut, off, tmp, "offline-host", BASE_FN)
    )
    check_case(
        "analyzer-offline-host-mismatch-positive",
        off_verdict["verdict"] == "NON_REGRESSION_EVIDENCED"
        and off_verdict["metadata"]["validation_passed"] is True,
        f"verdict={off_verdict['verdict']} reasons={off_verdict.get('reasons', [])[:2]}",
    )
    bound = build_campaign(sut, reg, tmp, "hostbind", BASE_FN)
    tampers = [
        (
            "analyzer-rejects-wrong-captured-cpu",
            lambda r: r["host_before"].update(chosen_cpu=10**6),
            ("chosen_cpu",),
        ),
        (
            "analyzer-rejects-wrong-captured-model",
            lambda r: r["host_before"].update(chosen_cpu_model="wrong-model"),
            ("chosen_cpu_model", "cpu_model"),
        ),
        (
            "analyzer-rejects-wrong-taskset-prefix",
            lambda r: r.update(command=["synthetic-workload"]),
            ("taskset", "command"),
        ),
    ]
    for tag, mutate, tokens in tampers:
        recs = copy.deepcopy(bound)
        mutate(recs[0])
        verdict = analyze_with(sut, reg, recs)
        blob = " ".join(str(r) for r in verdict.get("reasons", []))
        check_case(
            tag,
            verdict["verdict"] == "INCONCLUSIVE"
            and not verdict["targets"]
            and any(t in blob for t in tokens),
            f"verdict={verdict['verdict']} reasons={verdict.get('reasons', [])[:2]}",
        )


def std_adversaries(sut: Sut, reg: Json, tmp: Path) -> None:
    """F6-std: stored case_std_ns must be finite, nonnegative and recomputed."""
    intact = build_campaign(sut, reg, tmp, "stdintact", BASE_FN)
    idx = next(
        i
        for i, r in enumerate(intact)
        if r["block_kind"] == "measure" and r["row_kind"] == "criterion"
    )
    template = intact[idx]
    old_times = list(template["sample_times_ns"])
    old_norm = list(template["normalized_ns"])
    factors = [0.97 if i % 2 == 0 else 1.03 for i in range(len(old_times))]
    spread_times = [t * f for t, f in zip(old_times, factors)]
    spread_norm = [v * f for v, f in zip(old_norm, factors)]
    spread_median = statistics.median(spread_norm)
    spread_std = statistics.stdev(spread_norm)
    if not spread_std > 0:
        check_case("std-precondition-nonzero-dispersion", False, f"std={spread_std}")
        return
    malformed = [
        ("analyzer-rejects-nan-std", float("nan")),
        ("analyzer-rejects-negative-std", -5.0),
    ]
    for tag, value in malformed:
        recs = copy.deepcopy(intact)
        recs[idx]["case_std_ns"] = value
        verdict = analyze_with(sut, reg, recs)
        blob = " ".join(str(r) for r in verdict.get("reasons", []))
        check_case(
            tag,
            verdict["verdict"] == "INCONCLUSIVE"
            and not verdict["targets"]
            and "is not finite/nonnegative" in blob,
            f"verdict={verdict['verdict']} reasons={verdict.get('reasons', [])[:2]}",
        )
    forged = copy.deepcopy(intact)
    forged[idx]["sample_times_ns"] = list(spread_times)
    forged[idx]["normalized_ns"] = list(spread_norm)
    forged[idx]["case_median_ns"] = spread_median
    forged[idx]["case_std_ns"] = 0.0
    verdict = analyze_with(sut, reg, forged)
    blob = " ".join(str(r) for r in verdict.get("reasons", []))
    check_case(
        "analyzer-rejects-forged-low-std",
        verdict["verdict"] == "INCONCLUSIVE"
        and not verdict["targets"]
        and "does not match recomputation" in blob,
        f"verdict={verdict['verdict']} reasons={verdict.get('reasons', [])[:2]}",
    )


def parser_adversaries(sut: Sut, tmp: Path) -> None:
    run_mod = sut.run
    error = run_mod.RegistrationError

    def expect_error(name: str, call: Callable[[], object]) -> None:
        try:
            call()
            check_case(f"parser-{name}", False, "corrupt input accepted")
        except error:
            check_case(f"parser-{name}", True, "")
        except Exception as exc:  # noqa: BLE001
            check_case(f"parser-{name}", False, f"wrong error {exc!r}")

    for name, values in (
        ("criterion-short-interval", {"iters": [100.0] * 10, "times": [5.0e8] * 10}),
        ("criterion-bad-count", {"iters": [100.0] * 9, "times": [1.5e9] * 9}),
    ):
        path = tmp / f"{name}.json"
        path.write_text(json.dumps(values), encoding="utf-8")
        expect_error(name, lambda p=path: run_mod.validate_criterion_sample(p, 10, 1))

    def node_case(name: str, bench: str, ident: Json, objs: list[Json]) -> None:
        path = tmp / f"{name}.log"
        write_stdout(path, objs)
        expect_error(
            name,
            lambda: run_mod.parse_node_stdout(
                path, bench, {bench: ident}, dict(CORPUS)
            ),
        )

    def t2_mutated(name: str, mutate: Callable[[list[Json]], None]) -> None:
        objs = good_t2_objs()
        mutate(objs)
        node_case(name, T2_ROW, T2_IDENTITY, objs)

    def t3_mutated(name: str, mutate: Callable[[list[Json]], None]) -> None:
        objs = good_t3_objs()
        mutate(objs)
        node_case(name, T3_ROW, T3_IDENTITY, objs)

    t2_mutated("node-bad-sum", lambda o: o[5].update(total_ns=o[5]["total_ns"] + 1))
    t2_mutated("node-bad-count", lambda o: o[5].update(unit_count=3))
    t2_mutated("node-legacy-us", lambda o: o[5].update(unit_us=[1, 2]))
    t2_mutated("node-redundant-mean", lambda o: o[5].update(mean=1.25e9))
    t2_mutated("node-identity-drift", lambda o: o[5].update(tip="ff" * 32))
    t2_mutated(
        "node-tip-of-wrong-sample-index",
        lambda o: o[5].update(tip=T2_IDENTITY["tips"][4]),
    )
    t2_mutated(
        "node-below-2s-floor",
        lambda o: o[5].update(
            unit_ns=[750_000_000, 750_000_000], total_ns=1_500_000_000
        ),
    )
    t2_mutated(
        "node-warmup-below-floor", lambda o: o[1].update(unit_ns=[1, 1], total_ns=2)
    )
    t2_mutated("node-missing-warmup", lambda o: o.pop(0))
    t2_mutated("node-warmup-flag-in-measured", lambda o: o[7].update(warmup=True))
    t2_mutated("node-wrong-engine", lambda o: o[5].update(engine="kernel"))
    t3_mutated("T3-arc-reuse-false", lambda o: o[5].update(arc_reuse=False))
    t3_mutated("T3-missing-tip-height", lambda o: o[5].pop("tip_height"))
    t3_mutated("T3-wrong-tip-height", lambda o: o[5].update(tip_height=111))
    t3_mutated("T3-wrong-tip", lambda o: o[5].update(tip="cd" * 32))
    t3_mutated("T3-legacy-us", lambda o: o[5].update(rpc_hit_us=[1]))
    t3_mutated("T3-rpc-txs-mismatch", lambda o: o[5].update(rpc_txs=9))
    t3_mutated("T3-curtime-order", lambda o: o[5].update(hit_curtime=10))
    t3_mutated(
        "T3-service-arm-below-floor",
        lambda o: o[5].update(service_hit_ns=[1, 1], service_hit_total_ns=2),
    )


def counted_adversaries(sut: Sut, reg: Json, tmp: Path) -> None:
    """Focused counted raw-evidence adversaries (decision-mandated list).

    Each fixture is real counted stdout consumed by the SUT's real
    parse_counted_stdout/counted_case_fields, or a tampered counted record
    consumed by the real analyzer path. Nothing is fabricated and no
    workload runs.
    """
    run_mod = sut.run
    error = run_mod.RegistrationError

    def expect_error(name: str, call: Callable[[], object], hint: str = "") -> None:
        try:
            call()
            check_case(f"counted-{name}", False, "corrupt counted input accepted")
        except error as exc:
            hit = hint in str(exc) if hint else True
            check_case(
                f"counted-{name}",
                hit,
                "" if hit else f"rejected without expected reason {hint!r}: {exc}",
            )
        except Exception as exc:  # noqa: BLE001 - probe reports any SUT failure
            check_case(f"counted-{name}", False, f"wrong error {exc!r}")

    def counted_case(
        name: str,
        objs: list[CountedSample],
        row_id: str = A_ADMISSION,
        hint: str = "",
    ) -> None:
        path = tmp / f"counted-{name}.log"
        write_counted_stdout(path, objs)
        expect_error(
            name,
            lambda: run_mod.parse_counted_stdout(path, row_id),
            hint,
        )

    def mutated(name: str, mutate: Callable[[list[CountedSample]], None]) -> None:
        objs = good_counted_objs(A_ADMISSION)
        mutate(objs)
        counted_case(name, objs)

    # --- sample-set shape -------------------------------------------------
    mutated("missing-sample", lambda o: o.pop(5))
    mutated("duplicate-sample", lambda o: o.insert(5, copy.deepcopy(o[5])))
    mutated(
        "reordered-samples",
        lambda o: o.__setitem__(slice(1, 11), list(reversed(o[1:11]))),
    )
    counted_case("wrong-row-samples", good_counted_objs(A_GUARD), hint="!= row")
    mutated("wrong-single-bench", lambda o: o[4].update(bench=A_GUARD))

    # --- warmup rules -----------------------------------------------------
    mutated("warmup-absent", lambda o: o.pop(0))
    mutated("warmup-extra", lambda o: o.insert(1, copy.deepcopy(o[0])))
    mutated(
        "warmup-flag-missing",
        lambda o: o[0].pop("warmup"),
    )
    mutated(
        "warmup-flag-wrong",
        lambda o: o[0].update(warmup="true"),
    )
    mutated(
        "warmup-not-index0",
        lambda o: (
            o.__setitem__(
                0, make_counted_obj(A_ADMISSION, 0, False, COUNTED_WARM_UNITS)
            )
            or o.__setitem__(
                1, make_counted_obj(A_ADMISSION, 1, True, COUNTED_MEASURE_UNITS)
            )
        ),
    )
    mutated(
        "warmup-below-floor",
        lambda o: o[0].update(
            unit_ns=[10_000_000, 10_000_000], unit_count=2, total_ns=20_000_000
        ),
    )
    # The warmup obeys the same measured-work rule: one warmup below the floor
    # is refused even when every measured sample is fine.
    mutated(
        "warmup-zero-total",
        lambda o: o[0].update(unit_ns=[0, 0], unit_count=2, total_ns=0),
    )

    # --- wire-format and field rules --------------------------------------
    def malformed_json(name: str, line: str) -> None:
        path = tmp / f"counted-{name}.log"
        objs = good_counted_objs(A_ADMISSION)
        lines = [
            "mrp-counted: synthetic fixture diagnostics (ignored line)",
            *(counted_line(o) for o in objs[:4]),
            line,
            *(counted_line(o) for o in objs[5:]),
        ]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        expect_error(
            name,
            lambda: run_mod.parse_counted_stdout(path, A_ADMISSION),
        )

    malformed_json("malformed-prefixed-json", "MRP_COUNTED_SAMPLE {not json")
    malformed_json(
        "prefixed-truncated-json", 'MRP_COUNTED_SAMPLE {"bench": "x", "sampl'
    )
    # A JSON object without the prefix is an auxiliary line, not a sample.
    no_prefix = tmp / "counted-no-prefix.log"
    objs = good_counted_objs(A_ADMISSION)
    lines = [json.dumps(objs[0], separators=(",", ":"))]
    lines += [counted_line(o) for o in objs[1:]]
    no_prefix.write_text("\n".join(lines) + "\n", encoding="utf-8")
    # The unprefixed warmup line is skipped as an auxiliary line, so the
    # refusal is the ordered-stream check (samples 1..10 without a warmup),
    # not a "missing prefix" message.
    expect_error(
        "unprefixed-sample-line",
        lambda: run_mod.parse_counted_stdout(no_prefix, A_ADMISSION),
        "must be warmup 0 then measured",
    )
    # Two prefixes on one line is a malformed prefixed line.
    double_prefix = tmp / "counted-double-prefix.log"
    objs = good_counted_objs(A_ADMISSION)
    lines = [counted_line(o) for o in objs]
    lines.insert(3, 'MRP_COUNTED_SAMPLE MRP_COUNTED_SAMPLE {"bench": "x"}')
    double_prefix.write_text("\n".join(lines) + "\n", encoding="utf-8")
    expect_error(
        "double-prefixed-line",
        lambda: run_mod.parse_counted_stdout(double_prefix, A_ADMISSION),
        "MRP_COUNTED_SAMPLE",
    )

    # Single-fault fixtures: the replacement object carries the SAME sample
    # index as the slot it replaces, so the only fault is the field one and
    # the ordered-stream check cannot mask it.
    def field_fault(name: str, index: int, hint: str, **updates: object) -> None:
        objs = good_counted_objs(A_ADMISSION)
        objs[index] = {
            **make_counted_obj(A_ADMISSION, index, False, COUNTED_MEASURE_UNITS),
            **updates,
        }
        counted_case(name, objs, hint=hint)

    field_fault("unknown-field-redundant-mean", 6, "unknown field", mean=1.0)
    field_fault("unknown-field-percentile", 6, "unknown field", p99=1.0)
    objs = good_counted_objs(A_ADMISSION)
    objs[6] = make_counted_obj(A_ADMISSION, 6, False, COUNTED_MEASURE_UNITS)
    del objs[6]["unit_count"]
    counted_case("missing-key-unit-count", objs, hint="missing key")
    objs = good_counted_objs(A_ADMISSION)
    objs[6] = make_counted_obj(A_ADMISSION, 6, False, COUNTED_MEASURE_UNITS)
    objs[6]["warmup"] = 0
    counted_case("warmup-field-not-bool", objs, hint="warmup must be a bool")

    # --- value-domain rules ------------------------------------------------
    def value_obj(index: int, **updates: object) -> CountedSample:
        base = make_counted_obj(A_ADMISSION, index, False, COUNTED_MEASURE_UNITS)
        base.update(updates)
        return base

    objs = good_counted_objs(A_ADMISSION)
    objs[4] = value_obj(4, bench=True)
    counted_case("bench-not-string", objs)
    objs = good_counted_objs(A_ADMISSION)
    objs[4] = value_obj(4, sample="4")
    counted_case("sample-not-int", objs)
    objs = good_counted_objs(A_ADMISSION)
    objs[4] = value_obj(4, unit_ns=[200_000_000.5] * 5)
    counted_case("unit-ns-noninteger", objs, hint="nonnegative u64")
    objs = good_counted_objs(A_ADMISSION)
    objs[4] = value_obj(4, unit_ns=[-1, 1_000_000_000, 0, 0, 0])
    counted_case("unit-ns-negative", objs, hint="nonnegative u64")
    objs = good_counted_objs(A_ADMISSION)
    big = 2**64
    objs[4] = value_obj(4, unit_ns=[big, 0, 0, 0, 0], total_ns=big)
    counted_case("unit-ns-overflow", objs, hint="nonnegative u64")
    objs = good_counted_objs(A_ADMISSION)
    objs[4] = value_obj(4, unit_ns=[0] * 5, unit_count=5, total_ns=0)
    counted_case(
        "zero-units-zero-total", objs, hint="below the 1 s measured-work floor"
    )
    objs = good_counted_objs(A_ADMISSION)
    objs[4] = value_obj(4, unit_ns=[0] * 5, unit_count=5, total_ns=COUNTED_FLOOR_NS)
    counted_case("zero-units-positive-total", objs)
    objs = good_counted_objs(A_ADMISSION)
    objs[4] = value_obj(4, unit_count=4)
    counted_case("unit-count-mismatch", objs, hint="must equal len(unit_ns)")
    objs = good_counted_objs(A_ADMISSION)
    objs[4] = value_obj(4, total_ns=COUNTED_FLOOR_NS + 1)
    counted_case("total-ns-mismatch", objs, hint="must equal sum(unit_ns) exactly")
    objs = good_counted_objs(A_ADMISSION)
    objs[4] = value_obj(4, unit_ns=[199_999_999] * 5, total_ns=999_999_995)
    counted_case("total-below-floor", objs, hint="below the 1 s measured-work floor")
    # An empty unit list is refused as nonempty-list before the floor rule
    # can fire; assert the SUT's actual first rejection, not a guessed one.
    objs = good_counted_objs(A_ADMISSION)
    objs[4] = value_obj(4, unit_count=0, unit_ns=[], total_ns=0)
    counted_case("unit-count-zero", objs, hint="unit_ns must be a nonempty list")

    # --- first-crossing stopping rule (sampler contract) -------------------
    # Over-collection: the prefix already reaches the floor before the final
    # unit, so the sampler would have stopped earlier; the record lies about
    # stopping. Legal zero durations before the crossing unit stay valid.
    objs = good_counted_objs(A_ADMISSION)
    objs[4] = value_obj(
        4,
        unit_ns=[600_000_000, 600_000_000, 600_000_000],
        unit_count=3,
        total_ns=1_800_000_000,
    )
    counted_case(
        "overcollected-past-first-crossing",
        objs,
        hint="first whole unit reaching the floor",
    )
    objs = good_counted_objs(A_ADMISSION)
    objs[4] = value_obj(
        4,
        unit_ns=[1_000_000_000, 1_000_000_000],
        unit_count=2,
        total_ns=2_000_000_000,
    )
    counted_case(
        "overcollected-exact-prefix-crossing",
        objs,
        hint="first whole unit reaching the floor",
    )
    ok_crossing = tmp / "counted-ok-crossing.log"
    objs = good_counted_objs(A_ADMISSION)
    objs[4] = value_obj(
        4,
        unit_ns=[0, 0, 0, 1_000_000_000],
        unit_count=4,
        total_ns=1_000_000_000,
    )
    write_counted_stdout(ok_crossing, objs)
    try:
        _, meas_ok = run_mod.parse_counted_stdout(ok_crossing, A_ADMISSION)
        check_case(
            "counted-zero-units-before-crossing-valid",
            len(meas_ok) == 10
            and meas_ok[3]["unit_ns"] == [0, 0, 0, 1_000_000_000]
            and meas_ok[3]["total_ns"] == COUNTED_FLOOR_NS,
            f"legal zero-before-crossing sample refused: {len(meas_ok)} samples",
        )
    except Exception as exc:  # noqa: BLE001
        check_case("counted-zero-units-before-crossing-valid", False, f"raised {exc!r}")

    # --- record-level tampering through the real analyzer -------------------
    intact = build_campaign(sut, reg, tmp, "counted-intact", BASE_FN)
    counted_idx = next(i for i, r in enumerate(intact) if r["row_kind"] == "counted")

    def record_verdict(tag: str, mutate: Callable[[Json], None]) -> None:
        recs = copy.deepcopy(intact)
        mutate(recs[counted_idx])
        verdict = analyze_with(sut, reg, recs)
        check_case(
            f"counted-{tag}",
            verdict["verdict"] == "INCONCLUSIVE"
            and not verdict["targets"]
            and verdict["metadata"]["validation_passed"] is False,
            f"verdict={verdict['verdict']} reasons={verdict.get('reasons', [])[:2]}",
        )

    record_verdict(
        "forged-normalized",
        lambda r: r.update(normalized_ns=[v * 0.5 for v in r["normalized_ns"]]),
    )
    record_verdict(
        "forged-sample-times",
        lambda r: r.update(sample_times_ns=[t // 2 for t in r["sample_times_ns"]]),
    )
    record_verdict(
        "forged-warmup-absent",
        lambda r: r.update(counted_warmup_samples=[]),
    )
    record_verdict(
        "forged-warmup-count",
        lambda r: r.update(counted_warmups_seen=0),
    )
    record_verdict(
        "forged-warmup-not-raw",
        lambda r: r.update(counted_warmup_samples=[{"warmup": True}]),
    )
    record_verdict(
        "forged-criterion-artifact",
        lambda r: r.update(
            criterion_sample_path=r["counted_stdout_path"], sample_iters=None
        ),
    )
    record_verdict(
        "forged-counted-samples-truncated",
        lambda r: r.update(counted_samples=r["counted_samples"][:9]),
    )
    record_verdict(
        "forged-raw-total",
        lambda r: r["counted_samples"][0].update(
            total_ns=r["counted_samples"][0]["total_ns"] // 2
        ),
    )

    # The analyzer's T4 connect-guard p99 gate reads the percentile of the
    # POOLED NORMALIZED SAMPLE ESTIMATES (measured_analyze.py
    # _evaluate_t4 -> rout["pooled"][arm]["p99"], computed in
    # _analyze_gated_row from each measure record's normalized_ns) — never a
    # raw-unit percentile. This block proves it without touching the
    # campaign's row identity: a second deepcopy of the intact campaign
    # keeps every record's real row (admitted and unseen guards included),
    # and only the RAW per-unit population of the T4 connect-guard
    # candidates' counted samples is redistributed to
    # [0]*(unit_count-1)+[total_ns]. That is first-crossing legal, leaves
    # total_ns (hence every normalized estimate) untouched, and visibly
    # changes the pooled raw-unit population. Synthetic stdout is rebuilt to
    # a FRESH per-case path (the intact campaign's on-disk stdout is never
    # overwritten) and parsed by the real seam with each record's own pinned
    # row, so raw objects and derived arrays stay consistent and nothing is
    # fabricated.
    A_UNSEEN = "connect_unseen_signed_spend_block/flat"
    T4_GUARDS = (A_GUARD, A_UNSEEN)

    def is_t4_guard_candidate(r: Json, row_id: str | None = None) -> bool:
        if r.get("row_kind") != "counted":
            return False
        if r.get("target") != "T4" or r.get("arm") != "candidate":
            return False
        if r.get("block_kind") != "measure":
            return False
        return row_id is None or r.get("row") == row_id

    def rebuild_record_stdout(r: Json, per_sample_units: list[list[int]]) -> None:
        """Rewrite one record's counted stdout and re-derive its fields.

        per_sample_units carries one unit list per measured sample, 1..10.
        The warmup keeps its own count and total. The pinned row for this record
        (the id/argv/samples dict), never a blanket admission row: the seam
        stamps the row identity. The stdout goes to a fresh per-case file —
        the intact campaign's on-disk stdout is never rewritten.
        """
        row = row_of(reg, "T4", r["row"])
        stdout = tmp / "counted-redistribution" / f"{r['case_index']:04d}.log"
        stdout.parent.mkdir(parents=True, exist_ok=True)
        warmup = copy.deepcopy(r["counted_warmup_samples"][0])
        warmup["unit_ns"] = [0] * (warmup["unit_count"] - 1) + [warmup["total_ns"]]
        objs = [warmup] + [
            make_counted_obj(r["row"], 1 + j, False, per_sample_units[j])
            for j in range(10)
        ]
        write_counted_stdout(stdout, objs)
        r.update(counted_case_fields_via_sut(sut, stdout, row))

    def redistribute_guard_units(
        units_for: Callable[[Json], list[list[int]]],
    ) -> list[Json]:
        recs = copy.deepcopy(intact)
        touched = [
            r for r in recs if is_t4_guard_candidate(r) and r["row"] in T4_GUARDS
        ]
        if not touched:
            raise SystemExit("no T4 connect-guard candidate measure records found")
        for r in touched:
            rebuild_record_stdout(r, units_for(r))
        return recs

    def to_zero_prefix(r: Json) -> list[list[int]]:
        """Redistribute one sample's units to [0]*(n-1)+[total_ns].

        Same unit_count, same total_ns (so the normalized estimate is
        byte-identical), same first-crossing legality — only the raw
        per-unit population changes.
        """
        return [
            [0] * (len(s["unit_ns"]) - 1) + [s["total_ns"]]
            for s in r["counted_samples"]
        ]

    def raw_unit_pool(records: list[Json], row_id: str) -> list[int]:
        return [
            u
            for r in records
            if is_t4_guard_candidate(r, row_id)
            for s in r["counted_samples"]
            for u in s["unit_ns"]
        ]

    def normalized_pool(records: list[Json], row_id: str, arm: str) -> list[float]:
        return [
            float(v)
            for r in records
            if r.get("row_kind") == "counted"
            and r.get("target") == "T4"
            and r.get("arm") == arm
            and r.get("block_kind") == "measure"
            and r.get("row") == row_id
            for v in r["normalized_ns"]
        ]

    def percentile_99(values: list[float]) -> float:
        """The analyzer's _percentiles interpolation at (n-1)*0.99."""
        ordered = sorted(values)
        pos = 0.99 * (len(ordered) - 1)
        lo = int(pos)
        hi = min(lo + 1, len(ordered) - 1)
        frac = pos - lo
        return ordered[lo] * (1.0 - frac) + ordered[hi] * frac

    def pooled_p99(verdict: Json, row_id: str, arm: str) -> float | None:
        row_out = verdict.get("targets", {}).get("T4", {}).get("rows", {}).get(row_id)
        if not isinstance(row_out, dict):
            return None
        return row_out.get("pooled", {}).get(arm, {}).get("p99")

    def t4_target(verdict: Json) -> Json:
        return verdict.get("targets", {}).get("T4", {})

    def guard_records(records: list[Json]) -> list[Json]:
        return [r for r in records if is_t4_guard_candidate(r)]

    def derived_field_invariants_hold(before: Json, after: Json) -> bool:
        return (
            before["normalized_ns"] == after["normalized_ns"]
            and before["sample_times_ns"] == after["sample_times_ns"]
            and before["sample_iters"] == after["sample_iters"]
        )

    # Guard rails on the fixture itself: the redistribution must actually
    # change the raw population (known multi-unit guard fixture) while
    # leaving totals and counts identical.
    baseline = next(r for r in intact if is_t4_guard_candidate(r, A_GUARD))
    multi_unit = all(len(s["unit_ns"]) > 1 for s in baseline["counted_samples"])
    totals_intact = all(
        sum(s["unit_ns"]) == s["total_ns"] for s in baseline["counted_samples"]
    )
    check_case(
        "counted-redistribution-fixture-multi-unit",
        multi_unit and totals_intact,
        "guard fixture is not a known multi-unit fixture; pick another",
    )

    # The valid intact campaign and the redistributed campaign must BOTH be
    # analyzable end to end.
    baseline_verdict = analyze_with(sut, reg, copy.deepcopy(intact))
    check_case(
        "counted-normalized-intact-analyzable",
        baseline_verdict["metadata"]["validation_passed"] is True,
        f"verdict={baseline_verdict['verdict']} "
        f"reasons={baseline_verdict.get('reasons', [])[:2]}",
    )
    redistributed = redistribute_guard_units(to_zero_prefix)
    redist_verdict = analyze_with(sut, reg, redistributed)
    check_case(
        "counted-normalized-redistributed-analyzable",
        redist_verdict["metadata"]["validation_passed"] is True,
        f"verdict={redist_verdict['verdict']} "
        f"reasons={redist_verdict.get('reasons', [])[:2]}",
    )

    # The pooled raw-unit population of the guards' candidate samples
    # provably changed: every measured sample went from all-equal units to
    # zeros plus one total-sized unit, so the raw multiset demonstrably
    # moved (many equal mid-size units replaced by zeros plus one big unit;
    # the raw max rises to total_ns). The p99 gate must NOT move with it.
    base_raw_pool = raw_unit_pool(intact, A_GUARD)
    new_raw_pool = raw_unit_pool(redistributed, A_GUARD)
    raw_changed = (
        len(new_raw_pool) == len(base_raw_pool)
        and sum(new_raw_pool) == sum(base_raw_pool)
        and sorted(new_raw_pool) != sorted(base_raw_pool)
        and percentile_99(new_raw_pool) != percentile_99(base_raw_pool)
    )
    check_case(
        "counted-redistribution-changes-raw-population",
        raw_changed,
        "redistribution did not demonstrably change the raw unit population",
    )

    # Normalized values are untouched by construction (same totals, same
    # counts): verify that on the records, then require the analyzer to
    # agree — both campaigns produce the SAME pooled candidate/control p99
    # on both T4 connect guards and an unchanged T4 verdict/keep, even
    # though the raw-unit population demonstrably moved. An analyzer that
    # pooled raw units instead of normalized estimates would report a
    # different p99 here and fail this check. Reads go through .get so a
    # failed analysis produces a FAIL line, not a KeyError traceback.
    derived_untouched = all(
        derived_field_invariants_hold(before, after)
        for before, after in zip(guard_records(intact), guard_records(redistributed))
    )
    t4_same = t4_target(baseline_verdict).get("verdict") == t4_target(
        redist_verdict
    ).get("verdict") and t4_target(baseline_verdict).get("keep") == t4_target(
        redist_verdict
    ).get("keep")
    guards_pooled = [
        (row_id, arm) for row_id in T4_GUARDS for arm in ("candidate", "control")
    ]
    p99_stable = all(
        pooled_p99(baseline_verdict, row_id, arm) is not None
        and pooled_p99(baseline_verdict, row_id, arm)
        == pooled_p99(redist_verdict, row_id, arm)
        for row_id, arm in guards_pooled
    )
    both_valid = (
        baseline_verdict["metadata"]["validation_passed"] is True
        and redist_verdict["metadata"]["validation_passed"] is True
    )
    base_t4 = t4_target(baseline_verdict)
    redist_t4 = t4_target(redist_verdict)
    check_case(
        "counted-normalized-p99-invariant-under-raw-redistribution",
        both_valid and derived_untouched and t4_same and p99_stable,
        f"valid={both_valid} derived_untouched={derived_untouched} t4_same={t4_same} "
        f"p99_stable={p99_stable} "
        f"baseline=({baseline_verdict['verdict']}, "
        f"T4 {base_t4.get('verdict')}/{base_t4.get('keep')}) "
        f"redistributed=({redist_verdict['verdict']}, "
        f"T4 {redist_t4.get('verdict')}/{redist_t4.get('keep')})",
    )

    # These pooled p99 values must equal the percentile derived
    # independently from the ORIGINAL normalized sample estimates (all
    # measured visits of the guard row pooled across records, interpolated
    # exactly like the analyzer's _percentiles), not from the raw units.
    # This is the assertion a raw-unit p99 substitution fails.
    derived_p99 = {
        (row_id, arm): percentile_99(normalized_pool(intact, row_id, arm))
        for row_id, arm in guards_pooled
    }
    p99_matches_derived = all(
        pooled_p99(baseline_verdict, row_id, arm) == value
        and pooled_p99(redist_verdict, row_id, arm) == value
        for (row_id, arm), value in derived_p99.items()
    )
    check_case(
        "counted-p99-equals-derived-normalized-percentile",
        p99_matches_derived,
        f"analyzer p99={pooled_p99(baseline_verdict, A_GUARD, 'candidate')} "
        f"derived={derived_p99[(A_GUARD, 'candidate')]}",
    )

    # The stored normalized array is the statistics input but never stands
    # alone: starting from a valid campaign, rewriting ONLY the derived
    # arrays (not the raw objects) must be refused by recomputation.
    forged = copy.deepcopy(intact)
    for r in forged:
        if not r.get("row_kind") == "counted":
            continue
        if r.get("target") != "T4" or r.get("arm") != "candidate":
            continue
        r["normalized_ns"] = [float(COUNTED_FLOOR_NS)] * 10
    forged_verdict = analyze_with(sut, reg, forged)
    check_case(
        "counted-stored-normalized-without-raw-refused",
        forged_verdict["metadata"]["validation_passed"] is False
        and forged_verdict["verdict"] == "INCONCLUSIVE"
        and not forged_verdict["targets"],
        f"verdict={forged_verdict['verdict']} "
        f"reasons={forged_verdict.get('reasons', [])[:2]}",
    )


def statistics_adversaries(sut: Sut, reg: Json, tmp: Path) -> None:
    def verdict_for(
        tag: str,
        value_fn: ValueFn,
        cold_fn: ValueFn = BASE_COLD,
        asm_fn: Callable[[str, str, int], int] | None = None,
    ) -> Json:
        return analyze_with(
            sut, reg, build_campaign(sut, reg, tmp, tag, value_fn, cold_fn, asm_fn)
        )

    def viol_fn(t: str, r: str, arm: str, v: int, j: int) -> float:
        if t == "T4" and r == A_ADMISSION and arm == "candidate" and v == 4:
            return 1_080_000.0  # +8%: visit median 8% off its arm median
        return BASE_FN(t, r, arm, v, j)

    verdict = verdict_for("viol", viol_fn)
    t4_reasons = verdict["targets"].get("T4", {}).get("reasons", [])
    check_case(
        "stats-5pct-violation-inconclusive",
        verdict["verdict"] == "INCONCLUSIVE"
        and any("0.05" in str(x) for x in t4_reasons),
        f"verdict={verdict['verdict']} T4={t4_reasons[:2]}",
    )

    verdict = verdict_for("inverted", INV_FN)
    keeps = [
        verdict["targets"].get(t, {}).get("keep") for t in ("T1", "T2", "T3", "T4")
    ]
    check_case(
        "stats-inverted-ratio-no-keep",
        verdict["verdict"] == "REGRESSION" and not any(k is True for k in keeps),
        f"verdict={verdict['verdict']} keeps={keeps}",
    )

    def floor_asm(t: str, arm: str, _v: int) -> int:
        return 2500 if t == "T2" and arm == "control" else 250000

    verdict = verdict_for("floor", BASE_FN, asm_fn=floor_asm)
    t2_out = verdict["targets"].get("T2", {})
    check_case(
        "stats-T2-floor-false-keep",
        t2_out.get("verdict") == "AT_FLOOR" and t2_out.get("keep") is False,
        f"T2={t2_out.get('verdict')} keep={t2_out.get('keep')}",
    )

    def guard_fn(t: str, r: str, arm: str, v: int, j: int) -> float:
        # Intended T4 connect-guard regression lives on measured visits only
        # (visit_index >= 4; zero-block visits 0-3 stay clean so the
        # zero-combined 5% gate is not tripped by the fixture itself).
        if t == "T4" and r == A_GUARD and arm == "candidate" and v >= 4:
            base = 1_144_000.0  # +4% over the 1.1e6 control median
            return base * (1.0 + 0.049 * (j / 9.0)) if v == 7 else base
        return BASE_FN(t, r, arm, v, j)

    verdict = verdict_for("guard", guard_fn)
    t4 = verdict["targets"].get("T4", {})
    t4_reasons = t4.get("reasons", [])
    check_case(
        "stats-T4-connect-guard",
        t4.get("verdict") == "REGRESSION"
        and any("0.03" in str(x) for x in t4_reasons)
        and any("p99" in str(x) for x in t4_reasons),
        f"T4={t4.get('verdict')} reasons={t4_reasons[:3]}",
    )

    def spread_fn(t: str, r: str, arm: str, v: int, j: int) -> float:
        if (
            t == "T1"
            and r == "mempool_insert_entry/fill/200"
            and arm == "candidate"
            and v == 4
        ):
            return 1_200_000.0
        return BASE_FN(t, r, arm, v, j)

    verdict = verdict_for("t1spread", spread_fn)
    t1_reasons = verdict["targets"].get("T1", {}).get("reasons", [])
    check_case(
        "stats-T1-spread-violation-inconclusive",
        verdict["verdict"] == "INCONCLUSIVE"
        and any("spread" in str(x) for x in t1_reasons),
        f"verdict={verdict['verdict']} T1={t1_reasons[:2]}",
    )

    sub_records = build_campaign(sut, reg, tmp, "sub1s", BASE_FN)
    for record in sub_records:
        if record["row_kind"] == "criterion":
            record["sample_times_ns"][0] = 5.0e8
            break
    sub_verdict = analyze_with(sut, reg, sub_records)
    check_case(
        "stats-subsecond-raw-interval-inconclusive",
        sub_verdict["verdict"] == "INCONCLUSIVE"
        and any("below 1 s" in str(x) for x in sub_verdict.get("reasons", [])),
        f"verdict={sub_verdict['verdict']} reasons={sub_verdict.get('reasons', [])[:2]}",
    )

    def zero_only_fn(t: str, r: str, arm: str, v: int, j: int) -> float:
        if t == "T4" and r == A_ADMISSION and arm == "zero" and v in (1, 2):
            return 1_200_000.0
        return BASE_FN(t, r, arm, v, j)

    verdict = verdict_for("zeroonly", zero_only_fn)
    t4_zero_reasons = verdict["targets"].get("T4", {}).get("reasons", [])
    check_case(
        "stats-zero-only-instability-inconclusive",
        verdict["verdict"] == "INCONCLUSIVE"
        and any("zero" in str(x) for x in t4_zero_reasons),
        f"verdict={verdict['verdict']} T4={t4_zero_reasons[:2]}",
    )

    def noise_fn(t: str, r: str, arm: str, v: int, j: int) -> float:
        if t == "T4" and r == A_ADMISSION and v >= 4:
            base = 1_000_000.0 if arm in ("candidate", "zero") else 1_060_000.0
            return base * (0.96 if v % 2 == 0 else 1.04)
        return BASE_FN(t, r, arm, v, j)

    verdict = verdict_for("noiseb", noise_fn)
    t4 = verdict["targets"].get("T4", {})
    check_case(
        "stats-ratio-passes-noise-blocks-keep",
        verdict["verdict"] == "NON_REGRESSION_EVIDENCED"
        and t4.get("keep") is False
        and "1.06" in " ".join(str(x) for x in t4.get("reasons", [])),
        f"verdict={verdict['verdict']} T4={t4.get('keep')} "
        f"reasons={t4.get('reasons', [])[:2]}",
    )


# --------------------------------------------------------------------------
# Tooling-owned review repairs (PR1642 inline 1,10,12,19,22 plus 42,43/body25
# Rust/doc companions proven by bench --mrp-verify and compile smoke; the
# Python probes below cover the runner/analyzer-owned boundary cases).
# --------------------------------------------------------------------------


def tooling_owned_adversaries(sut: Sut, reg: Json, tmp: Path) -> None:
    probe_dir = tmp / "tooling-owned"
    probe_dir.mkdir(parents=True, exist_ok=True)
    iso = probe_dir / "iso-cleanup"
    iso.mkdir(parents=True, exist_ok=True)
    iso_analyzer = iso / ANALYZER_FILE
    iso_analyzer.write_bytes(Path(sut.analyzer_path).read_bytes())
    clean_runner = Path(sut.runner_path).read_bytes()
    good_runner = iso / RUNNER_FILE
    good_runner.write_bytes(clean_runner)
    good_sha = sha_of(good_runner)
    good_reg = copy.deepcopy(reg)
    good_reg["scripts"]["runner"] = {"path": str(good_runner), "sha256": good_sha}
    good_reg["scripts"]["analyzer"] = {
        "path": str(iso_analyzer),
        "sha256": sha_of(iso_analyzer),
    }
    spec = importlib.util.spec_from_file_location(
        "mrp_tooling_cleanup_loader", iso_analyzer
    )
    if spec is None or spec.loader is None:
        check_case("tooling-loader-unavailable", False, "cannot load isolated copy")
        return
    loader = importlib.util.module_from_spec(spec)
    sys.modules["mrp_tooling_cleanup_loader"] = loader
    spec.loader.exec_module(loader)
    failing = iso / "failing_runner.py"
    failing.write_bytes(clean_runner + b'\nraise RuntimeError("probe top-level failure")\n')
    failing_sha = sha_of(failing)
    bad_reg = copy.deepcopy(good_reg)
    bad_reg["scripts"]["runner"] = {"path": str(failing), "sha256": failing_sha}
    saved = sys.modules.get("rbitcoin_mrp_run_validator")
    sentinel = ModuleType("rbitcoin_mrp_run_validator")
    sys.modules["rbitcoin_mrp_run_validator"] = sentinel
    try:
        runtime_exc: Exception | None = None
        try:
            loader._runner(copy.deepcopy(bad_reg))
        except Exception as exc:  # noqa: BLE001 - probe records any failure shape
            runtime_exc = exc
        check_case(
            "tooling-runner-runtime-error-cleanup",
            isinstance(runtime_exc, loader.AnalysisError)
            and sys.modules.get("rbitcoin_mrp_run_validator") is sentinel
            and loader._RUNNER is None,
            f"exc={runtime_exc!r} restored={sys.modules.get('rbitcoin_mrp_run_validator') is sentinel}",
        )
        interrupt_runner = iso / "interrupt_runner.py"
        interrupt_runner.write_bytes(clean_runner + b"\nraise KeyboardInterrupt()\n")
        interrupt_sha = sha_of(interrupt_runner)
        interrupt_reg = copy.deepcopy(good_reg)
        interrupt_reg["scripts"]["runner"] = {
            "path": str(interrupt_runner),
            "sha256": interrupt_sha,
        }
        interrupt_exc: BaseException | None = None
        try:
            loader._runner(copy.deepcopy(interrupt_reg))
        except BaseException as exc:  # noqa: BLE001 - interruption must surface
            interrupt_exc = exc
        check_case(
            "tooling-runner-interrupt-cleanup",
            isinstance(interrupt_exc, KeyboardInterrupt)
            and sys.modules.get("rbitcoin_mrp_run_validator") is sentinel
            and loader._RUNNER is None,
            f"exc={interrupt_exc!r} restored={sys.modules.get('rbitcoin_mrp_run_validator') is sentinel}",
        )
    finally:
        if saved is None:
            sys.modules.pop("rbitcoin_mrp_run_validator", None)
        else:
            sys.modules["rbitcoin_mrp_run_validator"] = saved
    first = loader._runner(copy.deepcopy(good_reg))
    check_case(
        "tooling-runner-success-caches",
        first is not None and loader._RUNNER is first,
        "successful load did not cache",
    )
    try:
        loader._runner(copy.deepcopy(bad_reg))
        second_failed = False
    except Exception:  # noqa: BLE001 - failure must preserve the good cache
        second_failed = True
    third = loader._runner(copy.deepcopy(good_reg))
    check_case(
        "tooling-runner-failure-preserves-cache",
        second_failed and third is first,
        "failed load clobbered the verified cache",
    )
    search_root = probe_dir / "criterion-search"
    both_home = search_root / "both"
    (both_home / "row-a" / "new").mkdir(parents=True, exist_ok=True)
    (both_home / "row-a" / "base").mkdir(parents=True, exist_ok=True)
    both_new = both_home / "row-a" / "new" / "sample.json"
    both_base = both_home / "row-a" / "base" / "sample.json"
    both_new.write_text(json.dumps({"iters": [1.0] * 10, "times": [1.5e9] * 10}))
    both_base.write_text(json.dumps({"iters": [1.0] * 10, "times": [1.5e9] * 10}))
    try:
        picked = sut.run.find_single_sample_json(both_home)
        both_ok = picked == both_new
        both_detail = f"picked={picked}"
    except Exception as exc:  # noqa: BLE001
        both_ok = False
        both_detail = f"raised {exc!r}"
    check_case("tooling-sample-both-dirs-selects-new", both_ok, both_detail)
    empty_home = search_root / "empty"
    empty_home.mkdir(parents=True, exist_ok=True)
    try:
        sut.run.find_single_sample_json(empty_home)
        empty_ok = False
        empty_detail = "zero matches accepted"
    except Exception as exc:  # noqa: BLE001
        empty_ok = "exactly one new/sample.json" in str(exc)
        empty_detail = str(exc)[:200]
    check_case("tooling-sample-zero-rejected", empty_ok, empty_detail)
    multi_home = search_root / "multi"
    for row in ("row-a", "row-b"):
        p = multi_home / row / "new" / "sample.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"iters": [1.0], "times": [1.5e9]}))
    try:
        sut.run.find_single_sample_json(multi_home)
        multi_ok = False
        multi_detail = "multiple matches accepted"
    except Exception as exc:  # noqa: BLE001
        multi_ok = "exactly one new/sample.json" in str(exc)
        multi_detail = str(exc)[:200]
    check_case("tooling-sample-multiple-new-rejected", multi_ok, multi_detail)
    base_only_home = search_root / "base-only"
    (base_only_home / "row-a" / "base").mkdir(parents=True, exist_ok=True)
    (base_only_home / "row-a" / "base" / "sample.json").write_text(
        json.dumps({"iters": [1.0], "times": [1.5e9]})
    )
    try:
        sut.run.find_single_sample_json(base_only_home)
        base_ok = False
        base_detail = "base-only accepted as new"
    except Exception as exc:  # noqa: BLE001
        base_ok = "exactly one new/sample.json" in str(exc)
        base_detail = str(exc)[:200]
    check_case("tooling-sample-base-only-rejected", base_ok, base_detail)
    manifest_probe = probe_dir / "manifest-runs"
    manifest_probe.mkdir(parents=True, exist_ok=True)
    (manifest_probe / "results.json").write_text(json.dumps([{"synthetic": True}]))
    (manifest_probe / "case" / "stdout.log").parent.mkdir(parents=True, exist_ok=True)
    (manifest_probe / "case" / "stdout.log").write_text("synthetic\n")
    valid_manifest = manifest_for_dir(manifest_probe)
    valid_records = build_campaign(sut, reg, tmp, "tooling-manifest-valid", BASE_FN)
    valid_reasons, _ = sut.ana.validate_all(
        copy.deepcopy(reg), copy.deepcopy(valid_records), manifest_probe, valid_manifest
    )
    check_case(
        "tooling-manifest-valid-passes",
        valid_reasons == [],
        f"valid manifest rejected: {valid_reasons[:3]}",
    )
    empty_manifest: Json = {"algorithm": "sha256", "files": {}}
    empty_reasons, _ = sut.ana.validate_all(
        copy.deepcopy(reg), copy.deepcopy(valid_records), manifest_probe, empty_manifest
    )
    check_case(
        "tooling-manifest-empty-rejected",
        bool(empty_reasons) and any("empty" in r or "missing" in r for r in empty_reasons),
        f"accepted: {empty_reasons[:2]}",
    )
    wrong_algo = copy.deepcopy(valid_manifest)
    wrong_algo["algorithm"] = "sha512"
    algo_reasons, _ = sut.ana.validate_all(
        copy.deepcopy(reg), copy.deepcopy(valid_records), manifest_probe, wrong_algo
    )
    check_case(
        "tooling-manifest-algorithm-rejected",
        bool(algo_reasons) and any("algorithm" in r for r in algo_reasons),
        f"accepted: {algo_reasons[:2]}",
    )
    partial = copy.deepcopy(valid_manifest)
    partial["files"].pop(next(iter(partial["files"])))
    partial_reasons, _ = sut.ana.validate_all(
        copy.deepcopy(reg), copy.deepcopy(valid_records), manifest_probe, partial
    )
    check_case(
        "tooling-manifest-partial-rejected",
        bool(partial_reasons) and any("omits" in r for r in partial_reasons),
        f"accepted: {partial_reasons[:2]}",
    )
    (manifest_probe / "unlisted.txt").write_text("extra\n")
    extra_reasons, _ = sut.ana.validate_all(
        copy.deepcopy(reg), copy.deepcopy(valid_records), manifest_probe, valid_manifest
    )
    check_case(
        "tooling-manifest-extra-file-rejected",
        bool(extra_reasons) and any("omits" in r for r in extra_reasons),
        f"accepted: {extra_reasons[:2]}",
    )
    (manifest_probe / "unlisted.txt").unlink()
    dot_alias = copy.deepcopy(valid_manifest)
    dot_alias["files"]["./results.json"] = dot_alias["files"].pop("results.json")
    dot_alias_reasons, _ = sut.ana.validate_all(
        copy.deepcopy(reg), copy.deepcopy(valid_records), manifest_probe, dot_alias
    )
    check_case(
        "tooling-manifest-dot-alias-key-rejected",
        any("canonical POSIX" in r for r in dot_alias_reasons),
        f"accepted: {dot_alias_reasons[:3]}",
    )
    produced_runs = probe_dir / "manifest-produced"
    (produced_runs / "case").mkdir(parents=True, exist_ok=True)
    (produced_runs / "results.json").write_text(json.dumps([{"synthetic": True}]))
    (produced_runs / "case" / "stdout.log").write_text("synthetic\n")
    # A regular nested file that shares a reserved name is an ordinary artifact.
    (produced_runs / "case" / "manifest.json").write_text("nested artifact\n")
    sut.run.write_manifest(produced_runs)
    produced = json.loads((produced_runs / "manifest.json").read_text())
    produced_reasons, _ = sut.ana.validate_all(
        copy.deepcopy(reg), copy.deepcopy(valid_records), produced_runs, produced
    )
    check_case(
        "tooling-manifest-producer-output-accepted",
        produced_reasons == []
        and sorted(produced["files"])
        == ["case/manifest.json", "case/stdout.log", "results.json"]
        and produced["files"]["case/manifest.json"]
        == sha_of(produced_runs / "case" / "manifest.json"),
        f"producer manifest rejected or wrong keys: {produced_reasons[:3]} {sorted(produced['files'])}",
    )
    link_runs = probe_dir / "manifest-symlink-runs"
    (link_runs / "case").mkdir(parents=True, exist_ok=True)
    (link_runs / "results.json").write_text(json.dumps([{"synthetic": True}]))
    (link_runs / "case" / "stdout.log").write_text("synthetic\n")
    link_clean_manifest = manifest_for_dir(link_runs)
    (link_runs / "alias.log").symlink_to("results.json")
    # `manifest_for_dir` follows symlinks, exactly as the old producer did, so
    # this manifest lists the alias with a matching digest.
    link_followed_manifest = manifest_for_dir(link_runs)
    for name, link_manifest in (
        ("omitted", link_clean_manifest),
        ("listed", link_followed_manifest),
    ):
        link_reasons, _ = sut.ana.validate_all(
            copy.deepcopy(reg), copy.deepcopy(valid_records), link_runs, link_manifest
        )
        check_case(
            f"tooling-manifest-symlink-artifact-{name}-rejected",
            any("is a symlink" in r for r in link_reasons),
            f"accepted: {link_reasons[:3]}",
        )
    try:
        sut.run.write_manifest(link_runs)
        producer_refused = False
        producer_detail = "symlinked runs artifact was anchored"
    except sut.run.RegistrationError as exc:
        producer_refused = "symlink" in str(exc)
        producer_detail = str(exc)[:200]
    check_case(
        "tooling-manifest-producer-refuses-symlink",
        producer_refused and not (link_runs / "manifest.json").exists(),
        producer_detail,
    )
    # The reserved-name scenario owns its fixture: it must not depend on what
    # the producer-refusal case above did or did not leave in `link_runs`.
    reserved_runs = probe_dir / "manifest-reserved-symlink-runs"
    (reserved_runs / "case").mkdir(parents=True, exist_ok=True)
    (reserved_runs / "results.json").write_text(json.dumps([{"synthetic": True}]))
    (reserved_runs / "case" / "stdout.log").write_text("synthetic\n")
    reserved_clean_manifest = manifest_for_dir(reserved_runs)
    (reserved_runs / "manifest.json").symlink_to("results.json")
    reserved_reasons, _ = sut.ana.validate_all(
        copy.deepcopy(reg),
        copy.deepcopy(valid_records),
        reserved_runs,
        reserved_clean_manifest,
    )
    check_case(
        "tooling-manifest-reserved-name-symlink-rejected",
        any("is a symlink" in r for r in reserved_reasons),
        f"accepted: {reserved_reasons[:3]}",
    )
    results_before = (reserved_runs / "results.json").read_bytes()
    try:
        sut.run.write_manifest(reserved_runs)
        reserved_refused = False
    except sut.run.RegistrationError:
        reserved_refused = True
    check_case(
        "tooling-manifest-producer-never-writes-through-symlink",
        reserved_refused
        and (reserved_runs / "results.json").read_bytes() == results_before,
        "producer wrote through a reserved-name symlink",
    )
    escape_manifest = copy.deepcopy(valid_manifest)
    escape_manifest["files"]["../evil.txt"] = "a" * 64
    escape_reasons, _ = sut.ana.validate_all(
        copy.deepcopy(reg), copy.deepcopy(valid_records), manifest_probe, escape_manifest
    )
    check_case(
        "tooling-manifest-escape-rejected",
        bool(escape_reasons) and any("escapes" in r or "malformed" in r for r in escape_reasons),
        f"accepted: {escape_reasons[:2]}",
    )
    absolute_manifest = copy.deepcopy(valid_manifest)
    absolute_manifest["files"]["/abs/path.txt"] = "b" * 64
    absolute_reasons, _ = sut.ana.validate_all(
        copy.deepcopy(reg), copy.deepcopy(valid_records), manifest_probe, absolute_manifest
    )
    check_case(
        "tooling-manifest-absolute-rejected",
        bool(absolute_reasons) and any("malformed" in r for r in absolute_reasons),
        f"accepted: {absolute_reasons[:2]}",
    )
    digest_manifest = copy.deepcopy(valid_manifest)
    victim_key = next(iter(digest_manifest["files"]))
    digest_manifest["files"][victim_key] = "ZZZ"
    digest_reasons, _ = sut.ana.validate_all(
        copy.deepcopy(reg), copy.deepcopy(valid_records), manifest_probe, digest_manifest
    )
    check_case(
        "tooling-manifest-digest-rejected",
        bool(digest_reasons) and any("digest" in r for r in digest_reasons),
        f"accepted: {digest_reasons[:2]}",
    )
    tamper_target = manifest_probe / victim_key
    tamper_target.write_bytes(tamper_target.read_bytes() + b"tamper\n")
    mismatch_reasons, _ = sut.ana.validate_all(
        copy.deepcopy(reg), copy.deepcopy(valid_records), manifest_probe, valid_manifest
    )
    check_case(
        "tooling-manifest-mismatch-rejected",
        bool(mismatch_reasons) and any("mismatch" in r for r in mismatch_reasons),
        f"accepted: {mismatch_reasons[:2]}",
    )
    prov_dir = probe_dir / "provenance"
    prov_dir.mkdir(parents=True, exist_ok=True)
    prov_counter = [0]

    def prov_swap(entry: Json, doc: Json) -> None:
        prov_counter[0] += 1
        entry.update(write_doc(prov_dir / f"prov-{prov_counter[0]}.json", doc))

    def prov_reject(name: str, mutate: Callable[[Json], None], hint: str) -> None:
        bad = copy.deepcopy(reg)
        mutate(bad)
        reasons = sut.run.validate_registration(bad, False)
        hit = any(hint in r for r in reasons)
        check_case(
            f"tooling-provenance-{name}",
            bool(reasons) and hit,
            "accepted invalid provenance"
            if not reasons
            else f"rejected without {hint!r}: {reasons[:3]}",
        )

    first_candidate = "candidate/insert_fill"
    candidate_doc = json.loads(Path(reg["binaries"][first_candidate]["receipt"]["path"]).read_text())
    def drop_source(b: Json) -> None:
        doc = {k: v for k, v in candidate_doc.items() if k != "source_commit"}
        prov_swap(b["binaries"][first_candidate]["receipt"], doc)
    prov_reject("candidate-missing-source", drop_source, "source_commit must be")
    def candidate_with_base(b: Json) -> None:
        doc = dict(candidate_doc)
        doc["base_commit"] = "b" * 40
        doc["transform"] = "synthetic control transform"
        prov_swap(b["binaries"][first_candidate]["receipt"], doc)
    prov_reject("candidate-with-base", candidate_with_base, "must not carry")
    first_control = "control_T1/insert_fill"
    control_doc = json.loads(Path(reg["binaries"][first_control]["receipt"]["path"]).read_text())
    def drop_base(b: Json) -> None:
        doc = {k: v for k, v in control_doc.items() if k != "base_commit"}
        prov_swap(b["binaries"][first_control]["receipt"], doc)
    prov_reject("control-missing-base", drop_base, "base_commit must be")
    def drop_transform(b: Json) -> None:
        doc = {k: v for k, v in control_doc.items() if k != "transform"}
        prov_swap(b["binaries"][first_control]["receipt"], doc)
    prov_reject("control-missing-transform", drop_transform, "transform")
    def control_claims_source(b: Json) -> None:
        doc = dict(control_doc)
        doc["source_commit"] = "c" * 40
        prov_swap(b["binaries"][first_control]["receipt"], doc)
    prov_reject("control-claims-source", control_claims_source, "must not claim")
    def control_bad_base(b: Json) -> None:
        doc = dict(control_doc)
        doc["base_commit"] = "b" * 40
        prov_swap(b["binaries"][first_control]["receipt"], doc)
    prov_reject("control-base-mismatch", control_bad_base, "base_commit")
    def candidate_disagree(b: Json) -> None:
        doc = dict(candidate_doc)
        doc["source_commit"] = "c" * 40
        prov_swap(b["binaries"][first_candidate]["receipt"], doc)
    prov_reject("candidate-disagree", candidate_disagree, "disagree")
    def malformed_commit(b: Json) -> None:
        doc = dict(candidate_doc)
        doc["source_commit"] = "ZZZ"
        prov_swap(b["binaries"][first_candidate]["receipt"], doc)
    prov_reject("malformed-commit", malformed_commit, "source_commit must be")
    def empty_transform(b: Json) -> None:
        doc = dict(control_doc)
        doc["transform"] = "   "
        prov_swap(b["binaries"][first_control]["receipt"], doc)
    prov_reject("empty-transform", empty_transform, "transform")
    second_control = "control_T2/sync_pipeline"
    second_control_doc = json.loads(
        Path(reg["binaries"][second_control]["receipt"]["path"]).read_text()
    )
    def duplicate_transform(b: Json) -> None:
        doc = dict(second_control_doc)
        doc["transform"] = control_doc["transform"]
        prov_swap(b["binaries"][second_control]["receipt"], doc)
    prov_reject(
        "duplicate-control-transform",
        duplicate_transform,
        "distinct per control tree",
    )
    def split_transform_within_tree(b: Json) -> None:
        doc = dict(control_doc)
        doc["transform"] = control_doc["transform"] + " variant"
        prov_swap(b["binaries"][first_control]["receipt"], doc)
    prov_reject(
        "disagreement-within-one-control-tree",
        split_transform_within_tree,
        "disagrees within one control tree",
    )
    def all_malformed_commits(b: Json) -> None:
        for key in sorted(b["binaries"]):
            entry = b["binaries"][key]
            tree_name = key.split("/", 1)[0]
            doc = json.loads(Path(entry["receipt"]["path"]).read_text())
            if tree_name == "candidate":
                doc["source_commit"] = "ZZZ"
            elif tree_name.startswith("control"):
                doc["base_commit"] = "ZZZ"
            else:
                raise SystemExit(
                    "probe prerequisite violated: unexpected tree "
                    f"{tree_name!r} in all-malformed-commits"
                )
            prov_swap(entry["receipt"], doc)
    prov_reject(
        "all-malformed-commits",
        all_malformed_commits,
        "lowercase 40- or 64-hex",
    )
    cancel_dir = probe_dir / "cancel-exit"
    cancel_dir.mkdir(parents=True, exist_ok=True)
    cancel_reg = copy.deepcopy(reg)
    cancel_reg["campaign_root"] = str(cancel_dir / "runs-cancelled")
    cancel_live = sut.run.validate_live_registration(
        copy.deepcopy(cancel_reg), True
    )
    if cancel_live:
        check_case(
            "tooling-cancel-exit-prerequisite",
            False,
            f"synthetic registration rejected by live path: {cancel_live[:3]}",
        )
        return
    cancel_file = cancel_dir / "reg_cancel.json"
    cancel_file.write_text(json.dumps(cancel_reg), encoding="utf-8")
    error_reg = copy.deepcopy(reg)
    error_reg["campaign_root"] = str(cancel_dir / "runs-error")
    error_file = cancel_dir / "reg_error.json"
    error_file.write_text(json.dumps(error_reg), encoding="utf-8")
    scripted: list[Json] = []
    real_execute = sut.run.execute_case

    def fake_execute(
        case: Json,
        _reg: Json,
        _runs_dir: Path,
        _cpu: int,
        _timeout_seconds: float,
    ) -> Json:
        record = dict(scripted.pop(0))
        row = case["row"]
        record["label"] = (
            f"{case['target']}-b{case['block']}"
            f"v{case['visit_index']:02d}-{case['arm']}-{row['id']}"
        )
        record["case_index"] = case["case_index"]
        return record

    sut.run.execute_case = fake_execute  # type: ignore[method-assign]
    try:
        scripted.append(
            {
                "cancelled": True,
                "error": "case cancelled; process group killed, no retry",
                "case_median_ns": 0,
            }
        )
        cancelled_err = io.StringIO()
        with contextlib.redirect_stderr(cancelled_err):
            cancelled_code = sut.run.cmd_run(cancel_file)
        check_case(
            "tooling-cancelled-error-exits-130",
            cancelled_code == 130 and "CANCELLED" in cancelled_err.getvalue(),
            f"exit={cancelled_code} "
            f"stderr={cancelled_err.getvalue()[:200]!r}",
        )
        scripted.append(
            {
                "cancelled": False,
                "error": "synthetic launch failure",
                "case_median_ns": 0,
            }
        )
        plain_err = io.StringIO()
        with contextlib.redirect_stderr(plain_err):
            plain_code = sut.run.cmd_run(error_file)
        check_case(
            "tooling-error-without-cancel-exits-1",
            plain_code == 1 and "STOP" in plain_err.getvalue(),
            f"exit={plain_code} stderr={plain_err.getvalue()[:200]!r}",
        )
    finally:
        sut.run.execute_case = real_execute  # type: ignore[method-assign]


def main() -> int:
    here = Path(__file__).resolve()
    ap = argparse.ArgumentParser(
        description="Adversarial smoke test for the measured-campaign "
        "runner/analyzer. Synthetic fixtures only; never launches benchmarks."
    )
    ap.add_argument(
        "--runner",
        default=str(here.with_name(RUNNER_FILE)),
        help=f"path to {RUNNER_FILE} (default: sibling of this file)",
    )
    ap.add_argument(
        "--analyzer",
        default=str(here.with_name(ANALYZER_FILE)),
        help=f"path to {ANALYZER_FILE} (default: sibling of this file)",
    )
    args = ap.parse_args()
    runner_path = Path(args.runner).resolve()
    analyzer_path = Path(args.analyzer).resolve()
    for path, name in ((runner_path, RUNNER_FILE), (analyzer_path, ANALYZER_FILE)):
        if path.name != name or not path.is_file():
            raise SystemExit(f"probe prerequisite missing: {name} not found at {path}")
    if runner_path.parent != analyzer_path.parent:
        raise SystemExit(
            "probe prerequisite: runner and analyzer must share one directory"
        )
    sut = Sut(
        load_sut(runner_path, "rbitcoin_mrp_run_sut"),
        load_sut(analyzer_path, "rbitcoin_mrp_analyze_sut"),
        runner_path,
        analyzer_path,
    )

    with tempfile.TemporaryDirectory(prefix="mrp-probe-") as tmpdir:
        tmp = Path(tmpdir)
        reg, _ = positive_phase(sut, tmp)
        if any(not ok for _, ok, _ in RESULTS):
            failed = [n for n, ok, _ in RESULTS if not ok]
            print(f"ABORT: positive phase failed {failed}; no adversary result counts.")
            return 1
        positives = len(RESULTS)
        row_adversaries(sut, reg)
        freeze_adversaries(sut, reg, tmp)
        script_and_evidence_adversaries(sut, reg, tmp)
        identity_adversaries(sut, reg)
        distinctness_and_loader_adversaries(sut, reg, tmp)
        analyzer_self_binding_adversaries(sut, reg, tmp)
        host_binding_adversaries(sut, reg, tmp)
        std_adversaries(sut, reg, tmp)
        parser_adversaries(sut, tmp)
        counted_adversaries(sut, reg, tmp)
        statistics_adversaries(sut, reg, tmp)
        tooling_owned_adversaries(sut, reg, tmp)
        bad_reg = copy.deepcopy(reg)
        row_of(bad_reg, "T1", "mempool_insert_entry/fill/200")["samples"] = 9
        bad_file = tmp / "reg_bad.json"
        bad_file.write_text(json.dumps(bad_reg), encoding="utf-8")
        proc = run_cli(sut.runner_path, "validate", "--registration", str(bad_file))
        check_case(
            "reject-cli-validate-bad-registration",
            proc.returncode != 0,
            "invalid registration passed CLI validate",
        )

    failed = [(n, d) for n, ok, d in RESULTS if not ok]
    print(
        f"\nprobe: {len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed "
        f"({positives} positive before any adversary; synthetic fixtures only; "
        "no workload launched)"
    )
    if failed:
        print("failures:")
        for name, detail in failed:
            print(f"  - {name}: {detail}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
