#!/usr/bin/env python3
"""Parallel execution engine behind tools/core-functional/run.sh.

Runs extracted Bitcoin Core functional tests one-per-process against the
bitcoin-rs node through the bin/bitcoind-wrapper adapter, classifies exit
codes (0 PASS, 77 SKIP, anything else FAIL - timeout gets its own marker),
and writes report.json (machine) + report.md (human) into the results dir.
The reports are the evidence owner for any compatibility claim made from this
lane; see tools/core-functional/README.md.
"""

import argparse
import concurrent.futures
import datetime
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time

LOG_TAIL_LINES = 30


def parse_args():
    parser = argparse.ArgumentParser(prog="run.sh", add_help=False)
    parser.add_argument("--tests", nargs="+", required=True)
    parser.add_argument("--dest", required=True, help="extraction dir (core-v31.1)")
    parser.add_argument("--config", required=True, help="rendered config.ini path")
    parser.add_argument("--results-dir", required=True)
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--template", required=True, help="config.ini template to render")
    return parser.parse_args()


def render_config(template, dest, output_path):
    text = pathlib.Path(template).read_text(encoding="utf-8")
    pathlib.Path(output_path).write_text(text.replace("@CORE_TESTS_DIR@", str(dest)), encoding="utf-8")


def classify(exit_code, timed_out):
    if timed_out:
        return "FAIL"
    if exit_code == 0:
        return "PASS"
    if exit_code == 77:
        return "SKIP"
    return "FAIL"


def log_tail(path):
    try:
        lines = pathlib.Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    return "\n".join(lines[-LOG_TAIL_LINES:]) if lines else None


def run_one(test, args, env):
    """Run a single test file; return its result record."""
    test_dir = pathlib.Path(args.dest) / "test" / "functional"
    script = test_dir / f"{test}.py"
    tmpdir = pathlib.Path(args.results_dir) / "tmp" / test
    if tmpdir.exists():
        shutil.rmtree(tmpdir)  # framework requires a nonexistent --tmpdir
    command = [
        "timeout", str(args.timeout), sys.executable, str(script),
        f"--configfile={args.config}",
        f"--tmpdir={tmpdir}",
        f"--cachedir={pathlib.Path(args.results_dir) / 'cache'}",
    ]
    started = time.monotonic()
    proc = subprocess.run(command, cwd=test_dir, env=env, capture_output=True, text=True)
    duration = time.monotonic() - started
    timed_out = proc.returncode == 124
    return {
        "name": test,
        "status": classify(proc.returncode, timed_out),
        "exit_code": proc.returncode,
        "timeout": timed_out,
        "duration_secs": round(duration, 1),
        "log_tail": log_tail(tmpdir / "test_framework.log") if proc.returncode != 0 else None,
    }


def main():
    args = parse_args()
    results_dir = pathlib.Path(args.results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)
    config_path = results_dir / "config.ini"
    render_config(args.template, args.dest, config_path)

    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(pathlib.Path(__file__).resolve().parent.parent / "shim")]
        + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else []))

    print(f"results dir : {results_dir}")
    print(f"core tests  : {args.dest}")
    print(f"node binary : {env.get('BITCOIN_RS_BIN', '<unset>')}")
    print(f"wrapper     : {env.get('BITCOIND', '<unset>')}")
    print(f"tests={len(args.tests)} jobs={args.jobs} timeout={args.timeout}s", flush=True)

    started = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {pool.submit(run_one, test, args, env): test for test in args.tests}
        records = []
        for future in concurrent.futures.as_completed(futures):
            record = future.result()
            records.append(record)
            marker = {"PASS": "+", "SKIP": "-", "FAIL": "x"}[record["status"]]
            note = " (timeout)" if record["timeout"] else ""
            print(f"[{marker}] {record['name']:<55} {record['status']}{note} "
                  f"({record['duration_secs']}s)", flush=True)
    records.sort(key=lambda record: record["name"])

    totals = {status: sum(1 for r in records if r["status"] == status)
              for status in ("PASS", "SKIP", "FAIL")}
    provenance = {}
    try:
        for line in (pathlib.Path(args.dest) / "PROVENANCE").read_text().splitlines():
            key, sep, value = line.partition("=")
            if sep:
                provenance[key] = value
    except OSError:
        pass

    report = {
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "core_tag": provenance.get("core_tag"),
        "core_commit": provenance.get("core_commit"),
        "core_source_repo": provenance.get("source_repo"),
        "dest": str(args.dest),
        "bitcoin_rs_bin": env.get("BITCOIN_RS_BIN"),
        "config": str(config_path),
        "jobs": args.jobs,
        "timeout_secs": args.timeout,
        "wall_secs": round(time.monotonic() - started, 1),
        "totals": {"pass": totals["PASS"], "skip": totals["SKIP"],
                   "fail": totals["FAIL"], "total": len(records)},
        "tests": records,
    }
    (results_dir / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    lines = [
        "# Core functional lane results",
        "",
        f"- generated: {report['generated_utc']}",
        f"- Core: {report['core_tag']} ({report['core_commit']}) from {report['core_source_repo']}",
        f"- node binary: `{report['bitcoin_rs_bin']}` via bin/bitcoind-wrapper",
        f"- totals: **{totals['PASS']} pass** / {totals['SKIP']} skip / {totals['FAIL']} fail "
        f"of {len(records)} in {report['wall_secs']}s",
        "",
        "| test | status | duration (s) |",
        "|------|--------|--------------|",
    ]
    for record in records:
        suffix = " (timeout)" if record["timeout"] else ""
        lines.append(f"| {record['name']} | {record['status']}{suffix} | {record['duration_secs']} |")
    (results_dir / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"\nreport: {results_dir / 'report.md'}")
    print(f"        {results_dir / 'report.json'}")
    return 1 if totals["FAIL"] else 0


if __name__ == "__main__":
    sys.exit(main())
