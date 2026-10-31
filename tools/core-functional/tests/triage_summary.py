#!/usr/bin/env python3
"""Summarize one run's failures: last exception per test from test_framework.log.

Scratch triage aid for the lane (not part of the evidence chain; the reports
under the results dir are). Prints one line per non-PASS test with the
innermost exception/error found in its test_framework.log.
"""

import json
import pathlib
import re
import sys

results = pathlib.Path(sys.argv[1])
report = json.loads((results / "report.json").read_text())

CAUSE = re.compile(
    r"^(?P<exc>[A-Za-z_.]*(?:Error|Exception|FailedToStart[A-Za-z]*))"r"(?::\s*(?P<msg>.*))?$"
)

for record in sorted(report["tests"], key=lambda r: (r["status"], r["name"])):
    if record["status"] == "PASS":
        continue
    log = results / "tmp" / record["name"] / "test_framework.log"
    cause = "<no framework log>"
    if log.is_file():
        found = []
        for line in log.read_text(errors="replace").splitlines():
            match = CAUSE.match(line.strip())
            if match:
                found.append(f"{match['exc']}: {match['msg'] or ''}".strip(": "))
        cause = found[-1] if found else "<no exception line>"
    note = " TIMEOUT" if record["timeout"] else ""
    print(f"{record['status']}{note:<8} {record['name']:<42} {cause[:150]}")
