"""Run AB/BA/AB on one CPU; retain raw samples and reject output divergence."""
import hashlib
import json
import math
import os
from pathlib import Path
import statistics
import subprocess
import sys

root = Path(sys.argv[1])
cpu = min(os.sched_getaffinity(0))
results = []
for mode in ('gate', 'tick'):
    for run, arm in enumerate(('control', 'candidate', 'candidate', 'control', 'control', 'candidate')):
        env = os.environ | {'FRONTIER_HEIGHT': '262144', 'FRONTIER_MODE': mode}
        exe = root / (arm + '-probe')
        completed = subprocess.run(['taskset', '-c', str(cpu), str(exe),
            'workbench_sync_frontier_measurement', '--ignored', '--exact', '--nocapture', '--test-threads=1'],
            capture_output=True, text=True, env=env, timeout=180)
        # The full test path is required with --exact.
        if '0 tests' in completed.stdout and 'SYNC_SAMPLE ' not in completed.stdout:
            completed = subprocess.run(['taskset', '-c', str(cpu), str(exe),
                'sync::tests::workbench_sync_frontier_measurement', '--ignored', '--exact', '--nocapture', '--test-threads=1'],
                capture_output=True, text=True, env=env, timeout=180)
        log = root / f'{mode}-{run}-{arm}.log'
        log.write_text(completed.stdout + completed.stderr)
        if completed.returncode:
            print(log.read_text())
            raise SystemExit(completed.returncode)
        samples, identities = [], []
        for line in completed.stdout.splitlines():
            if 'SYNC_SAMPLE ' in line:
                samples.append(json.loads(line.split('SYNC_SAMPLE ', 1)[1]))
            if 'SYNC_RESULT ' in line:
                identities.append(json.loads(line.split('SYNC_RESULT ', 1)[1]))
        assert len(samples) == 21 and len(identities) == 1, completed.stdout
        per_op = sorted(s['elapsed_ns'] / s['iterations'] for s in samples)
        result = dict(mode=mode, arm=arm, run=run, cpu=cpu, samples=samples,
            result=identities[0], median_ns=statistics.median(per_op),
            p95_ns=per_op[math.ceil(len(per_op)*.95)-1],
            p99_ns=per_op[math.ceil(len(per_op)*.99)-1], max_ns=max(per_op),
            binary_sha256=hashlib.sha256(exe.read_bytes()).hexdigest())
        results.append(result)
        print('PAIR_RUN', json.dumps({k:v for k,v in result.items() if k!='samples'}), flush=True)
summary = {}
for mode in ('gate', 'tick'):
    group = [r for r in results if r['mode']==mode]
    assert len({r['result']['result_hash'] for r in group})==1, 'control/candidate observable mismatch'
    arms = {}
    for arm in ('control', 'candidate'):
        values = [r['median_ns'] for r in group if r['arm']==arm]
        mid = statistics.median(values)
        arms[arm] = dict(run_medians_ns=values, median_ns=mid,
            stable_within_5_percent=all(abs(v-mid) <= .05*mid for v in values))
    summary[mode] = dict(arms=arms, ratio_control_over_candidate=arms['control']['median_ns']/arms['candidate']['median_ns'])
output = dict(scope='synthetic 262144-header branch-gate and saturated BlockSync tick; NOT end-to-end IBD',
    cpu=cpu, raw_runs=results, summary=summary, full_e2e_gate='UNMEASURED')
(root/'paired-results.json').write_text(json.dumps(output, indent=2)+'\n')
print('PAIRED_SUMMARY', json.dumps(summary), flush=True)
