"""Run the gate; accept no new failure and record an independently checked baseline.

The gate is an unchanged filesystem/cargo-metadata audit, not a node-behavior
binary. Re-run that exact executable against a pristine checkout at the same
path, so its compile-time CARGO_MANIFEST_DIR points at baseline source.
"""
from pathlib import Path
import json,re,subprocess
root=Path.cwd()
evidence=Path('/tmp/txindex-evidence')
base='7f5a460de67965ff36955bab1434c75f080ad384'
assert subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()==base
changed=subprocess.check_output(['git','diff','--cached','--name-only'],text=True).splitlines()
assert not any(p.startswith('bin/bitcoin-rs/tests/') or p.endswith('Cargo.toml') or p=='Cargo.lock' for p in changed)
assert not subprocess.check_output(['git','diff','--name-only'],text=True).strip()
def run(command,name):
    result=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    (evidence/name).write_text(result.stdout)
    print(result.stdout,flush=True)
    return result
command=['cargo','test','--locked','-p','bitcoin-rs','--no-default-features','--features','fjall','--test','overhaul_ownership','--','--nocapture']
candidate=run(command,'ownership.log')
if candidate.returncode==0:
    (evidence/'ownership-status.json').write_text(json.dumps({'candidate':'passed','baseline':base},indent=2))
    raise SystemExit(0)
def failures(log): return set(re.findall(r'^test ([\w:]+) \.\.\. FAILED$',log,re.M))
expected={'mempool_writer_source_scan_passes'}
assert failures(candidate.stdout)==expected, 'Unexpected ownership gate failure'
assert '16 passed; 1 failed' in candidate.stdout
assert 'handles.mempool_gateway.remove_for_block(' in candidate.stdout
match=re.search(r'Running tests/overhaul_ownership\.rs \(([^)]+)\)',candidate.stdout)
assert match, 'Cannot identify the unchanged source-audit executable'
executable=(root/match[1]).resolve(); assert executable.is_file()
patch=evidence/'ownership-candidate.patch'
patch.write_bytes(subprocess.check_output(['git','diff','--cached','--binary']))
try:
    subprocess.run(['git','reset','--hard','HEAD'],check=True)
    assert not subprocess.check_output(['git','status','--porcelain'],text=True).strip()
    baseline=run([str(executable),'--nocapture'],'ownership-baseline.log')
finally:
    subprocess.run(['git','apply','--index','--binary',str(patch)],check=True)
assert baseline.returncode!=0 and failures(baseline.stdout)==expected
assert '16 passed; 1 failed' in baseline.stdout
def violation(log):
    return re.findall(r'^non-owner production code.*?: (\[.*\])$',log,re.M)
assert violation(candidate.stdout) and violation(candidate.stdout)==violation(baseline.stdout), 'Ownership diagnostics differ from baseline'
status={'candidate':'16 passed; 1 failed','baseline_result':'16 passed; 1 failed','baseline':base,'pre_existing_failure':'mempool_writer_source_scan_passes','diagnostic':violation(candidate.stdout),'new_failures':0,'baseline_method':'same unchanged source-audit executable against pristine source at the same path'}
(evidence/'ownership-status.json').write_text(json.dumps(status,indent=2)+'\n')
print('Ownership gate is NOT fully passing: the sole failure is identical on pristine baseline. No gate source or production mempool code was changed.',flush=True)
