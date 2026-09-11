#!/usr/bin/env python3
"""Validate one isolated source tree; publish only a passing atomic commit.

No force pushes, default-branch writes, merges, or pull-request automation.
Artifacts contain source changes and validation logs, never credentials.
"""
from pathlib import Path
import argparse
import json
import os
import subprocess
import sys
import traceback

BASE='a1178cc884e42b953a041d0c139bc47814b7ccae'
HELPERS=Path(__file__).resolve().parent
MESSAGES={
 'apply':'refactor(node)!: split chainstate operations and remove duplicate pool authority',
 'sync':'refactor(node): split sync responsibilities and remove redundant test aliases',
 'mining':'refactor(node)!: separate candidate, generation and validation ownership',
}


def run(command,log=None):
    print('+ '+' '.join(command),flush=True)
    if log is None:
        return subprocess.check_output(command,text=True).strip()
    with log.open('w') as output:
        result=subprocess.run(command,stdout=output,stderr=subprocess.STDOUT,text=True)
    data=log.read_text(errors='replace')
    if '--message-format=json' in command:
        counts={}
        for line in data.splitlines():
            try: obj=json.loads(line)
            except ValueError: continue
            if obj.get('reason')!='compiler-message': continue
            m=obj['message']; counts[m['level']]=counts.get(m['level'],0)+1
            if m['level']=='error': print(m.get('rendered',m['message']),flush=True)
        print('Compiler diagnostics: '+json.dumps(counts),flush=True)
    else:
        lines=data.splitlines()
        if result.returncode: print('\n'.join(lines[-240:]),flush=True)
        else: print('\n'.join(line for line in lines if line.startswith(('test result:','Pruned ','Removed ','Finished','PUBLISHED'))) or '\n'.join(lines[-5:]),flush=True)
    if result.returncode: raise subprocess.CalledProcessError(result.returncode,command)
    return data


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('group',choices=MESSAGES); args=ap.parse_args(); group=args.group
    if os.environ.get('GITHUB_REPOSITORY')!='gosuda/bitcoin-rs' or os.environ.get('GITHUB_REF')!='refs/heads/automation/node-splits-finish-20260911': raise RuntimeError('Unexpected publishing context')
    out=Path(os.environ['RUNNER_TEMP'])/('node-splits-'+group); out.mkdir(exist_ok=False)
    work=Path(os.environ['RUNNER_TEMP'])/('node-product-'+group)
    result={'group':group,'base':BASE,'state':'blocked','checks':[]}
    try:
        run(['git','worktree','add','--detach',str(work),BASE])
        os.chdir(work)
        report=out/'report.json'
        run([sys.executable,str(HELPERS/'extract.py'),group,'--report',str(report)],out/'extraction.log')
        transformed=json.loads(report.read_text())
        allowed=set(transformed['paths'])
        allowed={p for p in allowed if Path(p).exists()}
        run(['cargo','fmt','--all'],out/'format.log')
        unexpected=set(run(['git','diff','--name-only']).splitlines())-allowed
        if unexpected: raise RuntimeError(f'Formatting touched unrelated paths: {sorted(unexpected)}')
        native=['--locked','-p','bitcoin-rs-node','--no-default-features','--features','fjall,zmq']
        run(['cargo','check',*native,'--lib','--message-format=json'],out/'production.jsonl')
        run(['cargo','test',*native,'--lib','--no-run','--message-format=json'],out/'test-build.jsonl')
        result['checks']+=['production compilation','unit-test compilation']
        run([sys.executable,str(HELPERS/'extract.py'),group,'--report',str(report),'--prune',str(out/'production.jsonl'),str(out/'test-build.jsonl')],out/'imports.log')
        run(['cargo','fmt','--all'],out/'format-final.log')
        run(['cargo','fmt','--all','--','--check'],out/'format-check.log')
        run(['git','diff','--check'],out/'whitespace.log')
        run(['cargo','clippy','--locked','-p','bitcoin-rs-node','-p','bitcoin-rs','--no-default-features','--features','fjall,zmq','--all-targets','--','-D','warnings'],out/'clippy.log')
        result['checks']+=['rustfmt','diff whitespace','node and binary all-target strict Clippy']
        run(['cargo','test',*native,'--tests','--','--test-threads=4'],out/'node-tests.log')
        run(['cargo','test','--locked','-p','bitcoin-rs','--no-default-features','--features','fjall','--test','overhaul_ownership','--test','overhaul_evidence'],out/'architecture-gates.log')
        if group=='apply':
            run(['cargo','test','--locked','-p','bitcoin-rs-rpc','--no-default-features','--test','policy_contract'],out/'rpc-policy.log')
            result['checks'].append('RPC policy contracts')
            env=dict(os.environ); env['RUSTDOCFLAGS']='-D warnings'
            command=['cargo','doc',*native,'--no-deps']
            with (out/'rustdoc.log').open('w') as log:
                done=subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT,text=True)
            if done.returncode:
                print((out/'rustdoc.log').read_text(),flush=True)
                raise subprocess.CalledProcessError(done.returncode,command)
            result['checks'].append('warning-free Rust documentation')
        result['checks']+=['full native node tests','ownership and evidence gates']
        unexpected=set(run(['git','diff','--name-only']).splitlines())-allowed
        if unexpected: raise RuntimeError(f'Unaccounted changed paths: {sorted(unexpected)}')
        untracked=set(run(['git','ls-files','--others','--exclude-standard']).splitlines())
        if untracked-allowed: raise RuntimeError(f'Unaccounted new paths: {sorted(untracked-allowed)}')
        if any(p.startswith('.github/') for p in allowed): raise RuntimeError('Publishing helpers must not enter product commits')
        run(['git','add','--',*sorted(allowed)])
        staged=set(run(['git','diff','--cached','--name-only']).splitlines())
        if not staged or staged-allowed: raise RuntimeError('Unexpected staged source set')
        result['paths']=sorted(staged)
        result['sizes']={p:len(Path(p).read_bytes().splitlines()) for p in sorted(staged) if p.endswith('.rs')}
        result['tree']=run(['git','write-tree'])
        run(['git','config','user.name','github-actions[bot]'])
        run(['git','config','user.email','41898282+github-actions[bot]@users.noreply.github.com'])
        run(['git','commit','-m',MESSAGES[group],'-m','Related to #742. Source ownership changes; consensus and durable commit order are retained. Native compilation, tests, Clippy and applicable architecture gates passed before publication.'],out/'commit.log')
        if run(['git','rev-parse','HEAD^{tree}'])!=result['tree']: raise RuntimeError('Tested tree changed during commit')
        result['commit']=run(['git','rev-parse','HEAD'])
        result['branch']='refactor/node-split-'+group+'-20260911'
        run(['git','format-patch','--stdout','-1'],out/'source.patch')
        run(['git','diff','--stat',BASE,'HEAD'],out/'diffstat.txt')
        remote=run(['git','ls-remote','--heads','origin','refs/heads/'+result['branch']])
        if remote:
            sha=remote.split()[0]
            run(['git','fetch','origin',sha])
            if run(['git','rev-parse',sha+'^{tree}'])!=result['tree']: raise RuntimeError('Refusing to overwrite an existing different branch')
            result['commit']=sha
        else:
            run(['git','push','origin','HEAD:refs/heads/'+result['branch']],out/'publish.log')
        result['state']='published'
        print('PUBLISHED '+json.dumps(result),flush=True)
        return 0
    except Exception as error:
        result['error']=str(error)
        traceback.print_exc()
        # Export partial source for inspection, never a product branch.
        if work.is_dir():
            os.chdir(work)
            (out/'partial-diff.patch').write_text(run(['git','diff']))
        return 1
    finally:
        (out/'result.json').write_text(json.dumps(result,indent=2))
        with open(os.environ['GITHUB_STEP_SUMMARY'],'a') as summary:
            summary.write('## '+group+'\n\n```json\n'+json.dumps(result,indent=2)+'\n```\n')


if __name__=='__main__': sys.exit(main())
