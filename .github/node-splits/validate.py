"""Run isolated transformations and native checks; publish no unvalidated branch."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from split_core import items, parse, write
from refactor import BASE

HERE = Path(__file__).resolve().parent


def run(argv, cwd=None, capture=False, check=True):
    print('+', ' '.join(map(str,argv)), flush=True)
    return subprocess.run(argv,cwd=cwd,text=True,check=check,
                          stdout=subprocess.PIPE if capture else None)


def prune_unused(messages, allowed):
    locations = {}
    for entry in messages:
        message = entry.get('message',{})
        code = (message.get('code') or {}).get('code')
        if code != 'unused_imports':
            continue
        for span in message.get('spans',[]):
            if span.get('is_primary') and span['file_name'] in allowed:
                locations.setdefault(span['file_name'],set()).add(span['byte_start'])
    count = 0
    for filename, positions in locations.items():
        path = Path(filename)
        data = path.read_bytes()
        _, declarations, _ = items(data)
        has_tests = any(i.kind=='mod_item' and 'test' in i.name for i in declarations)
        edits = []
        for item in declarations:
            if item.kind != 'use_declaration' or not any(item.node.start_byte <= p < item.node.end_byte for p in positions):
                continue
            if item.code.startswith(b'pub '):
                raise RuntimeError(f'Refusing to delete a public export: {filename}: {item.code!r}')
            if has_tests and b'test' not in item.cfg:
                # A library-only diagnostic must not remove a fixture import.
                # Recheck under cfg(test); a genuinely unused test import will
                # be removed on the next complete all-targets compile.
                edits.append((item.node.start_byte,item.node.start_byte,b'#[cfg(test)]\n'))
            else:
                start = item.node.start_byte-len(item.prefix)
                edits.append((start,item.node.end_byte,b'\n'))
        for a,b,replacement in sorted(edits,reverse=True):
            data = data[:a]+replacement+data[b:]
        if edits:
            write(path,data)
            count += len(edits)
    return count


def compiler_pass():
    argv = ['cargo','check','--locked','-p','bitcoin-rs-node','--no-default-features','--features','fjall','--all-targets','--message-format=json']
    result = run(argv,capture=True,check=False)
    Path('/tmp/compiler.jsonl').write_text(result.stdout)
    messages = []
    for line in result.stdout.splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if entry.get('reason') == 'compiler-message':
            messages.append(entry)
    return result.returncode,messages


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--group',required=True)
    parser.add_argument('--publish',action='store_true')
    args = parser.parse_args()
    if os.environ.get('GITHUB_REPOSITORY') != 'gosuda/bitcoin-rs':
        raise RuntimeError('Unexpected repository')
    if os.environ.get('GITHUB_REF') != 'refs/heads/automation/node-splits-20260911':
        raise RuntimeError('Unexpected automation ref')
    checkout = Path(os.environ['GITHUB_WORKSPACE'])
    work = Path(os.environ['RUNNER_TEMP'])/('node-splits-'+args.group)
    if work.exists():
        raise RuntimeError('Refusing occupied worktree')
    run(['git','worktree','add','--detach',str(work),BASE],cwd=checkout)
    os.chdir(work)
    run([sys.executable,str(HERE/'refactor.py'),'--group',args.group])
    report = json.loads(Path('/tmp/node-splits-report.json').read_text())
    allowed = set(report['changed_paths'])
    for iteration in range(6):
        rc,messages = compiler_pass()
        edits = prune_unused(messages,allowed)
        print(f'IMPORT_PASS {iteration}: returncode={rc}, removed_or_test_scoped={edits}',flush=True)
        errors = [m['message'] for m in messages if m['message'].get('level')=='error']
        if edits:
            continue
        for message in errors[:80]:
            print(message.get('rendered') or message['message'],flush=True)
        if rc:
            raise RuntimeError(f'Native compile refused candidate: {len(errors)} errors')
        break
    else:
        raise RuntimeError('Import cleanup did not converge')
    run(['cargo','fmt','--all'])
    changed = set(run(['git','diff','--name-only'],capture=True).stdout.splitlines())
    if changed-allowed:
        raise RuntimeError(f'Formatting touched unrelated files: {sorted(changed-allowed)}')
    run(['cargo','fmt','--all','--','--check'])
    run(['git','diff','--check'])
    run(['cargo','clippy','--locked','-p','bitcoin-rs-node','--no-default-features','--features','fjall','--all-targets','--','-D','warnings'])
    run(['cargo','check','--locked','-p','bitcoin-rs','--no-default-features','--features','fjall','--all-targets'])
    run(['cargo','test','--locked','-p','bitcoin-rs-node','--no-default-features','--features','fjall','--lib','--','--test-threads=1'])
    run(['cargo','test','--locked','-p','bitcoin-rs','--no-default-features','--features','fjall','--test','overhaul_ownership','--','--nocapture'])
    # Algorithm body conservation excludes comments and imports and normalizes
    # only the explicit owner-qualified API paths. It is not a substitute for
    # native tests but catches accidental drops, copies, and body edits.
    if report['function_bodies_before'] != report['function_bodies_after']:
        raise RuntimeError('Function body count changed')
    if report['body_multiset_removed'] or report['body_multiset_added']:
        raise RuntimeError('Function body token multiset changed; inspect before publication')
    run(['git','add','--',*sorted(allowed)])
    staged = set(run(['git','diff','--cached','--name-only'],capture=True).stdout.splitlines())
    if staged != allowed:
        raise RuntimeError(f'Staged set differs: {staged ^ allowed}')
    run(['git','diff','--cached','--check'])
    report['diffstat'] = run(['git','diff','--cached','--stat'],capture=True).stdout
    report['validated'] = True
    if args.publish:
        branch = 'refactor/node-'+args.group+'-splits-20260911'
        existing = run(['git','ls-remote','--heads','origin','refs/heads/'+branch],capture=True).stdout.strip()
        if existing:
            raise RuntimeError(f'Refusing to replace existing branch {branch}')
        run(['git','config','user.name','github-actions[bot]'])
        run(['git','config','user.email','41898282+github-actions[bot]@users.noreply.github.com'])
        title = 'refactor(node)!: split '+args.group+' responsibilities and remove old owner paths'
        run(['git','commit','-m',title,'-m','Related to #742. Existing algorithm bodies and regression scenarios retained; native compile, Clippy, library tests and ownership gate run before publication.'])
        run(['git','push','origin','HEAD:refs/heads/'+branch])
        report['branch'] = branch
        report['sha'] = run(['git','rev-parse','HEAD'],capture=True).stdout.strip()
    Path('/tmp/node-splits-report.json').write_text(json.dumps(report,indent=2))
    print('NODE_SPLITS_RESULT '+json.dumps(report),flush=True)
    with open(os.environ['GITHUB_STEP_SUMMARY'],'a') as out:
        out.write('```json\n'+json.dumps(report,indent=2)+'\n```\n')


if __name__ == '__main__':
    main()
