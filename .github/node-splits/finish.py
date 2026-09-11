"""Resume the native-gated node refactor. This file is workbench-only."""
from collections import Counter, defaultdict
from pathlib import Path
import importlib
import inspect
import json
import os
import re
import subprocess
import sys
import textwrap
import traceback

import remaining as m
r = m.r
# Existing native compilation accepts a variable named `raw`. This pinned
# tree-sitter grammar mistakes exactly `&raw` for a raw-reference operator.
# Accept no other recovery node; rustc still checks every generated module.
def parse(src):
    tree = r.PARSER.parse(src)
    stack, errors = [tree.root_node], []
    while stack:
        node = stack.pop()
        if node.is_missing or (node.type == 'ERROR' and node.text != b'&raw'):
            errors.append((node.type, node.start_point, node.text[:100]))
        stack.extend(node.children)
    if errors:
        raise RuntimeError(f'Rust syntax rejected: {errors[:8]}')
    return list(r.items(src, tree.root_node))

r.parse = parse

def test_only(item):
    return bool(re.search(r'#\[cfg\([^\]]*\btest\b', item.prefix))


def external_test_text(path, entries):
    texts = []
    def walk(p, current, inherited=False):
        for item in current:
            if test_only(item) and item.node.type != 'mod_item':
                texts.append(item.text)
            if item.node.type != 'mod_item' or not (inherited or test_only(item)):
                continue
            body = item.node.child_by_field_name('body')
            if body is not None:
                texts.append(body.text.decode())
                continue
            explicit = re.search(r'path\s*=\s*"([^"]+)"', item.prefix)
            other = p.parent / explicit[1] if explicit else p.with_suffix('') / (item.name + '.rs')
            if other.exists():
                data = other.read_bytes()
                texts.append(data.decode())
                walk(other, parse(data), True)
    walk(path, entries)
    return '\n'.join(texts)

r.external_test_text = external_test_text
r.test_only = test_only
source = inspect.getsource(r.split_implementation)
source = source.replace("if item.node.type == 'mod_item' and 'test' in item.prefix:", "if test_only(item):")
old = """                elif adjusted.startswith('self::'):
                    adjusted = 'super::' + adjusted[6:]
"""
new = old + """                elif adjusted.split('::', 1)[0] in declared and declared[adjusted.split('::', 1)[0]].node.type == 'mod_item':
                    adjusted = 'super::' + adjusted
"""
assert old in source
source = source.replace(old, new)
old_local = "            local_lines.append(f'use super::{owner}::{name};' if owner else f'use super::{name};')"
new_local = """            condition = '\\n'.join(re.findall(r'#\\[cfg\\([^\\]]*\\)\\]', declared[name].prefix))
            local_lines.append((condition + '\\n' if condition else '') + (f'use super::{owner}::{name};' if owner else f'use super::{name};'))"""
assert old_local in source
source = source.replace(old_local, new_local)
exec(compile(source, '<scope-aware-split>', 'exec'), r.__dict__)

# Added module nesting may require changing a test's explicit `super` path.
# Record the exact old/new token pair instead of discarding all path tokens.
MIGRATIONS = {}
def normalized_literal(value):
    # Rust escaped-newline indentation has no string value. Raw literals are
    # deliberately not normalized.
    return re.sub(r'(\\+)\r?\n[ \t]*', lambda match: match[1] + '\n' if len(match[1]) % 2 else match[0], value)

r.normalized_literal = normalized_literal
m.normalized_literal = normalized_literal
inventory_source = inspect.getsource(m.inventory)
inventory_source = inventory_source.replace("tokens.append((node.type, node.text.decode()))", "tokens.append((node.type, normalized_literal(node.text.decode()) if node.type == 'string_literal' else node.text.decode()))")
exec(compile(inventory_source, '<literal-value-inventory>', 'exec'), m.__dict__)
raw_inventory = m.inventory

def inventory(root):
    raw = raw_inventory(root)
    out = Counter()
    for key, count in raw.items():
        seen = set()
        while key in MIGRATIONS:
            if key in seen:
                raise RuntimeError('Cyclic token migration')
            seen.add(key)
            key = MIGRATIONS[key]
        out[key] += count
    return out

m.inventory = inventory

def test_key(item):
    name = item.name
    body = item.node.child_by_field_name('body').text.decode()
    for old, new in [('segment_name_pub', 'segment_name'), ('parse_segment_name_pub', 'parse_segment_name')]:
        body = re.sub(r'\b' + old + r'\b', new, body)
    tokens, queue = [], [r.PARSER.parse(body.encode()).root_node]
    while queue:
        node = queue.pop()
        if node.type in ('line_comment', 'block_comment'):
            continue
        if not node.children or node.type in ('string_literal', 'raw_string_literal', 'char_literal'):
            tokens.append((node.type, normalized_literal(node.text.decode()) if node.type == 'string_literal' else node.text.decode()))
        else:
            queue.extend(reversed(node.children))
    return name, tuple(tokens)


def shift_super(text):
    data = text.encode()
    tree = r.PARSER.parse(data)
    stack, edits = [tree.root_node], []
    while stack:
        node = stack.pop()
        if node.type == 'mod_item':
            # A nested module has a different lexical parent. None of its
            # internal relative paths change when its containing function moves.
            continue
        if node.type == 'super' and data[max(0,node.start_byte-2):node.start_byte] != b'::':
            edits.append((node.start_byte, node.start_byte, 'super::'))
        stack.extend(node.children)
    return r.rewrite(data, edits).decode()


def partition_tests(path):
    src = path.read_bytes()
    if len(src.splitlines()) <= 550:
        return []
    entries = parse(src)
    identifier_counts = Counter()
    stack = [r.PARSER.parse(src).root_node]
    while stack:
        node = stack.pop()
        if node.type in ('identifier', 'type_identifier'):
            identifier_counts[node.text.decode()] += 1
        if node.type not in ('line_comment', 'block_comment', 'string_literal', 'raw_string_literal'):
            stack.extend(node.children)
    groups = defaultdict(list)
    for item in entries:
        if item.node.type == 'function_item' and item.test and identifier_counts[item.name] == 1:
            groups[m.topic(item.name)].append(item)
    edits, made, declarations = [], [], []
    for category, tests in groups.items():
        chunks, chunk, size = [], [], 0
        for item in tests:
            length = len(item.text.splitlines())
            if chunk and size + length > 450:
                chunks.append(chunk)
                chunk, size = [], 0
            chunk.append(item)
            size += length
        if chunk:
            chunks.append(chunk)
        for number, selected in enumerate(chunks, 1):
            name = f'{category}_{number}'
            dest = path.with_suffix('') / (name + '.rs')
            if dest.exists():
                raise RuntimeError(f'Test destination exists: {dest}')
            dest.parent.mkdir(parents=True, exist_ok=True)
            texts = []
            for item in selected:
                moved = shift_super(item.text)
                moved_item = next(i for i in parse(moved.encode()) if i.node.type == 'function_item')
                before, after = test_key(item), test_key(moved_item)
                if before != after:
                    if after in MIGRATIONS and MIGRATIONS[after] != before:
                        raise RuntimeError('Ambiguous test scope migration')
                    MIGRATIONS[after] = before
                texts.append(moved)
            dest.write_text('use super::*;\n\n' + '\n'.join(texts))
            made.append(dest)
            declarations.append(f'#[cfg(test)]\nmod {name};\n')
            edits.extend((item.start, item.end, '') for item in selected)
    path.write_bytes(r.rewrite(src, edits) + ('\n' + '\n'.join(declarations)).encode())
    return made

m.partition_tests = partition_tests
base_transform = m.transform

def add_import(path, text):
    source = path.read_text()
    if text in source:
        return
    at = 0
    for line in source.splitlines(keepends=True):
        if not line.strip() or line.startswith('//!'):
            at += len(line)
        else:
            break
    path.write_text(source[:at] + text + '\n' + source[at:])


def transform(work, label, relative, stages):
    expected = base_transform(work, label, relative, stages)
    root = work / 'crates/node/src'
    if label == 'storage-footprint':
        path = root / 'storage_footprint.rs'
        path.write_text(path.read_text().replace('use sha2::Digest;\n', ''))
    if label == 'journal':
        for rel, names in {
            'chainstate_journal/writer.rs': ['Read', 'Write'],
            'chainstate_journal/writer/open.rs': ['Read', 'Write'],
            'chainstate_journal/writer/rewind.rs': ['Write'],
        }.items():
            path = root / rel
            text = path.read_text()
            for name in names:
                text = text.replace('use std::io::' + name + ';\n', '')
            path.write_text(text)
    if label == 'checkpoint':
        for rel in ['checkpoint.rs', 'checkpoint/format.rs', 'checkpoint/publish.rs']:
            path = root / rel
            path.write_text(path.read_text().replace('use std::io::Read;\n', ''))
        add_import(root / 'checkpoint.rs', '#[cfg(test)]\nuse std::path::Path;')
    if label == 'txindex':
        add_import(root / 'txindex_worker.rs', '#[cfg(test)]\nuse bitcoin_rs_rpc::context::ScriptIndexQuery;')
    return expected

m.transform = transform
# Fix the acceptance parser. "10 passed" must not be mistaken for "0 passed".
validate_source = inspect.getsource(m.validate)
assert "all('0 passed;' in line for line in summary)" in validate_source
validate_source = validate_source.replace("all('0 passed;' in line for line in summary)", "all(re.search(r'\\bok\\. 0 passed;', line) for line in summary)")
exec(compile(validate_source, '<exact-test-count>', 'exec'), m.__dict__)

# Already published groups stay untouched; their own PRs carry validation.
m.GROUPS = [g for g in m.GROUPS if g[0] not in ('mining','recovery-evidence','tx-ingress')]


def main():
    root = Path(os.environ['GITHUB_WORKSPACE'])
    temp = Path(os.environ['RUNNER_TEMP'])
    artifacts = temp / 'node-remaining-results'
    artifacts.mkdir(exist_ok=True)
    r.command('git','fetch','origin',m.BASE,cwd=root)
    r.command('git','config','user.name','github-actions[bot]',cwd=root)
    r.command('git','config','user.email','41898282+github-actions[bot]@users.noreply.github.com',cwd=root)
    work = temp / 'node-finish-candidate'
    r.command('git','worktree','add','--detach',str(work),m.BASE,cwd=root)
    before = inventory(work/'crates/node/src')
    m.checked(work,artifacts,'baseline','clippy',['cargo','+1.95.0','clippy','--locked','-p','bitcoin-rs-node','--all-targets','--no-default-features','--features','fjall,zmq','--','-D','warnings'])
    results, failures, by_name = [], [], {}
    try:
        for number,(label,relative,stages,filters,dep) in enumerate(m.GROUPS,1):
            if dep and dep not in by_name:
                failures.append({'group':label,'error':'unvalidated prerequisite '+dep})
                continue
            base = by_name[dep]['sha'] if dep else m.BASE
            # This is a new workbench-owned scratch worktree, never a user
            # checkout. Reusing its exact path lets Cargo reuse dependencies.
            r.command('git','reset','--hard',base,cwd=work)
            r.command('git','clean','-fd',cwd=work)
            try:
                original_lines=len((work/'crates/node/src'/relative).read_text().splitlines())
                expected=transform(work,label,relative,stages)
                paths,tests=m.validate(work,artifacts,label,expected,before,filters)
                os.environ['GIT_AUTHOR_DATE']=f'2026-09-11T11:30:{number:02d}Z'
                os.environ['GIT_COMMITTER_DATE']=os.environ['GIT_AUTHOR_DATE']
                tree=m.git(work,'write-tree')
                sha=m.git(work,'commit-tree',tree,'-p',base,'-m',f'refactor(node): separate {label} responsibilities and contract tests\n\nRelated to #742. Native formatting, strict Clippy and focused tests\npassed. Existing tests retain their body tokens except explicit module\npath rebasing and removal of journal forwarding aliases.')
                r.command('git','reset','--hard',sha,cwd=work)
                result=dict(group=label,sha=sha,base=base,branch=m.PREFIX+label,expected_old=None,dependency=dep,paths=paths,tests=tests,clippy='passed',format='passed',test_tokens='preserved except explicit scope migrations',root_lines_before=original_lines,root_lines_after=len((work/'crates/node/src'/relative).read_text().splitlines()))
                results.append(result);by_name[label]=result
                (artifacts/(label+'-tree.json')).write_text(json.dumps([dict(path=p,sha=m.git(work,'hash-object',p),lines=len((work/p).read_text().splitlines())) for p in paths],indent=2))
            except Exception as error:
                traceback.print_exc()
                failures.append(dict(group=label,error=str(error)))
                r.command('git','add','--','crates/node/src',cwd=work)
                (artifacts/(label+'-candidate.patch')).write_text(r.command('git','diff','--cached','--binary',cwd=work,capture=True))
            m.record(artifacts,results,failures)
    finally:
        m.record(artifacts,results,failures)
    return bool(failures)

if __name__=='__main__':
    if sys.argv[1:]==['publish']:
        m.publish()
    else:
        sys.exit(main())
