"""Compiler-diagnostic driven import cleanup; no lint suppression is added."""
import collections
import json
import re
import subprocess
from pathlib import Path
import refactor_patched as r
from import_helpers import dedup_imports, relative_paths


def cleanup_imports(log):
    unused = collections.defaultdict(set)
    for line in Path(log).read_text().splitlines():
        try:
            data = json.loads(line)
        except ValueError:
            continue
        message = data.get('message', {})
        if (message.get('code') or {}).get('code') != 'unused_imports':
            continue
        for span in message.get('spans', []):
            if span.get('is_primary'):
                unused[span['file_name']].add((span['byte_start'], span['byte_end']))
    for file, spans in unused.items():
        path = Path(file)
        source = path.read_text()
        edits = []

        def visit(node):
            if node.type == 'use_declaration':
                if any(node.start_byte <= a and b <= node.end_byte for a, b in spans):
                    if len(r.use_leaves(source, node)) > 1:
                        return
                    start = node.start_byte
                    previous = node.prev_named_sibling
                    while previous and previous.type == 'attribute_item':
                        start = previous.start_byte
                        previous = previous.prev_named_sibling
                    edits.append((start, node.end_byte))
                return
            for child in node.named_children:
                visit(child)

        visit(r.parse(source))
        data = source.encode()
        for start, end in sorted(set(edits), reverse=True):
            data = data[:start] + data[end:]
        path.write_text(re.sub(r'\n{3,}', '\n\n', data.decode()))


def normalize():
    paths = subprocess.check_output(['git', 'diff', '--name-only', '--diff-filter=ACMR'], text=True).splitlines()
    paths += subprocess.check_output(['git', 'ls-files', '--others', '--exclude-standard'], text=True).splitlines()
    rust = []
    for name in sorted(set(paths)):
        if not name.endswith('.rs'):
            continue
        path = Path(name)
        text = path.read_text()
        text = re.sub(r';\n(?:[ \t]*\n)+(?=([ \t]*)(?:#\[(?:cfg|allow)[^\n]*\]\n[ \t]*)*use\s)', ';\n', text)
        path.write_text(re.sub(r'\n{3,}', '\n\n', text))
        rust.append(name)
    if rust:
        subprocess.run(['rustfmt', '--edition', '2024', *rust], check=True)


def print_errors(log):
    for line in Path(log).read_text().splitlines():
        try:
            data = json.loads(line)
        except ValueError:
            continue
        message = data.get('message', {})
        if message.get('level') == 'error':
            print(message.get('rendered', message.get('message')), flush=True)
