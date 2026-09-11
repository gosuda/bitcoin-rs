"""Source-preserving helpers for the isolated node refactoring workbench."""
from pathlib import Path
import re
import refactor_patched as r
from import_helpers import dedup_imports, relative_paths

BASE = '0e10cd7e1cfc3d37654c1d622be19cebc2dda196'


def assign(groups, mapping):
    for group, names in mapping.items():
        groups.update(dict.fromkeys(names.split(), group))
    return groups


def frontmatter(text):
    header, spans = [], []
    for node in r.parse(text).named_children:
        if node.type == 'inner_attribute_item' or (node.type == 'line_comment' and r.txt(text, node).startswith('//!')):
            header.append(r.txt(text, node))
            spans.append((node.start_byte, node.end_byte))
    data = text.encode()
    for start, end in sorted(spans, reverse=True):
        data = data[:start] + data[end:]
    return '\n'.join(header) + '\n' + data.decode()


def migration(text, first=False):
    path = r.ROOT.parent / 'MIGRATION.md'
    if first:
        path.write_text('# Node ownership API migration\n\nThese changes remove obsolete import paths. There are no deprecated aliases or\nforwarding modules; consumers must import from each implementation owner.\n\nConsensus validation, durability ordering, rollback and stored formats are not\nmigration targets. Tests move with their owners instead of being removed to\naccommodate an API change. There is still one authoritative state representation.\n')
    with path.open('a') as handle:
        handle.write('\n' + text.strip() + '\n')


def external_tests(owner, source, groups):
    local = {r.name_of(source, node) for node, raw in r.items(source) if node.type == 'mod_item'}
    for node, raw in r.items(source):
        if node.type != 'mod_item' or not r.is_test(raw) or node.child_by_field_name('body') is not None:
            continue
        name = r.name_of(source, node)
        attr = re.search(r'#\[path\s*=\s*"([^"]+)"\]', raw)
        path = (r.ROOT / attr.group(1)) if attr else r.ROOT / owner / (name + '.rs')
        if not path.exists():
            continue
        text = relative_paths(path.read_text(), owner.replace('/', '::') + '::' + name, True)
        imports = r.canonical_imports(source, owner.replace('/', '::'), local)
        links = '\n'.join('use crate::' + owner.replace('/', '::') + '::' + group + '::*;' for group in sorted(set(groups.values())) if group)
        r.write(path, frontmatter(dedup_imports(imports + '\n' + links + '\n' + text)))


def split(old, new, groups, methods=None):
    source = r.split_owner(old, new, groups, methods)
    external_tests(new, source, groups)
    return source


def remove_items(path, names):
    source = path.read_text()
    spans = []

    def visit(node):
        if node.type in ('function_item', 'function_signature_item', 'struct_item') and r.name_of(source, node) in names:
            start = node.start_byte
            previous = node.prev_named_sibling
            while previous and previous.type in ('attribute_item', 'line_comment', 'block_comment'):
                start = previous.start_byte
                previous = previous.prev_named_sibling
            spans.append((start, node.end_byte))
            return
        for child in node.named_children:
            visit(child)

    visit(r.parse(source))
    data = source.encode()
    for start, end in sorted(spans, reverse=True):
        data = data[:start] + data[end:]
    path.write_text(re.sub(r'impl JournalRecord\s*\{\s*\}', '', data.decode()))
