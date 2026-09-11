"""Scratch-only syntax-aware extraction. Product commits exclude this helper."""
from collections import Counter, defaultdict
from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
import tree_sitter
import tree_sitter_rust

PARSER = tree_sitter.Parser(tree_sitter.Language(tree_sitter_rust.language()))
MOVES = {}


def parse(data):
    tree = PARSER.parse(data)
    if tree.root_node.has_error:
        errors = []
        def visit(n):
            if n.type == 'ERROR' or n.is_missing:
                errors.append((n.type, list(n.start_point), n.text[:100].decode(errors='replace')))
            for c in n.children:
                visit(c)
        visit(tree.root_node)
        raise ValueError(f'Rust syntax: {errors[:8]}')
    return tree


@dataclass
class Item:
    node: object
    prefix: bytes
    code: bytes
    @property
    def kind(self):
        return self.node.type
    @property
    def name(self):
        n = self.node.child_by_field_name('name')
        return n.text.decode() if n else ''
    @property
    def text(self):
        return self.prefix + self.code
    @property
    def cfg(self):
        return b''.join(re.findall(rb'#\[(?:cfg|cfg_attr)\([\s\S]*?\)\]\s*', self.prefix))


def items(data, parent=None):
    parent = parent or parse(data).root_node
    pos = 0 if parent.type == 'source_file' else parent.start_byte + 1
    header = b''
    result = []
    for n in parent.named_children:
        if n.type in ('line_comment', 'block_comment', 'attribute_item', 'inner_attribute_item'):
            if not result and (n.type == 'inner_attribute_item' or n.text.startswith((b'//!', b'/*!'))):
                header += data[pos:n.end_byte]
                pos = n.end_byte
            continue
        result.append(Item(n, data[pos:n.start_byte], data[n.start_byte:n.end_byte]))
        pos = n.end_byte
    end = len(data) if parent.type == 'source_file' else parent.end_byte - 1
    return header, result, data[pos:end]


def type_name(item):
    if item.kind != 'impl_item':
        return item.name
    n = item.node.child_by_field_name('type')
    return re.match(r'(?:[A-Za-z_]\w*::)*([A-Za-z_]\w*)', n.text.decode()).group(1)


def accessible(code, kind):
    if kind in ('function_item', 'struct_item', 'enum_item', 'type_item', 'const_item', 'static_item', 'trait_item'):
        if not re.match(rb'pub\b', code):
            code = b'pub(super) ' + code
        if kind == 'struct_item':
            n = next(n for n in parse(code).root_node.named_children if n.type == 'struct_item')
            body = n.child_by_field_name('body')
            if body and body.type == 'field_declaration_list':
                edits = [f.start_byte for f in body.named_children if f.type == 'field_declaration' and not any(c.type == 'visibility_modifier' for c in f.named_children)]
                for p in sorted(edits, reverse=True):
                    code = code[:p] + b'pub(super) ' + code[p:]
    elif kind == 'impl_item':
        n = next(n for n in parse(code).root_node.named_children if n.type == 'impl_item')
        if n.child_by_field_name('trait') is None:
            edits = [m.start_byte for m in n.child_by_field_name('body').named_children if m.type in ('function_item', 'const_item') and not any(c.type == 'visibility_modifier' for c in m.named_children)]
            for p in sorted(edits, reverse=True):
                code = code[:p] + b'pub(super) ' + code[p:]
    return code


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data.rstrip() + b'\n')


def copied_imports(original, modules):
    result = b''
    for i in original:
        if i.kind != 'use_declaration':
            continue
        code = re.sub(rb'^pub(?:\([^)]*\))?\s+', b'', i.code)
        code = re.sub(rb'\buse\s+super::', b'use super::super::', code)
        code = re.sub(rb'\buse\s+self::', b'use super::', code)
        for mod in modules:
            code = re.sub(rb'\buse\s+' + re.escape(mod.encode()) + rb'::', b'use super::' + mod.encode() + b'::', code)
        result += i.cfg + code + b'\n'
    return result


def split(path, groups, method_groups=None, docs=None, public_modules=()):
    data = path.read_bytes()
    header, original, tail = items(data)
    methods = method_groups or {}
    owners = {}
    for module, names in groups.items():
        for name in names.split():
            if name in owners:
                raise ValueError(f'Duplicate owner {name}')
            owners[name] = module
    root = []
    extracted = defaultdict(list)
    seen = set()
    for item in original:
        name = type_name(item)
        mod = owners.get(name) if item.kind not in ('use_declaration', 'mod_item') else None
        if mod:
            seen.add(name)
            extracted[mod].append(Item(item.node, item.prefix, accessible(item.code, item.kind)))
        elif item.kind == 'impl_item' and name in methods and item.node.child_by_field_name('trait') is None:
            body = item.node.child_by_field_name('body')
            _, children, ending = items(data, body)
            keep = []
            separated = defaultdict(list)
            for child in children:
                owner = next((m for m, names in methods[name].items() if child.name in names.split()), None)
                (separated[owner] if owner else keep).append(child)
            opening = data[item.node.start_byte:body.start_byte + 1]
            for owner, content in separated.items():
                code = opening + b''.join(c.prefix + accessible(c.code, c.kind) for c in content) + b'\n}\n'
                extracted[owner].append(Item(item.node, b'\n', code))
            if keep:
                root.append(Item(item.node, item.prefix, opening + b''.join(c.text for c in keep) + ending + b'}'))
        else:
            root.append(item)
    if set(owners) - seen:
        raise ValueError(f'{path}: missing definitions {set(owners) - seen}')
    for method_plan in methods.values():
        for mod, names in method_plan.items():
            text = b''.join(i.text for i in extracted[mod])
            for name in names.split():
                if not re.search(rb'\bfn\s+' + name.encode() + rb'\b', text):
                    raise ValueError(f'{path}: missing method {name}')
    definitions = {i.name: i for i in original if i.name and i.kind not in ('use_declaration', 'mod_item')}
    imports = copied_imports(original, [i.name for i in original if i.kind == 'mod_item'])
    declarations = b'\n'
    root_links = b''
    for mod, content in extracted.items():
        desc = (docs or {}).get(mod, mod.replace('_', ' ').capitalize() + '.')
        vis = 'pub mod ' if mod in public_modules else 'pub(crate) mod '
        declarations += ('/// ' + desc + '\n' + vis + mod + ';\n').encode()
        raw = b''.join(i.text for i in content)
        used = set(re.findall(rb'\b[A-Za-z_]\w*\b', raw))
        owned = {type_name(i) for i in content if i.kind != 'impl_item'}
        links = b''
        for name, definition in definitions.items():
            if name.encode() not in used or name in owned or owners.get(name) == mod:
                continue
            target = 'super::' + (owners[name] + '::' if name in owners else '') + name
            links += definition.cfg + ('use ' + target + ';\n').encode()
        write(path.with_suffix('') / (mod + '.rs'), ('//! ' + desc + '\n\n').encode() + imports + links + b'\n' + raw)
        for name, owner in owners.items():
            if owner != mod or name not in definitions:
                continue
            definition = definitions[name]
            root_links += definition.cfg + f'use {mod}::{name};\n'.encode()
            if re.match(rb'pub\b', definition.code):
                MOVES[(str(path), name)] = mod
    write(path, header + declarations + root_links + b''.join(i.text for i in root) + tail)
    return {str(path), *(str(path.with_suffix('') / (m + '.rs')) for m in extracted)}


def topic(name):
    for t, keys in [
        ('sequence_locks', ('bip68',)), ('difficulty', ('daa', 'difficulty', 'nbits', 'testnet4', 'pow_limit', 'proof_of_work')),
        ('bip30', ('bip30',)), ('scripts', ('verify_block_transactions', 'bip16', 'verify_flags')),
        ('utxo', ('block_local_utxo', 'utxo_changes', 'coinbase_maturity', 'apply_scratch')),
        ('windows', ('window', 'apply_cache', 'batch_drain', 'restore_split', 'settle_window', 'buffered')),
        ('notifications', ('publish', 'zmq', 'sequence_event', 'mining_generation', 'follower_dispatch', 'fee_estimator')),
        ('reorg', ('reorg', 'branch', 'invalidate', 'disconnect_body', 'checkpoint_fallback')),
        ('disconnect', ('disconnect', 'rewind', 'undo_record', 'marker')),
        ('peers', ('peer', 'fanout', 'getheaders', 'getdata', 'headers', 'prefix_probe', 'staller')),
        ('staging', ('stag', 'received', 'pending', 'inbound_blocks', 'cold_start', 'wedg')),
        ('admission', ('admission', 'concurrent', 'generation', 'precommit', 'failed_undo')),
    ]:
        if any(k in name for k in keys):
            return t
    return 'validation'


def shard_tests(path, limit=850):
    data = path.read_bytes()
    header, original, tail = items(data)
    groups = defaultdict(list)
    fixtures = []
    for item in original:
        if item.kind == 'function_item' and re.search(rb'#\[(?:test|[\w:]+::test)\]', item.prefix):
            groups[topic(item.name)].append(item)
        else:
            fixtures.append(item.text)
    created = set()
    declarations = b'\n'
    exports = b''
    for name, tests in groups.items():
        parts = [[]]
        count = 0
        for item in tests:
            lines = item.text.count(b'\n')
            if parts[-1] and count + lines > limit:
                parts.append([])
                count = 0
            parts[-1].append(item)
            count += lines
        for index, part in enumerate(parts):
            module = name + (f'_{index+1}' if index else '')
            target = path.with_suffix('') / (module + '.rs')
            text = b'use super::*;\n'
            for item in part:
                others = data[:item.node.start_byte] + data[item.node.end_byte:]
                called = re.search(rb'\b' + re.escape(item.name.encode()) + rb'\s*\(', others)
                code = accessible(item.code, item.kind) if called else item.code
                if called:
                    exports += item.cfg + f'use {module}::{item.name};\n'.encode()
                text += item.prefix + code
            write(target, text)
            declarations += f'mod {module};\n'.encode()
            created.add(str(target))
    write(path, header + b''.join(fixtures) + declarations + exports + tail)
    return created


def extract_tests(path, limit=850):
    data = path.read_bytes()
    header, original, tail = items(data)
    out = []
    created = set()
    for item in original:
        body = item.node.child_by_field_name('body')
        if item.kind != 'mod_item' or body is None or 'test' not in item.name:
            out.append(item.text)
            continue
        target = path.with_suffix('') / (item.name + '.rs')
        if target.exists():
            raise ValueError(f'Test collision {target}')
        write(target, data[body.start_byte+1:body.end_byte-1])
        out.append(item.prefix + f'mod {item.name};'.encode())
        created.add(str(target))
        if target.read_bytes().count(b'\n') > limit:
            created |= shard_tests(target, limit)
    if created:
        write(path, header + b''.join(out) + tail)
        created.add(str(path))
    return created


def parse_uses(text):
    text = re.sub(r'//[^\n]*|/\*.*?\*/', '', text, flags=re.S)
    def commas(s):
        depth = 0
        last = 0
        result = []
        for i, c in enumerate(s):
            depth += c == '{'
            depth -= c == '}'
            if c == ',' and depth == 0:
                result.append(s[last:i])
                last = i + 1
        return result + [s[last:]]
    def expand(s, prefix=''):
        s = s.strip()
        if not s:
            return []
        if '{' in s:
            p, rest = s.split('{', 1)
            return sum((expand(x, prefix+p) for x in commas(rest.rsplit('}', 1)[0])), [])
        base, *alias = re.split(r'\s+as\s+', s)
        base = prefix.rstrip(':') if base == 'self' else prefix + base
        return [(base, alias[0] if alias else None)]
    return expand(text)


def source_paths(root):
    return [p for base in ('crates', 'bin', 'tools') for p in (root/base).rglob('*.rs') if '/target/' not in str(p)]


def update_consumers(root):
    changed = set()
    mapping = {}
    for (path, name), mod in MOVES.items():
        local = path.removeprefix('crates/node/src/').removesuffix('.rs').replace('/', '::')
        mapping[local+'::'+name] = local+'::'+mod+'::'+name
    for path in source_paths(root):
        innode = str(path).startswith('crates/node/')
        lib = str(path) == 'crates/node/src/lib.rs'
        maps = {'bitcoin_rs_node::'+a: 'bitcoin_rs_node::'+b for a,b in mapping.items()}
        if innode:
            maps.update({'crate::'+a: 'crate::'+b for a,b in mapping.items()})
        key = mapping.get('mining::GenerationKey')
        if key:
            maps['bitcoin_rs_node::GenerationKey'] = 'bitcoin_rs_node::'+key
            if innode:
                maps['crate::GenerationKey'] = 'crate::'+key
        data = path.read_bytes()
        if not any(old.encode() in data for old in maps) and not lib:
            # Grouped imports can name the source module without its symbol.
            if not any((prefix+m.split('::')[0]+'::').encode() in data for m in mapping for prefix in ('crate::','bitcoin_rs_node::')):
                continue
        tree = parse(data)
        edits = []
        ignored = []
        def walk(n):
            if n.type in ('string_literal','raw_string_literal','char_literal','line_comment','block_comment'):
                ignored.append((n.start_byte,n.end_byte))
                return
            if n.type == 'use_declaration':
                match = re.match(r'((?:pub(?:\([^)]*\))?\s+)?use\s+)(.*);$', n.text.decode(), re.S)
                if not match:
                    return
                old = parse_uses(match.group(3))
                new = []
                for p, alias in old:
                    if lib and p == 'mining::GenerationKey' and key and match.group(1).startswith('pub '):
                        continue
                    new.append((mapping.get(p,p) if lib else maps.get(p,p), alias))
                if new != old:
                    text = match.group(1)+'{'+', '.join(p+(' as '+a if a else '') for p,a in new)+'};'
                    edits.append((n.start_byte,n.end_byte,text.encode()))
                return
            for c in n.named_children:
                walk(c)
        walk(tree.root_node)
        for old, new in maps.items():
            for match in re.finditer(rb'(?<![A-Za-z_0-9])'+re.escape(old.encode())+rb'(?![A-Za-z_0-9])',data):
                a,b = match.span()
                if any(a<y and b>x for x,y in ignored) or any(a<y and b>x for x,y,_ in edits):
                    continue
                edits.append((a,b,new.encode()))
        for a,b,replacement in sorted(edits,reverse=True):
            data = data[:a]+replacement+data[b:]
        if data != path.read_bytes():
            write(path,data)
            changed.add(str(path))
    return changed


def standalone_imports(path):
    data = path.read_bytes()
    _, declarations, _ = items(data)
    edits = []
    for item in declarations:
        if item.kind != 'use_declaration':
            continue
        match = re.match(r'((?:pub(?:\([^)]*\))?\s+)?use\s+)(.*);$', item.code.decode(), re.S)
        if not match:
            continue
        leaves = parse_uses(match.group(3))
        if len(leaves) < 2:
            continue
        lines = []
        for i,(p,a) in enumerate(leaves):
            lines.append((item.cfg if i else b'')+(match.group(1)+p+(' as '+a if a else '')+';\n').encode())
        edits.append((item.node.start_byte,item.node.end_byte,b''.join(lines)))
    for a,b,replacement in sorted(edits,reverse=True):
        data = data[:a]+replacement+data[b:]
    write(path,data)


def function_bodies(paths, reverse=None):
    result = Counter()
    def tokens(n):
        if n.type in ('line_comment','block_comment','use_declaration'):
            return b''
        if not n.children or n.type in ('string_literal','raw_string_literal','char_literal'):
            return n.text
        return b''.join(tokens(c) for c in n.children)
    for path in paths:
        tree = parse(path.read_bytes())
        def walk(n):
            if n.type == 'function_item':
                body = n.child_by_field_name('body')
                if body:
                    text = tokens(body)
                    for new,old in (reverse or {}).items():
                        text = text.replace(new.encode(),old.encode())
                    result[hashlib.sha256(text).hexdigest()] += 1
            for c in n.named_children:
                walk(c)
        walk(tree.root_node)
    return result
