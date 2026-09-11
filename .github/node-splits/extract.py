#!/usr/bin/env python3
"""Temporary source transformation; not included in product commits.

Only moves parsed Rust item bytes and explicitly rewrites source paths.
Compiler-driven import cleanup is restricted to unused-import diagnostics.
Every product tree must compile, pass strict Clippy, and pass native tests.
"""
from __future__ import annotations
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
import argparse
import json
import re
import subprocess
import tree_sitter
import tree_sitter_rust

PARSER = tree_sitter.Parser(tree_sitter.Language(tree_sitter_rust.language()))
BASE = 'a1178cc884e42b953a041d0c139bc47814b7ccae'
CHANGED = set()
MOVES = {}


def parse(data):
    # The grammar misreads a borrow of an identifier named raw as a raw-pointer
    # operator. Mask only that identifier; all emitted bytes use original data.
    syntax = re.sub(rb'&(\s*)raw\b(?!\s+(?:const|mut)\b)', lambda m: b'&'+m[1]+b'r_w', data)
    tree = PARSER.parse(syntax)
    if tree.root_node.has_error:
        errors = []
        def visit(node):
            if node.type == 'ERROR' or node.is_missing:
                errors.append((node.type, tuple(node.start_point), data[node.start_byte:node.end_byte][:100].decode(errors='replace')))
            for child in node.children:
                visit(child)
        visit(tree.root_node)
        raise ValueError(f'Rust syntax error: {errors[:8]}')
    return tree


@dataclass
class Item:
    node: object
    prefix: bytes
    code: bytes
    @property
    def kind(self): return self.node.type
    @property
    def name(self):
        n = self.node.child_by_field_name('name')
        return n.text.decode() if n else ''
    @property
    def text(self): return self.prefix+self.code
    @property
    def cfg(self):
        tree = PARSER.parse(self.prefix+b'fn __placeholder() {}')
        return b'\n'.join(n.text for n in tree.root_node.named_children if n.type == 'attribute_item' and n.text.startswith((b'#[cfg(', b'#[cfg_attr(')))+b'\n'


def items(data, parent=None):
    parent = parent or parse(data).root_node
    start = 0 if parent.type == 'source_file' else parent.start_byte+1
    header = b''
    result = []
    for node in parent.named_children:
        if node.type in ('line_comment', 'block_comment', 'attribute_item', 'inner_attribute_item'):
            if not result and (node.type == 'inner_attribute_item' or node.text.startswith((b'//!', b'/*!'))):
                header += data[start:node.end_byte]
                start = node.end_byte
            continue
        result.append(Item(node, data[start:node.start_byte], data[node.start_byte:node.end_byte]))
        start = node.end_byte
    end = len(data) if parent.type == 'source_file' else parent.end_byte-1
    return header, result, data[start:end]


def typename(item):
    if item.kind != 'impl_item': return item.name
    n = item.node.child_by_field_name('type')
    m = re.match(r'(?:[A-Za-z_]\w*::)*([A-Za-z_]\w*)', n.text.decode()) if n else None
    return m.group(1) if m else ''


def accessible(code, kind):
    if kind in ('function_item','struct_item','enum_item','union_item','type_item','const_item','static_item','trait_item'):
        if not re.match(rb'pub\b', code): code = b'pub(super) '+code
        if kind in ('struct_item','union_item'):
            n = next(n for n in parse(code).root_node.named_children if n.type == kind)
            body = n.child_by_field_name('body')
            edits = []
            if body and body.type == 'field_declaration_list':
                for f in body.named_children:
                    if f.type == 'field_declaration' and not any(c.type == 'visibility_modifier' for c in f.named_children): edits.append(f.start_byte)
            for pos in sorted(edits, reverse=True): code = code[:pos]+b'pub(super) '+code[pos:]
    elif kind == 'impl_item':
        n = next(n for n in parse(code).root_node.named_children if n.type == kind)
        if n.child_by_field_name('trait') is None:
            edits = [f.start_byte for f in n.child_by_field_name('body').named_children if f.type in ('function_item','const_item') and not any(c.type == 'visibility_modifier' for c in f.named_children)]
            for pos in sorted(edits, reverse=True): code = code[:pos]+b'pub(super) '+code[pos:]
    return code


def write(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str): data = data.encode()
    path.write_bytes(data.rstrip()+b'\n')
    CHANGED.add(str(path))


def rebase_includes(data):
    return re.sub(rb'(\binclude(?:_str|_bytes)?!\s*\(\s*")([^"/][^"]*)("\s*\))', lambda m: m[1]+b'../'+m[2]+m[3], data)


def split(path, groups, methods=None, public=(), docs=None):
    path = Path(path)
    source = path.read_bytes()
    header, original, tail = items(source)
    owners = {}
    for mod, names in groups.items():
        for name in names.split():
            if name in owners: raise ValueError(f'Duplicate owner {name}')
            owners[name] = mod
    methods = methods or {}
    extracted = defaultdict(list)
    root = []
    seen = set()
    locals_ = [i.name for i in original if i.kind == 'mod_item' and not re.search(rb'\btest\b', i.cfg)]
    imports = []
    for item in original:
        if item.kind != 'use_declaration': continue
        code = re.sub(rb'^pub(?:\([^)]*\))?\s+', b'', item.code)
        code = re.sub(rb'\buse\s+super::', b'use super::super::', code)
        code = re.sub(rb'\buse\s+self::', b'use super::', code)
        for mod in locals_:
            code = re.sub(rb'\buse\s+'+re.escape(mod.encode())+rb'::', b'use super::'+mod.encode()+b'::', code)
        imports.append(item.cfg+code+b'\n')
    for item in original:
        name = typename(item)
        owner = owners.get(name) if item.kind not in ('use_declaration','mod_item') else None
        if owner:
            seen.add(name)
            extracted[owner].append(Item(item.node, item.prefix, accessible(item.code, item.kind)))
        elif item.kind == 'impl_item' and name in methods and item.node.child_by_field_name('trait') is None:
            body = item.node.child_by_field_name('body')
            _, children, ending = items(source, body)
            kept = []
            buckets = defaultdict(list)
            for child in children:
                mod = next((m for m, names in methods[name].items() if child.name in names.split()), None)
                if mod: buckets[mod].append(child)
                else: kept.append(child)
            opening = source[item.node.start_byte:body.start_byte+1]
            for mod, children_ in buckets.items():
                text = opening+b''.join(c.prefix+accessible(c.code,c.kind) for c in children_)+b'\n}'
                extracted[mod].append(Item(item.node, item.cfg, text))
            if kept: root.append(Item(item.node,item.prefix,opening+b''.join(c.text for c in kept)+ending+b'}'))
        else: root.append(item)
    if set(owners)-seen: raise ValueError(f'{path}: missing definitions {sorted(set(owners)-seen)}')
    for method_map in methods.values():
        for mod, names in method_map.items():
            code = b''.join(i.text for i in extracted[mod])
            for name in names.split():
                if not re.search(rb'\bfn\s+'+name.encode()+rb'\b', code): raise ValueError(f'{path}: missing method {name}')
    bindings = defaultdict(list)
    for i in original:
        if i.name and i.kind not in ('use_declaration','mod_item','impl_item'): bindings[i.name].append(i)
        if i.kind == 'macro_invocation':
            for n in re.findall(rb'\bstatic\s+(\w+)\s*:', i.code): bindings[n.decode()].append(i)
    declarations = b'\n'
    for mod, content in extracted.items():
        target = path.with_suffix('')/(mod+'.rs')
        if target.exists(): raise ValueError(f'Destination collision {target}')
        visibility = 'pub' if mod in public else 'pub(crate)'
        desc = (docs or {}).get(mod, mod.replace('_',' ').capitalize()+'.')
        declarations += f'/// {desc}\n{visibility} mod {mod};\n'.encode()
        raw = b''.join(i.text for i in content)
        used = set(re.findall(rb'\b[A-Za-z_]\w*\b', raw))
        owned = {typename(i) for i in content if i.kind != 'impl_item'}
        links = []
        for name, defs in bindings.items():
            if name.encode() not in used or name in owned or owners.get(name) == mod: continue
            cfg = defs[0].cfg if len(defs) == 1 else b''
            owner = owners.get(name)
            links.append(cfg+f'use super::{(owner+"::") if owner else ""}{name};\n'.encode())
        for local in locals_:
            if local.encode() in used: links.append(f'use super::{local};\n'.encode())
        write(target, f'//! {desc}\n\n'.encode()+b''.join(imports)+b''.join(links)+rebase_includes(raw))
    rootlinks = []
    for name, owner in owners.items():
        defs = bindings.get(name, [])
        if not defs: continue
        cfg = defs[0].cfg if len(defs) == 1 else b''
        rootlinks.append(cfg+f'use {owner}::{name};\n'.encode())
        if any(re.match(rb'pub\b', d.code) for d in defs): MOVES[(str(path),name)] = owner
    write(path, header+declarations+b''.join(rootlinks)+b''.join(i.text for i in root)+tail)


TOPICS = [('sequence_locks',('bip68',)),('difficulty',('daa','difficulty','nbits','testnet4','pow_limit','proof_of_work')),
 ('bip30',('bip30',)),('scripts',('verify_block_transactions','bip16','verify_flags')),
 ('utxo',('block_local_utxo','utxo_changes','coinbase_maturity','apply_scratch')),
 ('windows',('window','apply_cache','batch_drain','restore_split','settle_window','buffered')),
 ('notifications',('publish','zmq','sequence_event','mining_generation','follower_dispatch','fee_estimator')),
 ('reorg',('reorg','branch','invalidate','disconnect_body','checkpoint_fallback')),
 ('disconnect',('disconnect','rewind','undo_record','marker')),
 ('peers',('peer','fanout','getheaders','getdata','headers','prefix_probe','staller')),
 ('staging',('stag','received','pending','inbound_blocks','cold_start','wedg')),
 ('admission',('admission','concurrent','generation','precommit','failed_undo'))]


def shard_tests(path, limit=800):
    data = path.read_bytes()
    header, original, tail = items(data)
    buckets = defaultdict(list)
    fixtures = []
    for item in original:
        if item.kind == 'function_item' and re.search(rb'#\[(?:test|[\w:]+::test)\]', item.prefix):
            topic = next((t for t, keys in TOPICS if any(k in item.name for k in keys)), 'validation')
            buckets[topic].append(item)
        else: fixtures.append(item.text)
    declarations = b'\n'
    for topic, tests in buckets.items():
        chunks = [[]]
        count = 0
        for item in tests:
            lines = item.text.count(b'\n')
            if chunks[-1] and count+lines > limit: chunks.append([]); count=0
            chunks[-1].append(item.text)
            count += lines
        for number, chunk in enumerate(chunks):
            name = topic+('' if number == 0 else f'_{number+1}')
            text = re.sub(rb'\bsuper::', b'super::super::', b''.join(chunk))
            write(path.with_suffix('')/(name+'.rs'), b'use super::*;\n'+rebase_includes(text))
            declarations += f'mod {name};\n'.encode()
    write(path, header+b''.join(fixtures)+declarations+tail)


def extract_tests(path):
    path = Path(path)
    data = path.read_bytes()
    header, original, tail = items(data)
    result = []
    moved = False
    for item in original:
        body = item.node.child_by_field_name('body') if item.kind == 'mod_item' else None
        if body is None or not re.search(rb'\btest\b', item.cfg): result.append(item.text); continue
        target = path.with_suffix('')/(item.name+'.rs')
        if target.exists(): raise ValueError(f'Test destination collision {target}')
        write(target, rebase_includes(data[body.start_byte+1:body.end_byte-1]))
        result.append(item.prefix+f'mod {item.name};'.encode())
        moved = True
        if target.read_bytes().count(b'\n') > 850: shard_tests(target)
    if moved: write(path, header+b''.join(result)+tail)


def parse_uses(text):
    def commas(s):
        depth=0; start=0; out=[]
        for pos, c in enumerate(s):
            depth += c == '{'; depth -= c == '}'
            if c == ',' and depth == 0: out.append(s[start:pos]); start=pos+1
        return out+[s[start:]]
    def expand(s, prefix=''):
        s=s.strip()
        if not s: return []
        if '{' in s:
            left,right=s.split('{',1)
            return sum((expand(v,prefix+left) for v in commas(right.rsplit('}',1)[0])),[])
        base,*alias=re.split(r'\s+as\s+',s)
        base=prefix.rstrip(':') if base=='self' else prefix+base
        return [(base,alias[0] if alias else None)]
    return expand(text)


def sources():
    return [p for folder in ('crates','bin','tools') for p in Path(folder).rglob('*.rs') if 'target' not in p.parts]


def update_consumers():
    maps={}
    for (path,name),owner in MOVES.items():
        stem=path.removeprefix('crates/node/src/').removesuffix('.rs').replace('/','::')
        for prefix in ('crate::','bitcoin_rs_node::'): maps[prefix+stem+'::'+name]=prefix+stem+'::'+owner+'::'+name
    for path in sources():
        data=path.read_bytes(); edits=[]; localmaps=dict(maps)
        if str(path)=='crates/node/src/lib.rs': localmaps.update({a.removeprefix('crate::'):b.removeprefix('crate::') for a,b in maps.items() if a.startswith('crate::')})
        def walk(node):
            if node.type=='use_declaration':
                m=re.match(r'((?:pub(?:\([^)]*\))?\s+)?use\s+)(.*);$',node.text.decode(),re.S)
                if m:
                    old=parse_uses(m[2]); new=[(localmaps.get(p,p),a) for p,a in old]
                    if old!=new:
                        text=m[1]+'{'+', '.join(p+((' as '+a) if a else '') for p,a in new)+'};'
                        edits.append((node.start_byte,node.end_byte,text.encode()))
                return
            for child in node.named_children: walk(child)
        walk(parse(data).root_node)
        for a,b,replacement in sorted(edits,reverse=True): data=data[:a]+replacement+data[b:]
        # Macro token trees and rustdoc source paths also use qualified names.
        for old,new in maps.items(): data=re.sub(re.escape(old.encode())+rb'\b',new.encode(),data)
        if data != path.read_bytes(): write(path,data)


def test_inventory():
    result=Counter()
    for path in Path('crates/node').rglob('*.rs'):
        data=path.read_bytes()
        def visit(node):
            if node.type=='function_item':
                previous=node.prev_named_sibling; attrs=[]
                while previous is not None and previous.type in ('attribute_item','line_comment','block_comment'):
                    attrs.append(previous.text); previous=previous.prev_named_sibling
                if re.search(rb'#\[(?:test|[\w:]+::test)\]',b''.join(attrs)): result[node.child_by_field_name('name').text.decode()]+=1
            for child in node.named_children: visit(child)
        visit(parse(data).root_node)
    return result


def unused_diagnostics(path):
    result=defaultdict(set)
    for line in Path(path).read_text().splitlines():
        try: obj=json.loads(line)
        except ValueError: continue
        if obj.get('reason')!='compiler-message': continue
        m=obj['message']
        if m['level']=='error': raise ValueError('Compiler errors must be repaired before import cleanup')
        if (m.get('code') or {}).get('code')!='unused_imports': continue
        for span in m['spans']:
            if not span.get('is_primary'): continue
            file=Path(span['file_name'])
            if not file.exists(): continue
            data=file.read_bytes()
            if span['text'] and data.decode().splitlines()[span['line_start']-1]!=span['text'][0]['text']: raise ValueError(f'Stale diagnostics {file}')
            text=data[span['byte_start']:span['byte_end']]
            for item in items(data)[1]:
                if item.kind!='use_declaration' or not item.node.start_byte<=span['byte_start']<item.node.end_byte: continue
                matched=[]
                m=re.match(rb'(?:pub(?:\([^)]*\))?\s+)?use\s+(.*);',item.code,re.S)
                tokens=set(re.findall(rb'\b\w+\b|\*',text))
                for p,a in parse_uses(m[1].decode()):
                    name=a if a not in (None,'_') else p.rsplit('::',1)[-1]
                    if name.encode() in tokens or (name=='*' and p.removesuffix('::*').encode().endswith(text)): matched.append((p,a))
                if not matched: raise ValueError(f'Unmatched unused-import span {file}: {text!r}')
                result[(str(file),item.node.start_byte)].update(matched)
    return result


def render_paths(pairs):
    trie={}
    for path,alias in sorted(set(pairs),key=lambda p:(p[0],p[1] or '')):
        node=trie
        for part in path.split('::'): node=node.setdefault(part,{})
        node.setdefault(None,[]).append(alias)
    def render(name,node):
        children=[render(n,v) for n,v in sorted(((n,v) for n,v in node.items() if n is not None),key=lambda p:p[0])]
        aliases=node.get(None,[])
        if not children:
            if len(aliases)!=1: raise ValueError('Ambiguous import')
            return name+(' as '+aliases[0] if aliases[0] else '')
        children=['self'+(' as '+a if a else '') for a in aliases]+children
        return name+'::'+(children[0] if len(children)==1 else '{'+', '.join(children)+'}')
    return [render(n,v) for n,v in sorted(trie.items())]


def prune_imports(prod_path,test_path,paths):
    prod=unused_diagnostics(prod_path); test=unused_diagnostics(test_path)
    count=0
    for p in paths:
        file=Path(p)
        if file.suffix!='.rs' or not file.exists(): continue
        data=file.read_bytes(); header,original,tail=items(data); normal=defaultdict(list); rest=[]
        for item in original:
            if item.kind!='use_declaration' or item.code.startswith(b'pub '): rest.append(item.text); continue
            m=re.match(rb'(?P<vis>pub\([^)]*\)\s+)?use\s+(.*);',item.code,re.S)
            if not m: raise ValueError(item.code)
            cfg=item.cfg.strip().decode(); vis=(m['vis'] or b'').decode().strip()
            is_test=bool(re.search(r'\bcfg\([^)]*\btest\b',cfg)) and 'not(test)' not in cfg
            is_not_test='not(test)' in cfg
            for pair in parse_uses(m[2].decode()):
                pu=pair in prod.get((p,item.node.start_byte),set()); tu=pair in test.get((p,item.node.start_byte),set())
                if (pu and tu) or (is_test and tu) or (is_not_test and pu): count+=1; continue
                newcfg=cfg
                if pu and not tu and not is_test: newcfg+='\n#[cfg(test)]'
                elif tu and not pu and not is_not_test: newcfg+='\n#[cfg(not(test))]'
                normal[(vis,newcfg.strip())].append(pair)
        lines=[]
        for (vis,cfg),pairs in sorted(normal.items()):
            for clause in render_paths(pairs): lines.append(((cfg+'\n') if cfg else '')+((vis+' ') if vis else '')+'use '+clause+';\n')
        write(file,header+b'\n\n'+b'\n'.join(s.encode() for s in lines)+b'\n'+b''.join(rest)+tail)
    print(f'Removed {count} compiler-confirmed unused bindings',flush=True)


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('group'); ap.add_argument('--prune',nargs=2); ap.add_argument('--report',required=True)
    args=ap.parse_args(); report_path=Path(args.report)
    if args.prune:
        report=json.loads(report_path.read_text()); prune_imports(*args.prune,report['paths']); return
    if subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()!=BASE: raise ValueError('Unpinned source checkout')
    import recipes
    before=test_inventory()
    recipes.apply(args.group)
    update_consumers()
    recipes.finish(args.group)
    after=test_inventory()
    allowed=Counter({n:1 for n in recipes.RETIRED.get(args.group,())})
    if before-after!=allowed or after-before: raise ValueError(f'Test identity drift: removed={before-after}, added={after-before}')
    for p in CHANGED:
        if Path(p).suffix=='.rs' and Path(p).exists(): parse(Path(p).read_bytes())
    report={'base':BASE,'group':args.group,'test_functions':sum(after.values()),'retired_alias_tests':dict(allowed),'paths':sorted(CHANGED),'moves':[{'source':p,'symbol':n,'owner':m} for (p,n),m in sorted(MOVES.items())]}
    report_path.write_text(json.dumps(report,indent=2))
    print(json.dumps(report,indent=2))


if __name__=='__main__':
    # Imported recipes must share this module's state, not import a second copy.
    import sys
    sys.modules['extract']=sys.modules[__name__]
    main()
