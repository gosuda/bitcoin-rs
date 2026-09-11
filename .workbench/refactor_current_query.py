"""Source-only follow-up over current main's existing worker boundaries."""
from pathlib import Path
from collections import defaultdict
import re
import hashlib
from refactor_txindex import items, significant, identifiers, function_inventory, promote_item
from clean_txindex_imports import flatten

root=Path('crates/node/src/txindex_worker')
path=root/'query.rs'
original=path.read_text()
assert hashlib.sha256(original.encode()).hexdigest() == '00f43e4326fe14e12f360a345873afe6f152986994c87ab6ebffe15ceb04ba11'
parent=(root.with_suffix('.rs')).read_text()
external={}
for i in items(parent):
    if i.kind!='use': continue
    statement=i.text[significant(i.text)[0][0]:].strip()
    m=re.fullmatch(r'(?:pub(?:\([^)]*\))?\s+)?use\s+(.*);',statement,re.S)
    for leaf in flatten(m[1]):
        if leaf.split('::',1)[0] not in {'std','arc_swap','bitcoin_rs_chain','bitcoin_rs_index','bitcoin_rs_primitives','bitcoin_rs_rpc','bitcoin_rs_storage','parking_lot'}: continue
        name=leaf.split(' as ')[-1] if ' as ' in leaf else leaf.rsplit('::',1)[-1]
        external[name]=leaf
parent_names={'TxIndexRuntime','QUERY_SCAN_ROW_LIMIT','QUERY_SCAN_BYTE_LIMIT','QUERY_SCAN_COUNT_LIMIT','QUERY_BODY_READ_LIMIT','MAX_SERIALIZED_BLOCK_BYTES'}
owners={'QueryBudget':'budget','QueryEngineLive':'query','TxIndexQueryEngine':'query','IndexProgress':'progress','IndexBlockSource':'source'}
groups=defaultdict(list)
body_methods={'resolve_hash_at_height','hash_at_height','resolve_block','resolve_block_body_bytes','verify_block','validated_positions','resolve_positioned_transaction','transaction_from_full_block','transaction_for','locate_transaction_for','outpoint_value_for','spending_input'}
core_methods={'new','query_health','require_enabled','with_snapshot'}
for i in items(original):
    if i.kind=='use': continue
    owner=owners[i.name]
    if i.kind=='struct' and i.name=='QueryBudget': i.text=promote_item(i)
    if i.kind=='impl' and i.name=='QueryBudget':
        ms=i.methods()
        for m in ms:m.text=promote_item(m)
        i.text=i.with_methods(ms)
    elif i.kind=='impl' and i.name=='TxIndexQueryEngine' and ' for ' not in ' '.join(v for _,_,v in significant(i.text[:i.body_start])):
        byowner=defaultdict(list)
        for m in i.methods():
            dest='query' if m.name in core_methods else 'progress' if m.name=='index_progress_for' else 'body' if m.name in body_methods else 'script'
            if dest!='query':m.text=promote_item(m)
            byowner[dest].append(m)
        for dest,ms in byowner.items():groups[dest].append(i.with_methods(ms))
        continue
    groups[owner].append(i.text)
headers={'query':'Coherent query admission, snapshot fencing, and protocol entry points.',
'budget':'Aggregate scan, body-read, and byte budgets for one public query.',
'body':'Identity-checked block bodies, exact positions, and transaction resolution.',
'script':'Exact script-history, spender, and authoritative live-output composition.',
'progress':'Coherent capability watermark progress against one applied tip.',
'source':'Index-side block source over the authoritative tree and body store.'}
outdir=root/'query';outdir.mkdir()
for module,parts in groups.items():
    code='\n\n'.join(p.strip() for p in parts)+'\n'
    ids=identifiers(code)
    imports=defaultdict(set)
    for name,leaf in external.items():
        if name in ids or (name=='BlockSource' and '.block_at_height(' in code):
            prefix,tail=leaf.split('::',1);imports[prefix].add(tail)
    for name in parent_names & ids:
        imports['super'].add(name if module=='query' else 'super::'+name)
    for name,owner in owners.items():
        if name in ids and owner!=module:
            if module=='query':
                if name not in {'IndexProgress','IndexBlockSource'}:imports[owner].add(name)
            else: imports['super'].add(name)
    prefix='//! '+headers[module]+'\n\n'
    if module=='query':
        prefix+='mod body;\nmod budget;\nmod progress;\nmod script;\nmod source;\n\n'
        prefix+='pub(crate) use progress::IndexProgress;\npub(crate) use source::IndexBlockSource;\n\n'
    for first,leaves in sorted(imports.items()):
        names=sorted(leaves)
        prefix+='use '+first+'::'+(names[0] if len(names)==1 else '{'+', '.join(names)+'}')+';\n'
    dest=path if module=='query' else outdir/(module+'.rs')
    dest.write_text(prefix+'\n'+code)
after=function_inventory(path.read_text())
for p in outdir.glob('*.rs'):after.update(function_inventory(p.read_text()))
assert function_inventory(original)==after,'query function body drift'
print('Preserved all',sum(after.values()),'current-main query function bodies exactly')

p=Path('crates/node/src/storage_backend.rs');s=p.read_text()
old='''        (
            "txindex_worker.rs",
            include_str!("txindex_worker.rs"),
            Some("mod body_reader_tests;"),
        ),'''
assert old in s
entries=[]
files=[root.with_suffix('.rs')]+[p for p in root.rglob('*.rs') if not p.name.endswith('tests.rs')]
for source in sorted(files):
    name=source.relative_to(Path('crates/node/src')).as_posix()
    text=source.read_text()
    boundary=next((v for v in ['mod body_reader_tests;','mod tests {','mod tests;'] if v in text),None)
    cut='None' if boundary is None else 'Some("'+boundary+'")'
    entries.append('        ("'+name+'", include_str!("'+name+'"), '+cut+'),')
s=s.replace(old,'\n'.join(entries))
old_match='''            let production = match test_module {
                Some(boundary) => {
                    let start = source
                        .find(boundary)
                        .unwrap_or_else(|| panic!("{name} lost its expected test-module boundary"));
                    &source[..start]
                }
                None => source,
            };'''
assert old_match in s
s=s.replace(old_match,'            let production = production_source(name, source, *test_module);')
addition='''
    fn production_source<'a>(name: &str, source: &'a str, boundary: Option<&str>) -> &'a str {
        match boundary {
            Some(boundary) => {
                let start = source.find(boundary)
                    .unwrap_or_else(|| panic!("{name} lost its expected test-module boundary"));
                &source[..start]
            }
            None => source,
        }
    }

    #[test]
    fn runtime_backend_inventory_covers_txindex_modules() {
        for (name, source, boundary) in RUNTIME_CONSUMERS {
            if !name.starts_with("txindex_worker") { continue; }
            let production = production_source(name, source, *boundary);
            for line in production.lines() {
                let Some(child) = line.trim().strip_prefix("mod ")
                    .and_then(|declaration| declaration.strip_suffix(';')) else { continue; };
                let directory = name.strip_suffix(".rs").expect("Rust module source");
                let expected = format!("{directory}/{child}.rs");
                assert!(RUNTIME_CONSUMERS.iter().any(|(path, _, _)| *path == expected),
                    "{expected} is absent from the concrete-backend construction gate");
            }
        }
    }
'''
pos=s.rfind('}');s=s[:pos]+addition+s[pos:];p.write_text(s)
p=Path('crates/node/README.md');s=p.read_text();needle='## Features\n'
assert needle in s
s=s.replace(needle,'''## Transaction-index query boundaries

The existing `txindex_worker` lifecycle, startup, reconciliation, catch-up, cursor,
and rollback owners remain separate. Its `query` module owns snapshot admission
and protocol entry points, with private `budget`, `body`, `script`, `progress`, and
`source` modules for the corresponding query responsibilities. The concrete
backend-construction gate covers all production worker modules, including nested
query modules, and checks its inventory against their module declarations.

'''+needle)
p.write_text(s)
print('Covered',len(entries),'production txindex sources and added an inventory regression gate')

p=root.with_suffix('.rs');s=p.read_text();parsed=items(s)
def only_test(item):
    return '#[cfg(test)]' in item.text[:significant(item.text)[0][0]]
prod=identifiers('\n'.join(i.text for i in parsed if i.kind!='use' and not only_test(i)))
for child in root.glob('*.rs'):
    if child.name.endswith('tests.rs'):continue
    for i in items(child.read_text()):
        if only_test(i):continue
        if i.kind=='use':
            statement=i.text[significant(i.text)[0][0]:].strip()
            m=re.fullmatch(r'(?:pub(?:\([^)]*\))?\s+)?use\s+(.*);',statement,re.S)
            for leaf in flatten(m[1]):
                if leaf.startswith('super::'):
                    prod.add(leaf[len('super::'):].split('::')[0].split(' as ')[0])
        else:
            prod.update(re.findall(r'\bsuper::(\w+)',i.text))
test_files=[root/'body_reader_tests.rs']+list(root.parent.glob('txindex_worker_*tests.rs'))
test_names=set().union(*(identifiers(t.read_text()) for t in test_files))
test_names.update(identifiers('\n'.join(i.text for i in parsed if i.kind!='use' and only_test(i))))
test_names.update({'BlockSource','ScriptIndexQuery','TxIndexQuery'})
new=[]
for i in parsed:
    if i.kind!='use':new.append(i.text.strip());continue
    start=significant(i.text)[0][0];leading=i.text[:start]
    statement=i.text[start:].strip()
    m=re.fullmatch(r'(?P<vis>pub(?:\([^)]*\))?\s+)?use\s+(?P<tree>.*);',statement,re.S)
    attrs=list(dict.fromkeys(re.findall(r'#\[[^\]]+\]',leading)))
    for leaf in flatten(m['tree']):
        name=leaf.split(' as ')[-1] if ' as ' in leaf else leaf.rsplit('::',1)[-1]
        visibility=m['vis'] or ''
        if not visibility and name not in prod and name not in test_names:continue
        guarded=attrs.copy()
        if not visibility and name not in prod and '#[cfg(test)]' not in guarded:guarded.append('#[cfg(test)]')
        new.append('\n'.join([*guarded,visibility+'use '+leaf+';']))
header='\n'.join(line for line in s.splitlines() if line.startswith('//!'))
result=re.sub(r'^//!.*\n','', '\n\n'.join(new),flags=re.M)
result=re.sub(r'(?m)(^mod [a-z_]+;)\n\n(?=mod [a-z_]+;)',r'\1\n',result)
p.write_text((header+'\n\n'+result+'\n').replace('[`ScriptIndexQuery`]', '[`bitcoin_rs_rpc::context::ScriptIndexQuery`]'))
assert function_inventory(s)==function_inventory(p.read_text()),'worker parent function body drift'
print('Preserved worker parent function bodies; isolated test-only import dependencies')

for p in [root.with_suffix('.rs'),path,*outdir.glob('*.rs')]:
    s=p.read_text();groups=defaultdict(set);body=[]
    for i in items(s):
        if i.kind!='use':body.append(re.sub(r'^//!.*\n','',i.text,flags=re.M).strip());continue
        at=significant(i.text)[0][0]
        attrs=tuple(dict.fromkeys(re.findall(r'#\[[^\]]+\]',i.text[:at])))
        m=re.fullmatch(r'(?P<vis>pub(?:\([^)]*\))?\s+)?use\s+(?P<tree>.*);',i.text[at:].strip(),re.S)
        for leaf in flatten(m['tree']):
            first,tail=leaf.split('::',1)
            groups[(m['vis'] or '',attrs,first)].add(tail)
    imports=[]
    for (visibility,attrs,first),leaves in sorted(groups.items()):
        names=sorted(leaves)
        imports.append('\n'.join([*attrs,visibility+'use '+first+'::'+(names[0] if len(names)==1 else '{'+', '.join(names)+'}')+';']))
    header='\n'.join(line for line in s.splitlines() if line.startswith('//!'))
    body='\n\n'.join(body)
    body=re.sub(r'(?m)(^mod [a-z_]+;)\n\n(?=mod [a-z_]+;)',r'\1\n',body)
    p.write_text(header+'\n\n'+'\n'.join(imports)+'\n\n'+body+'\n')
