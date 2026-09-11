"""Final, scoped lint/doc fixes and import grouping; workbench only."""
from collections import defaultdict
from pathlib import Path
import re
import sys
from refactor_txindex import items, significant
from clean_txindex_imports import flatten


def replace(path, old, new, count=1):
    s=path.read_text()
    assert s.count(old)==count,(path,old,s.count(old))
    path.write_text(s.replace(old,new))


def compact_imports(path):
    source=path.read_text()
    grouped=defaultdict(set)
    body=[]
    for item in items(source):
        if item.kind!='use':
            body.append(re.sub(r'^//!.*\n','',item.text,flags=re.M).strip())
            continue
        start=significant(item.text)[0][0]
        leading=item.text[:start]
        attrs=tuple(dict.fromkeys(re.findall(r'#\[[^\]]+\]',leading)))
        match=re.fullmatch(r'(?P<vis>pub(?:\([^)]*\))?\s+)?use\s+(?P<tree>.*);',item.text[start:].strip(),re.S)
        assert match,item.text
        for leaf in flatten(match['tree']):
            prefix,sep,tail=leaf.partition('::')
            assert sep,leaf
            grouped[(match['vis'] or '',attrs,prefix)].add(tail)
    imports=[]
    for (vis,attrs,prefix),leaves in sorted(grouped.items()):
        names=sorted(leaves)
        tree=prefix+'::'+(names[0] if len(names)==1 else '{'+', '.join(names)+'}')
        imports.append('\n'.join([*attrs,vis+'use '+tree+';']))
    header='\n'.join(line for line in source.splitlines() if line.startswith('//!'))
    rest='\n\n'.join(body)
    rest=re.sub(r'(?m)(^mod [a-z_]+;)\n\n(?=mod [a-z_]+;)',r'\1\n',rest)
    path.write_text(header+'\n\n'+'\n'.join(imports)+'\n\n'+rest+'\n')


scope=sys.argv[1]
root=Path('crates/index/src/index' if scope=='index' else 'crates/node/src/txindex_worker')
if scope=='index':
    replace(root/'rows/tests.rs',
        'for_each_row_group(&rows, |key, positions| grouped.push((key, positions.to_vec())));',
        'for_each_row_group(&rows, |key, positions| { grouped.push((key, positions.to_vec())); });')
    replace(root/'rows.rs','let mut record = |op: &LiveOp|','let record = |op: &LiveOp|')
    replace(root/'rows.rs','for_each(&mut record)','for_each(record)',2)
    replace(root/'rows.rs',
        '/// reverse order so the coalescing rule stays "the chronologically last\n/// forward operation decides".',
        '/// reverse order so the earliest forward operation determines each key\'s\n/// undo mutation.')
    files=[p for p in root.glob('*.rs') if p.name!='tests.rs']
else:
    replace(Path('crates/node/src/embed.rs'),
        '#[allow(clippy::unused_async, clippy::unused_async_trait_impl)]',
        '#[allow(clippy::unused_async)]',5)
    replace(Path('crates/node/src/checkpoint/tests/behavior_2.rs'),
        ': MuHash numerator/denominator, then',': `MuHash` numerator/denominator, then')
    files=[p for p in root.glob('*.rs') if p.stem not in {'heartbeat','namespace','scheduling','body_reader_tests'}]+[root.with_suffix('.rs')]
for p in files:
    compact_imports(p)
print('Grouped imports without widening visibility; addressed observed strict lints:',scope)
