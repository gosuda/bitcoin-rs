"""Work-only deterministic import narrowing before compiler validation."""
import re
from pathlib import Path
from refactor_txindex import items, significant, identifiers


def flatten(tree, prefix=''):
    tree=tree.strip()
    opening=tree.find('{')
    if opening<0:
        if tree=='self':
            yield prefix.removesuffix('::')
        else:
            yield prefix+tree
        return
    assert tree.endswith('}')
    prefix+=tree[:opening].strip()
    inner=tree[opening+1:-1]
    start=depth=0
    for n,c in enumerate(inner+','):
        if c=='{': depth+=1
        elif c=='}': depth-=1
        elif c==',' and depth==0:
            part=inner[start:n].strip();start=n+1
            if part: yield from flatten(part,prefix)


def clean(scope):
    root=Path('crates/index/src/index' if scope=='index' else 'crates/node/src/txindex_worker')
    production_exports={'TxIndexRuntime','TxIndexWorker','TxIndexLifecycle','TxIndexQueryAdapter','TxIndexCapability','IndexBlockSource','Generation','TxIndexOpenSpec','DEFAULT_ROLLBACK_REBUILD_CUTOVER'}
    files=list(root.glob('*.rs'))
    if scope=='index': files=[p for p in files if p.name!='tests.rs']
    else: files=[p for p in files if p.stem not in {'heartbeat','namespace','scheduling','body_reader_tests'}]+[root.with_suffix('.rs')]
    for p in files:
        src=p.read_text();parsed=items(src)
        body='\n'.join(i.text for i in parsed if i.kind!='use')
        ids=identifiers(body)
        for attribute in re.findall(r'#\[[^\]]+\]', body):
            ids.update(re.findall(r'\b\w+\b',attribute))
        facade=p==root.with_suffix('.rs')
        if facade:
            tests=[root/'body_reader_tests.rs']+list(root.parent.glob('txindex_worker_*tests.rs'))
            ids.update(set().union(*(identifiers(t.read_text()) for t in tests)))
        out=[]
        for i in parsed:
            if i.kind!='use':
                out.append(i.text);continue
            pos=significant(i.text)[0][0]
            leading=i.text[:pos]
            statement=i.text[pos:].strip()
            m=re.fullmatch(r'(?P<vis>pub(?:\([^)]*\))?\s+)?use\s+(?P<tree>.*);',statement,re.S)
            assert m,statement
            visibility=m['vis'] or ''
            for n,leaf in enumerate(flatten(m['tree'])):
                leaf=re.sub(r'\s+',' ',leaf)
                name=leaf.split(' as ')[-1] if ' as ' in leaf else leaf.rsplit('::',1)[-1]
                implicit=(scope=='index' and ((p.stem=='rows' and name=='IntoBytes') or (p.stem=='block' and name=='_')))
                implicit|=(scope=='node' and p.stem=='forward' and leaf=='rayon::prelude::*')
                if facade and visibility:
                    keep=name in production_exports or name in ids
                else:
                    keep=name in ids or implicit
                if not keep: continue
                attrs='\n'.join(re.findall(r'#\[[^\]]+\]',leading))
                if facade and visibility and name not in production_exports and 'cfg(test)' not in attrs:
                    attrs+='\n#[cfg(test)]'
                if scope=='node' and p.stem=='lifecycle' and name in {'TxIndexWriter','PreparedBatchLimits','Worker','REVISION_QUIET_PERIOD','FORWARD_BATCH_DELAY'}:
                    attrs+='\n#[cfg(test)]'
                out.append('\n'+attrs+'\n'+visibility+'use '+leaf+';')
        header='\n'.join(line for line in src.splitlines() if line.startswith('//!'))+'\n'
        result='\n'.join(out)
        result=re.sub(r'^//!.*\n','',result,flags=re.M)
        p.write_text(header+result+'\n')
    print('Narrowed imports and isolated test-only facade/lifecycle dependencies:',scope)
