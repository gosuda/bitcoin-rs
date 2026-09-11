#!/usr/bin/env python3
"""One-shot source refactor; workbench only, never included in a source PR."""
from __future__ import annotations
import collections
import hashlib
from pathlib import Path
import re
import textwrap
from dataclasses import dataclass
from pygments.lexers import RustLexer
from pygments.token import Token

ROOT = Path.cwd()

def tokens(s):
    return list(RustLexer().get_tokens_unprocessed(s))

def significant(s):
    out = []
    attribute_depth = 0
    for p, t, v in tokens(s):
        if t in Token.Comment.Preproc:
            attribute_depth += v.count('[') - v.count(']')
            continue
        if attribute_depth or t in Token.Comment or t in Token.Text or t in Token.Literal.String.Doc:
            continue
        out.append((p, t, v))
    assert attribute_depth == 0
    return out

def identifiers(s):
    return set(re.findall(r'[A-Za-z_][A-Za-z_0-9]*', ' '.join(v for _,t,v in significant(s) if t not in Token.Literal.String)))

def norm(s):
    return ''.join(v for _,_,v in significant(s))

@dataclass
class Item:
    text: str
    kind: str
    name: str
    body_start: int | None = None
    body_end: int | None = None

    def methods(self):
        assert self.body_start is not None and self.body_end is not None
        return items(self.text[self.body_start+1:self.body_end])

    def with_methods(self, ms):
        return self.text[:self.body_start+1]+'\n'+''.join(m.text for m in ms)+'\n}'

def items(s):
    out = []
    start = 0
    braces = parens = brackets = 0
    code = []
    body_start = None
    for p,t,v in significant(s):
        code.append(v)
        if t not in Token.Punctuation:
            continue
        for off,c in enumerate(v):
            if c == '{':
                if braces == 0 and parens == 0 and brackets == 0:
                    body_start = p+off
                braces += 1
            elif c == '}': braces -= 1
            elif c == '(': parens += 1
            elif c == ')': parens -= 1
            elif c == '[': brackets += 1
            elif c == ']': brackets -= 1
            assert min(braces,parens,brackets) >= 0, (s[start:p+30], braces,parens,brackets)
            if braces or parens or brackets: continue
            head = ''.join(code)
            match = re.match(r'(?:pub(?:\([^)]*\))?)?(?:(?:async|unsafe)\s*)?(constfn|fn|const|static|struct|enum|trait|type|use|mod|impl)',head)
            if not match: continue
            kind=match[1]
            end = (c == ';') or (c == '}' and kind not in ('const','static','type','use'))
            if not end: continue
            content = s[start:p+off+1]
            sig = ' '.join(v for _,_,v in significant(content))
            if kind == 'impl':
                opening = sig.split('{',1)[0]
                if ' for ' in opening:
                    target = opening.rsplit(' for ',1)[1]
                else:
                    target = opening[len('impl'):].strip()
                    if target.startswith('<'):
                        depth=0
                        for i,ch in enumerate(target):
                            if ch=='<': depth+=1
                            elif ch=='>':
                                depth-=1
                                if depth==0:
                                    target=target[i+1:].strip(); break
                name=re.match(r'([A-Za-z_]\w*)',target)[1]
            else:
                m=re.search(r'\b'+ ('fn' if kind=='constfn' else kind)+r'\s+([A-Za-z_]\w*)',sig)
                name=m[1] if m else ''
            out.append(Item(content,kind,name,None if body_start is None else body_start-start, p+off-start if c=='}' else None))
            start=p+off+1
            code=[]
            body_start=None
    assert not code, ('unterminated', s[start:start+200])
    assert not s[start:].strip(), ('trailing',s[start:])
    assert ''.join(i.text for i in out).strip()==s.strip()
    return out

EXTERNAL_INDEX = {
    'ControlFlow':'use std::ops::ControlFlow;',
    **{n:f'use bitcoin_rs_primitives::{n};' for n in 'Block Hash256 OutPoint Tx Txid encode'.split()},
    **{n:f'use bitcoin_rs_storage::{n};' for n in 'ColumnFamily KvSnapshot KvStore PrefixScanLimit StorageError WriteBatch WriteCondition'.split()},
    'bsl':'use bitcoin_slices::bsl;', 'Visitor':'use bitcoin_slices::Visitor;',
    'Error':'use thiserror::Error;', 'debug':'use tracing::debug;',
    'as_bytes':'use zerocopy::IntoBytes;',
    'SelectedWatermark':'use crate::reconcile::SelectedWatermark;',
    'reconcile_selected_watermark':'use crate::reconcile::selected_watermark as reconcile_selected_watermark;',
    **{n:f'use crate::types::{n};' for n in 'HashPrefixRow HeaderRow ScriptHash ScriptHashRow SpendingPrefixRow TxidRow'.split()},
}

def promote_item(item):
    s=item.text
    ts=significant(s)
    first=ts[0][0]
    if ts[0][2] == 'pub': return s
    return s[:first]+'pub(super) '+s[first:]

def promote_fields(item, fields):
    s=item.text
    for field in fields:
        s,n=re.subn(r'^(\s*)('+re.escape(field)+r'\s*:)',r'\1pub(super) \2',s,flags=re.M)
        assert n==1,(item.name,field,n)
    return s

def promote_methods(item, names):
    ms=item.methods()
    for m in ms:
        if m.name in names:
            m.text=promote_item(m)
    return item.with_methods(ms)

def refactor_index():
    path=ROOT/'crates/index/src/index.rs'
    src=path.read_text()
    assert hashlib.sha256(src.encode()).hexdigest() == '4c8b9b3949522f90159ab103e1ee796bd51dcf68830bb09355c330aa3da5eb9b', 'unexpected index source'
    parsed=items(src)
    groups=collections.defaultdict(list)
    public={}
    defs={}
    for i in parsed:
        if i.kind=='use': continue
        if i.kind=='mod':
            assert i.name=='tests'
            test_src=textwrap.dedent(i.text[i.body_start+1:i.body_end]).strip()+'\n'
            test_src=test_src.replace('IndexWriter, Indexer, is_op_return_script','IndexWriter, Indexer')
            test_src='use super::block::is_op_return_script;\n'+test_src
            continue
        if i.name=='IndexError': owner='error'
        elif i.name in {'IndexWatermark','IndexCapability','IndexCapabilities','IndexWatermarks','watermark_key','WATERMARK_LEN','TX_LOOKUP_WATERMARK_KEY','SCRIPT_HISTORY_WATERMARK_KEY','SCRIPT_LIVE_WATERMARK_KEY','put_selected_watermarks','selected_watermark'}: owner='capability'
        elif i.name in {'IndexWriter','has_any_index_row'}: owner='write'
        elif i.name in {'PreparedBlock','PreparedBatch','PreparedBatchLimits'}: owner='prepared'
        elif i.name in {'LiveOp','IndexRowCounts','PendingRows','PositionedRow','distinct_row_count','for_each_row_group','apply_live_ops','put_rows','delete_rows'}: owner='rows'
        elif i.name in {'SpentCoinScripts','NoSpentScripts','MAX_LIVE_SCRIPT_SIZE','pending_rows_for_block_with_header','push_live_ops','IndexBlockVisitor','is_null_prevout','is_op_return_script'}: owner='block'
        elif i.name in {'ScriptHistoryEntry','BlockSource','transaction_at','positioned_history','scan_height_history','positioned_unspent_outputs','scan_height_unspent_outputs','append_matching_outputs','funds_scripthash'}: owner='resolve'
        elif i.name in {'TxIndexScanRow','TxIndexScan','ScriptLiveScan','TxIndexSnapshot','StoreTxIndexSnapshot','IndexReader'}: owner='snapshot'
        elif i.name in {'INDEX_FORMAT_VERSION_KEY','INDEX_FORMAT_VERSION','IndexFormat','FormatMarker'}: owner='format'
        elif i.name in {'Indexer','collect_prefix_rows_with_values','collect_prefix_rows'}: owner='reader'
        else: owner='state'
        if i.kind=='impl' and i.name in {'IndexWriter','Indexer'}:
            head=norm(i.text[:i.body_start])
            if 'IndexReaderfor' in head:
                owner='snapshot'
            else:
                byowner=collections.defaultdict(list)
                for m in i.methods():
                    dest=owner
                    if i.name=='IndexWriter' and m.name.startswith('prepare_block'): dest='block'
                    elif i.name=='Indexer' and m.name.startswith('resolve_'): dest='resolve'
                    elif i.name=='Indexer' and m.name in {'ensure_format_version','read_format_version','has_any_header'}: dest='format'
                    byowner[dest].append(m)
                for dest, ms in byowner.items():
                    groups[dest].append(Item(i.with_methods(ms),i.kind,i.name))
                continue
        groups[owner].append(i)
        if i.kind not in ('impl','use'):
            assert i.name not in defs, i.name
            defs[i.name]=owner
            if re.match(r'pub\s+(?!\()', ' '.join(v for _,_,v in significant(i.text))):
                public[i.name]=owner
    shared_fields={
      'IndexWriteFence': {'watermarks'},
      'PreparedBlock': {'capabilities','rows'},
      'PositionedRow': {'row','position'},
      'PendingRows': {'txid_rows','funding_rows','spending_rows','header_rows','live_ops'},
      'Indexer': {'store','last_counts'}, 'IndexWriter': {'indexer','generation'},
    }
    shared_methods={
      'IndexCapabilities': {'to_mask','from_mask'},
      'PendingRows': {'sort','counts','append','total','encoded_bytes'},
      'Indexer': {'iter_funding_rows_with_values','iter_txid_rows_with_values'},
    }
    group_ids={owner:set().union(*(identifiers(i.text) for i in its)) for owner,its in groups.items()}
    needed={name for name,owner in defs.items() if any(name in ids for other,ids in group_ids.items() if other!=owner)}
    needed.add('is_op_return_script')
    for owner, its in groups.items():
        for i in its:
            if i.kind=='struct' and i.name in shared_fields:
                i.text=promote_fields(i,shared_fields[i.name])
            elif i.kind=='impl' and i.name in shared_methods:
                i.text=promote_methods(items(i.text)[0],shared_methods[i.name])
            if i.kind!='impl' and i.name in needed:
                i.text=promote_item(i)
    outdir=path.with_suffix('');outdir.mkdir()
    headers={
      'error':'Typed failures shared by index reads, preparation, and durable writes.',
      'capability':'Capability selection and the exact durable watermark representation.',
      'state':'Coherent write fences and cooperative, versioned capability-reset recovery.',
      'prepared':'Bounded prepared-block ownership and batch admission.',
      'rows':'Canonical row accounting, grouping, and ordered live-view mutations.',
      'block':'Parse-once block preparation and authoritative spent-script anchoring.',
      'reader':'Read-side store access and typed prefix-row decoding.',
      'resolve':'Exact transaction and script resolution, including independent scan references.',
      'snapshot':'Point-in-time, bounded, typed index scans.',
      'format':'Row-value format reporting and marker decoding.',
      'write':'The sole concrete owner of durable index mutations.',
    }
    for owner, its in groups.items():
        code='\n\n'.join(i.text.strip() for i in its)+'\n'
        ids=identifiers(code)
        imports=list(dict.fromkeys(EXTERNAL_INDEX.values()))
        if owner=='block': imports.append('use bitcoin_slices::Visit as _;')
        for target in sorted(groups):
            names=sorted(n for n,own in defs.items() if own==target and n in ids and target!=owner)
            if names: imports.append('use super::'+target+'::{'+', '.join(names)+'};')
        for n,target in defs.items():
            if target!=owner:
                code=code.replace('[`'+n+'`]', '[`super::'+target+'::'+n+'`]')
        (outdir/(owner+'.rs')).write_text('//! '+headers[owner]+'\n\n'+'\n'.join(imports)+'\n\n'+code)
    (outdir/'tests.rs').write_text(test_src)
    facade='//! Confirmed transaction indexing with separate read, preparation, and durable-write owners.\n\n'
    facade+='\n'.join('mod '+m+';' for m in sorted(groups))+'\n\n'
    for owner in sorted(set(public.values())):
        names=sorted(n for n,o in public.items() if o==owner)
        facade+='pub use '+owner+'::{'+', '.join(names)+'};\n'
    facade+='\n#[cfg(all(test, feature = "rocksdb"))]\nmod tests;\n'
    path.write_text(facade)
    audit_index(src, path, outdir)
    print('INDEX: split',len(src.splitlines()),'lines into', {p.name:len(p.read_text().splitlines()) for p in sorted(outdir.glob('*.rs'))})

def function_inventory(source):
    found = collections.Counter()
    for item in items(source):
        if item.kind in ('fn', 'constfn'):
            body = item.text[item.body_start+1:item.body_end] if item.body_start is not None else item.text
            found[(item.name, norm(body))] += 1
        elif item.kind in ('impl', 'trait', 'mod') and item.body_start is not None:
            found.update(function_inventory(item.text[item.body_start+1:item.body_end]))
    return found

def audit_index(original, root, directory):
    before = function_inventory(original)
    after = function_inventory(root.read_text())
    for path in directory.glob('*.rs'):
        after.update(function_inventory(path.read_text()))
    missing, added = before-after, after-before
    assert not missing and not added, ('function body drift', [(n, c) for (n, _), c in missing.items()], [(n, c) for (n, _), c in added.items()])
    print('Exact function-body inventory:', sum(before.values()), 'preserved')

if __name__=='__main__':
    refactor_index()
