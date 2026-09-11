#!/usr/bin/env python3
"""Reviewed cleanup after the audited source moves; not shipped in PRs."""
import sys
from pathlib import Path
from refactor_txindex import items


def replace_body(source, name, body):
    match=[i for i in items(source) if i.kind in ('fn','constfn') and i.name==name]
    assert len(match)==1,name
    item=match[0]
    new=item.text[:item.body_start+1]+'\n'+body.rstrip()+'\n}'
    return source.replace(item.text,new,1)


def index():
    root=Path('crates/index/src/index')
    path=root/'rows.rs'
    s=path.read_text()
    s=replace_body(s,'distinct_row_count', '''    rows.chunk_by(|left, right| left.row == right.row).count()''')
    s=replace_body(s,'for_each_row_group', '''    let mut positions = Vec::new();
    for group in rows.chunk_by(|left, right| left.row == right.row) {
        positions.clear();
        positions.extend(group.iter().map(|entry| entry.position));
        emit(group[0].row, &positions);
    }''')
    s=replace_body(s,'apply_live_ops', '''    let mut last: hashbrown::HashMap<[u8; crate::types::SCRIPT_LIVE_ROW_SIZE], bool> =
        hashbrown::HashMap::new();
    let mut record = |op: &LiveOp| {
        let (row, insert) = match op {
            LiveOp::Insert(row) => (row, !invert),
            LiveOp::Delete(row) => (row, invert),
        };
        last.insert(*row.as_bytes(), insert);
    };
    if invert {
        ops.iter().rev().for_each(&mut record);
    } else {
        ops.iter().for_each(&mut record);
    }
    for (key, insert) in last {
        if insert {
            batch.put(ColumnFamily::ScriptLive, &key, &[]);
        } else {
            batch.delete(ColumnFamily::ScriptLive, &key);
        }
    }''')
    s=replace_body(s,'put_rows', '''    for (cf, positioned) in [
        (ColumnFamily::TxConfirmed, &rows.txid_rows),
        (ColumnFamily::Funding, &rows.funding_rows),
        (ColumnFamily::Spending, &rows.spending_rows),
    ] {
        for_each_row_group(positioned, |row, positions| {
            batch.put(cf, row.as_bytes(), &crate::types::TxPositionValue::encode(positions));
        });
    }
    for row in &rows.header_rows {
        batch.put(ColumnFamily::BlockHeaders, row, &[]);
    }
    apply_live_ops(batch, &rows.live_ops, false);''')
    s=replace_body(s,'delete_rows', '''    for (cf, positioned) in [
        (ColumnFamily::TxConfirmed, &rows.txid_rows),
        (ColumnFamily::Funding, &rows.funding_rows),
        (ColumnFamily::Spending, &rows.spending_rows),
    ] {
        for group in positioned.chunk_by(|left, right| left.row == right.row) {
            batch.delete(cf, group[0].row.as_bytes());
        }
    }
    // Rollback reverses the authoritative live transition, preserving op order.
    apply_live_ops(batch, &rows.live_ops, true);
    if delete_shared_identity {
        for row in &rows.header_rows {
            batch.delete(ColumnFamily::BlockHeaders, row);
        }
    }''')
    s+='\n#[cfg(test)]\nmod tests;\n'
    path.write_text(s)
    (root/'rows').mkdir()
    (root/'rows/tests.rs').write_text(ROW_TESTS)
    unused={'capability':['KvStore'],'rows':['KvStore'],'state':['KvSnapshot'],'format':['KvSnapshot'],'reader':['KvSnapshot'],'resolve':['KvSnapshot'],'write':['KvSnapshot']}
    for module,names in unused.items():
        p=root/(module+'.rs'); text=p.read_text()
        for name in names: text=text.replace('use bitcoin_rs_storage::'+name+';\n','')
        if module=='write': text=text.replace('use zerocopy::IntoBytes;\n','')
        p.write_text(text)
    p=root/'resolve.rs';p.write_text(p.read_text().replace('[`resolve_transaction`]','[`Self::resolve_transaction`]'))
    p=root/'write.rs'; text=p.read_text()
    old='''    /// Durable process epoch fencing this writer's reset work. Adoption of
    /// an interrupted reset re-fences the marker to this generation before
    /// any row deletion, and only this generation may clear the marker.'''
    new='''    /// Process epoch recorded as reset-claim provenance. Any process may
    /// complete the exact claim; the durable reset bytes, not this epoch,
    /// fence ordinary mutations and reset completion.'''
    assert old in text;p.write_text(text.replace(old,new))
    p=Path('crates/index/README.md');text=p.read_text();needle='## Features\n'
    section='''## Implementation boundaries

`index.rs` is the public facade. Its private modules separate block preparation
(`block`, `prepared`), canonical row mutation (`rows`), durable writes (`write`),
and coherent fences/reset recovery (`state`). Read-side scans (`reader`,
`snapshot`) and exact resolution (`resolve`) remain separate from mutations;
`capability`, `format`, and `error` own shared representations and typed outcomes.
Public paths and on-disk encodings do not depend on this layout.

'''
    assert needle in text;p.write_text(text.replace(needle,section+needle))
    print('Reviewed simplifications: five row functions; added three backend-independent regression tests')

ROW_TESTS='''use std::collections::BTreeMap;

use bitcoin_rs_primitives::{Hash256, OutPoint, Txid};
use bitcoin_rs_storage::{ColumnFamily, WriteBatch};

use super::{IndexError, IndexRowCounts, LiveOp, PendingRows, PositionedRow, apply_live_ops,
    delete_rows, distinct_row_count, for_each_row_group, put_rows};
use crate::types::{HashPrefixRow, ScriptHash, ScriptLiveRow, TxPosition};

#[derive(Debug, Eq, PartialEq)]
struct Mutation {
    cf: ColumnFamily,
    key: Vec<u8>,
    value: Option<Vec<u8>>,
}

#[derive(Default)]
struct RecordingBatch {
    mutations: Vec<Mutation>,
    ranges: Vec<(ColumnFamily, Vec<u8>, Vec<u8>)>,
}

impl WriteBatch for RecordingBatch {
    fn put(&mut self, cf: ColumnFamily, key: &[u8], value: &[u8]) {
        self.mutations.push(Mutation { cf, key: key.to_vec(), value: Some(value.to_vec()) });
    }
    fn delete(&mut self, cf: ColumnFamily, key: &[u8]) {
        self.mutations.push(Mutation { cf, key: key.to_vec(), value: None });
    }
    fn delete_range(&mut self, cf: ColumnFamily, start: &[u8], end: &[u8]) {
        self.ranges.push((cf, start.to_vec(), end.to_vec()));
    }
}

fn positioned_rows() -> Vec<PositionedRow> {
    let first = HashPrefixRow::new([1; 8], 7);
    let second = HashPrefixRow::new([2; 8], 7);
    vec![
        PositionedRow { row: second, position: TxPosition::new(500, 30) },
        PositionedRow { row: first, position: TxPosition::new(256, 20) },
        PositionedRow { row: first, position: TxPosition::new(81, 10) },
        PositionedRow { row: first, position: TxPosition::new(81, 10) },
    ]
}

#[test]
fn groups_preserve_distinct_keys_and_numeric_positions() {
    let mut rows = positioned_rows();
    rows.sort_unstable();
    rows.dedup();
    let mut grouped = Vec::new();
    for_each_row_group(&rows, |key, positions| grouped.push((key, positions.to_vec())));
    assert_eq!(distinct_row_count(&rows), 2);
    assert_eq!(grouped, vec![
        (HashPrefixRow::new([1; 8], 7), vec![TxPosition::new(81, 10), TxPosition::new(256, 20)]),
        (HashPrefixRow::new([2; 8], 7), vec![TxPosition::new(500, 30)]),
    ]);
    assert_eq!(distinct_row_count(&[]), 0);
    let mut empty_groups = 0;
    for_each_row_group(&[], |_, _| empty_groups += 1);
    assert_eq!(empty_groups, 0);
}

#[test]
fn row_accounting_matches_emitted_bytes_and_shared_header_deletion() -> Result<(), IndexError> {
    let mut rows = PendingRows {
        txid_rows: positioned_rows(),
        funding_rows: positioned_rows(),
        spending_rows: positioned_rows(),
        header_rows: vec![[1; crate::types::HEADER_ROW_SIZE]],
        live_ops: Vec::new(),
    };
    rows.sort();
    assert_eq!(rows.counts(), IndexRowCounts { txids: 2, funding: 2, spending: 2, headers: 1, live: 0 });
    let mut puts = RecordingBatch::default();
    put_rows(&mut puts, &rows);
    assert_eq!(puts.mutations.len(), rows.total());
    let encoded_bytes: usize = puts.mutations.iter()
        .map(|mutation| mutation.key.len() + mutation.value.as_ref().map_or(0, Vec::len)).sum();
    assert_eq!(rows.encoded_bytes()?, encoded_bytes);
    for delete_shared_identity in [false, true] {
        let mut deletes = RecordingBatch::default();
        delete_rows(&mut deletes, &rows, delete_shared_identity);
        let expected: Vec<_> = puts.mutations.iter()
            .filter(|mutation| delete_shared_identity || mutation.cf != ColumnFamily::BlockHeaders)
            .map(|mutation| Mutation { cf: mutation.cf, key: mutation.key.clone(), value: None }).collect();
        assert_eq!(deletes.mutations, expected);
        assert!(deletes.ranges.is_empty());
    }
    assert!(puts.ranges.is_empty());
    Ok(())
}

#[test]
fn live_coalescing_matches_first_and_last_operations_for_all_small_sequences() {
    let outpoint = OutPoint::new(Txid(Hash256::from_le_bytes(&[0; 32])), 0);
    let keys = [ScriptLiveRow::new(ScriptHash::from_byte_array([0; 32]), &outpoint),
        ScriptLiveRow::new(ScriptHash::from_byte_array([1; 32]), &outpoint)];
    let choices = [LiveOp::Insert(keys[0]), LiveOp::Delete(keys[0]),
        LiveOp::Insert(keys[1]), LiveOp::Delete(keys[1])];
    for len in 0..=5_u32 {
        for mut pattern in 0..4_usize.pow(len) {
            let mut ops = Vec::new();
            for _ in 0..len {
                ops.push(choices[pattern % 4]);
                pattern /= 4;
            }
            for invert in [false, true] {
                let mut batch = RecordingBatch::default();
                apply_live_ops(&mut batch, &ops, invert);
                let mut expected = BTreeMap::new();
                for key in keys {
                    let matches_key = |op: &&LiveOp| match op {
                        LiveOp::Insert(row) | LiveOp::Delete(row) => *row == key,
                    };
                    let decisive = if invert { ops.iter().find(matches_key) } else { ops.iter().rfind(matches_key) };
                    if let Some(op) = decisive {
                        let insert = matches!(op, LiveOp::Insert(_)) != invert;
                        expected.insert(key.as_bytes().to_vec(), insert.then(Vec::new));
                    }
                }
                let actual: BTreeMap<_, _> = batch.mutations.iter().map(|mutation| {
                    assert_eq!(mutation.cf, ColumnFamily::ScriptLive);
                    (mutation.key.clone(), mutation.value.clone())
                }).collect();
                assert_eq!(actual.len(), batch.mutations.len(), "each live key is emitted once");
                assert_eq!(actual, expected, "invert={invert}, ops={ops:?}");
                assert!(batch.ranges.is_empty());
            }
        }
    }
}
'''


def node():
    p=Path('crates/node/README.md');text=p.read_text();needle='## Features\n'
    section='''## Transaction-index runtime

`txindex_worker.rs` is the stable composition facade. Private modules keep
runtime health and lifecycle publication separate from supervised storage open,
reconciliation decisions, bounded forward work, rollback, and authoritative
live-view anchoring. The query engine separates snapshot admission and work
budgets from body resolution, script queries, and progress reporting. Existing
namespace, heartbeat, and wake scheduling owners remain in place.

'''
    assert needle in text;p.write_text(text.replace(needle,section+needle))

if __name__=='__main__':
    {'index':index,'node':node}[sys.argv[1]]()
    from clean_txindex_imports import clean
    clean(sys.argv[1])
