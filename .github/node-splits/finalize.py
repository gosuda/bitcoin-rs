"""Native acceptance and publication of the remaining source-only node splits."""
from collections import Counter
import ast
from pathlib import Path
import re
import sys

import finish as f
m, r = f.m, f.r
m.BASE = r.BASE = '802ac778d67132cee65a9195edcf4fe2f8059ae4'
m.PREFIX = 'refactor/node-split-802ac7-'
GATE = 'bin/bitcoin-rs/tests/support/ownership_scan.rs'

# A comma immediately before a call's closing parenthesis is optional syntax;
# tuple commas and all literal bytes remain significant to the inventory.
def optional_call_comma(node):
    return (node.type == ',' and node.parent is not None
            and node.parent.type == 'arguments' and node.next_sibling is not None
            and node.next_sibling.type == ')')


def test_key(item):
    body = item.node.child_by_field_name('body').text.decode()
    for old, new in [('segment_name_pub', 'segment_name'), ('parse_segment_name_pub', 'parse_segment_name')]:
        body = re.sub(r'\b' + old + r'\b', new, body)
    tokens, queue = [], [r.PARSER.parse(body.encode()).root_node]
    while queue:
        node = queue.pop()
        if node.type in ('line_comment', 'block_comment') or optional_call_comma(node):
            continue
        if not node.children or node.type in ('string_literal', 'raw_string_literal', 'char_literal'):
            value = node.text.decode()
            tokens.append((node.type, f.normalized_literal(value) if node.type == 'string_literal' else value))
        else:
            queue.extend(reversed(node.children))
    return item.name, tuple(tokens)


def raw_inventory(root):
    found = Counter()
    for path in root.rglob('*.rs'):
        src = path.read_bytes()
        stack = [r.PARSER.parse(src).root_node]
        while stack:
            for item in r.items(src, stack.pop()):
                if item.node.type == 'function_item' and item.test:
                    found[test_key(item)] += 1
                if item.node.type == 'mod_item':
                    body = item.node.child_by_field_name('body')
                    if body is not None:
                        stack.append(body)
    return found

f.test_key = test_key
f.raw_inventory = raw_inventory


def remove_imports(path, declarations):
    src = path.read_bytes()
    edits = [(i.start, i.end, '') for i in f.parse(src)
             if i.node.type == 'use_declaration' and i.node.text.decode() in declarations]
    path.write_bytes(r.rewrite(src, edits))


def repair(work, label):
    src = work / 'crates/node/src'
    if label == 'sync':
        for name in ['branches', 'commit', 'receive']:
            remove_imports(src/'sync'/(name+'.rs'), ['use bitcoin::hashes::Hash;'])
    elif label == 'apply':
        path = src/'apply/consensus_rule_tests.rs'
        text = path.read_text().replace('use fixtures_behavior::p2sh_template_bare_spend_block;',
            '#[cfg(feature = "kernel")]\nuse fixtures_behavior::p2sh_template_bare_spend_block;')
        path.write_text(text)
        f.add_import(src/'apply/consensus_rule_tests/fixtures_validation.rs', 'use bitcoin_rs_chain::NodeId;')
        removals = {
            'apply/connect.rs': ['use super::block_txids;', 'use rayon::prelude::*;', 'use bitcoin_rs_storage::block_body::BlockBodyStore;', 'use bitcoin_rs_consensus::rust_path::UtxoView;'],
            'apply/contextual.rs': ['use bitcoin_rs_primitives::CompactTarget;', 'use rayon::prelude::*;', 'use bitcoin_rs_consensus::rust_path::UtxoView;'],
            'apply/window.rs': ['use bitcoin_rs_consensus::rust_path::UtxoView;'],
            'apply/entrypoints.rs': ['use bitcoin_rs_consensus::rust_path::UtxoView;', 'use bitcoin_rs_primitives::ConsensusEncode;', 'use bitcoin_rs_storage::block_body::BlockBodyStore;', 'use rayon::prelude::*;'],
            'apply/disconnect.rs': ['use rayon::prelude::*;'],
            'apply/publication.rs': ['use rayon::prelude::*;'],
            'apply.rs': ['use bitcoin_rs_chain::ChainWork;', 'use bitcoin_rs_primitives::ConsensusEncode;', 'use rayon::prelude::*;'],
            'apply/consensus_rule_tests.rs': ['use rayon::prelude::*;'],
            'apply/consensus_rule_tests/fixtures_transitions.rs': ['use rayon::prelude::*;'],
            'apply/consensus_rule_tests/fixtures_behavior.rs': ['use rayon::prelude::*;'],
            'apply/consensus_rule_tests/fixtures_validation.rs': ['use rayon::prelude::*;'],
        }
        for relative, declarations in removals.items():
            remove_imports(src/relative, declarations)
        f.add_import(src/'apply.rs', '#[cfg(test)]\nuse rayon::prelude::*;')
    elif label == 'txindex':
        f.add_import(src/'txindex_worker/lifecycle.rs', '#[cfg(test)]\nuse bitcoin_rs_index::{writer::TxIndexWriter, PreparedBatchLimits, IndexCapabilities};\n#[cfg(test)]\nuse super::{Worker, REVISION_QUIET_PERIOD, FORWARD_BATCH_DELAY};')
        f.add_import(src/'txindex_worker/startup.rs', '#[cfg(test)]\nuse super::wait_txindex_open_gate;')
        for name in ['startup','reconciliation','query_transaction','rollback','query_snapshot','query_script','query_protocol','lifecycle','cursor']:
            remove_imports(src/'txindex_worker'/(name+'.rs'), ['use rayon::prelude::*;'])
        remove_imports(src/'txindex_worker.rs', ['use rayon::prelude::*;', 'use bitcoin_rs_index::TxIndexSnapshot;'])
        f.add_import(src/'txindex_worker.rs', '#[cfg(test)]\nuse bitcoin_rs_index::TxIndexSnapshot;')
        for name, declarations in {
            'query_snapshot': ['use bitcoin_rs_storage::block_body::BlockBodyStore;'],
            'rollback': ['use bitcoin_rs_storage::block_body::BlockBodyReader;', 'use bitcoin_rs_storage::block_body::BlockBodyStore;'],
            'catch_up': ['use bitcoin_rs_index::TxIndexSnapshot;', 'use bitcoin_rs_storage::block_body::BlockBodyStore;'],
            'cursor': ['use bitcoin_rs_index::IndexReader;', 'use bitcoin_rs_index::TxIndexSnapshot;', 'use bitcoin_rs_storage::block_body::BlockBodyStore;'],
        }.items():
            remove_imports(src/'txindex_worker'/(name+'.rs'), declarations)
    elif label == 'journal':
        f.add_import(src/'chainstate_journal/writer.rs', '#[cfg(test)]\nuse std::io::Write;')

_base_transform = m.transform

def transform(work, label, relative, stages):
    expected = _base_transform(work, label, relative, stages)
    repair(work, label)
    if label == 'apply':
        gate = work / GATE
        text = gate.read_text()
        old = '("crates/node/src/apply.rs", "handles.mempool_gateway")'
        if text.count(old) != 1:
            raise RuntimeError('The authoritative gateway owner allowlist changed')
        gate.write_text(text.replace(old, '("crates/node/src/apply/connect.rs", "handles.mempool_gateway")'))
        expected.add(gate)
    return expected

m.transform = transform
m.GROUPS = [g for g in m.GROUPS if g[0] not in ('checkpoint','import')]

# Keep the ownership gate pinned to one exact file after moving its owner.
# No new allowed mutation owner or broad module exception is introduced.
module_source = Path(m.__file__).read_text()
functions = {n.name: ast.get_source_segment(module_source, n)
             for n in ast.parse(module_source).body if isinstance(n, ast.FunctionDef)}
validate_source = functions['validate']
validate_source = validate_source.replace("all('0 passed;' in line for line in summary)", "all(re.search(r'\\bok\\. 0 passed;', line) for line in summary)")
validate_source = validate_source.replace("'git', 'add', '--', 'crates/node/src'", "'git', 'add', '--', 'crates/node/src', 'bin/bitcoin-rs/tests/support/ownership_scan.rs'")
for name, source in [('validate', validate_source), ('publish', functions['publish'])]:
    old = "any(not p.startswith('crates/node/src/') for p in paths)"
    new = "any(not (p.startswith('crates/node/src/') or p == 'bin/bitcoin-rs/tests/support/ownership_scan.rs') for p in paths)"
    assert old in source
    exec(compile(source.replace(old, new), '<scoped-ownership-gate>', 'exec'), m.__dict__)

_native_validate = m.validate

def validate(work, artifacts, label, expected, before, filters):
    paths, tests = _native_validate(work, artifacts, label, expected, before, filters)
    if label in ('apply', 'sync', 'txindex', 'reorg'):
        text = m.checked(work, artifacts, label, 'ownership-core-resource-gates', [
            'cargo', '+1.95.0', 'test', '--locked', '-p', 'bitcoin-rs',
            '--no-default-features', '--features', 'fjall,zmq',
            '--test', 'overhaul_ownership', '--test', 'overhaul_core_api',
            '--test', 'overhaul_resource_bounds', '--', '--nocapture',
        ])
        tests += re.findall(r'test result:.*', text)
    return paths, tests

m.validate = validate

if __name__ == '__main__':
    if sys.argv[1:] == ['publish']:
        m.publish()
    else:
        sys.exit(f.main())
