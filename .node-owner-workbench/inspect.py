import json
from pathlib import Path
from tree_sitter import Language, Parser
import tree_sitter_rust

parser = Parser(Language(tree_sitter_rust.language()))
paths = ['apply.rs', 'sync.rs', 'txindex_worker.rs', 'chainstate_journal/writer.rs', 'mining.rs', 'checkpoint.rs', 'recovery_evidence.rs', 'storage_footprint.rs', 'reorg.rs', 'chainstate_journal/replay.rs']
for path in paths:
    source = Path('crates/node/src', path).read_bytes()
    root = parser.parse(source).root_node
    assert not root.has_error, path
    print('\nOWNER ' + path)
    for item in root.named_children:
        if item.type in ('use_declaration', 'line_comment', 'block_comment', 'attribute_item', 'inner_attribute_item'):
            continue
        name = item.child_by_field_name('name') or item.child_by_field_name('type')
        label = source[name.start_byte:name.end_byte].decode() if name else item.type
        print(item.start_point.row + 1, item.end_point.row + 1, item.type, label)
        if item.type == 'impl_item':
            body = item.child_by_field_name('body')
            for method in body.named_children:
                name = method.child_by_field_name('name')
                if name:
                    print('  METHOD', method.start_point.row + 1, method.end_point.row + 1, source[name.start_byte:name.end_byte].decode())
