"""Caller migration and removal of the old journal forwarding surface."""
from pathlib import Path
import re
import subprocess
from support import r, BASE, remove_items


def short_paths():
    mappings = {}
    for old, new in [('checkpoint', 'checkpoint'), ('recovery_evidence', 'recovery'), ('chainstate_journal/writer', 'chainstate_journal/writer'), ('chainstate_journal/replay', 'chainstate_journal/replay')]:
        source = subprocess.check_output(['git', 'show', BASE + ':crates/node/src/' + old + '.rs'], text=True)
        original = {r.name_of(source, node) for node, raw in r.items(source) if node.type not in ('use_declaration', 'impl_item', 'mod_item', 'macro_invocation')}
        for path in [r.ROOT / (new + '.rs'), *(r.ROOT / new).glob('*.rs')]:
            if 'tests' in path.stem or path.stem == 'fixtures':
                continue
            text = path.read_text()
            for node, raw in r.items(text):
                name = r.name_of(text, node)
                if node.type in ('use_declaration', 'impl_item', 'mod_item', 'macro_invocation') or name not in original:
                    continue
                target = '::'.join(path.relative_to(r.ROOT).with_suffix('').parts) + '::' + name
                mappings[old.replace('/', '::') + '::' + name] = target
                if '/' in old:
                    mappings[old.split('/')[-1] + '::' + name] = target
    for path in r.ROOT.rglob('*.rs'):
        source = path.read_text()
        text = source
        for old, new in sorted(mappings.items(), key=lambda entry: -len(entry[0])):
            if old != new:
                text = re.sub(r'(?<![\w:])' + re.escape(old) + r'(?!\w)', new, text)
        if text != source:
            path.write_text(text)


def obsolete_api():
    root = r.ROOT
    remove_items(root / 'chainstate_journal/emit.rs', {'flush_through'})
    remove_items(root / 'chainstate_journal/writer.rs', {'state'})
    remove_items(root / 'chainstate_journal/writer/durability.rs', {'flush_to'})
    remove_items(root / 'chainstate_journal/record.rs', {'BlockMeta', 'block_meta'})
    path = root / 'chainstate_journal/record.rs'
    text = path.read_text().replace('BlockMeta, ', '')
    start = text.index('        let meta = sample().block_meta();')
    end = text.index('        Ok(())', start)
    text = text[:start] + '''        let record = sample();
        assert_eq!(record.height, 42);
        assert_eq!(record.block_hash, [9; 32]);
        assert_eq!(record.prev_hash, [8; 32]);
        assert_eq!(record.block_tx_count, 70_000);
        assert_eq!(record.coin_stats_height_delta, -1);
''' + text[end:]
    path.write_text(text)
    for path in (root / 'chainstate_journal/writer').rglob('*.rs'):
        if 'tests' not in str(path):
            continue
        text = path.read_text()
        text = re.sub(r'\b(writer|reopened)\.flush_to\([12]\)', r'\1.advance_durability()', text)
        path.write_text(text.replace('writer.state()', 'writer.state'))


def test_paths():
    for path in (r.ROOT / 'chainstate_journal/replay').rglob('*.rs'):
        text = path.read_text()
        text = text.replace('super::writer::parse_segment_name_pub', 'crate::chainstate_journal::writer::segments::parse_segment_name')
        text = text.replace('super::writer::segment_name_pub', 'crate::chainstate_journal::writer::segments::segment_name')
        text = text.replace('super::record::Coin', 'crate::chainstate_journal::record::Coin')
        path.write_text(text)
    for path in (r.ROOT / 'checkpoint/tests').rglob('*.rs'):
        text = path.read_text().replace('super::super::', 'super::')
        text = text.replace('super::write_checkpoint(', 'crate::checkpoint::publication::write_checkpoint(')
        path.write_text(text)


def after_fix():
    path = r.ROOT / 'checkpoint/publication.rs'
    text = path.read_text()
    if not re.search(r'(?m)^use std::path::(?:Path|\{[^}]*\bPath\b)', text):
        text = text.replace('//! Publication for checkpoint.\n', '')
        path.write_text('#[cfg(test)]\nuse std::path::Path;\n' + text)
