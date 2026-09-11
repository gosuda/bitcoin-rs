"""Retain imports used only by existing chainstate tests."""
import re
from support import r


def after_fix():
    required = {
        'chainstate/preparation.rs': ['bitcoin_rs_primitives::Tx', 'rayon::prelude::*'],
        'chainstate/rules.rs': ['super::transactions::plan_block_transactions'],
    }
    for name, imports in required.items():
        path = r.ROOT / name
        text = path.read_text()
        additions = []
        for dependency in imports:
            statement = 'use ' + dependency + ';'
            if statement not in text:
                additions.append('#[cfg(test)]\n' + statement)
        if additions:
            first = next((node.start_byte for node in r.parse(text).named_children if node.type not in ('line_comment', 'block_comment', 'inner_attribute_item')), 0)
            data = text.encode()
            text = (data[:first] + ('\n'.join(additions) + '\n').encode() + data[first:]).decode()
            path.write_text(text)

    # Express the newly merged index identity check as tuple equality. All six
    # field comparisons are retained; this resolves the baseline Clippy warning
    # without changing reconciliation decisions.
    path = r.ROOT.parent.parent / 'index/src/reconcile.rs'
    text = path.read_text()
    old = '''let identity_matches_cursor = cursor.epoch == identity.epoch
        && cursor.sequence == identity.sequence
        && cursor.hash == identity.tip_hash
        && cursor.height == identity.tip_height;'''
    new = '''let identity_matches_cursor =
        (cursor.epoch, cursor.sequence, cursor.hash, cursor.height)
            == (identity.epoch, identity.sequence, identity.tip_hash, identity.tip_height);'''
    changed = text.replace(old, new)
    changed = re.sub(r'let identity_matches_target = identity\.tip_hash == target\.hash\s*&& identity\.tip_height == target\.height;', 'let identity_matches_target = (identity.tip_hash, identity.tip_height) == (target.hash, target.height);', changed)
    if changed != text:
        path.write_text(changed)
