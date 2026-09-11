"""Chainstate mutation and reorganization: no apply compatibility facade."""
from pathlib import Path
import re
from support import r, assign, dedup_imports, migration


def run():
    r.phase_chainstate()
    groups = assign({}, {
        'error': 'ReorgError',
        'bodies': 'LoadedBranchBody LoadedBranchPrefix load_branch_bodies load_available_branch_prefix branch_nodes load_branch_body decode_branch_body validate_branch_body',
        'execution': 'settle_disconnect_debt settle_reorg_transition DISCONNECT_STREAM_WINDOW LoadedPlanProgress preflight_disconnect_bodies applied_tip_height execute_streamed_plan reconsider_disconnected_transactions current_reorg_plan',
    })
    source = r.split_owner('reorg', 'reorg', groups)
    path = r.ROOT / 'reorg/tests.rs'
    body = path.read_text().replace('use super::*;', '').replace('super::', 'crate::reorg::')
    imports = r.canonical_imports(source, 'reorg', {'tests'})
    r.write(path, dedup_imports(imports + '\nuse super::*;\nuse super::bodies::*;\nuse super::execution::*;\nuse super::error::*;\n' + body))
    r.migrate_paths()
    owner = 'chainstate/consensus_rule_tests'
    groups = assign({}, {
        'undo': 'RejectingUndoStore CompleteRejectingUndoStore FailingUndoPersist',
        'publishers': 'FailAfterStartupTxIndex RecordingSequencePublisher BlockingBodyStore AppliedTipVisiblePublisher TransitionHeldPublisher RecordingRawTxPublisher RecordingRawBlockPublisher PanickingOptOutPublisher PanickingNoRawblockPublisher RecordingGenerationControl generation_unavailable zmq_followers',
        'blocks': 'BIP68_TEST_PREVOUT_HEIGHT BIP68_TEST_PREVOUT_MTP MAINNET_POW_LIMIT_BITS MAINNET_POW_LIMIT_DIV_4_BITS DAA_ANCHOR_TIME transaction coinbase_transaction coinbase_transaction_with_height block_with_transaction block_with_transactions block_with_prev_hash_and_transactions next_fixture_time mined_block_with_prev_hash_and_transactions block_with_pow_header pow_header seed_pow_chain seed_pow_period_with_tip_bits seed_pow_chain_with_headers seed_known_bip34_activation_chain interpolated_time fixture_txid op_return_script txids_merkle_root target_to_compact_lossy scaled_pow_limit_bits pow_limit_bits retarget_bits_for_test assert_nbits_error',
        'spends': 'utxo_with_output utxo_with_outputs_at_height spending_transaction spending_transaction_with_version spending_transaction_to_script op_true_script softfork_state seed_block_tree_for_bip68_time seed_block_tree_for_bip68_time_at_height seed_block_tree_with_times assert_bip_error assert_bip_error_reason_contains duplicate_spend_block bad_script_spend_block p2sh_template_bare_spend_block excess_value_spend_block',
        'reorg_fixture': 'MapBodyStore ReorgBodyLoadingFixture reorg_body_loading_fixture assert_reorg_load_failure_preserved_state',
    })
    r.split_owner(owner, owner, groups)
    path = r.ROOT / (owner + '.rs')
    text = path.read_text()
    for group in sorted(set(groups.values())):
        text += '\nuse ' + group + '::*;\n'
    r.write(path, text)
    r.migrate_paths()
    root = r.ROOT / 'chainstate.rs'
    text = root.read_text()
    declarations = []
    for match in list(re.finditer(r'#\[cfg\(test\)\]\s*mod (\w+tests);', text)):
        name = match.group(1)
        declarations.append('mod ' + name + ';')
        source_path = r.ROOT / 'chainstate' / (name + '.rs')
        target_path = r.ROOT / 'chainstate/tests' / (name + '.rs')
        target_path.parent.mkdir(parents=True, exist_ok=True)
        if source_path.with_suffix('').exists():
            source_path.with_suffix('').rename(target_path.with_suffix(''))
        source_path.rename(target_path)
        for file in [target_path, *target_path.with_suffix('').rglob('*.rs')]:
            body = file.read_text()
            if file == target_path:
                body = re.sub(r'\bsuper::', 'super::super::', body)
            body = body.replace('crate::chainstate::' + name + '::', 'crate::chainstate::tests::' + name + '::')
            file.write_text(body)
    text = re.sub(r'#\[cfg\(test\)\]\s*mod (\w+tests);', '', text)
    root.write_text(text + '\n#[cfg(test)]\nmod tests;\n')
    r.write(r.ROOT / 'chainstate/tests.rs', '//! Chainstate invariants and shared test fixtures.\n\n' + '\n'.join(declarations))
    for file in (r.ROOT / 'chainstate/tests').rglob('*.rs'):
        body = file.read_text().replace('crate::chainstate::consensus_rule_tests', 'crate::chainstate::tests::consensus_rule_tests')
        body = body.replace('crate::chainstate::consensus_bytes', 'bitcoin_rs_primitives::consensus_bytes')
        file.write_text(body)
    for name in ['blocks', 'spends', 'undo', 'publishers', 'reorg_fixture']:
        file = r.ROOT / ('chainstate/tests/consensus_rule_tests/' + name + '.rs')
        file.write_text(file.read_text().replace('pub(super)', 'pub(in crate::chainstate::tests)'))
    path = Path('bin/bitcoin-rs/tests/support/ownership_scan.rs')
    path.write_text(path.read_text().replace('crates/node/src/apply.rs', 'crates/node/src/chainstate/connect.rs'))
    for path in Path('docs').rglob('*.md'):
        text = path.read_text()
        replacement = text.replace('crates/node/src/apply.rs', 'crates/node/src/chainstate.rs').replace('node/src/apply.rs', 'node/src/chainstate.rs')
        if text != replacement:
            path.write_text(replacement)
    migration('''## Chainstate and reorganization

`apply` and its crate-root re-exports are removed. Import `Chainstate`,
`ChainTransition`, `ChainstateSnapshot`, `ConnectOutcome`, and `DisconnectOutcome`
from `bitcoin_rs_node::chainstate`. Errors belong to `chainstate::error`, the
assume-valid gate to `chainstate::assume_valid`, and window types to
`chainstate::window`. Undo types come directly from `bitcoin_rs_storage`.
`ReorgError` belongs to `reorg::error`.

Admission, connect, disconnect, window settlement, publication, header context,
prevouts, transaction planning, and contextual rules have distinct implementations
around one mutation handle. Reorganization separates branch-body loading from
transition execution. The old source files and public forwarding exports are
removed, and callers and ownership-gate paths migrate with the implementation.
''', first=True)


def after_fix():
    path = r.ROOT / 'chainstate/assume_valid.rs'
    text = path.read_text()
    if 'use arc_swap::ArcSwap;' not in text:
        text = text.replace('//! Assume valid for chainstate.\n', '')
        path.write_text('#[cfg(test)]\nuse arc_swap::ArcSwap;\n' + text)
