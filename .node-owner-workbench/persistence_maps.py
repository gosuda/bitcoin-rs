"""Implemented persistence owners from the previously validated refactor."""
from support import assign

WRITER = assign({}, {
    'head': 'HEAD_MAGIC HEAD_VERSION MAX_HEAD_BYTES HeadMarker read_head_bytes',
    'segments': 'SEGMENT_NAME_MAX SEGMENT_GEN_WIDTH segment_name parse_segment_name scan_fork_cursor ForkCursor',
    'marker': 'FULL_REVALIDATION_MARKER JOURNAL_DIR_NAME clear_full_revalidation_marker_at clear_full_revalidation_marker clear_full_revalidation_marker_with_sync',
    'error': 'JournalWriterError',
    'faults': 'JournalWriterFailpoint',
})
WRITER_METHODS = assign({}, {
    'recovery': 'open initialize restore recover_active_segment',
    'append': 'append next_append_frontier append_record_bytes fail_append',
    'durability': 'advance_durability publish_head_now write_head_atomic flush_to advance_durability_upto try_advance_durability_upto',
    'rewind': 'rewind_to committed_cursor_at truncate_after invalidate_generation',
    'compaction': 'freeze compact_to_checkpoint resume maybe_rotate',
    'faults': 'fail_segment_append fail_segment_sync fail_storage_flush fail_rewind_truncate fail_head_temp_write fail_head_temp_sync fail_head_rename fail_head_dir_sync failpoint inject_failpoint',
    'telemetry': 'record_lag_metrics record_size_metric journal_size_bytes',
})
CHECKPOINT = assign({}, {
    'format': 'CHECKPOINT_ROOT CURRENT_FILE MANIFEST_FILE HEADERS_FILE UTXO_FILE COINSTATS_FILE CURRENT_FORMAT MANIFEST_FORMAT HEADER_CODEC UTXO_CODEC COINSTATS_CODEC CURRENT_VERSION MANIFEST_VERSION UTXO_VERSION COINSTATS_VERSION COINSTATS_MAGIC COINSTATS_PAYLOAD_LEN COINSTATS_ARTIFACT_LEN MAX_CHECKPOINT_PAYLOAD_BYTES MAX_CHECKPOINT_METADATA_BYTES CurrentV1 CheckpointTipV1 HeadersArtifactV1 UtxoArtifactV1 CoinStatsArtifactV1 CheckpointManifestV1 manifest_tip parse_tip network_name hex_encode decode_hex decode_nibble',
    'error': 'CheckpointCorruption CheckpointLoadError CheckpointError classify_checkpoint_error classify_open_error checkpoint_file_error classify_checkpoint_io corrupt_checkpoint is_checkpoint_corruption',
    'load': 'CheckpointLoad RestoredChainstate load_checkpoint_from_dir load_checkpoint read_current read_manifest load_headers load_payloads load_payloads_inner read_checkpoint_snapshot validate_coinstats_manifest open_regular_file verify_artifact decode_coinstats_artifact require_filename',
    'publication': 'CheckpointWrite CHECKPOINT_WRITE_BUFFER_SIZE HashingWriter write_checkpoint_from_dir write_checkpoint checkpoint_best_tip_id write_checkpoint_inner write_checkpoint_with_failpoint',
    'generation': 'GenerationPaths allocate_generation generation_paths generation_name valid_generation_name valid_staging_name valid_current_temp_name cleanup_after_publication',
    'file_io': 'write_file sync_file sync_checkpoint_dir sync_root rename_generation rename_current',
    'faults': 'CheckpointFailpoint inject_next_checkpoint_failpoint test_failpoint injected_io',
})
CHECKPOINT[''] = 'faults'
REPLAY = assign({}, {
    'error': 'JournalReplayError',
    'stream': 'stream_committed_range checked_frame_len stream_segment',
    'validation': 'validate_replayed_head insert_replayed_header apply_record_mutations advance_coin_stats require_live_coin hex block_hash_of',
    'accumulator': 'ReplayAccumulator replay_records',
})
RECOVERY = assign({}, {
    'file_io': 'MAX_FILE_BYTES EvidenceError write_bounded read_bounded read_and_validate sync_dir',
    'witness': 'WITNESS_FILE WITNESS_PREV WITNESS_TMP WITNESS_FORMAT AppliedTipWitness decode_applied_tip_witness write_witness read_witness',
    'marker': 'MARKER_FILE MARKER_PREV MARKER_TMP MARKER_FORMAT RollbackEventKind ChainRollbackEvent write_marker read_marker',
    'warnings': 'WarningSnapshot WarningStore checkpoint_fallback_warning index_ahead_warning',
    'detection': 'detect_checkpoint_fallback',
})
