#![expect(clippy::expect_used, reason = "test fixtures panic on setup failure")]

use super::*;

fn entry(height: u32, hash: &str, offset: u64, len: usize) -> ManifestBlock {
    ManifestBlock {
        height,
        hash: hash.to_owned(),
        offset,
        payload_length: len,
    }
}

#[test]
fn manifest_shape_rejects_gaps() {
    let doc = Manifest {
        network: "mainnet".to_owned(),
        network_magic: "f9beb4d9".to_owned(),
        start_height: 0,
        stop_height: 1,
        archive_sha256: "ab".repeat(32),
        archive_bytes: 200,
        blocks: vec![
            entry(0, &"ab".repeat(32), 0, 90),
            entry(0, &"ab".repeat(32), 98, 90),
        ],
    };
    assert!(check_manifest_shape(&doc).is_err());
}

#[test]
fn manifest_shape_rejects_unpacked_offset() {
    let doc = Manifest {
        network: "mainnet".to_owned(),
        network_magic: "f9beb4d9".to_owned(),
        start_height: 0,
        stop_height: 0,
        archive_sha256: "ab".repeat(32),
        archive_bytes: 98,
        blocks: vec![entry(0, &"ab".repeat(32), 8, 90)],
    };
    assert!(check_manifest_shape(&doc).is_err());
}

#[test]
fn magic_hex_rejects_short_input() {
    assert!(parse_magic_hex("f9be").is_err());
    assert_eq!(
        parse_magic_hex("f9beb4d9").expect("valid magic"),
        [0xf9, 0xbe, 0xb4, 0xd9]
    );
}

#[test]
fn manifest_reader_rejects_non_json() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("manifest.json");
    std::fs::write(&path, b"not json").expect("write");
    assert!(read_manifest(&path).is_err());
}

#[test]
fn corpus_open_rejects_directory() {
    let dir = tempfile::tempdir().expect("tempdir");
    assert!(open_corpus(dir.path()).is_err());
}

#[test]
fn state_writer_refuses_to_clobber() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("state.json");
    let state = CertifiedState {
        height: 1,
        bestblock: "ab".repeat(32),
        txouts: 2,
        total_amount_sat: 5_000_000_000,
        muhash: "cd".repeat(32),
        utxo_hash_serialized_3: "ef".repeat(32),
        bodies_available: true,
        disconnect_ready: true,
    };
    write_state(&path, &state).expect("first write");
    assert!(write_state(&path, &state).is_err());
}

#[test]
fn connect_batch_relieve_journal_retention_pressure() {
    use bitcoin_rs_chain::regtest_fixture;

    let dir = tempfile::tempdir().expect("tempdir");
    let mut config =
        crate::NodeConfig::default_for_network(bitcoin_rs_primitives::Network::Regtest);
    config.data_dir = dir.path().join("backpressure-node");
    config.p2p.listen.clear();
    config.chainstate_journal.max_journal_mib = 1;
    config.chainstate_journal.rotate_mib = 1;

    let genesis = bitcoin_rs_primitives::Network::Regtest.genesis_block();
    let state = crate::state::NodeState::open(config.clone(), None).expect("open node");
    let genesis_tip = state
        .apply_block(&bitcoin_rs_primitives::BlockPayload::from_local(
            genesis.clone(),
        ))
        .expect("genesis");
    state.publish_checkpoint().expect("baseline checkpoint");

    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(
            config
                .data_dir
                .join("chainstate-journal/segment-9999999999.log"),
        )
        .expect("pressure file")
        .set_len(1024 * 1024)
        .expect("pressure size");

    let child =
        regtest_fixture::mined_regtest_child_at(genesis.block_hash(), 1).expect("mine child");
    assert!(
        matches!(
            state.apply_block(&bitcoin_rs_primitives::BlockPayload::from_local(
                child.clone()
            )),
            Err(crate::ConnectMutationError::NotCommitted(
                bitcoin_rs_chainstate::ApplyError::JournalBackpressure(_)
            ))
        ),
        "the fixture must prove retention pressure refuses the child"
    );

    let mut batch = vec![bitcoin_rs_primitives::BlockPayload::from_local(child)];
    connect_batch(&state, &mut batch).expect("relief retries the refused block");
    assert!(
        batch.is_empty(),
        "the batch drains even through the relief path"
    );
    let tip = state
        .chainstate()
        .applied_tip_snapshot()
        .expect("relief must commit the child");
    assert_ne!(
        tip.as_ref(),
        &genesis_tip,
        "the tip must advance past genesis"
    );
    assert_eq!(tip.height, 1, "the retried child commits at height 1");
}

fn corpus_manifest_bytes(network: &str, magic: &str) -> Vec<u8> {
    format!(
        concat!(
            r#"{{"archive":{{"sha256":"{archive}","size":196}},"corpus_id":"C150","entries":"#,
            r#"[{{"height":100,"hash":"{h0}","offset":0,"payload_length":90}},"#,
            r#"{{"height":101,"hash":"{h1}","offset":98,"payload_length":90}}],"#,
            r#""genesis_hash":"{h0}","manifest_sha256":"{msha}","#,
            r#""network":"{network}","network_magic":"{magic}","#,
            r#""range":{{"start_height":100,"stop_height":101}},"#,
            r#""schema":"bitcoin-rs-corpus-manifest","#,
            r#""source_tip_hash":"{h1}","version":1}}"#
        ),
        archive = "ab".repeat(32),
        h0 = "ab".repeat(32),
        h1 = "cd".repeat(32),
        msha = "00".repeat(32),
        network = network,
        magic = magic,
    )
    .into_bytes()
}

#[test]
fn corpus_schema_normalizes_to_internal_manifest() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("manifest.json");
    std::fs::write(&path, corpus_manifest_bytes("regtest", "fabfb5da")).expect("write");
    let doc = read_manifest(&path).expect("corpus manifest parses");
    assert_eq!(doc.network, "regtest");
    assert_eq!(doc.start_height, 100);
    assert_eq!(doc.stop_height, 101);
    assert_eq!(doc.archive_bytes, 196);
    assert_eq!(doc.blocks.len(), 2);
    assert_eq!(doc.blocks[0].height, 100);
    assert_eq!(doc.blocks[1].offset, 98);
    assert!(check_manifest_shape(&doc).is_ok());
}

#[test]
fn manifest_reader_rejects_unknown_schema() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("manifest.json");
    std::fs::write(
            &path,
            br#"{"schema":"unknown-manifest-v9","network":"regtest","network_magic":"fabfb5da","start_height":0,"stop_height":0,"archive_sha256":"ab","archive_bytes":0,"blocks":[]}"#,
        )
        .expect("write");
    assert!(read_manifest(&path).is_err());
}

#[test]
fn manifest_reader_rejects_unsupported_corpus_version() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("manifest.json");
    let mut raw = corpus_manifest_bytes("regtest", "fabfb5da");
    let text = String::from_utf8(raw.clone()).expect("utf8");
    raw = text
        .replace(r#""version":1"#, r#""version":2"#)
        .into_bytes();
    std::fs::write(&path, raw).expect("write");
    assert!(read_manifest(&path).is_err());
}

#[test]
fn manifest_network_matches_configured_identity() {
    let regtest = bitcoin_rs_primitives::Network::Regtest.identity_name();
    assert_eq!(regtest, "regtest");
    let doc = Manifest {
        network: "regtest".to_owned(),
        network_magic: "fabfb5da".to_owned(),
        start_height: 100,
        stop_height: 101,
        archive_sha256: "ab".repeat(32),
        archive_bytes: 196,
        blocks: vec![
            entry(100, &"ab".repeat(32), 0, 90),
            entry(101, &"cd".repeat(32), 98, 90),
        ],
    };
    assert!(check_manifest_network(&doc, regtest).is_ok());
    assert!(check_manifest_network(&doc, "mainnet").is_err());
}

#[test]
fn offline_import_pins_full_validation_mode() {
    use bitcoin_rs_chainstate::ValidationMode;
    for inherited in [
        ValidationMode::Full,
        ValidationMode::AssumeValid,
        ValidationMode::Fast,
    ] {
        assert_eq!(
            resolve_offline_validation_mode(inherited),
            ValidationMode::Full
        );
    }
}

fn binding_entry(height: u32, hash: &str) -> ManifestBlock {
    entry(height, hash, 0, HEADER_LEN)
}

fn header_hash_hex(header: &[u8; HEADER_LEN]) -> String {
    bitcoin_rs_primitives::encode::double_sha256(header).to_string()
}

#[test]
fn connected_records_stay_bound_to_the_manifest() {
    let header = [7u8; HEADER_LEN];
    let doc_hash = header_hash_hex(&header);
    let good = binding_entry(3, &doc_hash);
    let mut payload = header.to_vec();
    check_payload_against_entry(&good, &payload).expect("bound record");
    let upper = binding_entry(3, &doc_hash.to_ascii_uppercase());
    check_payload_against_entry(&upper, &payload).expect("case-insensitive");
    payload[10] ^= 0x01;
    assert!(check_payload_against_entry(&good, &payload).is_err());
    let wrong = binding_entry(3, &"ab".repeat(32));
    assert!(check_payload_against_entry(&wrong, &header).is_err());
    let runt = binding_entry(3, &doc_hash);
    assert!(check_payload_against_entry(&runt, &header[..HEADER_LEN - 1]).is_err());
}

#[test]
fn offline_import_refuses_stale_persisted_index_namespace() {
    let fresh = tempfile::tempdir().expect("tempdir");
    refuse_stale_persisted_indexes(fresh.path()).expect("absent namespace");
    std::fs::create_dir(fresh.path().join("txindex")).expect("empty namespace");
    refuse_stale_persisted_indexes(fresh.path()).expect("empty namespace");
    std::fs::write(fresh.path().join("txindex").join("CURRENT"), b"stale").expect("seed stale row");
    assert!(refuse_stale_persisted_indexes(fresh.path()).is_err());
    let stray = tempfile::tempdir().expect("tempdir");
    std::fs::write(stray.path().join("txindex"), b"stale").expect("seed stray file");
    assert!(refuse_stale_persisted_indexes(stray.path()).is_err());
}

struct TwoBlockArchive {
    blocks: Vec<bitcoin_rs_primitives::Block>,
    corpus: Vec<u8>,
    manifest: Vec<u8>,
    stop_hash: String,
}

fn two_block_archive() -> TwoBlockArchive {
    use sha2::Digest as _;
    let genesis = bitcoin_rs_primitives::Network::Regtest.genesis_block();
    let child = bitcoin_rs_chain::regtest_fixture::mined_regtest_child_at(genesis.block_hash(), 1)
        .expect("mine child");
    let blocks = vec![genesis, child];
    let magic = bitcoin_rs_primitives::Network::Regtest.magic();
    let mut corpus = Vec::new();
    let mut entries = Vec::new();
    let mut offset: u64 = 0;
    for (index, block) in blocks.iter().enumerate() {
        let payload = bitcoin_rs_primitives::BlockPayload::from_local(block.clone());
        let raw = payload.bytes();
        let mut framed = Vec::with_capacity(8 + raw.len());
        framed.extend_from_slice(&magic);
        framed.extend_from_slice(
            &u32::try_from(raw.len())
                .expect("payload fits")
                .to_le_bytes(),
        );
        framed.extend_from_slice(raw);
        entries.push(format!(
            r#"{{"height":{index},"hash":"{hash}","offset":{offset},"payload_length":{len}}}"#,
            index = u32::try_from(index).expect("index fits"),
            hash = block.block_hash(),
            len = raw.len()
        ));
        offset += u64::try_from(framed.len()).expect("offset fits");
        corpus.extend_from_slice(&framed);
    }
    let mut hasher = sha2::Sha256::new();
    hasher.update(&corpus);
    let manifest = format!(
        r#"{{"schema":"core-framed-archive-manifest-v1","network":"regtest","network_magic":"fabfb5da","start_height":0,"stop_height":1,"archive_sha256":"{digest}","archive_bytes":{bytes},"blocks":[{blocks}]}}"#,
        digest = bitcoin_rs_primitives::encode::hex_encode(&hasher.finalize()),
        bytes = corpus.len(),
        blocks = entries.join(",")
    );
    let stop_hash = blocks[1].block_hash().to_string();
    TwoBlockArchive {
        blocks,
        corpus,
        manifest: manifest.into_bytes(),
        stop_hash,
    }
}

fn offline_import_config(data_dir: &std::path::Path) -> crate::NodeConfig {
    let mut config =
        crate::NodeConfig::default_for_network(bitcoin_rs_primitives::Network::Regtest);
    config.data_dir = data_dir.to_path_buf();
    config.p2p.listen.clear();
    config
}

fn write_archive_fixture(
    dir: &std::path::Path,
    archive: &TwoBlockArchive,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let corpus = dir.join("corpus.bin");
    let manifest = dir.join("manifest.json");
    std::fs::write(&corpus, &archive.corpus).expect("write corpus");
    std::fs::write(&manifest, &archive.manifest).expect("write manifest");
    (corpus, manifest)
}

#[test]
fn offline_import_fresh_dir_validates_and_records_provenance() {
    let archive = two_block_archive();
    let dir = tempfile::tempdir().expect("tempdir");
    let data_dir = dir.path().join("node");
    let (corpus, manifest) = write_archive_fixture(dir.path(), &archive);
    let state = dir.path().join("state.json");
    run_offline_import(offline_import_config(&data_dir), &corpus, &manifest, &state)
        .expect("fresh import succeeds");
    let record = read_full_validation_provenance(&data_dir).expect("provenance recorded");
    assert_eq!(record.height, 1, "provenance binds the certified tip");
    assert!(
        record.tip_hash.eq_ignore_ascii_case(&archive.stop_hash),
        "provenance binds the certified tip hash"
    );
    let text = String::from_utf8(std::fs::read(&state).expect("read state")).expect("utf8");
    assert!(text.contains("\"height\": 1"), "state certifies height 1");
    assert!(
        text.contains(&archive.stop_hash),
        "state certifies the archive tip"
    );
}

#[test]
fn offline_import_certified_dir_resumes_idempotently() {
    let archive = two_block_archive();
    let dir = tempfile::tempdir().expect("tempdir");
    let data_dir = dir.path().join("node");
    let (corpus, manifest) = write_archive_fixture(dir.path(), &archive);
    run_offline_import(
        offline_import_config(&data_dir),
        &corpus,
        &manifest,
        &dir.path().join("state.json"),
    )
    .expect("first import succeeds");
    let resume_state = dir.path().join("state-resume.json");
    run_offline_import(
        offline_import_config(&data_dir),
        &corpus,
        &manifest,
        &resume_state,
    )
    .expect("certified directory resumes");
    let text = String::from_utf8(std::fs::read(&resume_state).expect("read state")).expect("utf8");
    assert!(
        text.contains("\"height\": 1"),
        "resume still certifies height 1"
    );
    assert!(
        text.contains(&archive.stop_hash),
        "resume still certifies the archive tip"
    );
}

#[test]
fn offline_import_refuses_tip_without_provenance() {
    let archive = two_block_archive();
    let dir = tempfile::tempdir().expect("tempdir");
    let data_dir = dir.path().join("node");
    {
        let live = crate::state::NodeState::open(offline_import_config(&data_dir), None)
            .expect("open node");
        for block in &archive.blocks {
            live.apply_block(&bitcoin_rs_primitives::BlockPayload::from_local(
                block.clone(),
            ))
            .expect("connect");
        }
    }
    let (corpus, manifest) = write_archive_fixture(dir.path(), &archive);
    let error = run_offline_import(
        offline_import_config(&data_dir),
        &corpus,
        &manifest,
        &dir.path().join("state.json"),
    )
    .expect_err("tip without provenance refuses");
    let message = error.to_string();
    assert!(
        message.contains("provenance") && message.contains("fresh data directory"),
        "refusal must name provenance and the remedy, got: {message}"
    );
}

#[test]
fn network_magic_refuses_non_hex_without_panicking() {
    assert_eq!(
        parse_magic_hex("f9beb4d9").expect("hex"),
        [0xf9, 0xbe, 0xb4, 0xd9]
    );
    assert!(parse_magic_hex("\u{e9}\u{e9}f9be").is_err());
    assert!(parse_magic_hex("+fbeb4d9").is_err());
    assert!(parse_magic_hex("f9beb4d").is_err());
}

#[test]
fn manifest_read_refuses_oversized_input_without_buffering_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("manifest.json");
    std::fs::write(&path, [b' '; 17]).expect("manifest");
    assert_eq!(read_bounded(&path, 17).expect("at bound").len(), 17);
    let error = read_bounded(&path, 16).expect_err("oversized manifest");
    assert!(error.to_string().contains("byte bound"), "{error}");
}
