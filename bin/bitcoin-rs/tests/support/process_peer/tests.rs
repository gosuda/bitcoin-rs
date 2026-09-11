//! Tests for failure records (REF-07d).

use std::fs::File;
use std::io::Write as _;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use bitcoin::consensus::serialize;
use bitcoin::p2p::Magic;
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use serde_json::Value;
use tempfile::TempDir;

use super::ProcessPeer;

fn fixture() -> (ProcessPeer, TcpStream, TempDir) {
    let dir = tempfile::tempdir().expect("record directory");
    let listener = TcpListener::bind("127.0.0.1:0").expect("local listener");
    let stream = TcpStream::connect_timeout(
        &listener.local_addr().expect("listener address"),
        Duration::from_secs(1),
    )
    .expect("local connection");
    let (remote, _) = listener.accept().expect("connected peer");
    remote
        .set_write_timeout(Some(Duration::from_secs(1)))
        .expect("write time limit");
    let peer = ProcessPeer {
        stream,
        journal: File::create(dir.path().join("p2p.jsonl")).expect("record file"),
        journal_bytes: 0,
        started: Instant::now(),
    };
    (peer, remote, dir)
}

fn assert_failure(dir: &TempDir, first_direction: &str, error: &super::HarnessError) {
    let records: Vec<Value> = std::fs::read_to_string(dir.path().join("p2p.jsonl"))
        .expect("record text")
        .lines()
        .map(|line| serde_json::from_str(line).expect("record JSON"))
        .collect();
    assert_eq!(
        records.first().expect("first record")["direction"],
        first_direction
    );
    let last = records.last().expect("last record");
    assert_eq!(last["direction"], "failure");
    assert_eq!(last["error"], error.to_string());
}

#[test]
fn checksum_failure_keeps_the_frame_and_error() {
    let (mut peer, mut remote, dir) = fixture();
    let mut frame = serialize(&RawNetworkMessage::new(
        Magic::REGTEST,
        NetworkMessage::Ping(1),
    ));
    frame[20] ^= 1;
    remote.write_all(&frame).expect("send incorrect checksum");
    let error = peer
        .receive(Instant::now() + Duration::from_secs(1))
        .expect_err("checksum failure");
    assert_failure(&dir, "received", &error);
}

#[test]
fn write_failure_keeps_the_attempt_and_error() {
    let (mut peer, _remote, dir) = fixture();
    peer.stream
        .shutdown(Shutdown::Write)
        .expect("close the writer");
    let error = peer
        .send(
            NetworkMessage::Ping(1),
            Instant::now() + Duration::from_secs(1),
        )
        .expect_err("write failure");
    assert!(matches!(error, super::HarnessError::Io(_)));
    assert_failure(&dir, "sending", &error);
}

#[test]
fn record_write_failure_does_not_replace_the_network_error() {
    let (mut peer, remote, dir) = fixture();
    remote
        .shutdown(Shutdown::Write)
        .expect("close the remote writer");
    peer.journal = File::open(dir.path().join("p2p.jsonl")).expect("read-only record file");
    let error = peer
        .receive(Instant::now() + Duration::from_secs(1))
        .expect_err("closed reader");
    assert!(matches!(error, super::HarnessError::Protocol(_)));
}

#[test]
fn read_completion_fails_after_the_time_limit() {
    let (mut peer, _remote, _dir) = fixture();
    let result = super::read_exact(&mut peer.stream, &mut [], Instant::now());
    assert!(result.is_err(), "an expired operation must not succeed");
}

#[test]
fn send_deadline_keeps_the_attempt_and_error() {
    let (mut peer, _remote, dir) = fixture();
    let error = peer
        .send(NetworkMessage::Ping(1), Instant::now())
        .expect_err("expired time limit");
    assert_failure(&dir, "sending", &error);
}
