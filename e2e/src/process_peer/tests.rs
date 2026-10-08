//! Tests for failure records (REF-07d).
#![expect(
    clippy::expect_used,
    reason = "test fixtures abort on their first unmet setup invariant"
)]

use std::fs::File;
use std::io::{Read as _, Write as _};
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
        pending: super::FrameBuffer::default(),
    };
    (peer, remote, dir)
}

fn assert_failure(dir: &TempDir, first_direction: &str, error: &super::Error) {
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
    assert!(matches!(error, super::Error::Io(_)));
    assert_failure(&dir, "sending", &error);
}

#[test]
fn send_deadline_keeps_the_attempt_and_error() {
    let (mut peer, mut remote, dir) = fixture();
    let error = peer
        .send(NetworkMessage::Ping(1), Instant::now())
        .expect_err("expired time limit");
    assert!(
        matches!(error, super::Error::Protocol(ref message) if message == "P2P operation deadline")
    );
    assert_failure(&dir, "sending", &error);
    remote.set_nonblocking(true).expect("nonblocking reader");
    let mut byte = [0];
    assert_eq!(
        remote
            .read(&mut byte)
            .expect_err("expired send must not write")
            .kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn read_completion_fails_after_the_time_limit() {
    let (mut peer, _remote, _dir) = fixture();
    let result = super::read_frame(
        &mut peer.stream,
        Instant::now(),
        &mut super::FrameBuffer::default(),
    );
    assert!(result.is_err(), "an expired operation must not succeed");
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
    assert!(matches!(error, super::Error::Protocol(_)));
}

#[test]
fn bytes_past_the_deadline_do_not_renew_it() {
    let (mut peer, mut remote, _dir) = fixture();
    remote.write_all(&[7]).expect("one byte before the read");
    // Wait for the byte to reach the socket so the lapsed deadline pauses on
    // real progress instead of timing out on an empty queue.
    peer.stream
        .set_read_timeout(Some(Duration::from_millis(50)))
        .expect("peek timeout");
    let mut one = [0u8; 1];
    let wait_until = Instant::now() + Duration::from_secs(5);
    loop {
        match peer.stream.peek(&mut one) {
            Ok(1) => break,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            result => panic!("the test byte was not delivered cleanly: {result:?}"),
        }
        assert!(Instant::now() < wait_until, "the byte never arrived");
        std::thread::sleep(Duration::from_millis(5));
    }
    let mut pending = super::FrameBuffer::default();
    let error = super::read_frame(&mut peer.stream, Instant::now(), &mut pending)
        .expect_err("lapsed-deadline progress must still interrupt");
    assert!(
        matches!(error, super::Error::Protocol(ref message) if message == "P2P frame paused at the read deadline"),
        "a byte slipping in during the floor must not renew the deadline: {error:?}"
    );
}

#[test]
fn a_paused_frame_resumes_from_where_it_stopped() {
    let (mut peer, mut remote, _dir) = fixture();
    let frame = serialize(&RawNetworkMessage::new(
        Magic::REGTEST,
        NetworkMessage::Ping(1),
    ));
    remote
        .write_all(&frame[..10])
        .expect("partial header bytes");
    // Wait for the partial header to be queued so the first call consumes
    // it before its deadline interrupts.
    peer.stream
        .set_read_timeout(Some(Duration::from_millis(50)))
        .expect("peek timeout");
    let mut ten = [0u8; 10];
    let wait_until = Instant::now() + Duration::from_secs(5);
    loop {
        match peer.stream.peek(&mut ten) {
            Ok(10) => break,
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => panic!("peek failed: {error}"),
        }
        assert!(
            Instant::now() < wait_until,
            "the header bytes never arrived"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let mut pending = super::FrameBuffer::default();
    let error = super::read_frame(
        &mut peer.stream,
        Instant::now() + Duration::from_millis(250),
        &mut pending,
    )
    .expect_err("a partial frame must pause at the deadline");
    assert!(
        !matches!(error, super::Error::Protocol(ref message) if message == "P2P payload byte limit"),
        "a paused frame must not surface as desynced: {error:?}"
    );
    assert_eq!(
        pending.bytes.len(),
        10,
        "the paused call keeps its consumed header bytes"
    );
    remote.write_all(&frame[10..]).expect("remaining bytes");
    let completed = super::read_frame(
        &mut peer.stream,
        Instant::now() + Duration::from_secs(1),
        &mut pending,
    )
    .expect("the paused frame resumes");
    assert_eq!(completed, frame);
}
