#![no_main]

use std::fs::{self, File};
use std::io::Write as _;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr as _;
use std::time::SystemTime;

use bitcoin::hashes::Hash as _;
use bitcoin::hashes::sha256;
use bitcoin_rs_p2p::addrman::AddressBook;
use bitcoin_rs_p2p::subnet::{BannedSubnet, IpSubnet, is_banned};
use bitcoin_rs_primitives::PeerEndpoint;
use libfuzzer_sys::arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;

const MAGIC: [u8; 4] = [1, 2, 3, 4];

struct Record {
    host: [u8; 3],
    port: u16,
    services: u64,
    last_seen: u64,
    last_success: u64,
    failures: u32,
    tried: bool,
    buckets: Vec<u16>,
}

fn sealed(payload: &[u8]) -> Vec<u8> {
    let mut bytes = payload.to_vec();
    bytes.extend_from_slice(sha256::Hash::hash(payload).as_byte_array());
    bytes
}

fn write_book(path: &std::path::Path, payload: &[u8]) {
    if let Ok(mut file) = File::create(path) {
        let _ = file.write_all(&sealed(payload));
        let _ = file.sync_all();
    }
}

fn candidate(record: &Record) -> String {
    let endpoint = PeerEndpoint::new(
        IpAddr::V4(Ipv4Addr::new(
            11,
            record.host[0],
            record.host[1],
            record.host[2],
        )),
        record.port.max(1),
    );
    let buckets: Vec<String> = record.buckets.iter().map(u16::to_string).collect();
    format!(
        "{{\"addr\":\"{}\",\"services\":{},\"source\":{{\"ip\":\"11.0.0.1\"}},\"last_seen\":{},\"last_success\":{},\"failures\":{},\"tried\":{},\"new_buckets\":[{}]}}",
        bitcoin_rs_p2p::format_endpoint(endpoint),
        record.services,
        record.last_seen,
        record.last_success,
        record.failures,
        record.tried,
        buckets.join(",")
    )
}

fn book_skeleton(records: &[Record]) -> Vec<u8> {
    let records: Vec<String> = records.iter().map(candidate).collect();
    format!(
        "{{\"format\":\"bitcoin-rs-addrman\",\"version\":1,\"magic\":[1,2,3,4],\"secret\":[{}],\"records\":[{}],\"asmap_id\":null,\"anchors\":[]}}",
        vec!["0"; 32].join(","),
        records.join(",")
    )
    .into_bytes()
}

fn records_from(u: &mut Unstructured<'_>) -> Vec<Record> {
    let Ok(count) = u.arbitrary::<u8>() else {
        return Vec::new();
    };
    let count = usize::from(count % 6);
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        let host = u.arbitrary::<[u8; 3]>().unwrap_or_default();
        let port = u.arbitrary::<u16>().unwrap_or(1);
        let services = u.arbitrary::<u64>().unwrap_or(0);
        let last_seen = u.arbitrary::<u64>().unwrap_or(0);
        let tried = u.arbitrary::<bool>().unwrap_or(false);
        let last_success = if tried {
            u.arbitrary::<u64>().unwrap_or(1)
        } else {
            0
        };
        let failures = u.arbitrary::<u32>().unwrap_or(0);
        let buckets = if tried {
            Vec::new()
        } else {
            let Ok(first) = u.arbitrary::<u16>() else {
                break;
            };
            let Ok(second) = u.arbitrary::<u16>() else {
                break;
            };
            vec![first % 1024, second % 1024]
        };
        records.push(Record {
            host,
            port,
            services,
            last_seen,
            last_success,
            failures,
            tried,
            buckets,
        });
    }
    records
}

fuzz_target!(|data: &[u8]| {
    let Ok(dir) = tempfile::tempdir() else {
        return;
    };
    let base = dir.path().join("peers.dat");
    let scoped = dir.path().join("peers-01020304.dat");
    let mut u = Unstructured::new(data);
    let mode = u.arbitrary::<u8>().unwrap_or_default() % 4;

    match mode {
        0 => {
            let payload = data.get(1..).unwrap_or_default().to_vec();
            write_book(&scoped, &payload);
            let book = AddressBook::open(Some(base), MAGIC, false, None);
            if let Ok(after) = fs::read(&scoped) {
                assert_eq!(after, sealed(&payload), "loading must not rewrite the address book");
            }
            assert!(
                book.is_empty() || book.is_writable(),
                "a rejected address book must load no records"
            );
        }
        1 => {
            let payload = book_skeleton(&[]);
            write_book(&scoped, &payload);
            let book = AddressBook::open(Some(base), MAGIC, false, None);
            if let Ok(after) = fs::read(&scoped) {
                assert_eq!(after, sealed(&payload), "loading must not rewrite the address book");
            }
            assert!(
                book.is_writable(),
                "an empty well-formed address book must load and stay writable"
            );
            assert!(book.is_empty(), "the empty address book must load no records");
        }
        2 => {
            let records = records_from(&mut u);
            let payload = book_skeleton(&records);
            write_book(&scoped, &payload);
            let book = AddressBook::open(Some(base), MAGIC, false, None);
            if let Ok(after) = fs::read(&scoped) {
                assert_eq!(after, sealed(&payload), "loading must not rewrite the address book");
            }
            if book.is_writable() {
                assert_eq!(
                    book.len(),
                    records.len(),
                    "a loaded book must retain every admissible record"
                );
            }
        }
        _ => {
            let version = 1 + u32::from(u.arbitrary::<u8>().unwrap_or_default() % 9);
            let payload = format!("{{\"version\":{version},\"magic\":[1,2,3,4]}}").into_bytes();
            write_book(&base, &payload);
            let book = AddressBook::open(Some(base.clone()), MAGIC, false, None);
            if let Ok(after) = fs::read(&base) {
                assert_eq!(after, sealed(&payload), "loading must not rewrite the legacy book");
            }
            assert!(
                !scoped.exists(),
                "loading a legacy book must not publish a scoped book"
            );
            assert!(
                book.is_writable(),
                "a matching legacy book keeps discovery writable"
            );
        }
    }

    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(subnet) = IpSubnet::from_str(text) {
            let entry = BannedSubnet {
                subnet,
                banned_until: None,
                ban_created: SystemTime::now(),
                reason: String::new(),
            };
            let _ = is_banned(
                &[entry],
                std::net::Ipv4Addr::LOCALHOST.into(),
                SystemTime::now(),
            );
        }
    }
});
