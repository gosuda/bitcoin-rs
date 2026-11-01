#![no_main]

use std::fs::{self, File};
use std::io::Write as _;
use std::str::FromStr as _;
use std::time::SystemTime;

use bitcoin_rs_p2p::addrman::AddressBook;
use bitcoin_rs_p2p::subnet::{BannedSubnet, IpSubnet, is_banned};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(dir) = tempfile::tempdir() else {
        return;
    };
    let magic = [1, 2, 3, 4];
    let base = dir.path().join("peers.dat");
    let scoped = dir.path().join("peers-01020304.dat");

    if let Ok(mut file) = File::create(&scoped) {
        let _ = file.write_all(data);
        let _ = file.sync_all();
    }

    let original = data.to_vec();
    let book = AddressBook::open(Some(base), magic, false, None);

    if !book.is_writable() {
        if let Ok(after) = fs::read(&scoped) {
            assert_eq!(after, original);
        }
    }

    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(subnet) = IpSubnet::from_str(s) {
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
