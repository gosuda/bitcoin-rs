//! Ban-list threshold behavior.
use std::net::{IpAddr, Ipv4Addr};

use bitcoin_rs_p2p::banlist::BanList;

#[test]
fn score_99_is_not_banned_but_100_is_banned() {
    let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let mut banlist = BanList::new("banlist.test");

    banlist.add_score(ip, 99, None, "below threshold");
    assert!(!banlist.is_banned(&ip));

    banlist.add_score(ip, 1, None, "threshold reached");
    assert!(banlist.is_banned(&ip));
}
