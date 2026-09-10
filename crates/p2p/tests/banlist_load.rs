//! Ban-list loading must distinguish missing files from corrupt or inaccessible data.
//!
//! Contract: `crates/p2p/README.md#ban-list-persistence-contract` owns the
//! persisted row format and expiry semantics; `CONSTRAINTS.md` `CL-23` requires
//! unavailable data not to be treated as empty.
use std::error::Error;
use std::net::IpAddr;
use std::time::{Duration, UNIX_EPOCH};

use bitcoin_rs_p2p::banlist::BanList;
use bitcoin_rs_p2p::wire::PeerError;

#[test]
fn missing_file_loads_an_empty_list() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("missing.dat");
    let list = BanList::load(&path)?;
    assert!(list.entries.is_empty());
    assert!(!path.exists());
    Ok(())
}

#[test]
fn unrepresentable_expiry_is_an_invalid_entry() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("banlist.dat");
    let row = format!("192.0.2.1\t100\t{}\tinvalid expiry", u64::MAX);
    std::fs::write(&path, format!("{row}\n"))?;
    assert!(matches!(
        BanList::load(&path),
        Err(PeerError::InvalidBanEntry(line)) if line == row
    ));
    assert_eq!(std::fs::read_to_string(&path)?, format!("{row}\n"));
    Ok(())
}

#[test]
fn valid_and_permanent_expiries_keep_their_meaning() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("banlist.dat");
    std::fs::write(
        &path,
        "192.0.2.1\t100\t0\tpermanent\n192.0.2.2\t100\t1\texpired\n",
    )?;
    let list = BanList::load(&path)?;
    let permanent: IpAddr = "192.0.2.1".parse()?;
    let expired: IpAddr = "192.0.2.2".parse()?;
    assert_eq!(list.entries[&permanent].banned_until, None);
    assert_eq!(
        list.entries[&expired].banned_until,
        UNIX_EPOCH.checked_add(Duration::from_secs(1))
    );
    assert!(list.entries[&permanent].is_banned(UNIX_EPOCH));
    assert!(!list.entries[&expired].is_banned(UNIX_EPOCH + Duration::from_secs(1)));
    Ok(())
}

#[cfg(unix)]
#[test]
fn filesystem_errors_are_not_an_empty_ban_list() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("banlist.dat");
    std::os::unix::fs::symlink("banlist.dat", &path)?;
    assert!(matches!(BanList::load(&path), Err(PeerError::Io(_))));
    assert!(std::fs::symlink_metadata(&path)?.file_type().is_symlink());
    Ok(())
}
