use super::*;

#[test]
fn ordinary_selection_uses_existing_service_contract_for_new_and_tried() {
    // Core ordinary-service policy is separate from FEELER Good and address-DB
    // service policy: NETWORK|WITNESS, or LIMITED|WITNESS below depth144.
    for tried in [false, true] {
        for (services, depth, expected) in [
            (0, 143, false),
            (1, 143, false),
            (8, 143, false),
            (9, u64::MAX, true),
            (1024, 143, false),
            (1032, 143, true),
            (1032, 144, false),
            (1032, u64::MAX, false),
            (1033, u64::MAX, true),
        ] {
            let book = book();
            book.learn_peer(addr(2).ip(), &[(target(), services, EPOCH)], EPOCH);
            if tried {
                book.succeeded(target(), services, EPOCH + 1);
            }
            assert_eq!(
                book.ordinary_services_eligible(target(), depth),
                expected,
                "services={services} depth={depth} tried={tried}"
            );
            assert_eq!(
                book.select(&[], &[], EPOCH + 2, depth, |_| true),
                expected.then_some(target())
            );
            assert_eq!(
                book.state.lock().stored.records[0].tried,
                tried,
                "eligibility never rewrites Core membership"
            );
        }
    }
}

#[test]
fn current_services_are_rechecked_after_unlocked_policy_callback() {
    let book = book();
    book.learn_peer(addr(2).ip(), &[(target(), 9, EPOCH)], EPOCH);
    assert_eq!(
        book.select(&[], &[], EPOCH, u64::MAX, |endpoint| {
            assert!(book.state.try_lock().is_some());
            book.set_services(endpoint, 1);
            true
        }),
        None
    );
    assert_eq!(
        book.select(&[], &[], EPOCH, u64::MAX, |endpoint| {
            book.set_services(endpoint, 9);
            true
        }),
        Some(target())
    );
}

#[test]
fn accepted_version_service_update_is_metadata_only_canonical_and_idempotent() {
    let book = book();
    book.learn_peer(addr(2).ip(), &[(target(), 9, EPOCH)], EPOCH);
    book.attempted(target(), true, EPOCH + 1);
    let (before, revision, last_good) = {
        let manager = book.state.lock();
        (
            manager.stored.records[0].clone(),
            manager.revision,
            manager.last_good,
        )
    };
    let mapped: SocketAddr = "[::ffff:8.8.8.8]:8333".parse().expect("alias");
    book.set_services(mapped, 1);
    assert!(!book.ordinary_services_eligible(mapped, u64::MAX));
    {
        let manager = book.state.lock();
        let after = &manager.stored.records[0];
        assert_eq!(after.services, 1);
        assert_eq!(
            (
                after.last_seen,
                after.last_success,
                after.last_attempt,
                after.last_count_attempt,
                after.failures
            ),
            (
                before.last_seen,
                before.last_success,
                before.last_attempt,
                before.last_count_attempt,
                before.failures
            )
        );
        assert_eq!(
            (&after.source, after.tried, &after.new_buckets),
            (&before.source, before.tried, &before.new_buckets)
        );
        assert_eq!(manager.last_good, last_good);
        assert_eq!(manager.revision, revision + 1);
    }
    book.set_services(target(), 1);
    book.set_services(addr(99), 0);
    assert_eq!(book.state.lock().revision, revision + 1);
    assert_eq!(book.len(), 1);
    assert!(
        book.ordinary_services_eligible(addr(99), u64::MAX),
        "missing metadata is not invented evidence"
    );
}

#[test]
fn only_unproven_dns_zero_flags_keep_native_bootstrap_exception() {
    for source in [
        Source::dns("seed"),
        Source::LegacyDns(77),
        Source::Ip(addr(2).ip()),
    ] {
        let directory = tempfile::tempdir().expect("directory");
        let path = directory.path().join("peers.dat");
        let book = AddressBook::open(Some(path.clone()), [1; 4], false, None);
        book.state
            .lock()
            .learn(target(), 0, source.clone(), EPOCH, EPOCH, 0);
        let dns = matches!(source, Source::Internal(_) | Source::LegacyDns(_));
        assert_eq!(book.ordinary_services_eligible(target(), u64::MAX), dns);
        book.set_services(target(), 0);
        assert_eq!(
            book.ordinary_services_eligible(target(), u64::MAX),
            dns,
            "the existing fields cannot distinguish an ordinary-rejected DNS VERSION0 without Good"
        );
        book.succeeded(target(), 0, EPOCH + 1);
        assert!(
            book.state.lock().stored.records[0].tried,
            "feeler Good is not gated on WITNESS"
        );
        assert!(!book.ordinary_services_eligible(target(), u64::MAX));
        book.learn_dns("fresh-seed", &[target()], EPOCH + 7200);
        assert!(!book.ordinary_services_eligible(target(), u64::MAX));
        book.save();
        let restored = AddressBook::open(Some(path), [1; 4], false, None);
        assert!(!restored.ordinary_services_eligible(target(), u64::MAX));
        assert_eq!(
            restored.select(&[], &[], EPOCH + 7201, u64::MAX, |_| true),
            None
        );
    }
}

#[test]
fn later_gossip_service_upgrade_uses_the_single_current_field() {
    let book = book();
    book.learn_peer(addr(2).ip(), &[(target(), 1, EPOCH)], EPOCH);
    book.succeeded(target(), 1, EPOCH + 1);
    assert!(!book.ordinary_services_eligible(target(), u64::MAX));
    book.learn_peer(addr(3).ip(), &[(target(), 8, EPOCH + 2)], EPOCH + 2);
    assert!(book.ordinary_services_eligible(target(), u64::MAX));
    assert_eq!(
        book.select(&[], &[], EPOCH + 2, u64::MAX, |_| true),
        Some(target())
    );
    book.set_services(target(), 1);
    assert!(!book.ordinary_services_eligible(target(), u64::MAX));
}
