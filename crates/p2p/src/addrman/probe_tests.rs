use super::*;

fn challenger() -> SocketAddr {
    "8.8.8.8:412".parse().expect("actual Core collision")
}
fn collision_book() -> Arc<AddressBook> {
    let book = oracle_book();
    {
        let mut manager = book.state.lock();
        assert!(manager.learn(target(), 9, source(1), EPOCH - 1000, EPOCH, 0));
        assert!(manager.good(target(), true, EPOCH - 20_000));
        assert!(manager.learn(challenger(), 9, source(1), EPOCH - 1000, EPOCH, 0));
        assert!(!manager.good(challenger(), true, EPOCH - 2401));
        assert_eq!(manager.tried_slot(target()), 82 * 64 + 29);
        assert_eq!(
            manager.tried_slot(challenger()),
            manager.tried_slot(target())
        );
        assert_eq!(manager.collisions, [challenger()]);
    }
    book
}
fn state(book: &AddressBook, addr: SocketAddr) -> Candidate {
    let manager = book.state.lock();
    manager.stored.records[manager.by_addr[&addr]].clone()
}

#[test]
fn collision_pending_active_policy_and_callback_bounds_recheck_current_state() {
    for protection in 0..4 {
        let book = collision_book();
        book.attempted(target(), false, EPOCH - 61);
        if protection == 0 {
            book.queued(target());
        }
        let active = if protection == 1 {
            vec![target()]
        } else {
            vec![]
        };
        let before = state(&book, challenger());
        let mut calls = 0;
        book.resolve_collisions(&active, EPOCH, |addr| {
            calls += 1;
            assert!(book.state.try_lock().is_some(), "policy executes unlocked");
            if protection == 3 {
                book.queued(target());
            }
            protection != 2 || addr != target()
        });
        assert_eq!(calls, 2, "only challenger and incumbent policy decisions");
        let after = state(&book, challenger());
        assert!(!after.tried);
        assert_eq!(after.last_success, before.last_success);
        assert_eq!(after.last_attempt, before.last_attempt);
    }
}

#[test]
fn make_tried_clears_all_refs_demotes_and_removes_only_colliding_new_reference() {
    for victim_refs in [1, 2] {
        let book = collision_book();
        let victim: SocketAddr = "8.8.9.89:8333".parse().expect("actual Core New collider");
        {
            let mut manager = book.state.lock();
            for n in 2..=8 {
                add_ref(&mut manager, challenger(), &source(n), EPOCH);
            }
            assert_eq!(refs(&manager, challenger()), 8);
            assert!(manager.learn(victim, 9, source(1), EPOCH - 1000, EPOCH, 0));
            if victim_refs == 2 {
                add_ref(&mut manager, victim, &source(2), EPOCH);
            }
            manager.stored.anchors.push(Anchor {
                addr: target(),
                confirmed_at: EPOCH - 10,
            });
        }
        book.attempted(target(), false, EPOCH - 61);
        book.resolve_collisions(&[], EPOCH, |_| true);
        let manager = book.state.lock();
        assert!(manager.stored.records[manager.by_addr[&challenger()]].tried);
        assert_eq!(refs(&manager, challenger()), 0);
        assert_eq!(refs(&manager, target()), 1);
        assert_eq!(refs(&manager, victim), victim_refs - 1);
        assert_eq!(
            manager.stored.anchors[0].addr,
            target(),
            "demotion retains anchor identity"
        );
        assert_indexes(&manager);
    }
}

#[test]
fn pending_final_demotion_victim_defers_all_membership_and_good_health() {
    let book = collision_book();
    let victim: SocketAddr = "8.8.9.89:8333".parse().expect("collider");
    {
        let mut manager = book.state.lock();
        manager.learn(victim, 9, source(1), EPOCH - 1000, EPOCH, 0);
    }
    book.queued(victim);
    book.attempted(target(), false, EPOCH - 61);
    let before = state(&book, challenger());
    let global_good = book.state.lock().last_good;
    book.resolve_collisions(&[], EPOCH, |_| true);
    let after = state(&book, challenger());
    assert_eq!(
        (after.last_success, after.last_attempt, after.failures),
        (before.last_success, before.last_attempt, before.failures)
    );
    assert_eq!(book.state.lock().last_good, global_good);
    assert!(!after.tried);
    assert_indexes(&book.state.lock());
    book.unqueue(victim);
    book.resolve_collisions(&[], EPOCH, |_| true);
    assert!(state(&book, challenger()).tried);
}

#[test]
fn feeler_connected_incumbent_gets_good_but_pending_attempt_does_not() {
    let book = collision_book();
    let mapped: SocketAddr = "[::ffff:8.8.8.8]:8333".parse().expect("alias");
    assert_eq!(
        book.feeler(&[mapped], &[mapped], EPOCH, |_| true),
        Some(challenger())
    );
    assert_eq!(state(&book, target()).last_success, EPOCH);
    book.resolve_collisions(&[], EPOCH + 1, |_| true);
    assert_eq!(book.state.lock().collisions, Vec::<SocketAddr>::new());
    let book = collision_book();
    book.queued(mapped);
    let before = state(&book, target()).last_success;
    assert_eq!(
        book.feeler(&[mapped], &[], EPOCH, |_| true),
        Some(challenger())
    );
    assert_eq!(state(&book, target()).last_success, before);
    assert!(book.queued_feeler(challenger()));
    assert!(!book.queued_feeler(addr(2)));
    assert_eq!(
        book.pending_count_excluding(&[]),
        1,
        "feeler consumes no steady slot"
    );
    assert_eq!(book.feeler(&[], &[], EPOCH, |_| true), None);
}

#[test]
fn connected_collision_good_uses_ip_not_port_but_not_linked_ipv6_group() {
    let book = collision_book();
    let other_port: SocketAddr = "[::ffff:8.8.8.8]:18444".parse().expect("TCP alias");
    book.feeler(&[other_port], &[other_port], EPOCH, |_| true);
    assert_eq!(state(&book, target()).last_success, EPOCH);
    let book = collision_book();
    let linked: SocketAddr = "[2002:808:808::1]:8333".parse().expect("linked IPv6");
    assert_eq!(
        book.feeler(&[linked], &[linked], EPOCH, |_| true),
        Some(target())
    );
    assert_eq!(state(&book, target()).last_success, EPOCH - 20_000);
    let book = collision_book();
    book.feeler(&[other_port], &[], EPOCH, |_| true);
    assert_eq!(state(&book, target()).last_success, EPOCH - 20_000);
}

const V3_ANCHORS: &[u8] = include_bytes!("../../tests/data/addrman-historical-v3-anchors.dat");
const V4_ANCHORS: &[u8] = include_bytes!("../../tests/data/addrman-historical-v4-anchors.dat");
const V6_REFS: &[u8] = include_bytes!("../../tests/data/addrman-core-v6-eight-refs.dat");

#[test]
fn actual_historical_anchor_and_v6_files_migrate_with_exact_backup() {
    for (schema, bytes) in [(3, V3_ANCHORS), (4, V4_ANCHORS), (6, V6_REFS)] {
        let directory = tempfile::tempdir().expect("directory");
        let base = directory.path().join("peers.dat");
        let path = network_path(&base, [1; 4]);
        fs::write(&path, bytes).expect("historic bytes");
        let book = AddressBook::open(Some(base.clone()), [1; 4], false, None);
        {
            let manager = book.state.lock();
            assert!(manager.writable);
            assert_eq!(manager.stored.version, VERSION);
            assert_eq!(manager.collisions, Vec::<SocketAddr>::new());
            if schema == 6 {
                assert_eq!(refs(&manager, target()), 8);
            } else {
                assert_eq!(manager.stored.anchors.len(), 2);
                assert!(
                    manager
                        .stored
                        .anchors
                        .iter()
                        .all(|anchor| anchor.confirmed_at == EPOCH + 6)
                );
            }
            assert_indexes(&manager);
        }
        let backup = path.with_extension(format!(
            "v{schema}-{}.bak",
            Sha256::digest(bytes)[..].to_lower_hex_string()
        ));
        assert_eq!(fs::read(backup).expect("backup"), bytes);
        book.save();
        let restored = AddressBook::open(Some(base), [1; 4], false, None);
        assert_eq!(restored.len(), book.len());
        assert_indexes(&restored.state.lock());
    }
}

#[test]
fn anchors_consume_durably_and_return_original_metadata_only_before_dispatch() {
    let directory = tempfile::tempdir().expect("directory");
    let base = directory.path().join("peers.dat");
    let book = AddressBook::open(Some(base.clone()), [1; 4], false, None);
    book.learn_dns("seed", &[target(), addr(2)], EPOCH);
    book.succeeded(target(), 9, EPOCH);
    book.succeeded(addr(2), 9, EPOCH);
    book.remember_anchors(&[target(), addr(2)], EPOCH);
    book.save();
    let anchors = book.take_restart_anchors(EPOCH + 1);
    assert_eq!(anchors.len(), 2);
    assert_eq!(
        AddressBook::open(Some(base.clone()), [1; 4], false, None)
            .state
            .lock()
            .stored
            .anchors,
        Vec::<Anchor>::new()
    );
    assert!(book.queue_anchor(target()));
    book.defer_anchor(target());
    assert!(book.queue_anchor(target()));
    assert!(book.anchor_dispatched(target()));
    assert!(!book.anchor_dispatched(target()));
    book.return_restart_anchors(EPOCH + 100);
    let restored = AddressBook::open(Some(base), [1; 4], false, None);
    let manager = restored.state.lock();
    assert_eq!(
        manager.stored.anchors,
        [Anchor {
            addr: addr(2),
            confirmed_at: EPOCH
        }]
    );
    assert!(
        !book.anchor_dispatched(addr(2)),
        "a stale channel item cannot consume returned metadata"
    );
}

#[test]
fn failed_anchor_consumption_exposes_no_claims_and_newer_confirmation_wins_return() {
    let directory = tempfile::tempdir().expect("directory");
    let base = directory.path().join("peers.dat");
    let book = AddressBook::open(Some(base.clone()), [1; 4], false, None);
    book.learn_dns("seed", &[target()], EPOCH);
    book.succeeded(target(), 9, EPOCH);
    book.remember_anchors(&[target()], EPOCH);
    book.save();
    let path = network_path(&base, [1; 4]);
    fs::remove_file(&path).expect("file");
    fs::create_dir(&path).expect("failed replace");
    assert_eq!(
        book.take_restart_anchors(EPOCH + 1),
        Vec::<SocketAddr>::new()
    );
    assert!(book.state.lock().pending.is_empty());
    assert_eq!(
        book.state.lock().stored.anchors,
        [Anchor {
            addr: target(),
            confirmed_at: EPOCH
        }]
    );
    fs::remove_dir(&path).expect("repair publication path");
    book.save();
    assert_eq!(
        AddressBook::open(Some(base), [1; 4], false, None)
            .state
            .lock()
            .stored
            .anchors,
        [Anchor {
            addr: target(),
            confirmed_at: EPOCH
        }]
    );
    let book = super::book();
    book.learn_dns("seed", &[target()], EPOCH);
    book.succeeded(target(), 9, EPOCH);
    book.remember_anchors(&[target()], EPOCH);
    assert_eq!(book.take_restart_anchors(EPOCH + 1), [target()]);
    book.remember_anchors(&[target()], EPOCH + 100);
    book.return_restart_anchors(EPOCH + 101);
    assert_eq!(
        book.state.lock().stored.anchors,
        [Anchor {
            addr: target(),
            confirmed_at: EPOCH + 100
        }]
    );
}

fn collision_oracle() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../tests/data/core-addrman-collisions-v31.1.json"
    ))
    .expect("independent Core output")
}
fn manager_from_collision_snapshot(row: &serde_json::Value) -> Manager {
    let mut manager = Manager::new([1; 4], false, None, NetGroups::default());
    manager.stored.secret =
        <[u8; 32]>::from_hex("41f758f2e5cc078d3795b4fc0cb60c2d735fa92cc020572bdc982dd2d564d11b")
            .expect("Core secret");
    for name in ["incumbent", "victim", "challenger", "second_challenger"] {
        let entry = &row[name];
        if entry["present"] != true {
            continue;
        }
        manager.stored.records.push(Candidate {
            creation_id: u64::try_from(manager.stored.records.len()).expect("creation ID"),
            addr: entry["endpoint"]
                .as_str()
                .expect("endpoint")
                .parse()
                .expect("address"),
            services: 9,
            source: Source::Ip(
                entry["primary_source"]
                    .as_str()
                    .expect("source")
                    .parse()
                    .expect("IP"),
            ),
            last_seen: entry["seen"].as_u64().expect("seen"),
            last_success: entry["last_success"].as_u64().expect("success"),
            last_attempt: entry["last_try"].as_u64().expect("try"),
            failures: u32::try_from(entry["attempts"].as_u64().expect("failures")).expect("u32"),
            last_count_attempt: 0,
            tried: entry["tried"].as_bool().expect("membership"),
            new_buckets: entry["new_slots"]
                .as_array()
                .expect("slots")
                .iter()
                .map(|slot| u16::try_from(slot[0].as_u64().expect("bucket")).expect("u16"))
                .collect(),
        });
    }
    manager.install_indexes();
    manager.collisions.push(challenger());
    if row["queue"] == 2 {
        manager.collisions.push(
            row["second_challenger"]["endpoint"]
                .as_str()
                .expect("second")
                .parse()
                .expect("address"),
        );
    }
    manager.last_good = row["last_good"].as_u64().expect("good");
    manager
}
fn assert_collision_snapshot(manager: &Manager, row: &serde_json::Value) {
    assert_eq!(
        u64::try_from(manager.stored.records.len()).expect("bounded count"),
        row["records"],
        "{} records",
        row["case"]
    );
    assert_eq!(
        u64::try_from(manager.collisions.len()).expect("bounded count"),
        row["queue"],
        "{} queue",
        row["case"]
    );
    assert_eq!(
        manager.last_good, row["last_good"],
        "{} global Good",
        row["case"]
    );
    for name in ["incumbent", "victim", "challenger", "second_challenger"] {
        let entry = &row[name];
        if entry.is_null() {
            continue;
        }
        let addr: SocketAddr = entry["endpoint"]
            .as_str()
            .expect("endpoint")
            .parse()
            .expect("address");
        let actual = manager
            .by_addr
            .get(&addr)
            .map(|index| &manager.stored.records[*index]);
        assert_eq!(
            actual.is_some(),
            entry["present"],
            "{} {name} presence",
            row["case"]
        );
        let Some(actual) = actual else { continue };
        assert_eq!(actual.tried, entry["tried"]);
        assert_eq!(
            u64::try_from(actual.new_buckets.len()).expect("bounded count"),
            entry["refs"]
        );
        assert_eq!(actual.last_seen, entry["seen"]);
        assert_eq!(
            actual.last_success, entry["last_success"],
            "{} {name} success",
            row["case"]
        );
        assert_eq!(actual.last_attempt, entry["last_try"]);
        assert_eq!(actual.failures, entry["attempts"]);
        assert_eq!(
            actual.source,
            Source::Ip(
                entry["primary_source"]
                    .as_str()
                    .expect("source")
                    .parse()
                    .expect("IP")
            )
        );
        let mut slots: Vec<_> = actual
            .new_buckets
            .iter()
            .map(|bucket| {
                vec![
                    usize::from(*bucket),
                    manager.new_slot(addr, usize::from(*bucket)) % 64,
                ]
            })
            .collect();
        slots.sort();
        assert_eq!(
            serde_json::to_value(slots).expect("slots"),
            entry["new_slots"]
        );
    }
    assert_indexes(manager);
}

#[test]
fn collision_transitions_match_actual_core_snapshots() {
    let oracle = collision_oracle();
    let rows = oracle["rows"].as_array().expect("rows");
    let mut compared = 0;
    for before in rows {
        let Some(label) = before["case"]
            .as_str()
            .and_then(|name| name.strip_suffix("-before"))
        else {
            continue;
        };
        let Some(after) = rows
            .iter()
            .find(|row| row["case"] == format!("{label}-after"))
        else {
            continue;
        };
        let mut manager = manager_from_collision_snapshot(before);
        let allowed = manager
            .stored
            .records
            .iter()
            .map(|entry| entry.addr)
            .collect();
        manager.resolve_collisions(&HashSet::new(), &allowed, EPOCH);
        assert_collision_snapshot(&manager, after);
        compared += 1;
    }
    assert!(
        compared >= 21,
        "all timing, demotion and defensive-state cases"
    );
}

#[test]
fn collision_queue_counts_challengers_and_caps_ten_even_for_one_incumbent() {
    let oracle = collision_oracle();
    let rows = oracle["rows"].as_array().expect("rows");
    let book = oracle_book();
    let mut manager = book.state.lock();
    manager.learn(target(), 9, source(1), EPOCH - 100_000, EPOCH, 0);
    manager.good(target(), false, EPOCH - 20_000);
    for (index, endpoint) in rows[0]["colliders"]
        .as_array()
        .expect("colliders")
        .iter()
        .take(11)
        .enumerate()
    {
        let addr: SocketAddr = endpoint
            .as_str()
            .expect("endpoint")
            .parse()
            .expect("address");
        assert!(manager.learn(
            addr,
            9,
            source(u8::try_from(index + 2).expect("source")),
            EPOCH - 100_000,
            EPOCH,
            0
        ));
        assert!(!manager.good(addr, true, EPOCH - 30));
        let expected = rows
            .iter()
            .find(|row| row["case"] == format!("queue-add-{}", index + 1))
            .expect("Core row");
        assert_eq!(
            u64::try_from(manager.collisions.len()).expect("bounded count"),
            expected["queue"]
        );
        assert_eq!(
            u64::try_from(manager.stored.records.len()).expect("bounded count"),
            expected["records"]
        );
        assert_eq!(manager.last_good, expected["last_good"]);
        assert_indexes(&manager);
    }
    manager.good(challenger(), true, EPOCH);
    assert_eq!(manager.collisions.len(), 10);
    assert_eq!(
        manager.stored.records[manager.by_addr[&challenger()]].last_success,
        EPOCH
    );
}

#[test]
fn connected_collision_good_and_new_selection_match_actual_core() {
    let oracle = collision_oracle();
    let rows = oracle["rows"].as_array().expect("rows");
    let expected_good = rows
        .iter()
        .find(|row| row["case"] == "already-connected-after-good")
        .expect("Core Good");
    let expected_resolved = rows
        .iter()
        .find(|row| row["case"] == "already-connected-after-resolve")
        .expect("Core Resolve");
    let mut manager = manager_from_collision_snapshot(expected_good);
    let old = manager.by_addr[&target()];
    manager.stored.records[old].last_success = EPOCH - 20_000;
    manager.stored.records[old].last_attempt = EPOCH - 1234;
    manager.last_good = EPOCH - 30;
    let book = AddressBook {
        state: Mutex::new(manager),
        publication: Mutex::new(()),
    };
    assert_eq!(
        book.feeler(&[target()], &[target()], EPOCH, |_| true),
        Some(challenger())
    );
    assert_collision_snapshot(&book.state.lock(), expected_good);
    book.resolve_collisions(&[], EPOCH, |_| true);
    assert_collision_snapshot(&book.state.lock(), expected_resolved);
}

#[test]
fn successful_connected_challenger_can_promote_without_losing_pending_identity() {
    let book = collision_book();
    book.queued(challenger());
    book.attempted(target(), false, EPOCH - 61);
    book.resolve_collisions(&[challenger()], EPOCH, |_| true);
    assert!(state(&book, challenger()).tried);
    assert!(book.is_pending(challenger()));
    assert_indexes(&book.state.lock());
}

#[test]
fn historical_anchor_migration_obeys_configured_map_and_unknown_shape_barriers() {
    for bytes in [V3_ANCHORS, V4_ANCHORS] {
        let directory = tempfile::tempdir().expect("directory");
        let base = directory.path().join("peers.dat");
        let path = network_path(&base, [1; 4]);
        let map = directory.path().join("map.raw");
        fs::write(&path, bytes).expect("old bytes");
        fs::write(&map, b"invalid map").expect("invalid map");
        let invalid = AddressBook::open(Some(base.clone()), [1; 4], false, Some(&map));
        assert!(!invalid.state.lock().writable);
        assert_eq!(
            invalid.take_restart_anchors(EPOCH + 10),
            Vec::<SocketAddr>::new()
        );
        assert_eq!(invalid.state.lock().stored.anchors.len(), 2);
        invalid.save();
        assert_eq!(fs::read(&path).expect("preserved"), bytes);
        assert_eq!(
            fs::read_dir(directory.path()).expect("directory").count(),
            2,
            "invalid map creates no migration backup"
        );
        fs::write(
            &map,
            include_bytes!("../../tests/data/asmap-linked-ipv4-core-v31.1.raw"),
        )
        .expect("restore map");
        let restored = AddressBook::open(Some(base.clone()), [1; 4], false, Some(&map));
        assert!(restored.state.lock().writable);
        assert_eq!(restored.state.lock().stored.anchors.len(), 2);
        assert_indexes(&restored.state.lock());
        restored.save();
        let prefix = AddressBook::open(Some(base.clone()), [1; 4], false, None);
        assert!(prefix.state.lock().writable);
        assert_eq!(prefix.state.lock().stored.anchors.len(), 2);
        assert_indexes(&prefix.state.lock());
        prefix.save();
        let current = fs::read(&path).expect("current");
        let mut value: serde_json::Value =
            serde_json::from_slice(&current[..current.len() - 32]).expect("JSON");
        value["anchors"] = serde_json::json!([{"addr":"9.9.9.9:8333","confirmed_at":EPOCH}]);
        let malformed = fixture_bytes(&value);
        fs::write(&path, &malformed).expect("orphan anchor");
        let rejected = AddressBook::open(Some(base), [1; 4], false, None);
        assert!(!rejected.state.lock().writable);
        rejected.save();
        assert_eq!(fs::read(path).expect("rejected preserved"), malformed);
    }
}

#[test]
fn anchor_reservation_precedes_publication_and_failed_commit_rolls_it_back() {
    let directory = tempfile::tempdir().expect("directory");
    let base = directory.path().join("peers.dat");
    let book = AddressBook::open(Some(base), [1; 4], false, None);
    book.learn_dns("seed", &[target()], EPOCH);
    book.succeeded(target(), 9, EPOCH);
    book.remember_anchors(&[target()], EPOCH);
    book.save();
    let publication = book.publication.lock();
    let taker = Arc::clone(&book);
    let worker = std::thread::spawn(move || taker.take_restart_anchors(EPOCH + 1));
    let deadline = Instant::now() + Duration::from_secs(5);
    while !book.is_pending(target()) {
        assert!(Instant::now() < deadline, "take reached pending transfer");
        std::thread::yield_now();
    }
    assert!(!book.queued_feeler(target()));
    book.queued(target());
    assert!(matches!(
        book.state.lock().pending.get(&target()),
        Some(PendingClaim::AnchorReservation(_))
    ));
    drop(publication);
    assert_eq!(worker.join().expect("take"), [target()]);
    book.return_restart_anchors(EPOCH + 2);
    assert_eq!(
        book.state.lock().stored.anchors,
        [Anchor {
            addr: target(),
            confirmed_at: EPOCH
        }]
    );
    book.queued(target());
    assert_eq!(
        book.take_restart_anchors(EPOCH + 3),
        Vec::<SocketAddr>::new()
    );
    assert_eq!(
        book.state.lock().stored.anchors,
        [Anchor {
            addr: target(),
            confirmed_at: EPOCH
        }],
        "preexisting dial cannot consume an unused anchor"
    );
}

#[test]
fn collision_resolution_uses_creation_order_not_reversed_good_order() {
    let book = oracle_book();
    let second: SocketAddr = "8.8.8.8:1343".parse().expect("second actual Core collider");
    let mut manager = book.state.lock();
    manager.learn(target(), 9, source(1), EPOCH - 1000, EPOCH, 0);
    manager.good(target(), true, EPOCH - 20_000);
    manager.learn(challenger(), 9, source(2), EPOCH - 1000, EPOCH, 0);
    manager.learn(second, 9, source(3), EPOCH - 1000, EPOCH, 0);
    manager.good(second, true, EPOCH - 30);
    manager.good(challenger(), true, EPOCH - 30);
    assert_eq!(manager.collisions, [challenger(), second]);
    let old = manager.by_addr[&target()];
    manager.stored.records[old].last_attempt = EPOCH - 61;
    let allowed = manager
        .stored
        .records
        .iter()
        .map(|entry| entry.addr)
        .collect();
    manager.resolve_collisions(&HashSet::new(), &allowed, EPOCH);
    assert!(manager.stored.records[manager.by_addr[&challenger()]].tried);
    assert!(!manager.stored.records[manager.by_addr[&second]].tried);
    assert_eq!(manager.collisions, Vec::<SocketAddr>::new());
    assert_indexes(&manager);
    assert!(
        !serde_json::to_string(&manager.stored)
            .expect("stored")
            .contains("creation_id")
    );
}

#[test]
fn feelers_use_advertised_address_database_services_without_inventing_dns_bits() {
    let book = book();
    book.learn_dns("seed", &[target()], EPOCH);
    assert_eq!(book.feeler(&[], &[], EPOCH, |_| true), None);
    assert_eq!(book.select(&[], &[], EPOCH, |_| true), Some(target()));
    book.learn_peer(addr(2).ip(), &[(target(), 1, EPOCH)], EPOCH);
    assert_eq!(book.feeler(&[], &[], EPOCH, |_| true), Some(target()));
    book.state.lock().stored.records[0].services = 1024;
    assert_eq!(book.feeler(&[], &[], EPOCH, |_| true), Some(target()));
    book.state.lock().stored.records[0].services = 8;
    assert_eq!(book.feeler(&[], &[], EPOCH, |_| true), None);
}

#[test]
fn regular_queue_admission_never_takes_probe_or_anchor_claims() {
    let book = book();
    let alias: SocketAddr = "[::ffff:8.8.8.8]:8333".parse().expect("alias");
    assert!(book.queued_feeler(target()));
    assert!(!book.queued(alias));
    assert!(book.is_feeler(target()));
    book.unqueue(alias);
    book.learn_dns("seed", &[target()], EPOCH);
    book.succeeded(target(), 9, EPOCH);
    book.remember_anchors(&[target()], EPOCH);
    assert_eq!(book.take_restart_anchors(EPOCH + 1), [target()]);
    assert!(!book.queued(alias));
    assert!(book.queue_anchor(alias));
    assert!(!book.queued(target()));
    assert!(book.anchor_dispatched(alias));
    assert!(
        book.queued(target()),
        "the same ordinary Dial purpose is compatible"
    );
    assert!(book.is_pending(alias));
}

#[test]
fn returned_anchor_releases_same_as_group_and_rejection_preserves_other_purposes() {
    let directory = tempfile::tempdir().expect("directory");
    let map = directory.path().join("asmap.raw");
    fs::write(
        &map,
        include_bytes!("../../tests/data/asmap-source-quota-core-v31.1.raw"),
    )
    .expect("Core map");
    let book = AddressBook::open(None, [1; 4], false, Some(&map));
    book.state.lock().stored.secret = [1; 32];
    let anchor: SocketAddr = "8.8.0.1:8333".parse().expect("anchor");
    let other: SocketAddr = "9.9.0.1:8333".parse().expect("same Core ASN");
    book.learn_dns("seed", &[anchor, other], EPOCH);
    assert_eq!(book.len(), 2);
    book.succeeded(anchor, 9, EPOCH);
    book.remember_anchors(&[anchor], EPOCH);
    assert_eq!(book.take_restart_anchors(EPOCH + 1), [anchor]);
    book.reject_queued(anchor, false);
    assert!(book.is_pending(anchor));
    assert_eq!(book.select(&[], &[], EPOCH + 2, |addr| addr == other), None);
    book.return_restart_anchor(anchor, EPOCH + 2);
    assert!(!book.is_pending(anchor));
    assert_eq!(
        book.select(&[], &[], EPOCH + 2, |addr| addr == other),
        Some(other)
    );
    assert_eq!(
        book.state.lock().stored.anchors,
        [Anchor {
            addr: anchor,
            confirmed_at: EPOCH
        }]
    );
    assert!(book.queued_feeler(other));
    book.reject_queued(other, false);
    assert!(book.is_feeler(other));
    book.reject_queued(other, true);
    assert!(!book.is_pending(other));
}
