use std::time::{Duration, Instant};

use parking_lot::Mutex;

use super::{WarningKind, Warnings, process_start, process_uptime, record_process_start};

/// `MetricsServer::bind` installs a process-global recorder. Serialize every
/// test that publishes or scrapes metrics so another test cannot change the
/// recorder mid-assertion. Production is unchanged.
pub(super) static SERVER_TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn process_start_is_recorded_once_and_uptime_advances() {
    use std::thread;

    record_process_start(Instant::now());
    let first = process_start();
    let before = process_uptime();

    thread::sleep(Duration::from_millis(25));
    // A second record must not move the clock — earliest-wins is what
    // makes the node, rather than the latest caller, own the origin.
    record_process_start(Instant::now());

    assert_eq!(
        process_start(),
        first,
        "a second record_process_start must not move the start instant"
    );
    let Some(before) = before else {
        panic!("uptime must be observable after record_process_start");
    };
    let after = process_uptime().unwrap_or_else(|| panic!("uptime must stay observable"));
    assert!(
        after >= before + Duration::from_millis(20),
        "uptime must advance with elapsed time: {before:?} -> {after:?}"
    );
}

#[test]
fn warnings_keep_first_message_and_report_in_kind_order() {
    let warnings = Warnings::new();
    assert!(warnings.messages().is_empty());

    assert!(warnings.set(WarningKind::ClockOutOfSync, "clock out of sync"));
    // Core ignores a later message for an already-active kind.
    assert!(!warnings.set(WarningKind::ClockOutOfSync, "superseded message"));
    assert!(warnings.set(WarningKind::FatalInternalError, "fatal"));
    assert!(warnings.set(WarningKind::UnknownNewRulesActivated, "unknown rules"));

    assert_eq!(
        warnings.messages(),
        [
            "unknown rules".to_owned(),
            "clock out of sync".to_owned(),
            "fatal".to_owned(),
        ],
        "kernel warnings must sort before node warnings regardless of set order"
    );

    assert!(warnings.unset(WarningKind::ClockOutOfSync));
    assert!(!warnings.unset(WarningKind::ClockOutOfSync));
    assert_eq!(
        warnings.messages(),
        ["unknown rules".to_owned(), "fatal".to_owned()]
    );
}

mod readiness;

mod server;
