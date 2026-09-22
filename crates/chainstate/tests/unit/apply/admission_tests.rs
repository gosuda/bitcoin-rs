use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;

use super::ApplyAdmission;
use crate::ApplyError;

#[test]
fn shutdown_closes_admission_and_waits_for_in_flight_apply() {
    let admission = Arc::new(ApplyAdmission::new());
    let Ok(in_flight) = admission.enter() else {
        panic!("initial apply must be admitted");
    };
    let closing = Arc::clone(&admission);
    let (tx, rx) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        let _exclusive = closing.close();
        assert!(tx.send(()).is_ok());
    });

    assert!(rx.recv_timeout(Duration::from_millis(20)).is_err());
    drop(in_flight);
    assert!(rx.recv_timeout(Duration::from_secs(1)).is_ok());
    assert!(thread.join().is_ok());
    assert!(matches!(admission.enter(), Err(ApplyError::Shutdown)));
}
