use crate::runtime::DerivedIndexRuntime;

// SNP-08
#[test]
fn only_heights_without_historical_facts_await_them() {
    let (wake_tx, _wake_rx) = crossbeam_channel::bounded(1);
    let runtime = DerivedIndexRuntime::new(wake_tx);
    assert!(!runtime.awaits_historical_facts(0));

    runtime.set_historical_window(200, 50);
    assert!(!runtime.awaits_historical_facts(49));
    assert!(runtime.awaits_historical_facts(50));
    assert!(runtime.awaits_historical_facts(200));
    assert!(!runtime.awaits_historical_facts(201));

    runtime.note_historical_facts(60);
    assert!(!runtime.awaits_historical_facts(60));
    assert!(runtime.awaits_historical_facts(61));

    runtime.note_historical_facts(10);
    assert!(runtime.awaits_historical_facts(61));
}
