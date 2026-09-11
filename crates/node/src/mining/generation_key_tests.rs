use super::GenerationKey;
use super::parse_long_poll_id;
use bitcoin_rs_mining::TemplateId;
use bitcoin_rs_primitives::Hash256;

#[test]
fn long_poll_round_trips_template_id() {
    let tip = Hash256::from_le_bytes(&[0x11; 32]);
    let key = GenerationKey {
        tip_hash: tip,
        mempool_sequence: 7,
    };
    let id = key.template_id();
    let Some(parsed) = parse_long_poll_id(id.as_str()) else {
        panic!("generated long-poll id did not parse");
    };
    assert_eq!(parsed, key);
    assert_eq!(TemplateId::new(&tip, 7).as_str(), id.as_str());
}

#[test]
fn hashes_per_second_divides_work_by_elapsed_seconds() {
    let mut work = [0_u8; 32];
    work[31] = 120;
    let rate = super::hashes_per_second(work, 60);
    assert!(
        (rate - 2.0).abs() < f64::EPSILON,
        "120 work over 60s must be 2.0 hashes/s, got {rate}"
    );
    let zero_elapsed = super::hashes_per_second(work, 0);
    assert!(
        zero_elapsed.abs() < f64::EPSILON,
        "zero elapsed must report 0.0 hashes/s, got {zero_elapsed}"
    );
    let negative_elapsed = super::hashes_per_second(work, -1);
    assert!(
        negative_elapsed.abs() < f64::EPSILON,
        "negative elapsed must report 0.0 hashes/s, got {negative_elapsed}"
    );
}
