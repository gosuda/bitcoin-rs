use super::decode_reservation;

#[kani::proof]
fn decode_reservation_covers_the_wire_image() {
    let wire_len: usize = kani::any();
    assert!(decode_reservation(wire_len) >= wire_len);
}

#[kani::proof]
fn decode_reservation_is_monotone() {
    let smaller: usize = kani::any();
    let larger: usize = kani::any();
    kani::assume(smaller <= larger);
    assert!(decode_reservation(smaller) <= decode_reservation(larger));
}
