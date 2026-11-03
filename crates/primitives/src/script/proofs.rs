use super::Witness;

const MAX_ITEMS: usize = 4;
const MAX_ITEM_LEN: usize = 4;

#[kani::proof]
#[kani::unwind(5)]
#[kani::solver(minisat)]
fn witness_push_then_get_returns_the_pushed_items_in_order() {
    let count: usize = kani::any();
    kani::assume(count <= MAX_ITEMS);
    let mut witness = Witness::new();
    let mut items = [[0_u8; MAX_ITEM_LEN]; MAX_ITEMS];
    let mut lengths = [0_usize; MAX_ITEMS];
    for index in 0..count {
        let length: usize = kani::any();
        kani::assume(length <= MAX_ITEM_LEN);
        let item: [u8; MAX_ITEM_LEN] = kani::any();
        witness.push(&item[..length]);
        items[index] = item;
        lengths[index] = length;
    }
    assert_eq!(witness.len(), count);
    assert_eq!(witness.is_empty(), count == 0);
    for index in 0..count {
        assert_eq!(witness.get(index), Some(&items[index][..lengths[index]]));
    }
    assert!(witness.get(count).is_none());
}
