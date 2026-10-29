use bitcoin_rs_primitives::Amount;
use bitcoin_rs_utxo::contract::{BlockChanges, UtxoAdd};

use super::{Mutation, mutations_for_block};
use crate::test_fixtures::journal_coin as coin;

#[test]
fn classifies_bip30_restore_as_overwrite_before_spends() -> Result<(), super::JournalDeltaError> {
    let old = coin(1, 10, 50);
    let mut new = old.clone();
    new.height = 100;
    new.txout.value = Amount::from_sat(25);
    let spent = coin(2, 20, 12);
    let mut changes = BlockChanges::with_capacity(1, 1);
    changes.add(UtxoAdd::new(
        new.outpoint,
        &new.txout,
        new.coinbase,
        new.height,
    ));
    changes.remove(spent.outpoint);

    let mutations = mutations_for_block(&changes, vec![old.clone(), spent.clone()])?;

    assert_eq!(
        mutations,
        vec![
            Mutation::Overwrite {
                old_coin: old,
                new_coin: new,
            },
            Mutation::Spend { coin: spent },
        ]
    );
    Ok(())
}
