use bitcoin_rs_primitives::{Amount, Hash256, OutPoint, TxOut, Txid};
use bitcoin_rs_utxo::{BlockChanges, UtxoAdd};

use super::{Coin, Mutation, mutations_for_block};

fn coin(marker: u8, height: u32, value: u64) -> Coin {
    Coin {
        outpoint: OutPoint::new(Txid(Hash256::from_le_bytes(&[marker; 32])), 0),
        txout: TxOut {
            value: Amount::from_sat(value),
            script_pubkey: vec![0x51].into(),
        },
        height,
        coinbase: true,
    }
}

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
