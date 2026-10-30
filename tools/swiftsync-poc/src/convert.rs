use bitcoin::hashes::Hash;
use bitcoin_rs_primitives::{Amount, Hash256, OutPoint, Script, TxOut, Txid};

pub fn block_hash(value: bitcoin::BlockHash) -> Hash256 {
    Hash256::from_le_bytes(&value.to_byte_array())
}

pub fn txid(value: bitcoin::Txid) -> Txid {
    Txid::from(Hash256::from_le_bytes(&value.to_byte_array()))
}

pub fn outpoint(value: &bitcoin::OutPoint) -> OutPoint {
    OutPoint::new(txid(value.txid), value.vout)
}

pub fn txout(value: &bitcoin::TxOut) -> TxOut {
    TxOut {
        value: Amount::from_sat(value.value.to_sat()),
        script_pubkey: Script::from_bytes(value.script_pubkey.as_bytes().to_vec()),
    }
}
