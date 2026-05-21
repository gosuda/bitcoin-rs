//! Wire codec message round trips.
use std::io::Cursor;

use bitcoin::TxMerkleNode;
use bitcoin::Txid;
use bitcoin::bip152::{
    BlockTransactions, BlockTransactionsRequest, HeaderAndShortIds, PrefilledTransaction, ShortId,
};
use bitcoin::block::BlockHash;
use bitcoin::block::{Header, Version};
use bitcoin::hashes::Hash;
use bitcoin::p2p::Magic;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_blockdata::{GetHeadersMessage, Inventory};
use bitcoin::p2p::message_compact_blocks::{BlockTxn, CmpctBlock, GetBlockTxn, SendCmpct};
use bitcoin::pow::CompactTarget;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use bitcoin_rs_p2p::handshake::version_message;
use bitcoin_rs_p2p::wire::{PeerError, read_message, write_message};

#[test]
fn round_trips_ping_pong_version_verack_inv_getheaders() -> Result<(), PeerError> {
    let messages = vec![
        NetworkMessage::Ping(42),
        NetworkMessage::Pong(42),
        NetworkMessage::Version(version_message(99, 123)),
        NetworkMessage::Verack,
        NetworkMessage::Inv(vec![Inventory::Transaction(Txid::from_byte_array(
            [7u8; 32],
        ))]),
        NetworkMessage::GetHeaders(GetHeadersMessage::new(
            vec![BlockHash::all_zeros()],
            BlockHash::all_zeros(),
        )),
    ];

    for message in messages {
        let mut cursor = Cursor::new(Vec::new());
        write_message(&mut cursor, Magic::BITCOIN, &message)?;
        cursor.set_position(0);
        let decoded = read_message(&mut cursor, Magic::BITCOIN)?;
        assert_eq!(decoded, message);
    }

    Ok(())
}

#[test]
fn round_trips_compact_block_messages() -> Result<(), PeerError> {
    let block_hash = BlockHash::from_byte_array([3u8; 32]);
    let transaction = compact_block_transaction();
    let messages = vec![
        NetworkMessage::SendCmpct(SendCmpct {
            send_compact: false,
            version: 1,
        }),
        NetworkMessage::SendCmpct(SendCmpct {
            send_compact: true,
            version: 2,
        }),
        NetworkMessage::CmpctBlock(CmpctBlock {
            compact_block: HeaderAndShortIds {
                header: compact_block_header(),
                nonce: 99,
                short_ids: vec![ShortId::default()],
                prefilled_txs: vec![PrefilledTransaction {
                    idx: 0,
                    tx: transaction.clone(),
                }],
            },
        }),
        NetworkMessage::GetBlockTxn(GetBlockTxn {
            txs_request: BlockTransactionsRequest {
                block_hash,
                indexes: vec![1, 3],
            },
        }),
        NetworkMessage::BlockTxn(BlockTxn {
            transactions: BlockTransactions {
                block_hash,
                transactions: vec![transaction],
            },
        }),
    ];

    for message in messages {
        let mut cursor = Cursor::new(Vec::new());
        write_message(&mut cursor, Magic::BITCOIN, &message)?;
        cursor.set_position(0);
        let decoded = read_message(&mut cursor, Magic::BITCOIN)?;
        assert_eq!(decoded, message);
    }

    Ok(())
}

fn compact_block_header() -> Header {
    Header {
        version: Version::ONE,
        prev_blockhash: BlockHash::all_zeros(),
        merkle_root: TxMerkleNode::all_zeros(),
        time: 0,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce: 0,
    }
}

fn compact_block_transaction() -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::new(),
        }],
    }
}
