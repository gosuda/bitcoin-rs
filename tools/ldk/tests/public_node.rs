//! Real public-API consumer on a blocking OS thread; no test-seam or RPC client.

use std::error::Error;

use bitcoin::{
    Amount, Block, BlockHash, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    WPubkeyHash, Witness, absolute, consensus, hashes::Hash, transaction,
};
use bitcoin_rs_ldk_spike::{AdapterError, NativeBackend};
use bitcoin_rs_node::{Network, Node, NodeConfig, NodeError, RuntimeInputs};
use futures_executor::block_on;
use lightning::chain::chaininterface::{BroadcasterInterface, ConfirmationTarget, FeeEstimator};
use lightning_block_sync::{BlockData, BlockSource, BlockSourceErrorKind};

type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

#[test]
fn public_node_reads_fees_and_admission_refusals() -> TestResult {
    std::thread::Builder::new()
        .name("ldk-consumer".into())
        .spawn(probe)?
        .join()
        .expect("consumer thread panicked")
}

fn probe() -> TestResult {
    let dir = tempfile::tempdir()?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    config.p2p.connect.clear();
    config.rpc.bind = "127.0.0.1:0".parse()?;
    config.observability.metrics_bind = None;
    let reopen_config = config.clone();

    let node = block_on(Node::start(config, RuntimeInputs::default()))?;
    {
        let backend = NativeBackend::new(&node, 321);
        let source: &dyn BlockSource = &backend;
        let fees: &dyn FeeEstimator = &backend;
        let broadcaster: &dyn BroadcasterInterface = &backend;

        let (hash, height) =
            block_on(source.get_best_block()).map_err(|error| error.into_inner())?;
        assert_eq!(height, Some(0));
        let BlockData::FullBlock(block) =
            block_on(source.get_block(&hash)).map_err(|error| error.into_inner())?
        else {
            panic!("Node supplies full blocks");
        };
        let native_genesis = Network::Regtest.genesis_block();
        let expected: Block =
            consensus::deserialize(&bitcoin_rs_primitives::consensus_bytes(&native_genesis))?;
        assert_eq!(block, expected);
        assert_eq!(block.block_hash(), hash);
        assert_eq!(
            hash.to_byte_array(),
            *native_genesis.block_hash().as_bytes()
        );

        assert!(node.fee_estimate(6).is_none());
        for target in [
            ConfirmationTarget::MaximumFeeEstimate,
            ConfirmationTarget::UrgentOnChainSweep,
            ConfirmationTarget::MinAllowedAnchorChannelRemoteFee,
            ConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee,
            ConfirmationTarget::AnchorChannelFee,
            ConfirmationTarget::NonAnchorChannelFee,
            ConfirmationTarget::ChannelCloseMinimum,
            ConfirmationTarget::OutputSpendingFee,
        ] {
            assert_eq!(fees.get_est_sat_per_1000_weight(target), 321);
        }
        assert_eq!(
            NativeBackend::new(&node, 0)
                .get_est_sat_per_1000_weight(ConfirmationTarget::UrgentOnChainSweep),
            253
        );

        let missing = BlockHash::from_byte_array([42; 32]);
        let error = block_on(source.get_block(&missing))
            .err()
            .expect("unknown block");
        assert_eq!(error.kind(), BlockSourceErrorKind::Transient);

        for hint in [None, Some(0), Some(123)] {
            let data =
                block_on(source.get_header(&hash, hint)).map_err(|error| error.into_inner())?;
            assert_eq!(data.header, block.header);
            assert_eq!(data.height, 0);
            assert_eq!(data.chainwork, block.header.work());
        }
        let mut subscription = node.subscribe_chain()?;
        assert!(node.poll_chain(&mut subscription)?.is_none());
        let target = node.pin_chain()?;
        assert!(
            node.replay_chain(native_genesis.block_hash(), &target, 1)?
                .complete
        );
        let validated = block_on(lightning_block_sync::init::validate_best_block_header(
            &backend,
        ))
        .map_err(|error| error.into_inner())?;
        assert_eq!(validated.height, 0);

        let tx = orphan_transaction();
        let native_tx = bitcoin_rs_primitives::deserialize::<bitcoin_rs_primitives::Tx>(
            &consensus::serialize(&tx),
        )?;
        assert_eq!(
            tx.compute_txid().to_byte_array(),
            *native_tx.txid().as_bytes()
        );
        assert_eq!(
            tx.compute_wtxid().to_byte_array(),
            *native_tx.wtxid().as_bytes()
        );
        assert!(matches!(
            backend.try_broadcast_transactions(&[&tx]),
            Err(AdapterError::Node(NodeError::Broadcast(reason))) if reason == "missing-inputs",
        ));
        assert!(matches!(
            backend.try_broadcast_transactions(&[&tx, &tx]),
            Err(AdapterError::Node(NodeError::Broadcast(reason))) if reason == "package-contains-duplicates",
        ));
        broadcaster.broadcast_transactions(&[]);
        broadcaster.broadcast_transactions(&[&tx]);
        assert_eq!(node.mempool_info().txs, 0);
    }
    let before_shutdown = node.snapshot();
    block_on(node.shutdown())?;
    let reopened = block_on(Node::start(reopen_config, RuntimeInputs::default()))?;
    assert_eq!(reopened.snapshot().tip_hash, before_shutdown.tip_hash);
    assert!(reopened.snapshot().epoch > before_shutdown.epoch);
    block_on(reopened.shutdown())?;
    Ok(())
}

fn orphan_transaction() -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([42; 32]), 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[vec![1; 72], vec![2; 33]]),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([1; 20])),
        }],
    }
}
