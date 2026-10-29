use super::*;
use bitcoin_rs_chain::regtest_fixture;
use bitcoin_rs_primitives::{Block, BlockPayload, Network};
use std::{
    future::Future,
    task::{Context, Poll, Waker},
};

fn run<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("node operation unexpectedly parked"),
    }
}

fn config(dir: &std::path::Path) -> crate::NodeConfig {
    let mut config = crate::NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.join("node");
    config.p2p.listen.clear();
    config.p2p.connect.clear();
    config.rpc.bind.set_port(0);
    config.observability.metrics_bind = None;
    config
}

fn block(parent: BlockHash, height: u32, tag: u32) -> anyhow::Result<Block> {
    let txs = vec![regtest_fixture::coinbase(height)];
    let mut block = Block {
        header: Header {
            prev_blockhash: parent,
            version: 0x2000_0000,
            merkle_root: regtest_fixture::merkle_root(&txs)
                .ok_or_else(|| anyhow::anyhow!("merkle"))?,
            time: 1_296_688_603 + height * 600 + tag,
            bits: Network::Regtest.genesis_block().header.bits,
            nonce: 0,
        },
        txs,
    };
    regtest_fixture::mine_block_to_declared_target(&mut block)?;
    Ok(block)
}

#[test]
fn settled_poll_replays_gaps_disconnects_and_pinned_targets() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let node = run(Node::start(
        config(dir.path()),
        crate::RuntimeInputs::default(),
    ))?;
    let genesis = node.snapshot().tip_hash.into();
    let mut sub = node.subscribe_chain()?;
    assert!(node.poll_chain(&mut sub)?.is_none());
    let one = BlockPayload::from_local(block(genesis, 1, 0)?);
    node.state.apply_block(&one)?;
    let update = node
        .poll_chain(&mut sub)?
        .ok_or_else(|| anyhow::anyhow!("connect hint"))?;
    assert!(!update.gap);
    let pinned_one = update.current;
    let two = BlockPayload::from_local(block(one.block().block_hash(), 2, 0)?);
    node.state.apply_block(&two)?;
    let three = BlockPayload::from_local(block(two.block().block_hash(), 3, 0)?);
    node.state.apply_block(&three)?;
    let update = node
        .poll_chain(&mut sub)?
        .ok_or_else(|| anyhow::anyhow!("gap hint"))?;
    assert!(update.gap);
    let first = node.replay_chain(genesis, &update.current, 1)?;
    assert_eq!(first.steps.len(), 1);
    assert!(!first.complete);
    let rest = node.replay_chain(first.position, &update.current, 2)?;
    assert!(rest.complete);
    assert!(
        rest.steps
            .iter()
            .all(|step| matches!(step, ChainStep::Connected(_)))
    );
    assert_eq!(
        node.replay_chain(genesis, &pinned_one, 1)?.position,
        one.block().block_hash()
    );
    crate::reorg::invalidate_block(
        &node.state.chainstate(),
        &node.state.chain_followers(),
        two.block().block_hash().into(),
    )?;
    let alternate = BlockPayload::from_local(block(one.block().block_hash(), 2, 1)?);
    node.state.apply_block(&alternate)?;
    let target = node.pin_chain()?;
    let replay = node.replay_chain(three.block().block_hash(), &target, 10)?;
    assert!(replay.complete);
    assert!(
        matches!(&replay.steps[..], [ChainStep::Disconnected(a), ChainStep::Disconnected(b), ChainStep::Connected(c)] if a.height == 3 && b.height == 2 && c.header == alternate.block().header)
    );
    assert!(node.replay_chain(genesis, &target, 0).is_err());
    assert!(node.replay_chain(genesis, &target, 257).is_err());
    assert!(
        node.replay_chain(Hash256::from_le_bytes(&[42; 32]).into(), &target, 1)
            .is_err()
    );
    let snapshot = node.snapshot();
    run(node.shutdown())?;
    let reopened = run(Node::start(
        config(dir.path()),
        crate::RuntimeInputs::default(),
    ))?;
    let mut resumed = Node::resume_chain(snapshot);
    assert!(
        reopened
            .poll_chain(&mut resumed)?
            .is_some_and(|update| update.gap)
    );
    assert!(reopened.replay_chain(genesis, &target, 1).is_err());
    run(reopened.shutdown())?;
    Ok(())
}

#[test]
fn unsettled_or_failed_chain_fences_never_publish_a_stable_hint() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let node = run(Node::start(
        config(dir.path()),
        crate::RuntimeInputs::default(),
    ))?;
    let mut sub = node.subscribe_chain()?;
    let before = sub.cursor();
    let chain = node.state.chainstate();
    let transition = chain.begin_transition()?;
    assert!(node.poll_chain(&mut sub).is_err());
    assert_eq!(sub.cursor(), before);
    drop(transition);
    let fence = node.state.mempool_gateway().begin_chain_change()?;
    assert!(node.pin_chain().is_err());
    fence.finish()?;
    assert!(node.poll_chain(&mut sub)?.is_none());
    let bad = block(before.tip_hash.into(), 1, 0)?;
    let mut bad = bad;
    bad.txs.clear();
    assert!(
        node.state
            .apply_block(&BlockPayload::from_local(bad))
            .is_err()
    );
    assert_eq!(node.settled_snapshot()?, before);
    drop(node.state.mempool_gateway().begin_chain_change()?);
    assert!(node.poll_chain(&mut sub).is_err());
    assert_eq!(sub.cursor(), before);
    drop(node);
    Ok(())
}
