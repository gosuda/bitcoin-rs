from pathlib import Path
import subprocess
import sys

path = Path('crates/p2p/src/listener.rs')


def replace(text, old, new):
    assert text.count(old) == 1, (str(path), text.count(old), old[:100])
    return text.replace(old, new, 1)


if sys.argv[1:] == ['fix']:
    text = path.read_text()
    text = replace(text, '''    fn send_block(
        &self,
        source: crate::PeerSource,
        block: bitcoin_rs_primitives::Block,
        serialized: bytes::Bytes,
    ) {
        let mut inbound = crate::InboundBlock {''', '''    fn send_block(
        &self,
        lease: &crate::PeerLease,
        peer_addr: SocketAddr,
        block: bitcoin_rs_primitives::Block,
        serialized: bytes::Bytes,
    ) {
        let source = lease.source(peer_addr);
        let mut inbound = crate::InboundBlock {''')
    text = replace(text, '''        loop {
            if self.is_cancelled() {
                tracing::debug!(
                    peer_addr = %source.addr,
                    "dropping inbound block: session cancelled"
''', '''        loop {
            if self.is_cancelled() || lease.is_cancelled() {
                tracing::debug!(
                    peer_addr = %source.addr,
                    "dropping inbound block: session or peer cancelled"
''')
    text = replace(text,
        'inbound_sync_sinks.send_block(lease.source(peer_addr), block, raw);',
        'inbound_sync_sinks.send_block(lease, peer_addr, block, raw);')
    text = replace(text,
        'sinks.send_block(source, block, serialized.clone());',
        'sinks.send_block(&lease, addr, block, serialized.clone());')
    start = text.index('    #[test]\n    fn send_block_unblocks_when_session_is_cancelled()')
    end = text.index('    #[test]\n    fn message_loop_exits_before_read_when_cancelled()', start)
    text = text[:start] + '''    /// P2P-02: cancellation releases a blocked sender without a queue drain.
    #[test]
    fn send_block_unblocks_when_connection_or_session_is_cancelled()
    -> Result<(), Box<dyn std::error::Error>> {
        for cancel_session in [false, true] {
            let (headers_tx, _headers_rx) = crossbeam_channel::unbounded();
            let (blocks_tx, blocks_rx) = crossbeam_channel::bounded(1);
            let session_cancel = Arc::new(AtomicBool::new(false));
            let sinks = InboundSyncSinks::new(headers_tx, blocks_tx, None)
                .with_session_cancel(Arc::clone(&session_cancel));
            let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 18_448));
            let (tx, _rx) = crossbeam_channel::unbounded();
            let lease = crate::PeerLease::new(tx);
            let lease_probe = lease.clone();
            let source = lease.source(addr);
            let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
            let serialized = bytes::Bytes::from(bitcoin::consensus::encode::serialize(&genesis));
            let block = bitcoin_rs_primitives::Block::consensus_decode(&serialized)
                .map_err(|_| std::io::Error::other("genesis block must decode"))?;
            sinks.send_block(&lease, addr, block.clone(), serialized.clone());
            assert_eq!(blocks_rx.len(), 1);

            let (done_tx, done_rx) = crossbeam_channel::bounded(1);
            let blocked = std::thread::spawn(move || {
                sinks.send_block(&lease, addr, block, serialized);
                let _ = done_tx.send(());
            });
            if cancel_session {
                session_cancel.store(true, Ordering::Release);
            } else {
                lease_probe.cancel();
            }
            // A deadlock detector, not a latency target. Whether the worker
            // reaches the full queue before or after cancellation cannot
            // affect its obligation to stop without downstream progress.
            let completed = done_rx.recv_timeout(FAILSAFE);
            let queued = blocks_rx.try_recv();
            // Release a broken sender before asserting, so red controls do
            // not hang the process or leak a detached worker.
            drop(blocks_rx);
            blocked
                .join()
                .map_err(|_| std::io::Error::other("send_block thread panicked"))?;
            assert!(
                completed.is_ok(),
                "cancelled peer kept block delivery waiting on a full queue"
            );
            assert_eq!(queued?.source, Some(source));
        }
        Ok(())
    }

''' + text[end:]
    assert 'sinks.send_block(source,' not in text
    path.write_text(text)
    contract = Path('docs/contracts/p2p-wire.md')
    doc = contract.read_text()
    old = '  already cancelled lease enqueue nothing.\n'
    doc = replace(doc, old, old + '''- A connection delivering a decoded block observes both its peer lease and
  service cancellation while waiting for inbound queue capacity. Teardown
  does not require downstream consumers to drain the full queue.
''')
    old = '## Proven by\n'
    doc = replace(doc, old, old + '''
- `crates/p2p/src/listener.rs` tests
  `send_block_unblocks_when_connection_or_session_is_cancelled` and
  `sinks_stamp_exact_connection_source` cover cancellation during block
  delivery without losing connection identity (P2P-02).
''')
    contract.write_text(doc)
elif sys.argv[1:] == ['negative-control']:
    original = path.read_bytes()
    text = original.decode()
    corrected = 'if self.is_cancelled() || lease.is_cancelled() {'
    text = replace(text, corrected, 'if self.is_cancelled() {')
    try:
        path.write_text(text)
        result = subprocess.run(
            ['cargo', 'test', '--locked', '-p', 'bitcoin-rs-p2p', '--lib',
             'send_block_unblocks_when_connection_or_session_is_cancelled',
             '--', '--nocapture'],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=600,
        )
        evidence = Path('/tmp/manual-ban-evidence')
        evidence.mkdir(exist_ok=True)
        (evidence / 'block-delivery-negative.txt').write_text(result.stdout)
        print(result.stdout, flush=True)
        assert result.returncode != 0, 'Original cancellation predicate unexpectedly passed'
        assert 'cancelled peer kept block delivery waiting on a full queue' in result.stdout
        assert 'test result: FAILED. 0 passed; 1 failed;' in result.stdout
    finally:
        path.write_bytes(original)
else:
    raise SystemExit('expected fix or negative-control')
