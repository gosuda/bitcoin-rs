# Core v2 regtest fixture

core200.dat is the unmodified output of Bitcoin Core v31.1 dumptxoutset,
generated from Core's deterministic CreateBlockChain(200) sequence. Bitcoin
Core accepted every block over submitblock and reported the same compiled
regtest-200 base, 201 cumulative transactions, 200 live outputs and
hash_serialized_3 as bitcoin-rs.

- Core source: [mining.cpp](https://github.com/bitcoin/bitcoin/blob/9be056a8a72b624dae9623b2f7bded92c2a21c91/src/test/util/mining.cpp#L33-L64)
  and [snapshot fuzz fixture](https://github.com/bitcoin/bitcoin/blob/9be056a8a72b624dae9623b2f7bded92c2a21c91/src/test/fuzz/utxo_snapshot.cpp).
- Binary: the v31.1 x86_64 Linux binary installed by scripts/install-bitcoind.sh,
  SHA-256 986e63b3c8770f08d0059820ad3dd085d1ab9e1bea23946c243f858a06888a08.
- Snapshot: 14,439 bytes, SHA-256
  bb96a8a22e8114c36e0f570217795f5cc46baf366b0e74e7588de5b1e4392e7c.
- Base: 385901ccbd69dff6bbd00065d01fb8a9e464dede7cfe0372443884f9b1dcf6b9.
- State commitment: 17dcc016d188d16068907cdeb38b75691a118d43053b8cd6a25969419381d13a.
- provenance.json records the reference responses. Its dump path is normalized
  to core200.dat; the artifact bytes are unchanged.
- blocks200.json contains the exact accepted wire blocks for process tests.
  Its digest is recorded in provenance.json. It is generated from the upstream
  sequence; it is not an alternate trust anchor.

From the repository root, generate a new isolated directory and compare:

~~~sh
python3 crates/utxo/tests/fixtures/core-v2/generate.py \
  --bitcoind "$(scripts/install-bitcoind.sh --print-path)" \
  --output /tmp/core-v2-reproduction
cmp /tmp/core-v2-reproduction/core200.dat \
  crates/utxo/tests/fixtures/core-v2/core200.dat
cmp /tmp/core-v2-reproduction/blocks200.json \
  crates/utxo/tests/fixtures/core-v2/blocks200.json
~~~

The generator verifies the pinned reference binary digest and refuses an
existing output datadir. It constructs blocks according to the independent
upstream sequence, submits them to Core, asks Core to serialize the snapshot,
and checks Core's base/commitment responses. It does not write snapshot bytes
or accept a caller-provided trust root.

The fixture establishes decoder/commitment parity for this small state.
Core-to-bitcoin-rs process activation, lifecycle recovery and genuine mainnet
artifact verification require their own evidence. Unit tests additionally
cover Core's special script encodings and malformed inputs; the coinbase-only
fixture does not exercise every script representation.

