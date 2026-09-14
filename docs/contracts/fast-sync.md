# Fast-sync contract (v1)

Fast sync is an opt-in block-download policy. This contract is normative; the
configuration and scheduler tests cite these clauses.

- **FS-01 Configuration precedence:** fast sync is disabled by default and may
  be enabled by the `--fast-sync` CLI flag, `BITCOIN_RS_FAST_SYNC` environment
  variable, or `fast_sync` TOML setting. Higher-precedence configuration may
  override lower-precedence values.
- **FS-02 Fan-out threshold:** with fast sync enabled, block-request fan-out
  begins at two eligible peers; below two peers the normal deep fallback is
  retained.
- **FS-03 Window striping:** once fan-out is active, the 256-block pending
  window is divided among currently eligible peers, with a minimum stripe of
  eight blocks per peer. Thus two eligible peers receive 128 blocks each and
  the eight-block floor is reached at the 32-peer outbound target.

Owners: `bin/bitcoin-rs/src/main.rs` (configuration) and
`crates/p2p/src/download_window.rs` (scheduling).

Executable proof: the tests named `fast_sync_defaults_off_and_enables_from_flag_or_environment`
and `fast_sync_budget_stripes_window_across_fast_outbound_target`.
