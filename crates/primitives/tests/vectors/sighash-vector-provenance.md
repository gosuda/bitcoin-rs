# Sighash vector provenance

Every file in this directory is an authoritative reference vector, not a
self-generated pin.

- `bip143.json` — transcribed from BIP143 "Alternative Signing Procedure",
  Specification examples (P2WPKH and P2SH-P2WSH 6-of-6 multisig), bitcoin/bips
  commit `620871a7a442e276a058b487cd8743775fb499a4`
  (https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki).
- `bip341-wallet-test-vectors.json` — verbatim copy of the BIP341 wallet test
  vectors, bitcoin/bips commit `620871a7a442e276a058b487cd8743775fb499a4`
  (https://github.com/bitcoin/bips/blob/master/bip-0341/wallet-test-vectors.json).
  The `keyPathSpending` section pins the BIP341 key-path signature message for
  every base SIGHASH mode. BIP342 script-path signature messages share the
  BIP341 message with the extension defined in BIP342 "Common Signature Message
  Extension" (`tapleaf_hash` || `key_version` || `codesep_pos`); the tapscript
  upstream JSON was published only in the now-defunct sipa/bip-taproot
  repository, so script-path leaves are covered structurally in
  `crates/primitives/tests/differential.rs` with each synthetic pin commented
  to the exact BIP341/BIP342 section that defines the hashed fields.

Regenerating fixtures from this crate's own implementation is forbidden here:
if a vector must change, cite the new upstream commit in this file and the
commit that imports it.
