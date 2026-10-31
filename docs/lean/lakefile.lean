import Lake
open Lake DSL

package leanProofs

@[default_target]
lean_lib Proofs where
  globs := #[.one `Proofs, .submodules `Primitives, .submodules `Utxo,
    .submodules `Mempool, .submodules `ChainAdmission, .submodules `PeerLeases,
    .submodules `ProjectionMining, .submodules `P2p]
