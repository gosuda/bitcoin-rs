# Consensus difficulty contract

## `DAA-01`: Bitcoin Core 31.1 difficulty adjustment

The node's permanent difficulty tests follow the Bitcoin Core 31.1 product
reference recorded in `docs/contracts/reference-set.md` (`REF-02`). The
retarget timespan is clamped to one quarter through four times the target
timespan. Testnet's minimum-difficulty exception applies after a gap greater
than 20 minutes (the 1,800-second threshold), while a timely block inherits the
last non-minimum target. Retarget boundaries take precedence over that
exception.

These rules correspond to Bitcoin Core's `GetNextWorkRequired` and
`CalculateNextWorkRequired` consensus paths; update this contract and the
reference identity together when reviewing consensus changes.
