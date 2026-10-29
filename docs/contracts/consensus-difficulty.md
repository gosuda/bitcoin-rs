# Consensus difficulty contract
## `DAA-01`: Bitcoin Core 31.1 difficulty adjustment
Permanent tests follow the Core 31.1 product reference (`REF-02` in [reference-set.md](reference-set.md)); retarget timespan clamped to 1/4–4x target; testnet minimum-difficulty exception after a gap over 20 minutes (1,800 s), timely blocks inherit the last non-minimum target; retarget boundaries take precedence over that exception.
Rules map to Core `GetNextWorkRequired`/`CalculateNextWorkRequired`; update contract and reference identity together on consensus review.
