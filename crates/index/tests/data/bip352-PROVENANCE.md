# BIP352 public scan fixture

`bip352-public-scan.json` projects
[bitcoin/bips receiving vectors](https://github.com/bitcoin/bips/blob/8754690b725e9aa93ca8bd91bf0ac85dc44ce096/bip-0352/send_and_receive_test_vectors.json)
at `8754690b725e9aa93ca8bd91bf0ac85dc44ce096`.
Upstream source SHA256:
`f5f9ed4afd76a1b76f3c70b1cbe67532f89abbe559f8e02d7fc3d8ecb93af4a1`.
BIP352 is BSD-2-Clause; its authors are Josie Baker, Ruben Somsen and
Sebastian Falbesoner, as identified in the pinned BIP.

Iterate top-level cases and each `receiving` entry in source order (28 cases,
29 entries). Keep case comment; `given.vin` fields `txid`, `vout`, `scriptSig`,
`txinwitness`, `prevout`; `given.outputs`; and `expected.input_pub_key_sum` /
`expected.tweak` (null if absent). No wallet private-key, receiver-key, address,
label-secret or signature expectation is retained. Never generate expectations
with the Rust implementation.

The test injects one synthetic P2TR candidate only in negative cases with empty
output lists, to exercise input ineligibility instead of the no-output shortcut.
All expectations remain upstream values. Labels/outputs are opaque public
candidates; this fixture does not implement a wallet scanner.

For independent execution, check out that bitcoin/bips commit and run its
unmodified `python3 reference.py send_and_receive_test_vectors.json` from
`bip-0352/` (vendored secp256k1lab is included). The full fixture contains
wallet secret test material unrelated to the keyless API and is not stored here.
