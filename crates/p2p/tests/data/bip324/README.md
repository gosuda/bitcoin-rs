# BIP324 reference vectors

Both CSV files are verbatim copies from bitcoin/bips commit
`a50c0ea32b104832d15b10a3d65bc77ee8df98da`, directory `bip-0324/`
(https://github.com/bitcoin/bips/tree/a50c0ea32b104832d15b10a3d65bc77ee8df98da/bip-0324).
BIP324 and its auxiliary files are licensed BSD-3-Clause. The upstream files
use CRLF line endings; the `.gitattributes` beside them stores them unconverted.

| File | SHA-256 |
| --- | --- |
| `packet_encoding_test_vectors.csv` | `61704507945e2fa99e6c799fab888593eb7a2c3d2018f42ee4a3c3abe0684269` |
| `ellswift_decode_test_vectors.csv` | `a238a66b093bed3c571d5b57cb2bb1f69487788f0f872f7ea7501b5b98be20b0` |

`packet_encoding_test_vectors.csv` pins the ECDH shared secret, the HKDF key
schedule, the garbage terminators, the session id, and the ciphertext of the
packet sent after `in_idx` empty packets. Its rows cross the 224-packet rekey
boundary. `ellswift_decode_test_vectors.csv` pins ElligatorSwift decoding.
The upstream `xswiftec_inv_test_vectors.csv` is not copied: it tests an
encoding-inverse helper that libsecp256k1 does not expose.

The vectors come from the BIP's reference implementation
(`bip-0324/gen_test_vectors.py`), not from this crate. Regenerating them here
is forbidden; to change them, cite the new upstream commit in this file.
