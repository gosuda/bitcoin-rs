//! Equivalence between the v4 and v5 `UtxoRecord` payload codecs.
//!
//! v5 exists to make the record smaller — a mainnet attribution run put the
//! UTXO set at 77.4% of process RSS (`docs/benchmarks/utxo-memory.md`) — so this
//! file carries a **third** assertion beyond the usual pair. Equivalence and
//! speed are not enough: a v5 codec that is lossless and faster but not smaller
//! has missed the point, so size is asserted here too.
//!
//! Equivalence is **per field**, over every decoded output, in order. Comparing
//! encoded bytes would be meaningless: the two layouts are supposed to differ.
// A codec test that cannot encode or decode its own fixtures has failed, and
// panicking names the offending case.
#![allow(clippy::expect_used)]

use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_utxo::{OneUtxoOut, RecordCodec};
use proptest::prelude::*;

/// Owned form of one output, since `OneUtxoOut` borrows its script.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Out {
    vout: u32,
    value: u64,
    script: Vec<u8>,
    coinbase: bool,
    height: u32,
}

impl Out {
    fn view(&self) -> OneUtxoOut<'_> {
        OneUtxoOut {
            vout: self.vout,
            value: self.value,
            script_pubkey: &self.script,
            coinbase: self.coinbase,
            height: self.height,
        }
    }
}

fn views(outputs: &[Out]) -> Vec<OneUtxoOut<'_>> {
    outputs.iter().map(Out::view).collect()
}

fn txid() -> Hash256 {
    Hash256::from_le_bytes(&[0x3c; 32])
}

/// Encoded payload sizes for one output set, under each codec.
struct Sizes {
    v4: usize,
    v5: usize,
}

/// Asserts both codecs round-trip `outputs` to identical fields in identical
/// order, and returns what each cost in bytes.
///
/// Checking v4 against the input as well as against v5 matters: an oracle that
/// is only ever compared to the thing it is checking can be wrong in the same
/// direction and prove nothing.
fn assert_equivalent(outputs: &[Out]) -> Sizes {
    let views = views(outputs);
    let encoded_v4 = RecordCodec::encode_v4(txid(), &views).expect("v4 encodes");
    let encoded_v5 = RecordCodec::encode_v5(txid(), &views).expect("v5 encodes");

    let decoded_v4 = RecordCodec::decode_v4(&encoded_v4).expect("v4 decodes");
    let decoded_v5 = RecordCodec::decode_v5(&encoded_v5).expect("v5 decodes");

    assert_eq!(
        decoded_v4.len(),
        outputs.len(),
        "v4 lost or invented an output"
    );
    assert_eq!(
        decoded_v5.len(),
        outputs.len(),
        "v5 lost or invented an output"
    );

    for (index, ((source, v4), v5)) in outputs.iter().zip(&decoded_v4).zip(&decoded_v5).enumerate()
    {
        let expected = source.view();
        for (label, got_v4, got_v5) in [
            ("vout", u64::from(v4.vout), u64::from(v5.vout)),
            ("value", v4.value, v5.value),
            ("height", u64::from(v4.height), u64::from(v5.height)),
            ("coinbase", u64::from(v4.coinbase), u64::from(v5.coinbase)),
        ] {
            let want = match label {
                "vout" => u64::from(expected.vout),
                "value" => expected.value,
                "height" => u64::from(expected.height),
                _ => u64::from(expected.coinbase),
            };
            assert_eq!(got_v4, want, "v4 {label} wrong at output {index}");
            assert_eq!(got_v5, want, "v5 {label} wrong at output {index}");
        }
        assert_eq!(
            v4.script_pubkey, expected.script_pubkey,
            "v4 script wrong at output {index}"
        );
        assert_eq!(
            v5.script_pubkey, expected.script_pubkey,
            "v5 script wrong at output {index}"
        );
    }

    Sizes {
        v4: encoded_v4.len(),
        v5: encoded_v5.len(),
    }
}

/// A 22-byte P2WPKH-shaped script, the most common output on mainnet.
fn p2wpkh(tag: u8) -> Vec<u8> {
    let mut script = vec![0x00, 0x14];
    script.extend(core::iter::repeat_n(tag, 20));
    script
}

#[test]
fn the_adversarial_field_values_survive_both_codecs() {
    let cases = [
        // Zero everywhere.
        Out {
            vout: 0,
            value: 0,
            script: Vec::new(),
            coinbase: false,
            height: 0,
        },
        // Saturated everywhere: `u64::MAX` takes v5's amount escape.
        Out {
            vout: u32::MAX,
            value: u64::MAX,
            script: vec![0xAB; usize::from(u16::MAX)],
            coinbase: true,
            height: u32::MAX,
        },
        // Exactly the money supply, and one satoshi past it: the boundary
        // between the compact amount and the escape.
        Out {
            vout: 1,
            value: 21_000_000 * 100_000_000,
            script: p2wpkh(0x11),
            coinbase: false,
            height: 1,
        },
        Out {
            vout: 2,
            value: 21_000_000 * 100_000_000 + 1,
            script: p2wpkh(0x22),
            coinbase: true,
            height: 2,
        },
        // Past `LEGACY_INLINE_CAPACITY` and past the vout bitmap.
        Out {
            vout: 65,
            value: 50 * 100_000_000,
            script: p2wpkh(0x33),
            coinbase: true,
            height: 210_000,
        },
        // A non-standard script that no compression scheme should shrink.
        Out {
            vout: 3,
            value: 1,
            script: vec![0x6a, 0x4c, 0xFF],
            coinbase: false,
            height: 840_000,
        },
    ];

    // Each on its own, so a failure names one case...
    for case in &cases {
        assert_equivalent(core::slice::from_ref(case));
    }
    // ...and all together, which is the only way the >8-output overflow
    // partition and the cursor walking from one output to the next are covered.
    assert_equivalent(&cases);
}

#[test]
fn a_record_with_more_outputs_than_the_inline_partition_holds_round_trips() {
    let outputs: Vec<Out> = (0..40_u32)
        .map(|index| Out {
            vout: index,
            value: u64::from(index) * 100_000,
            script: p2wpkh(u8::try_from(index).unwrap_or(0)),
            coinbase: index == 0,
            height: 700_000 + index,
        })
        .collect();
    let sizes = assert_equivalent(&outputs);
    assert!(
        sizes.v5 < sizes.v4,
        "v5 must be smaller on a mainnet-shaped record: {} vs {}",
        sizes.v5,
        sizes.v4
    );
}

/// The measured saving on the output shape mainnet actually holds.
///
/// `docs/benchmarks/utxo-memory.md` projects the tip RSS from a per-output byte
/// count, so this is the number that projection rests on. Asserting a floor
/// rather than an exact figure: the point is that the saving is real and large,
/// and pinning it exactly would break on any future encoding change that is
/// still an improvement.
#[test]
fn v5_saves_at_least_eight_bytes_per_mainnet_shaped_output() {
    let outputs: Vec<Out> = (0..64_u32)
        .map(|index| Out {
            vout: index,
            // Round amounts, which is what the Core transform exists for.
            value: u64::from(index + 1) * 10_000_000,
            script: p2wpkh(u8::try_from(index).unwrap_or(0)),
            coinbase: false,
            height: 800_000 + index,
        })
        .collect();
    let sizes = assert_equivalent(&outputs);

    let saved = sizes.v4 - sizes.v5;
    let per_output = saved / outputs.len();
    assert!(
        per_output >= 8,
        "expected >= 8 bytes saved per output, got {per_output} ({} -> {})",
        sizes.v4,
        sizes.v5
    );
}

/// v5 is not smaller on every conceivable input, and the exception is worth a
/// test rather than a footnote.
///
/// A script over 16,383 bytes needs a 3-byte varint length where v4 spent a
/// fixed 2, so v5 costs one byte more. It is reachable — an oversized
/// `scriptPubKey` is unspendable but still enters the UTXO set — and it is
/// irrelevant: one byte against a script of at least 16 KB.
#[test]
fn an_oversized_script_is_the_one_shape_v5_does_not_shrink() {
    let outputs = [Out {
        vout: 0,
        value: 1,
        script: vec![0x51; 20_000],
        coinbase: false,
        height: 1,
    }];
    let sizes = assert_equivalent(&outputs);
    assert!(
        sizes.v5 <= sizes.v4 + 1,
        "v5 overhead on an oversized script grew beyond one byte: {} vs {}",
        sizes.v5,
        sizes.v4
    );
}

prop_compose! {
    /// Unconstrained field values: the codec must be total over everything its
    /// callers can construct, not just over consensus-valid outputs.
    fn any_output()(
        vout in any::<u32>(),
        value in any::<u64>(),
        script in prop::collection::vec(any::<u8>(), 0..80),
        coinbase in any::<bool>(),
        height in any::<u32>(),
    ) -> Out {
        Out { vout, value, script, coinbase, height }
    }
}

prop_compose! {
    /// Mainnet-shaped: small vouts, plausible heights, standard script sizes,
    /// amounts inside the money supply.
    fn mainnet_output()(
        vout in 0..16_u32,
        value in 0..=21_000_000_u64 * 100_000_000,
        script_len in prop::sample::select(vec![22_usize, 23, 25, 34]),
        coinbase in any::<bool>(),
        height in 0..1_000_000_u32,
    )(
        vout in Just(vout),
        value in Just(value),
        script in prop::collection::vec(any::<u8>(), script_len..=script_len),
        coinbase in Just(coinbase),
        height in Just(height),
    ) -> Out {
        Out { vout, value, script, coinbase, height }
    }
}

proptest! {
    #[test]
    fn both_codecs_round_trip_every_field(outputs in prop::collection::vec(any_output(), 0..12)) {
        assert_equivalent(&outputs);
    }

    /// Size is the whole reason v5 exists, so it is a property, not a spot
    /// check.
    #[test]
    fn v5_is_never_larger_on_a_mainnet_shaped_record(
        outputs in prop::collection::vec(mainnet_output(), 1..12),
    ) {
        let sizes = assert_equivalent(&outputs);
        prop_assert!(
            sizes.v5 < sizes.v4,
            "v5 {} was not smaller than v4 {}",
            sizes.v5,
            sizes.v4
        );
    }

    /// Two distinct output sets must not encode to the same bytes, or a lookup
    /// could return another transaction's coin.
    #[test]
    fn v5_encoding_is_injective(a in any_output(), b in any_output()) {
        prop_assume!(a != b);
        let encoded_a = RecordCodec::encode_v5(txid(), &views(&[a])).expect("encodes");
        let encoded_b = RecordCodec::encode_v5(txid(), &views(&[b])).expect("encodes");
        prop_assert_ne!(encoded_a, encoded_b);
    }
}
