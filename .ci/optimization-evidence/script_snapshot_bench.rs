use bitcoin_rs_consensus::primitives::{
    Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
};
use bitcoin_rs_consensus::script::{PreparedTransaction, VerifyFlags};
use std::hint::black_box;
use std::time::Instant;

fn measure(name: &str, script_sig: &[u8], script_pubkey: &[u8], witness: Witness) {
    let outpoint = OutPoint::new(Txid(Hash256::from_le_bytes(&[7; 32])), 0);
    let tx = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: outpoint,
            script_sig: Script::from_bytes(script_sig.to_vec()),
            sequence: Sequence::MAX,
            witness,
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(9_000),
            script_pubkey: Script::from_bytes(vec![0x51]),
        }],
        lock_time: LockTime::ZERO,
    };
    let prevout = TxOut {
        value: Amount::from_sat(10_000),
        script_pubkey: Script::from_bytes(script_pubkey.to_vec()),
    };
    let prepared =
        PreparedTransaction::from_owned(&tx, vec![(outpoint, prevout)]).expect("fixture");
    let verify = || {
        assert!(
            black_box(&prepared)
                .verify_input(0, VerifyFlags::MANDATORY, None)
                .expect("valid fixture")
        );
    };
    const WARMUP: u32 = 1_000;
    const DEFAULT_ITERATIONS: u32 = 20_000;
    let warmup = Instant::now();
    for _ in 0..WARMUP {
        verify();
    }
    let warmup_ns = (warmup.elapsed().as_nanos() / u128::from(WARMUP)).max(1);
    let iterations = if warmup_ns.saturating_mul(u128::from(DEFAULT_ITERATIONS)) < 20_000_000 {
        u32::try_from((50_000_000 / warmup_ns).clamp(u128::from(DEFAULT_ITERATIONS), 2_000_000))
            .expect("bounded calibration fits u32")
    } else {
        DEFAULT_ITERATIONS
    };

    let mut elapsed_ns = [0u128; 9];
    for sample in &mut elapsed_ns {
        let start = Instant::now();
        for _ in 0..iterations {
            verify();
        }
        *sample = start.elapsed().as_nanos();
    }
    let mut ordered = elapsed_ns;
    ordered.sort_unstable();
    print!("{name},{iterations}");
    for sample in elapsed_ns {
        print!(",{sample}");
    }
    println!(
        ",{},{},{}",
        ordered[0] / u128::from(iterations),
        ordered[4] / u128::from(iterations),
        ordered[8] / u128::from(iterations),
    );
}

fn main() {
    println!(
        "workload,iterations_per_sample,sample_1_elapsed_ns,sample_2_elapsed_ns,sample_3_elapsed_ns,sample_4_elapsed_ns,sample_5_elapsed_ns,sample_6_elapsed_ns,sample_7_elapsed_ns,sample_8_elapsed_ns,sample_9_elapsed_ns,min_ns_per_op,median_ns_per_op,max_ns_per_op"
    );
    measure("legacy_op_true", &[], &[0x51], Witness::new());
    measure(
        "p2wsh_op_true",
        &[],
        &P2WSH,
        Witness::from_stack(vec![vec![0x51]]),
    );
    measure("p2sh_op_true", &[1, 0x51], &P2SH, Witness::new());
}

const P2WSH: [u8; 34] = [
    0, 32, 74, 232, 21, 114, 240, 110, 27, 136, 253, 92, 237, 122, 26, 0, 9, 69, 67, 46, 131, 225,
    85, 30, 111, 114, 30, 233, 192, 11, 140, 195, 50, 96,
];
const P2SH: [u8; 23] = [
    169, 20, 218, 23, 69, 233, 181, 73, 189, 11, 250, 26, 86, 153, 113, 199, 126, 186, 48, 205, 90,
    75, 135,
];
