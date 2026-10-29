use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use bitcoin_rs_e2e::{Kind, ProcessNode, SpawnOptions};
use sonic_rs::{JsonValueTrait as _, json};
use std::error::Error;

use crate::support::regtest_blocks;
use regtest_blocks::{block, coinbase, submit};

#[test]
#[ignore = "manual pinned-Core capacity/expiry comparison"]
fn core_expires_stale_members_before_capacity_trim() -> Result<(), Box<dyn Error>> {
    for (package, native_fee) in [(false, 100), (true, 100), (false, 11_000), (true, 11_000)] {
        let mut core = ProcessNode::spawn_with(
            Kind::Core,
            &SpawnOptions {
                extra_args: &[
                    "-maxmempool=5",
                    "-mempoolexpiry=336",
                    "-acceptnonstdtxn=1",
                    "-minrelaytxfee=0.00001000",
                    "-incrementalrelayfee=0.00001000",
                ],
                ..SpawnOptions::default()
            },
        )?;
        let time = u32::try_from(bitcoin_rs_e2e::mock_time())?;
        let mut previous =
            bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest).block_hash();
        let mut funding = None;
        for height in 1..=101 {
            let outputs = if height == 1 {
                vec![
                    TxOut {
                        value: Amount::from_sat(10_000_000),
                        script_pubkey: ScriptBuf::from_bytes(vec![0x51])
                    };
                    120
                ]
            } else {
                vec![TxOut {
                    value: Amount::ZERO,
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                }]
            };
            let cb = coinbase(height, outputs);
            if height == 1 {
                funding = Some(cb.compute_txid());
            }
            let next = block(previous, time + height, vec![cb])?;
            submit(&core, &next)?;
            previous = next.block_hash();
        }
        let funding = funding.ok_or("funding")?;
        let transaction = |index, fee| Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(funding, index),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(10_000_000 - fee),
                script_pubkey: ScriptBuf::from_bytes(vec![0; 50_000]),
            }],
        };
        let vsize = u64::try_from(transaction(0, 0).vsize())?;
        let mut count = 0;
        let mut last_usage = 0;
        let before = loop {
            let tx = transaction(count, 10 * vsize);
            core.rpc(
                "sendrawtransaction",
                &json!([bitcoin::consensus::encode::serialize_hex(&tx), 0, 1]),
            )?;
            count += 1;
            let info = core.rpc("getmempoolinfo", &json!([]))?;
            let usage = info["usage"].as_u64().ok_or("usage")?;
            let capacity = info["maxmempool"].as_u64().ok_or("capacity")?;
            let delta = usage - last_usage;
            if capacity - usage < delta {
                break info;
            }
            last_usage = usage;
            if count >= 119 {
                return Err("fixture did not approach capacity".into());
            }
        };
        core.rpc("setmocktime", &json!([time + 336 * 3600 + 1]))?;
        let fee = vsize * native_fee / 85;
        let fresh = transaction(count, fee);
        let raw = bitcoin::consensus::encode::serialize_hex(&fresh);
        let result = if package {
            core.rpc("submitpackage", &json!([[raw], 0, 1]))?
        } else {
            core.rpc("sendrawtransaction", &json!([raw, 0, 1]))?
        };
        let after = core.rpc("getmempoolinfo", &json!([]))?;
        println!(
            "B Core31.1 package={package} native_fee={native_fee} old_count={count} candidate_vbytes={} fee={fee} age_secs=1209601 before={before} result={result} after={after}",
            fresh.vsize()
        );
        assert_eq!(after["size"], json!(1));
        assert_eq!(before["mempoolminfee"], after["mempoolminfee"]);
        core.stop()?;
    }
    Ok(())
}
