from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    file = Path(path)
    text = file.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one match, found {count}")
    file.write_text(text.replace(old, new, 1))


replace_once(
    "crates/mempool/src/gateway.rs",
    "        self.by_outpoint.get(outpoint).map(|txout| (*txout).clone())\n",
    "        self.by_outpoint.get(outpoint).map(|txout| (**txout).clone())\n",
)

replace_once(
    "crates/consensus/tests/overhaul_prepared_inputs.rs",
    """    // Replace the source records after taking the immutable snapshot.  The
    // prepared verification entry below must consume only `resolved`.
    view.utxos.insert(
        outpoint(1),
        TxOut {
            value: 1,
            script_pubkey: vec![0x6a],
        },
    );
    let flags = bitcoin_rs_script::VerifyFlags::MANDATORY;
    let stable = bitcoin_rs_consensus::verify_transaction_resolved(&tx, &resolved, 0, 0, flags);
    assert_eq!(stable, Ok(()), "source replacement must not affect prepared facts");
""",
    """    let flags = bitcoin_rs_script::VerifyFlags::MANDATORY;
    let expected = bitcoin_rs_consensus::verify_transaction_resolved(&tx, &resolved, 0, 0, flags);

    // Replace the source records after taking the immutable snapshot.  The
    // prepared verification entry below must consume only `resolved` and
    // therefore reproduce the pre-replacement verdict exactly.
    view.utxos.insert(
        outpoint(1),
        TxOut {
            value: 1,
            script_pubkey: vec![0x6a],
        },
    );
    let stable = bitcoin_rs_consensus::verify_transaction_resolved(&tx, &resolved, 0, 0, flags);
    assert_eq!(
        stable, expected,
        "source replacement must not affect prepared facts"
    );
""",
)
