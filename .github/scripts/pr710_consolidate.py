"""Preserve merged RPC coverage and retain only PR710's additional assertions."""
import hashlib
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1])
main = "51ed6b123bda3b775aabc008ad581c338b96da79"
assert subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip() == main

def read(path, expected):
    raw = (root / path).read_bytes()
    actual = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    assert actual == expected, (path, actual)
    return raw.decode()

def replace(text, old, new):
    assert text.count(old) == 1, (text.count(old), old)
    return text.replace(old, new, 1)

path = "crates/rpc/src/handlers/tx.rs"
original = read(path, "9ab2129530451d46ccb1266c0b011b5ea7d1de3c")
name = "package_prevouts_preserve_sigops_without_mutating_the_pool"
start = original.index("    fn " + name + "() {")
end = original.index("    #[test]", start)
old_test = original[start:end]
test = replace(old_test, "fn " + name + "() {", "fn " + name + "() -> Result<(), Box<dyn std::error::Error>> {")
old = "            let vsize = child.vsize();\n            let contexts = super::package_contexts(&ctx, &pool, &[parent, child]);"
new = """            let oracle: bitcoin::Transaction =
                bitcoin::consensus::deserialize(&consensus_bytes(&child))?;
            let expected_outpoint = oracle.input[0].previous_output;
            let oracle_output = bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(parent.outputs[1].value),
                script_pubkey: bitcoin::ScriptBuf::from_bytes(
                    parent.outputs[1].script_pubkey.clone(),
                ),
            };
            assert_eq!(
                u32::try_from(oracle.total_sigop_cost(|outpoint| {
                    (*outpoint == expected_outpoint).then(|| oracle_output.clone())
                }))?,
                4 + input_cost,
                "independent rust-bitcoin oracle",
            );
            let vsize = child.vsize();
            let txs = [parent, child];
            let contexts = super::package_contexts(&ctx, &pool, &txs);"""
test = replace(test, old, new)
test = replace(test, "            assert_eq!(pool.sequence_number(), sequence);", """            for vout in [2, u32::MAX] {
                let mut missing = txs[1].clone();
                missing.inputs[0].previous_output.vout = vout;
                let contexts =
                    super::package_contexts(&ctx, &pool, &[txs[0].clone(), missing]);
                assert!(contexts[1].missing_inputs);
                assert_eq!(contexts[1].fee, 0);
                assert_eq!(contexts[1].sigop_cost, 4);
            }
            assert_eq!(pool.sequence_number(), sequence);""")
assert test.endswith("        }\n    }\n\n")
test = test[:-len("    }\n\n")] + "        Ok(())\n    }\n\n"
text = original[:start] + test + original[end:]
assert text.split("#[cfg(test)]", 1)[0] == original.split("#[cfg(test)]", 1)[0]
assert text.count("fn " + name + "(") == 1
assert "package_prevouts_preserve_contextual_sigops_without_mutating_the_pool" not in text
(root / path).write_text(text)

path = "docs/policies/mempool-policy.md"
text = read(path, "712361cbb3e81c1332576a56f610a15c31150640")
anchor = "- A policy change that alters any §3 row"
text = replace(text, anchor, """- **Package-parent accounting**: `package_prevouts_preserve_sigops_without_mutating_the_pool`
  in `crates/rpc/src/handlers/tx.rs` checks nonzero output selection for
  P2SH and native/nested witness programs against BIP141 and rust-bitcoin.
  One-past-end and maximum output indices stay missing, with no contextual
  sigops, invented fee, or pool mutation. These are accounting checks, not
  package script-verification claims.
""" + anchor)
(root / path).write_text(text)
changed = set(subprocess.check_output(["git", "diff", "--name-only"], cwd=root, text=True).splitlines())
assert changed == {"crates/rpc/src/handlers/tx.rs", "docs/policies/mempool-policy.md"}, changed
print("Consolidated onto main; production source unchanged; one existing fixture strengthened.")
