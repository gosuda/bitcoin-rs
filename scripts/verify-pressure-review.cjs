"use strict";
const fs = require("node:fs");
const assert = require("node:assert/strict");
function replaceOne(path, from, to) {
  const text = fs.readFileSync(path, "utf8");
  const parts = text.split(from);
  assert.equal(parts.length, 2, "mutation must match exactly once: " + path);
  fs.writeFileSync(path, parts[0] + to + parts[1]);
}
const mode = process.argv[2];
if (mode === "mutate") {
  const mutation = process.argv[3];
  const sv2 = "crates/node/src/pool/sv2.rs";
  const ledger = "crates/node/src/pool/ledger.rs";
  if (mutation === "compact") {
    const path = "crates/p2p/src/listener.rs";
    replaceOne(path, "let hash = image.block_hash();\n            match retain_compact_image", "let _hash = image.block_hash();\n            match retain_compact_image");
    replaceOne(path, "(crate::compact_blocks::Outcome::Fallback(hash), None)", "return;");
  } else if (mutation === "drop-unavailable") {
    replaceOne(sv2, "Err(MiningControlError::Unavailable(_)) => true,", "Err(MiningControlError::Unavailable(_)) => false,");
    const text = fs.readFileSync(ledger, "utf8");
    const pattern = /let admission_refused = matches!\([\s\S]*?\);/g;
    assert.equal(Array.from(text.matchAll(pattern)).length, 1);
    fs.writeFileSync(ledger, text.replace(pattern, "let admission_refused = false;"));
  } else if (mutation === "consume-refusal-attempt") {
    replaceOne(sv2, "Err(MiningControlError::Unavailable(_)) => return Some(entry),",
      "Err(MiningControlError::Unavailable(_)) => { entry.attempts += 1; return Some(entry); },");
  } else if (mutation === "omit-retry-delay") {
    replaceOne(sv2, "        && now >= entry.next_attempt\n", "");
  } else {
    throw new Error("unknown mutation: " + mutation);
  }
} else if (mode === "check") {
  const [, , , path, statusText, outcome, namesText] = process.argv;
  const status = Number(statusText);
  const names = JSON.parse(namesText);
  assert.ok(Array.isArray(names) && names.every(name => typeof name === "string"));
  assert.ok(outcome === "pass" || outcome === "fail");
  assert.equal(status, outcome === "pass" ? 0 : 100, "nextest must execute the selected tests");
  const xml = fs.readFileSync(path, "utf8");
  const cases = Array.from(xml.matchAll(/<testcase\b([^>]*?)(?:\/>|>([\s\S]*?)<\/testcase>)/g));
  const observed = cases.map(match => {
    const name = /\bname="([^"]*)"/.exec(match[1]);
    assert.ok(name, "test case must name its test");
    assert.ok(!/<skipped\b/.test(match[2] || ""), "selected case must execute");
    return name[1];
  }).sort();
  assert.deepEqual(observed, names.slice().sort());
  const failures = cases.filter(match => /<failure\b/.test(match[2] || "")).length;
  const errors = cases.filter(match => /<error\b/.test(match[2] || "")).length;
  assert.equal(errors, 0);
  assert.equal(failures, outcome === "pass" ? 0 : names.length);
  console.log(JSON.stringify({tests: cases.length, failures, errors, status, names: observed}));
} else {
  throw new Error("expected mutate or check");
}
