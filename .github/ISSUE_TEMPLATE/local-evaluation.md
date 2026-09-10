---
name: Local evaluation report
about: Share one reproducible setup problem, integration finding, or documentation improvement.
title: '[Evaluation] '
---

## Before posting

**This is a public, non-security report.** Do not include private keys, seed
phrases, RPC credentials or cookies, production data, or identifying wallet
queries. Redact logs and configuration before attaching them. Use a disposable
local regtest environment, not real funds or a production datadir.

For a potential vulnerability, stop here and confirm a private reporting channel
with a maintainer before sharing technical details. This template is not a
security-reporting channel.

- [ ] I searched existing issues for the same finding.
- [ ] This report contains no security-sensitive details or secrets.
- [ ] I recorded actual commands and output; I did not reconstruct a successful result.

## What did you evaluate?

Describe one setup problem, integration behavior, or documentation improvement.
Link the guide, API contract, or example you used. State whether the attempt
completed, failed, or was blocked before the relevant behavior could be tested.

## Revision and environment

Record `unknown` for anything not captured; do not infer it. For optional
features, distinguish `none` from `unknown`.

| Field | Value |
| --- | --- |
| Source commit (`git rev-parse HEAD`) | |
| Local modifications (clean, or describe relevant changes) | |
| OS/version and CPU architecture | |
| Rust toolchain (`rustc --version --verbose`) | |
| Cargo version (`cargo --version`) | |
| Exact build command and profile | |
| Default features enabled? Additional features, or `none` | |
| Storage backend | |
| Validation engine and assume-valid setting | |
| Network and enabled indexes | |
| Fresh disposable datadir or reused test datadir? | |

## Minimal reproduction

Provide the smallest relevant commands in execution order, including redacted
configuration and environment-variable overrides. Never paste a complete
environment dump. State any prerequisites beyond the linked setup guide.

```sh
# Paste the commands you actually ran. Replace secrets with <REDACTED>.
```

## Expected behavior

Describe the expectation and link its documented owner. An expectation is not
an observed result.

## Actual behavior and evidence

Include relevant output, exit codes, and redacted logs. Report the first failed
step separately from later steps you did not execute. State how many attempts
produced the result, including failures rather than only the best attempt.

```text
Paste actual, redacted output here.
```

## Limits and next step

What did this evaluation not test? A successful startup or RPC response does
not establish consensus equivalence, recovery correctness, full-tip sync, or
production readiness. Performance claims need the benchmark owner's evidence,
not a first-run timing.

Suggest one actionable documentation or code change, or one question for a
maintainer. Do not attach sensitive datasets.

## Discovery source (optional)

Where did you find the project? Leave blank rather than including identifying
tracking data.

---

[Getting started](https://github.com/gosuda/bitcoin-rs/blob/main/docs/getting-started.md)
· [Contributing](https://github.com/gosuda/bitcoin-rs/blob/main/CONTRIBUTING.md)
· [Benchmark evidence](https://github.com/gosuda/bitcoin-rs/blob/main/docs/benchmarks/end-to-end-sync.md)
