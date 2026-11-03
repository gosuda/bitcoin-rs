# Report a security problem

This repository has no `SECURITY.md` and publishes no private security address at this commit. Use the route it does provide, and keep exploit details out of the public form.

## What exists

The only report form in the tree is [`.github/ISSUE_TEMPLATE/local-evaluation.yml`](https://github.com/gosuda/bitcoin-rs/blob/main/.github/ISSUE_TEMPLATE/local-evaluation.yml). It is a public form for a bounded developer task, including a successful run with a confusing step.

The form states its own limits. It tells reporters not to include seeds, private keys, RPC credentials, cookies, personal information, or sensitive logs. It also says not to disclose a suspected vulnerability there. It says to use private vulnerability reporting from the Security tab if that feature is enabled; otherwise ask maintainers for a private route without exploit details.

[`CONTRIBUTING.md`](https://github.com/gosuda/bitcoin-rs/blob/main/CONTRIBUTING.md) covers contributions, commit conventions, pull-request verification, and BIP proposals. It does not define a security policy or a response time.

> **Warning** The issue form is public. Do not put exploit steps, secrets, credentials, or sensitive logs in it. A public report cannot be withdrawn.

## If the finding is sensitive

Check the repository's Security tab first. If private vulnerability reporting is enabled, use that form. It keeps the report out of the public issue tracker.

If private reporting is not enabled, ask maintainers for a private route without exploit details. State that you have a security report and ask where to send it. Do not include the exploit details in that first message. The tree publishes no security mailbox, so do not invent one.

Do not open a public issue with the details while you wait. Do not paste a seed, a private key, an RPC cookie, or a full log into any public form.

## If the finding is not sensitive

Use the evaluation form for a build, setup, documentation, or public-interface problem that contains no exploit. The form asks for the source revision, the environment and build, the task and reproduction steps, the expected result, and the actual result. Include the first relevant error and the exit status. A successful HTTP status alone is not a successful JSON-RPC result.

The form also asks you to distinguish actual results from steps you did not attempt. That distinction is part of the evidence.

## What the repository does not promise

No security response time, bounty, or disclosure deadline appears in the tree, and this page adds none. The maintainers' process is whatever they state in the report thread.

Dependency advisories are separate from an implementation finding. The `deny` gate runs `cargo deny` over the full dependency graph, and a failure is a bug report, not lint noise. See [Build and test](build-and-test.md) for that gate.

Owner: [`.github/ISSUE_TEMPLATE/local-evaluation.yml`](https://github.com/gosuda/bitcoin-rs/blob/main/.github/ISSUE_TEMPLATE/local-evaluation.yml). Next: [Build and test](build-and-test.md) covers the gates, and [Contracts and evidence](contracts.md) covers where a fix's proof lands.
