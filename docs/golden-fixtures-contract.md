# Golden fixture downloader contract (v1)

This file is the versioned contract for `scripts/fetch-golden.sh`. Changes to
these guarantees require a contract version change and corresponding test
review.

## 1. Fixture set

The authoritative, ordered fixture-height list is
`scripts/golden-fixture-heights.txt`. The downloader and its regression tests
must load that file; the list must not be duplicated in either implementation.

## 2. Successful publication and caching

For every listed height, a successful run publishes a non-empty `<height>.bin`
and `<height>.txids.txt` in the testdata directory. A complete pair is reused
without network requests. Missing or empty entries are fetched independently.
Downloads are staged and validated before publication: failed, empty, malformed,
or interrupted responses must not publish the corresponding file. Existing
valid files are preserved when their companion is being fetched.

## 3. Network request contract

For a fully empty fixture directory, the downloader makes exactly three
requests per listed height (height-to-hash, raw block, and transaction IDs).
A complete cache makes zero requests. Replacing one empty cache pair makes
three requests; removing only the txids file makes two requests. Transaction
IDs must be a non-empty JSON array of 64-character hexadecimal strings, and
block hashes must be 64-character hexadecimal strings.
