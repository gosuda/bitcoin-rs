# `fetch-golden.sh` fixture cache contract

The fixture cache entries managed by `scripts/fetch-golden.sh` must be regular
files. Every existing nonregular entry, including symbolic links (whether
dangling or pointing to a regular file), is rejected before any network,
staging, or publication operation. Rejection must leave the entry unchanged.

An existing regular file may be reused when nonempty; empty regular files may
be replaced by freshly downloaded fixture data.
