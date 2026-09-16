# Support-test contracts

Normative behavior for the shared support scanners and process harness. The
executable proofs are listed with each clause.

### `SUP-01`: Test-module scanner recognizes external declarations

The ownership scanner records a module stem only for a `#[cfg(test)]` (including
combined `cfg` predicates) external module declaration. Visibility modifiers
and intervening attributes/comments are allowed. Inline modules, functions,
ordinary modules, and `cfg(not(test))` declarations are not recorded.
Proof: `bin/bitcoin-rs/tests/support/ownership_scan_tests.rs::cfg_test_stems_cover_external_module_declarations_only`.

### `SUP-02`: Harness time limits have microsecond precision

A deadline strictly less than one microsecond from the start is expired; a
one-microsecond or longer deadline remains valid. This preserves the minimum
granularity used by the process harness.
Proof: `bin/bitcoin-rs/tests/support/process_node_tests.rs::socket_time_limit_rejects_sub_microsecond_intervals`.

### `SUP-03`: Selected harness ports remain reserved until ownership is dropped

The two loopback listeners returned by the harness reserve distinct ports.
Those ports cannot be rebound while the listeners are alive and become
available after the listeners are dropped.
Proof: `bin/bitcoin-rs/tests/support/process_node_tests.rs::selected_ports_stay_reserved`.
