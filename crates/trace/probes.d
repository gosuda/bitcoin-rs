provider validation {
    /*
     * Bitcoin Core `validation:block_connected`.
     *
     * Note on types: this file is the generator input for the `usdt` crate.
     * Its `uint8_t*` maps to a *dereferencing* operand (`8@(%reg)`), while
     * Bitcoin Core's tracepoints pass hash and message byte pointers by
     * value (`8@%reg`). The SDT note operand is what consumer scripts bind
     * to, so byte-pointer arguments are declared `uint64_t` and fed the
     * buffer address to reproduce Core's operand form exactly. See
     * `src/probe_abi.rs` and `docs/tracing.md`.
     */
    probe block_connected(uint64_t, int32_t, uint64_t, int32_t, int64_t, int64_t);
};

provider mempool {
    /* Bitcoin Core `mempool:added` / `mempool:removed`. */
    probe added(uint64_t, int32_t, int64_t);
    probe removed(uint64_t, char*, int32_t, int64_t, uint64_t);
};

provider net {
    /* Bitcoin Core `net:inbound_message` / `net:outbound_message`. */
    probe inbound_message(int64_t, char*, char*, char*, uint64_t, uint64_t);
    probe outbound_message(int64_t, char*, char*, char*, uint64_t, uint64_t);
};
