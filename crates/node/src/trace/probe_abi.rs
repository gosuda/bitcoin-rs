//! Documented ABI of the Bitcoin Core-compatible USDT probes.
//!
//! This table is the single source of truth for the provider names, probe
//! names, argument order, and argument layout (`size@operand` prefixes) that
//! [`crate`] emits. The layout prefixes are what a USDT consumer binds to;
//! the operand part of a SystemTap argument string is register-allocation
//! specific and differs between binaries, so compatibility is asserted on
//! the prefix sequence only. Byte-pointer arguments deliberately reproduce
//! Core's *pointer-by-value* operand form — see the note below.
//!
//! Widths and signs follow the SystemTap SDT notes emitted by a released
//! Bitcoin Core binary (verified out of tree against `bitcoind`), not
//! `doc/tracing.md`, wherever the two disagree. The in-repo test checks
//! bitcoin-rs's built artifact against this table rather than Core's notes;
//! the discrepancies are recorded per argument below.
//!
//! # Byte-pointer arguments
//!
//! Bitcoin Core passes hash and message byte buffers as *pointers by value*
//! (`8@%reg`): the consumer receives the buffer address. The `usdt` crate's
//! `uint8_t*` declaration maps to a *dereferencing* operand (`8@(%reg)`),
//! which hands the consumer the first bytes of the buffer instead of its
//! address — a semantic difference consumer scripts cannot ignore. To stay
//! Core-compatible, byte-buffer arguments are declared `uint64_t` in
//! `probes.d` and fed the buffer address. [`ArgSpec::prepare_type`] records
//! the pointer type callers see.
//!
//! String arguments need no such workaround: the `usdt` crate's `char*`
//! declaration generates the by-value pointer operand Core's probes use
//! (verified in `usdt-impl`'s STAPSDT operand formatter, and asserted
//! end-to-end by the test that compares the built artifact's note strings).

/// One probe argument.
#[derive(Debug)]
pub struct ArgSpec {
    /// Type written in `probes.d`, the generator input.
    pub d_type: &'static str,
    /// Type the probe-crate prepare closure hands to the emitter.
    ///
    /// Byte buffers appear as `*const u8` and are converted to the buffer
    /// address for the emitter; integer arguments use the corresponding Rust
    /// scalar (`i32`, `i64`, `u64`), and `char*` values use Rust string types
    /// (`&'static str` or `String`).
    pub prepare_type: &'static str,
    /// Type published in Bitcoin Core `doc/tracing.md`.
    pub core_doc: &'static str,
    /// Expected `size@` prefix of the `SystemTap` argument layout string.
    ///
    /// The leading `-` marks a signed argument. Pointers and strings are
    /// pointer-sized unsigned (`8@` on a 64-bit target).
    pub layout_prefix: &'static str,
}

/// One Core-compatible probe.
#[derive(Debug)]
pub struct ProbeSpec {
    /// USDT provider name (`validation`, `mempool`, `net`).
    pub provider: &'static str,
    /// USDT probe name, e.g. `block_connected`.
    pub name: &'static str,
    /// Arguments in emission order.
    pub args: &'static [ArgSpec],
}

/// `validation:block_connected`.
///
/// Core passes 64-bit values for arguments 5 and 6 (`int64_t nSigOpsCost`,
/// `int64_t` nanosecond duration); its `doc/tracing.md` documents `uint64`.
/// The shipped binary's SDT notes say `-8@` (signed) for both, and this
/// crate matches the binary because that is what consumer scripts bind to.
pub const BLOCK_CONNECTED: ProbeSpec = ProbeSpec {
    provider: "validation",
    name: "block_connected",
    args: &[
        ArgSpec {
            d_type: "uint64_t",
            prepare_type: "*const u8",
            core_doc: "Block Header Hash as pointer to unsigned chars (32 bytes in little-endian)",
            layout_prefix: "8@",
        },
        ArgSpec {
            d_type: "int32_t",
            prepare_type: "i32",
            core_doc: "Block Height as int32",
            layout_prefix: "-4@",
        },
        ArgSpec {
            d_type: "uint64_t",
            prepare_type: "u64",
            core_doc: "Transactions in the Block as uint64",
            layout_prefix: "8@",
        },
        ArgSpec {
            d_type: "int32_t",
            prepare_type: "i32",
            core_doc: "Inputs spent in the Block as int32",
            layout_prefix: "-4@",
        },
        ArgSpec {
            d_type: "int64_t",
            prepare_type: "i64",
            core_doc: "SigOps in the Block (excluding coinbase SigOps) as uint64 \
                       (int64 in Core's implementation; the exclusion is Core's \
                       doc text — the binary counts the coinbase's legacy SigOps \
                       like every other transaction)",
            layout_prefix: "-8@",
        },
        ArgSpec {
            d_type: "int64_t",
            prepare_type: "i64",
            core_doc: "Time it took to connect the Block in nanoseconds as uint64 \
                       (int64 in Core's implementation)",
            layout_prefix: "-8@",
        },
    ],
};

/// `mempool:added`.
pub const ADDED: ProbeSpec = ProbeSpec {
    provider: "mempool",
    name: "added",
    args: &[
        ArgSpec {
            d_type: "uint64_t",
            prepare_type: "*const u8",
            core_doc: "Transaction ID (hash) as pointer to unsigned chars (32 bytes in little-endian)",
            layout_prefix: "8@",
        },
        ArgSpec {
            d_type: "int32_t",
            prepare_type: "i32",
            core_doc: "Transaction virtual size as int32",
            layout_prefix: "-4@",
        },
        ArgSpec {
            d_type: "int64_t",
            prepare_type: "i64",
            core_doc: "Transaction fee as int64",
            layout_prefix: "-8@",
        },
    ],
};

/// `mempool:removed`.
pub const REMOVED: ProbeSpec = ProbeSpec {
    provider: "mempool",
    name: "removed",
    args: &[
        ArgSpec {
            d_type: "uint64_t",
            prepare_type: "*const u8",
            core_doc: "Transaction ID (hash) as pointer to unsigned chars (32 bytes in little-endian)",
            layout_prefix: "8@",
        },
        ArgSpec {
            d_type: "char*",
            prepare_type: "&'static str",
            core_doc: "Removal reason as pointer to C-style String (max. length 9 characters)",
            layout_prefix: "8@",
        },
        ArgSpec {
            d_type: "int32_t",
            prepare_type: "i32",
            core_doc: "Transaction virtual size as int32",
            layout_prefix: "-4@",
        },
        ArgSpec {
            d_type: "int64_t",
            prepare_type: "i64",
            core_doc: "Transaction fee as int64",
            layout_prefix: "-8@",
        },
        ArgSpec {
            d_type: "uint64_t",
            prepare_type: "u64",
            core_doc: "Transaction mempool entry time (epoch) as uint64",
            layout_prefix: "8@",
        },
    ],
};

/// `net:inbound_message`.
pub const INBOUND_MESSAGE: ProbeSpec = ProbeSpec {
    provider: "net",
    name: "inbound_message",
    args: &[
        ArgSpec {
            d_type: "int64_t",
            prepare_type: "i64",
            core_doc: "Peer ID as int64",
            layout_prefix: "-8@",
        },
        ArgSpec {
            d_type: "char*",
            prepare_type: "String",
            core_doc: "Peer Address and Port as pointer to C-style String \
                       (normally up to 68 characters)",
            layout_prefix: "8@",
        },
        ArgSpec {
            d_type: "char*",
            prepare_type: "String",
            core_doc: "Connection Type as pointer to C-style String (max. length 20 characters)",
            layout_prefix: "8@",
        },
        ArgSpec {
            d_type: "char*",
            prepare_type: "String",
            core_doc: "Message Type as pointer to C-style String (max. length 20 characters)",
            layout_prefix: "8@",
        },
        ArgSpec {
            d_type: "uint64_t",
            prepare_type: "u64",
            core_doc: "Message Size in bytes as uint64",
            layout_prefix: "8@",
        },
        ArgSpec {
            d_type: "uint64_t",
            prepare_type: "*const u8",
            core_doc: "Message Bytes as pointer to unsigned chars (i.e. bytes)",
            layout_prefix: "8@",
        },
    ],
};

/// `net:outbound_message`.
///
/// Identical ABI to [`INBOUND_MESSAGE`].
pub const OUTBOUND_MESSAGE: ProbeSpec = ProbeSpec {
    provider: "net",
    name: "outbound_message",
    args: INBOUND_MESSAGE.args,
};

/// Every probe this crate defines, in canonical order.
pub const PROBES: &[ProbeSpec] = &[
    BLOCK_CONNECTED,
    ADDED,
    REMOVED,
    INBOUND_MESSAGE,
    OUTBOUND_MESSAGE,
];

/// Returns the expected `layout_prefix` sequence of `spec`.
#[must_use]
pub fn layout_prefixes(spec: &ProbeSpec) -> Vec<&'static str> {
    spec.args.iter().map(|arg| arg.layout_prefix).collect()
}
