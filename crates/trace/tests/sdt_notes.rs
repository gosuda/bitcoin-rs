//! Asserts the built artifact's `SystemTap` SDT notes match the documented
//! Bitcoin Core probe ABI.
//!
//! This is the host-portable half of the acceptance evidence: it parses the
//! ELF `.note.stapsdt` notes of a built binary and checks provider names,
//! probe names, and argument layout strings against [`probe_abi`]. Run with
//! `SDT_ELF=<binary>` to check an arbitrary artifact (e.g. the node binary
//! built on Linux); by default it checks the test binary itself.
//!
//! On non-ELF hosts (macOS emits Mach-O/DOF instead of `.note.stapsdt`) the
//! note assertions are skipped and only the portable ABI-table checks run.

use std::fs;
use std::path::PathBuf;

use bitcoin_rs_trace::probe_abi;

/// One parsed `SystemTap` SDT note.
struct SdtNote {
    provider: String,
    name: String,
    args: String,
    semaphore: u64,
}

/// Outcome of [`parse_sdt_notes`].
enum SdtParse {
    /// Parsed notes and the ELF machine id for operand selection.
    Notes(u16, Vec<SdtNote>),
    /// Not a little-endian ELF64 binary (e.g. Mach-O on macOS carries DOF
    /// instead of SDT notes): there is legitimately nothing to parse.
    NotElf,
    /// The artifact claims ELF64 but its note sections are unparsable: a
    /// damaged artifact or a parser regression that must fail the test
    /// rather than skip the assertions.
    Malformed(&'static str),
}

/// Parses little-endian ELF64 `NT_STAPSDT` notes out of `bytes`.
fn parse_sdt_notes(bytes: &[u8]) -> SdtParse {
    if bytes.len() < 64 || &bytes[..4] != b"\x7fELF" || bytes[4] != 2 || bytes[5] != 1 {
        return SdtParse::NotElf;
    }
    match parse_elf64_sdt_notes(bytes) {
        Some((machine, notes)) => SdtParse::Notes(machine, notes),
        None => SdtParse::Malformed("ELF64 binary with unparsable note sections"),
    }
}

/// ELF64 section walk behind [`parse_sdt_notes`]; `None` means a malformed
/// binary, never a non-ELF one (the caller has already checked the magic).
///
/// Returns the ELF machine id alongside the notes so the caller can select
/// the architecture's register-operand spelling.
fn parse_elf64_sdt_notes(bytes: &[u8]) -> Option<(u16, Vec<SdtNote>)> {
    let read_u16 = |offset: usize| -> Option<u16> {
        Some(u16::from_le_bytes(
            bytes.get(offset..offset + 2)?.try_into().ok()?,
        ))
    };
    let read_u32 = |offset: usize| -> Option<u32> {
        Some(u32::from_le_bytes(
            bytes.get(offset..offset + 4)?.try_into().ok()?,
        ))
    };
    let read_u64 = |offset: usize| -> Option<u64> {
        Some(u64::from_le_bytes(
            bytes.get(offset..offset + 8)?.try_into().ok()?,
        ))
    };

    let machine = read_u16(18)?;
    let section_header_offset = usize::try_from(read_u64(40)?).ok()?;
    let section_header_size = usize::from(read_u16(58)?);
    let section_count = usize::from(read_u16(60)?);
    let mut notes = Vec::new();
    for index in 0..section_count {
        let header = section_header_offset + index * section_header_size;
        let section_type = read_u32(header + 4)?;
        if section_type != 7 {
            continue;
        }
        let section_offset = usize::try_from(read_u64(header + 24)?).ok()?;
        let section_size = usize::try_from(read_u64(header + 32)?).ok()?;
        let section = bytes.get(section_offset..section_offset.checked_add(section_size)?)?;
        let mut cursor = 0usize;
        while cursor + 12 <= section.len() {
            let name_size = usize::try_from(read_le_u32(section, cursor)?).ok()?;
            let desc_size = usize::try_from(read_le_u32(section, cursor + 4)?).ok()?;
            let note_type = read_le_u32(section, cursor + 8)?;
            cursor += 12;
            let name_end = cursor.checked_add(name_size)?;
            let name = section.get(cursor..name_end)?;
            cursor = align4(name_end);
            let desc_end = cursor.checked_add(desc_size)?;
            let desc = section.get(cursor..desc_end)?;
            cursor = align4(desc_end);
            if name.get(..7) != Some(b"stapsdt") || note_type != 3 || desc_size < 24 {
                continue;
            }
            let semaphore = read_le_u64(desc, 16)?;
            let strings = &desc[24..];
            let mut parts = strings.split(|byte| *byte == 0);
            let provider = parts.next().unwrap_or_default().to_vec();
            let probe = parts.next().unwrap_or_default().to_vec();
            let args = parts.next().unwrap_or_default().to_vec();
            notes.push(SdtNote {
                provider: String::from_utf8_lossy(&provider).into_owned(),
                name: String::from_utf8_lossy(&probe).into_owned(),
                args: String::from_utf8_lossy(&args).into_owned(),
                semaphore,
            });
        }
    }
    notes.sort_by(|left, right| (&left.provider, &left.name).cmp(&(&right.provider, &right.name)));
    Some((machine, notes))
}

fn read_le_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_le_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

const fn align4(offset: usize) -> usize {
    offset.saturating_add(3) & !3
}

/// Separator between a layout entry's `size@` prefix and its operand.
const ARG_SEPARATOR: char = '@';

/// x86-64 register operand spelling per argument index and byte width.
const X86_REGISTERS: [&[&str]; 4] = [
    &["%dil", "%sil", "%dl", "%cl", "%r8b", "%r9b"],
    &["%di", "%si", "%dx", "%cx", "%r8w", "%r9w"],
    &["%edi", "%esi", "%edx", "%ecx", "%r8d", "%r9d"],
    &["%rdi", "%rsi", "%rdx", "%rcx", "%r8", "%r9"],
];

/// Returns the register-spelling table index for a `probes.d` type's width.
fn width_index(d_type: &str) -> usize {
    match d_type {
        "int8_t" | "uint8_t" => 0,
        "int16_t" | "uint16_t" => 1,
        "int32_t" | "uint32_t" => 2,
        "int64_t" | "uint64_t" | "char*" => 3,
        other => panic!("unhandled probe argument type `{other}`"),
    }
}

/// Returns the expected full `SystemTap` layout string for `spec` on
/// x86-64, `None` on other architectures.
///
/// The operand half is architecture- and register-allocation specific: this
/// crate's generator passes arguments in the platform ABI registers, so the
/// spelling is deterministic per architecture — but only x86-64's spellings
/// are verified (the width-dependent `%edi`/`%rdi` table below). `AArch64`'s
/// generator may spell narrower arguments as `w`-registers, which upstream
/// marks untested, so other architectures compare `size@` prefixes only.
/// A consumer binds to both halves, so the verified architecture asserts
/// both — Core's own binaries use a different register assignment only
/// because the compiler allocated different registers at its probe sites.
fn expected_layout(spec: &probe_abi::ProbeSpec, machine: u16) -> Option<String> {
    // EM_X86_64: register name depends on the argument's width.
    if machine != 0x3E {
        return None;
    }
    let mut operands = Vec::new();
    for (index, arg) in spec.args.iter().enumerate() {
        // `layout_prefix` already ends in ARG_SEPARATOR (`size@`), matching
        // the SystemTap grammar's `Nf@OP`; only the operand is appended.
        operands.push(format!(
            "{}{}",
            arg.layout_prefix,
            X86_REGISTERS[width_index(arg.d_type)][index]
        ));
    }
    Some(operands.join(" "))
}

fn layout_prefixes_of(layout: &str) -> Vec<&str> {
    layout
        .split_whitespace()
        .map(|entry| {
            entry
                .split_inclusive(ARG_SEPARATOR)
                .next()
                .unwrap_or_default()
        })
        .collect()
}

/// Portable ABI-table assertions: the spec table itself must match Core's
/// published argument layout for every probe this slice implements.
#[test]
fn probe_table_matches_core_argument_layout() {
    let expected: &[(&str, &[&str])] = &[
        (
            "validation:block_connected",
            &["8@", "-4@", "8@", "-4@", "-8@", "-8@"],
        ),
        ("mempool:added", &["8@", "-4@", "-8@"]),
        ("mempool:removed", &["8@", "8@", "-4@", "-8@", "8@"]),
        (
            "net:inbound_message",
            &["-8@", "8@", "8@", "8@", "8@", "8@"],
        ),
        (
            "net:outbound_message",
            &["-8@", "8@", "8@", "8@", "8@", "8@"],
        ),
    ];
    assert_eq!(probe_abi::PROBES.len(), expected.len());
    for (spec, (name, prefixes)) in probe_abi::PROBES.iter().zip(expected) {
        let full_name = format!("{}:{}", spec.provider, spec.name);
        assert_eq!(&full_name, name);
        assert_eq!(&probe_abi::layout_prefixes(spec), prefixes);
    }
}

/// Forces monomorphisation of every probe wrapper so the test binary links
/// each probe's `.note.stapsdt` note.
///
/// The wrappers are generic over their `prepare` closures and the generated
/// note assembly is emitted per monomorphization: an artifact that never
/// instantiates a wrapper carries no note for it, and the assertion below
/// would fail with `missing SDT note`. The guard is opaque to the optimizer
/// and always false, so the calls are compiled in (notes linked) but never
/// run — no probe fires while the harness parses the binary.
#[cfg(feature = "usdt")]
#[inline(never)]
fn instantiate_probes() {
    if std::hint::black_box(false) {
        let hash = [0u8; 32];
        bitcoin_rs_trace::block_connected(|| (hash.as_ptr(), 0, 0, 0, 0, 0));
        bitcoin_rs_trace::added(|| (hash.as_ptr(), 0, 0));
        bitcoin_rs_trace::removed(|| (hash.as_ptr(), "block", 0, 0, 0));
        bitcoin_rs_trace::inbound_message(|| {
            (
                0,
                String::new(),
                String::new(),
                String::new(),
                0,
                hash.as_ptr(),
            )
        });
        bitcoin_rs_trace::outbound_message(|| {
            (
                0,
                String::new(),
                String::new(),
                String::new(),
                0,
                hash.as_ptr(),
            )
        });
    }
}

/// Asserts the artifact's embedded SDT notes carry Core's provider, probe
/// names, and argument layout prefixes.
#[test]
fn embedded_sdt_notes_match_core_layout() -> Result<(), Box<dyn std::error::Error>> {
    // Instantiate every probe before the test binary is read back: the notes
    // are link-time artifacts of these monomorphizations.
    #[cfg(feature = "usdt")]
    instantiate_probes();
    let path = match std::env::var_os("SDT_ELF") {
        Some(path) => PathBuf::from(path),
        None => std::env::current_exe()?,
    };
    let bytes = fs::read(&path)?;
    if !cfg!(feature = "usdt") {
        // Feature-off artifact: the whole point of the default build is that
        // no probe notes leak into it, so assert exactly that for whichever
        // artifact is under test instead of skipping silently.
        let notes = match parse_sdt_notes(&bytes) {
            SdtParse::NotElf => Vec::new(),
            SdtParse::Malformed(reason) => {
                return Err(format!("{}: {reason}", path.display()).into());
            }
            SdtParse::Notes(_, notes) => notes,
        };
        assert!(
            notes.iter().all(|note| probe_abi::PROBES
                .iter()
                .all(|spec| { note.provider != spec.provider || note.name != spec.name })),
            "a feature-off build must embed no Core-compatible probe notes"
        );
        return Ok(());
    }
    let (machine, notes) = match parse_sdt_notes(&bytes) {
        // Non-ELF artifact (Mach-O on macOS carries DOF instead of SDT
        // notes). The portable table test above still guards the ABI.
        SdtParse::NotElf => {
            eprintln!(
                "skipping SDT note assertion: {} is not a little-endian ELF64 binary",
                path.display()
            );
            return Ok(());
        }
        SdtParse::Malformed(reason) => {
            return Err(format!("{}: {reason}", path.display()).into());
        }
        SdtParse::Notes(machine, notes) => (machine, notes),
    };
    for spec in probe_abi::PROBES {
        let note = notes
            .iter()
            .find(|note| note.provider == spec.provider && note.name == spec.name)
            .ok_or_else(|| format!("missing SDT note {}:{}", spec.provider, spec.name))?;
        if let Some(expected) = expected_layout(spec, machine) {
            // Full-string check: both the size/sign prefix and the operand
            // form (register-direct like Core's `8@%reg`, never the
            // dereferencing `8@(%reg)` that binds a different value).
            assert_eq!(
                note.args, expected,
                "argument layout of {}:{} must match byte-for-byte",
                spec.provider, spec.name,
            );
        } else {
            assert_eq!(
                layout_prefixes_of(&note.args),
                probe_abi::layout_prefixes(spec),
                "argument layout of {}:{} does not match the Core-compatible table \
                 (actual `{}`)",
                spec.provider,
                spec.name,
                note.args,
            );
        }
        assert_ne!(
            note.semaphore, 0,
            "SDT note {}:{} carries no semaphore address",
            spec.provider, spec.name
        );
    }
    Ok(())
}
