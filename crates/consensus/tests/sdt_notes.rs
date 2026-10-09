//! Checks `probes.d` against Core's ABI and the artifact's embedded SDT notes.
//! `SDT_ELF` selects another artifact; otherwise the test reads itself.
//! Non-ELF hosts retain the declaration check but skip ELF note assertions.

use std::fs;
use std::io;
use std::path::PathBuf;

#[derive(Debug)]
struct ProbeDef {
    provider: String,
    name: String,
    args: Vec<String>,
}

/// Core's released binary ABI, in provider/probe/argument order.
/// Block-connected arguments 5/6 are signed despite Core's doc/tracing.md.
/// Buffers are pointers by value (`8@`), not dereferenced (`8@(%reg)`).
const CORE_ABI: &[(&str, &str, &[&str])] = &[
    (
        "validation",
        "block_connected",
        &["8@", "-4@", "8@", "-4@", "-8@", "-8@"],
    ),
    ("mempool", "added", &["8@", "-4@", "-8@"]),
    ("mempool", "removed", &["8@", "8@", "-4@", "-8@", "8@"]),
    (
        "net",
        "inbound_message",
        &["-8@", "8@", "8@", "8@", "8@", "8@"],
    ),
    (
        "net",
        "outbound_message",
        &["-8@", "8@", "8@", "8@", "8@", "8@"],
    ),
];

fn layout_prefix(d_type: &str) -> &'static str {
    match d_type {
        "int8_t" => "-1@",
        "uint8_t" => "1@",
        "int16_t" => "-2@",
        "uint16_t" => "2@",
        "int32_t" => "-4@",
        "uint32_t" => "4@",
        "int64_t" => "-8@",
        // `char*` and byte-buffer `uint64_t` are pointer-sized unsigned.
        "uint64_t" | "char*" => "8@",
        other => panic!("unhandled probe argument type `{other}`"),
    }
}

fn layout_prefixes(def: &ProbeDef) -> Vec<&'static str> {
    def.args.iter().map(|arg| layout_prefix(arg)).collect()
}

/// Parses the declaration-order subset of `DTrace` syntax used by `probes.d`.
fn parse_probes_d(text: &str) -> Vec<ProbeDef> {
    // `probes.d` comments are all `/* */` blocks.
    let mut stripped = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("/*") {
        stripped.push_str(&rest[..start]);
        rest = &rest[rest.find("*/").map_or(rest.len(), |end| end + 2)..];
    }
    stripped.push_str(rest);

    let mut probes = Vec::new();
    for block in stripped.split("provider").skip(1) {
        let Some((head, _)) = block.split_once('}') else {
            continue;
        };
        let Some((provider, body)) = head.split_once('{') else {
            continue;
        };
        let provider = provider.trim().to_owned();
        for decl in body.split(';') {
            let decl = decl.trim();
            let Some(sig) = decl.strip_prefix("probe") else {
                continue;
            };
            let Some((name, args)) = sig.trim().split_once('(') else {
                continue;
            };
            probes.push(ProbeDef {
                provider: provider.clone(),
                name: name.trim().to_owned(),
                args: args
                    .trim_end_matches(')')
                    .split(',')
                    .map(|arg| arg.trim().to_owned())
                    .filter(|arg| !arg.is_empty())
                    .collect(),
            });
        }
    }
    probes
}

fn probes_d() -> io::Result<Vec<ProbeDef>> {
    let text = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/probes.d"))?;
    let probes = parse_probes_d(&text);
    assert!(!probes.is_empty(), "probes.d declares no probes");
    Ok(probes)
}

struct SdtNote {
    provider: String,
    name: String,
    args: String,
    semaphore: u64,
}

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

fn parse_sdt_notes(bytes: &[u8]) -> SdtParse {
    if bytes.len() < 64 || &bytes[..4] != b"\x7fELF" || bytes[4] != 2 || bytes[5] != 1 {
        return SdtParse::NotElf;
    }
    match parse_elf64_sdt_notes(bytes) {
        Some((machine, notes)) => SdtParse::Notes(machine, notes),
        None => SdtParse::Malformed("ELF64 binary with unparsable note sections"),
    }
}

/// Returns the ELF machine and notes; `None` indicates malformed ELF64.
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

const ARG_SEPARATOR: char = '@';

const X86_REGISTERS: [&[&str]; 4] = [
    &["%dil", "%sil", "%dl", "%cl", "%r8b", "%r9b"],
    &["%di", "%si", "%dx", "%cx", "%r8w", "%r9w"],
    &["%edi", "%esi", "%edx", "%ecx", "%r8d", "%r9d"],
    &["%rdi", "%rsi", "%rdx", "%rcx", "%r8", "%r9"],
];

fn width_index(d_type: &str) -> usize {
    match d_type {
        "int8_t" | "uint8_t" => 0,
        "int16_t" | "uint16_t" => 1,
        "int32_t" | "uint32_t" => 2,
        "int64_t" | "uint64_t" | "char*" => 3,
        other => panic!("unhandled probe argument type `{other}`"),
    }
}

/// Full operand spelling is verified on x86-64; other architectures check
/// size/sign prefixes because register allocation and spelling differ.
fn expected_layout(def: &ProbeDef, machine: u16) -> Option<String> {
    // EM_X86_64: register name depends on the argument's width.
    if machine != 0x3E {
        return None;
    }
    let mut operands = Vec::new();
    for (index, arg) in def.args.iter().enumerate() {
        operands.push(format!(
            "{}{}",
            layout_prefix(arg),
            X86_REGISTERS[width_index(arg)][index]
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

/// Matches Core's providers, probes and argument prefixes in order.
#[test]
fn probes_d_matches_core_argument_layout() -> io::Result<()> {
    let probes = probes_d()?;
    assert_eq!(probes.len(), CORE_ABI.len());
    for (def, (provider, name, prefixes)) in probes.iter().zip(CORE_ABI) {
        assert_eq!(
            (def.provider.as_str(), def.name.as_str()),
            (*provider, *name)
        );
        assert_eq!(&layout_prefixes(def), prefixes);
    }
    Ok(())
}

/// Link every wrapper's SDT note without firing probes: `black_box(false)`
/// retains the monomorphizations while preventing argument preparation.
#[cfg(feature = "usdt")]
#[inline(never)]
fn instantiate_probes() {
    if std::hint::black_box(false) {
        let hash = [0u8; 32];
        bitcoin_rs_consensus::trace::block_connected(|| (hash.as_ptr(), 0, 0, 0, 0, 0));
        bitcoin_rs_consensus::trace::added(|| (hash.as_ptr(), 0, 0));
        bitcoin_rs_consensus::trace::removed(|| (hash.as_ptr(), "block", 0, 0, 0));
        let message = || {
            (
                0,
                String::new(),
                String::new(),
                String::new(),
                0,
                hash.as_ptr(),
            )
        };
        bitcoin_rs_consensus::trace::inbound_message(message);
        bitcoin_rs_consensus::trace::outbound_message(message);
    }
}

#[test]
fn embedded_sdt_notes_match_core_layout() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "usdt")]
    instantiate_probes();
    let path = match std::env::var_os("SDT_ELF") {
        Some(path) => PathBuf::from(path),
        None => std::env::current_exe()?,
    };
    let bytes = fs::read(&path)?;
    let probes = probes_d()?;
    if !cfg!(feature = "usdt") {
        let notes = match parse_sdt_notes(&bytes) {
            SdtParse::NotElf => Vec::new(),
            SdtParse::Malformed(reason) => {
                return Err(format!("{}: {reason}", path.display()).into());
            }
            SdtParse::Notes(_, notes) => notes,
        };
        assert!(
            notes.iter().all(|note| probes
                .iter()
                .all(|def| { note.provider != def.provider || note.name != def.name })),
            "a feature-off build must embed no Core-compatible probe notes"
        );
        return Ok(());
    }
    let (machine, notes) = match parse_sdt_notes(&bytes) {
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
    for def in &probes {
        let note = notes
            .iter()
            .find(|note| note.provider == def.provider && note.name == def.name)
            .ok_or_else(|| format!("missing SDT note {}:{}", def.provider, def.name))?;
        if let Some(expected) = expected_layout(def, machine) {
            assert_eq!(
                note.args, expected,
                "argument layout of {}:{} must match byte-for-byte",
                def.provider, def.name,
            );
        } else {
            assert_eq!(
                layout_prefixes_of(&note.args),
                layout_prefixes(def),
                "argument layout of {}:{} does not match the Core-compatible table \
                 (actual `{}`)",
                def.provider,
                def.name,
                note.args,
            );
        }
        assert_ne!(
            note.semaphore, 0,
            "SDT note {}:{} carries no semaphore address",
            def.provider, def.name
        );
    }
    Ok(())
}
