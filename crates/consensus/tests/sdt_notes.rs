use std::fs;
use std::path::PathBuf;

#[path = "sdt_notes_error.rs"]
mod error;
use error::TestError;

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

struct SdtNote {
    provider: String,
    name: String,
    args: String,
    semaphore: u64,
}

enum SdtParse {
    Notes(u16, Vec<SdtNote>),
    NotElf,
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

fn width_index_of_prefix(prefix: &str) -> usize {
    let digits = prefix
        .split_once('@')
        .map(|(digits, _)| digits)
        .unwrap_or_else(|| panic!("unhandled probe operand prefix `{prefix}`"));
    match digits.trim_start_matches('-').parse::<u8>() {
        Ok(1) => 0,
        Ok(2) => 1,
        Ok(4) => 2,
        Ok(8) => 3,
        other => panic!("unhandled probe operand width `{other:?}`"),
    }
}

fn expected_layout(prefixes: &[&str], machine: u16) -> Option<String> {
    if machine != 0x3E {
        return None;
    }
    let mut operands = Vec::new();
    for (index, prefix) in prefixes.iter().enumerate() {
        operands.push(format!(
            "{prefix}{}",
            X86_REGISTERS[width_index_of_prefix(prefix)][index]
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
fn embedded_sdt_notes_match_core_layout() -> Result<(), TestError> {
    #[cfg(feature = "usdt")]
    instantiate_probes();
    let path = match std::env::var_os("SDT_ELF") {
        Some(path) => PathBuf::from(path),
        None => std::env::current_exe()?,
    };
    let bytes = fs::read(&path)?;
    if !cfg!(feature = "usdt") {
        let notes = match parse_sdt_notes(&bytes) {
            SdtParse::NotElf => Vec::new(),
            SdtParse::Malformed(reason) => {
                return Err(TestError::MalformedNote {
                    path: path.display().to_string(),
                    reason,
                });
            }
            SdtParse::Notes(_, notes) => notes,
        };
        assert!(
            notes.iter().all(|note| CORE_ABI
                .iter()
                .all(
                    |(provider, name, _prefixes)| note.provider != *provider || note.name != *name
                )),
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
            return Err(TestError::MalformedNote {
                path: path.display().to_string(),
                reason,
            });
        }
        SdtParse::Notes(machine, notes) => (machine, notes),
    };
    for &(provider, name, prefixes) in CORE_ABI {
        let note = notes
            .iter()
            .find(|note| note.provider == provider && note.name == name)
            .ok_or(TestError::Missing("missing SDT note"))?;
        if let Some(expected) = expected_layout(prefixes, machine) {
            assert_eq!(
                note.args, expected,
                "argument layout of {provider}:{name} must match byte-for-byte"
            );
        } else {
            assert_eq!(
                layout_prefixes_of(&note.args),
                prefixes,
                "argument layout of {provider}:{name} does not match the Core-compatible table \
                 (actual `{}`)",
                note.args,
            );
        }
        assert_ne!(
            note.semaphore, 0,
            "SDT note {provider}:{name} carries no semaphore address"
        );
    }
    Ok(())
}
