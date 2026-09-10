//! Shared journal segment filename grammar; no file mutation or cursor state.

/// Maximum serialized segment name length sanity bound.
const SEGMENT_NAME_MAX: usize = 32;
/// Generations are padded to at least ten decimal digits.
const SEGMENT_GEN_WIDTH: usize = 10;

pub(super) fn segment_name(generation: u64) -> String {
    format!("segment-{generation:0SEGMENT_GEN_WIDTH$}.log")
}

pub(super) fn parse_segment_name(name: &str) -> Option<u64> {
    let raw = name.strip_prefix("segment-")?.strip_suffix(".log")?;
    if raw.is_empty() || raw.len() > SEGMENT_NAME_MAX || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    raw.parse().ok()
}

#[cfg(test)]
mod tests;
