//! Workspace release version surfaced for wire and RPC user-agent strings.

/// Current `bitcoin-rs` release version (from `[workspace.package].version`).
pub const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Bitcoin P2P user-agent subversion string (`/bitcoin-rs:<version>/`).
pub const USER_AGENT: &str = concat!("/bitcoin-rs:", env!("CARGO_PKG_VERSION"), "/");

/// Numeric client version, by Bitcoin Core's `CLIENT_VERSION` arithmetic.
///
/// `10000 * major + 100 * minor + patch`, read from the same string the user
/// agent carries, so the number a peer sees on the wire and the number
/// `getnetworkinfo` reports move together at release time. A pre-release
/// suffix (`0.4.0-rc1`) ends the numeric part and is ignored, as it is in Core.
#[must_use]
pub fn client_version() -> i64 {
    let mut parts = [0_i64; 3];
    let mut part = 0_usize;
    for byte in PKG_VERSION.bytes() {
        if byte == b'.' {
            part = part.saturating_add(1);
            if part >= parts.len() {
                break;
            }
        } else if byte.is_ascii_digit() {
            let digit = i64::from(byte.saturating_sub(b'0'));
            parts[part] = parts[part].saturating_mul(10).saturating_add(digit);
        } else {
            break;
        }
    }
    parts[0]
        .saturating_mul(10_000)
        .saturating_add(parts[1].saturating_mul(100))
        .saturating_add(parts[2])
}

#[cfg(test)]
mod tests {
    use super::{PKG_VERSION, USER_AGENT, client_version};

    /// The reported number is derived from the released version, not written
    /// out beside it where the two can drift.
    #[test]
    fn the_client_version_is_the_package_version() {
        let mut expected = 0_i64;
        let mut scale = [10_000_i64, 100, 1].into_iter();
        for field in PKG_VERSION.split('.').take(3) {
            let digits: String = field.chars().take_while(char::is_ascii_digit).collect();
            let value: i64 = digits.parse().unwrap_or(0);
            let Some(scale) = scale.next() else { break };
            expected += value * scale;
        }
        assert_eq!(client_version(), expected);
        assert!(
            USER_AGENT.contains(PKG_VERSION),
            "the user agent carries the same version"
        );
    }
}
