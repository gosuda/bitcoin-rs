//! Workspace release version surfaced for wire and RPC user-agent strings.

pub const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

pub const USER_AGENT: &str = concat!("/bitcoin-rs:", env!("CARGO_PKG_VERSION"), "/");

/// Core's `MAX_SUBVERSION_LENGTH` (`src/net.h`): the composed subversion
/// string may not exceed this many bytes.
pub const MAX_SUBVERSION_LENGTH: usize = 256;

/// Core's `SAFE_CHARS_UA_COMMENT` (`src/util/strencodings.h`): the BIP-0014
/// comment subset — ASCII alphanumerics plus ` .,;-_?@`.
const UA_COMMENT_SAFE_EXTRA: &str = " .,;-_?@";

/// Whether one `-uacomment` value is within Core's BIP-0014 safe subset.
#[must_use]
pub fn ua_comment_is_safe(comment: &str) -> bool {
    comment
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || UA_COMMENT_SAFE_EXTRA.contains(c))
}

/// The subversion string advertised in the version handshake and reported by
/// `getnetworkinfo`.
///
/// Core's `FormatSubVersion` shape: `/name:version(c1; c2)/` with the
/// parenthesized comments omitted when there are none, built on this node's
/// [`USER_AGENT`] base.
#[must_use]
pub fn sub_version(ua_comments: &[String]) -> String {
    if ua_comments.is_empty() {
        return USER_AGENT.to_owned();
    }
    let comments = ua_comments.join("; ");
    format!("{}({comments})/", USER_AGENT.trim_end_matches('/'))
}

/// Numeric client version, by Bitcoin Core's `CLIENT_VERSION` arithmetic.
/// `10000 * major + 100 * minor + patch`, read from the same string the user
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
    use super::{
        MAX_SUBVERSION_LENGTH, PKG_VERSION, USER_AGENT, client_version, sub_version,
        ua_comment_is_safe,
    };

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

    /// Core `FormatSubVersion` (`src/clientversion.cpp`) and `InitSubversion`
    /// (`src/init.cpp`): no comments leaves the bare `/name:version/`, several
    /// comments join with `"; "` inside one parenthesized group directly
    /// after the version and before the closing slash.
    #[test]
    fn sub_version_composes_comments_in_cores_shape() {
        assert_eq!(sub_version(&[]), USER_AGENT);
        assert_eq!(
            sub_version(&["testnode0".to_owned()]),
            format!("{}(testnode0)/", USER_AGENT.trim_end_matches('/'))
        );
        assert_eq!(
            sub_version(&["testnode0".to_owned(), "foo".to_owned()]),
            format!("{}(testnode0; foo)/", USER_AGENT.trim_end_matches('/'))
        );
    }

    /// Core's `SAFE_CHARS_UA_COMMENT` accepts ASCII alphanumerics plus
    /// ` .,;-_?@` and nothing else (`util_tests.cpp` pins the complement).
    #[test]
    fn ua_comment_safety_matches_cores_bip14_subset() {
        for accepted in ["testnode0", "foo bar", "a.,;-_?@"] {
            assert!(ua_comment_is_safe(accepted), "{accepted:?} is safe");
        }
        for refused in ["/", ":", "(", ")", "\u{20b3}", "\u{1f3c3}", "\0"] {
            assert!(!ua_comment_is_safe(refused), "{refused:?} is unsafe");
        }
        assert!("a".repeat(MAX_SUBVERSION_LENGTH).len() <= MAX_SUBVERSION_LENGTH);
    }
}
