pub(crate) fn parse_ascii_decimal<T: core::str::FromStr>(text: &str) -> Option<T> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::parse_ascii_decimal;

    #[test]
    fn parse_ascii_decimal_accepts_only_nonempty_ascii_digits() {
        assert_eq!(parse_ascii_decimal::<u32>("0"), Some(0));
        assert_eq!(parse_ascii_decimal::<u32>("007"), Some(7));
        assert_eq!(
            parse_ascii_decimal::<u64>("18446744073709551615"),
            Some(u64::MAX)
        );
        assert_eq!(parse_ascii_decimal::<u32>(""), None);
        assert_eq!(parse_ascii_decimal::<u32>("+1"), None);
        assert_eq!(parse_ascii_decimal::<u32>("-1"), None);
        assert_eq!(parse_ascii_decimal::<u32>(" 1"), None);
        assert_eq!(parse_ascii_decimal::<u32>("1 "), None);
        assert_eq!(parse_ascii_decimal::<u32>("1a"), None);
        assert_eq!(parse_ascii_decimal::<u32>("١"), None);
        assert_eq!(parse_ascii_decimal::<u32>("18446744073709551616"), None);
    }
}
