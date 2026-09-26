//! The one runtime validation-engine selector.
//!
//! Capability is not selection: the `kernel` Cargo feature means "bitcoinkernel
//! support is compiled into this build" and never selects an engine by itself.
//! Selection is [`ValidationEngine`] alone — configured once as
//! `validation.engine` (TOML `validation_engine`, `BITCOIN_RS_VALIDATION_ENGINE`,
//! `--validation-engine`) and passed explicitly to every seam that dispatches
//! between the script backends. [`ValidationEngine::Native`] is the default in
//! every build.

use core::fmt;

/// Which script-verification engine the validation pipeline runs.
///
/// Both variants name a selection in every build, including builds without the
/// `kernel` feature, so a configuration asking for an engine this build lacks
/// is rejected with the unsupported-build error at configuration validation —
/// before any chain state or worker exists — instead of dying at a parse layer
/// with an unrelated message. [`Self::is_supported`] is the capability check.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ValidationEngine {
    /// The native Rust interpreter in `bitcoin-rs-script`: legacy, P2SH,
    /// `SegWit` v0, and Taproot key-path and script-path spends. Compiled in
    /// every build and always supported.
    #[default]
    Native,
    /// Bitcoin Core's C++ consensus engine (`libbitcoinkernel`). Selecting it
    /// on a build without the `kernel` feature fails closed with
    /// [`crate::ConsensusError::UnsupportedEngine`].
    Kernel,
}

impl ValidationEngine {
    /// Every engine this type can name.
    pub const ALL: &'static [Self] = &[Self::Native, Self::Kernel];

    /// Returns the stable configuration spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Kernel => "kernel",
        }
    }

    /// Whether this engine's implementation is compiled into the current
    /// build. This is capability only; it says nothing about selection.
    #[must_use]
    pub const fn is_supported(self) -> bool {
        match self {
            Self::Native => true,
            Self::Kernel => cfg!(feature = "kernel"),
        }
    }

    /// Parses a configuration spelling, case-insensitively.
    ///
    /// `kernel` parses in every build so an unsupported selection produces the
    /// unsupported-build error at configuration validation rather than a parse
    /// error at one input layer.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "native" => Some(Self::Native),
            "kernel" => Some(Self::Kernel),
            _ => None,
        }
    }
}

impl fmt::Display for ValidationEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ValidationEngine {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value).ok_or_else(|| format!("unknown validation engine {value}"))
    }
}

use std::str::FromStr;

#[cfg(test)]
mod tests {
    use super::ValidationEngine;

    #[test]
    fn native_is_the_default_and_is_supported_in_every_build() {
        assert_eq!(ValidationEngine::default(), ValidationEngine::Native);
        assert!(ValidationEngine::Native.is_supported());
        assert_eq!(ValidationEngine::Native.as_str(), "native");
        assert_eq!(ValidationEngine::Kernel.as_str(), "kernel");
    }

    #[test]
    fn kernel_parses_in_every_build_but_is_only_supported_when_compiled() {
        assert_eq!(
            ValidationEngine::parse("kernel"),
            Some(ValidationEngine::Kernel)
        );
        assert_eq!(
            ValidationEngine::Kernel.is_supported(),
            cfg!(feature = "kernel"),
            "capability tracks the `kernel` feature only"
        );
    }

    #[test]
    fn spellings_are_case_insensitive_and_unknown_values_fail() {
        assert_eq!(
            ValidationEngine::parse(" Native "),
            Some(ValidationEngine::Native)
        );
        assert_eq!(
            ValidationEngine::parse("KERNEL"),
            Some(ValidationEngine::Kernel)
        );
        assert_eq!(ValidationEngine::parse("lenient"), None);
    }
}
