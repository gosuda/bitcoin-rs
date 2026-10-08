//! Shared unit-test helpers.

use core::fmt::Display;

pub(crate) trait OrFail<T> {
    #[track_caller]
    fn or_fail(self, context: &str) -> T;
}

impl<T, E: Display> OrFail<T> for Result<T, E> {
    fn or_fail(self, context: &str) -> T {
        match self {
            Ok(value) => value,
            Err(error) => panic!("{context}: {error}"),
        }
    }
}

impl<T> OrFail<T> for Option<T> {
    fn or_fail(self, context: &str) -> T {
        match self {
            Some(value) => value,
            None => panic!("{context}"),
        }
    }
}

pub(crate) type TestResult = Result<(), Box<dyn std::error::Error>>;
