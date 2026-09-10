use alloc::string::String;
use alloc::vec::Vec;

use anyhow::Result;

use super::error::EvidenceError;
use super::sample::Sample;

/// One product cell and every sample ever recorded for it.
///
/// An empty history is the honest state of an unmeasured cell; it is kept,
/// never dropped or defaulted.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cell {
    /// Cell identifier from the ledger matrix.
    pub id: String,
    /// Append-only sample history.
    pub samples: Vec<Sample>,
}

/// Schema tag every ledger and evidence file must carry.
pub const LEDGER_SCHEMA: &str = "bitcoin-rs-hot-path-ledger-v2";

/// The cell histories of `docs/benchmarks/hot-path-ledger.toml`.
///
/// Other top-level tables of that file belong to the attribution contract and
/// pass through untouched; this type owns only what a run may append to.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Ledger {
    /// Must equal [`LEDGER_SCHEMA`].
    pub schema: String,
    /// Every declared cell, measured or not.
    pub cells: Vec<Cell>,
    /// Top-level attribution-contract tables owned outside the benchmark tool.
    #[serde(flatten)]
    pub contract: std::collections::BTreeMap<String, toml::Value>,
}

impl Ledger {
    /// Parses ledger TOML and rejects any sample that lacks a full identity.
    pub fn parse(text: &str) -> Result<Self, EvidenceError> {
        let ledger: Self =
            toml::from_str(text).map_err(|error| EvidenceError::Schema(error.to_string()))?;
        if ledger.schema != LEDGER_SCHEMA {
            return Err(EvidenceError::Schema(format!(
                "schema {} is not {LEDGER_SCHEMA}",
                ledger.schema
            )));
        }
        for cell in &ledger.cells {
            for sample in &cell.samples {
                sample.check()?;
            }
        }
        Ok(ledger)
    }

    /// Appends a sample to a declared cell. Repeats are kept: a second run is
    /// evidence, not a correction.
    pub fn record(&mut self, cell: &str, sample: Sample) -> Result<(), EvidenceError> {
        sample.check()?;
        let cell = self
            .cells
            .iter_mut()
            .find(|candidate| candidate.id == cell)
            .ok_or_else(|| EvidenceError::UnknownCell(cell.into()))?;
        cell.samples.push(sample);
        Ok(())
    }

    /// Renders the ledger as TOML.
    pub fn render(&self) -> Result<String, EvidenceError> {
        toml::to_string(self).map_err(|error| EvidenceError::Schema(error.to_string()))
    }
}
