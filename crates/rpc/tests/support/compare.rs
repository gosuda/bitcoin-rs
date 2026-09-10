//! Structural comparator for the Core parity gate.
//!
//! Comparison is structural only, never JSON text: HTTP status, pinned
//! headers, the exact member set of each JSON-RPC envelope, identifier echo
//! by value, ordered batch elements, exact scalars, `f64` equality by
//! `to_bits`, complete pinned error objects, and required key presence.
//! Every position of a pinned response is classified exactly once — exact,
//! bit-exact float, chain-bound, volatile, or declared gap — and a
//! known-gap fixture may diverge from Core only at its declared paths.

use serde_json::Value;

use super::fixture::{
    BodyCheck, BodyForm, Checks, Fixture, HeaderCheck, HeaderClass, HttpTuple, Relation,
};

/// Chain identity read from the live `NodeState` before the replay runs, so
/// chain-bound keys compare against independently observed truth rather than
/// against the response under test.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LiveChain {
    /// Applied block count the harness mined.
    pub(crate) blocks: u64,
    /// Header count, taken as the applied tip height; the seed chain carries
    /// no headers-only lead.
    pub(crate) headers: u64,
    /// Applied tip hash in RPC display form.
    pub(crate) best_block_hash: String,
}

/// One comparison failure with the exact structural position that diverged.
#[derive(Debug)]
pub(crate) struct Mismatch {
    /// Fixture id the failure belongs to.
    pub(crate) fixture: String,
    /// Structural position (`status`, `header Content-Type`, `result.blocks`, ...).
    pub(crate) position: String,
    /// What diverged.
    pub(crate) why: String,
}

impl core::fmt::Display for Mismatch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "[{}] {}: {}", self.fixture, self.position, self.why)
    }
}

impl std::error::Error for Mismatch {}

/// Envelope dialect of one JSON-RPC response element.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub(crate) enum EnvelopeVersion {
    /// JSON-RPC 2.0: carries `jsonrpc:"2.0"`, success has `result` and no
    /// `error`, error has `error` and no `result`.
    V2,
    /// JSON-RPC 1.0 legacy: no `jsonrpc` member, `result` and `error` both
    /// present with an explicit `null` on the unused side.
    Legacy,
}

/// Outcome class of one envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub(crate) enum Outcome {
    /// Success envelope.
    Success,
    /// Application-level error envelope.
    Error,
}

/// Per-result comparison policy: every key of the pinned Core result is
/// classified exactly once — exact, bit-exact float, chain-bound, volatile,
/// or declared gap — and the live result may not carry any unclassified key.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResultCheck {
    /// The live result must additionally decode into the typed corepc v31
    /// `GetBlockchainInfo` wire struct.
    pub(crate) typed_chaininfo: bool,
    /// Keys compared for exact structural equality against Core.
    pub(crate) exact_keys: Vec<String>,
    /// Numeric keys compared bit-exactly via `f64::to_bits`.
    pub(crate) f64_bits_keys: Vec<String>,
    /// Keys compared against the independently read live chain identity.
    pub(crate) chain_bound_keys: Vec<String>,
    /// Keys whose value is wall-clock or storage dependent (time,
    /// mediantime, verificationprogress, ...): classified, type-checked,
    /// deliberately not value-compared.
    pub(crate) volatile_keys: Vec<String>,
    /// Declared divergence keys: the pinned current tuple carries the live
    /// shape and live must equal it, while the pinned Core value differs.
    pub(crate) gap_keys: Vec<String>,
}

impl ResultCheck {
    /// Every classified key, in declaration order per class.
    pub(crate) fn classes(&self) -> [(&'static str, &[String]); 5] {
        [
            ("exact", &self.exact_keys),
            ("f64-bits", &self.f64_bits_keys),
            ("chain-bound", &self.chain_bound_keys),
            ("volatile", &self.volatile_keys),
            ("gap", &self.gap_keys),
        ]
    }
}

/// Envelope-level check: member set, dialect, id echo, error code, and the
/// result policy. The error `message` is always compared exactly.
#[derive(Clone, Debug, PartialEq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnvelopeCheck {
    /// Envelope dialect.
    pub(crate) version: EnvelopeVersion,
    /// Outcome class.
    pub(crate) outcome: Outcome,
    /// Identifier that must be echoed exactly.
    pub(crate) id: Value,
    /// Numeric error code required when `outcome` is `Error`.
    pub(crate) error_code: Option<i64>,
    /// Result policy.
    pub(crate) result: ResultCheck,
}

impl EnvelopeCheck {
    /// The complete member set the envelope dialect prescribes.
    #[must_use]
    pub(crate) fn member_names(&self) -> Vec<&'static str> {
        match (self.version, self.outcome) {
            (EnvelopeVersion::V2, Outcome::Success) => vec!["jsonrpc", "result", "id"],
            (EnvelopeVersion::V2, Outcome::Error) => vec!["jsonrpc", "error", "id"],
            (EnvelopeVersion::Legacy, _) => vec!["result", "error", "id"],
        }
    }

    /// The `jsonrpc` member value the dialect prescribes, if any.
    #[must_use]
    pub(crate) fn jsonrpc_member(&self) -> Option<&'static str> {
        match self.version {
            EnvelopeVersion::V2 => Some("2.0"),
            EnvelopeVersion::Legacy => None,
        }
    }
}

/// Compares one replayed live tuple against its fixture under the fixture's
/// declared relation.
///
/// * `Exact`: the live tuple must match the pinned Core tuple structurally.
/// * `KnownGap`: the live tuple must match the pinned *current* tuple
///   structurally, and the Core tuple must differ from the current tuple at
///   exactly the declared [`Fixture::gap_paths`] and nowhere else. No
///   equality between Core and live is asserted.
///
/// # Errors
/// One [`Mismatch`] naming the first structural divergence.
pub(crate) fn compare(
    fixture: &Fixture,
    live: &HttpTuple,
    chain: &LiveChain,
) -> Result<(), Mismatch> {
    match &fixture.relation {
        Relation::Exact => compare_tuple(
            &fixture.id,
            "core",
            &fixture.core,
            live,
            &fixture.checks,
            chain,
        ),
        Relation::KnownGap => {
            let current = fixture.current.as_ref().ok_or_else(|| Mismatch {
                fixture: fixture.id.clone(),
                position: "relation".into(),
                why: "known gap without a pinned current tuple".into(),
            })?;
            if fixture.gap.as_deref().unwrap_or_default().trim().is_empty() {
                return Err(Mismatch {
                    fixture: fixture.id.clone(),
                    position: "relation".into(),
                    why: "known gap without a concrete gap identifier".into(),
                });
            }
            assert_divergence_exactly_at(fixture, current)?;
            compare_tuple(
                &fixture.id,
                "current",
                current,
                live,
                &fixture.checks,
                chain,
            )
        }
    }
}

/// Collects the complete set of structural positions where the pinned Core
/// tuple and the pinned current tuple differ: `status`, `headers.<name>`
/// (volatile transport headers `date`/`connection` excluded), and recursive
/// `body...` value paths.
#[must_use]
pub(crate) fn structural_diff_paths(core: &HttpTuple, current: &HttpTuple) -> Vec<String> {
    let mut paths = Vec::new();
    if core.status != current.status {
        paths.push("status".to_owned());
    }
    let normalize = |pairs: &[(String, String)]| -> Vec<(String, String)> {
        let mut normalized: Vec<(String, String)> = pairs
            .iter()
            .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
            .filter(|(name, _)| name != "date" && name != "connection")
            .collect();
        normalized.sort();
        normalized
    };
    let core_headers = normalize(&core.headers);
    let current_headers = normalize(&current.headers);
    let names: std::collections::BTreeSet<&str> = core_headers
        .iter()
        .map(|(name, _)| name.as_str())
        .chain(current_headers.iter().map(|(name, _)| name.as_str()))
        .collect();
    for name in names {
        let core_value = core_headers
            .iter()
            .find(|(candidate, _)| candidate == name)
            .map(|(_, value)| value);
        let current_value = current_headers
            .iter()
            .find(|(candidate, _)| candidate == name)
            .map(|(_, value)| value);
        if core_value != current_value {
            paths.push(format!("headers.{name}"));
        }
    }
    match (&core.body, &current.body) {
        (BodyForm::Json { value: a }, BodyForm::Json { value: b }) => {
            value_diff_paths(a, b, "body", &mut paths);
        }
        (BodyForm::Text { text: a }, BodyForm::Text { text: b }) => {
            if a != b {
                paths.push("body".to_owned());
            }
        }
        (BodyForm::Empty, BodyForm::Empty) => {}
        _ => paths.push("body".to_owned()),
    }
    paths
}

/// Recursively records every path at which two JSON values diverge.
fn value_diff_paths(core: &Value, current: &Value, prefix: &str, paths: &mut Vec<String>) {
    if let (Some(core_object), Some(current_object)) = (core.as_object(), current.as_object()) {
        let names: std::collections::BTreeSet<&str> = core_object
            .iter()
            .map(|(key, _)| key.as_str())
            .chain(current_object.iter().map(|(key, _)| key.as_str()))
            .collect();
        for name in names {
            let child = format!("{prefix}.{name}");
            match (core_object.get(name), current_object.get(name)) {
                (Some(core_value), Some(current_value)) => {
                    value_diff_paths(core_value, current_value, &child, paths);
                }
                _ => paths.push(child),
            }
        }
        return;
    }
    if let (Some(core_array), Some(current_array)) = (core.as_array(), current.as_array()) {
        if core_array.len() != current_array.len() {
            paths.push(prefix.to_owned());
            return;
        }
        for (index, (core_value, current_value)) in
            core_array.iter().zip(current_array.iter()).enumerate()
        {
            value_diff_paths(
                core_value,
                current_value,
                &format!("{prefix}[{index}]"),
                paths,
            );
        }
        return;
    }
    if !value_equal(core, current) {
        paths.push(prefix.to_owned());
    }
}

/// A known gap may only diverge from Core at its declared paths and nowhere
/// else: the complete structural diff must equal the declared set, which
/// also proves the gap is real rather than vacuous.
fn assert_divergence_exactly_at(fixture: &Fixture, current: &HttpTuple) -> Result<(), Mismatch> {
    let mut observed = structural_diff_paths(&fixture.core, current);
    observed.sort();
    let mut declared = fixture.gap_paths.clone();
    declared.sort();
    if observed.is_empty() {
        return Err(Mismatch {
            fixture: fixture.id.clone(),
            position: "relation".into(),
            why: "known gap no longer holds: the pinned Core tuple and the pinned current \
                  tuple are structurally identical, so the gap must be reclassified"
                .into(),
        });
    }
    if observed != declared {
        return Err(Mismatch {
            fixture: fixture.id.clone(),
            position: "relation".into(),
            why: format!(
                "known gap diverges at {observed:?} but the fixture declares exactly \
                 {declared:?}"
            ),
        });
    }
    Ok(())
}

fn compare_tuple(
    fixture: &str,
    side: &str,
    expected: &HttpTuple,
    live: &HttpTuple,
    checks: &Checks,
    chain: &LiveChain,
) -> Result<(), Mismatch> {
    let need = |position: String, why: String| Mismatch {
        fixture: fixture.to_owned(),
        position: format!("{side}.{position}"),
        why,
    };

    if checks.http_status && expected.status != live.status {
        return Err(need(
            "status".into(),
            format!(
                "expected HTTP {} but replay answered {}",
                expected.status, live.status
            ),
        ));
    }
    // Derived framing: Content-Length is not pinned data. A 204 must omit it;
    // every other tuple with a known wire body length must carry exactly one
    // ASCII-decimal header equal to that length.
    check_tuple_content_length(fixture, side, expected)?;
    check_tuple_content_length(fixture, side, live)?;
    // Header membership is complete: every name on the pinned side and on
    // the live side — the union — must be classified exactly once as
    // exact, volatile, or gap (Content-Length is covered by the derived
    // `body_length` class), and each class enforces its own rule.
    compare_headers(fixture, side, expected, live, &checks.headers)?;

    match (&expected.body, &checks.body, &live.body) {
        (BodyForm::Empty, BodyCheck::Empty, BodyForm::Empty) => {}
        (BodyForm::Empty, BodyCheck::Empty, live_form) => {
            return Err(need(
                "body".into(),
                format!("expected an empty body but replay answered {live_form:?}"),
            ));
        }
        (BodyForm::Text { text }, BodyCheck::Text, BodyForm::Text { text: live_text }) => {
            if text.as_bytes() != live_text.as_bytes() {
                return Err(need(
                    "body".into(),
                    format!("expected plain-text body {text:?} but replay answered {live_text:?}"),
                ));
            }
        }
        (BodyForm::Text { text }, BodyCheck::Text, live_form) => {
            return Err(need(
                "body".into(),
                format!("expected plain-text body {text:?} but replay answered {live_form:?}"),
            ));
        }
        (
            BodyForm::Json {
                value: expected_value,
            },
            BodyCheck::Single { envelope },
            BodyForm::Json { value: live_value },
        ) => {
            compare_envelope(fixture, side, envelope, live_value, expected_value, chain)?;
        }
        (
            BodyForm::Json {
                value: expected_value,
            },
            BodyCheck::Batch { elements },
            BodyForm::Json { value: live_value },
        ) => {
            compare_batch(fixture, side, elements, live_value, expected_value, chain)?;
        }
        _ => {
            return Err(need(
                "body".into(),
                "fixture check form does not match the pinned body form".into(),
            ));
        }
    }
    Ok(())
}

/// Case-insensitive single header lookup over a tuple's pinned headers.
fn header_value<'a>(tuple: &'a HttpTuple, name: &str) -> Option<&'a str> {
    tuple
        .headers
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

/// Enforces the derived `Content-Length` invariant on one tuple. A 204 has no
/// content and must omit the header; otherwise a known wire body length must
/// carry exactly one matching ASCII-decimal header. When the length is not
/// derivable (a JSON-body pinned tuple), the live side owns the check.
fn check_tuple_content_length(
    fixture: &str,
    side: &str,
    tuple: &HttpTuple,
) -> Result<(), Mismatch> {
    let fail = |why: String| Mismatch {
        fixture: fixture.to_owned(),
        position: format!("{side}.header Content-Length"),
        why,
    };
    let declared: Vec<&str> = tuple
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.as_str())
        .collect();
    if declared.len() > 1 {
        return Err(fail("duplicate Content-Length headers".into()));
    }
    if tuple.status == 204 {
        if tuple.body_len != Some(0) {
            return Err(fail("204 response must have an empty body".into()));
        }
        // RFC 9110 §8.6 forbids Content-Length on 204, but libevent-era
        // Core captures show `Content-Length: 0`. Accept both capture
        // forms; the node's own omission is pinned by the negative probe.
        if let Some(value) = declared.first() {
            if *value != "0" || declared.len() != 1 {
                return Err(fail("204 Content-Length must be absent or exactly \"0\"".into()));
            }
        }
        return Ok(());
    }
    let Some(length) = tuple.body_len else {
        return Ok(());
    };
    let Some(value) = declared.first() else {
        return Err(fail(format!(
            "response must carry exactly one Content-Length header for its {length} \
             body bytes"
        )));
    };
    let parsed: Option<u64> = (*value)
        .parse()
        .ok()
        .filter(|_| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()));
    match parsed {
        Some(parsed) if parsed == length => Ok(()),
        Some(parsed) => Err(fail(format!(
            "Content-Length {parsed} does not equal the body's actual {length} bytes"
        ))),
        None => Err(fail("Content-Length must be ASCII digits only".into())),
    }
}

/// Enforces the complete header classification: the union of pinned and
/// live header names must each be classified exactly once, exact names must
/// carry equal values, volatile names must be present on both sides (their
/// value is wall-clock or connection dependent), and gap names must diverge.
fn compare_headers(
    fixture: &str,
    side: &str,
    expected: &HttpTuple,
    live: &HttpTuple,
    headers: &HeaderCheck,
) -> Result<(), Mismatch> {
    let need = |name: &str, why: String| Mismatch {
        fixture: fixture.to_owned(),
        position: format!("{side}.header {name}"),
        why,
    };
    // Union of names, keyed case-insensitively, keeping the first wire
    // spelling for display.
    let mut names: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for (name, _) in expected.headers.iter().chain(live.headers.iter()) {
        names
            .entry(name.to_ascii_lowercase())
            .or_insert_with(|| name.clone());
    }
    for (lower, display) in names {
        if headers.body_length && lower == "content-length" {
            // Already enforced per tuple by check_tuple_content_length.
            continue;
        }
        let Some(class) = headers.class_of(&lower) else {
            return Err(need(
                &display,
                "header name is not classified; every pinned and live header must be \
                 classified exactly once as exact, volatile or gap"
                    .into(),
            ));
        };
        let expected_value = header_value(expected, &lower);
        let live_value = header_value(live, &lower);
        match class {
            HeaderClass::Exact => {
                let (Some(expected_value), Some(live_value)) = (expected_value, live_value) else {
                    return Err(need(
                        &display,
                        format!(
                            "exact header must be present on both sides (pinned: {}, live: {})",
                            expected_value.is_some(),
                            live_value.is_some()
                        ),
                    ));
                };
                if expected_value != live_value {
                    return Err(need(
                        &display,
                        format!("expected {expected_value:?} but replay answered {live_value:?}"),
                    ));
                }
            }
            HeaderClass::Volatile => {
                if expected_value.is_none() || live_value.is_none() {
                    return Err(need(
                        &display,
                        format!(
                            "volatile header must be present on both sides (pinned: {}, live: {})",
                            expected_value.is_some(),
                            live_value.is_some()
                        ),
                    ));
                }
            }
            HeaderClass::Gap => {
                let (Some(expected_value), Some(live_value)) = (expected_value, live_value) else {
                    return Err(need(
                        &display,
                        "gap header must be present on both sides so its divergence is \
                         provable"
                            .into(),
                    ));
                };
                if expected_value == live_value {
                    return Err(need(
                        &display,
                        "gap header is classified gap but both sides carry the same \
                         value, so nothing diverges there"
                            .into(),
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Compares a batch positionally: live element N against Core element N.
/// Positional id equality is the ordering proof — a live response that
/// reordered Core's elements fails on the id, before any deeper compare.
fn compare_batch(
    fixture: &str,
    side: &str,
    elements: &[EnvelopeCheck],
    live: &Value,
    core: &Value,
    chain: &LiveChain,
) -> Result<(), Mismatch> {
    let need = |position: String, why: String| Mismatch {
        fixture: fixture.to_owned(),
        position: format!("{side}.{position}"),
        why,
    };
    let Some(core_rows) = core.as_array() else {
        return Err(need(
            "body".into(),
            "pinned Core batch is not a JSON array".into(),
        ));
    };
    let Some(live_rows) = live.as_array() else {
        return Err(need(
            "body".into(),
            "expected a JSON array batch response".into(),
        ));
    };
    if core_rows.len() != elements.len() || live_rows.len() != elements.len() {
        return Err(need(
            "body".into(),
            format!(
                "expected {} batch elements but core pinned {} and replay answered {}",
                elements.len(),
                core_rows.len(),
                live_rows.len()
            ),
        ));
    }
    for (index, ((core_row, live_row), envelope)) in core_rows
        .iter()
        .zip(live_rows.iter())
        .zip(elements)
        .enumerate()
    {
        let Some(core_id) = core_row.get("id") else {
            return Err(need(
                "body".into(),
                format!("pinned Core batch element {index} carries no id"),
            ));
        };
        let Some(live_id) = live_row.get("id") else {
            return Err(need(
                "body".into(),
                format!("replay batch element {index} carries no id"),
            ));
        };
        if !value_equal(core_id, live_id) {
            return Err(need(
                format!("body[{index}].id"),
                format!(
                    "batch order diverges: core pinned id {} at position {index} but replay \
                     answered {}",
                    value_repr(core_id),
                    value_repr(live_id)
                ),
            ));
        }
        compare_envelope(fixture, side, envelope, live_row, core_row, chain)?;
    }
    Ok(())
}

/// Compact re-serialization of a value for failure messages only; never
/// used for comparison.
fn value_repr(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "<unserializable>".to_owned())
}

fn compare_envelope(
    fixture: &str,
    side: &str,
    envelope: &EnvelopeCheck,
    live: &Value,
    core: &Value,
    chain: &LiveChain,
) -> Result<(), Mismatch> {
    let need = |position: String, why: String| Mismatch {
        fixture: fixture.to_owned(),
        position: format!("{side}.{position}"),
        why,
    };

    // The complete member set of the envelope is structural: the live
    // element must carry exactly the members the dialect prescribes, no
    // more, no fewer.
    let expected_members = envelope.member_names();
    let Some(object) = live.as_object() else {
        return Err(need(
            "envelope".into(),
            "response element is not a JSON object".into(),
        ));
    };
    let live_members: Vec<&str> = object.iter().map(|(key, _)| key.as_str()).collect();
    if live_members.len() != expected_members.len() {
        return Err(need(
            "envelope".into(),
            format!(
                "expected envelope members {expected_members:?} but replay answered \
                 {live_members:?}"
            ),
        ));
    }
    for member in &expected_members {
        if live.get(*member).is_none() {
            return Err(need(
                "envelope".into(),
                format!("envelope is missing the {member:?} member"),
            ));
        }
    }

    if let Some(jsonrpc) = envelope.jsonrpc_member() {
        if live.get("jsonrpc").and_then(Value::as_str) != Some(jsonrpc) {
            return Err(need(
                "envelope.jsonrpc".into(),
                format!("expected {jsonrpc:?}"),
            ));
        }
    }

    let live_id = live
        .get("id")
        .ok_or_else(|| need("envelope.id".into(), "envelope carries no id member".into()))?;
    if !value_equal(live_id, &envelope.id) {
        return Err(need(
            "envelope.id".into(),
            format!(
                "expected identifier to be echoed exactly as {:?}",
                envelope.id
            ),
        ));
    }

    match envelope.outcome {
        Outcome::Success => {
            let Some(result) = live.get("result") else {
                return Err(need(
                    "envelope".into(),
                    "success envelope carries no result".into(),
                ));
            };
            let core_result = core.get("result").ok_or_else(|| {
                need(
                    "envelope".into(),
                    "pinned Core success envelope carries no result".into(),
                )
            })?;
            compare_result(fixture, side, &envelope.result, result, core_result, chain)?;
            if envelope.version == EnvelopeVersion::Legacy
                && !live.get("error").is_some_and(Value::is_null)
            {
                return Err(need(
                    "envelope.error".into(),
                    "legacy success envelope must carry an explicit null error member".into(),
                ));
            }
        }
        Outcome::Error => {
            compare_error(fixture, side, envelope, live, core)?;
        }
    }
    Ok(())
}

/// Compares the complete pinned error object: the live error must carry the
/// same member set, every member must equal the pinned value, and the
/// `message` text is compared exactly on every row. The legacy dialect
/// additionally requires the explicit null `result` member, the v2 dialect
/// its absence.
fn compare_error(
    fixture: &str,
    side: &str,
    envelope: &EnvelopeCheck,
    live: &Value,
    core: &Value,
) -> Result<(), Mismatch> {
    compare_error_code(fixture, side, envelope, live)?;
    compare_error_members(fixture, side, live, core)?;
    compare_error_dialect(fixture, side, envelope, live)?;
    Ok(())
}

/// The error envelope must pin an error code and answer with exactly it.
fn compare_error_code(
    fixture: &str,
    side: &str,
    envelope: &EnvelopeCheck,
    live: &Value,
) -> Result<(), Mismatch> {
    let need = |position: String, why: String| Mismatch {
        fixture: fixture.to_owned(),
        position: format!("{side}.{position}"),
        why,
    };
    let Some(expected_code) = envelope.error_code else {
        return Err(need(
            "error.code".into(),
            "fixture check must pin an error code for an error envelope".into(),
        ));
    };
    let Some(error) = live.get("error") else {
        return Err(need(
            "envelope".into(),
            "error envelope carries no error member".into(),
        ));
    };
    let Some(code) = error.get("code").and_then(Value::as_i64) else {
        return Err(need(
            "error.code".into(),
            "error carries no numeric code".into(),
        ));
    };
    if code != expected_code {
        return Err(need(
            "error.code".into(),
            format!("expected {expected_code} but replay answered {code}"),
        ));
    }
    Ok(())
}

/// The complete pinned error object: the live error must carry the same
/// member set, every member must equal the pinned value, and the `message`
/// text is compared exactly on every row.
fn compare_error_members(
    fixture: &str,
    side: &str,
    live: &Value,
    core: &Value,
) -> Result<(), Mismatch> {
    let need = |position: String, why: String| Mismatch {
        fixture: fixture.to_owned(),
        position: format!("{side}.{position}"),
        why,
    };
    let Some(pinned_error) = core.get("error") else {
        return Err(need(
            "error".into(),
            "pinned Core error envelope carries no error member".into(),
        ));
    };
    let Some(pinned_object) = pinned_error.as_object() else {
        return Err(need(
            "error".into(),
            "pinned Core error must be a JSON object".into(),
        ));
    };
    let Some(live_object) = live.get("error").and_then(Value::as_object) else {
        return Err(need("error".into(), "error must be a JSON object".into()));
    };
    let pinned_members: Vec<&str> = pinned_object.iter().map(|(key, _)| key.as_str()).collect();
    let live_members: Vec<&str> = live_object.iter().map(|(key, _)| key.as_str()).collect();
    if live_members.len() != pinned_members.len() {
        return Err(need(
            "error".into(),
            format!(
                "expected error members {pinned_members:?} but replay answered {live_members:?}"
            ),
        ));
    }
    for key in pinned_members {
        compare_error_member(fixture, side, key, pinned_error, live)?;
    }
    Ok(())
}

/// One pinned error member: message text is always compared exactly, so a
/// genuine wording divergence is a structured known gap declared at
/// `body.error.message`, never a weakened comparison.
fn compare_error_member(
    fixture: &str,
    side: &str,
    key: &str,
    pinned_error: &Value,
    live: &Value,
) -> Result<(), Mismatch> {
    let need = |position: String, why: String| Mismatch {
        fixture: fixture.to_owned(),
        position: format!("{side}.{position}"),
        why,
    };
    let Some(pinned_value) = pinned_error.get(key) else {
        return Err(need(
            format!("error.{key}"),
            "check expects a pinned member the Core error does not carry".into(),
        ));
    };
    let Some(live_value) = live.get("error").and_then(|error| error.get(key)) else {
        return Err(need(
            format!("error.{key}"),
            format!("error is missing the pinned member {key:?}"),
        ));
    };
    if !value_equal(live_value, pinned_value) {
        return Err(need(
            format!("error.{key}"),
            format!(
                "expected {} but replay answered {}",
                value_repr(pinned_value),
                value_repr(live_value)
            ),
        ));
    }
    Ok(())
}

/// The dialect closing rule: a v2 error envelope must not also carry a
/// result member; the legacy dialect requires the explicit null result.
fn compare_error_dialect(
    fixture: &str,
    side: &str,
    envelope: &EnvelopeCheck,
    live: &Value,
) -> Result<(), Mismatch> {
    let need = |position: String, why: String| Mismatch {
        fixture: fixture.to_owned(),
        position: format!("{side}.{position}"),
        why,
    };
    match envelope.version {
        EnvelopeVersion::V2 => {
            if live.get("result").is_some() {
                return Err(need(
                    "envelope".into(),
                    "error envelope must not also carry a result member".into(),
                ));
            }
        }
        EnvelopeVersion::Legacy => {
            if !live.get("result").is_some_and(Value::is_null) {
                return Err(need(
                    "envelope.result".into(),
                    "legacy error envelope must carry an explicit null result member".into(),
                ));
            }
        }
    }
    Ok(())
}

fn compare_result(
    fixture: &str,
    side: &str,
    checks: &ResultCheck,
    live: &Value,
    core: &Value,
    chain: &LiveChain,
) -> Result<(), Mismatch> {
    let need = |position: String, why: String| Mismatch {
        fixture: fixture.to_owned(),
        position: format!("{side}.{position}"),
        why,
    };

    if live.as_object().is_none() {
        return Err(need("result".into(), "result must be a JSON object".into()));
    }
    let live_keys: Vec<String> = live
        .as_object()
        .map(|object| object.iter().map(|(key, _)| key.to_owned()).collect())
        .unwrap_or_default();

    // Every live key must be classified exactly once; an unclassified key is
    // a structural divergence the fixture does not declare.
    let classified: std::collections::BTreeSet<&str> = checks
        .classes()
        .iter()
        .flat_map(|(_, keys)| keys.iter().map(String::as_str))
        .collect();
    for key in &live_keys {
        if !classified.contains(key.as_str()) {
            return Err(need(
                format!("result.{key}"),
                format!("result carries the unclassified key {key:?}"),
            ));
        }
    }

    compare_classified_keys(fixture, side, checks, live, core)?;
    compare_chain_bound_keys(fixture, side, checks, live, chain)?;
    Ok(())
}

/// Walks every classified key (exact, f64-bits, volatile, gap) and enforces
/// its class rule against the compared side.
fn compare_classified_keys(
    fixture: &str,
    side: &str,
    checks: &ResultCheck,
    live: &Value,
    core: &Value,
) -> Result<(), Mismatch> {
    let need = |position: String, why: String| Mismatch {
        fixture: fixture.to_owned(),
        position: format!("{side}.{position}"),
        why,
    };
    for (class, keys) in checks.classes() {
        for key in keys {
            // Chain-bound keys are handled by their own loop below against
            // the independently read node state.
            if class == "chain-bound" {
                continue;
            }
            let Some(core_value) = core.get(key.as_str()) else {
                return Err(need(
                    format!("result.{key}"),
                    format!("check classifies {key:?} but the compared side does not carry it"),
                ));
            };
            let Some(live_value) = live.get(key.as_str()) else {
                return Err(need(
                    format!("result.{key}"),
                    format!("result is missing the classified key {key:?}"),
                ));
            };
            compare_classified_key(fixture, side, class, key, live_value, core_value)?;
        }
    }
    Ok(())
}

/// One classified key: dispatches on the class and enforces its rule.
fn compare_classified_key(
    fixture: &str,
    side: &str,
    class: &str,
    key: &str,
    live_value: &Value,
    core_value: &Value,
) -> Result<(), Mismatch> {
    let need = |position: String, why: String| Mismatch {
        fixture: fixture.to_owned(),
        position: format!("{side}.{position}"),
        why,
    };
    match class {
        "exact" => {
            if !value_equal(live_value, core_value) {
                return Err(need(
                    format!("result.{key}"),
                    format!(
                        "expected {} but replay answered {}",
                        value_repr(core_value),
                        value_repr(live_value)
                    ),
                ));
            }
        }
        "f64-bits" => {
            let Some(core_bits) = core_value.as_f64() else {
                return Err(need(
                    format!("result.{key}"),
                    "classified f64 key is not a number on the compared side".into(),
                ));
            };
            let Some(live_bits) = live_value.as_f64() else {
                return Err(need(
                    format!("result.{key}"),
                    format!("result must carry {key:?} as a JSON number"),
                ));
            };
            if core_bits.to_bits() != live_bits.to_bits() {
                return Err(need(
                    format!("result.{key}"),
                    format!(
                        "f64 bits diverge: compared side {:#016x} vs live {:#016x}",
                        core_bits.to_bits(),
                        live_bits.to_bits()
                    ),
                ));
            }
        }
        "volatile" => {
            if json_kind(live_value) != json_kind(core_value) {
                return Err(need(
                    format!("result.{key}"),
                    format!(
                        "volatile key {key:?} must keep the pinned JSON type, expected \
                         kind {} but replay answered kind {}",
                        json_kind(core_value),
                        json_kind(live_value)
                    ),
                ));
            }
        }
        "gap" => {
            // The declared divergence position: live must answer with the
            // pinned current-tuple value, which the compared side (the
            // current tuple in gap mode) carries. Equality is still
            // enforced — the divergence is Core-vs-current and is proven by
            // `assert_divergence_exactly_at`.
            if !value_equal(live_value, core_value) {
                return Err(need(
                    format!("result.{key}"),
                    format!(
                        "declared gap key {key:?} must equal the pinned current value: \
                         expected {} but replay answered {}",
                        value_repr(core_value),
                        value_repr(live_value)
                    ),
                ));
            }
        }
        _ => {
            return Err(need(
                format!("result.{key}"),
                format!("unsupported classification {class:?}"),
            ));
        }
    }
    Ok(())
}

/// Chain-bound keys compare against the independently read node state,
/// never against the response under test.
fn compare_chain_bound_keys(
    fixture: &str,
    side: &str,
    checks: &ResultCheck,
    live: &Value,
    chain: &LiveChain,
) -> Result<(), Mismatch> {
    let need = |position: String, why: String| Mismatch {
        fixture: fixture.to_owned(),
        position: format!("{side}.{position}"),
        why,
    };
    for key in &checks.chain_bound_keys {
        let Some(live_value) = live.get(key.as_str()) else {
            return Err(need(
                format!("result.{key}"),
                format!("result is missing the chain-bound key {key:?}"),
            ));
        };
        // `blocks` and `headers` are JSON numbers, `bestblockhash` a JSON
        // string; both compare against the live node state read before the
        // replay, never against the response under test.
        let diverged = match key.as_str() {
            "blocks" => live_value.as_u64() != Some(chain.blocks),
            "headers" => live_value.as_u64() != Some(chain.headers),
            "bestblockhash" => live_value.as_str() != Some(chain.best_block_hash.as_str()),
            other => {
                return Err(need(
                    format!("result.{other}"),
                    "unsupported chain-bound key: the comparator only binds blocks, headers \
                     and bestblockhash"
                        .into(),
                ));
            }
        };
        if diverged {
            return Err(need(
                format!("result.{key}"),
                format!(
                    "chain-bound value diverges from the live node state: expected \
                     {chain:?} binding but replay answered {}",
                    value_repr(live_value)
                ),
            ));
        }
    }
    Ok(())
}

/// Coarse JSON kind of a value, used to type-check volatile keys.
fn json_kind(value: &Value) -> u8 {
    if value.is_null() {
        0
    } else if value.is_boolean() {
        1
    } else if value.is_number() {
        2
    } else if value.is_string() {
        3
    } else if value.is_array() {
        4
    } else {
        5
    }
}

/// Typed corepc v31 decode of a live `getblockchaininfo` body; a body that
/// does not deserialize into the versioned wire struct fails the gate.
///
/// # Errors
/// Propagates the sonic-rs decode error.
pub(crate) fn typed_getblockchain_info(
    body: &[u8],
) -> Result<corepc_types::v31::GetBlockchainInfo, sonic_rs::Error> {
    sonic_rs::from_slice(body)
}

/// Structural equality for JSON values: objects compare by complete member
/// set and per-member equality, arrays by ordered elements, strings and
/// booleans by value, integral numbers by value, and non-integral floating
/// point numbers by `f64::to_bits`, so a decimal reformatting can never pass
/// or fail a comparison.
#[must_use]
pub(crate) fn value_equal(a: &Value, b: &Value) -> bool {
    if let (Some(a), Some(b)) = (a.as_object(), b.as_object()) {
        return a.len() == b.len()
            && a.iter().all(|(key, value)| {
                b.get(key.as_str())
                    .is_some_and(|other| value_equal(value, other))
            });
    }
    if let (Some(a), Some(b)) = (a.as_array(), b.as_array()) {
        return a.len() == b.len()
            && a.iter()
                .zip(b.iter())
                .all(|(left, right)| value_equal(left, right));
    }
    if let (Some(a), Some(b)) = (a.as_str(), b.as_str()) {
        return a == b;
    }
    if let (Some(a), Some(b)) = (a.as_bool(), b.as_bool()) {
        return a == b;
    }
    if a.is_null() && b.is_null() {
        return true;
    }
    if let (Some(a), Some(b)) = (a.as_i64(), b.as_i64()) {
        return a == b;
    }
    // Every numeric comparison is bitwise: equal bits or no equality. This
    // is the Core float parity doctrine — value parity, never text parity —
    // and it keeps clippy's float comparison ban satisfied without a
    // tolerance that could mask a real divergence.
    match (a.as_f64(), b.as_f64()) {
        (Some(a), Some(b)) => a.to_bits() == b.to_bits(),
        _ => false,
    }
}
