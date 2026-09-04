//! Comparing this node's RPC results against Bitcoin Core's declared schemas.
//!
//! #78 scope item 2 asks for a differential harness: for each supported method,
//! compare this node against the pinned Core reference. The obvious way is to
//! run a `bitcoind` and diff the answers, and it is the right way for *values*.
//! It cannot be the whole answer here, for a reason the manifest already
//! records: the pinned reference is 31.99.0, a master snapshot, and no release
//! binary exists for it. A harness that cannot run until Core cuts a release is
//! a harness that verifies nothing today.
//!
//! Core declares each method's result shape in its own source, beside the
//! handler, as `RPCResult` literals. Those are not documentation that drifts --
//! `RPCHelpMan::Check` asserts Core's own handlers against them in debug
//! builds, so Core keeps them true. `tools/core-rpc-schema/extract.py` reads
//! them into `docs/api/core-rpc-schema.json`, and this compares what this node
//! emits against what Core says it would.
//!
//! **What this checks:** the top-level result shape. Field names, their JSON
//! types, and which Core marks optional. That is #78's "result schemas are
//! compared, not merely method names or selected key sets", for the top level.
//!
//! **What it does not check:** values, and nested objects. Values need a live
//! Core, which #78 keeps as a separate documented lane. Nested shapes the
//! extractor does not claim, because it cannot verify them, and an unverified
//! claim is worse than an absent one.
//!
//! The point of the comparison is not that it passes. It is that every
//! difference it finds is one the manifest declares, field by field -- so a
//! deviation stops being prose and becomes a checked list.

use sonic_rs::{JsonContainerTrait as _, JsonType, JsonValueTrait, Value};

/// Core's declared schema for one method, as the extractor emits it.
pub struct CoreSchema {
    /// Result variants, in Core's declaration order. One entry for a method
    /// that returns a single shape.
    pub variants: Vec<CoreVariant>,
}

/// One shape a method may return.
pub struct CoreVariant {
    /// The condition Core labels it with, when it labels one.
    pub when: Option<String>,
    /// Core's `RPCResult::Type` name.
    pub kind: String,
    /// Declared top-level fields, for object results.
    pub fields: Vec<CoreField>,
}

/// One declared field.
pub struct CoreField {
    /// Field name as it appears in the JSON.
    pub name: String,
    /// Core's `RPCResult::Type` name.
    pub kind: String,
    /// Whether Core marks it `/*optional=*/true`.
    pub optional: bool,
}

/// How this node's answer differs from Core's declared shape.
///
/// Deliberately a set of named differences rather than a boolean. "Differs" is
/// not actionable; "Core declares `unbroadcastcount` and this does not emit it"
/// is, and it is the thing the manifest has to declare.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct SchemaDiff {
    /// Fields Core declares non-optional that this node does not emit.
    pub missing: Vec<String>,
    /// Fields this node emits that Core does not declare.
    pub extra: Vec<String>,
    /// Fields both declare, whose JSON type disagrees, as `name: ours vs core`.
    pub mismatched: Vec<String>,
}

impl SchemaDiff {
    /// Whether the answer matches Core's declaration exactly.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.missing.is_empty() && self.extra.is_empty() && self.mismatched.is_empty()
    }
}

/// Core's `RPCResult::Type` names, as `ExpectedType` in `rpc/util.cpp` maps them.
#[derive(Clone, Copy)]
enum SchemaType {
    None,
    Str,
    StrHex,
    Num,
    StrAmount,
    NumTime,
    Bool,
    Arr,
    ArrFixed,
    Obj,
    ObjDyn,
    Any,
    Elision,
}

impl SchemaType {
    fn parse(kind: &str) -> Option<Self> {
        Some(match kind {
            "NONE" => Self::None,
            "STR" => Self::Str,
            "STR_HEX" => Self::StrHex,
            "NUM" => Self::Num,
            "STR_AMOUNT" => Self::StrAmount,
            "NUM_TIME" => Self::NumTime,
            "BOOL" => Self::Bool,
            "ARR" => Self::Arr,
            "ARR_FIXED" => Self::ArrFixed,
            "OBJ" => Self::Obj,
            "OBJ_DYN" => Self::ObjDyn,
            "ANY" => Self::Any,
            "ELISION" => Self::Elision,
            _ => return None,
        })
    }
}

/// Whether a JSON value satisfies one of Core's declared result types.
///
/// **Transcribed from Core's `ExpectedType` in `rpc/util.cpp`**, case for case,
/// rather than inferred from the type names. That matters more than it looks:
/// `STR_AMOUNT` is *not* a string. Core maps it to `VNUM` and renders amounts
/// as bare numbers -- the name describes the formatting, not the wire type. A
/// mapping built from the names reports every amount field in every method as a
/// type mismatch, which is what mine did before I read the table.
///
/// `ANY` and `ELISION` are Core's own opt-outs (`std::nullopt` there) and match
/// anything. Unknown names are rejected while loading the schema below.
#[must_use]
pub fn type_matches(kind: &str, value: &Value) -> bool {
    let Some(kind) = SchemaType::parse(kind) else {
        return false;
    };
    match kind {
        SchemaType::None => value.get_type() == JsonType::Null,
        SchemaType::Str | SchemaType::StrHex => value.get_type() == JsonType::String,
        SchemaType::Num | SchemaType::StrAmount | SchemaType::NumTime => {
            value.get_type() == JsonType::Number
        }
        SchemaType::Bool => value.get_type() == JsonType::Boolean,
        SchemaType::Arr | SchemaType::ArrFixed => value.get_type() == JsonType::Array,
        SchemaType::Obj | SchemaType::ObjDyn => value.get_type() == JsonType::Object,
        SchemaType::Any | SchemaType::Elision => true,
    }
}

/// Compares one answer against one declared variant.
///
/// Only object variants have fields to compare; for a scalar the answer is
/// either the declared type or a mismatch, and the mismatch is reported under
/// the empty field name so it has somewhere to go.
#[must_use]
pub fn diff_against(variant: &CoreVariant, value: &Value) -> SchemaDiff {
    let mut diff = SchemaDiff::default();
    if !type_matches(&variant.kind, value) {
        diff.mismatched.push(format!(
            "<result>: {:?} vs {}",
            value.get_type(),
            variant.kind
        ));
        return diff;
    }
    let Some(object) = value.as_object() else {
        return diff;
    };

    // `OBJ_DYN` is Core's "dictionary with keys that are not literals". The one
    // field it declares is a *placeholder* describing what every value looks
    // like, not a key that appears in the answer -- `getindexinfo` declares
    // `name` and returns `{"basicblockfilterindex": {...}}`. Comparing keys
    // here would report the placeholder missing and every real key extra, which
    // is a comparison of the wrong thing rather than a finding.
    if variant.kind == "OBJ_DYN" {
        let Some(declared) = variant.fields.first() else {
            return diff;
        };
        for (name, entry) in object {
            if !type_matches(&declared.kind, entry) {
                diff.mismatched.push(format!(
                    "{}: {:?} vs {}",
                    name,
                    entry.get_type(),
                    declared.kind
                ));
            }
        }
        diff.mismatched.sort_unstable();
        return diff;
    }

    for field in &variant.fields {
        match object.get(&field.name.as_str()) {
            Some(found) => {
                if !type_matches(&field.kind, found) {
                    diff.mismatched.push(format!(
                        "{}: {:?} vs {}",
                        field.name,
                        found.get_type(),
                        field.kind
                    ));
                }
            }
            // An absent optional field is Core's own behaviour, not a
            // difference: Core omits `txcount` when it does not know one.
            None if field.optional => {}
            None => diff.missing.push(field.name.clone()),
        }
    }

    for (name, _) in object {
        if !variant.fields.iter().any(|field| field.name == name) {
            diff.extra.push(name.to_owned());
        }
    }

    diff.missing.sort_unstable();
    diff.extra.sort_unstable();
    diff.mismatched.sort_unstable();
    diff
}

/// Compares an answer against every variant, keeping the closest match.
///
/// A method with variants returns one shape per call -- `gettxout` answers null
/// or an object, `getblock` a string or one of three objects -- and the caller
/// knows which it asked for far less reliably than the answer shows. Scoring
/// every variant and keeping the least different one is what makes the
/// comparison work without teaching this which arguments select what.
#[must_use]
pub fn diff_best(schema: &CoreSchema, value: &Value) -> SchemaDiff {
    let mut best: Option<SchemaDiff> = None;
    for variant in &schema.variants {
        let diff = diff_against(variant, value);
        if diff.is_empty() {
            return diff;
        }
        let score = |d: &SchemaDiff| d.missing.len() + d.extra.len() + d.mismatched.len();
        if best
            .as_ref()
            .is_none_or(|current| score(&diff) < score(current))
        {
            best = Some(diff);
        }
    }
    best.unwrap_or_default()
}

/// The extracted schema document, embedded so the check cannot drift from it.
const SCHEMA_JSON: &str = include_str!("../../../../docs/api/core-rpc-schema.json");

fn required_schema_str<'a>(value: &'a Value, key: &str, what: &str) -> &'a str {
    let Some(text) = value.get(key).and_then(JsonValueTrait::as_str) else {
        panic!("{what} must be a string");
    };
    assert!(
        key != "type" || !text.is_empty(),
        "{what} must be a non-empty string"
    );
    text
}

fn read_field(field: &Value) -> CoreField {
    let name = required_schema_str(field, "name", "schema field name");
    let kind = required_schema_str(field, "type", "schema field type");
    let parsed =
        SchemaType::parse(kind).unwrap_or_else(|| panic!("unsupported schema field type: {kind}"));
    if matches!(parsed, SchemaType::Elision) {
        panic!(
            "schema field {name:?} is an unexpanded ELISION marker; \
             regenerate docs/api/core-rpc-schema.json"
        );
    }
    let optional = match field.get("optional") {
        None => false,
        Some(value) => value
            .as_bool()
            .unwrap_or_else(|| panic!("schema field optional must be a boolean")),
    };
    CoreField {
        name: name.to_owned(),
        kind: kind.to_owned(),
        optional,
    }
}

fn read_variant(value: &Value) -> CoreVariant {
    let fields = match value.get("fields") {
        None => alloc::vec![],
        Some(fields) => {
            let Some(array) = fields.as_array() else {
                panic!("schema variant fields must be an array");
            };
            array.iter().map(read_field).collect()
        }
    };
    let kind = required_schema_str(value, "type", "schema variant type");
    assert!(
        SchemaType::parse(kind).is_some(),
        "unsupported schema variant type: {kind}"
    );
    CoreVariant {
        when: value
            .get("when")
            .and_then(JsonValueTrait::as_str)
            .map(alloc::borrow::ToOwned::to_owned),
        kind: kind.to_owned(),
        fields,
    }
}

/// Parses the extracted document into the shapes above.
///
/// Hand-rolled rather than derived, because the document is data this repository
/// produces and a `serde` derive would make its field names part of two files
/// that have to agree. The parse is strict: a document it cannot read is a
/// panic, not a silently empty schema set that would make every check pass.
#[must_use]
pub fn load_schemas() -> alloc::collections::BTreeMap<alloc::string::String, CoreSchema> {
    load_schemas_from(SCHEMA_JSON)
}

fn load_schemas_from(
    json: &str,
) -> alloc::collections::BTreeMap<alloc::string::String, CoreSchema> {
    let document: Value = sonic_rs::from_str(json)
        .unwrap_or_else(|err| panic!("the extracted Core schema must parse: {err}"));
    let Some(methods) = document.get("methods").and_then(|m| m.as_object().cloned()) else {
        panic!("the extracted Core schema must carry a `methods` object");
    };

    let mut out = alloc::collections::BTreeMap::new();
    for (name, value) in &methods {
        let variants = match value.get("variants") {
            None => alloc::vec![read_variant(value)],
            Some(variants) => {
                let Some(array) = variants.as_array() else {
                    panic!("schema method `{name}` variants must be an array");
                };
                assert!(
                    !array.is_empty(),
                    "schema method `{name}` must not carry an empty variants array"
                );
                array.iter().map(read_variant).collect()
            }
        };
        let _ = out.insert(name.to_owned(), CoreSchema { variants });
    }
    out
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use bitcoin_rs_primitives::{Block, Network};
    use sonic_rs::JsonValueTrait as _;

    use super::{diff_best, load_schemas};
    use crate::context::{
        BlockTemplateRequest, BlockTemplateResult, BlockValidationResult, Context, MiningControl,
        MiningControlError, MiningInfo,
    };

    /// Enough mining control for `getmininginfo` to answer. After main's
    /// mining-control cutover the method refuses a bare context, and dropping
    /// it from the table would shrink the oracle rather than record the
    /// closed gap.
    struct SchemaMiningControl;

    impl MiningControl for SchemaMiningControl {
        fn get_block_template(
            &self,
            _request: BlockTemplateRequest,
        ) -> Result<BlockTemplateResult, MiningControlError> {
            Err(MiningControlError::Unavailable(
                "schema comparison does not assemble templates".into(),
            ))
        }

        fn mining_info(&self) -> Result<MiningInfo, MiningControlError> {
            Ok(MiningInfo {
                blocks: 0,
                last_candidate: None,
                bits: 0x207f_ffff,
                difficulty: 1.0,
                network_hashes_per_second: 0.0,
                pooled_transactions: 0,
                network: Network::Regtest,
                next_bits: 0x207f_ffff,
                next_difficulty: 1.0,
                minimum_fee_rate: 1_000,
                signet: None,
                warnings: Vec::new(),
            })
        }

        fn submit_block(&self, _block: Block) -> Result<BlockValidationResult, MiningControlError> {
            Ok(BlockValidationResult::Accepted)
        }

        fn publish_generation(&self) {}
    }

    /// Methods this compares, and the parameters it compares them with.
    ///
    /// Deliberately the ones that answer on a default context (plus mining
    /// control and a debug log path, which `getmininginfo` and `getrpcinfo`
    /// now require). A method that needs a
    /// chain, an index or a mempool would need a fixture per method, and a
    /// fixture written to make a comparison pass is not evidence -- it is the
    /// answer, restated. The list grows as fixtures that mean something get
    /// built, and `coverage_is_recorded_so_it_cannot_silently_shrink` stops it
    /// shrinking by accident.
    const COMPARED: &[(&str, &str)] = &[
        ("getblockchaininfo", "[]"),
        ("getblockcount", "[]"),
        ("getbestblockhash", "[]"),
        ("getdifficulty", "[]"),
        ("getchaintxstats", "[]"),
        ("getchaintips", "[]"),
        ("getmempoolinfo", "[]"),
        ("getrawmempool", "[]"),
        ("getrawmempool", "[true]"),
        ("getrawmempool", "[false, true]"),
        ("getmininginfo", "[]"),
        ("getnetworkinfo", "[]"),
        ("getpeerinfo", "[]"),
        ("getconnectioncount", "[]"),
        ("getnettotals", "[]"),
        ("listbanned", "[]"),
        ("uptime", "[]"),
        ("getrpcinfo", "[]"),
        ("getmemoryinfo", "[]"),
        ("getindexinfo", "[]"),
        ("estimatesmartfee", "[6]"),
        (
            "validateaddress",
            // BIP173 P2WPKH example: a valid mainnet witness address, so the
            // comparison sees address, scriptPubKey, and the witness fields.
            "[\"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4\"]",
        ),
        ("validateaddress", "[\"not a real address\"]"),
    ];

    /// The declared field lists for one method, from the manifest.
    fn declared(manifest: &toml::Table, method: &str) -> (Vec<String>, Vec<String>, Vec<String>) {
        let Some(entries) = manifest.get("rpc").and_then(toml::Value::as_array) else {
            panic!("the manifest must carry an `rpc` array");
        };
        let entry = entries.iter().find(|entry| {
            entry
                .get("method")
                .and_then(toml::Value::as_str)
                .is_some_and(|name| name == method)
        });
        let Some(entry) = entry else {
            panic!("`{method}` is compared but carries no manifest entry");
        };
        let list = |key: &str| -> Vec<String> {
            entry
                .get(key)
                .and_then(toml::Value::as_array)
                .map(|array| {
                    array
                        .iter()
                        .filter_map(|value| value.as_str().map(alloc::borrow::ToOwned::to_owned))
                        .collect()
                })
                .unwrap_or_default()
        };
        let mut missing = list("schema_missing");
        let mut extra = list("schema_extra");
        let mut mismatched = list("schema_mismatched");
        missing.sort_unstable();
        extra.sort_unstable();
        mismatched.sort_unstable();
        (missing, extra, mismatched)
    }

    /// Every compared method differs from Core exactly as the manifest says.
    ///
    /// Both directions, and the second is the one that keeps this honest. A
    /// field that starts differing fails, which is the obvious half. A field
    /// the manifest records as differing and which no longer does *also*
    /// fails -- a stale deviation is a lie in the other direction, and the
    /// usual way a compatibility document rots is by describing a gap somebody
    /// quietly closed.
    ///
    /// The failure message names each field rather than saying the shapes
    /// differ, because "differs" is not something anyone can act on.
    #[test]
    fn compared_methods_differ_from_core_exactly_as_declared() {
        let schemas = load_schemas();
        let manifest: toml::Table = toml::from_str(crate::compat_manifest::MANIFEST_TOML)
            .unwrap_or_else(|err| panic!("the compatibility manifest must parse: {err}"));
        let handler = crate::Handler::new(Arc::new(
            Context::new()
                .with_mining_control(Arc::new(SchemaMiningControl))
                .with_debug_log_path(std::path::PathBuf::from("/tmp/debug.log")),
        ));

        let mut report = alloc::string::String::new();
        for (method, params) in COMPARED {
            let Some(schema) = schemas.get(*method) else {
                panic!("`{method}` is compared but absent from the extracted Core schema");
            };
            let parsed: sonic_rs::Value = sonic_rs::from_str(params)
                .unwrap_or_else(|err| panic!("`{method}` parameters must parse: {err}"));
            let Ok(answer) = handler.dispatch(method, &parsed) else {
                // A method in this list must answer, or it is not being
                // compared and the list is overstating its own coverage.
                panic!("`{method}` {params} is listed as compared but does not answer");
            };

            let found = diff_best(schema, &answer);
            let (missing, extra, mismatched) = declared(&manifest, method);
            if found.missing != missing || found.extra != extra || found.mismatched != mismatched {
                report.push_str(&alloc::format!(
                    "{method}:\n  found    missing={:?} extra={:?} mismatched={:?}\n                       declared missing={:?} extra={:?} mismatched={:?}\n",
                    found.missing,
                    found.extra,
                    found.mismatched,
                    missing,
                    extra,
                    mismatched
                ));
            }
        }

        assert!(
            report.is_empty(),
            "the manifest and Core's declared schemas disagree:\n{report}"
        );
    }

    /// Coverage is recorded, so it cannot silently shrink.
    ///
    /// A harness whose method list quietly gets shorter reports the same
    /// unbroken green while checking less. The count is stated here, so
    /// removing a method is a decision somebody makes rather than a diff nobody
    /// reads -- and adding one is too.
    #[test]
    fn coverage_is_recorded_so_it_cannot_silently_shrink() {
        let methods: alloc::collections::BTreeSet<_> =
            COMPARED.iter().map(|(method, _)| *method).collect();
        assert_eq!(
            methods.len(),
            20,
            "the compared-method list changed; update the count and say why in the PR"
        );
        assert_eq!(
            COMPARED.len(),
            23,
            "the compared-invocation list changed; update the count and say why in the PR"
        );
        assert_eq!(
            invocations("getrawmempool"),
            &["[]", "[true]", "[false, true]"],
            "getrawmempool must exercise the array, verbose, and sequence result shapes"
        );
        assert_eq!(
            invocations("validateaddress"),
            &[
                "[\"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4\"]",
                "[\"not a real address\"]",
            ],
            "validateaddress must exercise both the valid and sparse-invalid shapes"
        );

        let schemas = load_schemas();
        assert!(
            schemas.len() > 90,
            "the extracted Core schema holds {} methods, which does not look like a \
             full extraction -- the extractor, not this node, is what broke",
            schemas.len()
        );
    }

    fn invocations(method: &str) -> alloc::vec::Vec<&str> {
        COMPARED
            .iter()
            .filter(|(name, _)| *name == method)
            .map(|(_, params)| *params)
            .collect()
    }

    /// Core's ELISION marker is a splice, not a field. The checked-in document
    /// must already be expanded: a leftover empty-name ELISION would make
    /// `getblock` verbosity 2 compare against a fictitious key and miss every
    /// inherited field.
    #[test]
    fn extracted_schema_expands_elision_instead_of_emitting_it() {
        let schemas = load_schemas();
        for (method, schema) in &schemas {
            for variant in &schema.variants {
                for field in &variant.fields {
                    assert_ne!(
                        field.kind, "ELISION",
                        "{method}: unexpanded ELISION field {:?}",
                        field.name
                    );
                }
            }
        }

        let getblock = schemas
            .get("getblock")
            .unwrap_or_else(|| panic!("getblock must be in the extracted schema"));
        let verbosity_2 = getblock
            .variants
            .iter()
            .find(|variant| variant.when.as_deref() == Some("for verbosity = 2"))
            .unwrap_or_else(|| panic!("getblock must declare a verbosity-2 variant"));
        let names: alloc::vec::Vec<_> = verbosity_2
            .fields
            .iter()
            .map(|field| field.name.as_str())
            .collect();
        assert!(
            names.contains(&"hash") && names.contains(&"tx"),
            "getblock verbosity 2 must inherit verbosity 1's fields, not only tx: {names:?}"
        );

        let getrawtransaction = schemas
            .get("getrawtransaction")
            .unwrap_or_else(|| panic!("getrawtransaction must be in the extracted schema"));
        let verbosity_2 = getrawtransaction
            .variants
            .iter()
            .find(|variant| variant.when.as_deref() == Some("for verbosity = 2"))
            .unwrap_or_else(|| panic!("getrawtransaction must declare a verbosity-2 variant"));
        let names: alloc::vec::Vec<_> = verbosity_2
            .fields
            .iter()
            .map(|field| field.name.as_str())
            .collect();
        assert!(
            names.contains(&"hex") && names.contains(&"fee") && names.contains(&"vin"),
            "getrawtransaction verbosity 2 must inherit verbosity 1's fields: {names:?}"
        );
    }

    /// The BIP173 fixture must actually take the valid branch. An invalid
    /// look-alike still schema-matches, because every valid-address field is
    /// optional and the sparse `{isvalid: false}` object is then a silent pass.
    #[test]
    fn validateaddress_valid_fixture_emits_the_valid_fields() {
        let handler = crate::Handler::new(Arc::new(
            Context::new().with_mining_control(Arc::new(SchemaMiningControl)),
        ));
        let params = sonic_rs::from_str("[\"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4\"]")
            .unwrap_or_else(|err| panic!("{err}"));
        let answer = handler
            .dispatch("validateaddress", &params)
            .unwrap_or_else(|err| panic!("validateaddress must answer: {err}"));
        let isvalid = answer
            .get("isvalid")
            .and_then(sonic_rs::JsonValueTrait::as_bool);
        assert_eq!(isvalid, Some(true), "expected a valid address: {answer}");
        for field in ["address", "scriptPubKey", "isscript", "iswitness"] {
            assert!(
                answer.get(field).is_some(),
                "valid validateaddress must emit {field}: {answer}"
            );
        }
    }

    /// `STR_AMOUNT` is a number on the wire. Reading the name as a string is
    /// how the first run reported every amount field as a type mismatch.
    #[test]
    fn str_amount_matches_a_number_not_a_string() {
        let number = sonic_rs::from_str("1.5").unwrap_or_else(|err| panic!("{err}"));
        let text = sonic_rs::from_str("\"1.5\"").unwrap_or_else(|err| panic!("{err}"));
        assert!(super::type_matches("STR_AMOUNT", &number));
        assert!(!super::type_matches("STR_AMOUNT", &text));
        assert!(!super::type_matches("NOT_A_CORE_TYPE", &number));
    }

    /// `OBJ_DYN` keys are placeholders. Comparing them as literals reports the
    /// placeholder missing and every real key extra.
    #[test]
    fn obj_dyn_compares_values_not_placeholder_keys() {
        let schema = super::CoreSchema {
            variants: alloc::vec![super::CoreVariant {
                when: None,
                kind: "OBJ_DYN".into(),
                fields: alloc::vec![super::CoreField {
                    name: "name".into(),
                    kind: "OBJ".into(),
                    optional: false,
                }],
            }],
        };
        let value = sonic_rs::from_str(r#"{"basicblockfilterindex":{}}"#)
            .unwrap_or_else(|err| panic!("{err}"));
        assert!(diff_best(&schema, &value).is_empty());
    }

    #[test]
    #[should_panic(expected = "must be a string")]
    fn load_schemas_rejects_a_missing_field_name() {
        let _ = super::load_schemas_from(
            r#"{"methods":{"x":{"type":"OBJ","fields":[{"type":"NUM"}]}}}"#,
        );
    }

    #[test]
    #[should_panic(expected = "unsupported schema field type")]
    fn load_schemas_rejects_an_unknown_field_type() {
        let _ = super::load_schemas_from(
            r#"{"methods":{"x":{"type":"OBJ","fields":[{"name":"n","type":"NOT_A_TYPE"}]}}}"#,
        );
    }

    #[test]
    #[should_panic(expected = "empty variants array")]
    fn load_schemas_rejects_an_empty_variants_array() {
        let _ = super::load_schemas_from(r#"{"methods":{"x":{"variants":[]}}}"#);
    }

    #[test]
    #[should_panic(expected = "unexpanded ELISION marker")]
    fn load_schemas_rejects_an_unexpanded_elision_field() {
        let _ = super::load_schemas_from(
            r#"{"methods":{"x":{"type":"OBJ","fields":[{"name":"","type":"ELISION"}]}}}"#,
        );
    }
}
