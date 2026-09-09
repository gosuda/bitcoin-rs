from pathlib import Path
import subprocess


def run(*args: str) -> str:
    result = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if result.returncode:
        print(result.stdout, flush=True)
        raise SystemExit(result.returncode)
    return result.stdout


def replace(path: str, old: str, new: str) -> None:
    file = Path(path)
    text = file.read_text()
    assert text.count(old) == 1, (path, text.count(old), old)
    file.write_text(text.replace(old, new, 1))


base = "f846c7fbeed40e70431cf83ab4f2cb656bf9ea0b"
branch = "fix/g18-sample-cell-axes"
assert run("git", "rev-parse", "HEAD").strip() == base
assert not run("git", "ls-remote", "--heads", "origin", f"refs/heads/{branch}").strip()
run("git", "switch", "-c", branch)

gate = "bin/bitcoin-rs/tests/gates/g18_hot_path_ledger.rs"
old = '''fn check_sample_paths(ledger: &Ledger) -> Result<(), (&str, &str)> {
    let ids: BTreeSet<&str> = ledger.paths.iter().map(|row| row.id.as_str()).collect();
    for cell in &ledger.cells {
        for sample in &cell.samples {
            if sample.path.is_empty() || !ids.contains(sample.path.as_str()) {
                return Err((cell.id.as_str(), sample.path.as_str()));
            }
        }
    }
    Ok(())
}

#[test]
fn cell_histories_match_the_matrix_and_runtime_schema() {
    let ledger = load_ledger();
    check_sample_paths(&ledger).unwrap_or_else(|(cell, path)| {
        panic!("cell `{cell}` contains undeclared sample path `{path}`");
    });
'''
new = '''fn check_sample_paths(ledger: &Ledger) -> Result<(), (&str, &str)> {
    let ids: BTreeSet<&str> = ledger.paths.iter().map(|row| row.id.as_str()).collect();
    for cell in &ledger.cells {
        for sample in &cell.samples {
            if sample.path.is_empty() || !ids.contains(sample.path.as_str()) {
                return Err((cell.id.as_str(), sample.path.as_str()));
            }
        }
    }
    Ok(())
}

fn canonical_corpus_id(matrix_id: &str) -> Option<&'static str> {
    match matrix_id {
        "c150" => Some("C150"),
        "cmodern" => Some("Cmodern"),
        _ => None,
    }
}

fn check_sample_cell_axes(ledger: &Ledger) -> Result<(), String> {
    for cell in &ledger.cells {
        let mut parts = cell.id.split('.');
        let Some(_domain) = parts.next() else {
            return Err(format!("cell `{}` has no domain coordinate", cell.id));
        };
        let Some(matrix_corpus) = parts.next() else {
            return Err(format!("cell `{}` has no corpus coordinate", cell.id));
        };
        let Some(_arch) = parts.next() else {
            return Err(format!("cell `{}` has no architecture coordinate", cell.id));
        };
        let Some(expected_backend) = parts.next() else {
            return Err(format!("cell `{}` has no backend coordinate", cell.id));
        };
        if parts.next().is_some() {
            return Err(format!("cell `{}` has more than four coordinates", cell.id));
        }
        let Some(expected_corpus) = canonical_corpus_id(matrix_corpus) else {
            return Err(format!(
                "cell `{}` has unknown corpus coordinate `{matrix_corpus}`",
                cell.id
            ));
        };
        for sample in &cell.samples {
            let Some(corpus) = sample.identity.corpus.as_ref() else {
                return Err(format!(
                    "cell `{}` contains a sample without corpus identity",
                    cell.id
                ));
            };
            if corpus.id != expected_corpus {
                return Err(format!(
                    "cell `{}` expects corpus `{expected_corpus}` but sample declares `{}`",
                    cell.id, corpus.id
                ));
            }
            if sample.identity.backend != expected_backend {
                return Err(format!(
                    "cell `{}` expects backend `{expected_backend}` but sample declares `{}`",
                    cell.id, sample.identity.backend
                ));
            }
        }
    }
    Ok(())
}

#[test]
fn cell_histories_match_the_matrix_and_runtime_schema() {
    let ledger = load_ledger();
    check_sample_paths(&ledger).unwrap_or_else(|(cell, path)| {
        panic!("cell `{cell}` contains undeclared sample path `{path}`");
    });
    check_sample_cell_axes(&ledger).unwrap_or_else(|error| panic!("{error}"));
'''
replace(gate, old, new)

anchor = '''/// HPA-05: a valid earlier sample must not hide a bad later sample or cell.
#[test]
fn undeclared_sample_paths_are_rejected_in_later_histories() {
    let cell_id = "muhash.cmodern.arm64.redb";
    for path in [
        "not.declared",
        "",
        " ",
        "CELL.WALL",
        "cell.wall.extra",
        "probe.assume_valid",
    ] {
        let ledger = ledger_with_sample_paths(cell_id, &["cell.wall", path]);
        assert_eq!(check_sample_paths(&ledger), Err((cell_id, path)));
    }
}
'''
addition = anchor + '''
/// HPA-12: corpus spelling and backend must agree with the cell coordinate.
#[test]
fn sample_corpus_and_backend_must_match_the_cell() {
    let cell_id = "muhash.cmodern.arm64.redb";
    let mut ledger = ledger_with_sample_paths(cell_id, &["cell.wall"]);
    assert_eq!(check_sample_cell_axes(&ledger), Ok(()));

    let sample = &mut ledger
        .cells
        .iter_mut()
        .find(|cell| cell.id == cell_id)
        .expect("fixture cell")
        .samples[0];
    sample.identity.corpus.as_mut().expect("fixture corpus").id = "C150".into();
    let error = check_sample_cell_axes(&ledger).expect_err("wrong corpus must fail");
    assert!(error.contains("expects corpus `Cmodern`"));

    sample.identity.corpus.as_mut().expect("fixture corpus").id = "Cmodern".into();
    sample.identity.backend = "rocksdb".into();
    let error = check_sample_cell_axes(&ledger).expect_err("wrong backend must fail");
    assert!(error.contains("expects backend `redb`"));
}

/// HPA-12: matrix spelling is mapped explicitly instead of case-folded.
#[test]
fn corpus_coordinate_mapping_is_exact() {
    assert_eq!(canonical_corpus_id("c150"), Some("C150"));
    assert_eq!(canonical_corpus_id("cmodern"), Some("Cmodern"));
    for invalid in ["C150", "Cmodern", "modern", "c150.extra", ""] {
        assert_eq!(canonical_corpus_id(invalid), None);
    }
}
'''
replace(gate, anchor, addition)

contract = "docs/contracts/hot-path-attribution.md"
old = '''### `HPA-12`: Evidence identity per sample

- Every sample in the evidence ledger carries an identity tuple:
  artifact (binary or library hash), configuration (feature set,
  backend, network, cache budget), corpus (stop hash, block count,
  validity class), and durability identity (flush mode, checkpoint
  policy, `CURRENT_SCHEMA`).
- A sample missing any of these four fields is inadmissible. It cannot
  fill a product cell or supply a promotion or regression verdict.
'''
new = '''### `HPA-12`: Evidence identity per sample

- Every sample in the evidence ledger carries an identity tuple:
  artifact (binary or library hash), configuration (feature set,
  backend, network, cache budget), corpus (stop hash, block count,
  validity class), and durability identity (flush mode, checkpoint
  policy, `CURRENT_SCHEMA`).
- A sample missing any of these four fields is inadmissible. It cannot
  fill a product cell or supply a promotion or regression verdict.
- G18 binds each sample's canonical corpus id and backend to the corpus
  and backend coordinates in its cell id. Matrix `c150` maps only to
  evidence `C150`; `cmodern` maps only to `Cmodern`; backend spelling is
  exact. The current sample schema has no separate canonical architecture
  field, so G18 does not infer an architecture coordinate from the
  free-form hardware identity.
'''
replace(contract, old, new)
proof_old = '''  `additional_declared_sample_paths_are_allowed`, and
  `undeclared_sample_paths_are_rejected_in_later_histories` for HPA-05.
'''
proof_new = '''  `additional_declared_sample_paths_are_allowed`, and
  `undeclared_sample_paths_are_rejected_in_later_histories` for HPA-05;
  `sample_corpus_and_backend_must_match_the_cell` and
  `corpus_coordinate_mapping_is_exact` for HPA-12.
'''
replace(contract, proof_old, proof_new)

run("rustfmt", "--edition", "2024", gate)
run("git", "diff", "--check")
changed = run("git", "diff", "--name-only").splitlines()
assert set(changed) == {gate, contract}, changed
print(run("git", "diff", "--stat"), flush=True)
print(run("git", "diff", "--", gate, contract), flush=True)
run("git", "add", "--", gate, contract)
run(
    "git",
    "-c",
    "user.name=github-actions[bot]",
    "-c",
    "user.email=41898282+github-actions[bot]@users.noreply.github.com",
    "commit",
    "-m",
    "test(g18): bind sample corpus and backend to their cells",
)
run("git", "push", "origin", f"HEAD:refs/heads/{branch}")
print("PUBLISHED_SHA=" + run("git", "rev-parse", "HEAD").strip(), flush=True)
