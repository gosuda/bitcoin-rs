mod clauses;
mod links;
mod render;
mod tags;
mod text;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;

const EVIDENCE_PATH: &str = "docs/contracts/evidence-index.md";
const README_PATH: &str = "docs/contracts/README.md";

#[derive(Debug, Parser)]
#[command(
    about = "Generate and check the contract evidence index",
    long_about = "Generate docs/contracts/evidence-index.md and the contract list in \
        docs/contracts/README.md from the clause definitions and the tag lines beside their \
        proofs.\n\nWith --check, verify that both generated files are current. Verify also that \
        every tag names a clause defined by a heading or a bold requirement in docs/contracts. \
        Verify also that every backticked code path under crates, bin, e2e, fuzz or tools \
        resolves, and that every path::symbol citation under those roots names a symbol in the \
        cited file. Dated records under docs/benchmarks/data cite the tree at their measurement \
        date and are not resolved. Directory references and document paths are not file \
        citations; document paths are checked as Markdown links."
)]
struct Args {
    #[arg(long)]
    check: bool,

    #[arg(long, value_name = "PATH", default_value = ".")]
    root: PathBuf,
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(problems) => {
            for problem in problems {
                eprintln!("error: {problem}");
            }
            ExitCode::FAILURE
        }
    }
}

fn run(args: &Args) -> Result<(), Vec<String>> {
    let root = resolve_root(&args.root)?;
    let mut problems = Vec::new();
    let definitions = clauses::parse(&root, &mut problems);
    let tagged = tags::scan(&root, &definitions, &mut problems);
    if !problems.is_empty() {
        return Err(problems);
    }
    let index = render::evidence_index(&definitions, &tagged);
    let block = render::readme_block(&definitions);
    if args.check {
        check(&root, &index, &block)
    } else {
        write_outputs(&root, &index, &block)
    }
}

fn resolve_root(root: &Path) -> Result<PathBuf, Vec<String>> {
    std::fs::canonicalize(root)
        .map_err(|error| vec![format!("cannot resolve root {}: {error}", root.display())])
}

fn check(root: &Path, index: &str, block: &str) -> Result<(), Vec<String>> {
    let mut problems = Vec::new();
    check_generated(root, index, block, &mut problems);
    links::check(root, &mut problems);
    if problems.is_empty() {
        return Ok(());
    }
    Err(problems)
}

fn check_generated(root: &Path, index: &str, block: &str, problems: &mut Vec<String>) {
    let index_path = root.join(EVIDENCE_PATH);
    match std::fs::read_to_string(&index_path) {
        Ok(existing) if existing == index => {}
        Ok(_) => problems.push(format!(
            "{EVIDENCE_PATH} is stale; run cargo run --locked -p contract-index"
        )),
        Err(_) => problems.push(format!(
            "{EVIDENCE_PATH} is missing; run cargo run --locked -p contract-index"
        )),
    }
    let readme_path = root.join(README_PATH);
    let existing = match std::fs::read_to_string(&readme_path) {
        Ok(existing) => existing,
        Err(error) => {
            problems.push(format!("cannot read {README_PATH}: {error}"));
            return;
        }
    };
    match render::splice_readme(&existing, block) {
        Err(problem) => problems.push(problem),
        Ok(expected) if expected == existing => {}
        Ok(_) => problems.push(format!(
            "{README_PATH} contract list is stale; run cargo run --locked -p contract-index"
        )),
    }
}

fn write_outputs(root: &Path, index: &str, block: &str) -> Result<(), Vec<String>> {
    write_file(&root.join(EVIDENCE_PATH), index)?;
    let readme_path = root.join(README_PATH);
    let readme = read_file(&readme_path)?;
    let spliced = render::splice_readme(&readme, block).map_err(|problem| vec![problem])?;
    write_file(&readme_path, &spliced)
}

fn read_file(path: &Path) -> Result<String, Vec<String>> {
    std::fs::read_to_string(path)
        .map_err(|error| vec![format!("cannot read {}: {error}", path.display())])
}

fn write_file(path: &Path, content: &str) -> Result<(), Vec<String>> {
    std::fs::write(path, content)
        .map_err(|error| vec![format!("cannot write {}: {error}", path.display())])
}
