//! G20 — Formal model checker gate.
//!
//! **G20 — Formal models.** Runs the pinned Apalache 0.62.2 checker against the
//! `docs/models/{ChainAdmission,PeerLeases,ProjectionMining}.tla` and `.cfg`
//! files, per plan appendix FTL-4 and FTL-5.
//!
//! A red gate blocks production bodies of the implementer tasks it guards:
//! `ChainAdmission` gates T08/T11/T18; `PeerLeases` gates T24;
//! `ProjectionMining` gates T29/T35. The model is checked before the owner cut,
//! never the reverse.
//!
//! Contract: `CONSTRAINTS.md` §"Proof inventory" and `docs/api/core-compat.toml`
//! `[reference.formal_tool]`.

#![expect(
    clippy::expect_used,
    reason = "gate test: panics name the missing identity per FTL-5 rc semantics"
)]

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use bitcoin::hashes::{Hash, sha256};
use bitcoin_rs_rpc::compat_manifest::{ReferenceSet, reference_set};

const EXPECTED_VERSION: &str = "0.62.2";
const MODELS: [&str; 3] = ["ChainAdmission", "PeerLeases", "ProjectionMining"];
const SAFETY_INV: &str = "--inv=TypeOK,Safety,TransitionSafety";
const TEMPORAL: &str = "--temporal=ConditionalProgress";
const LENGTH: &str = "--length=128";
const CONSTRAINTS: &str = "CONSTRAINTS.md";
const JAR: &str = "lib/apalache.jar";
const JVM_ARGS_DEFAULT: &str = "4096m";
const SMT_SOLVER_DEFAULT: &str = "z3";
const TIMEOUT_SECS: u64 = 3600;
const OUTCOME_NO_ERROR: &str = "The outcome is: NoError";
const EXITCODE_OK: &str = "EXITCODE: OK";
const HEX: &[u8; 16] = b"0123456789abcdef";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CheckKind {
    Safety,
    Temporal,
}
struct InventoryRow {
    tla_sha: [u8; 32],
    cfg_sha: [u8; 32],
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("resolve workspace root")
}

fn apalache_home() -> PathBuf {
    match std::env::var_os("APALACHE_HOME") {
        Some(v) if !v.is_empty() => PathBuf::from(v),
        _ => workspace_root().join("target/tools/apalache-0.62.2"),
    }
}

fn apalache_executable(home: &Path) -> PathBuf {
    home.join("bin").join("apalache-mc")
}

fn jar_path(home: &Path) -> PathBuf {
    home.join(JAR)
}

fn file_sha256(path: &Path) -> [u8; 32] {
    let bytes = fs::read(path).expect("read file for sha256");
    sha256::Hash::hash(&bytes).to_byte_array()
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(char::from(HEX[usize::from(b >> 4)]));
        s.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    s
}

fn parse_sha256_hex(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

fn reference_set_or_fail() -> ReferenceSet {
    let Ok(set) = reference_set() else {
        panic!("g20: compat manifest reference set unreadable (skill rc 11)");
    };
    set
}

fn spawn_or_chmod(cmd: &mut Command, exe: &Path) -> std::io::Result<Child> {
    match cmd.spawn() {
        Ok(child) => Ok(child),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = fs::metadata(exe) {
                    let mut perms = meta.permissions();
                    perms.set_mode(0o755);
                    let _ = fs::set_permissions(exe, perms).ok();
                }
            }
            cmd.spawn()
        }
        Err(e) => Err(e),
    }
}

fn run_version(exe: &Path) -> std::process::Output {
    let mut cmd = Command::new(exe);
    cmd.arg("version").current_dir(workspace_root());
    match cmd.output() {
        Ok(out) => out,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = fs::metadata(exe) {
                    let mut perms = meta.permissions();
                    perms.set_mode(0o755);
                    let _ = fs::set_permissions(exe, perms).ok();
                }
            }
            Command::new(exe)
                .arg("version")
                .current_dir(workspace_root())
                .output()
                .expect("run apalache-mc version after chmod")
        }
        Err(e) => panic!("g20: cannot run apalache-mc version (skill rc 11): {e}"),
    }
}

fn verify_tool_identity() -> PathBuf {
    let home = apalache_home();
    let exe = apalache_executable(&home);
    let jar = jar_path(&home);
    let set = reference_set_or_fail();

    assert!(
        exe.is_file(),
        "g20: apalache-mc executable missing at {} (skill rc 11)",
        exe.display()
    );
    assert!(
        jar.is_file(),
        "g20: apalache.jar missing at {} (skill rc 11)",
        jar.display()
    );
    assert!(
        set.formal_tool.version == EXPECTED_VERSION,
        "g20: compat manifest formal_tool.version is {} but {} was expected (skill rc 11)",
        set.formal_tool.version,
        EXPECTED_VERSION
    );

    let version_out = run_version(&exe);
    let version_text = String::from_utf8_lossy(&version_out.stdout).to_string()
        + &*String::from_utf8_lossy(&version_out.stderr);
    assert!(
        version_text.contains(&set.formal_tool.version),
        "g20: apalache-mc version output does not contain {}: stdout={:?} stderr={:?} (skill rc 11)",
        set.formal_tool.version,
        String::from_utf8_lossy(&version_out.stdout),
        String::from_utf8_lossy(&version_out.stderr)
    );

    let jar_hash = file_sha256(&jar);
    assert!(
        jar_hash == set.formal_tool.jar_sha256,
        "g20: apalache.jar SHA256 mismatch (skill rc 11): expected {} computed {}",
        hex_lower(&set.formal_tool.jar_sha256),
        hex_lower(&jar_hash)
    );

    home
}

fn parse_inventory(root: &Path) -> BTreeMap<String, InventoryRow> {
    let path = root.join(CONSTRAINTS);
    let text = fs::read_to_string(&path).expect("read CONSTRAINTS.md");
    let mut rows = BTreeMap::new();
    let mut in_inventory = false;

    for line in text.lines() {
        if line.starts_with("## Proof inventory") {
            in_inventory = true;
            continue;
        }
        if in_inventory && line.starts_with("## ") {
            break;
        }
        if !in_inventory || !line.starts_with('|') {
            continue;
        }

        let cells: Vec<&str> = line.split('|').collect();
        if cells.len() < 9 {
            continue;
        }

        let model = cells[1].trim();
        if !MODELS.contains(&model) {
            continue;
        }

        let tla_text = cells[2].trim();
        let cfg_text = cells[3].trim();
        let k_text = cells[5].trim();
        let tla_sha = parse_sha256_hex(tla_text).unwrap_or_else(|| {
            panic!(
                "g20: {CONSTRAINTS} row for {model} has unmeasured/malformed .tla sha256 (skill rc 15)"
            );
        });
        let cfg_sha = parse_sha256_hex(cfg_text).unwrap_or_else(|| {
            panic!(
                "g20: {CONSTRAINTS} row for {model} has unmeasured/malformed .cfg sha256 (skill rc 15)"
            );
        });
        let k = k_text.parse::<u32>().unwrap_or_else(|_| {
            panic!("g20: {CONSTRAINTS} row for {model} has unmeasured/malformed K (skill rc 15)")
        });
        assert!(
            k == 128,
            "g20: {CONSTRAINTS} row for {model} has K={k} but 128 required (skill rc 15)",
        );

        rows.insert(model.to_string(), InventoryRow { tla_sha, cfg_sha });
    }

    for model in MODELS {
        assert!(
            rows.contains_key(model),
            "g20: {CONSTRAINTS} proof inventory missing row for {model} (skill rc 15)",
        );
    }

    rows
}

fn verify_proof_inventory() -> BTreeMap<String, InventoryRow> {
    let root = workspace_root();
    let inventory = parse_inventory(&root);

    for model in MODELS {
        let row = inventory.get(model).expect("inventory row present");
        let tla = root.join("docs/models").join(format!("{model}.tla"));
        let cfg = root.join("docs/models").join(format!("{model}.cfg"));

        assert!(
            tla.is_file(),
            "g20: model file missing {} (skill rc 15)",
            tla.display()
        );
        assert!(
            cfg.is_file(),
            "g20: config file missing {} (skill rc 15)",
            cfg.display()
        );
        let tla_hash = file_sha256(&tla);
        assert!(
            tla_hash == row.tla_sha,
            "g20: {model}.tla SHA256 diverges from {} (skill rc 15): expected {} computed {}",
            CONSTRAINTS,
            hex_lower(&row.tla_sha),
            hex_lower(&tla_hash)
        );

        let cfg_hash = file_sha256(&cfg);
        assert!(
            cfg_hash == row.cfg_sha,
            "g20: {model}.cfg SHA256 diverges from {} (skill rc 15): expected {} computed {}",
            CONSTRAINTS,
            hex_lower(&row.cfg_sha),
            hex_lower(&cfg_hash)
        );
    }

    inventory
}

fn skill_rc(native: Option<i32>) -> u8 {
    match native {
        Some(0) => 0,
        Some(150 | 120) => 12,
        Some(12) => 13,
        None | Some(_) => 14,
    }
}

fn find_evidence(dir: &Path, depth: usize) -> Vec<PathBuf> {
    let mut found = Vec::new();
    if depth == 0 {
        return found;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return found;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() && depth > 1 {
            found.extend(find_evidence(&path, depth - 1));
        } else if path.is_file() {
            let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if name == "detailed.log" || name.starts_with("counterexample") {
                found.push(path);
            }
        }
    }
    found
}

fn copy_to_run_dir(out_dir: &Path, src: &Path, n: u8) -> PathBuf {
    let stem = src
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("evidence");
    let ext = src.extension().and_then(|s| s.to_str()).unwrap_or("");
    let dst_name = if ext.is_empty() {
        format!("{stem}-run-{n}")
    } else {
        format!("{stem}-run-{n}.{ext}")
    };
    let dst = out_dir.join(dst_name);
    fs::copy(src, &dst).expect("copy evidence file");
    dst
}

fn collect_evidence(root: &Path, out_dir: &Path, n: u8) -> Vec<PathBuf> {
    let mut evidence = find_evidence(out_dir, 2);

    for src in find_evidence(root, 1) {
        if src.parent() == Some(out_dir) {
            continue;
        }
        evidence.push(copy_to_run_dir(out_dir, &src, n));
    }

    evidence
}

fn execute_and_capture(
    cmd: &mut Command,
    exe: &Path,
    model: &str,
    kind: CheckKind,
) -> (Option<i32>, Vec<u8>, Vec<u8>) {
    let mut child = match spawn_or_chmod(cmd, exe) {
        Ok(c) => c,
        Err(e) => panic!("g20: cannot spawn apalache-mc for {model} {kind:?} (skill rc 14): {e}"),
    };

    let stdout_handle = child.stdout.take().expect("stdout pipe");
    let stderr_handle = child.stderr.take().expect("stderr pipe");

    let out_thread = thread::spawn(move || {
        let mut buf = Vec::new();
        let mut reader = stdout_handle;
        let _ = reader.read_to_end(&mut buf).ok();
        buf
    });
    let err_thread = thread::spawn(move || {
        let mut buf = Vec::new();
        let mut reader = stderr_handle;
        let _ = reader.read_to_end(&mut buf).ok();
        buf
    });

    let timeout = Duration::from_secs(TIMEOUT_SECS);
    let start = Instant::now();
    let native_rc = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.code(),
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill().ok();
                    let _ = child.wait().ok();
                    break None;
                }
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("g20: try_wait failed for {model} {kind:?} (skill rc 14): {e}"),
        }
    };

    let stdout = out_thread.join().expect("stdout reader");
    let stderr = err_thread.join().expect("stderr reader");
    (native_rc, stdout, stderr)
}

fn run_one(root: &Path, exe: &Path, model: &str, kind: CheckKind, n: u8) {
    let mut args = vec![
        "check".to_string(),
        format!("--config=docs/models/{model}.cfg"),
    ];
    match kind {
        CheckKind::Safety => args.push(SAFETY_INV.to_string()),
        CheckKind::Temporal => args.push(TEMPORAL.to_string()),
    }
    args.push(LENGTH.to_string());
    args.push(format!("--out-dir=target/apalache/{model}"));
    args.push(format!("docs/models/{model}.tla"));

    assert!(
        args.iter().any(|a| a == SAFETY_INV || a == TEMPORAL),
        "g20: argv missing expected property list"
    );
    assert!(
        args.iter().any(|a| a == LENGTH),
        "g20: argv missing --length=128"
    );

    let jvm_args = std::env::var("JVM_ARGS").unwrap_or_else(|_| JVM_ARGS_DEFAULT.to_string());
    let smt_solver = std::env::var("SMT_SOLVER").unwrap_or_else(|_| SMT_SOLVER_DEFAULT.to_string());

    let out_dir = root.join("target/apalache").join(model);
    fs::create_dir_all(&out_dir).expect("create apalache out-dir");

    let mut cmd = Command::new(exe);
    cmd.args(&args)
        .current_dir(root)
        .env("JVM_ARGS", &jvm_args)
        .env("SMT_SOLVER", &smt_solver)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let (native_rc, stdout, stderr) = execute_and_capture(&mut cmd, exe, model, kind);
    let skill = skill_rc(native_rc);

    let evidence = collect_evidence(root, &out_dir, n);
    let run_file = out_dir.join(format!("run-{n}.txt"));

    let mut run_text = String::new();
    run_text.push_str(&format!("# argv: {} {}\n", exe.display(), args.join(" ")));
    run_text.push_str(&format!(
        "# env: JVM_ARGS={jvm_args} SMT_SOLVER={smt_solver}\n"
    ));
    run_text.push_str(&format!("# native rc: {native_rc:?}, skill rc: {skill}\n"));
    run_text.push_str(&format!(
        "# evidence: {}\n",
        evidence
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ));
    run_text.push_str("# --- stdout ---\n");
    run_text.push_str(&String::from_utf8_lossy(&stdout));
    run_text.push_str("# --- stderr ---\n");
    run_text.push_str(&String::from_utf8_lossy(&stderr));
    fs::write(&run_file, run_text).expect("write run-<n>.txt");

    let combined = String::from_utf8_lossy(&stdout).to_string() + &String::from_utf8_lossy(&stderr);

    let trace = if let Some(p) = evidence.iter().find(|p| {
        p.file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|n| n.starts_with("counterexample"))
    }) {
        format!("counterexample evidence: {}", p.display())
    } else {
        "no counterexample files collected".to_string()
    };

    if native_rc != Some(0) {
        let hint = match skill {
            12 => "parse or type-check error",
            13 => &trace,
            14 => "spec-eval, system error, or timeout",
            _ => "unknown failure",
        };
        panic!(
            "g20: apalache {model} {kind:?} failed (native rc {:?} -> skill rc {skill}): {hint}; see {}",
            native_rc,
            run_file.display()
        );
    }
    assert!(
        combined.contains(OUTCOME_NO_ERROR),
        "g20: apalache {model} {kind:?} reported rc 0 but missing '{}' (skill rc 14); see {}",
        OUTCOME_NO_ERROR,
        run_file.display()
    );
    assert!(
        combined.contains(EXITCODE_OK),
        "g20: apalache {model} {kind:?} reported rc 0 but missing '{}' (skill rc 14); see {}",
        EXITCODE_OK,
        run_file.display()
    );
}

#[test]
fn apalache_tool_and_inventory_are_pinned() {
    verify_tool_identity();
    verify_proof_inventory();
}

#[test]
fn all_model_specs_check_with_apalache() {
    let home = verify_tool_identity();
    let _inventory = verify_proof_inventory();
    let root = workspace_root();
    let exe = apalache_executable(&home);

    for model in MODELS {
        run_one(&root, &exe, model, CheckKind::Safety, 1);
    }
    for model in MODELS {
        run_one(&root, &exe, model, CheckKind::Temporal, 2);
    }
}
