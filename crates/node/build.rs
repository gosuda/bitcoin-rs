//! Compile-time identity for storage-footprint evidence: git commit and rustc.

fn main() {
    let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") else {
        return;
    };
    let manifest_dir = std::path::PathBuf::from(manifest_dir);
    let lock_path = manifest_dir.join("../../Cargo.lock");
    println!("cargo:rerun-if-changed={}", lock_path.display());
    // Git HEAD may be either a detached commit or a symbolic reference.
    let git_dir = manifest_dir.join("../../.git");
    println!("cargo:rerun-if-changed={}", git_dir.join("HEAD").display());
    println!("cargo:rerun-if-changed={}", git_dir.join("index").display());

    if let Ok(output) = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(&manifest_dir)
        .output()
    {
        if output.status.success() {
            if let Ok(commit) = String::from_utf8(output.stdout) {
                let commit = commit.trim();
                if !commit.is_empty() {
                    println!("cargo:rustc-env=GIT_COMMIT={commit}");
                }
            }
        }
    }

    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    if let Ok(output) = std::process::Command::new(rustc).arg("-vV").output() {
        if let Ok(text) = String::from_utf8(output.stdout) {
            for line in text.lines() {
                if let Some(release) = line.strip_prefix("release: ") {
                    println!("cargo:rustc-env=RUSTC_RELEASE={release}");
                }
                if let Some(commit) = line.strip_prefix("commit-hash: ") {
                    println!("cargo:rustc-env=RUSTC_COMMIT={commit}");
                }
            }
        }
    }
}
