use std::io::{self, Read as _};
use std::path::Path;

use bitcoin_rs_mining::pool::stratum::sv2::AuthorityKeypair;
use thiserror::Error;
use zeroize::Zeroizing;

const KEY_BYTES: usize = 32;
const KEY_HEX_LEN: usize = KEY_BYTES * 2;
const MAX_KEY_FILE_BYTES: usize = 256;
const MAX_KEY_FILE_READ: u64 = 257;

#[derive(Debug, Error)]
pub(crate) enum AuthorityKeyError {
    #[error("could not open or read the SV2 authority key: {0}")]
    Io(#[from] io::Error),
    #[error(
        "the SV2 authority key must contain a 32-byte hex public key followed by a 32-byte hex secret key"
    )]
    InvalidFormat,
    #[cfg(unix)]
    #[error("the SV2 authority key must be a regular file with mode 0600")]
    InsecureFile,
    #[cfg(not(unix))]
    #[error("the SV2 authority key must be a regular file")]
    InsecureFile,
}

pub(crate) fn load(path: &Path) -> Result<AuthorityKeypair, AuthorityKeyError> {
    let file = open_private_file(path)?;
    let mut contents = Zeroizing::new(Vec::with_capacity(MAX_KEY_FILE_BYTES + 1));
    file.take(MAX_KEY_FILE_READ).read_to_end(&mut contents)?;
    if contents.len() > MAX_KEY_FILE_BYTES {
        return Err(AuthorityKeyError::InvalidFormat);
    }

    let text = std::str::from_utf8(&contents).map_err(|_| AuthorityKeyError::InvalidFormat)?;
    let mut fields = text.split_ascii_whitespace();
    let public_text = fields.next().ok_or(AuthorityKeyError::InvalidFormat)?;
    let secret_text = fields.next().ok_or(AuthorityKeyError::InvalidFormat)?;
    if fields.next().is_some() {
        return Err(AuthorityKeyError::InvalidFormat);
    }

    let mut public = [0; KEY_BYTES];
    decode_key_into(public_text, &mut public)?;
    let mut secret = Zeroizing::new([0; KEY_BYTES]);
    decode_key_into(secret_text, &mut secret)?;
    Ok(AuthorityKeypair::from_bytes(public, secret))
}

fn decode_key_into(text: &str, key: &mut [u8; KEY_BYTES]) -> Result<(), AuthorityKeyError> {
    if text.len() != KEY_HEX_LEN {
        return Err(AuthorityKeyError::InvalidFormat);
    }
    let digits = text.as_bytes();
    for (index, destination) in key.iter_mut().enumerate() {
        let high = hex_digit(digits[index * 2]).ok_or(AuthorityKeyError::InvalidFormat)?;
        let low = hex_digit(digits[index * 2 + 1]).ok_or(AuthorityKeyError::InvalidFormat)?;
        *destination = (high << 4) | low;
    }
    Ok(())
}

const fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(unix)]
fn open_private_file(path: &Path) -> Result<std::fs::File, AuthorityKeyError> {
    use std::os::unix::fs::PermissionsExt as _;

    use rustix::fs::{Mode, OFlags};

    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    let file = std::fs::File::from(descriptor);
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o7777 != 0o600 {
        return Err(AuthorityKeyError::InsecureFile);
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_private_file(_path: &Path) -> Result<std::fs::File, AuthorityKeyError> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "secure SV2 authority-key loading is unavailable on this platform",
    )
    .into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;

    const PUBLIC_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const SECRET_HEX: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    fn write_key_file(
        directory: &Path,
        name: &str,
        contents: &[u8],
        mode: u32,
    ) -> std::path::PathBuf {
        let path = directory.join(name);
        std::fs::write(&path, contents).expect("fixture key file must be writable");
        #[cfg(unix)]
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
            .expect("fixture key file mode must be settable");
        #[cfg(not(unix))]
        let _ = mode;
        path
    }

    fn valid_contents() -> Vec<u8> {
        format!("{PUBLIC_HEX} {SECRET_HEX}\n").into_bytes()
    }

    #[cfg(unix)]
    #[test]
    fn load_accepts_exactly_two_hex_fields_in_a_0600_regular_file() {
        let directory = tempfile::tempdir().expect("test scratch directory must exist");
        let path = write_key_file(directory.path(), "authority.key", &valid_contents(), 0o600);
        let pair = load(&path).expect("a 0600 regular file with two key fields must load");
        assert_eq!(pair.public(), &[0x11; KEY_BYTES]);
        let rendered = format!("{pair:?}");
        assert!(
            rendered.contains("<redacted>"),
            "stored secret must be redacted in Debug: {rendered}"
        );
        assert!(
            !rendered.contains(SECRET_HEX),
            "stored secret hex must never reach Debug output"
        );
    }

    #[cfg(unix)]
    #[test]
    fn load_tolerates_surrounding_ascii_whitespace_but_nothing_else() {
        let directory = tempfile::tempdir().expect("test scratch directory must exist");
        let padded = format!("\t{PUBLIC_HEX}  {SECRET_HEX}\r\n").into_bytes();
        let path = write_key_file(directory.path(), "padded.key", &padded, 0o600);
        assert!(
            load(&path).is_ok(),
            "ascii-whitespace separation must be accepted"
        );
        for (name, contents) in [
            ("empty.key", Vec::new()),
            ("one-field.key", PUBLIC_HEX.as_bytes().to_vec()),
            (
                "three-fields.key",
                format!("{PUBLIC_HEX} {SECRET_HEX} {PUBLIC_HEX}").into_bytes(),
            ),
            (
                "short-field.key",
                format!("{} {SECRET_HEX}", &PUBLIC_HEX[..62]).into_bytes(),
            ),
            (
                "non-hex.key",
                format!("{PUBLIC_HEX} {}", "zz".repeat(KEY_BYTES).as_str()).into_bytes(),
            ),
            ("non-utf8.key", [0xff; KEY_BYTES * 2].to_vec()),
        ] {
            let path = write_key_file(directory.path(), name, &contents, 0o600);
            assert!(
                matches!(load(&path), Err(AuthorityKeyError::InvalidFormat)),
                "malformed key file {name} must fail closed as InvalidFormat"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn load_rejects_inputs_larger_than_256_bytes() {
        let directory = tempfile::tempdir().expect("test scratch directory must exist");
        let oversized = vec![b'2'; MAX_KEY_FILE_BYTES + 1];
        assert_eq!(oversized.len(), 257);
        let path = write_key_file(directory.path(), "oversized.key", &oversized, 0o600);
        assert!(
            matches!(load(&path), Err(AuthorityKeyError::InvalidFormat)),
            "input above 256 bytes must fail closed as InvalidFormat"
        );
    }

    #[cfg(unix)]
    #[test]
    fn parse_errors_carry_no_key_input() {
        let directory = tempfile::tempdir().expect("test scratch directory must exist");
        let evil = format!("{PUBLIC_HEX} {}", "zz".repeat(KEY_BYTES)).into_bytes();
        let path = write_key_file(directory.path(), "evil.key", &evil, 0o644);
        let error = load(&path).expect_err("a 0644 key file must be refused");
        assert!(
            !matches!(error, AuthorityKeyError::InvalidFormat),
            "permission refusal must precede parsing: {error:?}"
        );
        let path = write_key_file(directory.path(), "badhex.key", &evil, 0o600);
        let error = load(&path).expect_err("non-hex secret must be refused");
        assert!(
            matches!(error, AuthorityKeyError::InvalidFormat),
            "malformed key must fail as InvalidFormat: {error:?}"
        );
        for rendered in [format!("{error}"), format!("{error:?}")] {
            assert!(
                !rendered.contains(&"zz".repeat(8)),
                "key input must not reach error text: {rendered}"
            );
            assert!(
                !rendered.contains(PUBLIC_HEX) && !rendered.contains(SECRET_HEX),
                "key input must not reach error text: {rendered}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn load_enforces_regular_file_and_0600_descriptor_checks() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("test scratch directory must exist");
        for mode in [0o644, 0o640, 0o600 | 0o111, 0o400] {
            let name = format!("mode-{mode:o}.key");
            let path = write_key_file(directory.path(), &name, &valid_contents(), mode);
            assert_eq!(
                std::fs::metadata(&path)
                    .expect("mode probe must be statable")
                    .permissions()
                    .mode()
                    & 0o7777,
                mode,
                "fixture must carry the probed mode"
            );
            assert!(
                matches!(load(&path), Err(AuthorityKeyError::InsecureFile)),
                "mode {mode:o} must be refused as insecure"
            );
        }
        let subdirectory = directory.path().join("not-a-file");
        std::fs::create_dir(&subdirectory).expect("fixture directory must exist");
        assert!(
            matches!(load(&subdirectory), Err(AuthorityKeyError::InsecureFile)),
            "a directory must be refused as insecure"
        );
    }

    #[cfg(unix)]
    #[test]
    fn load_refuses_a_final_component_symlink() {
        let directory = tempfile::tempdir().expect("test scratch directory must exist");
        let target = write_key_file(directory.path(), "target.key", &valid_contents(), 0o600);
        let link = directory.path().join("link.key");
        std::os::unix::fs::symlink(&target, &link).expect("fixture symlink must exist");
        assert!(
            load(&link).is_err(),
            "a final-component symlink must not bypass the descriptor check"
        );
    }

    #[cfg(not(unix))]
    #[test]
    fn load_fails_closed_without_platform_support() {
        let directory = tempfile::tempdir().expect("test scratch directory must exist");
        let path = write_key_file(directory.path(), "authority.key", &valid_contents(), 0o600);
        assert!(
            load(&path).is_err(),
            "key loading without platform support must fail closed"
        );
    }
}
