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


base = "d493b5dc24a1d3d10a9158caec2739e9f2741996"
branch = "fix/corpus-manifest-reader-integrity"
assert run("git", "rev-parse", "HEAD").strip() == base
assert not run("git", "ls-remote", "--heads", "origin", f"refs/heads/{branch}").strip()
run("git", "switch", "-c", branch)

codec = "tools/campaign-corpus/corpus.py"
replace(
    codec,
    "            self._entries.write(line + b\"\\n\")\n",
    "            _write_all(self._entries, line + b\"\\n\")\n",
)
replace(
    codec,
    '''        if not digits:
            raise ContractError(f"manifest {label} is not a JSON integer")
        return int(digits.decode("ascii"))
''',
    '''        if not digits:
            raise ContractError(f"manifest {label} is not a JSON integer")
        if len(digits) > 1 and digits[0] == ord("0"):
            raise ContractError(f"manifest {label} has a leading-zero JSON integer")
        return int(digits.decode("ascii"))
''',
)

tests = "tools/campaign-corpus/test_corpus.py"
replace(
    tests,
    '''class _FlakyWrites:
    """Writable stream wrapper that can inject a partial write then fail."""

    def __init__(self, stream: io.BufferedIOBase) -> None:
        self._stream = stream
        self.poisoned = False

    def write(self, data) -> int:
        if self.poisoned:
            self.poisoned = False
            if len(data) > 1:
                self._stream.write(data[: len(data) // 2])
            raise OSError("injected partial write failure")
        return self._stream.write(data)

    def __getattr__(self, name: str):
        return getattr(self._stream, name)
''',
    '''class _FlakyWrites:
    """Writable stream wrapper that can inject a partial write then fail."""

    def __init__(self, stream: io.BufferedIOBase) -> None:
        self._stream = stream
        self.poisoned = False

    def write(self, data) -> int:
        if self.poisoned:
            self.poisoned = False
            if len(data) > 1:
                self._stream.write(data[: len(data) // 2])
            raise OSError("injected partial write failure")
        return self._stream.write(data)

    def __getattr__(self, name: str):
        return getattr(self._stream, name)


class _ShortWrites:
    """Writable stream wrapper that succeeds after writing only a short prefix."""

    def __init__(self, stream: io.BufferedIOBase, chunk: int) -> None:
        self._stream = stream
        self._chunk = chunk

    def write(self, data) -> int:
        return self._stream.write(data[: self._chunk])

    def __getattr__(self, name: str):
        return getattr(self._stream, name)
''',
)

anchor = '''    def test_float_and_bool_integer_aliases_are_rejected(self) -> None:
        for label, mutate in (
            ("version-float", lambda doc: doc.update({"version": 1.0})),
            ("version-bool", lambda doc: doc.update({"version": True})),
            ("start-float", lambda doc: doc["range"].update({"start_height": 0.0})),
            ("size-float", lambda doc: doc["archive"].update({"size": float(FIX_ARCHIVE_SIZE)})),
            ("length-float", lambda doc: doc["entries"][2].update({"payload_length": 80.0})),
        ):
            with self.subTest(alias=label):
                doc = _golden_doc()
                mutate(doc)
                doc["manifest_sha256"] = _digest_over(doc)
                with self.assertRaises(ContractError):
                    _verify(self.freeze, self.root, _canonical(doc) + b"\\n")
'''
addition = anchor + '''
    def test_leading_zero_json_integer_is_rejected(self) -> None:
        canonical = _GOLDEN_MANIFEST.decode("ascii")
        malformed = canonical.replace('"version":1', '"version":01', 1)
        self.assertNotEqual(malformed, canonical)
        # Decoding 01 as integer 1 would reproduce the same canonical
        # preimage and therefore pass the digest check. JSON itself forbids it.
        with self.assertRaisesRegex(ContractError, "leading-zero JSON integer"):
            _verify(self.freeze, self.root, malformed.encode("ascii"))

    def test_manifest_entry_spool_survives_successful_short_writes(self) -> None:
        archive = io.BytesIO(_GOLDEN_ARCHIVE)
        manifest = io.BytesIO(_GOLDEN_MANIFEST)
        backing = io.BytesIO()
        spool = _ShortWrites(backing, 3)
        product = corpus.verify_archive(self.freeze, archive, manifest, entries=spool)
        self.assertEqual(product.corpus_id, FIX_CORPUS)
        backing.seek(0)
        lines = backing.readlines()
        self.assertEqual(len(lines), len(_expected_entries()))
        self.assertTrue(all(line.endswith(b"\\n") for line in lines))
'''
replace(tests, anchor, addition)

run("python3", "-m", "py_compile", codec, tests)
run("git", "diff", "--check")
changed = run("git", "diff", "--name-only").splitlines()
assert set(changed) == {codec, tests}, changed
print(run("git", "diff", "--stat"), flush=True)
print(run("git", "diff", "--", codec, tests), flush=True)
run("git", "add", "--", codec, tests)
run(
    "git",
    "-c",
    "user.name=github-actions[bot]",
    "-c",
    "user.email=41898282+github-actions[bot]@users.noreply.github.com",
    "commit",
    "-m",
    "fix(corpus): enforce JSON integer grammar and complete spool writes",
)
run("git", "push", "origin", f"HEAD:refs/heads/{branch}")
print("PUBLISHED_SHA=" + run("git", "rev-parse", "HEAD").strip(), flush=True)
