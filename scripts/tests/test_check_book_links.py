"""Offline tests of the mdBook link checker fixtures, not the live book."""

import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import check_book_links as checker

GOOD_SUMMARY = """\
# Summary

[Introduction](intro.md)

- [Chapter](chapter.md)
"""

GOOD_INTRO = """\
# Introduction

Same-file [anchor](#introduction), cross-file [setup](chapter.md#setup),
blob [lib](https://github.com/gosuda/bitcoin-rs/blob/main/crates/foo/src/lib.rs#L10-L20),
tree [dir](https://github.com/gosuda/bitcoin-rs/tree/main/crates/foo),
inline code `[ghost](ghost.md)` stays text.

[labelled][ref] uses the definition below.

[ref]: chapter.md#setup "labelled chapter"

```sh
[fenced](ghost.md)
```
"""

GOOD_CHAPTER = """\
# Chapter

## Setup

Raw anchor <a id="custom"></a> exists.
"""

# (heading body, expected mdBook id) pairs verified against a real
# `mdbook build` id attributes on 0.5.4.
SLUG_PROBES = (
    ("Hello, World!", "hello-world"),
    ("Two  spaces", "two--spaces"),
    ("Foo_bar baz", "foo_bar-baz"),
    ("Quo's \"typed\" list", "quos-typed-list"),
    ("The `utxo` index", "the-utxo-index"),
    ("Bold **and** *ital*", "bold-and-ital"),
    ("Dot.dot", "dotdot"),
    ("CAPS ARG MAX", "caps-arg-max"),
    ("Trailing hash #", "trailing-hash"),
    ("Multi   -  dash", "multi------dash"),
)


class FixtureBook:
    """Temporary docs/book layout with the good baseline chapters."""

    def __init__(self, temp_dir: Path) -> None:
        self.root = temp_dir / "repo"
        self.book = self.root / "docs/book"
        self.src = self.book / "src"
        self.src.mkdir(parents=True)
        self.write("SUMMARY.md", GOOD_SUMMARY)
        self.write("intro.md", GOOD_INTRO)
        self.write("chapter.md", GOOD_CHAPTER)
        self.tracked("crates/foo/src/lib.rs")

    def write(self, rel: str, text: str) -> Path:
        path = self.src / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def tracked(self, rel: str) -> Path:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("fixture\n", encoding="utf-8")
        return path

    def replace_summary(self, text: str) -> None:
        self.write("SUMMARY.md", text)

    def lines(self) -> list[str]:
        findings = checker.check(str(self.book))
        return [f"{f.path.removeprefix(str(self.book))}:{f.line}: {f.message}" for f in findings]


class CheckBookLinksTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.book = FixtureBook(Path(temporary.name))

    def test_good_book_is_clean(self) -> None:
        self.assertEqual(self.book.lines(), [])

    def test_missing_target(self) -> None:
        self.book.write(
            "intro.md",
            "# Introduction\n\n[ghost](ghost.md)\n",
        )
        self.assertEqual(
            self.book.lines(),
            [f"/src/intro.md:3: link target not found: ghost.md"],
        )

    def test_bad_anchor(self) -> None:
        self.book.write(
            "intro.md",
            "# Introduction\n\n[nope](chapter.md#missing) and [self](#nope)\n",
        )
        self.assertEqual(
            self.book.lines(),
            [
                f"/src/intro.md:3: anchor not found: #nope",
                f"/src/intro.md:3: anchor not found: chapter.md#missing",
            ],
        )

    def test_unlisted_chapter(self) -> None:
        self.book.write("extra.md", "# Extra\n")
        self.assertEqual(
            self.book.lines(),
            [f"/src/extra.md:1: chapter not listed in SUMMARY.md"],
        )

    def test_missing_summary_entry(self) -> None:
        self.book.replace_summary(
            "# Summary\n\n[Introduction](intro.md)\n\n- [Chapter](chapter.md)\n"
            "- [Missing](missing.md)\n"
        )
        self.assertEqual(
            self.book.lines(),
            ["/src/SUMMARY.md:6: link target not found: missing.md"],
        )

    def test_dead_blob_path(self) -> None:
        self.book.write(
            "intro.md",
            "# Introduction\n\n[dead](https://github.com/gosuda/bitcoin-rs"
            "/blob/main/crates/nope/src/lib.rs)\n",
        )
        self.assertEqual(
            self.book.lines(),
            ["/src/intro.md:3: github link is not a tracked path: crates/nope/src/lib.rs"],
        )

    def test_leaked_temp_path(self) -> None:
        self.book.write(
            "intro.md",
            "# Introduction\n\n$ bitcoin-rs --data-dir /tmp/worktree_Other/run\n",
        )
        self.assertEqual(
            self.book.lines(),
            ["/src/intro.md:3: throwaway path leaked: /tmp/worktree_"],
        )

    def test_em_dash(self) -> None:
        self.book.write("intro.md", "# Introduction\n\nfirst \u2014 second\n")
        self.assertEqual(
            self.book.lines(),
            ["/src/intro.md:3: em dash (U+2014) not allowed"],
        )

    def test_curly_quote(self) -> None:
        self.book.write("intro.md", "# Introduction\n\n\u201cquoted\u201d\n")
        self.assertEqual(
            self.book.lines(),
            [
                "/src/intro.md:3: curly quote (U+201C) not allowed",
                "/src/intro.md:3: curly quote (U+201D) not allowed",
            ],
        )

    def test_fenced_link_is_ignored(self) -> None:
        self.book.write(
            "intro.md",
            "# Introduction\n\n```sh\n[fenced](ghost.md)\n```\n",
        )
        self.assertEqual(self.book.lines(), [])

    def test_undefined_reference(self) -> None:
        self.book.write("intro.md", "# Introduction\n\n[orphan][nolabel]\n")
        self.assertEqual(
            self.book.lines(),
            ["/src/intro.md:3: reference label not defined: nolabel"],
        )

    def test_main_exit_codes(self) -> None:
        argv = ["check_book_links.py", str(self.book.book)]
        with patch.object(sys, "argv", argv):
            self.assertEqual(checker.main(), 0)
        self.book.write("intro.md", GOOD_INTRO + "\n[ghost](ghost.md)\n")
        with (
            patch.object(sys, "argv", argv),
            contextlib.redirect_stdout(io.StringIO()) as captured,
        ):
            self.assertEqual(checker.main(), 1)
        self.assertIn(
            "/src/intro.md:16: link target not found: ghost.md", captured.getvalue()
        )


class SlugTests(unittest.TestCase):
    def test_slugs_match_real_mdbook_build(self) -> None:
        for body, slug in SLUG_PROBES:
            with self.subTest(body=body):
                self.assertEqual(checker.heading_slug(body), slug)

    def test_duplicate_headings_are_numbered(self) -> None:
        page = checker.visible_lines("# Setup\n\ntext\n\n## Setup\n\nmore")[1]
        self.assertEqual(checker.page_anchors(page), {"setup", "setup-1"})

    def test_raw_html_anchor_counts(self) -> None:
        page = checker.visible_lines('# Setup\n\n<a id="custom"></a>\n')[1]
        self.assertEqual(checker.page_anchors(page), {"setup", "custom"})


if __name__ == "__main__":
    unittest.main()
