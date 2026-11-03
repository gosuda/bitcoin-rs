#!/usr/bin/env python3
"""Check the mdBook source tree for broken links and book hygiene.

Given a book directory (default docs/book), verify every Markdown link
under src: relative .md targets exist and their #anchor matches an
mdBook heading slug (lowercase, spaces to hyphens, punctuation dropped,
duplicates numbered -1, -2, ...), links to
github.com/gosuda/bitcoin-rs/blob|tree/main resolve to tracked
repository paths, and SUMMARY.md lists exactly the chapters under src.
Chapters must not leak throwaway worktree paths, em dashes, or curly
quotes. Fenced code blocks and inline code spans are excluded from link
parsing; the parser is line-based, so links spanning lines go unchecked.
Exit code 0 means no problems; exit code 1 prints one
`path:line: message` line per problem; exit code 2 means the book
directory is unusable.
"""

import argparse
import posixpath
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

DEFAULT_BOOK = "docs/book"
GITHUB_LINK_BASE = "https://github.com/gosuda/bitcoin-rs/"
TRACKED_LINK_PREFIXES = ("blob/main/", "tree/main/")
LEAKED_PREFIXES = ("/tmp/worktree_", "/tmp/book_")
EM_DASH = "\u2014"
CURLY_QUOTES: tuple[tuple[str, str], ...] = (
    ("\u2018", "U+2018"),
    ("\u2019", "U+2019"),
    ("\u201c", "U+201C"),
    ("\u201d", "U+201D"),
)
HEADING = re.compile(r"^ {0,3}(#{1,6}) (.+)$")
FENCE_OPEN = re.compile(r"^ {0,3}(`{3,}|~{3,})")
FENCE_CLOSE = re.compile(r"^ {0,3}([`~])\1*\s*$")
INLINE_LINK = re.compile(r'(?<!\!)\[([^\]]*)\]\(([^)\s]*)(?:\s+"[^"]*")?\)')
REFERENCE_USE = re.compile(r"(?<!\!)\[([^\]]+)\]\[([^\]]*)\]")
REFERENCE_DEF = re.compile(r'^ {0,3}\[([^\]]+)\]:\s+(\S+)(?:\s+"[^"]*")?\s*$')
CODE_SPAN = re.compile(r"`[^`]+`")
ATX_CLOSE = re.compile(r"\s+#+\s*$")
HTML_ID = re.compile(r'\bid="([^"]+)"')
EMPHASIS_DELIMITER_UNDERSCORE = re.compile(r"(?<![A-Za-z0-9])_|_(?![A-Za-z0-9])")


class BookError(Exception):
    """The book directory is missing or unusable."""


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    message: str

    def render(self) -> str:
        return f"{self.path}:{self.line}: {self.message}"


@dataclass(frozen=True)
class LinkUse:
    """One link occurrence: source page, line number, raw destination."""

    rel: str
    line: int
    target: str


@dataclass(frozen=True)
class Page:
    lines: tuple[tuple[int, str], ...]
    visible: tuple[tuple[int, str], ...]
    anchors: frozenset[str]


class Book:
    """Book source tree plus the caches the checks share."""

    def __init__(self, label: str) -> None:
        self.label = label
        self.root = Path(label)
        self.src = self.root / "src"
        summary = self.src / "SUMMARY.md"
        if not summary.is_file():
            raise BookError(
                f"{self.label}/src/SUMMARY.md is missing; "
                "pass a book directory that contains src/SUMMARY.md"
            )
        self.tracked = tracked_paths(repo_root(self.root))
        self.pages: dict[str, Page] = {}

    def report(self, path: str, line: int, message: str) -> Finding:
        return Finding(f"{self.label}/src/{path}", line, message)

    def page(self, rel: str) -> Page:
        cached = self.pages.get(rel)
        if cached is not None:
            return cached
        text = (self.src / rel).read_text(encoding="utf-8")
        lines, visible = visible_lines(text)
        page = Page(lines, visible, frozenset(page_anchors(visible)))
        self.pages[rel] = page
        return page

    def chapter_paths(self) -> list[str]:
        return sorted(
            path.relative_to(self.src).as_posix()
            for path in self.src.rglob("*.md")
            if path.name != "SUMMARY.md"
        )


def repo_root(book: Path) -> Path:
    """Locate the repository root that blob and tree links resolve into.

    Without a .git marker anywhere above the book (test fixtures), the
    root is two levels up, the docs/book layout.
    """
    for candidate in (book, *book.parents):
        if (candidate / ".git").exists():
            return candidate
    return book.parents[1]


def tracked_paths(root: Path) -> frozenset[str]:
    """Tracked files and their ancestor directories, as POSIX paths."""
    try:
        listing = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            capture_output=True,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        files = [
            path.relative_to(root).as_posix()
            for path in root.rglob("*")
            if path.is_file() and ".git" not in path.parts
        ]
    else:
        files = listing.stdout.decode("utf-8", "surrogateescape").split("\0")
    tracked: set[str] = set()
    for name in files:
        if not name:
            continue
        tracked.add(name)
        parts = name.split("/")
        for index in range(1, len(parts)):
            tracked.add("/".join(parts[:index]))
    return frozenset(tracked)


def visible_lines(
    text: str,
) -> tuple[tuple[tuple[int, str], ...], tuple[tuple[int, str], ...]]:
    """Return every line and the fence-free subset as (1-based no, text)."""
    lines: list[tuple[int, str]] = []
    visible: list[tuple[int, str]] = []
    fence: str | None = None
    for number, line in enumerate(text.splitlines(), start=1):
        lines.append((number, line))
        if fence is None:
            opener = FENCE_OPEN.match(line.lstrip(" "))
            if opener is not None:
                fence = opener.group(1)[0]
                continue
            visible.append((number, line))
        else:
            closer = FENCE_CLOSE.match(line.lstrip(" "))
            if closer is not None and closer.group(1) == fence:
                fence = None
    return tuple(lines), tuple(visible)


def heading_slug(raw: str) -> str:
    """Reduce an ATX heading body to its mdBook id per normalize_id."""
    text = ATX_CLOSE.sub("", raw)
    text = re.sub(r"`([^`]*)`", r"\1", text)
    text = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"!?\[([^\]]*)\]\[[^\]]*\]", r"\1", text)
    text = re.sub(r"<[^>]+>", "", text)
    text = text.replace("*", "")
    text = EMPHASIS_DELIMITER_UNDERSCORE.sub("", text)
    text = text.replace("\\", "")
    chars: list[str] = []
    for char in text.strip():
        if char.isalnum() or char in "_-":
            chars.append(char.lower() if char.isascii() else char)
        elif char.isspace():
            chars.append("-")
    return "".join(chars)


def page_anchors(visible: list[tuple[int, str]]) -> set[str]:
    """Heading ids numbered like mdBook's find_usable_id plus raw id=."""
    anchors: set[str] = set()
    for _, line in visible:
        heading = HEADING.match(line)
        if heading is None:
            continue
        slug = heading_slug(heading.group(2))
        if not slug:
            continue
        candidate = slug
        suffix = 1
        while candidate in anchors:
            candidate = f"{slug}-{suffix}"
            suffix += 1
        anchors.add(candidate)
    for _, line in visible:
        anchors.update(HTML_ID.findall(line))
    return anchors


def resolve_target(current: str, target: str) -> str:
    """Resolve a link target against its source file to a src-relative path."""
    base = PurePosixPath(current).parent
    return posixpath.normpath(base / target)


def check_link_target(book: Book, use: LinkUse, findings: list[Finding]) -> None:
    """Validate one link destination against the file system or git."""
    target = use.target
    if not target or target.startswith("//"):
        return
    if target.startswith("#"):
        if target[1:] not in book.page(use.rel).anchors:
            findings.append(book.report(use.rel, use.line, f"anchor not found: {target}"))
        return
    scheme = target.split(":", 1)[0]
    if scheme in ("http", "https"):
        check_github_target(book, use, findings)
        return
    if "://" in target or scheme == "mailto":
        return
    target_path, _, fragment = target.partition("#")
    if not target_path.endswith(".md"):
        return
    resolved = resolve_target(use.rel, target_path)
    if not (book.src / resolved).is_file():
        findings.append(book.report(use.rel, use.line, f"link target not found: {target}"))
        return
    if fragment and fragment not in book.page(resolved).anchors:
        findings.append(book.report(use.rel, use.line, f"anchor not found: {target}"))


def check_github_target(book: Book, use: LinkUse, findings: list[Finding]) -> None:
    target = use.target
    if not target.startswith(GITHUB_LINK_BASE):
        return
    rest = target[len(GITHUB_LINK_BASE):]
    for prefix in TRACKED_LINK_PREFIXES:
        if not rest.startswith(prefix):
            continue
        blob = rest[len(prefix):].split("#", 1)[0].rstrip("/")
        if blob and blob not in book.tracked:
            findings.append(
                book.report(use.rel, use.line, f"github link is not a tracked path: {blob}")
            )
        return


def reference_definitions(page: Page) -> dict[str, tuple[int, str]]:
    """Collect document-scoped link reference definitions, first wins."""
    definitions: dict[str, tuple[int, str]] = {}
    for line_no, line in page.visible:
        clean = CODE_SPAN.sub("", line)
        for match in REFERENCE_DEF.finditer(clean):
            label = match.group(1).strip().lower()
            if label not in definitions:
                definitions[label] = (line_no, match.group(2))
    return definitions


def check_page_links(book: Book, rel: str, findings: list[Finding]) -> None:
    """Parse inline and reference links on fence-free lines of one page."""
    page = book.page(rel)
    definitions = reference_definitions(page)
    for line_no, target in definitions.values():
        check_link_target(book, LinkUse(rel, line_no, target), findings)
    for line_no, line in page.visible:
        clean = CODE_SPAN.sub("", line)
        for match in INLINE_LINK.finditer(clean):
            text, target = match.group(1), match.group(2)
            if not text.startswith("!"):
                check_link_target(book, LinkUse(rel, line_no, target), findings)
        for match in REFERENCE_USE.finditer(clean):
            label, reference = match.group(1), match.group(2)
            if label.startswith("^"):
                continue
            reference = reference or label
            defined = definitions.get(reference.strip().lower())
            if defined is None:
                findings.append(
                    book.report(rel, line_no, f"reference label not defined: {reference}")
                )
                continue
            check_link_target(book, LinkUse(rel, line_no, defined[1]), findings)


def check_summary(book: Book, findings: list[Finding]) -> dict[str, int]:
    """Check SUMMARY links; return listed chapters with their line numbers."""
    listed: dict[str, int] = {}
    check_page_links(book, "SUMMARY.md", findings)
    page = book.page("SUMMARY.md")
    for line_no, line in page.visible:
        clean = CODE_SPAN.sub("", line)
        for match in INLINE_LINK.finditer(clean):
            target = match.group(2).partition("#")[0]
            if not target.endswith(".md"):
                continue
            resolved = resolve_target("SUMMARY.md", target)
            if resolved != "SUMMARY.md":
                listed[resolved] = line_no
    return listed


def check_hygiene(book: Book, rel: str, findings: list[Finding]) -> None:
    """Scan every line, fences included, for leaks and banned punctuation."""
    for line_no, line in book.page(rel).lines:
        for prefix in LEAKED_PREFIXES:
            if prefix in line:
                findings.append(
                    book.report(rel, line_no, f"throwaway path leaked: {prefix}")
                )
        if EM_DASH in line:
            findings.append(book.report(rel, line_no, "em dash (U+2014) not allowed"))
        for char, label in CURLY_QUOTES:
            if char in line:
                findings.append(book.report(rel, line_no, f"curly quote ({label}) not allowed"))


def check(book_label: str) -> list[Finding]:
    """Run every check over one book directory and sort the findings."""
    book = Book(book_label)
    findings: list[Finding] = []
    listed = check_summary(book, findings)
    for rel in book.chapter_paths():
        if rel not in listed:
            findings.append(
                book.report(rel, 1, "chapter not listed in SUMMARY.md")
            )
        check_page_links(book, rel, findings)
        check_hygiene(book, rel, findings)
    check_hygiene(book, "SUMMARY.md", findings)
    findings.sort(key=lambda finding: (finding.path, finding.line, finding.message))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "book",
        nargs="?",
        default=DEFAULT_BOOK,
        help=f"book directory with src/SUMMARY.md (default {DEFAULT_BOOK})",
    )
    args = parser.parse_args()
    try:
        findings = check(args.book)
    except BookError as error:
        print(str(error), file=sys.stderr)
        return 2
    if findings:
        for finding in findings:
            print(finding.render())
        return 1
    print(f"{args.book}: no problems")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
