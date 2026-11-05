"""Offline scan of files or stdin (agent transcripts, proxy logs, traffic dumps)."""

from __future__ import annotations

import os
import stat
import sys
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import BinaryIO

from agent_canary import alerts
from agent_canary.detect import find_matches, max_pattern_len
from agent_canary.models import Alert, Manifest, Match, Secret

CHUNK_SIZE = 8 * 1024 * 1024  # bytes read per step; bounds memory on huge dumps
SKIP_DIRS = frozenset({".git", ".venv", "node_modules"})
# A token byte put where a window is cut out of a longer stream, so a token id that touches
# the cut is not taken for a whole word; the neighbouring window sees its real neighbours.
_GLUE = b"z"

type _Key = tuple[str, Secret | None]


@dataclass
class ScanResult:
    alerts: list[Alert] = field(default_factory=list)
    errors: list[tuple[str, str]] = field(default_factory=list)  # (path, reason)
    decoys: int = 0  # planted decoy files, which contain every secret by design
    dirs: list[str] = field(default_factory=list)  # names of pruned SKIP_DIRS directories
    symlinks: int = 0  # symlinks and junctions inside walked directories
    special: int = 0  # FIFOs, sockets and devices inside walked directories

    def skipped_summary(self) -> str | None:
        """One line naming what was not scanned, or None when nothing was skipped."""
        parts = []
        if self.decoys:
            parts.append(_count(self.decoys, "planted decoy"))
        if self.dirs:
            names = ", ".join(sorted(set(self.dirs)))
            parts.append(f"{_count(len(self.dirs), 'dir')} ({names})")
        if self.symlinks:
            parts.append(_count(self.symlinks, "symlink"))
        if self.special:
            parts.append(_count(self.special, "special file"))
        return f"skipped: {', '.join(parts)}" if parts else None


def _count(n: int, noun: str) -> str:
    return f"{n} {noun}" if n == 1 else f"{n} {noun}s"


def _norm(path: str | Path) -> str:
    return os.path.normcase(str(Path(path).resolve()))


def _planted(manifests: Sequence[Manifest]) -> set[str]:
    """Resolved paths of the decoy files themselves: they contain every secret by design."""
    return {_norm(Path(m.workspace) / f) for m in manifests for f in m.files}


def _error(result: ScanResult, path: str | Path, exc: OSError) -> None:
    result.errors.append((str(exc.filename or path), exc.strerror or str(exc)))


def _walk(root: str, skip_dirs: frozenset[str], result: ScanResult) -> Iterator[Path]:
    """Regular files under `root`, sorted; symlinks and junctions are not followed."""
    visited: set[tuple[int, int]] = set()
    for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: _error(result, root, e)):
        try:
            st = Path(dirpath).stat()
        except OSError as exc:
            _error(result, dirpath, exc)
            dirnames.clear()
            continue
        if (st.st_dev, st.st_ino) in visited:
            dirnames.clear()
            continue
        visited.add((st.st_dev, st.st_ino))
        keep = []
        for name in sorted(dirnames):
            path = Path(dirpath) / name
            if path.is_symlink() or path.is_junction():
                result.symlinks += 1
            elif name in skip_dirs:
                result.dirs.append(name)
            else:
                keep.append(name)
        dirnames[:] = keep
        for name in sorted(filenames):
            path = Path(dirpath) / name
            try:
                mode = path.lstat().st_mode
            except OSError as exc:
                _error(result, path, exc)
                continue
            if stat.S_ISREG(mode):
                yield path
            elif stat.S_ISLNK(mode):
                result.symlinks += 1
            else:
                result.special += 1


def _hits(
    data: bytes, manifests: Sequence[Manifest], cut_before: bool, cut_after: bool
) -> list[Match]:
    """find_matches on a slice of a stream; `cut_*` say the stream continues on that side.

    A token id that touches a cut must not count as a whole word, so token-only matches are
    checked again with _GLUE on the cut sides. Secret values are plain substrings: a cut
    cannot create one.
    """
    hits = find_matches(data, manifests)
    if not (cut_before or cut_after) or all(m.secret is not None for m in hits):
        return hits
    glued = (_GLUE if cut_before else b"") + data + (_GLUE if cut_after else b"")
    by_token: Mapping[str, Manifest] = {m.token_id: m for m in manifests}
    return [
        m
        for m in hits
        if m.secret is not None or find_matches(glued, [replace(by_token[m.token_id], secrets=())])
    ]


def _first_line(
    window: bytes, keys: set[_Key], manifests: Sequence[Manifest], cut_before: bool, cut_after: bool
) -> int:
    """0-based line in `window` where the first match ends (shortest matching prefix)."""
    lo, hi = 1, len(window)
    while lo < hi:
        mid = (lo + hi) // 2
        hits = _hits(window[:mid], manifests, cut_before, cut_after or mid < len(window))
        if any((m.token_id, m.secret) in keys for m in hits):
            hi = mid
        else:
            lo = mid + 1
    return window.count(b"\n", 0, lo - 1)


def _scan_stream(stream: BinaryIO, manifests: Sequence[Manifest]) -> tuple[list[Match], int]:
    """Matches found in the stream and the 1-based line of the first one (0 if none)."""
    overlap = max_pattern_len(manifests)
    found: dict[_Key, Match] = {}
    line = 0
    lines_before = 0  # newlines in the data preceding `window`
    tail = b""
    at_start = True  # `window` begins at the first byte of the stream
    chunk = stream.read(CHUNK_SIZE)
    while chunk:
        following = stream.read(CHUNK_SIZE)  # read ahead: is `window` the end of the stream?
        window = tail + chunk
        cut_before, cut_after = not at_start, bool(following)
        hits = _hits(window, manifests, cut_before, cut_after)
        if hits and not line:
            keys = {(m.token_id, m.secret) for m in hits}
            line = lines_before + _first_line(window, keys, manifests, cut_before, cut_after) + 1
        for match in hits:
            key = (match.token_id, match.secret)
            if key not in found or match.encoding == "plain":
                found[key] = match
        tail = window[-overlap:] if len(window) > overlap else window
        at_start = at_start and len(tail) == len(window)
        lines_before += window.count(b"\n", 0, len(window) - len(tail))
        chunk = following
    with_secret = {m.token_id for m in found.values() if m.secret is not None}
    matches = [m for m in found.values() if m.secret is not None or m.token_id not in with_secret]
    return matches, line


def _scan_one(
    source: str, stream: BinaryIO, manifests: Sequence[Manifest], out: list[Alert]
) -> None:
    matches, line = _scan_stream(stream, manifests)
    if matches:
        out.append(alerts.make_alert("scan", source, f"line {line}", matches))


def _scan_file(path: Path, manifests: Sequence[Manifest], result: ScanResult) -> None:
    try:
        with path.open("rb") as stream:
            _scan_one(str(path), stream, manifests, result.alerts)
    except OSError as exc:
        _error(result, path, exc)


def scan_paths(
    paths: Sequence[str], manifests: Sequence[Manifest], all_dirs: bool = False
) -> ScanResult:
    """One Alert per file (or stdin for "-") that contains canaries; directories recurse.

    Planted decoy files are skipped, and inside directories so are symlinks, junctions,
    special files and (unless `all_dirs`) SKIP_DIRS. An explicit argument must be a
    regular file (a symlink to one is followed) or a directory. Anything that cannot be
    read is recorded in ScanResult.errors.
    """
    planted = _planted(manifests)
    skip_dirs = frozenset() if all_dirs else SKIP_DIRS
    result = ScanResult()
    for arg in paths:
        if arg == "-":
            _scan_one("<stdin>", sys.stdin.buffer, manifests, result.alerts)
            continue
        try:
            mode = Path(arg).stat().st_mode
        except OSError as exc:
            _error(result, arg, exc)
            continue
        if stat.S_ISDIR(mode):
            files: Iterator[Path] = _walk(arg, skip_dirs, result)
        elif stat.S_ISREG(mode):
            files = iter([Path(arg)])
        else:
            result.errors.append((arg, "not a regular file or directory"))
            continue
        for path in files:
            if _norm(path) in planted:
                result.decoys += 1
            else:
                _scan_file(path, manifests, result)
    return result
