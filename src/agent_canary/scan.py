"""Offline scan of files or stdin (agent transcripts, proxy logs, traffic dumps)."""

from __future__ import annotations

import os
import stat
import sys
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import BinaryIO

from agent_canary import alerts
from agent_canary.detect import find_matches, max_pattern_len
from agent_canary.models import Alert, Manifest, Match, Secret

CHUNK_SIZE = 8 * 1024 * 1024  # bytes read per step; bounds memory on huge dumps
SKIP_DIRS = frozenset({".git", ".venv", "node_modules"})

type _Key = tuple[str, Secret | None]


def _norm(path: str | Path) -> str:
    return os.path.normcase(str(Path(path).resolve()))


def _planted(manifests: Sequence[Manifest]) -> set[str]:
    """Resolved paths of the decoy files themselves: they contain every secret by design."""
    return {_norm(Path(m.workspace) / f) for m in manifests for f in m.files}


def _walk(root: str) -> Iterator[str]:
    """Regular files under `root`, sorted, not following symlinked directories."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            path = Path(dirpath) / name
            try:
                if stat.S_ISREG(path.stat().st_mode):
                    yield str(path)
            except OSError:
                continue


def _first_line(window: bytes, keys: set[_Key], manifests: Sequence[Manifest]) -> int:
    """0-based line in `window` where the first match ends (shortest matching prefix)."""
    lo, hi = 1, len(window)
    while lo < hi:
        mid = (lo + hi) // 2
        if any((m.token_id, m.secret) in keys for m in find_matches(window[:mid], manifests)):
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
    while chunk := stream.read(CHUNK_SIZE):
        window = tail + chunk
        hits = find_matches(window, manifests)
        if hits and not line:
            keys = {(m.token_id, m.secret) for m in hits}
            line = lines_before + _first_line(window, keys, manifests) + 1
        for match in hits:
            key = (match.token_id, match.secret)
            if key not in found or match.encoding == "plain":
                found[key] = match
        tail = window[-overlap:] if len(window) > overlap else window
        lines_before += window.count(b"\n", 0, len(window) - len(tail))
    with_secret = {m.token_id for m in found.values() if m.secret is not None}
    matches = [m for m in found.values() if m.secret is not None or m.token_id not in with_secret]
    return matches, line


def _scan_one(
    source: str, stream: BinaryIO, manifests: Sequence[Manifest], out: list[Alert]
) -> None:
    matches, line = _scan_stream(stream, manifests)
    if matches:
        out.append(alerts.make_alert("scan", source, f"line {line}", matches))


def scan_paths(paths: Sequence[str], manifests: Sequence[Manifest]) -> list[Alert]:
    """One Alert per file (or stdin for "-") that contains canaries; directories recurse.

    Unreadable files are skipped, and so are the planted decoy files.
    """
    planted = _planted(manifests)
    found: list[Alert] = []
    for arg in paths:
        if arg == "-":
            _scan_one("<stdin>", sys.stdin.buffer, manifests, found)
            continue
        files = _walk(arg) if Path(arg).is_dir() else iter([arg])
        for path in files:
            try:
                if _norm(path) in planted:
                    continue
                with Path(path).open("rb") as stream:
                    _scan_one(path, stream, manifests, found)
            except OSError:
                continue
    return found
