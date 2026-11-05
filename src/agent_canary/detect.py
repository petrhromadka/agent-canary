"""Find planted canaries (token ids and secret values) in arbitrary observed data.

Besides the plain value, each canary is searched for as it would look after the common
encodings a leaking agent applies: percent-encoding (form or URL), JSON string escapes
(`\\/` and `\\u00XX`), base64 (standard and URL-safe, alone or inside a larger encoded blob,
wrapped into lines or not), hex and UTF-16LE. All searching is on bytes, so binary dumps
need no decoding.
"""

from __future__ import annotations

import base64
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from functools import cached_property, lru_cache
from urllib.parse import unquote_to_bytes

from agent_canary.models import Manifest, Match

# Shortest base64 fragment searched for. Shorter fragments of short values would match
# random base64 data; 12 characters carry 72 bits.
MIN_BASE64_LEN = 12

# Narrowest line width assumed for wrapped base64 when bounding pattern spans (PEM wraps at
# 64, coreutils and MIME at 76). Narrower wrapping is still found, but not across chunks.
MIN_WRAP = 32

_TOKEN_BYTES = frozenset(b"abcdefghijklmnopqrstuvwxyz0123456789")
_LETTERS = frozenset(b"abcdefghijklmnopqrstuvwxyz")
_BASE64_CHARS = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
_URLSAFE_TO_STANDARD = bytes.maketrans(b"-_", b"+/")
_JSON_ASCII_ESCAPE = re.compile(rb"\\u00([0-7][0-9a-fA-F])")


@dataclass(frozen=True, slots=True)
class _Patterns:
    plain: bytes  # UTF-8 of the value
    hex: bytes  # lowercase, searched in the lowercased haystack so upper and lower both match
    base64: tuple[bytes, ...]  # standard-alphabet fragments, one per alignment
    base64_quoted: tuple[bytes, ...]  # the fragments that change when percent-encoded
    base64_text: bool  # the value is itself base64 text, so it may appear re-wrapped
    utf16: bytes  # UTF-16LE of the value


def _base64_fragments(raw: bytes) -> tuple[bytes, ...]:
    """Base64 text that `raw` produces wherever it sits inside a larger encoded blob.

    The encoding of `raw` depends on its offset modulo 3 in the blob, so encode it after
    0, 1 and 2 prefix bytes and keep only the characters whose 6 bits all come from `raw`.
    Padding never appears in a fragment, so padded and unpadded blobs both match.
    """
    fragments: list[bytes] = []
    for prefix in range(3):
        encoded = base64.b64encode(bytes(prefix) + raw)
        start = -(-8 * prefix // 6)  # first character with no prefix bits
        end = 8 * (prefix + len(raw)) // 6  # last character with no padding bits
        fragment = encoded[start:end]
        if len(fragment) >= MIN_BASE64_LEN:
            fragments.append(fragment)
    return tuple(fragments)


@lru_cache(maxsize=4096)
def _patterns(value: str) -> _Patterns:
    raw = value.encode("utf-8")
    fragments = _base64_fragments(raw)
    return _Patterns(
        plain=raw,
        hex=raw.hex().encode("ascii"),
        base64=fragments,
        base64_quoted=tuple(f for f in fragments if b"+" in f or b"/" in f),
        base64_text=len(raw) >= MIN_BASE64_LEN and all(b in _BASE64_CHARS for b in raw),
        utf16=value.encode("utf-16-le"),
    )


class _Haystack:
    """The observed data plus derived views, each computed at most once and only if needed."""

    def __init__(self, data: bytes) -> None:
        self.data = data

    @cached_property
    def lower(self) -> bytes:
        return self.data.lower()

    @cached_property
    def json(self) -> bytes | None:
        """Data with the JSON escapes `\\/` and `\\u00XX` undone, or None when there are none."""
        if b"\\" not in self.data:
            return None
        decoded = self.data.replace(b"\\/", b"/")
        if b"\\u00" in decoded:
            decoded = _JSON_ASCII_ESCAPE.sub(lambda m: bytes([int(m[1], 16)]), decoded)
        return None if decoded == self.data else decoded

    @cached_property
    def unwrapped(self) -> bytes:
        """JSON-unescaped data without line breaks: CR, LF and the escapes `\\r`, `\\n`."""
        data = self.data if self.json is None else self.json
        if b"\n" in data or b"\r" in data:
            data = data.replace(b"\n", b"").replace(b"\r", b"")
        if b"\\" in data:
            data = data.replace(b"\\n", b"").replace(b"\\r", b"")
        return data

    @cached_property
    def base64(self) -> bytes:
        """The unwrapped data with the URL-safe base64 alphabet mapped to the standard one."""
        data = self.unwrapped
        if b"-" in data or b"_" in data:
            data = data.translate(_URLSAFE_TO_STANDARD)
        return data

    @cached_property
    def unquoted(self) -> bytes | None:
        """Percent- and plus-decoded data, or None when decoding changes nothing."""
        if b"%" in self.data:
            decoded = unquote_to_bytes(self.data.replace(b"+", b" "))
        elif b"+" in self.data:
            decoded = self.data.replace(b"+", b" ")
        else:
            return None
        return None if decoded == self.data else decoded

    @cached_property
    def unquoted_lower(self) -> bytes | None:
        return None if self.unquoted is None else self.unquoted.lower()

    @cached_property
    def has_quoted_base64(self) -> bool:
        """Whether percent-encoded base64 characters ('+', '/') occur at all."""
        return self.unquoted is not None and (b"%2b" in self.lower or b"%2f" in self.lower)


def _has_base64(patterns: _Patterns, hay: _Haystack) -> bool:
    if any(fragment in hay.base64 for fragment in patterns.base64):
        return True
    unquoted = hay.unquoted
    return (
        unquoted is not None
        and hay.has_quoted_base64
        and any(fragment in unquoted for fragment in patterns.base64_quoted)
    )


def _find_value(value: str, hay: _Haystack) -> str | None:
    """Encoding under which a secret value appears (case-sensitive), "plain" first."""
    patterns = _patterns(value)
    if patterns.plain in hay.data:
        return "plain"
    if hay.unquoted is not None and patterns.plain in hay.unquoted:
        return "url"
    if hay.json is not None and patterns.plain in hay.json:
        return "json"
    if patterns.base64_text and hay.unwrapped is not hay.data and patterns.plain in hay.unwrapped:
        return "plain"
    if _has_base64(patterns, hay):
        return "base64"
    if patterns.hex in hay.lower:
        return "hex"
    if patterns.utf16 in hay.data:
        return "utf-16"
    return None


def _has_word(data: bytes, word: bytes, width: int = 1) -> bool:
    """`word` occurs in lowercased `data` not inside a longer [a-z0-9] run.

    `width` is the bytes per character: 1 for ASCII, 2 for UTF-16LE. A backslash and a
    letter right before `word` are a string escape such as `\\n`, which ends the run.
    """

    def char(i: int) -> int | None:
        if i < 0 or i + width > len(data) or any(data[i + 1 : i + width]):
            return None
        return data[i]

    pos = data.find(word)
    while pos >= 0:
        before = char(pos - width)
        escaped = before in _LETTERS and char(pos - 2 * width) == ord("\\")
        if (before not in _TOKEN_BYTES or escaped) and char(pos + len(word)) not in _TOKEN_BYTES:
            return True
        pos = data.find(word, pos + 1)
    return False


def _find_token(token_id: str, hay: _Haystack) -> str | None:
    """Encoding under which a token id appears; plain and url forms ignore case."""
    patterns = _patterns(token_id)
    if _has_word(hay.lower, patterns.plain):
        return "plain"
    if hay.unquoted_lower is not None and _has_word(hay.unquoted_lower, patterns.plain):
        return "url"
    if _has_base64(patterns, hay):
        return "base64"
    if patterns.hex in hay.lower:
        return "hex"
    if _has_word(hay.lower, patterns.utf16, width=2):
        return "utf-16"
    return None


def find_matches(data: bytes | str, manifests: Sequence[Manifest]) -> list[Match]:
    """Every canary that appears in `data`, at most one Match per (token, secret).

    Match.encoding is "plain" when the value appears unencoded (a value that is itself
    base64 text also when re-wrapped into lines), else "url", "json", "base64", "hex" or
    "utf-16". A token id alone (seen in a hostname or URL) yields a Match with secret=None;
    it is dropped when a secret of the same token was also found in the same data.
    """
    raw = data.encode("utf-8", errors="replace") if isinstance(data, str) else data
    hay = _Haystack(raw)
    matches: list[Match] = []
    for manifest in manifests:
        found = []
        for secret in manifest.secrets:
            encoding = _find_value(secret.value, hay)
            if encoding is not None:
                found.append(Match(manifest.token_id, secret, encoding))
        if not found:
            encoding = _find_token(manifest.token_id, hay)
            if encoding is not None:
                found.append(Match(manifest.token_id, None, encoding))
        matches.extend(found)
    return matches


REDACTED = "<redacted>"


def safe_detail(candidates: Iterable[str], manifests: Sequence[Manifest], limit: int) -> str:
    """The first candidate, cut to `limit` characters, that shows no secret value.

    A candidate qualifies only when neither it nor its cut form contains a secret value
    in any searched encoding, so a value is neither logged whole nor left half-cut by the
    truncation. Token ids may remain: they name the canary, they are not credentials.
    Returns REDACTED when no candidate qualifies.
    """
    for candidate in candidates:
        cut = candidate[:limit]
        texts = (candidate,) if cut == candidate else (candidate, cut)
        if not any(m.secret for text in texts for m in find_matches(text, manifests)):
            return cut
    return REDACTED


def max_pattern_len(manifests: Sequence[Manifest]) -> int:
    """Upper bound on how many bytes any searched form of any canary can span.

    Chunked readers overlap consecutive chunks by at least this much so no match is
    split across a boundary.
    """
    longest = max(
        (
            len(value.encode("utf-8"))
            for m in manifests
            for value in (m.token_id, *(s.value for s in m.secrets))
        ),
        default=0,
    )
    # The longest form is base64 (4 chars per 3 bytes) with every character JSON-escaped as
    # `\u00XX` (6 bytes) and an escaped line break `\u000d\u000a` (12 bytes) after every
    # MIN_WRAP characters. +6 for the UTF-16LE characters around a token id that decide
    # whether it is a whole token (an escape before it, one character after it).
    chars = -(-4 * longest // 3)
    return 6 * chars + 12 * (chars // MIN_WRAP + 1) + 6
