"""Find planted canaries (token ids and secret values) in arbitrary observed data.

Besides the plain value, each canary is searched for as it would look after the common
encodings a leaking agent applies: percent-encoding (form or URL, once or twice), JSON string
escapes (`\\/` and `\\u00XX`), base64 (standard and URL-safe, alone or inside a larger encoded
blob, wrapped into lines or not), base32, hex (plain, grouped, `\\xNN`, `0xNN` lists and
`xxd`/`hexdump` dumps), UTF-16LE, reversed, and gzip or zlib streams (raw or base64-encoded).
All searching is on bytes, so binary dumps need no decoding. Views that only some data needs
(twice unquoted, separator-free hex, decompressed) are built only when their trigger bytes occur.
"""

from __future__ import annotations

import base64
import binascii
import re
import zlib
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

# Shortest base32 fragment searched for: 15 characters carry 75 bits.
MIN_BASE32_LEN = 15

# Decompression limits per find_matches call: candidate streams tried, output bytes per
# stream and in total. They bound the work on hostile input such as zip bombs.
MAX_INFLATE_TRIES = 16
MAX_INFLATE_OUT = 1024 * 1024
MAX_INFLATE_TOTAL = 4 * 1024 * 1024
_INFLATE_STEP = 16 * 1024  # compressed bytes fed per decompress call
_MIN_BASE64_STREAM = 24  # shortest base64 run tried as a compressed stream

# Bytes per byte of the widest separated-hex form searched (`0x41, ` is 6, `\\x41` inside a
# JSON string is 5, `hexdump -C` is under 5), and slack for the offset and ASCII columns of
# the dump lines a value starts and ends in.
HEX_SEPARATED_WIDTH = 6
HEX_DUMP_SLACK = 2 * 80

_TOKEN_BYTES = frozenset(b"abcdefghijklmnopqrstuvwxyz0123456789")
_LETTERS = frozenset(b"abcdefghijklmnopqrstuvwxyz")
_BASE64_CHARS = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
_URLSAFE_TO_STANDARD = bytes.maketrans(b"-_", b"+/")
_JSON_ASCII_ESCAPE = re.compile(rb"\\u00([0-7][0-9a-fA-F])")
_NON_HEX = bytes(b for b in range(256) if b not in b"0123456789abcdef")
_HEX_PREFIX = re.compile(rb"0x(?=[0-9a-f])")  # not the `0x` of `50xyz`
_HEX_SEPARATORS = (b" ", b"\t", b"\n", b":", b",", b"-", b"\\x")
_HEX_SEPARATED = re.compile(rb"[0-9a-f]{2}(?:[ \t\r\n:,\-]|\\x|, ?0x)[0-9a-f]{2}")
# One line of an `xxd`, `hexdump -C` or `od -tx1` dump (lowercased), with the line break
# before it: the offset, the hex column (group 1), then an optional ASCII column after two
# or more blanks. Starting at a literal line break lets the search skip from line to line.
_DUMP_LINE = re.compile(
    rb"\n[ \t]*(?:[0-9a-f]{4,16}(?::[ \t]*|[ \t]{2})|[0-7]{7}[ \t])"
    rb"((?:[0-9a-f]{2,8}[ \t]{1,2})*[0-9a-f]{2,8})(?:[ \t]{2,}[^\n]*)?(?=\n|\Z)"
)


def _class_table(members: bytes) -> bytes:
    """translate() table mapping `members` to b"u" and every other byte to b"."."""
    return bytes(ord("u") if b in members else ord(".") for b in range(256))


# Single-case base32 alphabets (base32 text is never mixed-case). Base32 fragments are
# searched only in runs of one of them, which keeps the many fragments cheap on large data.
_BASE32_TABLES = (
    _class_table(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"),
    _class_table(b"abcdefghijklmnopqrstuvwxyz234567"),
)
_BASE64_STREAM_STARTS = (b"H4sI", b"eA", b"eF", b"eJ", b"eN")  # gzip and zlib headers
_BASE64_RUN = re.compile(rb"[A-Za-z0-9+/]+")
_RAW_STREAM_STARTS = (  # gzip and zlib headers
    (b"\x1f\x8b\x08", "gzip"),
    (b"\x78\x01", "zlib"),
    (b"\x78\x5e", "zlib"),
    (b"\x78\x9c", "zlib"),
    (b"\x78\xda", "zlib"),
)


@dataclass(frozen=True, slots=True)
class _Patterns:
    plain: bytes  # UTF-8 of the value
    hex: bytes  # lowercase, searched in the lowercased haystack so upper and lower both match
    base64: tuple[bytes, ...]  # standard-alphabet fragments, one per alignment
    base64_quoted: tuple[bytes, ...]  # the fragments that change when percent-encoded
    base64_text: bool  # the value is itself base64 text, so it may appear re-wrapped
    utf16: bytes  # UTF-16LE of the value
    base32: tuple[bytes, ...]  # lowercase fragments, one per alignment
    reversed: bytes  # UTF-8 of the value with its characters in reverse order


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


def _base32_fragments(raw: bytes) -> tuple[bytes, ...]:
    """Lowercase base32 text that `raw` produces wherever it sits in a larger encoded blob.

    Like _base64_fragments with 5-byte groups: encode after 0 to 4 prefix bytes and keep the
    characters whose 5 bits all come from `raw`. Searched in lowercased data, so upper- and
    lowercase base32 both match.
    """
    fragments: list[bytes] = []
    for prefix in range(5):
        encoded = base64.b32encode(bytes(prefix) + raw).lower()
        start = -(-8 * prefix // 5)
        end = 8 * (prefix + len(raw)) // 5
        fragment = encoded[start:end]
        if len(fragment) >= MIN_BASE32_LEN:
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
        base32=_base32_fragments(raw),
        reversed=value[::-1].encode("utf-8"),
    )


def _inflate(data: bytes, start: int, budget: int) -> bytes:
    """What a gzip or zlib stream at `data[start]` decompresses to, at most `budget` bytes.

    Truncated or corrupt streams yield the output produced before the damage.
    """
    inflater = zlib.decompressobj(wbits=32 + zlib.MAX_WBITS)  # accepts a gzip or zlib header
    out: list[bytes] = []
    size = 0
    for i in range(start, len(data), _INFLATE_STEP):
        try:
            piece = inflater.decompress(data[i : i + _INFLATE_STEP], budget - size)
        except zlib.error:
            break
        out.append(piece)
        size += len(piece)
        if size >= budget or inflater.eof:
            break
    return b"".join(out)


def _stream_starts(hay: _Haystack) -> list[tuple[str, bytes, int]]:
    """(encoding, buffer, offset) for each place a gzip or zlib stream may start.

    Raw headers are looked for in the data, base64-encoded ones at the start of a base64
    run of at least _MIN_BASE64_STREAM characters in the unwrapped, URL-safe-mapped view.
    At most MAX_INFLATE_TRIES candidates.
    """
    starts: list[tuple[str, bytes, int]] = []
    data = hay.data
    for header, name in _RAW_STREAM_STARTS:
        if header[1:2] not in data:  # a single-byte search is far cheaper than the pair
            continue
        pos = data.find(header)
        while pos >= 0 and len(starts) < MAX_INFLATE_TRIES:
            starts.append((name, data, pos))
            pos = data.find(header, pos + 1)
    b64 = hay.base64
    for prefix in _BASE64_STREAM_STARTS:
        name = "gzip+base64" if prefix == b"H4sI" else "zlib+base64"
        pos = b64.find(prefix)
        while pos >= 0 and len(starts) < MAX_INFLATE_TRIES:
            if pos == 0 or b64[pos - 1] not in _BASE64_CHARS:
                run = _BASE64_RUN.match(b64, pos)
                if run is not None and len(run[0]) >= _MIN_BASE64_STREAM:
                    text = run[0][: len(run[0]) // 4 * 4]
                    starts.append((name, binascii.a2b_base64(text), 0))
            pos = b64.find(prefix, pos + 1)
    return starts


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
    def unquoted_twice(self) -> bytes | None:
        """Data percent-decoded twice (`%252F` to `/`), or None without an encoded `%`."""
        if self.unquoted is None or b"%25" not in self.data:
            return None
        decoded = unquote_to_bytes(self.unquoted.replace(b"+", b" "))
        return None if decoded == self.unquoted else decoded

    @cached_property
    def unquoted_twice_lower(self) -> bytes | None:
        return None if self.unquoted_twice is None else self.unquoted_twice.lower()

    @cached_property
    def base32(self) -> bytes:
        """Lowercased single-case base32 runs of the unwrapped data, space-separated."""
        data = self.unwrapped
        probe = b"u" * MIN_BASE32_LEN
        runs: list[bytes] = []
        for table in _BASE32_TABLES:
            classes = data.translate(table)
            pos = classes.find(probe)
            while pos >= 0:
                end = classes.find(b".", pos + MIN_BASE32_LEN)
                end = len(data) if end < 0 else end
                runs.append(data[pos:end])
                pos = classes.find(probe, end)
        return b" ".join(runs).lower()

    @cached_property
    def hex(self) -> bytes | None:
        """Lowercased hex digits with separators, `0x`, `\\x` and dump columns removed.

        None unless two hex pairs are joined by a separator somewhere, so data without one
        pays only for the trigger search.
        """
        lower = self.lower
        if not any(sep in lower for sep in _HEX_SEPARATORS) or not _HEX_SEPARATED.search(lower):
            return None
        data = _DUMP_LINE.sub(rb"\n\1", b"\n" + lower) if b"\n" in lower else lower
        if b"0x" in data:
            data = _HEX_PREFIX.sub(b"", data)
        return data.translate(None, _NON_HEX)

    @cached_property
    def inflated(self) -> list[tuple[str, bytes, bytes]]:
        """(encoding, output, lowercased output) of each gzip or zlib stream in the data."""
        found: list[tuple[str, bytes, bytes]] = []
        total = 0
        for name, buffer, start in _stream_starts(self):
            out = _inflate(buffer, start, min(MAX_INFLATE_OUT, MAX_INFLATE_TOTAL - total))
            total += len(out)
            if out:
                found.append((name, out, out.lower()))
            if total >= MAX_INFLATE_TOTAL:
                break
        return found

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
    if any(fragment in hay.base32 for fragment in patterns.base32):
        return "base32"
    if patterns.reversed in hay.data:
        return "reversed"
    if hay.unquoted_twice is not None and patterns.plain in hay.unquoted_twice:
        return "url"
    if hay.hex is not None and patterns.hex in hay.hex:
        return "hex"
    for name, out, _ in hay.inflated:
        if patterns.plain in out:
            return name
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
    if any(fragment in hay.base32 for fragment in patterns.base32):
        return "base32"
    if _has_word(hay.lower, patterns.reversed):
        return "reversed"
    twice = hay.unquoted_twice_lower
    if twice is not None and _has_word(twice, patterns.plain):
        return "url"
    if hay.hex is not None and patterns.hex in hay.hex:
        return "hex"
    for name, _, lower in hay.inflated:
        if _has_word(lower, patterns.plain):
            return name
    return None


def find_matches(data: bytes | str, manifests: Sequence[Manifest]) -> list[Match]:
    """Every canary that appears in `data`, at most one Match per (token, secret).

    Match.encoding is "plain" when the value appears unencoded (a value that is itself
    base64 text also when re-wrapped into lines), else "url", "json", "base64", "hex",
    "utf-16", "base32", "reversed", or "gzip", "zlib", "gzip+base64" or "zlib+base64" when
    it is in the plain text a compressed stream decompresses to. A token id alone (seen in
    a hostname or URL) yields a Match with secret=None; it is dropped when a secret of the
    same token was also found in the same data.
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
    split across a boundary. Compressed streams have no such bound: a stream cut by a chunk
    boundary is searched only up to the cut.
    """
    longest = max(
        (
            len(value.encode("utf-8"))
            for m in manifests
            for value in (m.token_id, *(s.value for s in m.secrets))
        ),
        default=0,
    )
    # The longest encoded form is base32 (8 chars per 5 bytes; base64 is 4 per 3) with every
    # character JSON-escaped as `\u00XX` (6 bytes) and an escaped line break `\u000d\u000a`
    # (12 bytes) after every MIN_WRAP characters. Separated hex takes at most
    # HEX_SEPARATED_WIDTH bytes per byte plus the dump columns around it; double
    # percent-encoding (`%25XX`) takes 5. +6 for the UTF-16LE characters around a token id
    # that decide whether it is a whole token (an escape before it, one character after it).
    chars = -(-8 * longest // 5)
    encoded = 6 * chars + 12 * (chars // MIN_WRAP + 1)
    return max(encoded, HEX_SEPARATED_WIDTH * longest + HEX_DUMP_SLACK) + 6
