"""Fuzz-style robustness tests: seeded random inputs against the parsers and matchers.

Every test uses a fixed `random.Random` seed, so a failure reproduces exactly. Secret values
are built at runtime so no secret-shaped literal sits in the source.
"""

import base64
import contextlib
import json
import random
import re
import string
import struct
from pathlib import Path
from urllib.parse import quote

import pytest

from agent_canary import store
from agent_canary.alerts import sanitize
from agent_canary.detect import find_matches
from agent_canary.dns_listener import parse_query
from agent_canary.models import Manifest, Secret


def seeded(seed: int) -> random.Random:
    return random.Random(seed)  # noqa: S311 -- reproducible test data, not cryptography


TOKEN_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"
VALUE_ALPHABET = string.ascii_letters + string.digits + "~?>/+=-_.!@#"
TEXT_ALPHABET = string.ascii_letters + string.digits + " \n"


def random_value(rng: random.Random) -> str:
    return "".join(rng.choices(VALUE_ALPHABET, k=rng.randint(16, 48)))


def random_manifest(rng: random.Random, n_secrets: int | None = None) -> Manifest:
    n = rng.randint(1, 3) if n_secrets is None else n_secrets
    return Manifest(
        token_id="".join(rng.choices(TOKEN_ALPHABET, k=12)),
        workspace="/w",
        created="2026-11-05T00:00:00+00:00",
        dns_domain=None,
        http_url=None,
        secrets=tuple(Secret("env", ".env", f"KEY_{i}", random_value(rng)) for i in range(n)),
    )


# --- DNS parse_query ---------------------------------------------------------------------


def dns_query(name: str, qdcount: int = 1, flags: int = 0x0100) -> bytes:
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
    return (
        struct.pack("!HHHHHH", 0xBEEF, flags, qdcount, 0, 0, 0) + labels + b"\x00\x00\x01\x00\x01"
    )


VALID_QUERIES = [
    dns_query("a.b.example.com"),
    dns_query("x" * 63 + "." + "y" * 63 + ".z.example.org"),
    dns_query("abcdefgh2345.canary.example.com"),
    dns_query("localhost"),
]


def check_parsed(packet: bytes, result: tuple[int, str, int, int] | None) -> None:
    if result is None:
        return
    txid, qname, qtype, end = result
    assert 0 <= txid <= 0xFFFF
    assert 0 <= qtype <= 0xFFFF
    assert 12 < end <= len(packet)
    if all(b < 0x80 for b in packet[12 : end - 4]):  # high bytes are shown as 4-char escapes
        assert len(qname) <= 253, packet.hex()


def test_valid_queries_parse():
    for packet in VALID_QUERIES:
        result = parse_query(packet)
        assert result is not None
        check_parsed(packet, result)


def test_parse_query_random_bytes():
    rng = seeded(1)
    for _ in range(3000):
        packet = rng.randbytes(rng.randint(0, 600))
        check_parsed(packet, parse_query(packet))


def test_parse_query_random_bytes_with_valid_header():
    rng = seeded(2)
    header = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0)
    for _ in range(3000):
        packet = header + rng.randbytes(rng.randint(0, 300))
        check_parsed(packet, parse_query(packet))


def test_parse_query_every_truncation():
    for packet in VALID_QUERIES:
        for length in range(len(packet)):
            truncated = packet[:length]
            result = parse_query(truncated)
            check_parsed(truncated, result)
            if length < len(packet) - 4:  # the question is cut before its type and class
                assert result is None


def test_parse_query_mutated_valid_query():
    rng = seeded(3)
    for _ in range(4000):
        packet = bytearray(rng.choice(VALID_QUERIES))
        for _ in range(rng.randint(1, 4)):
            packet[rng.randrange(len(packet))] = rng.randrange(256)
        check_parsed(bytes(packet), parse_query(bytes(packet)))


def test_parse_query_oversized_label_and_pointer_bytes():
    for base in VALID_QUERIES:
        for pos in range(12, len(base)):
            for value in (63, 64, 127, 128, 192, 193, 255):
                packet = bytearray(base)
                packet[pos] = value
                check_parsed(bytes(packet), parse_query(bytes(packet)))
    # A length byte of 64 or more is never a plain label: rejected, not read as one.
    for value in (64, 192, 255):
        packet = bytearray(dns_query("a.example.com"))
        packet[12] = value
        assert parse_query(bytes(packet)) is None


def test_parse_query_compression_pointer_loop():
    header = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0)
    assert parse_query(header + b"\xc0\x0c\x00\x01\x00\x01") is None
    assert parse_query(header + b"\x01a\xc0\x0c\x00\x01\x00\x01") is None


@pytest.mark.parametrize("qdcount", [0, 1, 2, 255, 256, 65535])
def test_parse_query_qdcount_extremes(qdcount):
    packet = dns_query("a.example.com", qdcount=qdcount)
    result = parse_query(packet)
    check_parsed(packet, result)
    assert (result is None) == (qdcount == 0)


def test_parse_query_response_flag_and_name_length_limits():
    assert parse_query(dns_query("a.example.com", flags=0x8180)) is None
    # 253 characters is the longest legal name: 63 + 63 + 63 + 61 plus three dots.
    longest = ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 61])
    assert len(longest) == 253
    result = parse_query(dns_query(longest))
    assert result is not None and result[1] == longest
    # One byte more makes the wire form 256 bytes, over the 255 limit.
    assert parse_query(dns_query(".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 62]))) is None


def test_parse_query_ascii_names_stay_within_253_chars():
    rng = seeded(4)
    for _ in range(500):
        labels = [rng.randbytes(rng.randint(1, 63)) for _ in range(rng.randint(1, 4))]
        labels = [bytes(b & 0x7F for b in x) for x in labels]
        name = b"".join(bytes([len(x)]) + x for x in labels)
        packet = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + name + b"\x00\x00\x01\x00\x01"
        result = parse_query(packet)
        assert result is not None
        assert len(result[1]) <= 253


# --- detect.find_matches -----------------------------------------------------------------


def random_haystack(rng: random.Random, size: int) -> bytes:
    kind = rng.choice(["bytes", "text", "base64", "hex"])
    if kind == "bytes":
        return rng.randbytes(size)
    if kind == "text":
        return "".join(rng.choices(TEXT_ALPHABET + string.punctuation, k=size)).encode()
    if kind == "base64":
        return base64.b64encode(rng.randbytes(size * 3 // 4))
    return rng.randbytes(size // 2).hex().encode()


def test_find_matches_never_raises_and_has_no_false_positives():
    rng = seeded(5)
    manifests = [random_manifest(rng) for _ in range(4)]
    for i in range(1500):
        size = rng.randint(0, 64 * 1024) if i % 50 == 0 else rng.randint(0, 2000)
        data = random_haystack(rng, size)
        assert find_matches(data, manifests) == []


def test_find_matches_accepts_arbitrary_text():
    rng = seeded(6)
    manifests = [random_manifest(rng)]
    for _ in range(1000):
        codepoints = rng.choices(range(0x110000), k=rng.randint(0, 300))
        text = "".join(chr(c) for c in codepoints)  # includes lone surrogates
        assert find_matches(text, manifests) == []


def test_find_matches_without_manifests_or_secrets():
    rng = seeded(7)
    bare = random_manifest(rng, n_secrets=0)
    assert find_matches(rng.randbytes(100), []) == []
    assert find_matches(rng.randbytes(100), [bare]) == []
    assert find_matches(b"", [random_manifest(rng)]) == []


def plant_in_text(rng: random.Random, planted: bytes) -> bytes:
    """Random text with `planted` inserted at a random offset."""
    text = "".join(rng.choices(TEXT_ALPHABET, k=rng.randint(0, 3000))).encode()
    at = rng.randint(0, len(text))
    return text[:at] + planted + text[at:]


def base64_forms(rng: random.Random, value: str) -> list[bytes]:
    """The value inside a random blob at a random alignment, in several base64 spellings."""
    blob = rng.randbytes(rng.randint(0, 40)) + value.encode() + rng.randbytes(rng.randint(0, 40))
    standard = base64.b64encode(blob)
    return [
        standard,
        standard.rstrip(b"="),
        base64.urlsafe_b64encode(blob),
        base64.urlsafe_b64encode(blob).rstrip(b"="),
        quote(standard.decode(), safe="").encode(),
    ]


def assert_found(data: bytes, manifests: list[Manifest], target: Manifest, value: str) -> None:
    hits = [m for m in find_matches(data, manifests) if m.secret and m.secret.value == value]
    assert len(hits) == 1, (value, data[:200])
    assert hits[0].token_id == target.token_id


def test_planted_value_found_in_plain_percent_and_hex_forms():
    rng = seeded(8)
    for _ in range(300):
        manifests = [random_manifest(rng) for _ in range(rng.randint(1, 3))]
        target = rng.choice(manifests)
        value = rng.choice(target.secrets).value
        raw = value.encode()
        forms = [
            raw,
            quote(value, safe="").encode(),
            re.sub(r"%[0-9A-F]{2}", lambda m: m.group().lower(), quote(value, safe="")).encode(),
            raw.hex().encode(),
            raw.hex().upper().encode(),
        ]
        for form in forms:
            assert_found(plant_in_text(rng, form), manifests, target, value)


def test_planted_value_found_in_base64_blob_at_every_alignment():
    rng = seeded(9)
    for _ in range(300):
        manifests = [random_manifest(rng) for _ in range(rng.randint(1, 3))]
        target = rng.choice(manifests)
        value = rng.choice(target.secrets).value
        for form in base64_forms(rng, value):
            assert_found(plant_in_text(rng, form), manifests, target, value)


def test_planted_token_id_found_as_whole_word_only():
    rng = seeded(10)
    for _ in range(300):
        manifest = random_manifest(rng, n_secrets=0)
        host = f"{rng.choice(['a', 'zz', 'x1'])}.{manifest.token_id}.example.com".encode()
        hits = find_matches(plant_in_text(rng, b" " + host + b" "), [manifest])
        assert [(m.token_id, m.secret) for m in hits] == [(manifest.token_id, None)]


# --- alerts.sanitize ---------------------------------------------------------------------

SPECIAL_CHARS = [
    *map(chr, range(0x20)),
    "\x7f",
    "\x85",
    "\x9b",
    "\u200b",
    "\u2028",
    "\u2029",
    "\u202a",
    "\u202e",
    "\u2066",
    "\u2069",
    "\ufeff",
    "\ud800",
    "\udfff",
    "\U0010ffff",
]


def random_unicode(rng: random.Random) -> str:
    parts: list[str] = []
    for _ in range(rng.randint(0, 120)):
        pick = rng.random()
        if pick < 0.35:
            parts.append(rng.choice(SPECIAL_CHARS))
        elif pick < 0.45:
            parts.append("\x1b[" + rng.choice(["31m", "2J", "0;0H", "?25l"]))
        elif pick < 0.55:
            parts.append("\x1b]0;" + "".join(rng.choices(string.ascii_letters, k=5)) + "\x07")
        elif pick < 0.8:
            parts.append(chr(rng.randrange(0x110000)))
        else:
            parts.append(rng.choice(string.printable))
    return "".join(parts)


def test_sanitize_output_is_printable_and_bounded():
    rng = seeded(11)
    for _ in range(4000):
        text = random_unicode(rng)
        limit = rng.randint(3, 300)
        out = sanitize(text, limit)
        assert all(ch.isprintable() for ch in out), repr(text)
        assert len(out) <= limit, repr(text)


def test_sanitize_default_limit_and_known_attacks():
    rng = seeded(12)
    for _ in range(500):
        out = sanitize(random_unicode(rng) * 5)
        assert all(ch.isprintable() for ch in out)
        assert len(out) <= 200
    out = sanitize("ok\x1b[31m\u202eevil\r\n\x00")
    assert "\x1b" not in out and "\u202e" not in out and "\n" not in out
    assert sanitize("plain text") == "plain text"


# --- Manifest.from_dict and store.load_all -----------------------------------------------


def valid_manifest_dict() -> dict:
    manifest = random_manifest(seeded(13))
    return manifest.to_dict()


def random_json_value(rng: random.Random, depth: int = 0):
    pick = rng.randrange(8 if depth < 3 else 5)
    if pick == 0:
        return None
    if pick == 1:
        return rng.choice([True, False])
    if pick == 2:
        return rng.randint(-(2**40), 2**40)
    if pick == 3:
        return rng.random()
    if pick == 4:
        return "".join(rng.choices(string.printable, k=rng.randint(0, 12)))
    if pick == 5:
        return [random_json_value(rng, depth + 1) for _ in range(rng.randint(0, 3))]
    return {
        "".join(rng.choices(string.ascii_lowercase, k=4)): random_json_value(rng, depth + 1)
        for _ in range(rng.randint(0, 3))
    }


def test_from_dict_roundtrip():
    original = valid_manifest_dict()
    assert Manifest.from_dict(json.loads(json.dumps(original))).to_dict() == original


def test_from_dict_rejects_garbage_with_expected_exceptions():
    rng = seeded(14)
    expected = (KeyError, TypeError, ValueError)
    for _ in range(3000):
        data = valid_manifest_dict()
        for _ in range(rng.randint(1, 3)):
            key = rng.choice([*data, "extra"])
            if rng.random() < 0.2:
                data.pop(key, None)
            else:
                data[key] = random_json_value(rng)
        with contextlib.suppress(*expected):
            Manifest.from_dict(data)
    for junk in (None, 1, "x", [], [1, 2], 1.5, True):
        with pytest.raises(expected):
            Manifest.from_dict(junk)  # type: ignore[arg-type]


def test_load_all_skips_corrupt_files(tmp_path: Path):
    rng = seeded(15)
    good = valid_manifest_dict()
    good_text = json.dumps(good)
    for i in range(300):
        name = "".join(rng.choices(TOKEN_ALPHABET, k=12))
        kind = i % 4
        if kind == 0:
            body = rng.randbytes(rng.randint(0, 200))
        elif kind == 1:
            body = good_text[: rng.randint(0, len(good_text))].encode()
        elif kind == 2:
            data = bytearray(good_text.encode())
            for _ in range(rng.randint(1, 5)):
                data[rng.randrange(len(data))] = rng.randrange(256)
            body = bytes(data)
        else:
            body = json.dumps(random_json_value(rng)).encode()
        (tmp_path / f"{name}.json").write_bytes(body)
    (tmp_path / "good.json").write_text(good_text)  # wrong name: skipped
    (tmp_path / f"{good['token_id']}.json").write_text(good_text)
    loaded = store.load_all(tmp_path)
    assert all(isinstance(m, Manifest) for m in loaded)


def test_load_all_survives_mixed_type_fields(tmp_path: Path):
    first = valid_manifest_dict()
    second = {**valid_manifest_dict(), "created": 5}
    (tmp_path / ("a" * 12 + ".json")).write_text(json.dumps(first))
    (tmp_path / ("b" * 12 + ".json")).write_text(json.dumps(second))
    store.load_all(tmp_path)


def test_load_all_survives_deeply_nested_json(tmp_path: Path):
    (tmp_path / ("a" * 12 + ".json")).write_text("[" * 100_000)
    assert store.load_all(tmp_path) == []
