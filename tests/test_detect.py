import base64
import json
import random

import pytest

from agent_canary.detect import MIN_WRAP, find_matches, max_pattern_len
from agent_canary.models import Manifest, Secret

CANARY = "abcdefgh2345"
VALUE = "test-value-1-~~~???>>>abcdef"  # '~', '?', '>' put '+' and '/' in its base64


def manifest(value: str = VALUE) -> Manifest:
    return Manifest(
        token_id=CANARY,
        workspace="/w",
        created="2026-11-05T00:00:00+00:00",
        dns_domain=None,
        http_url=None,
        secrets=(Secret("env", ".env", "API_KEY", value),),
    )


def encodings(data: str | bytes, m: Manifest | None = None) -> list[tuple[bool, str]]:
    return [(h.secret is not None, h.encoding) for h in find_matches(data, [m or manifest()])]


@pytest.mark.parametrize("prefix", [b"", b"x", b"xy"])
def test_base64_inside_blob_at_every_alignment(prefix):
    blob = prefix + b'{"key": "' + VALUE.encode() + b'", "more": "data"}'
    standard = base64.b64encode(blob)
    urlsafe = base64.urlsafe_b64encode(blob).rstrip(b"=")
    assert standard.rstrip(b"=") != urlsafe
    assert encodings(b"payload=" + standard) == [(True, "base64")]
    assert encodings(b"payload=" + urlsafe) == [(True, "base64")]


def test_url_and_hex_encodings_and_plain_preferred():
    value = "test value/1=abc"
    m = manifest(value)
    form = "q=test+value%2F1%3Dabc"
    every_byte = "".join(f"%{b:02X}" for b in value.encode())
    assert encodings(form, m) == [(True, "url")]
    assert encodings(every_byte, m) == [(True, "url")]
    assert encodings("x" + value.encode().hex().upper(), m) == [(True, "hex")]
    assert encodings(value.encode().hex(), m) == [(True, "hex")]
    both = f"{value} {base64.b64encode(value.encode()).decode()} {value.encode().hex()}"
    assert encodings(both, m) == [(True, "plain")]
    assert encodings(value.upper(), m) == []


def test_token_id_whole_token_and_encoded():
    assert encodings(f"GET /t/{CANARY.upper()}/env") == [(False, "plain")]
    assert encodings(f"x{CANARY}") == []
    assert encodings(f"{CANARY}9") == []
    assert encodings(f"id={base64.b64encode(CANARY.encode()).decode()}") == [(False, "base64")]
    assert encodings(f"{CANARY} and {VALUE}") == [(True, "plain")]


def wrap(text: bytes, width: int, sep: bytes = b"\n") -> bytes:
    return sep.join(text[i : i + width] for i in range(0, len(text), width))


@pytest.mark.parametrize(("width", "as_json"), [(76, False), (64, False), (76, True)])
def test_wrapped_base64_found_wherever_the_line_break_falls(width, as_json):
    for offset in range(width):
        blob = b"x" * offset + b"API_KEY=" + VALUE.encode() + b"\n"
        wrapped = wrap(base64.b64encode(blob), width, b"\r\n" if as_json else b"\n")
        data = json.dumps({"out": wrapped.decode()}) if as_json else wrapped
        assert encodings(data) == [(True, "base64")], offset


def test_base64_text_value_found_rewrapped_or_stripped():
    value = base64.b64encode(bytes(range(7, 250, 5))).decode()[:70]  # like one ssh key line
    body = ("A" * 33 + value + "B" * 40).encode()
    m = manifest(value)
    for data in (wrap(body, 64), wrap(body, 76, b"\r\n"), json.dumps(wrap(body, 64).decode())):
        assert encodings(data, m) == [(True, "plain")]


def test_utf16le_value_and_token():
    assert encodings(f"API_KEY={VALUE}\r\n".encode("utf-16-le")) == [(True, "utf-16")]
    assert encodings(f"GET /t/{CANARY.upper()}/env".encode("utf-16-le")) == [(False, "utf-16")]
    assert encodings(f"x{CANARY}".encode("utf-16-le")) == []


def test_json_escaped_slash_and_unicode():
    value = "test value/1=abc+def"
    m = manifest(value)
    backslash = chr(92)
    assert encodings(value.replace("/", backslash + "/"), m) == [(True, "json")]
    escaped = value.replace("+", backslash + "u002b").replace("=", backslash + "u003D")
    assert encodings(escaped, m) == [(True, "json")]


def test_token_id_after_json_escape_is_a_whole_token():
    assert encodings(json.dumps(f"id:\n{CANARY}\tok")) == [(False, "plain")]
    assert encodings(json.dumps(f"x{CANARY}")) == []


def test_max_pattern_len_covers_escaped_wrapped_base64():
    m = manifest()
    chars = base64.b64encode(VALUE.encode()).rstrip(b"=")
    escaped = [b"".join(b"\\u%04x" % c for c in line) for line in wrap(chars, MIN_WRAP).split()]
    form = b"\\u000d\\u000a".join(escaped)
    assert encodings(form, m) == [(True, "base64")]
    assert len(form) <= max_pattern_len([m])


def test_no_false_positive_on_random_megabyte():
    rng = random.Random(1)  # noqa: S311 -- reproducible test data, not cryptography
    raw = rng.randbytes(256 * 1024)
    text = base64.b64encode(raw) + raw.hex().encode() + raw
    assert len(text) > 1024 * 1024
    many = [manifest(f"test-value-{i}-{rng.randbytes(8).hex()}") for i in range(30)]
    assert find_matches(text, many) == []
