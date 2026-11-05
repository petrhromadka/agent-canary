import base64
import random

import pytest

from agent_canary.detect import find_matches
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


def test_no_false_positive_on_random_megabyte():
    rng = random.Random(1)  # noqa: S311 -- reproducible test data, not cryptography
    raw = rng.randbytes(256 * 1024)
    text = base64.b64encode(raw) + raw.hex().encode() + raw
    assert len(text) > 1024 * 1024
    many = [manifest(f"test-value-{i}-{rng.randbytes(8).hex()}") for i in range(30)]
    assert find_matches(text, many) == []
