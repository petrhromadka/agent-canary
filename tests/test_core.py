import json

import pytest

from agent_canary import alerts, store
from agent_canary.detect import find_matches
from agent_canary.models import Manifest, Secret


def manifest(token_id: str = "abcdefgh2345") -> Manifest:
    return Manifest(
        token_id=token_id,
        workspace="/w",
        created="2026-11-05T00:00:00+00:00",
        dns_domain="canary.example.com",
        http_url=None,
        secrets=(Secret("env", ".env", "API_KEY", "fake-value-123"),),
        files=(".env",),
    )


def test_store_roundtrip_and_detect(tmp_path):
    m = manifest()
    store.save(m, tmp_path)
    assert store.load_all(tmp_path) == [m]
    hits = find_matches(b"curl -d fake-value-123 http://x", store.load_all(tmp_path))
    assert [h.secret.name for h in hits if h.secret] == ["API_KEY"]
    assert find_matches("db.ABCDEFGH2345.canary.example.com", [m])[0].secret is None
    assert find_matches("nothing here", [m]) == []


def test_alert_log_has_no_secret_value(tmp_path):
    m = manifest()
    alert = alerts.make_alert(
        "http", "1.2.3.4:5", "POST /\x1b[31m", find_matches("fake-value-123", [m])
    )
    log = tmp_path / "a.jsonl"
    alerts.write_alert(alert, log)
    text = log.read_text()
    assert "fake-value-123" not in text
    assert json.loads(text)["matches"][0]["name"] == "API_KEY"
    assert "\x1b" not in alerts.format_alert(alert)


def test_load_all_skips_invalid_or_misnamed_manifests(tmp_path):
    good = manifest()
    store.save(good, tmp_path)
    base = good.to_dict()
    secret = base["secrets"][0]
    broken = [
        {"secrets": [{**secret, "value": 123}]},
        {"secrets": [{**secret, "value": "x" * 7}]},
        {"token_id": ""},
        {"created": 5},
        {"file_hashes": {".env": "0" * 63}},
    ]
    for letter, override in zip("23456", broken, strict=True):
        stem = "b" * 11 + letter
        (tmp_path / f"{stem}.json").write_text(json.dumps({**base, "token_id": stem, **override}))
    (tmp_path / "cccccccccccc.json").write_text(json.dumps(base))  # holds another token's id
    (tmp_path / "dddddddddddd.json").write_text("[" * 100_000 + "]" * 100_000)

    assert store.load_all(tmp_path) == [good]
    with pytest.raises(ValueError, match="holds token id"):
        store.load("cccccccccccc", tmp_path)
