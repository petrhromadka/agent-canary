import contextlib
import http.client
import queue
import threading
import urllib.request

import pytest

from agent_canary.http_listener import HttpCanaryServer
from agent_canary.models import Alert, Manifest, Secret

CANARY_ID = "abcdefgh2345"
SECRETS = (
    Secret("env", ".env", "API_KEY", "test-value-1"),
    Secret("aws", ".aws/credentials", "aws_access_key_id", "test-value-2"),
)


@pytest.fixture
def server():
    manifest = Manifest(
        token_id=CANARY_ID,
        workspace="/w",
        created="2026-11-05T00:00:00+00:00",
        dns_domain=None,
        http_url="http://127.0.0.1:1",
        secrets=SECRETS,
    )
    got: queue.Queue[Alert] = queue.Queue()
    srv = HttpCanaryServer("127.0.0.1", 0, manifests_loader=lambda: [manifest], on_alert=got.put)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv, got
    srv.shutdown()
    srv.server_close()


def request(srv, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection(*srv.server_address[:2], timeout=5)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        return resp.status, resp.read(), resp.getheaders()
    finally:
        conn.close()


def names(alert):
    return [m.secret.name if m.secret else None for m in alert.matches]


def test_token_in_path_alerts(server):
    srv, got = server
    status, body, _ = request(srv, "GET", f"/t/{CANARY_ID}/env")
    assert (status, body) == (200, b"ok")
    alert = got.get(timeout=2)
    assert alert.channel == "http"
    assert alert.detail == f"GET /t/{CANARY_ID}/env"
    assert alert.source.startswith("127.0.0.1:")
    assert alert.matches[0].token_id == CANARY_ID
    assert names(alert) == [None]


def test_secret_in_json_body_header_and_encoded_query(server):
    srv, got = server
    req = urllib.request.Request(
        f"http://127.0.0.1:{srv.server_address[1]}/hook",
        data=b'{"key": "test-value-1"}',
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310 (local test server)
        assert resp.status == 200
    assert names(got.get(timeout=2)) == ["API_KEY"]

    request(
        srv, "GET", "/", headers={"Authorization": "AWS4-HMAC-SHA256 Credential=test-value-2/x"}
    )
    assert names(got.get(timeout=2)) == ["aws_access_key_id"]

    request(srv, "PUT", "/x?k=test%2Dvalue%2D1&q=a+b")
    assert names(got.get(timeout=2)) == ["API_KEY"]


def test_unrelated_request_no_alert_and_generic_headers(server):
    srv, got = server
    for method in ("GET", "HEAD", "OPTIONS", "PROPFIND"):
        status, body, headers = request(srv, method, "/wp-login.php?x=1")
        assert status == 200
        assert body == (b"" if method == "HEAD" else b"ok")
        text = repr(headers).lower()
        assert "canary" not in text
        assert "python" not in text
    assert got.empty()


def test_oversized_body_does_not_hang(server):
    srv, got = server
    body = b"test-value-1 " + b"x" * (2 * 1024 * 1024)
    # The server closes after reading 1 MiB; the client may see a reset while sending.
    with contextlib.suppress(OSError):
        request(srv, "POST", "/upload", body=body)
    assert names(got.get(timeout=5)) == ["API_KEY"]
    assert request(srv, "GET", "/")[0] == 200
