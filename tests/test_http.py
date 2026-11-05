import base64
import contextlib
import http.client
import json
import queue
import socket
import threading
import time
import urllib.request

import pytest

from agent_canary import alerts
from agent_canary.http_listener import HttpCanaryServer
from agent_canary.models import Alert, Manifest, Secret

CANARY_ID = "abcdefgh2345"
SECRETS = (
    Secret("env", ".env", "API_KEY", "test-value-1"),
    Secret("aws", ".aws/credentials", "aws_access_key_id", "test-value-2"),
)


def start(**kwargs):
    manifest = Manifest(
        token_id=CANARY_ID,
        workspace="/w",
        created="2026-11-05T00:00:00+00:00",
        dns_domain=None,
        http_url="http://127.0.0.1:1",
        secrets=SECRETS,
    )
    got: queue.Queue[Alert] = queue.Queue()
    srv = HttpCanaryServer(
        "127.0.0.1", 0, manifests_loader=lambda: [manifest], on_alert=got.put, **kwargs
    )
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, got


@pytest.fixture
def server():
    srv, got = start()
    yield srv, got
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def quick_server():
    """A server with a 1 s connection deadline and room for two connections."""
    srv, got = start(deadline=1.0, max_connections=2)
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
    request(srv, "GET", f"/t/{CANARY_ID}/env")
    assert got.empty()  # same leak again within the dedup window


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


def raw(srv, data, timeout=5.0):
    with socket.create_connection(srv.server_address[:2], timeout=timeout) as sock:
        sock.sendall(data)
        out = b""
        while chunk := sock.recv(65536):
            out += chunk
        return out


def test_alert_detail_never_shows_a_secret_value(server):
    srv, got = server
    value = SECRETS[0].value
    forms = {
        f"/{value}": "GET /<redacted>",
        f"/a?key={value}": "GET /a",
        f"/b?key={value.replace('-', '%2D')}": "GET /b",
        "/c?key=" + "".join(f"%{b:02X}" for b in value.encode()): "GET /c",
        "/d?key=" + base64.b64encode(value.encode()).decode(): "GET /d",
        "/e?" + "a" * 187 + value: "GET /e",  # the old 200-character cut kept 10 characters
    }
    for path, detail in forms.items():
        request(srv, "GET", path)
        alert = got.get(timeout=2)
        assert names(alert) == ["API_KEY"], path
        assert alert.detail == detail
        for line in (json.dumps(alert.to_dict()), alerts.format_alert(alert)):
            assert not any(value[i : i + 8] in line for i in range(len(value) - 7)), line


def test_responses_look_like_nginx(server):
    srv, _ = server
    ok = raw(srv, b"GET / HTTP/1.1\r\nHost: a\r\n\r\n")
    assert ok.startswith(b"HTTP/1.1 200 OK\r\n")
    assert b"\r\nServer: nginx\r\n" in ok
    assert b"\r\nConnection: close\r\n" in ok
    too_large = b"GET / HTTP/1.1\r\nX: " + b"x" * 17000 + b"\r\n\r\n"
    for junk in (b"garbage\r\n\r\n", too_large):
        resp = raw(srv, junk)
        assert resp.startswith(b"HTTP/1.1 400 Bad Request\r\n")
        assert b"\r\nContent-Type: text/html\r\n" in resp
        assert resp.endswith(b"<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n")


def test_trickling_client_is_cut_off_at_the_deadline(quick_server):
    srv, _ = quick_server
    start_time = time.monotonic()
    with socket.create_connection(srv.server_address[:2], timeout=5) as sock:
        sock.sendall(b"GET / HTTP/1.1\r\n")
        sock.settimeout(0.2)
        with contextlib.suppress(OSError):  # a reset or abort also means disconnected
            while time.monotonic() - start_time < 5:
                sock.sendall(b"X")
                with contextlib.suppress(TimeoutError):
                    if sock.recv(1) == b"":
                        break
    assert time.monotonic() - start_time < 3


def test_short_body_is_still_searched_after_the_deadline(quick_server):
    srv, got = quick_server
    body = SECRETS[0].value.encode()
    with socket.create_connection(srv.server_address[:2], timeout=5) as sock:
        # Content-Length promises one byte more than is sent; the socket stays open.
        head = b"POST / HTTP/1.1\r\nContent-Length: %d\r\n\r\n" % (len(body) + 1)
        sock.sendall(head + body)
        assert sock.recv(100).startswith(b"HTTP/1.1 200 OK")
    assert names(got.get(timeout=2)) == ["API_KEY"]


def test_connections_over_the_limit_are_closed(quick_server):
    srv, _ = quick_server

    def get():
        try:
            return raw(srv, b"GET / HTTP/1.1\r\n\r\n")
        except OSError:  # Windows may report the immediate close as a reset
            return b""

    idle = [socket.create_connection(srv.server_address[:2], timeout=5) for _ in range(2)]
    try:
        start_time = time.monotonic()
        assert get() == b""
        assert time.monotonic() - start_time < 0.5
    finally:
        for sock in idle:
            sock.close()
    # The idle handlers see EOF and free their slots.
    end = time.monotonic() + 2
    while (resp := get()) == b"" and time.monotonic() < end:
        time.sleep(0.05)
    assert resp.startswith(b"HTTP/1.1 200 OK")
