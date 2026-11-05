"""HTTP canary listener: answers every parsable request with a bland 200 and alerts on canaries.

Each request is searched for token ids and planted secret values in the request line,
the headers, the body and the percent-decoded path and query. Bodies are read by
Content-Length or, for `Transfer-Encoding: chunked`, de-chunked; either way at most
MAX_BODY bytes are read and the rest is ignored. The server speaks HTTP/1.0, so every
connection closes after one response and an unread body tail cannot desync the stream.
"""

from __future__ import annotations

import socket
import socketserver
import sys
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import cast
from urllib.parse import unquote_plus

from agent_canary import alerts, detect
from agent_canary.models import Alert, Manifest

MAX_BODY = 1024 * 1024
DETAIL_LIMIT = 200


class _Handler(BaseHTTPRequestHandler):
    timeout = 10  # seconds, applied to the connection socket
    server_version = "nginx"
    sys_version = ""

    def version_string(self) -> str:
        return self.server_version

    def log_message(self, format: str, *args: object) -> None:
        """Silent: the default logs request lines, which may carry secrets, to stderr."""

    def __getattr__(self, name: str) -> Callable[[], None]:
        # Every method (GET, POST, ..., PROPFIND, anything) gets the same handling, so
        # no stdlib "Unsupported method" page gives the server away.
        if name.startswith("do_"):
            return self._handle
        raise AttributeError(name)

    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
        """Replaces the stdlib HTML error page (malformed requests) with a bland one."""
        self.close_connection = True
        self._respond(code, b"error")

    def _respond(self, code: int, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _read_body(self) -> bytes:
        if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
            return self._read_chunked()
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return b""
        return self.rfile.read(min(length, MAX_BODY)) if length > 0 else b""

    def _read_chunked(self) -> bytes:
        parts: list[bytes] = []
        total = 0
        while total < MAX_BODY:
            line = self.rfile.readline(1024)
            if not line.endswith(b"\n"):
                break  # EOF or an absurdly long size line
            try:
                size = int(line.split(b";", 1)[0].strip(), 16)
            except ValueError:
                break
            if size <= 0:
                break  # last chunk; trailers are ignored
            want = min(size, MAX_BODY - total)
            data = self.rfile.read(want)
            parts.append(data)
            total += len(data)
            if len(data) < size:
                break  # hit the cap or EOF
            self.rfile.readline(1024)  # CRLF after the chunk data
        return b"".join(parts)

    def _source(self) -> str:
        host, port = self.client_address[:2]
        return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"

    def _handle(self) -> None:
        try:
            body = self._read_body()
            haystack = "\n".join(
                (
                    self.requestline,
                    str(self.headers),
                    body.decode("utf-8", errors="replace"),
                    unquote_plus(self.path),
                )
            )
            server = cast("HttpCanaryServer", self.server)
            matches = detect.find_matches(haystack, server.manifests_loader())
            if matches:
                detail = f"{self.command} {self.path[:DETAIL_LIMIT]}"
                server.on_alert(alerts.make_alert("http", self._source(), detail, matches))
        finally:
            self._respond(200, b"ok")


class HttpCanaryServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        host: str,
        port: int,
        *,
        manifests_loader: Callable[[], list[Manifest]],
        on_alert: Callable[[Alert], None],
    ) -> None:
        self.manifests_loader = manifests_loader
        self.on_alert = on_alert
        if ":" in host:
            self.address_family = socket.AF_INET6
        super().__init__((host, port), _Handler)

    def server_bind(self) -> None:
        # HTTPServer.server_bind calls socket.getfqdn(), which can stall for seconds.
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = str(host)
        self.server_port = int(port)

    def handle_error(self, request: object, client_address: object) -> None:
        """Keep serving; report only the exception type, never request data."""
        exc = sys.exception()
        if exc is not None and not isinstance(exc, OSError):
            print(f"http listener: handler error {type(exc).__name__}", file=sys.stderr)
