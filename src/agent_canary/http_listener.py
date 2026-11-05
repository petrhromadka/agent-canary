"""HTTP canary listener: answers every parsable request with a bland 200 and alerts on canaries.

Each request is read into one buffer and searched, raw and as decoded by `detect`, for
token ids and planted secret values. Bodies are read by Content-Length or, for
`Transfer-Encoding: chunked`, until the last chunk; either way at most MAX_BODY bytes.
Whatever arrived is searched even when the client stops early or the connection hits its
deadline. Every response closes the connection, so an unread body tail cannot desync
the stream.

Limits against slow or oversized clients: MAX_CONNECTIONS handlers at a time (more are
closed at once), one absolute DEADLINE_SECONDS per connection however slowly bytes
trickle in, MAX_HEAD bytes of request line plus headers and MAX_BODY bytes of body.
"""

from __future__ import annotations

import re
import socket
import socketserver
import sys
import threading
import time
from collections.abc import Callable
from email.utils import formatdate
from http.server import ThreadingHTTPServer
from typing import Any, cast

from agent_canary import alerts, detect
from agent_canary.models import Alert, Manifest

MAX_HEAD = 16 * 1024
MAX_BODY = 256 * 1024
MAX_CONNECTIONS = 64
DEADLINE_SECONDS = 10.0
WRITE_TIMEOUT = 2.0  # seconds for sending the response, after the read deadline
DETAIL_LIMIT = 200
RECV_SIZE = 65536

_HEAD_END = re.compile(rb"\r?\n\r?\n")
_TOO_LARGE = "Request Header Or Cookie Too Large"
_REASONS = {200: "OK", 400: "Bad Request", 414: "Request-URI Too Large"}


def _error_page(code: int, title: str, note: str = "") -> bytes:
    """The small HTML page nginx sends for an error status."""
    lines = [
        "<html>",
        f"<head><title>{code} {title}</title></head>",
        "<body>",
        f"<center><h1>{code} {_REASONS[code]}</h1></center>",
        *([f"<center>{note}</center>"] if note else []),
        "<hr><center>nginx</center>",
        "</body>",
        "</html>",
        "",
    ]
    return "\r\n".join(lines).encode("ascii")


class _Reader:
    """Socket reads into one growing buffer, all under one absolute deadline."""

    def __init__(self, sock: socket.socket, deadline: float) -> None:
        self.sock = sock
        self.deadline = deadline
        self.buf = bytearray()

    def fill(self, upto: int) -> bool:
        """Read more, keeping len(buf) <= upto. False on EOF, error or a passed deadline."""
        remaining = self.deadline - time.monotonic()
        if remaining <= 0 or len(self.buf) >= upto:
            return False
        self.sock.settimeout(remaining)
        try:
            data = self.sock.recv(min(upto - len(self.buf), RECV_SIZE))
        except OSError:  # includes TimeoutError
            return False
        self.buf += data
        return bool(data)


def _chunked_done(buf: bytearray, body_start: int) -> bool:
    """Whether the chunked body ends with the last chunk (trailers are not waited for)."""
    tail = b"\n" + bytes(buf[max(body_start, len(buf) - 6) :])
    return tail.endswith((b"\n0\r\n\r\n", b"\n0\n\n"))


def _dechunk(raw: bytes) -> bytes:
    """Chunk data of a (possibly cut or malformed) chunked body, as far as it parses."""
    out = bytearray()
    pos = 0
    while (eol := raw.find(b"\n", pos)) >= 0:
        try:
            size = int(raw[pos:eol].split(b";", 1)[0].strip(), 16)
        except ValueError:
            break
        if size <= 0:
            break
        start = eol + 1
        out += raw[start : start + size]
        pos = raw.find(b"\n", start + size)  # CRLF after the chunk data
        if pos < 0:
            break
        pos += 1
    return bytes(out)


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server = cast("HttpCanaryServer", self.server)
        sock = cast("socket.socket", self.request)
        reader = _Reader(sock, time.monotonic() + server.deadline)
        status: tuple[int, bytes] | None = None
        method = ""
        try:
            head_end = self._read_head(reader)
            line_end = reader.buf.find(b"\n")
            parts = bytes(reader.buf[: line_end if line_end >= 0 else len(reader.buf)]).split()
            method = parts[0].decode("utf-8", "backslashreplace") if parts else ""
            target = parts[1].decode("utf-8", "backslashreplace") if len(parts) > 1 else ""
            if head_end is None:
                # Too large gets nginx's answer; EOF or the deadline gets none, like nginx.
                if len(reader.buf) >= MAX_HEAD and line_end < 0:
                    status = (414, _error_page(414, "Request-URI Too Large"))
                elif len(reader.buf) >= MAX_HEAD:
                    status = (400, _error_page(400, _TOO_LARGE, _TOO_LARGE))
                haystack = bytes(reader.buf)
            elif len(parts) != 3 or not parts[2].startswith(b"HTTP/"):
                status = (400, _error_page(400, "Bad Request"))
                haystack = bytes(reader.buf)
            else:
                status = (200, b"ok")
                haystack = self._read_body(reader, head_end)
            if reader.buf:
                self._detect(server, haystack, method, target)
        finally:
            if status is not None:
                self._respond(sock, *status, head_only=method == "HEAD")

    @staticmethod
    def _read_head(reader: _Reader) -> int | None:
        """Read up to the blank line after the headers: offset of the body, or None."""
        searched = 0
        while True:
            end = _HEAD_END.search(reader.buf, max(0, searched - 3))
            if end:
                return end.end()
            searched = len(reader.buf)
            if not reader.fill(MAX_HEAD):
                return None

    @staticmethod
    def _read_body(reader: _Reader, body_start: int) -> bytes:
        """Read the body; returns everything received, plus the de-chunked body if chunked."""
        fields: dict[bytes, bytes] = {}
        for line in bytes(reader.buf[:body_start]).split(b"\n")[1:]:
            name, sep, value = line.partition(b":")
            if sep:
                fields[name.strip().lower()] = value.strip()
        if b"chunked" in fields.get(b"transfer-encoding", b"").lower():
            limit = body_start + MAX_BODY
            while not _chunked_done(reader.buf, body_start) and reader.fill(limit):
                pass
            return bytes(reader.buf) + b"\n" + _dechunk(bytes(reader.buf[body_start:]))
        try:
            length = int(fields.get(b"content-length", b"0"))
        except ValueError:
            length = 0
        want = body_start + min(max(length, 0), MAX_BODY)
        while len(reader.buf) < want and reader.fill(want):
            pass
        return bytes(reader.buf)

    def _detect(self, server: HttpCanaryServer, haystack: bytes, method: str, target: str) -> None:
        manifests = server.manifests_loader()
        matches = detect.find_matches(haystack, manifests)
        if not matches:
            return
        candidates = (
            f"{method} {target}",
            f"{method} {target.split('?', 1)[0]}",
            f"{method} /{detect.REDACTED}",
        )
        detail = detect.safe_detail(candidates, manifests, limit=DETAIL_LIMIT)
        host, port = self.client_address[:2]
        source = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        # Unlike DNS (where lookups come through resolvers), HTTP requests come straight from
        # the leaking host, so the same leak from another address is a separate alert. The
        # port is left out: every retry opens a new connection.
        ids = tuple(sorted(f"{m.token_id}:{m.secret.name if m.secret else ''}" for m in matches))
        if server.dedup.first_seen((ids, host, detail)):
            server.on_alert(alerts.make_alert("http", source, detail, matches))

    @staticmethod
    def _respond(sock: socket.socket, code: int, body: bytes, *, head_only: bool) -> None:
        content_type = "text/plain" if code == 200 else "text/html"
        head = (
            f"HTTP/1.1 {code} {_REASONS[code]}\r\n"
            "Server: nginx\r\n"
            f"Date: {formatdate(usegmt=True)}\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("ascii")
        sock.settimeout(WRITE_TIMEOUT)
        sock.sendall(head if head_only else head + body)


class HttpCanaryServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        host: str,
        port: int,
        *,
        manifests_loader: Callable[[], list[Manifest]],
        on_alert: Callable[[Alert], None],
        max_connections: int = MAX_CONNECTIONS,
        deadline: float = DEADLINE_SECONDS,
    ) -> None:
        self.manifests_loader = manifests_loader
        self.on_alert = on_alert
        self.deadline = deadline
        self.dedup = alerts.Dedup()
        self._slots = threading.BoundedSemaphore(max_connections)
        if ":" in host:
            self.address_family = socket.AF_INET6
        super().__init__((host, port), _Handler)

    def server_bind(self) -> None:
        # HTTPServer.server_bind calls socket.getfqdn(), which can stall for seconds.
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = str(host)
        self.server_port = int(port)

    def process_request(self, request: Any, client_address: Any) -> None:
        """Start a handler thread, or close the connection at once when all slots are busy."""
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def handle_error(self, request: object, client_address: object) -> None:
        """Keep serving; report only the exception type, never request data."""
        exc = sys.exception()
        if exc is not None and not isinstance(exc, OSError):
            print(f"http listener: handler error {type(exc).__name__}", file=sys.stderr)
