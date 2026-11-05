"""DNS canary listener: an authoritative-only UDP server for the delegated canary domain.

Any lookup of `<tag>.<token_id>.<dns_domain>` that reaches us raises an alert. Other names
under a canary domain get NXDOMAIN; names outside every canary domain get REFUSED, so the
listener never acts as an open resolver.
"""

from __future__ import annotations

import ipaddress
import socket
import socketserver
import struct
import threading
import time
from collections.abc import Callable
from typing import cast

from agent_canary import alerts
from agent_canary.detect import find_matches
from agent_canary.models import Alert, Manifest

QTYPE_A = 1
QTYPE_ANY = 255
RCODE_NOERROR = 0
RCODE_NXDOMAIN = 3
RCODE_REFUSED = 5
ANSWER_TTL = 60
DEDUP_SECONDS = 60.0
DEDUP_MAX_ENTRIES = 10_000

_HEADER = struct.Struct("!HHHHHH")


def parse_query(packet: bytes) -> tuple[int, str, int, int] | None:
    """Parse the first question of a DNS query: (txid, qname, qtype, question_end).

    `qname` keeps the case it was sent in, has no trailing dot, and shows non-ASCII bytes
    as `\\xNN`. Returns None for anything that is not a well-formed, uncompressed query.
    """
    if len(packet) < _HEADER.size:
        return None
    txid, flags, qdcount, _, _, _ = _HEADER.unpack_from(packet)
    if flags & 0x8000 or qdcount < 1:
        return None
    pos = _HEADER.size
    labels: list[bytes] = []
    wire_len = 1  # the terminating root byte
    while True:
        if pos >= len(packet):
            return None
        length = packet[pos]
        pos += 1
        if length == 0:
            break
        if length > 63:  # compression pointer (0xC0) or reserved label type
            return None
        wire_len += length + 1
        if wire_len > 255 or pos + length > len(packet):
            return None
        labels.append(packet[pos : pos + length])
        pos += length
    if pos + 4 > len(packet):
        return None
    (qtype,) = struct.unpack_from("!H", packet, pos)
    qname = b".".join(labels).decode("ascii", errors="backslashreplace")
    return txid, qname, qtype, pos + 4


def _under_domain(qname: str, domain: str) -> bool:
    domain = domain.lower().rstrip(".")
    return bool(domain) and (qname == domain or qname.endswith("." + domain))


class _Dedup:
    """Remembers recently alerted names; thread-safe and bounded."""

    def __init__(self, window: float = DEDUP_SECONDS, max_entries: int = DEDUP_MAX_ENTRIES):
        self._window = window
        self._max = max_entries
        self._seen: dict[str, float] = {}  # insertion order == time order
        self._lock = threading.Lock()

    def first_seen(self, key: str) -> bool:
        """True when `key` was not seen within the window (and records it now)."""
        now = time.monotonic()
        with self._lock:
            while self._seen:
                oldest_key, oldest_time = next(iter(self._seen.items()))
                if now - oldest_time < self._window and len(self._seen) < self._max:
                    break
                del self._seen[oldest_key]
            if key in self._seen:
                return False
            self._seen[key] = now
            return True


class _DnsHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server = cast("DnsCanaryServer", self.server)
        packet, sock = cast("tuple[bytes, socket.socket]", self.request)
        parsed = parse_query(packet)
        if parsed is None:
            return
        txid, qname, qtype, question_end = parsed
        lowered = qname.lower()
        manifests = server.manifests_loader()
        matches = find_matches(lowered, manifests)

        answers = b""
        if matches:
            rcode = RCODE_NOERROR
            if qtype in (QTYPE_A, QTYPE_ANY):
                answers = struct.pack("!HHHIH", 0xC00C, QTYPE_A, 1, ANSWER_TTL, 4)
                answers += server.answer_ip
        elif any(m.dns_domain and _under_domain(lowered, m.dns_domain) for m in manifests):
            rcode = RCODE_NXDOMAIN
        else:
            rcode = RCODE_REFUSED

        (flags,) = struct.unpack_from("!H", packet, 2)
        resp_flags = 0x8000 | (flags & 0x7800) | 0x0400 | (flags & 0x0100) | rcode
        header = _HEADER.pack(txid, resp_flags, 1, 1 if answers else 0, 0, 0)
        sock.sendto(header + packet[_HEADER.size : question_end] + answers, self.client_address)

        if matches and server.dedup.first_seen(lowered):
            ip, port = self.client_address[:2]
            source = f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"
            server.on_alert(alerts.make_alert("dns", source, qname, matches))


class DnsCanaryServer(socketserver.ThreadingUDPServer):
    daemon_threads = True

    def __init__(
        self,
        host: str,
        port: int,
        *,
        answer_ip: str,
        manifests_loader: Callable[[], list[Manifest]],
        on_alert: Callable[[Alert], None],
    ) -> None:
        self.answer_ip = ipaddress.IPv4Address(answer_ip).packed  # ValueError if invalid
        self.manifests_loader = manifests_loader
        self.on_alert = on_alert
        self.dedup = _Dedup()
        self.address_family = socket.AF_INET6 if ":" in host else socket.AF_INET
        super().__init__((host, port), _DnsHandler)

    def handle_error(self, request: object, client_address: object) -> None:
        """Drop the failed request silently: one bad packet must not stop or spam the server."""
