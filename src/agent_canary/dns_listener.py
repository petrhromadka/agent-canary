"""DNS canary listener: an authoritative-only UDP server for the delegated canary domain.

Any lookup of a name carrying a token id (`<tag>.<token_id>.<dns_domain>`) that reaches us
raises an alert. Inside a canary domain we answer authoritatively: A for canary names, SOA
and NS at the zone apex, NXDOMAIN or NODATA with an SOA for everything else. Names outside
every canary domain get REFUSED (still alerting when they carry a token id), so the listener
never acts as an open resolver.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import socket
import socketserver
import struct
import sys
import time
from collections.abc import Callable, Sequence
from typing import cast

from agent_canary import alerts
from agent_canary.detect import REDACTED, find_matches
from agent_canary.models import Alert, Manifest, Match, Secret

QTYPE_A = 1
QTYPE_NS = 2
QTYPE_SOA = 6
QTYPE_ANY = 255
QCLASS_IN = 1
QCLASS_ANY = 255
RCODE_NOERROR = 0
RCODE_NXDOMAIN = 3
RCODE_NOTIMP = 4
RCODE_REFUSED = 5
ANSWER_TTL = 60
NEGATIVE_TTL = 60  # SOA minimum: how long resolvers cache NXDOMAIN/NODATA
SOA_TIMERS = (1, 3600, 600, 86400, NEGATIVE_TTL)  # serial, refresh, retry, expire, minimum
MAX_NAME = 255  # longest DNS name on the wire; escaped non-ASCII bytes may be cut
# Left labels kept in an alert detail when they are the only label left of the token id:
# the tags the planters put in hostnames, plus the kind names. Any other left label may be
# (part of) an exfiltrated secret, so it is replaced by REDACTED.
PLANT_TAGS = frozenset({"db", "ssh", "aws", "env", "k8s", "registry", "git", "pypi"})
# Per token id at most this many alerts per window. The first alert of a token is never
# suppressed; suppressed lookups are dropped silently (no count is reported) and alerting
# resumes with the next lookup after the window ends. Dedup by name runs first.
RATE_LIMIT = 30
RATE_WINDOW = 60.0

NS_LABEL = b"ns1"  # the name server is ns1.<dns_domain>; it answers A with answer_ip
NS_LABEL_WIRE = bytes([len(NS_LABEL)]) + NS_LABEL

_HEADER = struct.Struct("!HHHHHH")


@dataclasses.dataclass(frozen=True, slots=True)
class _Query:
    txid: int
    flags: int
    labels: tuple[bytes, ...]
    offsets: tuple[int, ...]  # packet offset of each label's length byte
    qtype: int
    qclass: int
    end: int  # offset just past the question


def _parse(packet: bytes) -> _Query | None:
    if len(packet) < _HEADER.size:
        return None
    txid, flags, qdcount, _, _, _ = _HEADER.unpack_from(packet)
    if flags & 0x8000 or qdcount < 1:
        return None
    pos = _HEADER.size
    labels: list[bytes] = []
    offsets: list[int] = []
    wire_len = 1  # the terminating root byte
    while True:
        if pos >= len(packet):
            return None
        length = packet[pos]
        if length == 0:
            pos += 1
            break
        if length > 63:  # compression pointer (0xC0) or reserved label type
            return None
        wire_len += length + 1
        if wire_len > 255 or pos + 1 + length > len(packet):
            return None
        offsets.append(pos)
        labels.append(packet[pos + 1 : pos + 1 + length])
        pos += 1 + length
    if pos + 4 > len(packet):
        return None
    qtype, qclass = struct.unpack_from("!HH", packet, pos)
    return _Query(txid, flags, tuple(labels), tuple(offsets), qtype, qclass, pos + 4)


def _text(labels: Sequence[bytes]) -> str:
    return b".".join(labels).decode("ascii", errors="backslashreplace")


def parse_query(packet: bytes) -> tuple[int, str, int, int] | None:
    """Parse the first question of a DNS query: (txid, qname, qtype, question_end).

    `qname` keeps the case it was sent in, has no trailing dot, and shows non-ASCII bytes
    as `\\xNN`. Returns None for anything that is not a well-formed, uncompressed query.
    """
    q = _parse(packet)
    return None if q is None else (q.txid, _text(q.labels), q.qtype, q.end)


class _Index:
    """What the handler derives from the manifests, rebuilt only when the loader's list changes.

    DNS is case-insensitive and resolvers may flip letter case (DNS 0x20), so secrets are
    also searched lowercased, in manifests whose secret values are lowercased.
    """

    def __init__(self) -> None:
        self.manifests: list[Manifest] = []
        self.lowered: list[Manifest] = []
        self.original: dict[int, Secret] = {}  # id(lowercased secret) -> planted secret
        self.tokens: frozenset[bytes] = frozenset()
        self.domains: frozenset[tuple[bytes, ...]] = frozenset()  # lowercase labels

    def update(self, manifests: list[Manifest]) -> None:
        if manifests is self.manifests:
            return
        lowered, original = [], {}
        for m in manifests:
            secrets = tuple(dataclasses.replace(s, value=s.value.lower()) for s in m.secrets)
            original.update({id(low): s for low, s in zip(secrets, m.secrets, strict=True)})
            lowered.append(dataclasses.replace(m, secrets=secrets))
        self.manifests = manifests
        self.lowered, self.original = lowered, original
        self.tokens = frozenset(m.token_id.encode("ascii") for m in manifests)
        self.domains = frozenset(
            tuple(m.dns_domain.lower().rstrip(".").encode("ascii", "replace").split(b"."))
            for m in manifests
            if m.dns_domain and m.dns_domain.rstrip(".")
        )

    def find(self, texts: Sequence[str]) -> list[Match]:
        """Canaries in `texts` as sent or lowercased; a token-only match only without a secret."""
        hay = " ".join(texts)
        found: dict[tuple[str, int], Match] = {}
        for m in find_matches(hay, self.manifests):
            found.setdefault((m.token_id, id(m.secret)), m)
        for m in find_matches(hay.lower(), self.lowered):
            if m.secret is not None:
                secret = self.original[id(m.secret)]
                found.setdefault((m.token_id, id(secret)), Match(m.token_id, secret, m.encoding))
        with_secret = {m.token_id for m in found.values() if m.secret is not None}
        return [m for m in found.values() if m.secret is not None or m.token_id not in with_secret]

    def zone(self, lower: Sequence[bytes]) -> int | None:
        """Index of the first label of the longest canary domain `lower` ends with, if any."""
        starts = [
            len(lower) - len(d)
            for d in self.domains
            if len(d) <= len(lower) and tuple(lower[len(lower) - len(d) :]) == d
        ]
        return min(starts, default=None)


def _pointer(offset: int) -> bytes:
    return struct.pack("!H", 0xC000 | offset)


def _rr(owner: bytes, rtype: int, rdata: bytes, ttl: int = ANSWER_TTL) -> bytes:
    return owner + struct.pack("!HHIH", rtype, QCLASS_IN, ttl, len(rdata)) + rdata


def _soa(zone: bytes) -> bytes:
    rdata = NS_LABEL_WIRE + zone + b"\x0ahostmaster" + zone + struct.pack("!5I", *SOA_TIMERS)
    return _rr(zone, QTYPE_SOA, rdata, NEGATIVE_TTL)


class _RateLimit:
    """At most `limit` events per key per fixed window (single-threaded use)."""

    def __init__(self, limit: int = RATE_LIMIT, window: float = RATE_WINDOW) -> None:
        self._limit = limit
        self._window = window
        self._counts: dict[str, tuple[float, int]] = {}

    def allow(self, keys: Sequence[str]) -> bool:
        """Count one event for each key; True when any key is still under its limit."""
        now = time.monotonic()
        allowed = False
        for key in keys:
            start, count = self._counts.get(key, (now, 0))
            if now - start >= self._window:
                start, count = now, 0
            allowed |= count < self._limit
            self._counts[key] = (start, count + 1)
        return allowed


class _DnsHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server = cast("DnsCanaryServer", self.server)
        packet, sock = cast("tuple[bytes, socket.socket]", self.request)
        q = _parse(packet)
        if q is None:
            return
        rcode, answers, authority, alert = self._respond(server, q)
        resp_flags = 0x8000 | (q.flags & 0x7900) | rcode  # QR, echoed opcode and RD
        if rcode != RCODE_NOTIMP and rcode != RCODE_REFUSED:
            resp_flags |= 0x0400  # AA: we are the authority for the canary domains
        header = _HEADER.pack(q.txid, resp_flags, 1, len(answers), len(authority), 0)
        response = header + packet[_HEADER.size : q.end] + b"".join(answers + authority)
        # Alert before answering, so a client that got the answer can rely on the alert existing.
        try:
            if alert is not None:
                server.on_alert(alert)
        finally:
            sock.sendto(response, self.client_address)

    def _respond(
        self, server: DnsCanaryServer, q: _Query
    ) -> tuple[int, list[bytes], list[bytes], Alert | None]:
        if q.flags & 0x7800:  # opcode other than QUERY (IQUERY, STATUS, NOTIFY, UPDATE)
            return RCODE_NOTIMP, [], [], None
        manifests = server.manifests_loader()
        index = server.index
        index.update(manifests)
        lower = tuple(label.lower() for label in q.labels)
        zone_at = index.zone(lower)
        end = len(lower) if zone_at is None else zone_at
        token_at = next((i for i in reversed(range(end)) if lower[i] in index.tokens), None)
        # Payload: every label except the token id and the canary domain, on either side.
        if token_at is None:
            payload = q.labels[:end]
        else:
            payload = q.labels[:token_at] + q.labels[token_at + 1 : end]
        # A secret may be split across labels to fit 63 bytes each: search them joined too.
        texts = [_text(q.labels)] + ([_text(payload).replace(".", "")] if len(payload) > 1 else [])
        matches = index.find(texts)
        alert = self._alert(server, q, token_at, zone_at, matches)

        in_class = q.qclass in (QCLASS_IN, QCLASS_ANY)
        if zone_at is None or not in_class:
            return RCODE_REFUSED, [], [], alert
        zone = _pointer(q.offsets[zone_at])
        soa = [_soa(zone)]
        if zone_at == 1 and lower[0] == NS_LABEL and not matches:  # our NS name from the apex
            if q.qtype in (QTYPE_A, QTYPE_ANY):
                return RCODE_NOERROR, [_rr(_pointer(12), QTYPE_A, server.answer_ip)], [], None
            return RCODE_NOERROR, [], soa, None
        if matches:
            if q.qtype in (QTYPE_A, QTYPE_ANY):
                return RCODE_NOERROR, [_rr(_pointer(12), QTYPE_A, server.answer_ip)], [], alert
            return RCODE_NOERROR, [], soa, alert
        if zone_at == 0:  # the zone apex
            if q.qtype in (QTYPE_SOA, QTYPE_ANY):
                return RCODE_NOERROR, soa, [], alert
            if q.qtype == QTYPE_NS:
                return RCODE_NOERROR, [_rr(zone, QTYPE_NS, NS_LABEL_WIRE + zone)], [], alert
            return RCODE_NOERROR, [], soa, alert
        return RCODE_NXDOMAIN, [], soa, alert

    def _alert(
        self,
        server: DnsCanaryServer,
        q: _Query,
        token_at: int | None,
        zone_at: int | None,
        matches: list[Match],
    ) -> Alert | None:
        lower = [label.lower() for label in q.labels]
        # Dedup by name only: lookups reach us through recursive resolvers, so retries of one
        # leak arrive from varying resolver addresses and the source says little about the leaker.
        if not matches or not server.dedup.first_seen(b".".join(lower)):
            return None
        if not server.rate_limit.allow(sorted({m.token_id for m in matches})):
            return None
        ip, port = self.client_address[:2]
        source = f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"
        detail = _safe_name(q.labels, token_at, zone_at)
        if any(m.secret for m in server.index.find([detail, detail.replace(".", "")])):
            detail = REDACTED
        return alerts.make_alert("dns", source, detail, matches)


def _safe_name(labels: Sequence[bytes], token_at: int | None, zone_at: int | None) -> str:
    """The query name with every payload label replaced by one REDACTED marker.

    Only the token id, the canary domain and a lone plant tag right before the token id
    (`db.<token>.<domain>`) are kept, so no secret or part of one reaches the alert log.
    """
    end = len(labels) if zone_at is None else zone_at
    zone = [_text(labels[zone_at:])] if zone_at is not None else []
    if token_at is None:
        return ".".join([REDACTED, *zone]) if end else ".".join(zone)
    left = labels[:token_at]
    right = labels[token_at + 1 : end]
    if len(left) == 1 and _text(left).lower() in PLANT_TAGS:
        head = [_text(left).lower()]
    else:
        head = [REDACTED] if left else []
    middle = [REDACTED] if right else []
    return ".".join([*head, _text(labels[token_at : token_at + 1]), *middle, *zone])[:MAX_NAME]


class DnsCanaryServer(socketserver.UDPServer):
    """Handles each packet inline: the handler is pure computation, threads only cost."""

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
        self.dedup = alerts.Dedup()
        self.rate_limit = _RateLimit()
        self.index = _Index()
        self.address_family = socket.AF_INET6 if ":" in host else socket.AF_INET
        super().__init__((host, port), _DnsHandler)

    def server_bind(self) -> None:
        if self.address_family == socket.AF_INET6 and self.server_address[0] == "::":
            # Dual-stack: Windows defaults IPV6_V6ONLY to 1, so `::` would miss IPv4.
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()

    def handle_error(self, request: object, client_address: object) -> None:
        """Keep serving; report only the exception type (e.g. a failed alert-log write)."""
        exc = sys.exception()
        if exc is not None and not isinstance(exc, OSError):
            print(f"dns listener: handler error {type(exc).__name__}", file=sys.stderr)
