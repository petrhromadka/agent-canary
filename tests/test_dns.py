import socket
import struct
import threading
from dataclasses import replace

import pytest

from agent_canary import store
from agent_canary.dns_listener import DnsCanaryServer, parse_query
from agent_canary.models import Manifest, Secret

CANARY_ID = "abcdefgh2345"
DOMAIN = "canary.example.com"


def manifest() -> Manifest:
    return Manifest(
        token_id=CANARY_ID,
        workspace="/w",
        created="2026-11-05T00:00:00+00:00",
        dns_domain=DOMAIN,
        http_url=None,
        secrets=(Secret("env", ".env", "API_KEY", "test-value-1"),),
        files=(".env",),
    )


def query(name: str, qtype: int = 1, txid: int = 0x1234, opcode: int = 0, qclass: int = 1) -> bytes:
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
    return (
        struct.pack("!HHHHHH", txid, 0x0100 | opcode << 11, 1, 0, 0, 1)
        + labels
        + b"\0"
        + struct.pack("!HH", qtype, qclass)
    )


@pytest.fixture
def dns():
    alerts = []
    server = DnsCanaryServer(
        "127.0.0.1",
        0,
        answer_ip="192.0.2.7",
        manifests_loader=lambda: [manifest()],
        on_alert=alerts.append,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.settimeout(2)

    def ask(packet: bytes) -> bytes:
        client.sendto(packet, server.server_address)
        return client.recvfrom(4096)[0]

    yield ask, client, server, alerts
    client.close()
    server.shutdown()
    server.server_close()


def rcode(resp: bytes) -> int:
    return struct.unpack_from("!H", resp, 2)[0] & 0xF


def ancount(resp: bytes) -> int:
    return struct.unpack_from("!H", resp, 6)[0]


def nscount(resp: bytes) -> int:
    return struct.unpack_from("!H", resp, 8)[0]


def test_canary_query_answers_and_alerts_once(dns):
    ask, _, _, alerts = dns
    q = query(f"db.{CANARY_ID}.{DOMAIN}")
    resp = ask(q)
    assert resp[:2] == b"\x12\x34"
    flags = struct.unpack_from("!H", resp, 2)[0]
    assert flags & 0x8000 and flags & 0x0400 and flags & 0x0100
    assert rcode(resp) == 0 and ancount(resp) == 1
    assert resp[12 : len(q)] == q[12:]
    assert resp[-4:] == socket.inet_aton("192.0.2.7")
    ask(q)
    ask(query(f"db.{CANARY_ID}.{DOMAIN}", qtype=28))
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.channel == "dns" and alert.detail == f"db.{CANARY_ID}.{DOMAIN}"
    assert alert.source.startswith("127.0.0.1:")
    assert [(m.token_id, m.secret) for m in alert.matches] == [(CANARY_ID, None)]


def test_mixed_case_matches_and_is_echoed(dns):
    ask, _, _, alerts = dns
    q = query(f"Db.{CANARY_ID.upper()}.CaNaRy.Example.COM")
    resp = ask(q)
    assert rcode(resp) == 0 and ancount(resp) == 1
    assert resp[12 : len(q)] == q[12:]
    assert len(alerts) == 1


def test_aaaa_nxdomain_refused(dns):
    ask, _, _, alerts = dns
    resp = ask(query(f"x.{CANARY_ID}.{DOMAIN}", qtype=28))
    assert rcode(resp) == 0 and ancount(resp) == 0 and nscount(resp) == 1  # NODATA + SOA
    assert len(alerts) == 1
    resp = ask(query(f"www.{DOMAIN}"))
    assert rcode(resp) == 3 and nscount(resp) == 1  # NXDOMAIN + SOA
    assert struct.unpack_from("!H", resp, len(query(f"www.{DOMAIN}")) + 2)[0] == 6
    assert rcode(ask(query("www.example.org"))) == 5
    assert rcode(ask(query(f"y.{CANARY_ID}.{DOMAIN}", opcode=5))) == 4  # UPDATE: NOTIMP
    assert rcode(ask(query(f"y.{CANARY_ID}.{DOMAIN}", qclass=3))) == 5  # CHAOS: REFUSED
    assert len(alerts) == 2  # the CHAOS lookup still leaked the name
    # A token id outside every canary domain: not ours to answer, but still a leak.
    assert rcode(ask(query(f"a.{CANARY_ID}.example.org"))) == 5
    assert len(alerts) == 3 and alerts[-1].detail == f"<redacted>.{CANARY_ID}.<redacted>"


def test_apex_soa_ns_and_ns_host(dns):
    ask, _, _, alerts = dns
    for qtype, rtype in ((6, 6), (255, 6), (2, 2)):
        q = query(DOMAIN, qtype=qtype)
        resp = ask(q)
        assert rcode(resp) == 0 and ancount(resp) == 1 and nscount(resp) == 0
        assert struct.unpack_from("!H", resp, len(q) + 2)[0] == rtype
    resp = ask(query(DOMAIN))
    assert rcode(resp) == 0 and ancount(resp) == 0 and nscount(resp) == 1
    resp = ask(query(f"ns1.{DOMAIN}"))
    assert rcode(resp) == 0 and ancount(resp) == 1
    assert resp[-4:] == socket.inet_aton("192.0.2.7")
    assert alerts == []


def test_alerts_rate_limited_per_token(dns):
    ask, _, _, alerts = dns
    for i in range(35):
        assert rcode(ask(query(f"r{i}.{CANARY_ID}.{DOMAIN}"))) == 0
    assert len(alerts) == 30


def test_cached_loader_rereads_only_changed_manifests(tmp_path):
    store.save(manifest(), tmp_path)
    loader = store.CachedLoader(tmp_path, interval=0)
    first = loader()
    assert [m.token_id for m in first] == [CANARY_ID] and loader() is first
    store.save(replace(manifest(), token_id="bbcdefgh2345", created="2026-11-06"), tmp_path)
    assert [m.token_id for m in loader()] == [CANARY_ID, "bbcdefgh2345"]


def test_garbage_does_not_kill_server(dns):
    ask, client, server, alerts = dns
    for junk in (b"", b"\x00", b"\xff" * 40, query(f"db.{CANARY_ID}.{DOMAIN}")[:-3]):
        client.sendto(junk, server.server_address)
    response_bit = bytearray(query(f"db.{CANARY_ID}.{DOMAIN}"))
    response_bit[2] |= 0x80
    client.sendto(bytes(response_bit), server.server_address)
    assert rcode(ask(query(f"db.{CANARY_ID}.{DOMAIN}", txid=7))) == 0
    assert len(alerts) == 1


def test_parse_query_rejects_pointer_and_long_label():
    good = query("a.example.com", qtype=28)
    assert parse_query(good) == (0x1234, "a.example.com", 28, len(good))
    header = good[:12]
    assert parse_query(header + b"\xc0\x0c\x00\x01\x00\x01") is None
    assert parse_query(header + b"\x40" + b"a" * 64 + b"\x00\x00\x01\x00\x01") is None
    long_name = (b"\x3f" + b"a" * 63) * 4 + b"\x00\x00\x01\x00\x01"
    assert parse_query(header + long_name) is None


def test_answer_ip_must_be_ipv4():
    with pytest.raises(ValueError):
        DnsCanaryServer("127.0.0.1", 0, answer_ip="::1", manifests_loader=list, on_alert=print)


def test_secret_in_a_label_is_redacted_from_the_alert(dns):
    ask, _, _, alerts = dns
    value = manifest().secrets[0].value
    # Whole, split across labels, and split with resolver case randomization (DNS 0x20).
    for name in (f"{value}.x", f"{value[:6]}.{value[6:]}", f"{value[:5].upper()}.{value[5:]}"):
        assert rcode(ask(query(f"{name}.{CANARY_ID}.{DOMAIN}"))) == 0
    # Split right of the token id, behind a plant tag: nothing of the value may survive.
    assert rcode(ask(query(f"db.{CANARY_ID}.{value[:7]}.{value[7:]}.{DOMAIN}"))) == 0
    assert len(alerts) == 4
    for alert in alerts[:3]:
        assert alert.detail == f"<redacted>.{CANARY_ID}.{DOMAIN}"
    assert alerts[3].detail == f"db.{CANARY_ID}.<redacted>.{DOMAIN}"
    for alert in alerts:
        assert [m.secret.name for m in alert.matches if m.secret] == ["API_KEY"]
