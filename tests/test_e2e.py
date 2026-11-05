"""End-to-end: plant -> run a leaky agent -> catch it on the live DNS/HTTP listeners.

Everything runs on localhost against ephemeral ports. The agent-canary CLI is driven as
a subprocess (``python -m agent_canary``) exactly as a user would run it. The whole file
is budgeted to finish in well under 20 seconds.
"""

from __future__ import annotations

import json
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from queue import Empty, Queue

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
LEAKY_AGENT = REPO_ROOT / "examples" / "leaky_agent.py"
DNS_DOMAIN = "example.test"
START_TIMEOUT = 10.0
ALERT_TIMEOUT = 8.0


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _cli(state_dir: Path, *args: str, timeout: float = 15.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "agent_canary", "--state-dir", str(state_dir), *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _pump(proc: subprocess.Popen[str], sink: list[str], queue: Queue[str | None]) -> None:
    assert proc.stdout is not None
    for line in proc.stdout:
        sink.append(line)
        queue.put(line)
    queue.put(None)


def _await_line(queue: Queue[str | None], needle: str, timeout: float) -> None:
    end = time.monotonic() + timeout
    while True:
        remaining = end - time.monotonic()
        if remaining <= 0:
            raise AssertionError(f"timed out waiting for {needle!r} on listener stdout")
        try:
            line = queue.get(timeout=remaining)
        except Empty:
            raise AssertionError(f"timed out waiting for {needle!r}") from None
        if line is None:
            raise AssertionError(f"listener exited before printing {needle!r}")
        if needle in line:
            return


def _await_alerts(log: Path, predicate: Callable[[list[dict]], bool], timeout: float) -> list[dict]:
    end = time.monotonic() + timeout
    seen: list[dict] = []
    while time.monotonic() < end:
        if log.exists():
            seen = [
                json.loads(x) for x in log.read_text(encoding="utf-8").splitlines() if x.strip()
            ]
            if predicate(seen):
                return seen
        time.sleep(0.05)
    raise AssertionError(f"alert condition not met within {timeout}s; got {seen}")


@dataclass
class Canary:
    state_dir: Path
    workspace: Path
    token: str
    http_port: int
    dns_port: int
    log: Path
    manifest: dict
    stdout: list[str]

    def secret_values(self) -> list[str]:
        return [s["value"] for s in self.manifest["secrets"] if s["value"]]


@pytest.fixture
def canary(tmp_path: Path) -> object:
    state_dir = tmp_path / "state"
    workspace = tmp_path / "ws"
    workspace.mkdir()
    log = tmp_path / "alerts.jsonl"
    http_port = _free_port()
    dns_port = _free_port()

    planted = _cli(
        state_dir,
        "plant",
        str(workspace),
        "--dns-domain",
        DNS_DOMAIN,
        "--http-url",
        f"http://127.0.0.1:{http_port}",
    )
    assert planted.returncode == 0, f"plant failed: {planted.stderr}"
    match = re.search(r"token ([a-z2-7]{12}):", planted.stdout)
    assert match, f"no token id in plant output: {planted.stdout!r}"
    token = match.group(1)
    manifest = json.loads((state_dir / f"{token}.json").read_text(encoding="utf-8"))

    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "agent_canary",
            "--state-dir",
            str(state_dir),
            "listen",
            "--http",
            f"127.0.0.1:{http_port}",
            "--dns",
            f"127.0.0.1:{dns_port}",
            "--log",
            str(log),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        bufsize=1,
    )
    stdout: list[str] = []
    queue: Queue[str | None] = Queue()
    threading.Thread(target=_pump, args=(proc, stdout, queue), daemon=True).start()
    try:
        _await_line(queue, "alerts ->", START_TIMEOUT)
        joined = "".join(stdout)
        assert f"listening http on 127.0.0.1:{http_port}" in joined
        assert f"listening dns on 127.0.0.1:{dns_port}" in joined
        yield Canary(state_dir, workspace, token, http_port, dns_port, log, manifest, stdout)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        if proc.stdout is not None:
            proc.stdout.close()


def test_leaky_agent_is_caught_on_both_channels(canary: Canary) -> None:
    exfil = subprocess.run(
        [
            sys.executable,
            str(LEAKY_AGENT),
            "--workspace",
            str(canary.workspace),
            "--url",
            f"http://127.0.0.1:{canary.http_port}/exfil",
            "--dns",
            f"127.0.0.1:{canary.dns_port}",
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert exfil.returncode == 0, f"leaky agent failed: {exfil.stderr}"

    def caught(alerts: list[dict]) -> bool:
        http_ok = any(
            a["channel"] == "http"
            and any(m["name"] == "API_KEY" or m["kind"] == "aws" for m in a["matches"])
            for a in alerts
        )
        dns_ok = any(a["channel"] == "dns" and canary.token in a["detail"].lower() for a in alerts)
        return http_ok and dns_ok

    _await_alerts(canary.log, caught, ALERT_TIMEOUT)

    # No raw secret value may ever reach the log or the listener console.
    log_text = canary.log.read_text(encoding="utf-8")
    stdout_text = "".join(canary.stdout)
    for value in canary.secret_values():
        assert value not in log_text, f"secret value leaked into {canary.log}"
        assert value not in stdout_text, "secret value leaked into listener stdout"

    # Offline scan of a transcript that quotes one secret: exit code 1 (found).
    secret = next(s["value"] for s in canary.manifest["secrets"] if s["name"] == "API_KEY")
    transcript = canary.workspace.parent / "transcript.txt"
    transcript.write_text(f"assistant: I will run `export KEY={secret}`\n", encoding="utf-8")
    scanned = _cli(canary.state_dir, "scan", str(transcript))
    assert scanned.returncode == 1, (
        f"scan should flag the secret: {scanned.stdout} {scanned.stderr}"
    )

    # clean removes every planted file.
    cleaned = _cli(canary.state_dir, "clean", canary.token)
    assert cleaned.returncode == 0, cleaned.stderr
    for rel in canary.manifest["files"]:
        assert not (canary.workspace / rel).exists(), f"{rel} survived clean"


def test_aws_cli_style_request_alerts(canary: Canary) -> None:
    config = (canary.workspace / ".aws" / "config").read_text(encoding="utf-8")
    endpoint = next(
        line.split("=", 1)[1].strip()
        for line in config.splitlines()
        if line.strip().startswith("endpoint_url")
    )
    access_key_id = next(
        s["value"] for s in canary.manifest["secrets"] if s["name"] == "aws_access_key_id"
    )
    authorization = (
        f"AWS4-HMAC-SHA256 Credential={access_key_id}/20261105/us-east-1/execute-api/"
        "aws4_request, SignedHeaders=host;x-amz-date, Signature=0"
    )
    request = urllib.request.Request(  # noqa: S310 - localhost listener under test
        endpoint, data=b"{}", method="POST", headers={"Authorization": authorization}
    )
    with urllib.request.urlopen(request, timeout=5) as response:  # noqa: S310
        assert response.status == 200

    def aws_caught(alerts: list[dict]) -> bool:
        return any(
            a["channel"] == "http" and any(m["kind"] == "aws" for m in a["matches"]) for a in alerts
        )

    _await_alerts(canary.log, aws_caught, ALERT_TIMEOUT)
