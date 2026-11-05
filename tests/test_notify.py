"""Webhook and --exec notifications, delivered by `listen` without slowing the listeners."""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass, field
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from agent_canary import alerts, cli, notify
from agent_canary.models import Match, Secret

TIMEOUT = 10.0


@dataclass
class Receiver:
    """A local webhook target that records requests and answers with `status`."""

    status: int = 200
    location: str | None = None
    release: threading.Event = field(default_factory=threading.Event)  # set: answer at once
    requests: list[tuple[str, Message, bytes]] = field(default_factory=list)
    url: str = ""

    def __post_init__(self) -> None:
        self.release.set()

    def wait_for(self, count: int) -> None:
        end = time.monotonic() + TIMEOUT
        while len(self.requests) < count:
            assert time.monotonic() < end, f"receiver got {len(self.requests)} of {count}"
            time.sleep(0.02)


@pytest.fixture
def receiver_factory() -> Iterator[object]:
    servers: list[tuple[ThreadingHTTPServer, Receiver]] = []

    def make(**kwargs: object) -> Receiver:
        rec = Receiver(**kwargs)  # type: ignore[arg-type]

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                rec.requests.append((self.path, self.headers, body))
                rec.release.wait(TIMEOUT)
                self.send_response(rec.status)
                if rec.location:
                    self.send_header("Location", rec.location)
                self.send_header("Content-Length", "0")
                self.end_headers()

            do_GET = do_POST  # a followed 302 turns the POST into a GET

            def log_message(self, *args: object) -> None:
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        rec.url = f"http://127.0.0.1:{server.server_address[1]}"
        servers.append((server, rec))
        return rec

    yield make
    for server, rec in servers:
        rec.release.set()
        server.shutdown()
        server.server_close()


def _alert(token: str = "aaaabbbbcccc") -> alerts.Alert:
    secret = Secret("env", ".env", "API_KEY", "x" * 32)
    return alerts.make_alert("http", "127.0.0.1:1", "POST /up", [Match(token, secret, "base64")])


def _start_listen(state: Path, log: Path, *extra: str) -> tuple[subprocess.Popen[str], int]:
    cmd = [sys.executable, "-m", "agent_canary", "--state-dir", str(state), "listen"]
    proc = subprocess.Popen(
        [*cmd, "--http", "127.0.0.1:0", "--log", str(log), *extra],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        bufsize=1,
    )
    assert proc.stdout is not None
    for line in proc.stdout:
        if m := re.match(r"listening http on 127\.0\.0\.1:(\d+)", line):
            return proc, int(m.group(1))
    raise AssertionError(f"listener did not start: {proc.stderr.read() if proc.stderr else ''}")


def _plant(tmp_path: Path) -> tuple[Path, list[str]]:
    state, workspace = tmp_path / "state", tmp_path / "ws"
    workspace.mkdir()
    assert cli.main(["--state-dir", str(state), "plant", str(workspace), "--kinds", "env"]) == 0
    (manifest,) = state.glob("*.json")
    values = [s["value"] for s in json.loads(manifest.read_text(encoding="utf-8"))["secrets"]]
    return state, values


def _stop(proc: subprocess.Popen[str]) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=TIMEOUT)
    for pipe in (proc.stdout, proc.stderr):
        if pipe is not None:
            pipe.close()


def test_listen_posts_webhook_and_runs_exec_without_secret_values(tmp_path, receiver_factory):
    state, values = _plant(tmp_path)
    log, exec_out = tmp_path / "alerts.jsonl", tmp_path / "exec.json"
    failing, good = receiver_factory(status=500), receiver_factory()
    write_stdin = "import sys; open(sys.argv[1], 'wb').write(sys.stdin.buffer.read())"
    proc, port = _start_listen(
        state,
        log,
        # A dead webhook first: it must not stop the log, the second webhook or --exec.
        "--webhook",
        f"{failing.url}/hook/pathtoken?k=querytoken",
        "--webhook",
        f"{good.url}/hook",
        "--webhook-header",
        "X-Auth: headertoken",
        "--exec",
        f'"{sys.executable}" -c "{write_stdin}" "{exec_out}"',
    )
    try:
        request = urllib.request.Request(
            f"http://127.0.0.1:{port}/up", data=f"key={values[0]}".encode(), method="POST"
        )
        urllib.request.urlopen(request, timeout=TIMEOUT).close()  # noqa: S310
        good.wait_for(1)
        end = time.monotonic() + TIMEOUT
        while not (exec_out.exists() and exec_out.stat().st_size):
            assert time.monotonic() < end, "--exec command got no alert"
            time.sleep(0.05)
    finally:
        _stop(proc)

    path, headers, body = good.requests[0]
    assert path == "/hook"
    assert headers["X-Auth"] == "headertoken"
    assert headers["Content-Type"] == "application/json"
    sent = json.loads(body)
    logged = json.loads(log.read_text(encoding="utf-8").splitlines()[0])
    assert {k: v for k, v in sent.items() if k not in ("text", "content")} == logged
    assert sent["text"] == sent["content"]
    assert "CANARY HTTP from 127.0.0.1:" in sent["text"]
    assert json.loads(exec_out.read_bytes()) == sent
    for value in values:
        assert value not in body.decode(), "secret value in webhook payload"
    assert len(failing.requests) == 3


def test_failing_webhook_reports_host_only_and_does_not_block_others(receiver_factory, capsys):
    target = receiver_factory()
    redirect = receiver_factory(status=302, location=f"{target.url}/elsewhere")
    good = receiver_factory()
    notifier = notify.Notifier(
        [f"{redirect.url}/hook/pathtoken?k=querytoken", good.url], backoff=0.01
    )
    notifier.submit(_alert())
    good.wait_for(1)
    assert notifier.close(timeout=TIMEOUT)

    assert len(redirect.requests) == 3  # one try plus two retries
    assert target.requests == []  # the redirect was not followed
    err = capsys.readouterr().err
    assert "error: webhook 127.0.0.1 failed: HTTPError" in err
    assert "pathtoken" not in err
    assert "querytoken" not in err


def test_full_queue_drops_without_blocking(receiver_factory):
    slow = receiver_factory()
    slow.release.clear()  # hold every request until teardown
    notifier = notify.Notifier([slow.url], queue_size=2)
    start = time.monotonic()
    for _ in range(50):
        notifier.submit(_alert())
    assert time.monotonic() - start < 0.5
    assert notifier.dropped >= 47  # at most one in flight and two queued
    slow.release.set()
    assert notifier.close(timeout=TIMEOUT)


@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("--webhook", "ftp://127.0.0.1/hook"),
        ("--webhook", "file:///etc/passwd"),
        ("--webhook", "https:///no-host"),
        ("--webhook", "https://user:headertoken@127.0.0.1/hook"),
        ("--webhook-header", "X-Auth headertoken"),
        ("--exec", '"unterminated'),
    ],
)
def test_listen_rejects_bad_notification_options(tmp_path, capsys, option, value):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--state-dir", str(tmp_path), "listen", option, value])
    assert exc.value.code == 2
    assert "headertoken" not in capsys.readouterr().err


@pytest.mark.skipif(os.name == "nt", reason="SIGTERM cannot be delivered to a process on Windows")
def test_sigterm_flushes_webhook_queue_and_exits_zero(tmp_path, receiver_factory):
    state, values = _plant(tmp_path)
    slow = receiver_factory()
    slow.release.clear()
    proc, port = _start_listen(state, tmp_path / "alerts.jsonl", "--webhook", slow.url)
    try:
        request = urllib.request.Request(
            f"http://127.0.0.1:{port}/up", data=values[0].encode(), method="POST"
        )
        urllib.request.urlopen(request, timeout=TIMEOUT).close()  # noqa: S310
        slow.wait_for(1)  # delivery is in flight and held by the receiver
        proc.send_signal(signal.SIGTERM)
        threading.Timer(1.0, slow.release.set).start()
        assert proc.wait(timeout=TIMEOUT) == 0
        assert len(slow.requests) == 1
    finally:
        _stop(proc)
