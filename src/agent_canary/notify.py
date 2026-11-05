"""Alert notifications: webhook POSTs and local commands, delivered off the listener threads."""

from __future__ import annotations

import contextlib
import json
import os
import queue
import shlex
import subprocess
import sys
import threading
import time
import urllib.request
from dataclasses import dataclass
from pathlib import PurePath
from typing import Any
from urllib.parse import urlsplit

from agent_canary import alerts
from agent_canary.models import Alert

QUEUE_SIZE = 100
WEBHOOK_TIMEOUT = 5.0
WEBHOOK_RETRIES = 2
BACKOFF_SECONDS = 1.0  # doubled after each failed attempt
EXEC_TIMEOUT = 10.0
FLUSH_SECONDS = 5.0

_HEADER_NAME_CHARS = frozenset(
    "!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)


def parse_webhook_url(value: str) -> str:
    """Accept only absolute http(s) URLs with a host. Raises ValueError otherwise."""
    try:
        parts = urlsplit(value)
        host = parts.hostname
        parts.port  # noqa: B018 - raises ValueError on a malformed port
    except ValueError:
        raise ValueError("webhook URL is malformed") from None
    if parts.scheme not in ("http", "https") or not host:
        raise ValueError("webhook URL must be http:// or https:// with a host")
    if "@" in parts.netloc:
        raise ValueError("webhook URL must not hold credentials; use --webhook-header")
    return value


def parse_header(value: str) -> tuple[str, str]:
    """Parse 'Name: value'. Error messages never include the value (it may be a token)."""
    name, sep, content = value.partition(":")
    name, content = name.strip(), content.strip()
    if not sep or not name or not set(name) <= _HEADER_NAME_CHARS:
        raise ValueError("webhook header must look like 'Name: value'")
    if any(ch in content for ch in "\r\n\0"):
        raise ValueError(f"webhook header {name} value contains a line break or NUL")
    return name, content


def parse_command(value: str) -> list[str]:
    """Split a command line without a shell. Windows paths keep their backslashes."""
    if os.name == "nt":
        parts = [
            p[1:-1] if len(p) >= 2 and p[0] == p[-1] == '"' else p
            for p in shlex.split(value, posix=False)
        ]
    else:
        parts = shlex.split(value)
    if not parts:
        raise ValueError("exec command is empty")
    return parts


def payload(alert: Alert) -> dict[str, Any]:
    """The log line's dict plus the console line as `text` (Slack, Mattermost) and `content`
    (Discord). Neither carries a secret value: Alert never holds one."""
    line = alerts.format_alert(alert)
    return {**alert.to_dict(), "text": line, "content": line}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None  # urllib then raises HTTPError for the 3xx response


_opener = urllib.request.build_opener(_NoRedirect)


@dataclass(frozen=True)
class _Webhook:
    url: str
    host: str


class Notifier:
    """Queues alerts and delivers them in one daemon thread; `submit` never blocks."""

    def __init__(
        self,
        webhooks: list[str],
        headers: list[tuple[str, str]] | None = None,
        commands: list[list[str]] | None = None,
        *,
        queue_size: int = QUEUE_SIZE,
        timeout: float = WEBHOOK_TIMEOUT,
        retries: int = WEBHOOK_RETRIES,
        backoff: float = BACKOFF_SECONDS,
        exec_timeout: float = EXEC_TIMEOUT,
    ) -> None:
        self._webhooks = [_Webhook(u, urlsplit(u).hostname or "?") for u in webhooks]
        self._headers = {"Content-Type": "application/json", "User-Agent": "agent-canary"}
        self._headers.update(dict(headers or []))
        self._commands = list(commands or [])
        self._timeout = timeout
        self._retries = retries
        self._backoff = backoff
        self._exec_timeout = exec_timeout
        self._queue: queue.Queue[Alert | None] = queue.Queue(maxsize=queue_size)
        self._abort = threading.Event()
        self._lock = threading.Lock()
        self.dropped = 0
        self._thread = threading.Thread(target=self._run, name="agent-canary-notify", daemon=True)
        self._thread.start()

    def submit(self, alert: Alert) -> None:
        try:
            self._queue.put_nowait(alert)
        except queue.Full:
            with self._lock:
                self.dropped += 1
                first = self.dropped == 1
            if first:
                print("warning: notification queue full, dropping alerts", file=sys.stderr)

    def close(self, timeout: float = FLUSH_SECONDS) -> bool:
        """Deliver what is queued for up to `timeout` seconds. True when everything was sent."""
        deadline = time.monotonic() + timeout
        with contextlib.suppress(queue.Full):
            self._queue.put(None, timeout=timeout)
        self._thread.join(max(0.0, deadline - time.monotonic()))
        self._abort.set()
        return not self._thread.is_alive()

    def _run(self) -> None:
        while (alert := self._queue.get()) is not None:
            if self._abort.is_set():
                return
            body = json.dumps(payload(alert), ensure_ascii=True).encode("ascii")
            for hook in self._webhooks:
                self._post(hook, body)
            for command in self._commands:
                self._exec(command, body)

    def _post(self, hook: _Webhook, body: bytes) -> None:
        delay = self._backoff
        for attempt in range(self._retries + 1):
            request = urllib.request.Request(  # noqa: S310 - scheme checked by parse_webhook_url
                hook.url, data=body, headers=self._headers, method="POST"
            )
            try:
                with _opener.open(request, timeout=self._timeout) as response:
                    response.read(65536)
                return
            except Exception as exc:
                if attempt == self._retries or self._abort.wait(delay):
                    # Only the host: the path or query may hold a token.
                    host = alerts.sanitize(hook.host)
                    print(f"error: webhook {host} failed: {type(exc).__name__}", file=sys.stderr)
                    return
                delay *= 2

    def _exec(self, command: list[str], body: bytes) -> None:
        name = alerts.sanitize(PurePath(command[0]).name)  # arguments may hold a token
        try:
            result = subprocess.run(
                command,
                input=body + b"\n",  # line-oriented tools (logger, tee) want a newline
                timeout=self._exec_timeout,
                stdout=subprocess.DEVNULL,
                check=False,
            )
        except Exception as exc:
            print(f"error: exec {name} failed: {type(exc).__name__}", file=sys.stderr)
            return
        if result.returncode != 0:
            print(f"error: exec {name} exited with {result.returncode}", file=sys.stderr)
