"""Alert sink: JSON Lines log plus a sanitized one-line console format."""

from __future__ import annotations

import json
import threading
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from agent_canary.models import Alert, Channel, Match

_lock = threading.Lock()


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def make_alert(channel: Channel, source: str, detail: str, matches: Sequence[Match]) -> Alert:
    return Alert(time=now(), channel=channel, source=source, detail=detail, matches=tuple(matches))


def sanitize(text: str, limit: int = 200) -> str:
    """Make attacker-controlled text safe for a terminal: no control chars, bounded length."""
    cleaned = "".join(ch if ch.isprintable() else f"\\x{ord(ch):02x}" for ch in text)
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 3] + "..."


def format_alert(alert: Alert) -> str:
    what = "; ".join(m.describe() for m in alert.matches)
    return sanitize(
        f"[{alert.time}] CANARY {alert.channel.upper()} from {alert.source}: "
        f"{alert.detail} -> {what}",
        limit=500,
    )


def write_alert(alert: Alert, log_path: Path | None) -> None:
    """Append the alert as one JSON line (thread-safe). No-op when log_path is None."""
    if log_path is None:
        return
    line = json.dumps(alert.to_dict(), ensure_ascii=True) + "\n"
    with _lock:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(line)
