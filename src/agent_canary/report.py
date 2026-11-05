"""Summarize JSON Lines alert logs per token."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from agent_canary.alerts import sanitize

TEXT_SOURCES_SHOWN = 10


@dataclass
class TokenSummary:
    first_seen: str
    last_seen: str
    alerts: int = 0
    channels: Counter[str] = field(default_factory=Counter)
    secrets: set[tuple[str, str]] = field(default_factory=set)  # (name, path)
    encodings: set[str] = field(default_factory=set)
    sources: set[str] = field(default_factory=set)

    def to_dict(self) -> dict[str, Any]:
        return {
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "alerts": self.alerts,
            "channels": dict(sorted(self.channels.items())),
            "secrets": [{"name": n, "path": p} for n, p in sorted(self.secrets)],
            "encodings": sorted(self.encodings),
            "sources": sorted(self.sources),
        }


@dataclass
class Report:
    alerts: int = 0
    malformed: int = 0
    tokens: dict[str, TokenSummary] = field(default_factory=dict)

    def add_line(self, line: str) -> None:
        if not line.strip():
            return
        alert = _parse(line)
        if alert is None:
            self.malformed += 1
            return
        self.alerts += 1
        when, channel, source, matches = alert
        for token in dict.fromkeys(m["token_id"] for m in matches):
            summary = self.tokens.setdefault(token, TokenSummary(when, when))
            summary.first_seen = min(summary.first_seen, when)
            summary.last_seen = max(summary.last_seen, when)
            summary.alerts += 1
            summary.channels[channel] += 1
            summary.sources.add(source)
        for m in matches:
            summary = self.tokens[m["token_id"]]
            summary.encodings.add(m["encoding"])
            if m["name"] is not None:
                summary.secrets.add((m["name"], m["path"] or ""))

    def to_dict(self) -> dict[str, Any]:
        return {
            "alerts": self.alerts,
            "malformed_lines": self.malformed,
            "tokens": {t: s.to_dict() for t, s in sorted(self.tokens.items())},
        }

    def to_text(self) -> str:
        lines = []
        for token, s in sorted(self.tokens.items()):
            channels = ", ".join(f"{c} {n}" for c, n in sorted(s.channels.items()))
            lines.append(
                f"token {token}: {plural(s.alerts, 'alert')} ({channels}), "
                f"first {s.first_seen}, last {s.last_seen}"
            )
            if s.secrets:
                secrets = ", ".join(f"{n} ({p})" for n, p in sorted(s.secrets))
                lines.append(f"  secrets: {secrets}")
            lines.append(f"  encodings: {', '.join(sorted(s.encodings))}")
            sources = sorted(s.sources)
            shown = ", ".join(sources[:TEXT_SOURCES_SHOWN])
            more = len(sources) - TEXT_SOURCES_SHOWN
            lines.append(
                f"  sources ({len(sources)}): {shown}" + (f", +{more} more" if more > 0 else "")
            )
        lines.append(
            f"{plural(self.alerts, 'alert')}, {plural(len(self.tokens), 'token')}"
            if self.alerts
            else "no alerts"
        )
        # The log is written by the listener but may be edited by anyone: escape everything.
        return "\n".join(sanitize(line, limit=2000) for line in lines)


def plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _parse(line: str) -> tuple[str, str, str, list[dict[str, Any]]] | None:
    """Return (time, channel, source, matches) for a well-formed alert line, else None."""
    try:
        data = json.loads(line)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    when, channel, source, matches = (data.get(k) for k in ("time", "channel", "source", "matches"))
    if not (_text(when) and _text(channel) and isinstance(source, str)):
        return None
    if not isinstance(matches, list) or not matches:
        return None
    for m in matches:
        if not isinstance(m, dict) or not _text(m.get("token_id")) or not _text(m.get("encoding")):
            return None
        if not all(m.get(k) is None or isinstance(m.get(k), str) for k in ("name", "path")):
            return None
    return when, channel, source, matches
