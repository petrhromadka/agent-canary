"""Data model shared by every module: planted secrets, manifests, matches and alerts."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Channel = Literal["dns", "http", "scan"]


@dataclass(frozen=True)
class Secret:
    """One fake secret value written into a planted file."""

    kind: str  # planter kind that produced it: "aws", "env", "ssh", "npm"
    path: str  # file path relative to the workspace, forward slashes
    name: str  # e.g. "aws_secret_access_key" or "API_KEY"
    value: str


@dataclass(frozen=True)
class Manifest:
    """Record of one `plant` run. Stored outside the workspace so the agent cannot read it."""

    token_id: str  # 12 chars of lowercase base32 (a-z, 2-7): safe as a DNS label
    workspace: str  # absolute path
    created: str  # ISO 8601 UTC
    dns_domain: str | None  # canary hostnames are "<tag>.<token_id>.<dns_domain>"
    http_url: str | None  # canary URLs are "<http_url>/t/<token_id>/<tag>"
    secrets: tuple[Secret, ...] = ()
    files: tuple[str, ...] = ()  # files this run created, relative to workspace
    file_hashes: dict[str, str] = field(default_factory=dict)  # path -> sha256 hex at plant time

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Manifest:
        return cls(
            token_id=data["token_id"],
            workspace=data["workspace"],
            created=data["created"],
            dns_domain=data.get("dns_domain"),
            http_url=data.get("http_url"),
            secrets=tuple(Secret(**s) for s in data.get("secrets", [])),
            files=tuple(data.get("files", [])),
            file_hashes=dict(data.get("file_hashes", {})),
        )


@dataclass(frozen=True)
class Match:
    """A canary found in some observed data."""

    token_id: str
    secret: Secret | None  # None when only the token id (hostname/URL) was seen
    encoding: str  # how it appeared: "plain", "base64", "url", "hex", ...

    def describe(self) -> str:
        """Human description without the secret value."""
        if self.secret is None:
            what = f"token {self.token_id}"
        else:
            what = f"{self.secret.name} from {self.secret.path}"
        return what if self.encoding == "plain" else f"{what} ({self.encoding})"


@dataclass(frozen=True)
class Alert:
    """One detection event. Never carries a secret value, only which secret it was."""

    time: str  # ISO 8601 UTC
    channel: Channel
    source: str  # "ip:port" for listeners, file path or "<stdin>" for scan
    detail: str  # DNS qname, "METHOD /path" for HTTP, line reference for scan
    matches: tuple[Match, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "time": self.time,
            "channel": self.channel,
            "source": self.source,
            "detail": self.detail,
            "matches": [
                {
                    "token_id": m.token_id,
                    "kind": m.secret.kind if m.secret else None,
                    "path": m.secret.path if m.secret else None,
                    "name": m.secret.name if m.secret else None,
                    "encoding": m.encoding,
                }
                for m in self.matches
            ],
        }
