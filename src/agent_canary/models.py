"""Data model shared by every module: planted secrets, manifests, matches and alerts."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Channel = Literal["dns", "http", "scan"]


@dataclass(frozen=True)
class Secret:
    """One fake secret value written into a planted file."""

    kind: str  # planter kind that produced it, one of plant.KINDS
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
    def from_dict(cls, data: Any) -> Manifest:
        """Build from parsed JSON. Raises ValueError unless every field has the expected type."""
        from agent_canary.store import TOKEN_ID_RE

        def text(value: Any, what: str) -> str:
            if not isinstance(value, str) or not value:
                raise ValueError(f"manifest {what} must be a non-empty string")
            return value

        def optional(value: Any, what: str) -> str | None:
            return None if value is None else text(value, what)

        def array(value: Any, what: str) -> list[Any]:
            if not isinstance(value, list):
                raise ValueError(f"manifest {what} must be a list")
            return value

        if not isinstance(data, dict):
            raise ValueError("manifest must be a JSON object")
        token_id = text(data.get("token_id"), "token_id")
        if not TOKEN_ID_RE.match(token_id):
            raise ValueError(f"invalid token id: {token_id!r}")
        secrets = []
        for item in array(data.get("secrets", []), "secrets"):
            if not isinstance(item, dict) or set(item) != {"kind", "path", "name", "value"}:
                raise ValueError("manifest secret must have exactly kind, path, name, value")
            secret = Secret(**{key: text(item[key], f"secret {key}") for key in item})
            if len(secret.value) < 8:
                raise ValueError("manifest secret value must be at least 8 characters")
            secrets.append(secret)
        files = [text(f, "file") for f in array(data.get("files", []), "files")]
        hashes = data.get("file_hashes", {})
        if not isinstance(hashes, dict) or not all(
            isinstance(k, str) and isinstance(v, str) and re.fullmatch("[0-9a-f]{64}", v)
            for k, v in hashes.items()
        ):
            raise ValueError("manifest file_hashes must map paths to sha256 hex digests")
        return cls(
            token_id=token_id,
            workspace=text(data.get("workspace"), "workspace"),
            created=text(data.get("created"), "created"),
            dns_domain=optional(data.get("dns_domain"), "dns_domain"),
            http_url=optional(data.get("http_url"), "http_url"),
            secrets=tuple(secrets),
            files=tuple(files),
            file_hashes=dict(hashes),
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
