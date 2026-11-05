"""Plant fake credentials into a workspace. Placeholder: replaced by the plant implementer."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from agent_canary.models import Manifest

KINDS: tuple[str, ...] = ("aws", "env", "ssh", "npm")


def plant(
    workspace: Path,
    *,
    kinds: Sequence[str] = KINDS,
    dns_domain: str | None = None,
    http_url: str | None = None,
    state_dir: Path,
) -> tuple[Manifest, list[str]]:
    """Write canary files, save the manifest to state_dir. Returns (manifest, warnings)."""
    raise NotImplementedError


def clean(manifest: Manifest, state_dir: Path) -> list[str]:
    """Remove the files this manifest created and the manifest itself. Returns warnings."""
    raise NotImplementedError
