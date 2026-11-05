"""Offline scan of files or stdin. Placeholder: replaced by the scan implementer."""

from __future__ import annotations

from collections.abc import Sequence

from agent_canary.models import Alert, Manifest


def scan_paths(paths: Sequence[str], manifests: Sequence[Manifest]) -> list[Alert]:
    """One Alert per file (or stdin for "-") that contains canaries; directories recurse."""
    raise NotImplementedError
