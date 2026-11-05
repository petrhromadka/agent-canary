"""Manifest storage: one JSON file per token id in a state directory outside the workspace."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from agent_canary.models import Manifest

TOKEN_ID_RE = re.compile(r"^[a-z2-7]{12}$")


def default_state_dir() -> Path:
    """$AGENT_CANARY_HOME, else ~/.agent-canary."""
    env = os.environ.get("AGENT_CANARY_HOME")
    return Path(env) if env else Path.home() / ".agent-canary"


def _path(state_dir: Path, token_id: str) -> Path:
    if not TOKEN_ID_RE.match(token_id):
        raise ValueError(f"invalid token id: {token_id!r}")
    return state_dir / f"{token_id}.json"


def save(manifest: Manifest, state_dir: Path) -> Path:
    state_dir.mkdir(parents=True, exist_ok=True)
    path = _path(state_dir, manifest.token_id)
    path.write_text(json.dumps(manifest.to_dict(), indent=2) + "\n", encoding="utf-8")
    return path


def load(token_id: str, state_dir: Path) -> Manifest:
    path = _path(state_dir, token_id)
    return Manifest.from_dict(json.loads(path.read_text(encoding="utf-8")))


def load_all(state_dir: Path) -> list[Manifest]:
    """All manifests, oldest first. Unreadable files are skipped."""
    if not state_dir.is_dir():
        return []
    manifests = []
    for path in sorted(state_dir.glob("*.json")):
        if not TOKEN_ID_RE.match(path.stem):
            continue
        try:
            manifests.append(Manifest.from_dict(json.loads(path.read_text(encoding="utf-8"))))
        except (OSError, ValueError, KeyError, TypeError):
            continue
    return sorted(manifests, key=lambda m: m.created)


def remove(token_id: str, state_dir: Path) -> None:
    _path(state_dir, token_id).unlink(missing_ok=True)
