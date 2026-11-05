"""Manifest storage: one JSON file per token id in a state directory outside the workspace."""

from __future__ import annotations

import contextlib
import json
import os
import re
import tempfile
from pathlib import Path

from agent_canary.models import Manifest

TOKEN_ID_RE = re.compile(r"\A[a-z2-7]{12}\Z")


def default_state_dir() -> Path:
    """$AGENT_CANARY_HOME, else ~/.agent-canary."""
    env = os.environ.get("AGENT_CANARY_HOME")
    return Path(env) if env else Path.home() / ".agent-canary"


def _path(state_dir: Path, token_id: str) -> Path:
    if not TOKEN_ID_RE.match(token_id):
        raise ValueError(f"invalid token id: {token_id!r}")
    return state_dir / f"{token_id}.json"


def save(manifest: Manifest, state_dir: Path) -> Path:
    """Write the manifest atomically, readable only by the owner (POSIX modes)."""
    path = _path(state_dir, manifest.token_id)
    try:
        state_dir.mkdir(parents=True, mode=0o700)
    except FileExistsError:
        pass
    else:
        with contextlib.suppress(OSError):  # mkdir's mode is masked by the umask
            state_dir.chmod(0o700)
    data = (json.dumps(manifest.to_dict(), indent=2) + "\n").encode("utf-8")
    fd, tmp = tempfile.mkstemp(dir=state_dir, prefix=f".{manifest.token_id}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        Path(tmp).replace(path)
    except BaseException:
        with contextlib.suppress(OSError):
            Path(tmp).unlink()
        raise
    return path


def _read(path: Path) -> Manifest:
    try:
        manifest = Manifest.from_dict(json.loads(path.read_text(encoding="utf-8")))
    except RecursionError as exc:
        raise ValueError(f"{path.name}: JSON nested too deeply") from exc
    if manifest.token_id != path.stem:
        raise ValueError(f"{path.name} holds token id {manifest.token_id}")
    return manifest


def load(token_id: str, state_dir: Path) -> Manifest:
    return _read(_path(state_dir, token_id))


def load_all(state_dir: Path) -> list[Manifest]:
    """All valid manifests, oldest first. Unreadable or invalid files are skipped."""
    if not state_dir.is_dir():
        return []
    manifests = []
    for path in sorted(state_dir.glob("*.json")):
        if not TOKEN_ID_RE.match(path.stem):
            continue
        with contextlib.suppress(OSError, ValueError):
            manifests.append(_read(path))
    return sorted(manifests, key=lambda m: (m.created, m.token_id))


def remove(token_id: str, state_dir: Path) -> None:
    _path(state_dir, token_id).unlink(missing_ok=True)
