"""Find planted canaries (token ids and secret values) in arbitrary observed data."""

from __future__ import annotations

from collections.abc import Sequence

from agent_canary.models import Manifest, Match


def find_matches(data: bytes | str, manifests: Sequence[Manifest]) -> list[Match]:
    """Every canary that appears in `data`, at most one Match per (token, secret, encoding).

    A token id alone (seen in a hostname or URL) yields a Match with secret=None; it is
    dropped when a secret of the same token was also found in the same data.
    """
    text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
    lowered = text.lower()
    matches: list[Match] = []
    for manifest in manifests:
        found = [Match(manifest.token_id, s, "plain") for s in manifest.secrets if s.value in text]
        if not found and manifest.token_id in lowered:
            found = [Match(manifest.token_id, None, "plain")]
        matches.extend(found)
    return matches
