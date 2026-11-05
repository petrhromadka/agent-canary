"""HTTP canary listener. Placeholder: replaced by the HTTP implementer."""

from __future__ import annotations

from collections.abc import Callable
from http.server import ThreadingHTTPServer

from agent_canary.models import Alert, Manifest


class HttpCanaryServer(ThreadingHTTPServer):
    def __init__(
        self,
        host: str,
        port: int,
        *,
        manifests_loader: Callable[[], list[Manifest]],
        on_alert: Callable[[Alert], None],
    ) -> None:
        raise NotImplementedError
