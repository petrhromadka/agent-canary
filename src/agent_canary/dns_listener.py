"""DNS canary listener. Placeholder: replaced by the DNS implementer."""

from __future__ import annotations

import socketserver
from collections.abc import Callable

from agent_canary.models import Alert, Manifest


class DnsCanaryServer(socketserver.ThreadingUDPServer):
    def __init__(
        self,
        host: str,
        port: int,
        *,
        answer_ip: str,
        manifests_loader: Callable[[], list[Manifest]],
        on_alert: Callable[[Alert], None],
    ) -> None:
        raise NotImplementedError
