"""Command line interface: plant, listen, scan, report, list, clean."""

from __future__ import annotations

import argparse
import contextlib
import json
import signal
import sys
import threading
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from agent_canary import __version__, alerts, notify, store
from agent_canary.models import Alert


def _hostport(value: str) -> tuple[str, int]:
    host, sep, port = value.rpartition(":")
    if not sep or not host or not port.isdigit() or not 0 <= int(port) <= 65535:
        raise argparse.ArgumentTypeError(f"expected HOST:PORT, got {value!r}")
    return host.strip("[]"), int(port)


def _kinds(value: str) -> list[str]:
    from agent_canary.plant import KINDS

    kinds = [k.strip() for k in value.split(",") if k.strip()]
    unknown = sorted(set(kinds) - set(KINDS))
    if unknown or not kinds:
        raise argparse.ArgumentTypeError(f"unknown kinds {unknown}; choose from {list(KINDS)}")
    return kinds


def _argtype[T](parse: Callable[[str], T]) -> Callable[[str], T]:
    """Turn a ValueError from `parse` into an argparse error with the same message."""

    def convert(value: str) -> T:
        try:
            return parse(value)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(str(exc)) from None

    return convert


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-canary",
        description="Plant fake credentials for AI agents and detect when they leave the box.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--state-dir",
        type=Path,
        default=None,
        help="where manifests live (default: $AGENT_CANARY_HOME or ~/.agent-canary); "
        "keep it outside the agent's reach",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("plant", help="write fake credentials into a workspace")
    p.add_argument("workspace", type=Path)
    p.add_argument("--dns-domain", help="domain whose DNS you control, e.g. canary.example.com")
    p.add_argument("--http-url", help="base URL of your listener, e.g. http://203.0.113.5:8080")
    p.add_argument("--kinds", type=_kinds, default=None, help="comma list, default: all")

    p = sub.add_parser("listen", help="run DNS and/or HTTP canary listeners")
    p.add_argument("--http", type=_hostport, metavar="HOST:PORT", help="HTTP listener address")
    p.add_argument("--dns", type=_hostport, metavar="HOST:PORT", help="DNS (UDP) listener address")
    p.add_argument("--answer-ip", default="127.0.0.1", help="A record returned for canary names")
    p.add_argument("--log", type=Path, default=Path("alerts.jsonl"), help="JSON Lines alert log")
    p.add_argument(
        "--webhook",
        action="append",
        default=[],
        type=_argtype(notify.parse_webhook_url),
        metavar="URL",
        help="POST each alert as JSON to this http(s) URL; repeatable",
    )
    p.add_argument(
        "--webhook-header",
        action="append",
        default=[],
        type=_argtype(notify.parse_header),
        metavar="'NAME: VALUE'",
        help="extra header for every webhook request, e.g. for auth; repeatable",
    )
    p.add_argument(
        "--exec",
        action="append",
        default=[],
        type=_argtype(notify.parse_command),
        metavar="CMD",
        help="run CMD (no shell) per alert with the alert JSON on stdin; repeatable",
    )

    p = sub.add_parser("report", help="summarize JSON Lines alert logs per token")
    p.add_argument(
        "logs", nargs="*", type=Path, default=[Path("alerts.jsonl")], help="default: alerts.jsonl"
    )
    p.add_argument("--json", action="store_true", help="machine-readable output")

    p = sub.add_parser("scan", help="search files or stdin (transcripts, proxy logs) for canaries")
    p.add_argument("paths", nargs="*", default=["-"], help="files or directories; '-' is stdin")
    p.add_argument("--log", type=Path, default=None, help="also append alerts to this log")
    p.add_argument(
        "--all", action="store_true", help="also search .git, .venv and node_modules directories"
    )

    sub.add_parser("list", help="show planted canaries")

    p = sub.add_parser("clean", help="remove planted files and forget the canary")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("token_id", nargs="?")
    g.add_argument("--all", action="store_true")
    return parser


def _cmd_plant(args: argparse.Namespace, state_dir: Path) -> int:
    from agent_canary.plant import KINDS, plant

    try:
        manifest, warnings = plant(
            args.workspace,
            kinds=args.kinds or list(KINDS),
            dns_domain=args.dns_domain,
            http_url=args.http_url,
            state_dir=state_dir,
        )
    except (ValueError, OSError) as exc:
        print(f"error: {alerts.sanitize(str(exc), limit=1000)}", file=sys.stderr)
        return 2
    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)
    print(f"token {manifest.token_id}: planted {len(manifest.files)} files in {manifest.workspace}")
    for path in manifest.files:
        print(f"  {path}")
    return 0


def _cmd_listen(args: argparse.Namespace, state_dir: Path) -> int:
    from agent_canary.dns_listener import DnsCanaryServer
    from agent_canary.http_listener import HttpCanaryServer

    if args.http is None and args.dns is None:
        args.http = ("127.0.0.1", 8080)
    if args.webhook_header and not args.webhook:
        print("error: --webhook-header needs --webhook", file=sys.stderr)
        return 2

    loader = store.CachedLoader(state_dir)  # one per process: rereads only changed manifests
    notifier = None
    if args.webhook or args.exec:
        notifier = notify.Notifier(args.webhook, args.webhook_header, args.exec)

    def on_alert(alert: Alert) -> None:
        # Console first, so a failing log (disk full, permissions) cannot swallow the alert.
        print(alerts.format_alert(alert), flush=True)
        try:
            alerts.write_alert(alert, args.log)
        except Exception as exc:
            print(f"error: alert log write failed: {type(exc).__name__}", file=sys.stderr)
        if notifier is not None:
            notifier.submit(alert)

    try:  # create the log now, so `report` on a run without alerts finds an empty log
        alerts.touch_log(args.log)
    except OSError as exc:
        print(f"error: alert log write failed: {type(exc).__name__}", file=sys.stderr)

    servers = []
    if args.http is not None:
        http = HttpCanaryServer(*args.http, manifests_loader=loader, on_alert=on_alert)
        servers.append(("http", http))
    if args.dns is not None:
        dns = DnsCanaryServer(
            *args.dns, answer_ip=args.answer_ip, manifests_loader=loader, on_alert=on_alert
        )
        servers.append(("dns", dns))

    stop = threading.Event()
    previous = _on_stop_signals(stop)
    threads = []
    for name, server in servers:
        host, port = server.server_address[:2]
        print(f"listening {name} on {host}:{port}", flush=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        threads.append(thread)
    print(f"alerts -> {args.log}", flush=True)
    for hook in args.webhook:
        print(f"webhook -> {alerts.sanitize(urlsplit(hook).hostname or '')}", flush=True)
    try:
        # A short wait, not join(): signal handlers run only between waits, also on Windows.
        while not stop.wait(0.2) and any(t.is_alive() for t in threads):
            pass
    except KeyboardInterrupt:
        pass
    finally:
        for _, server in servers:
            server.shutdown()
            server.server_close()
        if notifier is not None:
            if not notifier.close():
                print("warning: notifications still pending at exit were dropped", file=sys.stderr)
            if notifier.dropped:
                print(
                    f"warning: {notifier.dropped} alerts not notified (queue full)",
                    file=sys.stderr,
                )
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    return 0


def _on_stop_signals(stop: threading.Event) -> dict[int, Any]:
    """Set `stop` on SIGINT, SIGTERM and (Windows) SIGBREAK where the platform allows it.
    Returns the handlers it replaced."""
    previous: dict[int, Any] = {}
    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        signum = getattr(signal, name, None)
        if signum is None:
            continue
        with contextlib.suppress(ValueError, OSError):  # not the main thread, or unsupported
            previous[signum] = signal.signal(signum, lambda *_: stop.set())
    return previous


def _cmd_report(args: argparse.Namespace, _: Path) -> int:
    from agent_canary.report import Report, plural

    result = Report()
    failed = False
    for path in args.logs:
        try:
            with path.open(encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    result.add_line(line)
        except OSError as exc:
            reason = exc.strerror or type(exc).__name__
            print(f"error: {alerts.sanitize(str(path))}: {reason}", file=sys.stderr)
            failed = True
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(result.to_text())
    if result.malformed:
        skipped = plural(result.malformed, "malformed line")
        print(f"warning: {skipped} skipped", file=sys.stderr)
    if failed:
        return 2
    return 1 if result.alerts else 0


def _cmd_scan(args: argparse.Namespace, state_dir: Path) -> int:
    from agent_canary.scan import scan_paths

    manifests = store.load_all(state_dir)
    if not manifests:
        print("error: no planted canaries in the state dir", file=sys.stderr)
        return 2
    result = scan_paths(args.paths, manifests, all_dirs=args.all)
    for alert in result.alerts:
        alerts.write_alert(alert, args.log)
        print(alerts.format_alert(alert))
    if not result.alerts and not result.errors:
        print("no canaries found")
    for path, reason in result.errors:
        print(f"error: {alerts.sanitize(path)}: {reason}", file=sys.stderr)
    if summary := result.skipped_summary():
        print(summary, file=sys.stderr)
    if result.errors:
        return 2
    return 1 if result.alerts else 0


def _cmd_list(_: argparse.Namespace, state_dir: Path) -> int:
    manifests = store.load_all(state_dir)
    if not manifests:
        print("no planted canaries")
    for m in manifests:  # manifest text is untrusted: the state dir may have been tampered with
        print(alerts.sanitize(f"{m.token_id}  {m.created}  {len(m.files)} files  {m.workspace}"))
    return 0


def _cmd_clean(args: argparse.Namespace, state_dir: Path) -> int:
    from agent_canary.plant import clean

    if args.all:
        targets = store.load_all(state_dir)
    else:
        try:
            targets = [store.load(args.token_id, state_dir)]
        except (ValueError, OSError) as exc:
            print(f"error: {alerts.sanitize(str(exc))}", file=sys.stderr)
            return 2
    for manifest in targets:
        try:
            warnings = clean(manifest, state_dir)
        except (ValueError, OSError) as exc:
            print(f"error: {alerts.sanitize(str(exc))}", file=sys.stderr)
            return 2
        for warning in warnings:
            print(f"warning: {alerts.sanitize(warning)}", file=sys.stderr)
        print(f"cleaned {manifest.token_id}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    state_dir = args.state_dir or store.default_state_dir()
    commands = {
        "plant": _cmd_plant,
        "listen": _cmd_listen,
        "scan": _cmd_scan,
        "report": _cmd_report,
        "list": _cmd_list,
        "clean": _cmd_clean,
    }
    return commands[args.command](args, state_dir)
