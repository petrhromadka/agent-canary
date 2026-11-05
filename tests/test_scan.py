import base64
import io
import sys
from types import SimpleNamespace

from agent_canary import scan, store
from agent_canary.cli import main
from agent_canary.models import Manifest, Secret

CANARY = "abcdefgh2345"
VALUE = "test-value-1-abcdef"


def manifest(workspace) -> Manifest:
    return Manifest(
        token_id=CANARY,
        workspace=str(workspace),
        created="2026-11-05T00:00:00+00:00",
        dns_domain=None,
        http_url=None,
        secrets=(Secret("env", ".env", "API_KEY", VALUE),),
        files=(".env",),
    )


def test_scan_dir_reports_line_and_skips_planted_file(tmp_path):
    (tmp_path / ".env").write_text(f"API_KEY={VALUE}\n")
    logs = tmp_path / "logs"
    logs.mkdir()
    encoded = base64.b64encode(VALUE.encode()).decode()
    (logs / "transcript.jsonl").write_text(f"one\ntwo\ncurl -d {VALUE} x\n{encoded}\n")
    (logs / "clean.txt").write_text("nothing\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.js").write_text(VALUE)

    [alert] = scan.scan_paths([str(tmp_path)], [manifest(tmp_path)])

    assert alert.source == str(logs / "transcript.jsonl")
    assert alert.detail == "line 3"
    assert [(m.secret.name, m.encoding) for m in alert.matches if m.secret] == [
        ("API_KEY", "plain")
    ]


def test_match_on_chunk_boundary(tmp_path, monkeypatch):
    monkeypatch.setattr(scan, "CHUNK_SIZE", 64)
    path = tmp_path / "dump.bin"
    path.write_bytes(b"a\n" * 27 + VALUE.encode() + b"\n" + b"z" * 200)  # straddles byte 64

    [alert] = scan.scan_paths([str(path)], [manifest(tmp_path / "ws")])

    assert alert.detail == "line 28"


def test_stdin_and_cli_exit_codes(tmp_path, monkeypatch, capsys):
    state = tmp_path / "state"
    store.save(manifest(tmp_path / "ws"), state)
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(f"{CANARY}.x".encode())))
    [alert] = scan.scan_paths(["-"], store.load_all(state))
    assert (alert.source, alert.matches[0].secret) == ("<stdin>", None)

    leak = tmp_path / "leak.txt"
    leak.write_text(VALUE)
    clean = tmp_path / "clean.txt"
    clean.write_text("nothing")
    assert main(["--state-dir", str(state), "scan", str(leak)]) == 1
    assert VALUE not in capsys.readouterr().out
    assert main(["--state-dir", str(state), "scan", str(clean)]) == 0
    assert main(["--state-dir", str(state), "scan", str(tmp_path / "missing")]) == 2
