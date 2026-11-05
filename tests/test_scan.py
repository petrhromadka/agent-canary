import base64
import io
import os
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

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

    result = scan.scan_paths([str(tmp_path)], [manifest(tmp_path)])

    [alert] = result.alerts
    assert result.skipped_summary() == "skipped: 1 planted decoy, 1 dir (node_modules)"
    assert alert.source == str(logs / "transcript.jsonl")
    assert alert.detail == "line 3"
    assert [(m.secret.name, m.encoding) for m in alert.matches if m.secret] == [
        ("API_KEY", "plain")
    ]
    assert len(scan.scan_paths([str(tmp_path)], [manifest(tmp_path)], all_dirs=True).alerts) == 2


def test_match_on_chunk_boundary(tmp_path, monkeypatch):
    monkeypatch.setattr(scan, "CHUNK_SIZE", 64)
    path = tmp_path / "dump.bin"
    path.write_bytes(b"a\n" * 27 + VALUE.encode() + b"\n" + b"z" * 200)  # straddles byte 64

    ms = [manifest(tmp_path / "ws")]

    [alert] = scan.scan_paths([str(path)], ms).alerts

    assert alert.detail == "line 28"
    # A token id glued to letters is no match, also when a window ends or starts right at it;
    # the third window starts where the second one's overlap begins.
    third = 2 * 64 - scan.max_pattern_len(ms)
    for before in (64 - len(CANARY), third):
        for glue, want in ((b"x", []), (b".", [CANARY])):
            blob = b"." * (before - 1) + glue + CANARY.encode() + glue + b"." * 300
            matches, _ = scan._scan_stream(io.BytesIO(blob), ms)
            assert [m.token_id for m in matches] == want


def test_stdin_and_cli_exit_codes(tmp_path, monkeypatch, capsys):
    state = tmp_path / "state"
    store.save(manifest(tmp_path / "ws"), state)
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(f"{CANARY}.x".encode())))
    [alert] = scan.scan_paths(["-"], store.load_all(state)).alerts
    assert (alert.source, alert.matches[0].secret) == ("<stdin>", None)

    leak = tmp_path / "leak.txt"
    leak.write_text(VALUE)
    clean = tmp_path / "clean.txt"
    clean.write_text("nothing")
    assert main(["--state-dir", str(state), "scan", str(leak)]) == 1
    assert VALUE not in capsys.readouterr().out
    assert main(["--state-dir", str(state), "scan", str(clean)]) == 0
    assert main(["--state-dir", str(state), "scan", str(tmp_path / "missing")]) == 2


def _deny_read(path, request) -> None:
    """Make `path` unreadable for the current user until the test ends."""
    if os.name == "nt":
        user = os.environ["USERNAME"]
        icacls = ["icacls", str(path)]
        subprocess.run([*icacls, "/deny", f"{user}:(RD)"], check=True, capture_output=True)
        request.addfinalizer(
            lambda: subprocess.run([*icacls, "/remove:d", user], check=True, capture_output=True)
        )
    else:
        mode = path.stat().st_mode
        path.chmod(0)
        request.addfinalizer(lambda: path.chmod(mode))
    try:
        path.read_bytes() if path.is_file() else list(path.iterdir())
    except PermissionError:
        return
    pytest.skip("permissions are not enforced for this user")


def test_unreadable_paths_are_errors(tmp_path, capsys, request):
    state = tmp_path / "state"
    store.save(manifest(tmp_path / "ws"), state)
    logs = tmp_path / "logs"
    (logs / "hidden").mkdir(parents=True)
    (logs / "leak.txt").write_text(VALUE)
    (logs / "hidden" / "t.txt").write_text(VALUE)
    _deny_read(logs / "hidden", request)
    locked = tmp_path / "locked.txt"
    locked.write_text(VALUE)
    _deny_read(locked, request)

    assert main(["--state-dir", str(state), "scan", str(logs), str(locked)]) == 2

    out, err = capsys.readouterr()
    assert "leak.txt" in out
    assert [line.rsplit(": ", 1)[0] for line in err.splitlines()] == [
        f"error: {logs / 'hidden'}",
        f"error: {locked}",
    ]


def _link_dir(link, target) -> None:
    if os.name == "nt":
        made = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], check=False)
        if made.returncode:
            pytest.skip("cannot create a junction")
    else:
        link.symlink_to(target, target_is_directory=True)


def test_links_are_not_followed(tmp_path):
    loop = tmp_path / "loop"
    loop.mkdir()
    (loop / "x.txt").write_text(VALUE)
    _link_dir(loop / "a", loop)
    _link_dir(loop / "b", loop)
    outside = tmp_path / "outside.txt"
    outside.write_text(VALUE)
    links = 2
    try:
        (loop / "f.txt").symlink_to(outside)
        links += 1
    except OSError:  # Windows without the symlink privilege
        pass

    start = time.monotonic()
    result = scan.scan_paths([str(loop)], [manifest(tmp_path / "ws")])

    assert time.monotonic() - start < 5
    assert [a.source for a in result.alerts] == [str(loop / "x.txt")]
    assert result.skipped_summary() == f"skipped: {links} symlinks"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs POSIX FIFOs")
def test_explicit_fifo_is_rejected(tmp_path):
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)

    result = scan.scan_paths([str(fifo)], [manifest(tmp_path / "ws")])

    assert result.errors == [(str(fifo), "not a regular file or directory")]
