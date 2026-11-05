"""`report`: per-token summary of JSON Lines alert logs."""

from __future__ import annotations

import json

from agent_canary import cli

TOKEN_A, TOKEN_B = "aaaabbbbcccc", "ddddeeeeffff"


def _match(token, name=None, path=None, encoding="plain"):
    kind = None if name is None else "env"
    return {"token_id": token, "kind": kind, "path": path, "name": name, "encoding": encoding}


def _line(time, channel, source, *matches):
    return json.dumps(
        {"time": time, "channel": channel, "source": source, "detail": "x", "matches": matches}
    )


SAMPLE = "\n".join(
    [
        _line(
            "2026-11-05T20:42:53+00:00",
            "http",
            "127.0.0.1:52227",
            _match(TOKEN_A, "API_KEY", ".env", "base64"),
            _match(TOKEN_A, "JWT_SECRET", ".env", "base64"),
        ),
        '{"time": "2026-11-05T20:43:00+00:00", "channel": "dns"',  # truncated write
        "",
        _line("2026-11-05T20:42:50+00:00", "dns", "127.0.0.1:62956", _match(TOKEN_A)),
        _line(
            "2026-11-05T21:00:00+00:00",
            "scan",
            "run-17/t.jsonl",
            _match(TOKEN_B, "API_KEY", ".env"),
        ),
        '["not", "an", "alert"]',
    ]
)


def test_report_summarizes_per_token_and_counts_malformed_lines(tmp_path, capsys):
    log = tmp_path / "alerts.jsonl"
    log.write_text(SAMPLE + "\n", encoding="utf-8")

    assert cli.main(["report", str(log), "--json"]) == 1
    out, err = capsys.readouterr()
    data = json.loads(out)
    assert data["alerts"] == 3
    assert data["malformed_lines"] == 2
    assert data["tokens"][TOKEN_A] == {
        "first_seen": "2026-11-05T20:42:50+00:00",
        "last_seen": "2026-11-05T20:42:53+00:00",
        "alerts": 2,
        "channels": {"dns": 1, "http": 1},
        "secrets": [{"name": "API_KEY", "path": ".env"}, {"name": "JWT_SECRET", "path": ".env"}],
        "encodings": ["base64", "plain"],
        "sources": ["127.0.0.1:52227", "127.0.0.1:62956"],
    }
    assert data["tokens"][TOKEN_B]["channels"] == {"scan": 1}
    assert "2 malformed lines skipped" in err

    assert cli.main(["report", str(log)]) == 1
    out, _ = capsys.readouterr()
    assert f"token {TOKEN_A}: 2 alerts (dns 1, http 1)" in out
    assert "  secrets: API_KEY (.env), JWT_SECRET (.env)" in out
    assert "3 alerts, 2 tokens" in out


def test_report_exit_codes_for_empty_and_unreadable_logs(tmp_path, capsys):
    empty = tmp_path / "empty.jsonl"
    empty.write_text("", encoding="utf-8")
    assert cli.main(["report", str(empty)]) == 0
    assert "no alerts" in capsys.readouterr().out

    assert cli.main(["report", str(empty), str(tmp_path / "missing.jsonl")]) == 2
    assert "missing.jsonl" in capsys.readouterr().err
