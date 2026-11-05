import base64
import dataclasses
import hashlib
import os
import shutil
import subprocess

import pytest

from agent_canary import store
from agent_canary.cli import main
from agent_canary.plant import clean, plant

DNS = "t.example.net"
URL = "http://203.0.113.5:8080/"
TELLTALE = ("canary", "decoy", "fake", "honeypot")


def plant_all(tmp_path, name="ws"):
    ws = tmp_path / name
    ws.mkdir()
    return plant(ws, dns_domain=DNS.upper(), http_url=URL, state_dir=tmp_path / "state")


def test_plant_writes_realistic_files_and_manifest(tmp_path):
    manifest, warnings = plant_all(tmp_path)
    ws = tmp_path / "ws"
    tid = manifest.token_id

    assert warnings == []
    assert store.load(tid, tmp_path / "state") == manifest
    assert manifest.http_url == URL.rstrip("/") and manifest.dns_domain == DNS
    assert {s.kind for s in manifest.secrets} == {"aws", "env", "ssh", "npm"}
    for secret in manifest.secrets:
        assert secret.value in (ws / secret.path).read_text(encoding="utf-8"), secret.name
    for rel in manifest.files:
        text = (ws / rel).read_text(encoding="utf-8").replace(str(ws.as_posix()), "")
        assert not any(word in text.lower() for word in TELLTALE), rel

    assert f"db.{tid}.{DNS}:5432" in (ws / ".env").read_text()
    assert f"WEBHOOK_URL={URL}t/{tid}/env" in (ws / ".env").read_text()
    assert f"endpoint_url = {URL}t/{tid}/aws" in (ws / ".aws/config").read_text()
    assert f"HostName ssh.{tid}.{DNS}" in (ws / ".ssh/config").read_text()
    key_path = (ws / ".ssh/id_ed25519").resolve().as_posix()
    assert f'IdentityFile "{key_path}"' in (ws / ".ssh/config").read_text()

    # The recorded private key line is one full line of the key body, past the constant header.
    key_lines = (ws / ".ssh/id_ed25519").read_text().splitlines()
    assert key_lines[0].startswith("-----BEGIN ") and key_lines[-1].startswith("-----END ")
    body = key_lines[1:-1]
    blob = base64.b64decode("".join(body))
    assert blob.startswith(b"openssh-key-v1\0")
    ssh_line = next(s.value for s in manifest.secrets if s.name == "ssh_private_key")
    assert ssh_line in body and body.index(ssh_line) >= 2

    other, _ = plant_all(tmp_path, "ws2")
    assert other.token_id != tid
    assert not {s.value for s in manifest.secrets} & {s.value for s in other.secrets}


@pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="ssh-keygen not on PATH")
@pytest.mark.parametrize("name", ["id_ed25519.pub", "id_ed25519"])
def test_keys_parse_with_ssh_keygen(tmp_path, name):
    plant_all(tmp_path)
    result = subprocess.run(
        ["ssh-keygen", "-l", "-f", str(tmp_path / "ws/.ssh" / name)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "ED25519" in result.stdout


def test_plant_refuses_bad_input_and_keeps_existing_files(tmp_path, capsys):
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / ".env").write_text("MINE=1\n")
    with pytest.raises(ValueError, match="inside the workspace"):
        plant(ws, state_dir=ws / "state")
    for bad in (
        {"dns_domain": "bad_label.example"},
        {"dns_domain": "ab\n.example.com"},
        {"http_url": "ftp://host"},
        {"http_url": "http://h:8080/x\n[profile p]\ncredential_process = x"},
    ):
        with pytest.raises(ValueError):
            plant(ws, state_dir=tmp_path / "state", **bad)

    manifest, warnings = plant(ws, kinds=["env", "npm"], state_dir=tmp_path / "state")
    assert (ws / ".env").read_text() == "MINE=1\n"
    assert manifest.files == (".npmrc",) and len(warnings) == 1
    assert "db.internal" not in (ws / ".npmrc").read_text()

    assert main(["--state-dir", str(tmp_path / "state"), "plant", str(ws), "--kinds", "env"]) == 2
    assert "error: nothing planted" in capsys.readouterr().err


def test_clean_removes_only_untouched_files_inside_workspace(tmp_path):
    manifest, _ = plant_all(tmp_path)
    ws = tmp_path / "ws"
    state = tmp_path / "state"
    (ws / ".env").write_text("edited by the user\n")
    outside = tmp_path / "outside.txt"
    outside.write_text("keep me")
    (ws / "notes.txt").write_text("keep me")  # inside, known content, but plant never creates it
    extra = ("../outside.txt", "notes.txt")
    tampered = dataclasses.replace(manifest, files=(*manifest.files, *extra))
    for rel in extra:
        tampered.file_hashes[rel] = hashlib.sha256(b"keep me").hexdigest()
    store.save(tampered, state)

    warnings = clean(store.load(manifest.token_id, state), state)
    assert len(warnings) == 3
    assert sum("not a file plant creates" in w for w in warnings) == 2
    assert any("modified" in w for w in warnings)

    assert (ws / ".env").read_text() == "edited by the user\n"
    assert outside.read_text() == "keep me"
    assert sorted(p.name for p in ws.iterdir()) == [".env", "notes.txt"]
    assert store.load_all(state) == []


def link_dir(link, target):
    """Make link point at target: a symlink, else (Windows without the privilege) a junction."""
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        if os.name != "nt":
            pytest.skip("symlinks unavailable")
        made = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, check=False
        )
        if made.returncode != 0:
            pytest.skip("neither symlinks nor junctions available")


def test_plant_and_clean_refuse_linked_or_blocked_directories(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    real_aws = tmp_path / "home_aws"
    real_aws.mkdir()
    link_dir(ws / ".aws", real_aws)
    (ws / ".ssh").write_text("a regular file, not a directory")

    manifest, warnings = plant(ws, http_url=URL, state_dir=tmp_path / "state")
    assert list(real_aws.iterdir()) == []
    assert manifest.files == (".env", ".npmrc")
    assert len(warnings) == 5 and all("not written" in w for w in warnings)

    # A tampered manifest naming a planted path behind the link does not reach outside.
    (real_aws / "config").write_text("keep me")
    tampered = dataclasses.replace(manifest, files=(*manifest.files, ".aws/config"))
    tampered.file_hashes[".aws/config"] = hashlib.sha256(b"keep me").hexdigest()
    store.save(tampered, tmp_path / "state")
    warnings = clean(store.load(manifest.token_id, tmp_path / "state"), tmp_path / "state")
    assert len(warnings) == 1 and "outside the workspace" in warnings[0]
    assert (real_aws / "config").read_text() == "keep me"


def test_failure_mid_plant_removes_everything_written(tmp_path, monkeypatch, capsys):
    ws = tmp_path / "ws"
    ws.mkdir()
    real_open = os.open
    calls = []

    def flaky_open(path, *args):
        calls.append(path)
        if len(calls) == 4:  # first file in .ssh, after .aws and .env were written
            raise PermissionError("denied")
        return real_open(path, *args)

    monkeypatch.setattr(os, "open", flaky_open)
    assert main(["--state-dir", str(tmp_path / "state"), "plant", str(ws)]) == 2
    assert capsys.readouterr().err == "error: denied\n"
    assert len(calls) == 4
    assert list(ws.iterdir()) == []
    assert store.load_all(tmp_path / "state") == []
