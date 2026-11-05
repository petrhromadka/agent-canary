# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-05

First public release.

### Added

- `plant`: writes fake `.aws/credentials`, `.aws/config`, `.env`, `.ssh/id_ed25519`,
  `.ssh/id_ed25519.pub`, `.ssh/config` and `.npmrc` into a workspace. Values are random and
  generated at runtime. Hostnames and URLs embed a per-run token id. Existing files are never
  overwritten, and the state directory must be outside the workspace.
- `listen`: a DNS (UDP) listener for a delegated canary domain and an HTTP listener for canary
  URLs and requests carrying planted secrets. Alerts print to the console and append to a JSON
  Lines log. Both listeners suppress repeated alerts for 60 seconds. The HTTP listener reads at
  most 256 KiB of a body and 16 KiB of headers and serves at most 64 connections at once.
  Manifests are cached and reloaded when the state directory changes (within 1 second).
- DNS listener behaviour: it serves only `A`, `SOA` and `NS`. The zone apex answers `NOERROR`
  with `SOA` and `NS` (`ns1.<domain>`, `hostmaster.<domain>`); `NXDOMAIN` and `NODATA` answers
  carry an `SOA` (negative TTL 60) so resolvers do not drop the zone. An opcode other than
  `QUERY` gets `NOTIMP`, a class other than `IN` or `ANY` gets `REFUSED`. A token id seen outside every
  canary domain still alerts but is answered `REFUSED`. Secrets are matched case-insensitively
  (resolvers randomize case), a secret split across labels is detected, and every label other than the
  token id, the canary domain and a lone plant tag is redacted in alert details. Alerts are rate-limited per token (about 30
  per minute). `--dns [::]:PORT` is dual-stack.
- Detection of plain, percent-encoded, base64 (standard and URL-safe) and hex copies of each
  planted value and token id. Also found: base64 wrapped at 64 or 76 columns or with
  JSON-escaped newlines, UTF-16LE text (PowerShell 5.1 redirection), and JSON escapes (`\/` and
  `\u002f`-style, encoding label `json`).
- `scan`: offline search of files, directories or stdin (agent transcripts, proxy logs). The
  planted decoy files are skipped. Exits with 1 when a canary is found, 0 when none is and 2 on
  an error. Unreadable files or directories are reported on stderr and make the exit code 2
  even if leaks were found; symlink and junction loops are pruned; symlinked files inside
  directories are not read; FIFOs and devices given as arguments are rejected (exit 2); a
  `skipped: ...` summary line is printed on stderr. `scan --all` also scans `.git`, `.venv` and
  `node_modules`.
- Documented limits, all reproduced in an audit: gzip+base64, base32, `xxd`-style grouped hex,
  `\xNN` escapes, double URL-encoding (`%252F`) and a secret split across streaming deltas in
  LLM-API proxy logs are not detected; exfiltration to a third-party host is caught only by
  `scan`, which sees only what was logged; DNS detection needs the agent's resolver to reach
  the internet.
- `list` and `clean`: show planted canaries and remove the files a run created, only when they
  are unchanged. `clean` deletes only the fixed set of planted file names and keeps any file it would
  reach through a symlink or junction.
- Alerts name the matched secret (file and key) and never contain its value, including in the
  `detail` field.

[0.1.0]: https://github.com/petrhromadka/agent-canary/releases/tag/v0.1.0
