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
  Lines log.
- `scan`: offline search of files, directories or stdin (agent transcripts, proxy logs). Exits
  with 1 when a canary is found.
- `list` and `clean`: show planted canaries and remove the files a run created, only when they
  are unchanged.
- Alerts name the matched secret (file and key) and never contain its value.

[0.1.0]: https://github.com/petrhromadka/agent-canary/releases/tag/v0.1.0
