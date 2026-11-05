# Contributing

Bug reports and pull requests are welcome. For security issues use the private process in
[SECURITY.md](SECURITY.md), not a public issue.

## Setup

You need Python 3.12 or newer, [uv](https://docs.astral.sh/uv/) and
[prek](https://github.com/j178/prek) (or `pre-commit`).

```sh
git clone https://github.com/petrhromadka/agent-canary
cd agent-canary
uv sync
prek install
```

## Checks

CI runs these four commands on Python 3.12, 3.13 and 3.14. Run them before opening a pull
request:

```sh
uv run ruff check .
uv run ruff format --check .
uv run ty check src
uv run pytest
```

Run everything the pre-commit hooks run, including gitleaks, with:

```sh
prek run --all-files
```

The project has no runtime dependencies. Adding one needs a strong reason in the pull request.

## Tests

- Test the behaviour you changed: the main path and the failures that can really happen. Prefer
  extending an existing test to adding a new one.
- Do not put secret-shaped strings in fixtures or source. gitleaks scans every commit and the CI
  run fails on strings that look like AWS keys, tokens or private keys. Build such values at
  runtime, for example by concatenating the prefix and a random suffix inside the test, or by
  reading the values back from the manifest that `plant` returns.
- Use temporary directories (`tmp_path`) for workspaces and state directories, and bind
  listeners to port 0 on `127.0.0.1`.

## Pull requests

- One logical change per commit, with an imperative subject of at most 72 characters.
- Update `README.md` and `CHANGELOG.md` when behaviour changes.
- Alerts, logs and console output must never include a planted secret value; this is the first
  thing reviewers check.
