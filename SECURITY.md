# Security Policy

agent-canary is a defensive detection tool. `plant` writes **fake** credentials that grant access
to nothing; `listen` only receives traffic and records which canary it carried; `scan` only
reads files. Nothing is sent anywhere by the tool itself.

## Design rules

- Alert logs and console output name the secret (file and key), never its value.
- Manifests live outside the workspace (`$AGENT_CANARY_HOME`, default `~/.agent-canary`) so the
  agent under test cannot read which files are decoys. `plant` refuses a state dir inside the
  workspace. This only helps against an agent confined to the workspace: an agent running as the
  same user with access to the home directory can read the state dir, so run the agent as another
  user or in a container.
- `plant` refuses to write through a symlink or junction and removes what it wrote if a later
  step fails.
- Listener input is untrusted: request bodies are capped, malformed DNS packets are dropped and
  control characters are escaped before anything is printed.
- The DNS listener answers only for canary domains and refuses everything else; it is not an
  open resolver.
- `clean` deletes only files recorded in the manifest that `plant` can create (a fixed list),
  inside the workspace, and only when their content is unchanged.

## Reporting a vulnerability

Please report vulnerabilities privately through
[GitHub Security Advisories](https://github.com/petrhromadka/agent-canary/security/advisories/new)
rather than a public issue. Include the version or commit, steps to reproduce and the impact you
expect. Highest priority: a planted value appearing in an alert log or console output, the
listener crashing on crafted input, or `clean` deleting a file it did not create.

## Supported versions

Only the latest release receives security fixes.
