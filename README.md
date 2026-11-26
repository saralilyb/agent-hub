# agent-hub

One MCP endpoint for several AI agents. The hub connects to your remote
MCP servers (the upstreams) and holds their credentials. Each agent gets
its own hub token and sees only the tools you allow it. Every tool list
and tool call is written to an audit log, without arguments.

It is one Python file on [FastMCP](https://gofastmcp.com), meant to run on
the machine where the agents run, or on a host they reach over a private
network.

## Why

Without a hub, every agent holds every credential, and each agent decides
for itself which tools it may use. With the hub:

- Upstream API keys and OAuth grants live in one process. Agents never
  see them, and the hub never forwards an agent's token upstream.
- An agent's token maps to an exact list of tools. Tools outside the list
  are absent from `tools/list` and refused on `tools/call`, with the same
  error as a tool that does not exist.
- A group of tools can be marked read-only. The hub then advertises those
  tools with `readOnlyHint: true`, and every other tool as not read-only,
  destructive and not idempotent (the MCP defaults for a tool nobody has
  vouched for), replacing whatever the upstream claims. A client's "ask
  before writes" setting then has a line it can trust. An agent
  marked `read_only` cannot be given anything else; the hub refuses to
  load such a config.
- OAuth upstreams share one long-lived session, so concurrent requests
  never race on a refresh-token rotation. The running hub never opens a
  browser; sign-in is a separate one-time command.
- Upstream error details are masked, and secrets and URL query values are
  scrubbed from logs.

## Limits

- Tools only. Resources and prompts are switched off.
- Upstreams must speak Streamable HTTP. Local stdio servers are not
  proxied.
- Policy is per tool, not per argument, and the hub does not ask a human
  before a call. Approval prompts belong to the client; the read-only
  hints above give it something reliable to act on.
- The hub serves plain HTTP. Keep it on loopback, or put TLS in front of
  it (Tailscale Serve, a reverse proxy). It logs a warning when bound to
  anything else.
- Hub tokens are static bearer tokens. Give each one an `expires` date and
  the narrowest tool list that works.

## Requirements

Python 3.12 or later and [uv](https://docs.astral.sh/uv/). The
[1Password CLI](https://developer.1password.com/docs/cli/) is optional:
`agent-hub` uses it when a `secrets.env.refs` file is present, and
otherwise expects secrets in the environment. Tested on macOS; the code
and scripts are POSIX and should run on Linux and the BSDs.

## Quick start

```sh
git clone https://github.com/saralilyb/agent-hub ~/src/agent-hub
cd ~/src/agent-hub
uv sync --frozen
mkdir -p ~/.config/agent-hub
cp examples/hub.example.toml ~/.config/agent-hub/hub.toml
```

Edit `hub.toml`: list your upstreams, then see which tools they offer.

```sh
./agent-hub tools
```

Make a token for each agent, keep it where that agent can read it (a
password manager, the agent's own secret store), and put its hash in
`[agents]`:

```sh
openssl rand -hex 32 > token          # or let your password manager do it
./agent-hub hash-token < token
rm token
```

Check the config and start the hub:

```sh
./agent-hub check
./agent-hub serve
```

## Configuration

The config file is `$AGENT_HUB_CONFIG` if set, else
`~/.config/agent-hub/hub.toml` (respecting `$XDG_CONFIG_HOME`). Relative
paths in it are relative to the file. Unknown keys are errors, so a
misspelt setting cannot be silently ignored.
[`examples/hub.example.toml`](examples/hub.example.toml) shows every
section.

**Secrets** never appear in the file. A value of `env:NAME` is read from
the environment variable `NAME`; `${NAME}` inside a string is replaced, so
`"Bearer ${TOKEN}"` and `"https://host/mcp?key=${KEY}"` work. Each
variable is removed from the environment once read.

**`[hub]`**: `name`, `host` (default `127.0.0.1`), `port` (`18797`),
`path` (`/mcp`), `state_dir` (default `~/.local/state/agent-hub`; holds
the OAuth store and the pid file), `audit_log` (default
`<state_dir>/audit.jsonl`), `audit_max_bytes` and `audit_backups`
(rotation, default 10 MB and 5), `oauth_key` (a Fernet key that encrypts
the OAuth store; required if any upstream uses OAuth), `oauth_dir`.

**`[hub.status]`**: `user` (default `admin`) and `password` for a
read-only status page at `/status`: upstream health, agents with their
tools and expiry dates, and the last 100 audit events.

**`[upstreams.NAME]`**: `url`, optional `headers`, or `auth = "oauth"`
with a `callback_port` and optional `scopes`. Tools appear to agents as
`NAME_tool`, so `NAME` must not contain `_`.

`scopes` decides what the hub's own grant at the upstream can do; it is
not per agent. Without it, the hub requests every scope the server
advertises. The design keeps the hub as the gate: grant the hub what any
agent may eventually need, and limit each agent with groups and
`read_only`. Set narrower `scopes` only when no agent should ever have
more, as a second limit. `agent-hub authorize` prints the scope the
server actually granted.

**`[groups.NAME]`**: `allow` (exact tool names), `groups` (other groups to
include), `access = "read"` to vouch that every tool in the group only
reads. A read group may include only other read groups. `agent-hub tools`
shows which tools are in a read group and warns when the upstream says
such a tool writes.

**`[agents.NAME]`**: `token_sha256` (one hash, or a list while rotating),
`groups`, `allow`, `expires` (a TOML date such as `2027-06-30`; from the
start of that day the token stops working), `read_only = true`.

## Commands

`./agent-hub COMMAND` runs `hub.py` from the repository's environment and
handles secrets. For `serve` and `tools` it runs under
`op run --env-file secrets.env.refs` when that file sits next to the
config; `authorize` receives only `AGENT_HUB_OAUTH_KEY` from it. An
`op.env` file next to the config, if present, is sourced first (for
example to set `OP_SERVICE_ACCOUNT_TOKEN`). No `OP_*` variable reaches the
hub process.

- `serve` runs the hub. `run-hub` does the same, for service managers.
- `tools [UPSTREAM]` lists upstream tools and what each one claims about
  writing, to help you write groups.
- `check` validates the config and lists agents, tool counts and expiry
  dates. It exits non-zero if the config is invalid or a token has
  expired, and warns about secrets written into the file as literals.
- `reload` reloads `[agents]` and `[groups]` in the running hub.
- `authorize UPSTREAM` signs in to an OAuth upstream (opens a browser).
- `hash-token` prints the SHA-256 of a token read from stdin.
- `bridge` serves the hub over stdio for one agent (see Antigravity
  below).

## Connecting agents

Each agent sends `Authorization: Bearer <its token>` to
`http://127.0.0.1:18797/mcp`. Configs for several clients are in
[`examples/clients/`](examples/clients/).

**Hermes Agent** and **Claude Code** expand `${VAR}` in headers, so the
token stays in an environment variable.

**Autolith** reads a header value from an environment variable named in
`mcp.sexp`. `clients/launch REFS COMMAND...` starts an agent under
`op run` with only the tokens named in REFS and a short allowlist of
variables, and
derives `AGENT_HUB_BEARER_<AGENT>` (`Bearer <token>`) for clients that
want the whole header value.

**Google Antigravity** documents custom headers in a hand-written
`mcp_config.json` only as literal values. Instead of writing the token
into that file, let Antigravity start the bridge as a local stdio server.
The bridge reads the token from the macOS keychain (or `--token-env NAME`)
and relays to the hub:

```sh
security add-generic-password -s agent-hub-antigravity -a "$USER" -w
# paste the token at the prompt
```

Then use
[`examples/clients/antigravity.json`](examples/clients/antigravity.json)
with absolute paths. Run the bridge directly from the virtual environment,
not under `op run` or `uv run`: its stdout carries the MCP protocol, and
anything else written there breaks it.

By default the bridge talks only to a hub on the same machine. A hub
elsewhere needs `--allow-remote` and an `https` URL. The URL sits in a
config file the agent may be able to edit, so leave `--allow-remote` off
unless you need it.

What the bridge protects against is accidental disclosure: the token is
not in a file the IDE indexes, syncs, or reads into the model's context.
It does not protect against the agent itself. Anything that runs as you,
including an agent with terminal access, can read the keychain item
(`security find-generic-password -w`) or start the bridge with its own
arguments. The limits on that token are the hub's: its tool list, its
read-only flag and its expiry date. Keep Antigravity's terminal
permissions strict.

## Operating

**As a service.** On macOS, adapt
[`examples/launchd/agent-hub.plist`](examples/launchd/agent-hub.plist).
Elsewhere, run `run-hub` under rc.d, systemd or similar.

**Changing agents or groups.** Edit the config, then `./agent-hub reload`.
It signals the running hub and prints the result from the audit log. The
hub holds a lock on its pid file in `state_dir` while it runs, so `reload`
never signals a stale pid, and a second hub cannot start on the same
`state_dir`. A config that fails validation is
rejected and the running policy stays. Changes to `[hub]` or
`[upstreams]` need a restart.

**Rotating a token.** Add the new hash to the agent's `token_sha256` list
and reload; move the agent to the new token; remove the old hash and
reload again.

**OAuth upstreams.** `./agent-hub authorize NAME` opens a browser on the
hub's host and stores the grant, encrypted, in `state_dir/oauth`. Restart
the hub afterwards. If a grant is revoked, only that upstream fails, with
a message naming the command to run.

**Audit log.** One JSON object per line: time, agent, method, tool,
decision (`allow` or `deny`), error type, and duration. Arguments and
results are never logged.

## Separate instances

Nothing is shared between two configs, so one checkout can serve two
fully separate hubs, for example personal and work. Give each its own
config directory (with its own `secrets.env.refs`), `state_dir`, port,
tokens, and service label, and set `AGENT_HUB_CONFIG` for the second one.
Or install the second on a different machine entirely.

## Development

```sh
uv sync --frozen
uv run --frozen pytest -q      # unit and end-to-end tests, offline
uv run --frozen ruff check .
shellcheck agent-hub run-hub clients/launch
```

The end-to-end tests start a real hub and a probe upstream on loopback
with tokens generated per run. CI also runs gitleaks over the full
history. Dependencies are locked with `exclude-newer` set 48 hours before
the last update, so no release younger than two days is picked up.

## License

ISC. See [LICENSE](LICENSE).
