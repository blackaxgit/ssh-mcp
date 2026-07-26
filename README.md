# ssh-mcp

SSH MCP server that lets AI assistants execute commands on remote servers.

[![License: MPL-2.0](https://img.shields.io/badge/License-MPL--2.0-brightgreen.svg)](LICENSE)
[![Claude Code Ready](https://img.shields.io/badge/Claude_Code-Auto_Install_Ready-blueviolet?logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxNiIgaGVpZ2h0PSIxNiIgdmlld0JveD0iMCAwIDE2IDE2Ij48dGV4dCB4PSIwIiB5PSIxMyIgZm9udC1zaXplPSIxNCI+8J+UpTwvdGV4dD48L3N2Zz4=)](#add-to-claude-code)

## What is this

ssh-mcp is a [Model Context Protocol](https://modelcontextprotocol.io/) server that gives AI assistants like Claude direct access to your SSH infrastructure. Once configured, Claude can run commands, transfer files, and query server groups across your fleet without leaving the conversation.

Connection details are read from your existing `~/.ssh/config`. No credentials are stored in the MCP configuration.

## Features

- Run shell commands on individual servers or across entire groups in parallel
- SFTP file upload and download over the existing SSH session
- Connection pooling — reuses SSH connections across tool calls
- Dangerous command detection — warns before executing destructive operations
- Server groups for organizing hosts (production, staging, per-service)
- SSH config integration — reads host, port, user, and identity from `~/.ssh/config`
- Custom config path via `SSH_MCP_CONFIG` environment variable
- `dry_run` previews — see which server, command, working directory and timeout would be used, without connecting
- SFTP local-path confinement — every local path stays inside a configured `transfer_root`
- stdio or streamable-HTTP transport, with bearer-token auth for network deployments
- Built-in `ssh-mcp healthcheck` subcommand for Docker's `HEALTHCHECK`
- Optional OpenTelemetry tracing via the `otel` extra

## Quick Start

### Install

```bash
# Run directly with uvx (no install required)
uvx ssh-mcp

# Or install with pip
pip install ssh-mcp
```

Requires Python 3.11+. Install [uv](https://docs.astral.sh/uv/getting-started/installation/) to use `uvx`.

#### Docker

A prebuilt image is published to GitHub Container Registry:

```bash
docker pull ghcr.io/blackaxgit/ssh-mcp:latest
```

Or run with Docker Compose:

```yaml
services:
  ssh-mcp:
    image: ghcr.io/blackaxgit/ssh-mcp:latest
    stdin_open: true
    restart: unless-stopped
    environment:
      SSH_MCP_CONFIG: /config/servers.toml
    volumes:
      - ./servers.toml:/config/servers.toml:ro
      - ~/.ssh:/home/sshmcp/.ssh:ro
```

The image uses a non-root `sshmcp` user (uid 1000). Mount your SSH keys and config file read-only. [compose.yaml](compose.yaml) in the repo carries a fuller example — it builds from the local Dockerfile rather than pulling the published image, and includes the HTTP-transport service, `ulimits` and healthcheck guidance omitted above.

### Create a config file

```bash
mkdir -p ~/.config/ssh-mcp
cp config/servers.example.toml ~/.config/ssh-mcp/servers.toml
```

Edit `~/.config/ssh-mcp/servers.toml` and add your servers. Server names must match `Host` entries in `~/.ssh/config`.

### Add to Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or the equivalent on your platform:

```json
{
  "mcpServers": {
    "ssh-mcp": {
      "command": "uvx",
      "args": ["ssh-mcp"]
    }
  }
}
```

To use a non-default config path, pass the environment variable:

```json
{
  "mcpServers": {
    "ssh-mcp": {
      "command": "uvx",
      "args": ["ssh-mcp"],
      "env": {
        "SSH_MCP_CONFIG": "/path/to/servers.toml"
      }
    }
  }
}
```

Restart Claude Desktop after editing the config.

### Add to Claude Code

If you use [Claude Code](https://docs.anthropic.com/en/docs/claude-code) instead of Claude Desktop, you can set everything up from the terminal:

```bash
# 1. Add the MCP server
claude mcp add ssh-mcp -- uvx ssh-mcp

# 2. Create the config directory and copy the example
mkdir -p ~/.config/ssh-mcp
curl -sL https://raw.githubusercontent.com/blackaxgit/ssh-mcp/main/config/servers.example.toml \
  > ~/.config/ssh-mcp/servers.toml

# 3. Edit with your servers (server names must match ~/.ssh/config Host entries)
${EDITOR:-nano} ~/.config/ssh-mcp/servers.toml

# 4. Restrict permissions
chmod 600 ~/.config/ssh-mcp/servers.toml
```

To use a custom config path:

```bash
claude mcp add ssh-mcp -e SSH_MCP_CONFIG=/path/to/servers.toml -- uvx ssh-mcp
```

## Configuration

### Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `SSH_MCP_CONFIG` | — | Absolute path to a TOML config file. Overrides the default search path. |
| `SSH_MCP_LOG_FORMAT` | `console` | Log output format. Set to `json` to emit single-line JSON events (timestamp, level, event, contextvars) suitable for log aggregators like Loki, Datadog, or Splunk. Any other value falls back to the colorized console renderer. |
| `SSH_MCP_TRANSPORT` | `stdio` | MCP transport. `stdio` = classic subprocess transport (default, used by Claude Desktop / Claude Code via `uvx ssh-mcp`). `http` or `streamable-http` = run as a network service over MCP streamable HTTP. |
| `SSH_MCP_HTTP_HOST` | `127.0.0.1` | Bind address for HTTP transport. **Binding to any non-localhost value (e.g. `0.0.0.0`) REQUIRES `SSH_MCP_HTTP_TOKEN` — startup aborts otherwise.** |
| `SSH_MCP_HTTP_PORT` | `8000` | TCP port for HTTP transport. |
| `SSH_MCP_HTTP_TOKEN` | — | Shared bearer secret. When set, every request must carry `Authorization: Bearer <token>` (scheme case-insensitive per RFC 7235) or receive HTTP 401. Mandatory for non-localhost binds (unless `SSH_MCP_HTTP_AUTH=none`). Minimum length 16 characters — shorter tokens are rejected at startup. Leading/trailing whitespace is stripped so `.env` files with trailing newlines work as expected. |
| `SSH_MCP_HTTP_TOKEN_FILE` | — | Path to a file containing the bearer token (alternative to `SSH_MCP_HTTP_TOKEN`). Read at startup, stripped of whitespace. Preferred for Docker secrets: mount the secret file and point this env var at it. |
| `SSH_MCP_HTTP_AUTH` | `bearer` | Authentication mode. `bearer` (default) enables the built-in middleware. `none` disables it entirely — useful when ssh-mcp sits behind a trusted reverse proxy that handles auth at the edge. Combining `none` with a non-localhost bind REQUIRES the explicit acknowledgement env var below. |
| `SSH_MCP_HTTP_NETWORK_NO_AUTH` | — | Magic-string escape hatch. Must equal literal `I_ACCEPT_RCE_RISK` to allow `SSH_MCP_HTTP_AUTH=none` + non-localhost bind. Intentionally verbose so nobody sets it by accident. |
| `SSH_MCP_HTTP_KEEPALIVE_TIMEOUT` | `2` | uvicorn `timeout_keep_alive` in seconds. Idle HTTP/1.1 connections are closed after this many seconds. v0.4.0 default (5s) accumulated enough concurrent connections under bursty n8n traffic to exhaust the container's 1024 fd limit — v0.4.1 default 2s is safer for spiky clients. Increase to 5–10 for long-polling MCP clients behind a load balancer. |
| `SSH_MCP_HTTP_LIMIT_CONCURRENCY` | `256` | uvicorn `limit_concurrency`. Max simultaneous in-flight requests before returning HTTP 503. Prevents unbounded growth under burst load. Tune up for high-QPS deployments; tune down on small containers. |
| `SSH_MCP_HTTP_BACKLOG` | `128` | uvicorn `backlog` — TCP listen backlog for the accept queue. Smaller caps SYN-flood exposure. |
| `SSH_MCP_HTTP_STATELESS` | `false` | Set to `true` for stateless sessions (recommended for load-balanced or serverless deployments). Default is stateful with server-side sessions. |
| `SSH_MCP_HTTP_ALLOWED_HOSTS` | — | Comma-separated extra Host-header values the SDK's DNS-rebinding protection should permit (e.g. `ssh-mcp.internal:*,api.example.com:8000`). Localhost aliases are always permitted. |
| `SSH_MCP_TRANSFER_ROOT` | `$XDG_DATA_HOME/ssh-mcp/transfers` | Directory SFTP transfers are confined to. Takes precedence over `transfer_root` in `[settings]`. See [Local path confinement](#security). |
| `XDG_CONFIG_HOME` | `~/.config` | Honoured when searching for `ssh-mcp/servers.toml` (see [Config file location](#config-file-location)). |
| `XDG_DATA_HOME` | `~/.local/share` | Base directory for the default transfer root. |
| `HYPOTHESIS_PROFILE` | `dev` | For local development / CI only. Set to `ci` to run property-based tests with `max_examples=200` instead of `50`. |

**fd exhaustion mitigation:** the Docker base image inherits a 1024 fd limit by default. Under sustained burst traffic that can run out quickly. Raise it in your compose file:

```yaml
ssh-mcp:
  # ...
  ulimits:
    nofile:
      soft: 65536
      hard: 65536
```

Pair that with the `SSH_MCP_HTTP_KEEPALIVE_TIMEOUT` / `SSH_MCP_HTTP_LIMIT_CONCURRENCY` knobs above for a full fix.

### Running over HTTP

ssh-mcp exposes the MCP streamable HTTP transport as an alternative to stdio. This lets MCP-aware clients connect over the network instead of launching a subprocess, which is useful for containerized deployments, shared-team servers, or anything that needs to survive a client restart.

> **WARNING: ssh-mcp serves plain HTTP, not HTTPS.** The bearer token is
> transmitted in cleartext on every request. Deploying on a public IP
> without a TLS-terminating reverse proxy (Caddy, nginx, Traefik) exposes
> the token to any network observer — equivalent to publishing a root
> shell. **Always terminate TLS before ssh-mcp reaches the network.**

**Security first.** ssh-mcp runs shell commands on remote servers. Exposing the HTTP endpoint without authentication is equivalent to exposing a root shell. The startup code enforces this:

- Binding to `127.0.0.1` / `localhost` / `::1` without a token is allowed — this matches the single-user workstation model.
- Binding to ANY other address without `SSH_MCP_HTTP_TOKEN` raises `RuntimeError` at startup and the process exits.
- The MCP SDK's DNS-rebinding protection is enabled by default. Remote clients connecting via a hostname must have it listed in `SSH_MCP_HTTP_ALLOWED_HOSTS`.
- Bearer-token comparison uses `hmac.compare_digest` to prevent timing attacks.

Local loopback (no auth needed):

```bash
SSH_MCP_TRANSPORT=http ssh-mcp
# → listening on http://127.0.0.1:8000/mcp
```

Container deployment with bearer auth:

```bash
TOKEN=$(openssl rand -hex 32)
docker run -d \
  -p 8000:8000 \
  -e SSH_MCP_TRANSPORT=http \
  -e SSH_MCP_HTTP_HOST=0.0.0.0 \
  -e SSH_MCP_HTTP_TOKEN="$TOKEN" \
  -e SSH_MCP_HTTP_STATELESS=true \
  -e SSH_MCP_HTTP_ALLOWED_HOSTS='ssh-mcp.internal:*' \
  -v ~/.ssh:/home/sshmcp/.ssh:ro \
  -v ./servers.toml:/config/servers.toml:ro \
  -e SSH_MCP_CONFIG=/config/servers.toml \
  ghcr.io/blackaxgit/ssh-mcp:latest
```

Clients connect with:

```
Authorization: Bearer <TOKEN>
Host: ssh-mcp.internal
```

For stateful sessions (default), FastMCP maintains per-client context across requests. For stateless deployments behind a load balancer, set `SSH_MCP_HTTP_STATELESS=true` — each request is handled independently with no server-side session.

### Healthcheck

The Docker image includes a built-in `ssh-mcp healthcheck` CLI subcommand that
Docker's `HEALTHCHECK` directive invokes automatically. No inline Python, no
`curl`, no manual compose surgery required. The subcommand:

- Auto-detects the transport via `SSH_MCP_TRANSPORT`:
  - **stdio mode**: verifies the package imports and `servers.toml` parses
  - **http mode**: sends a real MCP `initialize` JSON-RPC POST and checks for any non-5xx response
- Reads the same auth env vars as the server (`SSH_MCP_HTTP_TOKEN`, `SSH_MCP_HTTP_TOKEN_FILE`, `SSH_MCP_HTTP_AUTH`) — never logs the token
- Exits 0 if healthy, 1 otherwise
- Uses Python stdlib only (no `curl`/`wget` dependency)
- Applies a 3-second timeout to the HTTP probe. The stdio probe has no timeout of its own and relies on Docker's `--timeout=5s` (importing the server costs ~0.3s)

Run manually for debugging:

```bash
docker exec ssh-mcp ssh-mcp healthcheck && echo "healthy"
```

Check current status:

```bash
docker inspect ssh-mcp --format '{{.State.Health.Status}}'
```

To override the baked-in settings in your compose file:

```yaml
healthcheck:
  test: ["CMD", "ssh-mcp", "healthcheck"]
  interval: 15s
  timeout: 5s
  retries: 3
  start_period: 10s
```

### Tracing (OpenTelemetry)

Tracing is optional and off unless `opentelemetry-api` is importable:

```bash
uv pip install 'ssh-mcp[otel]'
```

The extra installs the **API layer only** — the SDK and exporter are yours to choose, so ssh-mcp stays lightweight for anyone who does not trace. Install and configure `opentelemetry-sdk` plus an exporter (OTLP, Jaeger, Tempo) yourself; without an SDK the API is a no-op and nothing is emitted.

Spans produced:

- `mcp.tool.<name>` — one per MCP tool call, tagged `mcp.tool.name`. Exceptions are recorded with `StatusCode.ERROR`.
- `ssh.execute`, `ssh.upload`, `ssh.download` — the SSH/SFTP operation inside the tool call.

Span attributes go through the same credential redaction as the audit log (see [Security](#security)).

### Reverse proxy deployment (auth at the edge)

If your reverse proxy (Caddy, nginx, Traefik, Envoy, Cloudflare Access, etc.) already authenticates requests before they reach ssh-mcp, you can disable the built-in bearer middleware with `SSH_MCP_HTTP_AUTH=none`. This mode is deliberately hard to enable on a public bind — you must also set a verbose acknowledgement env var:

```bash
docker run -d \
  --network internal \
  -e SSH_MCP_TRANSPORT=http \
  -e SSH_MCP_HTTP_HOST=0.0.0.0 \
  -e SSH_MCP_HTTP_AUTH=none \
  -e SSH_MCP_HTTP_NETWORK_NO_AUTH=I_ACCEPT_RCE_RISK \
  -e SSH_MCP_HTTP_ALLOWED_HOSTS='ssh-mcp.internal:*' \
  -v ~/.ssh:/home/sshmcp/.ssh:ro \
  -v ./servers.toml:/config/servers.toml:ro \
  -e SSH_MCP_CONFIG=/config/servers.toml \
  ghcr.io/blackaxgit/ssh-mcp:latest
```

**WARNING:** `SSH_MCP_HTTP_AUTH=none` + `SSH_MCP_HTTP_NETWORK_NO_AUTH=I_ACCEPT_RCE_RISK` is a remote code execution surface. The magic-string acknowledgement exists so operators physically type the words "I ACCEPT RCE RISK" before opting in. Every tool call reaches a shell on every managed SSH server. Use this only when:

1. ssh-mcp is on a **private Docker network** not reachable from the host's public interface, AND
2. The reverse proxy fronting it enforces authentication (basic auth, OAuth, mTLS, Cloudflare Access, etc.), AND
3. You have audit logging on the proxy that's immutable to the ssh-mcp process.

For localhost binds without auth, no acknowledgement is needed — that matches the historical stdio deployment model.

### Config file location

Checked in order:

1. `$SSH_MCP_CONFIG` environment variable
2. `$XDG_CONFIG_HOME/ssh-mcp/servers.toml`, falling back to `~/.config/ssh-mcp/servers.toml` (default)
3. `config/servers.toml` relative to the package (development only)

Example `servers.toml`:

```toml
[settings]
ssh_config_path = "~/.ssh/config"
command_timeout = 30          # SSH *connect* timeout in seconds, range 1..3600
max_output_bytes = 51200      # truncate captured output at this many bytes, per stream
max_command_bytes = 65536     # reject longer command strings at the tool boundary (1024..1048576)
connection_idle_timeout = 300 # seconds; eviction scan runs every 60s
known_hosts = true            # false removes MITM protection
max_parallel_hosts = 10       # process-wide concurrency cap for group execution (1..100)

[groups]
production = { description = "Production servers" }
staging    = { description = "Staging servers" }

[servers.web-prod-01]
description = "Production web server"
groups      = ["production"]

[servers.web-staging-01]
description = "Staging web server"
groups      = ["staging"]
jump_host   = "bastion"

[servers.db-prod-01]
description = "Production database"
groups      = ["production"]
user        = "dbadmin"
```

Note two things about the timeouts, because the names invite confusion:

- `command_timeout` is the **SSH connection-establishment** timeout, not the command execution timeout.
- Per-command timeout comes from the `timeout` argument of `execute` / `execute_on_group` (default 30) — unless the server block sets `timeout = N`, which **wins over the caller's argument**.

`max_parallel_hosts` bounds the whole process, not a single call: the semaphore is built once at startup, so concurrent `execute_on_group` calls share the same budget rather than each getting their own.

Per-server overrides (`hostname`, `port`, `user`, `identity_file`, `jump_host`, `default_dir`, `timeout`) take precedence over `~/.ssh/config`. See [config/servers.example.toml](config/servers.example.toml) for the annotated reference.

Restrict config file permissions to your user:

```bash
chmod 600 ~/.config/ssh-mcp/servers.toml
```

## Available Tools

| Tool | Description |
|------|-------------|
| `list_servers` | List configured servers; optionally filter by group |
| `list_groups` | List server groups with member counts |
| `execute` | Run a shell command on a single server (supports `force` to bypass dangerous-command detection, and `dry_run`) |
| `execute_on_group` | Run a command on all servers in a group (parallel; supports `fail_fast`, `force` and `dry_run`) |
| `upload_file` | Upload a file to a server via SFTP. Local path is relative to `transfer_root` |
| `download_file` | Download a file from a server via SFTP. Local path is relative to `transfer_root`; will not overwrite |

`dry_run=true` on either execute tool returns a `[DRY RUN]` preview of the server, command, working directory, timeout and `force` flag without opening a connection. Dangerous-command detection still runs, so a rejection can be previewed; if `force=true` *would* bypass a match, the preview carries an explicit `⚠️ DANGEROUS` banner.

Command strings longer than `max_command_bytes` (default 65536 encoded UTF-8 bytes) are rejected at the tool boundary, before redaction or dangerous-command matching runs. Single SFTP transfers are capped at 100 MiB: an oversized upload is refused outright, an oversized download only logs a warning (the bytes are already on disk). Use `rsync` or `scp` for anything larger.

## Security

**Dangerous command blocking.** ssh-mcp rejects commands that match known destructive patterns unless the tool caller passes `force=true`:

- Recursive deletes of `/`, `~`, `$HOME`, `$USER` — combined (`rm -rf /`) and split (`rm -r -f /`, `rm --recursive --force /`) flag forms, in any flag order
- `find / -delete`, `find / -exec rm`
- Block-device wipes: `shred /dev/*`, `wipefs /dev/*`, `blkdiscard /dev/*`, `sgdisk -Z /dev/*`
- Partition-table destruction: `parted /dev/… mklabel`, `fdisk /dev/sd*`
- `mkfs`, `dd if=…` and the reordered `dd of=… if=…` form
- Redirects into a block device or auth database: `> /dev/sd*`, `> /dev/nvme*`, `> /dev/hd*`, `> /etc/{passwd,shadow,gshadow,sudoers}`
- `chmod 777 /` — flag before *or* after the mode (`chmod -R 777 /`, `chmod 777 -R /`)
- Fork bombs (spaced and adjacent variants)
- Payload-execution wrappers: `base64 -d | bash|sh|zsh|python|perl|ruby`, `eval "…"`, `python|python3|perl|ruby -c`, `bash -c`

> **Note the last bullet — it catches ordinary commands too.** `bash -c '…'`, `python3 -c '…'` and `eval …` are blocked by default even when entirely benign. Wrap them differently (a script file, a heredoc) or pass `force=true` for an audited call.

ASCII control characters (null bytes, newlines, `\x01..\x1f`, `\x7f`) are normalized to spaces before matching, so `rm\x00-rf /` is caught just like `rm -rf /`. The regex is fuzz-tested with Hypothesis on every CI run.

> **This is a TRIPWIRE, not a security boundary.** The regex catches obvious accidents and shortcut destructive commands. It does NOT defend against a motivated attacker:
> - The base64/`eval`/`-c` wrappers above are matched *literally*; any rewrite the regex does not spell out (a different decoder, a temp file, `sh <<'EOF'`) gets through
> - Shell hex escapes (`$'\x72\x6d -rf /'`) are interpreted AFTER regex matching
> - Unicode homoglyphs (Cyrillic `р`, Greek `ρ`) do not match Latin `r`
> - Indirection via `$(...)` and `` `...` `` can hide intent — those are not matched at all
>
> If you need real isolation for untrusted tool callers, sandbox at a lower layer: run ssh-mcp inside a container with a restricted SSH config, use `ForceCommand` on the managed servers, or audit `force=false` usage via the structured logs. The dangerous-command filter exists to stop LLM accidents and typos, not adversaries.

**The bypass is not recorded in the audit log.** Audit records carry `server`, `command`, `exit_code` and `duration_ms` only; `force` is emitted solely as an OpenTelemetry span attribute (`ssh.force`), and therefore only when the optional `otel` extra is installed and an exporter is configured. A block is logged as a warning on the operational logger, not the audit logger. If you need a paper trail for bypasses, export traces or withhold `force=true` at the MCP client. Do not grant `force=true` to untrusted MCP clients.

**Credential redaction in logs.** ssh-mcp automatically redacts known credential patterns (MySQL `-p<pass>`, `--password=`, `PGPASSWORD=`, `Authorization: Bearer`, URL basic-auth `user:pass@host`, plus any env var ending in `_PASSWORD`, `_SECRET`, `_TOKEN`, `_KEY`, `_CREDENTIAL`, `_PWD`) from audit logs and OTel span attributes before they reach stderr or trace backends. The asyncssh internal channel logger is suppressed to WARNING level so it never emits the raw command.

> **Known limitation: command OUTPUT is NOT redacted.** If you run `cat /etc/mysql/my.cnf`, `env | grep PASSWORD`, or `kubectl get secret X -o yaml`, the stdout/stderr returned to the MCP client will contain plaintext secrets. The redaction pipeline only filters the COMMAND string (what you asked to run), not the OUTPUT (what it printed). Avoid running commands that print secrets via ssh-mcp — pass credentials through env vars, Docker/K8s secrets, or dedicated config files instead.

**Local path confinement (new in 0.6.0; versions ≤ 0.5.6 are affected by the flaw it fixes — see [CHANGELOG.md](CHANGELOG.md)).** SFTP `upload_file` and `download_file` no longer accept arbitrary absolute local paths. Every local path is **relative to a configured transfer root** and is resolved one component at a time beneath it, refusing a symbolic link at *any* component:

```toml
[settings]
transfer_root = "~/.local/share/ssh-mcp/transfers"   # default; honours $XDG_DATA_HOME
```

Override with the `SSH_MCP_TRANSFER_ROOT` environment variable. The directory is created `0700` on demand, must be owned by the user running ssh-mcp, and must not itself be a symlink — ssh-mcp refuses to start a transfer otherwise.

Consequences, all deliberate:

- **Absolute local paths and `..` are rejected.** Sub-directories are allowed, but they must already exist.
- **Downloads do not overwrite.** An existing destination fails rather than being silently replaced. A failed transfer removes its own partial file.
- **Remote non-regular files** (symlinks, devices, FIFOs) are refused on a best-effort basis. SFTP protocol v3 offers no atomic no-follow open, so a remote server that swaps the file between the check and the open can still win that race; the *local* destination stays confined regardless.
- Remote paths keep the existing sensitive-path denylist — a tripwire, not a boundary, matched as a substring after normalizing `//` and `./` away, case-insensitively. It covers `/etc/{shadow,gshadow,passwd,sudoers}` and `/etc/ssh/ssh_host_*`; `.ssh/{authorized_keys,id_rsa,id_ed25519,id_ecdsa,id_dsa,identity,config,known_hosts}`; `.aws/{credentials,config}`, `.azure/accesstokens.json`, `.config/gcloud/{credentials,access_tokens}.db`; `.kube/config`, `/etc/kubernetes/{admin,kubelet}.conf`, `/var/lib/kubelet/pki/`; `.netrc`, `.pgpass`, `.git-credentials`, `.docker/config.json`; `/proc/{self,<pid>}/{environ,mem,cmdline,maps,stack,status}`, `/proc/{kcore,kallsyms}`; the MySQL / PostgreSQL / MongoDB data directories under `/var/lib/`; and the Windows SAM / SECURITY hives plus `\users\administrator\.ssh\`. Public keys are **not** exempt — the old `*.pub` carve-out was a string check on a caller-supplied name and was removed.

Prior versions validated the caller's path *string* against a denylist and then handed that string to asyncssh, which resolved it independently — so anything not enumerated was writable. Confinement replaces enumeration: ssh-mcp opens the local file itself and never lets a caller-supplied path reach the SFTP library.

**Migrating from ≤ 0.5.x:** replace absolute local paths with names relative to `transfer_root`, or set `transfer_root` to the directory you were already using. There is no flag to restore the old behaviour.

**Host key verification** is on by default (`known_hosts = true`). Disabling `StrictHostKeyChecking` in `~/.ssh/config` weakens MITM protection and should be avoided in production.

**Audit logging.** Every tool call is logged to stderr with `server`, `command`, `exit_code`, `duration_ms`, and (for SFTP) byte counts. SFTP operations emit three-stage events: `sftp.upload.start` → `sftp.upload.complete` (or `sftp.upload.failed`), each tagged with a stable `connection_id` so a single transfer is grep-correlatable.

For production log aggregation, set `SSH_MCP_LOG_FORMAT=json` to emit single-line JSON events:

```json
{"event": "sftp.upload.complete bytes=4096 duration_ms=183", "level": "info", "timestamp": "2026-04-08T16:00:11.761575Z", "server": "web-prod-01", "operation": "upload", "local_path": "releases/app.tar.gz", "remote_path": "/var/www/release.tar.gz", "connection_id": "web-prod-01-4242-a3f1c9d2"}
```

When running in Docker, capture stderr with `docker logs` for the audit trail.

For vulnerability reports, see [SECURITY.md](SECURITY.md). Do not open public GitHub issues for security concerns.

## Development

```bash
git clone https://github.com/blackaxgit/ssh-mcp.git
cd ssh-mcp
uv sync --locked --extra dev
uv run pytest
uv run ruff check src/ tests/
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on making changes and submitting pull requests.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

Mozilla Public License 2.0. See [LICENSE](LICENSE).
