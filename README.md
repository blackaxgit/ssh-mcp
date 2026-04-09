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

The image uses a non-root `sshmcp` user (uid 1000). Mount your SSH keys and config file read-only. See [compose.yaml](compose.yaml) in the repo for a working example.

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
| `SSH_MCP_HTTP_TOKEN` | — | Shared bearer secret. When set, every request must carry `Authorization: Bearer <token>` (scheme case-insensitive per RFC 7235) or receive HTTP 401. Mandatory for non-localhost binds. Minimum length 16 characters — shorter tokens are rejected at startup. Leading/trailing whitespace is stripped so `.env` files with trailing newlines work as expected. |
| `SSH_MCP_HTTP_STATELESS` | `false` | Set to `true` for stateless sessions (recommended for load-balanced or serverless deployments). Default is stateful with server-side sessions. |
| `SSH_MCP_HTTP_ALLOWED_HOSTS` | — | Comma-separated extra Host-header values the SDK's DNS-rebinding protection should permit (e.g. `ssh-mcp.internal:*,api.example.com:8000`). Localhost aliases are always permitted. |
| `HYPOTHESIS_PROFILE` | `dev` | For local development / CI only. Set to `ci` to run property-based tests with `max_examples=200` instead of `50`. |

### Running over HTTP

ssh-mcp exposes the MCP streamable HTTP transport as an alternative to stdio. This lets MCP-aware clients connect over the network instead of launching a subprocess, which is useful for containerized deployments, shared-team servers, or anything that needs to survive a client restart.

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

### Config file location

Checked in order:

1. `$SSH_MCP_CONFIG` environment variable
2. `~/.config/ssh-mcp/servers.toml` (default)
3. `config/servers.toml` relative to the package (development only)

Example `servers.toml`:

```toml
[settings]
ssh_config_path = "~/.ssh/config"
command_timeout = 30          # seconds, range 1..3600
max_output_bytes = 51200      # truncate captured output at this many bytes
connection_idle_timeout = 300 # seconds; eviction scan runs every 60s
known_hosts = true            # false removes MITM protection
max_parallel_hosts = 10       # concurrency cap for execute_on_group (1..100)

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

Per-server overrides (`user`, `jump_host`) take precedence over `~/.ssh/config`. See [config/servers.example.toml](config/servers.example.toml) for the full reference.

Restrict config file permissions to your user:

```bash
chmod 600 ~/.config/ssh-mcp/servers.toml
```

## Available Tools

| Tool | Description |
|------|-------------|
| `list_servers` | List configured servers; optionally filter by group |
| `list_groups` | List server groups with member counts |
| `execute` | Run a shell command on a single server (supports `force` to bypass dangerous-command detection) |
| `execute_on_group` | Run a command on all servers in a group (parallel; supports `fail_fast` and `force`) |
| `upload_file` | Upload a local file to a server via SFTP (validates both local and remote paths) |
| `download_file` | Download a file from a server via SFTP (validates both local and remote paths) |

## Security

**Dangerous command blocking.** ssh-mcp rejects commands that match known destructive patterns — `rm -rf /`, `rm -rf ~`, `find / -delete`, `find / -exec rm`, `shred /dev/*`, `wipefs /dev/*`, `mkfs`, `dd if=...`, `> /dev/sd*`, `chmod 777 /`, fork bombs (spaced and adjacent variants) — unless the tool caller passes `force=true`. ASCII control characters (null bytes, newlines, `\x01..\x1f`, `\x7f`) are normalized to spaces before matching, so `rm\x00-rf /` is caught just like `rm -rf /`. The regex is fuzz-tested with Hypothesis on every CI run.

> **This is a TRIPWIRE, not a security boundary.** The regex catches obvious accidents and shortcut destructive commands. It does NOT defend against a motivated attacker:
> - Base64-encoded payloads (`echo <b64> | base64 -d | bash`) bypass by design
> - Shell hex escapes (`$'\x72\x6d -rf /'`) are interpreted AFTER regex matching
> - Unicode homoglyphs (Cyrillic `р`, Greek `ρ`) do not match Latin `r`
> - Indirection via `$(...)`, `` `...` ``, `eval`, `python -c`, etc. can hide intent
>
> If you need real isolation for untrusted tool callers, sandbox at a lower layer: run ssh-mcp inside a container with a restricted SSH config, use `ForceCommand` on the managed servers, or audit `force=false` usage via the structured logs. The dangerous-command filter exists to stop LLM accidents and typos, not adversaries.

When `force=true` is used, the audit log records the bypass explicitly so the operator has a clean paper trail. Do not grant `force=true` to untrusted MCP clients.

**Path validation.** SFTP `upload_file` and `download_file` validate **both** remote and local paths. Any of these block the transfer:

- Sensitive Unix paths: `/etc/shadow`, `/etc/passwd`
- SSH key material: `~/.ssh/authorized_keys`, `~/.ssh/id_rsa`, `~/.ssh/id_ed25519`, `~/.ssh/id_ecdsa`, `~/.ssh/id_dsa`
- Any path containing `..` (parent traversal)

This prevents an LLM client from exfiltrating secrets on either the MCP host or a managed server.

**Host key verification** is on by default (`known_hosts = true`). Disabling `StrictHostKeyChecking` in `~/.ssh/config` weakens MITM protection and should be avoided in production.

**Audit logging.** Every tool call is logged to stderr with `server`, `command`, `exit_code`, `duration_ms`, and (for SFTP) byte counts. SFTP operations emit three-stage events: `sftp.upload.start` → `sftp.upload.complete` (or `sftp.upload.failed`), each tagged with a stable `connection_id` so a single transfer is grep-correlatable.

For production log aggregation, set `SSH_MCP_LOG_FORMAT=json` to emit single-line JSON events:

```json
{"event": "sftp.upload.complete bytes=4096 duration_ms=183", "level": "info", "timestamp": "2026-04-08T16:00:11.761575Z", "server": "web-prod-01", "operation": "upload", "local_path": "/tmp/app.tar.gz", "remote_path": "/var/www/release.tar.gz", "connection_id": "web-prod-01-4242-a3f1c9d2"}
```

When running in Docker, capture stderr with `docker logs` for the audit trail.

For vulnerability reports, see [SECURITY.md](SECURITY.md). Do not open public GitHub issues for security concerns.

## Development

```bash
git clone https://github.com/blackaxgit/ssh-mcp.git
cd ssh-mcp
uv sync --extra dev
uv run pytest
uv run ruff check .
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on making changes and submitting pull requests.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

Mozilla Public License 2.0. See [LICENSE](LICENSE).
