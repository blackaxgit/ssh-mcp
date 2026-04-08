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

Config file location (checked in order):

1. `$SSH_MCP_CONFIG` environment variable
2. `~/.config/ssh-mcp/servers.toml` (default)
3. `config/servers.toml` relative to the package (development only)

Example `servers.toml`:

```toml
[settings]
ssh_config_path = "~/.ssh/config"
command_timeout = 30
max_output_bytes = 51200
connection_idle_timeout = 300
known_hosts = true

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

ssh-mcp blocks commands that match known destructive patterns (`rm -rf /`, disk wipes, fork bombs, `mkfs`, etc.) unless the tool caller passes `force=true`. Control characters (null bytes, newlines) are normalized before pattern matching to prevent trivial regex bypasses.

SFTP operations validate BOTH remote and local paths to prevent reading/writing sensitive files on either side: `/etc/shadow`, `/etc/passwd`, `~/.ssh/id_*`, `~/.ssh/authorized_keys`, and any path containing `..` traversal.

Host key verification is on by default (`known_hosts = true`). Disabling `StrictHostKeyChecking` in `~/.ssh/config` weakens MITM protection and should be avoided in production.

All tool calls are audit-logged to stderr with: server, command, exit code, duration, and transfer byte counts. When running in Docker, capture stderr with `docker logs` for your audit trail.

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
