# ssh-mcp

SSH MCP server that lets AI assistants execute commands on remote servers.

[![PyPI version](https://img.shields.io/pypi/v/ssh-mcp)](https://pypi.org/project/ssh-mcp/)
[![Python versions](https://img.shields.io/pypi/pyversions/ssh-mcp)](https://pypi.org/project/ssh-mcp/)
[![License: MPL-2.0](https://img.shields.io/badge/License-MPL--2.0-brightgreen.svg)](LICENSE)

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

```bash
claude mcp add ssh-mcp -- uvx ssh-mcp
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
| `execute` | Run a shell command on a single server |
| `execute_on_group` | Run a command on all servers in a group (parallel) |
| `upload_file` | Upload a local file to a server via SFTP |
| `download_file` | Download a file from a server via SFTP |

## Security

ssh-mcp warns before running commands that match known destructive patterns (`rm -rf`, disk wipes, shutdown). These are informational warnings — the AI assistant can still proceed if the operator confirms. Hard blocking is not enforced by design; access control is the operator's responsibility via SSH permissions on the target host.

Host key verification is on by default (`known_hosts = true`). Disabling `StrictHostKeyChecking` in `~/.ssh/config` weakens MITM protection and should be avoided in production.

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
