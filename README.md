# ssh-mcp

SSH MCP server for managing infrastructure via Claude Code.

## Install

```bash
# Install uv if needed: https://docs.astral.sh/uv/getting-started/installation/
claude mcp add ssh-mcp -- uvx ssh-mcp
```

## Configuration

Create `~/.config/ssh-mcp/servers.toml`:

```toml
[settings]
ssh_config_path = "~/.ssh/config"
command_timeout = 30

[servers.prod-web]
description = "Production web server"
groups = ["production"]

[servers.dev-web]
description = "Development web server"
groups = ["development"]

[groups]
production = { description = "Production servers" }
development = { description = "Development servers" }
```

Server names must match SSH config `Host` entries. Connection details (host, port, user, key) are read from `~/.ssh/config`.

## Tools

- `list_servers` — Show all configured servers with descriptions and groups
- `list_groups` — Show all server groups
- `execute` — Run command on a single server
- `execute_on_group` — Run command on all servers in a group
- `upload_file` — Upload file to server
- `download_file` — Download file from server

## Development

```bash
git clone https://github.com/blackaxgit/ssh-mcp.git
cd ssh-mcp
uv sync && uv run ssh-mcp
```
