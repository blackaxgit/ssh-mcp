# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-03-01

### Added

- SSH command execution via `execute` tool — run shell commands on a single configured server
- Parallel execution via `execute_on_group` tool — run a command across all servers in a named group
- SFTP file upload via `upload_file` tool
- SFTP file download via `download_file` tool
- Server inventory via `list_servers` and `list_groups` tools
- TOML-based server configuration at `~/.config/ssh-mcp/servers.toml`
- Server groups for organizing hosts (e.g., production, staging, development)
- Connection pooling — reuses SSH connections across tool calls for performance
- Dangerous command detection — warns before executing destructive commands such as `rm -rf`, disk wipes, and shutdown operations
- SSH config integration — reads host, port, user, and key from `~/.ssh/config`; no credentials stored in the MCP config
- Tilde expansion for config file paths
- Packaged for distribution via PyPI; installable with `uvx ssh-mcp`

[Unreleased]: https://github.com/blackaxgit/ssh-mcp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/blackaxgit/ssh-mcp/releases/tag/v0.1.0
