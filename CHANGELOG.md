# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-04-08

### Added

- `max_parallel_hosts` setting in `[settings]` — configurable concurrency cap for `execute_on_group` (default 10, range 1–100). Previously hardcoded to 10.
- `SSH_MCP_LOG_FORMAT` environment variable — set to `json` for single-line JSON logs (timestamp, level, event, contextvars) suitable for log aggregators. Defaults to colorized human-readable console output.
- `structlog 25.5+` and `orjson 3.10+` as runtime dependencies for structured logging.
- `ConfigError` exception class (subclass of `ValueError`) raised on TOML parse errors, unknown keys, and missing required fields — surfaces the offending key, the section, and the list of valid keys in a single actionable message.
- Docker support: multi-stage `Dockerfile` (python:3.13-slim-trixie + uv) and `compose.yaml` for stdio transport
- Prebuilt Docker image published to `ghcr.io/blackaxgit/ssh-mcp:latest` on main branch merges
- `force` parameter on `execute_on_group` MCP tool (already existed on `execute`) — bypass dangerous-command detection for trusted bulk operations
- Local path validation in `upload_file` and `download_file` — blocks reading/writing sensitive files on the MCP host (`/etc/shadow`, SSH keys, path traversal)
- CI/CD: mypy strict type checking, `pip-audit` dependency scanning, `bandit` security analysis, `pytest-cov` coverage reporting, Trivy container scanning
- Tests for MCP tool functions (`tests/test_server.py`) covering all 6 tools, lazy init race, and error passthrough
- Tests for circular jump-host detection
- Tests for `_is_dangerous_command` bypass attempts (null bytes, control characters, Unicode)
- Range validation in `Settings.__post_init__` — rejects negative `command_timeout`, `max_output_bytes < 1024`, `connection_idle_timeout < 10`, and `max_parallel_hosts` outside `1..100`.

### Changed

- MCP tool error handling consolidated into a single `@_mcp_tool` decorator, eliminating ~90 lines of duplicated `try / except ToolError / except Exception` boilerplate across the 6 tools. Tracebacks are now logged with `exc_info=True`.
- MCP tools now raise `ToolError` on failure instead of returning error strings — proper MCP protocol error signalling with `isError=true`
- `_init()` is now async with `asyncio.Lock` double-checked locking to prevent duplicate initialization under concurrent tool calls
- `_cleanup_connections()` no longer crashes when called while an event loop is running
- Connection eviction loop re-checks idle time inside the per-server lock to prevent TOCTOU races
- `execute_on_group` fail_fast path now drains cancelled tasks with `asyncio.gather(..., return_exceptions=True)` to prevent coroutine leaks
- `format_group_results` explicitly counts `exit_code=None` as failed with a clear `is_success` variable
- `_is_dangerous_command` normalizes ASCII control characters before regex matching to prevent null-byte bypass
- `asyncssh` upper bound added to dependencies: `>=2.14.0,<3.0.0`
- CI pipeline updated to 2026 best practices: `actions/checkout@v6`, `astral-sh/setup-uv@v8.0.0`, `docker/build-push-action@v7`, Trivy pinned by commit SHA

### Fixed

- Unknown TOML keys in `[settings]`, `[groups.*]`, or `[servers.*]` now surface the offending key name AND the list of valid keys, instead of crashing with an opaque `TypeError: unexpected keyword argument`.
- TOML parse errors now include the configuration file path in the error message for faster diagnosis.
- Missing `description` field on a server or group now raises `ConfigError` instead of `KeyError`.
- Dockerfile: use `--no-editable` in `uv sync` so the `ssh_mcp` package is copied into site-packages (previously editable install left a dangling `.pth` file pointing to `/app/src` which doesn't exist in the runtime stage)
- Dockerfile: use same `/app` WORKDIR in builder and runtime stages so console script shebangs resolve correctly
- Dockerfile: HEALTHCHECK uses `python -c "import ssh_mcp"` instead of `ps aux | grep` (the slim image has no `ps` binary)
- Server logs startup banner and config path so operators know the stdio server is ready even before the first tool call
- Eviction loop inconsistent state: `_running = True` now set AFTER `create_task` succeeds

### Security

- Fixed missing local path validation on SFTP upload/download — previously an LLM caller could exfiltrate `/etc/shadow` or SSH keys from the MCP host
- Fixed `asyncio.run()` in atexit handler that could crash or silently fail, leaving SSH connections open after shutdown
- Eliminated race condition in lazy server initialization that could create duplicate `SSHManager` instances and leak connections
- Fixed null-byte and control-character bypass in dangerous command detection (`rm\x00-rf /` was not caught by the regex)

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

[Unreleased]: https://github.com/blackaxgit/ssh-mcp/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/blackaxgit/ssh-mcp/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/blackaxgit/ssh-mcp/releases/tag/v0.1.0
