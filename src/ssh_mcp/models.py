"""Data models for SSH MCP server.

This module defines immutable configuration models using Pydantic v2
dataclasses with ``extra='forbid'`` strict key validation, plus a mutable
``ExecResult`` stdlib dataclass used to shuttle execution output.

Pydantic validates at construction time, so:
  * Unknown TOML keys raise a ``ValidationError`` that names the offender
    and lists valid fields — the config loader converts this into a
    ``ConfigError`` with section / host context.
  * Numeric ranges (``command_timeout``, ``max_output_bytes``,
    ``connection_idle_timeout``, ``max_parallel_hosts``) are enforced by
    ``Field(ge=..., le=...)`` — no manual ``__post_init__`` guards needed.
"""

from __future__ import annotations

from dataclasses import dataclass as stdlib_dataclass

from pydantic import ConfigDict, Field
from pydantic.dataclasses import dataclass as pyd_dataclass

# Strict config: unknown keys rejected, frozen instances cannot be mutated.
# ``validate_assignment=True`` is omitted because the classes are frozen —
# assignment is already blocked at the dataclass level.
_STRICT: ConfigDict = ConfigDict(extra="forbid")


@pyd_dataclass(frozen=True, config=_STRICT)
class Settings:
    """Global settings for SSH operations.

    Attributes:
        ssh_config_path: Path to SSH config file (supports ~ expansion)
        command_timeout: Default command execution timeout in seconds
        max_output_bytes: Maximum characters to capture from command output.
            Named "bytes" for historical reasons but the enforcement is
            character-based (``len(str)``), not byte-based. For ASCII
            output the two are equivalent; for multibyte (CJK, emoji)
            the actual byte size may exceed this limit.
        connection_idle_timeout: Seconds before idle connection is closed
        known_hosts: Whether to enforce strict known_hosts checking
        max_parallel_hosts: Maximum concurrent SSH connections during
            group execution. Bounded to 1..100 to prevent accidentally
            exhausting file descriptors or triggering fleet-wide load spikes.
    """

    ssh_config_path: str = "~/.ssh/config"
    command_timeout: int = Field(default=30, ge=1, le=3600)
    max_output_bytes: int = Field(default=51200, ge=1024, le=10_485_760)
    connection_idle_timeout: int = Field(default=300, ge=10)
    known_hosts: bool = True
    max_parallel_hosts: int = Field(default=10, ge=1, le=100)


@pyd_dataclass(frozen=True, config=_STRICT)
class GroupConfig:
    """Configuration for a logical server group.

    Groups allow organizing servers by environment, function, or team.

    Attributes:
        name: Unique group identifier
        description: Human-readable description of the group's purpose
    """

    name: str
    description: str


@pyd_dataclass(frozen=True, config=_STRICT)
class ServerConfig:
    """Configuration for a managed SSH server.

    All optional overrides default to None, allowing SSH config file or
    system defaults to take precedence.

    Attributes:
        name: Unique server identifier (SSH host alias)
        description: Human-readable server description
        groups: Tuple of group names this server belongs to
        hostname: Override SSH config hostname
        port: Override SSH config port
        user: Override SSH config user
        identity_file: Override SSH config identity file path
        jump_host: Override SSH config ProxyJump/bastion host
        default_dir: Default working directory for commands
        timeout: Override command timeout for this server
    """

    name: str
    description: str
    groups: tuple[str, ...] = ()
    hostname: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    user: str | None = None
    identity_file: str | None = None
    jump_host: str | None = None
    default_dir: str | None = None
    timeout: int | None = Field(default=None, ge=1, le=3600)


@stdlib_dataclass
class ExecResult:
    """Result from executing a command on a remote server.

    Mutable to allow construction during execution. This remains a stdlib
    dataclass because it is never loaded from user input — it is always
    constructed from trusted ``asyncssh`` output — and Pydantic validation
    would add runtime cost for every command execution.

    ExecResult is returned by execute() and execute_on_group() — these methods
    NEVER raise exceptions. All errors are embedded in the ``error`` field:
    - ``error is None`` + ``exit_code >= 0``: command succeeded
    - ``error is None`` + ``exit_code is None``: should not happen
    - ``error is not None`` + ``exit_code is None``: execution failed (SSH error,
      timeout, server not found, blocked by dangerous-command tripwire, cancelled
      by fail_fast)
    - ``error is not None`` + ``exit_code >= 0``: command ran but had issues

    SFTP operations (upload_file, download_file) follow a DIFFERENT contract:
    they RAISE ValueError or RuntimeError on failure. The _mcp_tool decorator
    converts all exceptions to ToolError for the MCP protocol.

    Attributes:
        server: Server name where command was executed
        command: The command that was executed
        stdout: Standard output captured from command
        stderr: Standard error captured from command
        exit_code: Process exit code (None if execution failed)
        error: Error message if execution failed
        duration_ms: Command execution duration in milliseconds
    """

    server: str
    command: str
    stdout: str
    stderr: str
    exit_code: int | None
    error: str | None = None
    duration_ms: int = 0
