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

import os
from dataclasses import dataclass as stdlib_dataclass

from pydantic import ConfigDict, Field, field_validator
from pydantic.dataclasses import dataclass as pyd_dataclass

from ssh_mcp.paths import default_transfer_root


def _expand(value: str | None) -> str | None:
    """Expand a leading ``~`` in a path-valued field.

    Applied at the *model* boundary rather than at call sites. Expansion used
    to live in the config loader and ran only when a ``[settings]`` block was
    present, so a minimal ``servers.toml`` left the default
    ``"~/.ssh/config"`` unexpanded and every connection died with
    ``FileNotFoundError: '~/.ssh/config'``. ``identity_file`` was never
    expanded anywhere at all. Doing it here means every path field gets it
    exactly once, whatever route the value arrived by.
    """
    return os.path.expanduser(value) if value else value


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
        max_output_bytes: Maximum **bytes** to capture from command output.
            This is a genuine byte bound, and it bounds *allocation*, not
            merely the response: output is consumed incrementally and the
            process is terminated once the budget is spent. Previously the
            check was character-based (``len(str)``) and ran only after
            asyncssh had already buffered the entire output, so a multibyte
            stream overran the stated limit ~4x and a large ``cat`` could
            exhaust memory regardless of the setting.
        max_command_bytes: Maximum length of a command string accepted by the
            execute tools. Enforced at the MCP tool boundary before the
            command reaches redaction or dangerous-command matching, both of
            which are superlinear in input length and, since Python's ``re``
            has no timeout, cannot bound themselves.
        transfer_root: Directory that SFTP transfers are confined to. All
            local paths passed to ``upload_file``/``download_file`` are
            resolved beneath it, refusing symlinks at every component.
            Defaults under ``$XDG_DATA_HOME`` (or ``~/.local/share``);
            override with the ``SSH_MCP_TRANSFER_ROOT`` environment variable.
        connection_idle_timeout: Seconds before idle connection is closed
        known_hosts: Whether to enforce strict known_hosts checking
        max_parallel_hosts: Maximum concurrent SSH connections during
            group execution. Bounded to 1..100 to prevent accidentally
            exhausting file descriptors or triggering fleet-wide load spikes.
    """

    # ``validate_default=True`` is load-bearing on the path fields: pydantic
    # does not run validators on defaults otherwise, which is precisely how
    # the unexpanded ``~/.ssh/config`` default survived (finding S5).
    ssh_config_path: str = Field(default="~/.ssh/config", validate_default=True)
    command_timeout: int = Field(default=30, ge=1, le=3600)
    max_output_bytes: int = Field(default=51200, ge=1024, le=10_485_760)
    max_command_bytes: int = Field(default=65536, ge=1024, le=1_048_576)
    transfer_root: str = Field(
        default_factory=default_transfer_root, validate_default=True
    )
    connection_idle_timeout: int = Field(default=300, ge=10)
    known_hosts: bool = True
    max_parallel_hosts: int = Field(default=10, ge=1, le=100)

    @field_validator("ssh_config_path", "transfer_root")
    @classmethod
    def _expand_paths(cls, value: str) -> str:
        # Inlined rather than delegating to the Optional-returning ``_expand``
        # helper: that needed an ``assert`` to satisfy the non-optional return
        # type, and asserts are stripped under ``python -O`` (bandit B101).
        #
        # Made absolute as well as expanded: a relative value (from TOML, the
        # env override, or a relative XDG_DATA_HOME) would otherwise bind to
        # whatever the process CWD happens to be when the root is pinned, so
        # the confinement boundary could move with the launcher.
        if not value:
            return value
        return os.path.abspath(os.path.expanduser(value))


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

    @field_validator("identity_file")
    @classmethod
    def _expand_identity_file(cls, value: str | None) -> str | None:
        # Passed straight to asyncssh's ``client_keys``, which does no ``~``
        # expansion of its own — so an unexpanded value silently fails to
        # authenticate rather than erroring usefully.
        return _expand(value)


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
