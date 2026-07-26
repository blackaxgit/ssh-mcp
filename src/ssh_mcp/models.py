"""Data models for SSH MCP server.

This module defines immutable configuration models using Pydantic v2
dataclasses with ``extra='forbid'`` strict key validation, plus a mutable
``ExecResult`` stdlib dataclass used to shuttle execution output.

Pydantic validates at construction time, so:
  * Unknown TOML keys raise a ``ValidationError`` that names the offender —
    the config loader converts this into a ``ConfigError`` carrying the
    section label plus, for the per-entity sections, the host / group name,
    and appends the list of valid keys itself via ``_valid_keys``.
  * Numeric ranges (``command_timeout``, ``max_output_bytes``,
    ``max_command_bytes``, ``max_parallel_hosts``, ``ServerConfig.port``,
    ``ServerConfig.timeout``) are enforced by ``Field(ge=..., le=...)``, and
    ``connection_idle_timeout`` by a lower bound alone — no manual
    ``__post_init__`` guards needed.
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
        command_timeout: Timeout in seconds for *establishing* a connection —
            it wraps ``asyncssh.connect`` and nothing else. It does NOT bound
            command execution: that comes from the ``timeout`` parameter of
            the execute tools (default 30s), overridden per server by
            ``ServerConfig.timeout``. Raising this will not keep a long
            command alive.
        max_output_bytes: Maximum **bytes** to capture from command output,
            applied to stdout and stderr *independently* rather than as a
            shared pool, so the combined worst case is 2x this setting — an
            accepted trade-off that mirrors the pre-S10 ``conn.run()``
            semantics.
            This is a genuine byte bound, and it bounds *allocation*, not
            merely the response: output is consumed incrementally and the
            process is terminated once the budget is spent. Previously the
            check was character-based (``len(str)``) and ran only after
            asyncssh had already buffered the entire output, so a multibyte
            stream overran the stated limit ~4x and a large ``cat`` could
            exhaust memory regardless of the setting. A
            ``[... output truncated at N bytes]`` marker is appended *after*
            the cut, so a truncated stream's returned string is a little
            longer than the budget itself.
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
            ``paths.ensure_root`` pins it on the first transfer and fails
            closed unless the platform offers POSIX ``openat``/``O_NOFOLLOW``
            (non-POSIX platforms therefore refuse *all* transfers) and the
            root is a real directory rather than a symlink, owned by the
            running uid, with mode ``0700`` — any group or other bit raises
            ``PathConfinementError``.
        connection_idle_timeout: Seconds before idle connection is closed
        known_hosts: Whether to enforce strict known_hosts checking
        max_parallel_hosts: Maximum concurrent in-flight ``execute()`` calls
            under group execution. The semaphore is built once per
            ``SSHManager``, so the bound is process-wide: independent
            ``execute_on_group()`` calls serialise against each other instead
            of each receiving their own budget (an intentional behaviour
            change). It caps executions, not pooled connections — entries in
            ``_connections`` outlive the semaphore release until the idle
            reaper closes them, so open descriptors can still exceed this
            number. Bounded to 1..100 to keep fleet-wide load spikes and
            descriptor growth in check.
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

    Every optional override except ``groups`` defaults to None, allowing SSH
    config file or system defaults to take precedence; ``groups`` defaults to
    an empty tuple.

    Attributes:
        name: Unique server identifier (SSH host alias)
        description: Human-readable server description
        groups: Tuple of group names this server belongs to
        hostname: Override SSH config hostname
        port: Override SSH config port (1..65535)
        user: Override SSH config user
        identity_file: Override SSH config identity file path
        jump_host: Override SSH config ProxyJump/bastion host
        default_dir: Default working directory for commands
        timeout: Override command timeout for this server, in seconds
            (1..3600)
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

    ExecResult is returned by execute() and execute_on_group(), which embed
    every ordinary error in the ``error`` field rather than raising. That
    promise is strong but not absolute: the broad handler in
    ``_execute_impl`` is ``except Exception``, so ``asyncio.CancelledError``
    still propagates out of execute() — which is exactly why
    execute_on_group() normalises any ``BaseException`` from a child task into
    an error-carrying ExecResult of its own.
    - ``error is None`` + ``exit_code >= 0``: the command ran to completion. A
      non-zero code is an ordinary command failure, not an execution failure.
      A ``dry_run`` preview also lands here, with ``exit_code=0`` and the
      preview text in ``stdout``.
    - ``error is None`` + ``exit_code == -1``: the remote process was killed by
      a signal — asyncssh reports -1 for an exit signal. Most commonly our own
      terminate() after the output budget was spent, so ``stdout``/``stderr``
      carry the truncation marker.
    - ``error is None`` + ``exit_code is None``: should not happen
    - ``error is not None`` + ``exit_code is None``: execution failed (SSH error,
      timeout, server not found, blocked by dangerous-command tripwire, cancelled
      by fail_fast)

    Every path that sets ``error`` also sets ``exit_code=None``, so
    ``error is not None`` alongside a numeric ``exit_code`` never occurs.

    SFTP operations (``SSHManager.upload``/``download``, surfaced as the
    ``upload_file``/``download_file`` MCP tools) follow a DIFFERENT contract:
    they RAISE ValueError or RuntimeError on failure. The _mcp_tool decorator
    converts those into ToolError for the MCP protocol, but re-raises an
    already-raised ToolError and ``asyncio.CancelledError`` unchanged.

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
