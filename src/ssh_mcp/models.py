"""Data models for SSH MCP server.

This module defines immutable configuration and result models using dataclasses.
All configuration models are frozen to ensure immutability.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    """Global settings for SSH operations.

    Attributes:
        ssh_config_path: Path to SSH config file (supports ~ expansion)
        command_timeout: Default command execution timeout in seconds
        max_output_bytes: Maximum bytes to capture from command output
        connection_idle_timeout: Seconds before idle connection is closed
        known_hosts: Whether to enforce strict known_hosts checking
    """

    ssh_config_path: str = "~/.ssh/config"
    command_timeout: int = 30
    max_output_bytes: int = 51200
    connection_idle_timeout: int = 300
    known_hosts: bool = True


@dataclass(frozen=True)
class GroupConfig:
    """Configuration for a logical server group.

    Groups allow organizing servers by environment, function, or team.

    Attributes:
        name: Unique group identifier
        description: Human-readable description of the group's purpose
    """

    name: str
    description: str


@dataclass(frozen=True)
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
    port: int | None = None
    user: str | None = None
    identity_file: str | None = None
    jump_host: str | None = None
    default_dir: str | None = None
    timeout: int | None = None


@dataclass
class ExecResult:
    """Result from executing a command on a remote server.

    Mutable to allow construction during execution.

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
