"""Unit tests for SSH MCP data models.

Tests cover Settings, GroupConfig, ServerConfig, and ExecResult dataclasses,
including defaults, custom values, immutability, and field validation.
"""

from __future__ import annotations

import pytest

from ssh_mcp.models import ExecResult, GroupConfig, ServerConfig, Settings


class TestSettings:
    """Tests for Settings dataclass."""

    def test_settings_defaults(self) -> None:
        """Test Settings uses correct default values."""
        settings = Settings()

        assert settings.ssh_config_path == "~/.ssh/config"
        assert settings.command_timeout == 30
        assert settings.max_output_bytes == 51200
        assert settings.connection_idle_timeout == 300
        assert settings.known_hosts is True

    def test_settings_custom_values(self) -> None:
        """Test Settings accepts custom values."""
        settings = Settings(
            ssh_config_path="/custom/path/config",
            command_timeout=60,
            max_output_bytes=102400,
            connection_idle_timeout=600,
            known_hosts=True,
        )

        assert settings.ssh_config_path == "/custom/path/config"
        assert settings.command_timeout == 60
        assert settings.max_output_bytes == 102400
        assert settings.connection_idle_timeout == 600
        assert settings.known_hosts is True

    def test_settings_frozen(self) -> None:
        """Test Settings is immutable (frozen)."""
        settings = Settings()

        with pytest.raises(AttributeError):
            settings.command_timeout = 60  # type: ignore[misc]

    def test_settings_partial_override(self) -> None:
        """Test Settings allows partial field override."""
        settings = Settings(command_timeout=120)

        assert settings.command_timeout == 120
        # Other fields should retain defaults
        assert settings.ssh_config_path == "~/.ssh/config"
        assert settings.max_output_bytes == 51200


class TestGroupConfig:
    """Tests for GroupConfig dataclass."""

    def test_group_creation(self) -> None:
        """Test GroupConfig creation with required fields."""
        group = GroupConfig(name="prod", description="Production servers")

        assert group.name == "prod"
        assert group.description == "Production servers"

    def test_group_frozen(self) -> None:
        """Test GroupConfig is immutable (frozen)."""
        group = GroupConfig(name="prod", description="Production servers")

        with pytest.raises(AttributeError):
            group.description = "New description"  # type: ignore[misc]


class TestServerConfig:
    """Tests for ServerConfig dataclass."""

    def test_server_minimal_fields(self) -> None:
        """Test ServerConfig with only required fields."""
        server = ServerConfig(name="web1", description="Web server 1")

        assert server.name == "web1"
        assert server.description == "Web server 1"
        assert server.groups == ()
        assert server.hostname is None
        assert server.port is None
        assert server.user is None
        assert server.identity_file is None
        assert server.jump_host is None
        assert server.default_dir is None
        assert server.timeout is None

    def test_server_with_groups(self) -> None:
        """Test ServerConfig with groups."""
        server = ServerConfig(
            name="web1",
            description="Web server 1",
            groups=("prod", "web"),
        )

        assert server.groups == ("prod", "web")
        assert len(server.groups) == 2

    def test_server_all_optional_overrides(self) -> None:
        """Test ServerConfig with all optional fields."""
        server = ServerConfig(
            name="web1",
            description="Web server 1",
            groups=("prod",),
            hostname="192.168.1.10",
            port=2222,
            user="deploy",
            identity_file="~/.ssh/deploy_key",
            jump_host="bastion",
            default_dir="/var/www",
            timeout=60,
        )

        assert server.hostname == "192.168.1.10"
        assert server.port == 2222
        assert server.user == "deploy"
        assert server.identity_file == "~/.ssh/deploy_key"
        assert server.jump_host == "bastion"
        assert server.default_dir == "/var/www"
        assert server.timeout == 60

    def test_server_frozen(self) -> None:
        """Test ServerConfig is immutable (frozen)."""
        server = ServerConfig(name="web1", description="Web server 1")

        with pytest.raises(AttributeError):
            server.description = "New description"  # type: ignore[misc]

    def test_server_empty_groups(self) -> None:
        """Test ServerConfig with explicit empty groups tuple."""
        server = ServerConfig(
            name="web1",
            description="Web server 1",
            groups=(),
        )

        assert server.groups == ()
        assert len(server.groups) == 0


class TestExecResult:
    """Tests for ExecResult dataclass."""

    def test_exec_result_creation(self) -> None:
        """Test ExecResult creation with all fields."""
        result = ExecResult(
            server="web1",
            command="uptime",
            stdout="up 142 days",
            stderr="",
            exit_code=0,
            duration_ms=150,
        )

        assert result.server == "web1"
        assert result.command == "uptime"
        assert result.stdout == "up 142 days"
        assert result.stderr == ""
        assert result.exit_code == 0
        assert result.error is None
        assert result.duration_ms == 150

    def test_exec_result_with_error(self) -> None:
        """Test ExecResult with error message."""
        result = ExecResult(
            server="web1",
            command="invalid-cmd",
            stdout="",
            stderr="",
            exit_code=None,
            error="Command not found",
            duration_ms=5,
        )

        assert result.error == "Command not found"
        assert result.exit_code is None

    def test_exec_result_mutable(self) -> None:
        """Test ExecResult is mutable (not frozen)."""
        result = ExecResult(
            server="web1",
            command="uptime",
            stdout="",
            stderr="",
            exit_code=0,
        )

        # Should allow modification
        result.stdout = "up 142 days"
        result.duration_ms = 200

        assert result.stdout == "up 142 days"
        assert result.duration_ms == 200

    def test_exec_result_default_duration(self) -> None:
        """Test ExecResult default duration_ms is 0."""
        result = ExecResult(
            server="web1",
            command="uptime",
            stdout="",
            stderr="",
            exit_code=0,
        )

        assert result.duration_ms == 0

    def test_exec_result_with_stderr(self) -> None:
        """Test ExecResult with stderr output."""
        result = ExecResult(
            server="web1",
            command="cat missing.txt",
            stdout="",
            stderr="cat: missing.txt: No such file or directory",
            exit_code=1,
            duration_ms=10,
        )

        assert result.stderr == "cat: missing.txt: No such file or directory"
        assert result.exit_code == 1
