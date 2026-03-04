"""Unit tests for SSH MCP configuration loader.

Tests cover ServerRegistry loading, validation, lookup methods, and error
handling for TOML configuration files.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from ssh_mcp.config import ServerRegistry
from ssh_mcp.models import GroupConfig, ServerConfig, Settings


class TestServerRegistryLoading:
    """Tests for ServerRegistry TOML loading."""

    def test_load_config_settings(self, tmp_config_file: Path) -> None:
        """Test settings are loaded correctly from config file."""
        registry = ServerRegistry(str(tmp_config_file))

        # Verify explicitly set settings are loaded
        assert registry.settings.ssh_config_path.endswith(".ssh/config")
        assert registry.settings.command_timeout == 30

        # Verify servers and groups exist
        servers = registry.all_servers()
        groups = registry.all_groups()

        assert len(servers) > 0
        assert len(groups) > 0

    def test_server_count_matches_fixture(self, tmp_config_file: Path) -> None:
        """Test config has expected number of servers from fixture."""
        registry = ServerRegistry(str(tmp_config_file))

        servers = registry.all_servers()

        assert len(servers) == 3

    def test_group_count_matches_fixture(self, tmp_config_file: Path) -> None:
        """Test config has expected number of groups from fixture."""
        registry = ServerRegistry(str(tmp_config_file))

        groups = registry.all_groups()

        assert len(groups) == 2

    def test_load_missing_config_raises(self) -> None:
        """Test FileNotFoundError for missing config file."""
        with pytest.raises(FileNotFoundError) as exc_info:
            ServerRegistry("/nonexistent/path/servers.toml")

        assert "not found" in str(exc_info.value).lower()

    def test_load_malformed_toml_raises(self, tmp_path: Path) -> None:
        """Test ValueError for malformed TOML."""
        malformed_file = tmp_path / "malformed.toml"
        malformed_file.write_text("[servers\ninvalid toml syntax")

        with pytest.raises(ValueError) as exc_info:
            ServerRegistry(str(malformed_file))

        assert "invalid toml" in str(exc_info.value).lower()

    def test_load_minimal_config(self, tmp_config_file: Path) -> None:
        """Test loading minimal valid config from fixture."""
        registry = ServerRegistry(str(tmp_config_file))

        assert len(registry.all_servers()) == 3
        assert len(registry.all_groups()) == 2


class TestServerRegistryLookup:
    """Tests for ServerRegistry lookup methods."""

    def test_get_server_known_server(self, tmp_config_file: Path) -> None:
        """Test get_server returns correct server from config."""
        registry = ServerRegistry(str(tmp_config_file))

        server = registry.get_server("test-web1")

        assert server.name == "test-web1"
        assert "Test web server 1" in server.description
        assert "test-prod" in server.groups

    def test_get_server_unknown_raises_keyerror(self, tmp_config_file: Path) -> None:
        """Test get_server raises KeyError for unknown server."""
        registry = ServerRegistry(str(tmp_config_file))

        with pytest.raises(KeyError) as exc_info:
            registry.get_server("nonexistent-server")

        error_msg = str(exc_info.value)
        assert "not found" in error_msg.lower()
        assert "available servers" in error_msg.lower()

    def test_get_group_known_group(self, tmp_config_file: Path) -> None:
        """Test get_group returns correct group from config."""
        registry = ServerRegistry(str(tmp_config_file))

        group = registry.get_group("test-prod")

        assert group.name == "test-prod"
        assert "production" in group.description.lower()

    def test_get_group_unknown_raises_keyerror(self, tmp_config_file: Path) -> None:
        """Test get_group raises KeyError for unknown group."""
        registry = ServerRegistry(str(tmp_config_file))

        with pytest.raises(KeyError) as exc_info:
            registry.get_group("nonexistent-group")

        error_msg = str(exc_info.value)
        assert "not found" in error_msg.lower()
        assert "available groups" in error_msg.lower()

    def test_servers_in_group_returns_correct_list(self, tmp_config_file: Path) -> None:
        """Test servers_in_group returns all servers in a group."""
        registry = ServerRegistry(str(tmp_config_file))

        servers = registry.servers_in_group("test-prod")

        assert len(servers) > 0
        # All returned servers should have test-prod in their groups
        for server in servers:
            assert "test-prod" in server.groups

    def test_servers_in_group_unknown_group_raises(self, tmp_config_file: Path) -> None:
        """Test servers_in_group raises KeyError for unknown group."""
        registry = ServerRegistry(str(tmp_config_file))

        with pytest.raises(KeyError):
            registry.servers_in_group("nonexistent-group")

    def test_all_servers_returns_list(self, tmp_config_file: Path) -> None:
        """Test all_servers returns all configured servers."""
        registry = ServerRegistry(str(tmp_config_file))

        servers = registry.all_servers()

        assert isinstance(servers, list)
        assert len(servers) == 3
        assert all(isinstance(s, ServerConfig) for s in servers)

    def test_all_groups_returns_list(self, tmp_config_file: Path) -> None:
        """Test all_groups returns all configured groups."""
        registry = ServerRegistry(str(tmp_config_file))

        groups = registry.all_groups()

        assert isinstance(groups, list)
        assert len(groups) == 2
        assert all(isinstance(g, GroupConfig) for g in groups)


class TestServerRegistryValidation:
    """Tests for ServerRegistry validation warnings."""

    def test_validation_warnings_logged(
        self, invalid_config_file: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test validation warnings are logged for invalid config."""
        with caplog.at_level(logging.WARNING):
            ServerRegistry(str(invalid_config_file))

        # Check that warnings were logged
        assert len(caplog.records) > 0

        warning_messages = [record.message for record in caplog.records]

        # Should have warning for server with no groups
        assert any("no groups" in msg.lower() for msg in warning_messages)

        # Should have warning for undefined group reference
        assert any("undefined group" in msg.lower() for msg in warning_messages)

        # Should have warning for invalid jump_host
        assert any("jump_host" in msg.lower() for msg in warning_messages)

        # Should have warning for name collision
        assert any("collides" in msg.lower() for msg in warning_messages)

    def test_server_with_jump_host_loaded_correctly(self, tmp_path: Path) -> None:
        """Test server with jump_host field is loaded correctly."""
        config_content = """
[groups]
infra = { description = "Infrastructure servers" }
app = { description = "Application servers" }

[servers.gateway]
description = "Gateway host"
groups = ["infra"]

[servers.app-server]
description = "Application server behind gateway"
groups = ["app"]
jump_host = "gateway"
"""
        config_file = tmp_path / "jump_host_servers.toml"
        config_file.write_text(config_content)
        registry = ServerRegistry(str(config_file))

        server = registry.get_server("app-server")

        assert server.jump_host == "gateway"
        assert "app" in server.groups

    def test_server_with_overrides_loaded_correctly(
        self, tmp_config_file: Path
    ) -> None:
        """Test server with SSH overrides is loaded correctly."""
        registry = ServerRegistry(str(tmp_config_file))

        server = registry.get_server("test-web2")

        assert server.hostname == "192.168.1.10"
        assert server.port == 2222
        assert server.name == "test-web2"


class TestServerRegistrySettings:
    """Tests for ServerRegistry settings loading."""

    def test_settings_property_returns_settings(self, tmp_config_file: Path) -> None:
        """Test settings property returns Settings instance."""
        registry = ServerRegistry(str(tmp_config_file))

        settings = registry.settings

        assert isinstance(settings, Settings)
        assert settings.command_timeout == 30

    def test_settings_defaults_applied_when_not_overridden(
        self, tmp_config_file: Path
    ) -> None:
        """Test that unspecified settings receive correct default values."""
        registry = ServerRegistry(str(tmp_config_file))

        settings = registry.settings

        # These fields are not set in tmp_config_file, so defaults apply
        assert settings.max_output_bytes == 51200
        assert settings.connection_idle_timeout == 300

    def test_settings_ssh_config_path_expanded(self, tmp_config_file: Path) -> None:
        """Test tilde expansion in ssh_config_path."""
        registry = ServerRegistry(str(tmp_config_file))

        # Path should be expanded (not contain ~)
        assert not registry.settings.ssh_config_path.startswith("~")
        assert ".ssh/config" in registry.settings.ssh_config_path
