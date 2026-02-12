"""Configuration loader for SSH MCP server.

This module provides the ServerRegistry class that loads and validates
server/group configuration from a TOML file, providing convenient lookup
and filtering methods.
"""

from __future__ import annotations

import logging
import os
import tomllib
from pathlib import Path

from ssh_mcp.models import GroupConfig, ServerConfig, Settings

logger = logging.getLogger(__name__)


class ServerRegistry:
    """Registry for SSH server and group configurations.

    Loads configuration from a TOML file and provides lookup methods
    for servers and groups. Validates all references and constraints
    during initialization.

    Attributes:
        settings: Global settings for SSH operations
    """

    def __init__(self, config_path: str) -> None:
        """Initialize registry by loading and validating TOML config.

        Args:
            config_path: Path to servers.toml configuration file

        Raises:
            FileNotFoundError: If config file doesn't exist
            ValueError: If TOML is malformed or validation fails
        """
        self._config_path = Path(os.path.expanduser(config_path))
        self._servers: dict[str, ServerConfig] = {}
        self._groups: dict[str, GroupConfig] = {}
        self._settings = Settings()
        self._load()

    @property
    def settings(self) -> Settings:
        """Get global settings."""
        return self._settings

    def get_server(self, name: str) -> ServerConfig:
        """Get server configuration by name.

        Args:
            name: Server name (SSH host alias)

        Returns:
            ServerConfig for the requested server

        Raises:
            KeyError: If server name not found
        """
        if name not in self._servers:
            available = ", ".join(sorted(self._servers.keys()))
            raise KeyError(
                f"Server '{name}' not found. Available servers: {available}"
            )
        return self._servers[name]

    def get_group(self, name: str) -> GroupConfig:
        """Get group configuration by name.

        Args:
            name: Group name

        Returns:
            GroupConfig for the requested group

        Raises:
            KeyError: If group name not found
        """
        if name not in self._groups:
            available = ", ".join(sorted(self._groups.keys()))
            raise KeyError(
                f"Group '{name}' not found. Available groups: {available}"
            )
        return self._groups[name]

    def servers_in_group(self, group_name: str) -> list[ServerConfig]:
        """Get all servers belonging to a group.

        Args:
            group_name: Name of the group to filter by

        Returns:
            List of ServerConfig objects in the specified group

        Raises:
            KeyError: If group name not found
        """
        # Validate group exists first
        self.get_group(group_name)
        return [
            server
            for server in self._servers.values()
            if group_name in server.groups
        ]

    def all_servers(self) -> list[ServerConfig]:
        """Get all configured servers.

        Returns:
            List of all ServerConfig objects
        """
        return list(self._servers.values())

    def all_groups(self) -> list[GroupConfig]:
        """Get all configured groups.

        Returns:
            List of all GroupConfig objects
        """
        return list(self._groups.values())

    def _load(self) -> None:
        """Load and validate configuration from TOML file.

        Raises:
            FileNotFoundError: If config file doesn't exist
            ValueError: If TOML is malformed or validation fails
        """
        if not self._config_path.exists():
            raise FileNotFoundError(
                f"Configuration file not found: {self._config_path}"
            )

        try:
            with open(self._config_path, "rb") as f:
                config_data = tomllib.load(f)
        except tomllib.TOMLDecodeError as e:
            raise ValueError(f"Invalid TOML in {self._config_path}: {e}") from e

        # Load settings
        if "settings" in config_data:
            settings_dict = config_data["settings"]
            # Expand ~ in ssh_config_path
            if "ssh_config_path" in settings_dict:
                settings_dict["ssh_config_path"] = os.path.expanduser(
                    settings_dict["ssh_config_path"]
                )
            self._settings = Settings(**settings_dict)

        # Warn if known_hosts verification is disabled
        if not self._settings.known_hosts:
            logger.warning(
                "known_hosts verification disabled - connections vulnerable to MITM attacks"
            )

        # Load groups
        if "groups" in config_data:
            for group_name, group_data in config_data["groups"].items():
                self._groups[group_name] = GroupConfig(
                    name=group_name, description=group_data["description"]
                )

        # Load servers
        if "servers" in config_data:
            for server_name, server_data in config_data["servers"].items():
                # Convert groups list to tuple
                groups = tuple(server_data.get("groups", []))

                # Build ServerConfig with optional overrides
                server = ServerConfig(
                    name=server_name,
                    description=server_data["description"],
                    groups=groups,
                    hostname=server_data.get("hostname"),
                    port=server_data.get("port"),
                    user=server_data.get("user"),
                    identity_file=server_data.get("identity_file"),
                    jump_host=server_data.get("jump_host"),
                    default_dir=server_data.get("default_dir"),
                    timeout=server_data.get("timeout"),
                )
                self._servers[server_name] = server

        # Validate configuration
        self._validate()

    def _validate(self) -> None:
        """Validate server/group references and constraints.

        Logs warnings to stderr for validation issues.
        """
        server_names = set(self._servers.keys())
        group_names = set(self._groups.keys())

        for server_name, server in self._servers.items():
            # Every server must reference at least one group
            if not server.groups:
                logger.warning(
                    "Server '%s' has no groups assigned", server_name
                )

            # Every group referenced by a server must be defined
            for group in server.groups:
                if group not in group_names:
                    logger.warning(
                        "Server '%s' references undefined group '%s'",
                        server_name, group,
                    )

            # Server names must not collide with group names
            if server_name in group_names:
                logger.warning(
                    "Server name '%s' collides with group name", server_name
                )

            # jump_host value must reference another defined server
            if server.jump_host and server.jump_host not in server_names:
                logger.warning(
                    "Server '%s' references undefined jump_host '%s'",
                    server_name, server.jump_host,
                )

        # Detect circular jump host chains
        for server_name, server in self._servers.items():
            if server.jump_host:
                visited = {server_name}
                current = server.jump_host
                path = [server_name, current]

                while current in self._servers:
                    if current in visited:
                        cycle_path = " -> ".join(path)
                        raise ValueError(f"Circular jump host chain: {cycle_path}")

                    visited.add(current)
                    next_jump = self._servers[current].jump_host
                    if next_jump:
                        path.append(next_jump)
                        current = next_jump
                    else:
                        break
