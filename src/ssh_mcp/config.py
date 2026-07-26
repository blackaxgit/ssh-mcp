"""Configuration loader for SSH MCP server.

This module provides the ServerRegistry class that loads and validates
server/group configuration from a TOML file, providing convenient lookup
and filtering methods, plus the ConfigError exception it raises on load
and validation failures.
"""

from __future__ import annotations

import logging
import os
import tomllib
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from ssh_mcp.models import GroupConfig, ServerConfig, Settings

logger = logging.getLogger(__name__)


class ConfigError(ValueError):
    """Raised when configuration loading or validation fails.

    Subclass of ValueError for backward compatibility with existing callers
    that catch ValueError. It also carries an actionable message and lets a
    caller narrow to `except ConfigError`, though no caller in this package
    does so today: both the MCP server and the healthcheck construct
    ``ServerRegistry`` without a handler and let the failure propagate.
    """


def _format_validation_error(section: str, context: str, exc: ValidationError) -> str:
    """Flatten a Pydantic ValidationError into a single actionable message.

    Pydantic lists each offending field with a location, an error type, and a
    message; this flattening reads exactly those three (``loc``, ``type``,
    ``msg``) and ignores the reported input value. For
    ``extra_forbidden`` it surfaces the offending field name; the list of
    valid keys for the section is appended by the call sites via
    ``_valid_keys``, so operators can fix typos without consulting the schema.

    Args:
        section: TOML section label (``settings``, ``groups``, ``servers``).
        context: Entity name (e.g. server/group name) for scoping; pass ``""``
            when the section has no per-entity name.
        exc: The Pydantic ValidationError to flatten.

    Returns:
        A single-line message describing every offending field.
    """
    suffix = f" for '{context}'" if context else ""
    messages: list[str] = []
    for err in exc.errors():
        loc = ".".join(str(p) for p in err.get("loc", ())) or "<root>"
        etype = err.get("type", "")
        msg = err.get("msg", "")
        if etype == "extra_forbidden":
            messages.append(f"unknown key '{loc}'")
        elif etype == "missing":
            messages.append(f"missing required key '{loc}'")
        else:
            messages.append(f"'{loc}': {msg}")
    joined = "; ".join(messages)
    return f"Invalid [{section}]{suffix}: {joined}"


def _valid_keys(model_cls: type) -> list[str]:
    """Return sorted list of valid field names for a Pydantic dataclass."""
    fields = getattr(model_cls, "__pydantic_fields__", None)
    if fields is None:
        return []
    return sorted(fields.keys())


class ServerRegistry:
    """Registry for SSH server and group configurations.

    Loads configuration from a TOML file and provides lookup methods
    for servers and groups. Schema validation (unknown keys, missing keys,
    numeric ranges) is fatal during initialization. Cross-reference checks —
    undefined groups, server/group name collisions, dangling ``jump_host`` —
    only log warnings, so such a config still loads; a circular jump host
    chain is the one cross-reference failure that aborts.

    Attributes:
        settings: Global settings for SSH operations
    """

    def __init__(self, config_path: str) -> None:
        """Initialize registry by loading and validating TOML config.

        A leading ``~`` in ``config_path`` is expanded. The
        ``SSH_MCP_TRANSFER_ROOT`` environment variable, if set, overrides the
        ``transfer_root`` setting read from the file.

        Args:
            config_path: Path to servers.toml configuration file (supports
                ``~`` expansion)

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
            raise KeyError(f"Server '{name}' not found. Available servers: {available}")
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
            raise KeyError(f"Group '{name}' not found. Available groups: {available}")
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
            server for server in self._servers.values() if group_name in server.groups
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

        Applies the ``SSH_MCP_TRANSFER_ROOT`` environment override on top of
        the ``[settings]`` section before the model is constructed.

        Raises:
            FileNotFoundError: If config file doesn't exist
            ConfigError: If TOML is malformed or Pydantic validation fails
            ValueError: If ``_validate`` finds a circular jump host chain
        """
        if not self._config_path.exists():
            raise FileNotFoundError(
                f"Configuration file not found: {self._config_path}"
            )

        try:
            with open(self._config_path, "rb") as f:
                config_data = tomllib.load(f)
        except tomllib.TOMLDecodeError as e:
            raise ConfigError(
                f"Failed to parse {self._config_path}: {e}. "
                f"Check TOML syntax near the reported position."
            ) from e

        # Load settings.
        #
        # Constructed unconditionally, even with no ``[settings]`` block: the
        # ``~`` expansion now lives in the model validator, and the previous
        # "only if the section exists" shape meant a minimal servers.toml
        # left the default ``~/.ssh/config`` unexpanded and broke every
        # connection with ``FileNotFoundError: '~/.ssh/config'``.
        settings_dict = dict(config_data.get("settings", {}))

        # ``Settings`` is a plain pydantic dataclass, not ``BaseSettings``, so
        # no field of it is bound to an environment variable (its
        # ``transfer_root`` default factory does consult ``XDG_DATA_HOME``, but
        # only to compute the default). The transfer root is the one setting a
        # container operator must be able to override without editing the
        # mounted TOML, so that override is applied explicitly here.
        # Precedence: env > TOML > computed default.
        env_transfer_root = os.environ.get("SSH_MCP_TRANSFER_ROOT", "").strip()
        if env_transfer_root:
            settings_dict["transfer_root"] = env_transfer_root

        try:
            self._settings = Settings(**settings_dict)
        except ValidationError as e:
            detail = _format_validation_error("settings", "", e)
            valid = ", ".join(_valid_keys(Settings))
            raise ConfigError(f"{detail}. Valid keys: {valid}") from e

        # Warn if known_hosts verification is disabled
        if not self._settings.known_hosts:
            logger.warning(
                "known_hosts verification disabled - connections vulnerable to MITM attacks"
            )

        # Load groups
        if "groups" in config_data:
            for group_name, group_data in config_data["groups"].items():
                try:
                    self._groups[group_name] = GroupConfig(
                        name=group_name,
                        **dict(group_data),
                    )
                except ValidationError as e:
                    detail = _format_validation_error("groups", group_name, e)
                    valid = ", ".join(
                        k for k in _valid_keys(GroupConfig) if k != "name"
                    )
                    raise ConfigError(f"{detail}. Valid keys: {valid}") from e

        # Load servers
        if "servers" in config_data:
            for server_name, server_data in config_data["servers"].items():
                # Convert groups list to tuple before Pydantic sees it
                data: dict[str, Any] = dict(server_data)
                if "groups" in data:
                    data["groups"] = tuple(data["groups"])
                try:
                    self._servers[server_name] = ServerConfig(
                        name=server_name,
                        **data,
                    )
                except ValidationError as e:
                    detail = _format_validation_error("servers", server_name, e)
                    valid = ", ".join(
                        k for k in _valid_keys(ServerConfig) if k != "name"
                    )
                    raise ConfigError(f"{detail}. Valid keys: {valid}") from e

        # Validate configuration
        self._validate()

    def _validate(self) -> None:
        """Validate server/group references and constraints.

        Logs warnings to stderr for reference issues (no groups assigned,
        undefined group, server/group name collision, undefined ``jump_host``)
        and lets the config load anyway.

        Raises:
            ValueError: If a circular jump host chain is detected. This is the
                only fatal check here, so it aborts ``__init__``.
        """
        server_names = set(self._servers.keys())
        group_names = set(self._groups.keys())

        for server_name, server in self._servers.items():
            # A server should reference at least one group (advisory only)
            if not server.groups:
                logger.warning("Server '%s' has no groups assigned", server_name)

            # A group referenced by a server should be defined (advisory only)
            for group in server.groups:
                if group not in group_names:
                    logger.warning(
                        "Server '%s' references undefined group '%s'",
                        server_name,
                        group,
                    )

            # Server names should not collide with group names (advisory only)
            if server_name in group_names:
                logger.warning("Server name '%s' collides with group name", server_name)

            # jump_host should reference another defined server (advisory only)
            if server.jump_host and server.jump_host not in server_names:
                logger.warning(
                    "Server '%s' references undefined jump_host '%s'",
                    server_name,
                    server.jump_host,
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
