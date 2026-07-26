"""Shared pytest fixtures for SSH MCP server tests.

This module provides reusable test fixtures for models, configurations, and
test data structures used by the other test modules.

Importing it also has a session-wide side effect: it registers and loads the
global Hypothesis profiles below, so every property test in the suite inherits
whichever profile ``HYPOTHESIS_PROFILE`` selects.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from hypothesis import HealthCheck, settings

from ssh_mcp.models import ExecResult, GroupConfig, ServerConfig, Settings

# Hypothesis profiles: ``dev`` is tuned for a fast inner loop, ``ci`` for a
# thorough fuzz run. Select via the HYPOTHESIS_PROFILE env var. No workflow in
# .github/ sets it, so CI currently runs ``dev`` (50 examples) too — export
# HYPOTHESIS_PROFILE=ci by hand, or in the workflow, to get the 200-example run.
#
# ``suppress_health_check`` is defensive only: every ``@given`` test in the
# suite takes Hypothesis-drawn arguments exclusively, so no function-scoped
# pytest fixture is currently reused across examples.
settings.register_profile(
    "dev",
    max_examples=50,
    deadline=500,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
settings.register_profile(
    "ci",
    max_examples=200,
    deadline=1000,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "dev"))


@pytest.fixture
def sample_settings() -> Settings:
    """Return a Settings instance with default values.

    Not fully hermetic: ``transfer_root`` comes from a ``default_factory``
    (``paths.default_transfer_root``) that reads ``XDG_DATA_HOME``, so it is
    ``~/.local/share/ssh-mcp/transfers`` only when that variable is unset. This
    fixture monkeypatches nothing — assert on it accordingly.

    Returns:
        Settings instance with default configuration
    """
    return Settings()


@pytest.fixture
def sample_settings_custom() -> Settings:
    """Return a Settings instance with custom values.

    Currently unreferenced by any test module. Two caveats if it is picked up
    again: ``known_hosts=True`` matches the model default, so this does not
    exercise the ``known_hosts=False`` MITM-warning branch in ``config.py``;
    and the fields added since it was written (``max_command_bytes``,
    ``transfer_root``, ``max_parallel_hosts``) are left at their defaults.

    Returns:
        Settings instance with custom configuration
    """
    return Settings(
        ssh_config_path="~/.ssh/custom_config",
        command_timeout=60,
        max_output_bytes=102400,
        connection_idle_timeout=600,
        known_hosts=True,
    )


@pytest.fixture
def sample_servers() -> list[ServerConfig]:
    """Return a list of sample ServerConfig objects.

    Deliberately not a self-consistent registry: ``bastion`` references
    ``jump_host="work"`` and ``groups=("infra",)``, neither of which exists here
    or in ``sample_groups``. Loading these two fixtures together through
    ``ConfigManager`` would log ``references undefined jump_host`` and
    ``references undefined group`` warnings (advisory only, not fatal).

    Returns:
        List of 4 test server configurations
    """
    return [
        ServerConfig(
            name="web1",
            description="Web server 1",
            groups=("prod", "web"),
        ),
        ServerConfig(
            name="web2",
            description="Web server 2",
            groups=("prod", "web"),
            hostname="192.168.1.10",
            port=2222,
            user="deploy",
        ),
        ServerConfig(
            name="db1",
            description="Database server 1",
            groups=("prod", "database"),
            identity_file="~/.ssh/db_key",
            default_dir="/var/lib/mysql",
            timeout=60,
        ),
        ServerConfig(
            name="bastion",
            description="Bastion host",
            groups=("infra",),
            jump_host="work",
        ),
    ]


@pytest.fixture
def sample_groups() -> list[GroupConfig]:
    """Return a list of sample GroupConfig objects.

    Defines ``prod``, ``web`` and ``database`` only — the ``infra`` group that
    ``sample_servers`` references is intentionally absent (see that fixture).

    Returns:
        List of 3 test group configurations
    """
    return [
        GroupConfig(name="prod", description="Production servers"),
        GroupConfig(name="web", description="Web application servers"),
        GroupConfig(name="database", description="Database servers"),
    ]


@pytest.fixture
def sample_exec_result() -> ExecResult:
    """Return a successful ExecResult.

    Returns:
        ExecResult with successful command execution
    """
    return ExecResult(
        server="web1",
        command="uptime",
        stdout=" 14:32:01 up 142 days, 12:45,  3 users,  load average: 0.15, 0.20, 0.18",
        stderr="",
        exit_code=0,
        duration_ms=150,
    )


@pytest.fixture
def sample_exec_error() -> ExecResult:
    """Return a failed ExecResult.

    Returns:
        ExecResult with failed command execution
    """
    return ExecResult(
        server="web1",
        command="invalid-command",
        stdout="",
        stderr="",
        exit_code=None,
        error="Command not found: invalid-command",
        duration_ms=5,
    )


@pytest.fixture
def tmp_config_file(tmp_path: Path) -> Path:
    """Create a minimal valid TOML config file for testing.

    The file content is fixed, but the ``Settings`` a ``ConfigManager`` derives
    from it are not: this fixture isolates no environment variables, and
    ``config.py`` applies ``SSH_MCP_TRANSFER_ROOT`` as an env > TOML > default
    override at load time (with ``XDG_DATA_HOME`` feeding the default). Clear or
    monkeypatch both when asserting on ``settings.transfer_root``.

    Args:
        tmp_path: pytest temporary directory fixture

    Returns:
        Path to the temporary config file
    """
    config_content = """
[settings]
ssh_config_path = "~/.ssh/config"
command_timeout = 30

[groups]
test-prod = { description = "Test production servers" }
test-dev = { description = "Test development servers" }

[servers.test-web1]
description = "Test web server 1"
groups = ["test-prod"]

[servers.test-web2]
description = "Test web server 2"
groups = ["test-prod"]
hostname = "192.168.1.10"
port = 2222

[servers.test-db1]
description = "Test database server"
groups = ["test-dev"]
"""
    config_file = tmp_path / "test_servers.toml"
    config_file.write_text(config_content)
    return config_file


@pytest.fixture
def invalid_config_file(tmp_path: Path) -> Path:
    """Create a TOML config with validation warnings.

    Args:
        tmp_path: pytest temporary directory fixture

    Returns:
        Path to the temporary config file with invalid references
    """
    config_content = """
[groups]
valid-group = { description = "Valid group" }

[servers.server-no-groups]
description = "Server with no groups"
groups = []

[servers.server-invalid-group]
description = "Server referencing undefined group"
groups = ["undefined-group"]

[servers.server-invalid-jump]
description = "Server with invalid jump host"
groups = ["valid-group"]
jump_host = "nonexistent-server"

[servers.valid-group]
description = "Server name colliding with group name"
groups = ["valid-group"]
"""
    config_file = tmp_path / "invalid_servers.toml"
    config_file.write_text(config_content)
    return config_file
