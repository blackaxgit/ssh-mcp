"""FastMCP server for SSH operations.

This module defines the MCP server entry point with 6 tools for SSH operations:
- list_servers: Show configured servers
- list_groups: Show server groups
- execute: Run command on single server
- execute_on_group: Run command on multiple servers in parallel
- upload_file: Upload via SFTP
- download_file: Download via SFTP
"""

from __future__ import annotations

import asyncio
import atexit
import logging
import os
import sys
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError

from ssh_mcp.config import ServerRegistry
from ssh_mcp.formatting import (
    format_exec_result,
    format_group_results,
    format_group_table,
    format_server_table,
)
from ssh_mcp.ssh import SSHManager

# Configure logging to stderr (required for stdio transport)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr,
)

logger = logging.getLogger(__name__)

# Create FastMCP server
mcp = FastMCP("ssh-mcp")

# Lazy-initialized globals
_registry: ServerRegistry | None = None
_ssh: SSHManager | None = None
# Lock is created at import time (not lazily) to eliminate the race window
# between `if _init_lock is None` and `_init_lock = asyncio.Lock()`.
_init_lock: asyncio.Lock = asyncio.Lock()


def _get_config_path() -> str:
    """Resolve configuration file path with fallback chain.

    Priority order:
    1. SSH_MCP_CONFIG environment variable (explicit override)
    2. ~/.config/ssh-mcp/servers.toml (XDG standard user config)
    3. config/servers.toml relative to package (development mode)

    Returns:
        str: Path to configuration file.

    Raises:
        FileNotFoundError: If no configuration file is found in any location.
    """
    # 1. Explicit override via environment variable
    if "SSH_MCP_CONFIG" in os.environ:
        return os.path.expanduser(os.environ["SSH_MCP_CONFIG"])

    # 2. XDG standard user config directory
    user_config = Path.home() / ".config" / "ssh-mcp" / "servers.toml"
    if user_config.exists():
        return str(user_config)

    # 3. Development mode: relative to package
    dev_config = Path(__file__).parent.parent.parent / "config" / "servers.toml"
    if dev_config.exists():
        return str(dev_config)

    # No config found - provide helpful error
    raise FileNotFoundError(
        "SSH MCP configuration not found. Please either:\n"
        f"  1. Set SSH_MCP_CONFIG environment variable to your config file path\n"
        f"  2. Create config at: {user_config}\n"
        f"  3. For development: ensure config exists at {dev_config}"
    )


def _cleanup_connections() -> None:
    """Cleanup SSH connections on exit."""
    global _ssh
    if _ssh is None:
        return
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(_ssh.close_all())
    except RuntimeError:
        # No running event loop — create one for cleanup
        try:
            asyncio.run(_ssh.close_all())
        except Exception as e:
            logger.warning(f"Error during connection cleanup: {e}")


async def _init() -> None:
    """Initialize registry and SSH manager on first tool call.

    Uses SSH_MCP_CONFIG environment variable if set, otherwise falls back to
    XDG standard path (~/.config/ssh-mcp/servers.toml) or development path.
    """
    global _registry, _ssh

    if _registry is not None:
        return  # Fast path — already initialized

    async with _init_lock:
        if _registry is not None:
            return  # Another coroutine initialized while we waited

        config_path = _get_config_path()
        logger.info(f"Loading configuration from {config_path}")
        _registry = ServerRegistry(config_path)
        _ssh = SSHManager(_registry, _registry.settings)
        logger.info(
            f"Initialized SSH MCP server: {len(_registry.all_servers())} servers, "
            f"{len(_registry.all_groups())} groups"
        )
        atexit.register(_cleanup_connections)


def _get_registry() -> ServerRegistry:
    """Return the initialized registry, raising if not yet initialized."""
    if _registry is None:
        raise RuntimeError("Server not initialized")
    return _registry


def _get_ssh() -> SSHManager:
    """Return the initialized SSH manager, raising if not yet initialized."""
    if _ssh is None:
        raise RuntimeError("Server not initialized")
    return _ssh


@mcp.tool()
async def list_servers(group: str | None = None) -> str:
    """List all configured SSH servers with their groups and descriptions.

    Args:
        group: Optional group name to filter by. Shows all servers if omitted.
               Use list_groups to see available group names.

    Returns:
        Formatted table of servers with name, groups, and description.
    """
    try:
        await _init()
        registry = _get_registry()

        if group is not None:
            # Filter by group
            try:
                servers = registry.servers_in_group(group)
                filter_label = f" in group '{group}'"
                if not servers:
                    return f"No servers found in group '{group}'"
            except KeyError as e:
                # Group not found - return error message instead of raising
                return f"Error: {e}"
        else:
            # Show all servers
            servers = registry.all_servers()
            filter_label = ""

        return format_server_table(servers, filter_label=filter_label)

    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Error listing servers: {e}")
        raise ToolError(str(e))


@mcp.tool()
async def list_groups() -> str:
    """List all server groups with descriptions and member counts.

    Returns:
        Formatted table of groups with name, description, and server count.
    """
    try:
        await _init()
        registry = _get_registry()

        groups = registry.all_groups()

        # Count servers per group
        server_counts = {}
        for group in groups:
            count = len(registry.servers_in_group(group.name))
            server_counts[group.name] = count

        return format_group_table(groups, server_counts)

    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Error listing groups: {e}")
        raise ToolError(str(e))


@mcp.tool()
async def execute(
    server: str,
    command: str,
    timeout: int = 30,
    working_dir: str | None = None,
    force: bool = False,
) -> str:
    """Execute a shell command on a single SSH server.

    Args:
        server: Server name (e.g. 'pro-dicentra', 'inf-ai'). Must match a configured
                server. Use list_servers to see available servers.
        command: Shell command to execute on the remote server.
        timeout: Command timeout in seconds. Default 30.
        working_dir: Remote directory to execute from. Uses server default if omitted.
        force: Bypass dangerous command detection. Use with extreme caution. Default false.

    Returns:
        Formatted command execution result with stdout, stderr, and exit code.
    """
    try:
        await _init()
        ssh = _get_ssh()

        result = await ssh.execute(server, command, timeout, working_dir, force)
        return format_exec_result(result)

    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Error executing command on {server}: {e}")
        raise ToolError(str(e))


@mcp.tool()
async def execute_on_group(
    group: str,
    command: str,
    timeout: int = 30,
    working_dir: str | None = None,
    fail_fast: bool = False,
    force: bool = False,
) -> str:
    """Execute a shell command on all servers in a group (parallel execution).

    Args:
        group: Group name (e.g. 'dicentra-prod', 'infra'). Use list_groups to see
               available groups.
        command: Shell command to execute on all servers in the group.
        timeout: Per-server command timeout in seconds. Default 30.
        working_dir: Remote directory to execute from on each server.
        fail_fast: If true, stop on first failure. Default false (run all).
        force: Bypass dangerous command detection. Use with extreme caution. Default false.

    Returns:
        Formatted summary of results from all servers in the group.
    """
    try:
        await _init()
        ssh = _get_ssh()

        results = await ssh.execute_on_group(
            group, command, timeout, working_dir, fail_fast, force
        )
        return format_group_results(results, group)

    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Error executing command on group {group}: {e}")
        raise ToolError(str(e))


@mcp.tool()
async def upload_file(
    server: str,
    local_path: str,
    remote_path: str,
) -> str:
    """Upload a file to a remote server via SFTP.

    Args:
        server: Server name (e.g. 'pro-dicentra').
        local_path: Absolute path to local file.
        remote_path: Absolute destination path on remote server.

    Returns:
        Confirmation message with file size.
    """
    try:
        await _init()
        ssh = _get_ssh()

        result = await ssh.upload(server, local_path, remote_path)
        return result

    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Error uploading file to {server}: {e}")
        raise ToolError(str(e))


@mcp.tool()
async def download_file(
    server: str,
    remote_path: str,
    local_path: str,
) -> str:
    """Download a file from a remote server via SFTP.

    Args:
        server: Server name (e.g. 'pro-dicentra').
        remote_path: Absolute path to remote file.
        local_path: Absolute local destination path.

    Returns:
        Confirmation message with file size.
    """
    try:
        await _init()
        ssh = _get_ssh()

        result = await ssh.download(server, remote_path, local_path)
        return result

    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Error downloading file from {server}: {e}")
        raise ToolError(str(e))


def main() -> None:
    """Entry point for console script (uvx ssh-mcp)."""
    from ssh_mcp import __version__

    logger.info(
        f"Starting ssh-mcp v{__version__} (stdio transport) - "
        f"waiting for MCP client on stdin"
    )
    try:
        config_path = _get_config_path()
        logger.info(f"Config will be loaded from {config_path} on first tool call")
    except FileNotFoundError as e:
        logger.warning(f"No config file found yet: {e}")
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
