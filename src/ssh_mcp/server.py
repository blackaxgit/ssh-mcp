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
import contextlib
import functools
import logging
import os
import sys
from collections.abc import Awaitable, Callable, Iterator
from pathlib import Path
from typing import Any, TypeVar, cast

import structlog
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

# ---------------------------------------------------------------------------
# OpenTelemetry tracing — soft-imported so ssh_mcp[otel] is genuinely optional.
#
# When `opentelemetry-api` is installed, every MCP tool call gets a span
# named ``mcp.tool.{name}`` with attributes for the tool name and (on
# failure) the exception type. Inner SSH operations create child spans
# inside this one via automatic context propagation. Operators bring their
# own SDK + exporter (Jaeger, Tempo, OTLP collector, etc).
#
# When `opentelemetry-api` is NOT installed, the helper ``_span`` below is a
# no-op context manager — zero runtime cost, zero import errors.
# ---------------------------------------------------------------------------
try:
    from opentelemetry import trace as _otel_trace

    _tracer: Any = _otel_trace.get_tracer("ssh_mcp")
    _otel_available: bool = True
except ImportError:  # pragma: no cover - exercised by env without extras
    _tracer = None
    _otel_available = False


@contextlib.contextmanager
def _span(name: str, **attributes: Any) -> Iterator[Any]:
    """Start an OTel span if the API is available, else a no-op.

    Usage::

        with _span("mcp.tool.execute", **{"mcp.tool.name": "execute"}) as span:
            ...
            if span is not None:
                span.set_attribute("ssh.exit_code", result.exit_code)

    The yielded span is ``None`` when OTel is not installed so caller code
    must null-check before calling ``set_attribute``.
    """
    if _tracer is None:
        yield None
        return
    with _tracer.start_as_current_span(name) as span:
        for k, v in attributes.items():
            if v is not None:
                span.set_attribute(k, v)
        try:
            yield span
        except Exception as e:
            span.record_exception(e)
            span.set_status(_otel_trace.Status(_otel_trace.StatusCode.ERROR))
            raise


def _configure_logging() -> None:
    """Configure stderr logging with console or JSON output.

    Routes stdlib ``logging`` calls (from all modules) through structlog so
    any ``logger.info(...)`` call in ssh.py / config.py / server.py receives
    consistent ISO timestamps and structured rendering without changes to
    call sites.

    Controlled by ``SSH_MCP_LOG_FORMAT``:
      * unset / "console" (default): colorized human-readable output (dev)
      * "json": single-line JSON, one object per event (production log
        aggregators, structured search)

    Called unconditionally at module import so tool calls are instrumented
    even during lazy init. Idempotent — clears prior handlers before adding
    its own so repeated imports (e.g. under pytest) do not duplicate output.
    """
    fmt = os.environ.get("SSH_MCP_LOG_FORMAT", "console").lower()

    # Processors applied to BOTH structlog-native loggers and stdlib foreign
    # loggers, so timestamps / levels / contextvars are consistent across
    # every log line no matter which logger produced it.
    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
    ]

    renderer: Any
    if fmt == "json":
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty())

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared_processors,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(formatter)

    root = logging.getLogger()
    # Clear existing handlers so repeated configuration (e.g. under pytest
    # reloads) does not duplicate log lines.
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(logging.INFO)


_configure_logging()

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


F = TypeVar("F", bound=Callable[..., Awaitable[str]])


def _mcp_tool(func: F) -> F:
    """Decorator: ensure server is initialized, log+raise ToolError on failure,
    and open an OpenTelemetry span around every tool invocation.

    Collapses the duplicated try/except boilerplate from each MCP tool into a
    single declarative wrapper. Preserves ToolError passthrough so structured
    errors raised by inner code propagate unchanged. Any other exception is
    logged with a traceback and re-raised as a ToolError so the MCP client
    receives `isError=true` with a useful message.

    The surrounding OTel span is named ``mcp.tool.{name}`` and carries the
    ``mcp.tool.name`` attribute. On failure it is marked with exception info
    and ``StatusCode.ERROR`` via ``_span``'s error path. When OTel is not
    installed, the span is a no-op.

    Apply BELOW ``@mcp.tool()`` so FastMCP registers the wrapped function.
    """

    tool_name = func.__name__

    @functools.wraps(func)
    async def wrapper(*args: Any, **kwargs: Any) -> str:
        try:
            with _span(f"mcp.tool.{tool_name}", **{"mcp.tool.name": tool_name}):
                await _init()
                return await func(*args, **kwargs)
        except ToolError:
            raise
        except Exception as e:
            logger.error("%s failed: %s", tool_name, e, exc_info=True)
            raise ToolError(str(e)) from e

    return cast(F, wrapper)


@mcp.tool()
@_mcp_tool
async def list_servers(group: str | None = None) -> str:
    """List all configured SSH servers with their groups and descriptions.

    Args:
        group: Optional group name to filter by. Shows all servers if omitted.
               Use list_groups to see available group names.

    Returns:
        Formatted table of servers with name, groups, and description.
    """
    registry = _get_registry()

    if group is not None:
        # Filter by group
        try:
            servers = registry.servers_in_group(group)
        except KeyError as e:
            # Group not found - return error message instead of raising
            return f"Error: {e}"
        filter_label = f" in group '{group}'"
        if not servers:
            return f"No servers found in group '{group}'"
    else:
        # Show all servers
        servers = registry.all_servers()
        filter_label = ""

    return format_server_table(servers, filter_label=filter_label)


@mcp.tool()
@_mcp_tool
async def list_groups() -> str:
    """List all server groups with descriptions and member counts.

    Returns:
        Formatted table of groups with name, description, and server count.
    """
    registry = _get_registry()

    groups = registry.all_groups()

    # Count servers per group
    server_counts = {}
    for group in groups:
        count = len(registry.servers_in_group(group.name))
        server_counts[group.name] = count

    return format_group_table(groups, server_counts)


@mcp.tool()
@_mcp_tool
async def execute(
    server: str,
    command: str,
    timeout: int = 30,
    working_dir: str | None = None,
    force: bool = False,
) -> str:
    """Execute a shell command on a single SSH server.

    Args:
        server: Server name (e.g. 'web-prod-01'). Must match a configured server.
                Use list_servers to see available servers.
        command: Shell command to execute on the remote server (exactly as it
                would be typed at a bash prompt).
        timeout: Command timeout in **seconds**. Default 30. Range 1–3600.
        working_dir: Absolute remote directory to cd into before running the
                command. Uses the server's ``default_dir`` from servers.toml
                if omitted, or the SSH login directory if neither is set.
        force: If True, bypass the dangerous-command detection regex. Use only
                for audited bulk operations — the block list catches rm -rf /,
                mkfs, dd-to-disk, chmod 777 /, and fork bombs. Default False.

    Returns:
        Formatted command execution result with stdout, stderr, and exit code.
        Long output is truncated at ``max_output_bytes`` (default 50 KiB).
    """
    ssh = _get_ssh()
    result = await ssh.execute(server, command, timeout, working_dir, force)
    return format_exec_result(result)


@mcp.tool()
@_mcp_tool
async def execute_on_group(
    group: str,
    command: str,
    timeout: int = 30,
    working_dir: str | None = None,
    fail_fast: bool = False,
    force: bool = False,
) -> str:
    """Execute a shell command on all servers in a group in parallel.

    Concurrency is capped by the ``max_parallel_hosts`` setting (default 10;
    configure in ``[settings]`` of servers.toml, range 1–100).

    Args:
        group: Group name (e.g. 'production', 'web'). Use list_groups to see
               available groups.
        command: Shell command to execute on every server in the group.
        timeout: Per-server command timeout in **seconds**. Default 30.
                Each server has its own timer; slow servers do NOT extend the
                per-server limit for others.
        working_dir: Absolute remote directory to cd into on each server.
                Uses each server's ``default_dir`` if omitted.
        fail_fast: If True, cancel remaining tasks as soon as any server
                returns a non-zero exit code or errors. Default False —
                run all servers to completion and report each result.
        force: If True, bypass the dangerous-command detection regex. Use only
                for audited bulk operations. Default False.

    Returns:
        Formatted summary showing per-server results, success/failure counts,
        and aggregate exit status.
    """
    ssh = _get_ssh()
    results = await ssh.execute_on_group(
        group, command, timeout, working_dir, fail_fast, force
    )
    return format_group_results(results, group)


@mcp.tool()
@_mcp_tool
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
    ssh = _get_ssh()
    return await ssh.upload(server, local_path, remote_path)


@mcp.tool()
@_mcp_tool
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
    ssh = _get_ssh()
    return await ssh.download(server, remote_path, local_path)


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
