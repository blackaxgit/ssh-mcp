"""MCP server for SSH operations.

This module defines the MCP server entry point with 6 tools for SSH operations:
- list_servers: Show configured servers
- list_groups: Show server groups
- execute: Run command on single server
- execute_on_group: Run command on multiple servers in parallel
- upload_file: Upload via SFTP
- download_file: Download via SFTP

It also hosts the process entry point ``main``, which serves those tools over
either the stdio or the streamable HTTP transport (see ``_run_http``) and
dispatches the ``ssh-mcp healthcheck`` CLI subcommand used by the container
health check.
"""

from __future__ import annotations

import asyncio
import atexit
import contextlib
import functools
import logging
import os
import stat
import sys
import traceback
from collections.abc import Awaitable, Callable, Iterator
from pathlib import Path
from typing import Any, TypeVar, cast

import structlog
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings

from ssh_mcp import __version__
from ssh_mcp.config import ServerRegistry
from ssh_mcp.formatting import (
    format_exec_result,
    format_group_results,
    format_group_table,
    format_server_table,
)
from ssh_mcp.ssh import SSHManager, _redact_secrets

# ---------------------------------------------------------------------------
# OpenTelemetry tracing.
#
# Every MCP tool call gets a span named ``mcp.tool.{name}`` with attributes
# for the tool name and (on failure) the exception type. Inner SSH
# operations create child spans inside this one via automatic context
# propagation. Operators bring their own SDK + exporter (Jaeger, Tempo,
# OTLP collector, etc); with the API alone the spans are created and go
# nowhere, which costs effectively nothing.
#
# There is no `ssh_mcp[otel]` extra any more — 0.7.0 deleted it, because
# mcp>=2 declares `opentelemetry-api>=1.28.0` as a HARD dependency, so the
# API is always installed alongside the SDK this server cannot run without.
# The try/except below is therefore vestigial: importing
# `mcp.server.mcpserver` above eagerly imports `opentelemetry.trace`, so an
# environment missing the API dies at that import, never here. It is kept
# as four cheap lines of insurance in case a future mcp release drops the
# dependency; do not read it as evidence that a no-tracing install is a
# supported configuration.
# ---------------------------------------------------------------------------
try:
    from opentelemetry import trace as _otel_trace

    _tracer: Any = _otel_trace.get_tracer("ssh_mcp")
except ImportError:  # pragma: no cover - unreachable; see comment above
    _tracer = None


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

    # Production incident 2026-04-11 (round 2): asyncssh emits the FULL
    # SSH command at INFO level via its internal channel logger as
    # ``[conn=N, chan=N]   Command: <raw command including credentials>``.
    # Our audit-log redaction in ``ssh.py`` only sanitizes the ssh-mcp
    # logger, so any ``mysql -p<pass>`` arriving via asyncssh's own
    # logger leaked the password despite v0.4.1.
    #
    # Raise the asyncssh logger family to WARNING so its INFO records
    # never reach our handler. We still see warnings/errors (real
    # connection failures, channel errors, etc.) — we just don't ship
    # the per-command audit trail to centralized log aggregators.
    for noisy in ("asyncssh", "asyncssh.sftp", "asyncssh.connection"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    # v2 (mcp>=2) logs tool-failure messages at INFO in
    # mcp/server/mcpserver/server.py::_handle_call_tool before converting a
    # ToolError into CallToolResult(is_error=True). ssh-mcp's raising tools
    # (upload_file/download_file) put local and remote paths in those
    # messages, and a wrapped asyncssh error can put credential text there.
    # Same class of leak as the asyncssh INFO logging above
    # (Production incident 2026-04-11 round 2), same mitigation.
    logging.getLogger("mcp.server.mcpserver.server").setLevel(logging.WARNING)


_configure_logging()

logger = logging.getLogger(__name__)

# Create the MCP server. _configure_logging() above still runs first, and
# MCPServer.__init__'s own configure_logging -> logging.basicConfig remains
# a no-op once the root logger already has handlers (same as v1) — this
# ordering is intentional, do not "fix" it.
#
# v1 reported the SDK's own version in serverInfo; v2 reports "" unless
# given one, so pass ssh-mcp's own version explicitly here for the first
# time. version MUST be passed by keyword: the constructor's positional
# order is (name, title, description, instructions, website_url, icons,
# version).
mcp = MCPServer("ssh-mcp", version=__version__)

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
    2. $XDG_CONFIG_HOME/ssh-mcp/servers.toml, falling back to
       ~/.config/ssh-mcp/servers.toml when XDG_CONFIG_HOME is unset
       (XDG standard user config)
    3. config/servers.toml relative to package (development mode)

    Returns:
        str: Path to configuration file.

    Raises:
        FileNotFoundError: If no configuration file is found in any location.
    """
    # 1. Explicit override via environment variable
    if "SSH_MCP_CONFIG" in os.environ:
        return os.path.expanduser(os.environ["SSH_MCP_CONFIG"])

    # 2. XDG standard user config directory. Honors $XDG_CONFIG_HOME when
    # set — this used to always resolve under ~/.config regardless of the
    # env var, which was inconsistent with transfer_root's XDG_DATA_HOME
    # handling (paths.py:default_transfer_root) elsewhere in this codebase.
    xdg_config_home = os.environ.get("XDG_CONFIG_HOME")
    config_base = Path(xdg_config_home) if xdg_config_home else Path.home() / ".config"
    user_config = config_base / "ssh-mcp" / "servers.toml"
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


# R5 finding #3: atexit registration flag — prevents stacking multiple
# handlers if _init() is called more than once (e.g. test teardown + re-init).
_atexit_registered: bool = False


def _cleanup_connections() -> None:
    """Best-effort SSH cleanup on process exit (registered for all transports).

    R5 audit: the ``loop.create_task()`` branch was dead code — by the
    time ``atexit`` fires the event loop is already torn down, so
    ``get_running_loop()`` always raises ``RuntimeError``. Removed.
    The ``asyncio.run()`` fallback creates a fresh loop which works for
    simple ``close()`` + ``wait_closed()`` calls on asyncssh connections.
    For the HTTP transport, the Starlette lifespan at ``_build_http_app``
    handles shutdown cleanly — this atexit handler is a belt-and-suspenders
    backup that fires only if the lifespan didn't run (e.g. stdio mode
    or abnormal exit).
    """
    global _ssh
    if _ssh is None:
        return
    try:
        asyncio.run(_ssh.close_all())
    except Exception as e:  # noqa: BLE001 - atexit cleanup: must never raise during interpreter shutdown
        logger.warning("Error during connection cleanup: %s", e)


async def _init() -> None:
    """Initialize registry and SSH manager on first tool call.

    Uses SSH_MCP_CONFIG environment variable if set, otherwise falls back to
    the XDG standard path (``$XDG_CONFIG_HOME``, or ``~/.config`` when that is
    unset, + ``/ssh-mcp/servers.toml``) or the development path — see
    ``_get_config_path`` for the full chain.
    """
    global _registry, _ssh

    if _registry is not None:
        return  # Fast path — already initialized

    async with _init_lock:
        if _registry is not None:
            return  # Another coroutine initialized while we waited

        config_path = _get_config_path()
        logger.info("Loading configuration from %s", config_path)
        _registry = ServerRegistry(config_path)
        _ssh = SSHManager(_registry, _registry.settings)
        logger.info(
            "Initialized SSH MCP server: %s servers, %s groups",
            len(_registry.all_servers()),
            len(_registry.all_groups()),
        )
        global _atexit_registered
        if not _atexit_registered:
            atexit.register(_cleanup_connections)
            _atexit_registered = True


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
    errors raised by inner code propagate unchanged, and re-raises
    ``asyncio.CancelledError`` untouched so a cancelled call stays cancelled
    instead of being converted into a tool failure. Any other exception is
    logged with a traceback and re-raised as a ToolError so the MCP client
    receives `isError=true` with a useful message.

    The surrounding OTel span is named ``mcp.tool.{name}`` and carries the
    ``mcp.tool.name`` attribute. On failure it is marked with exception info
    and ``StatusCode.ERROR`` via ``_span``'s error path. When OTel is not
    installed, the span is a no-op.

    Apply BELOW ``@mcp.tool()`` so MCPServer registers the wrapped function.
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
        except asyncio.CancelledError:
            raise
        except Exception as e:
            # Redact BOTH the message and the traceback. `exc_info=True`
            # was the leak: logging.Formatter renders the original
            # exception (and every `__cause__` in the chain) verbatim, so
            # the redaction on the line below was defeated on the log
            # path while only the client-visible ToolError stayed clean.
            # Reproduced 2026-09-06 by two validators and directly: a
            # RuntimeError carrying `mysql --password=hunter2` logged the
            # message as `--password={REDACTED}` and then printed
            # `hunter2` TWICE more in the traceback below it.
            #
            # Formatting the traceback ourselves and redacting the whole
            # rendered string keeps it useful for operators while holding
            # the invariant that no raw exception text reaches a logger.
            # Do not restore `exc_info=True` here.
            redacted = _redact_secrets(str(e))
            redacted_tb = _redact_secrets("".join(traceback.format_exception(e)))
            logger.error("%s failed: %s\n%s", tool_name, redacted, redacted_tb)
            raise ToolError(redacted) from e

    return cast(F, wrapper)


@mcp.tool()
@_mcp_tool
async def list_servers(group: str | None = None) -> str:
    """List all configured SSH servers with their groups and descriptions.

    Args:
        group: Optional group name to filter by. Shows all servers if omitted.
               Use list_groups to see available group names.

    Returns:
        Formatted table of servers with name, groups, and description. An
        unknown ``group`` is reported as a plain ``"Error: ..."`` string
        rather than raised as a tool error, and a group with no members
        returns ``"No servers found in group '<name>'"``.
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


def _check_command_length(command: str, max_bytes: int) -> None:
    """Reject an over-long ``command`` before it reaches the SSH layer.

    B2-cap: ``_redact_secrets`` and ``_is_dangerous_command`` in ``ssh.py``
    are both superlinear in input length, and Python's ``re`` has no
    timeout — a ~10 KB command measurably stalls the single-threaded event
    loop for over 6 seconds, reachable via ``dry_run=True`` before any SSH
    connection or authentication. This check is the other half of that
    fix: it is O(n) in the encoded length and runs before either function
    is reached, so a regex fix alone (bounding the quantifiers) cannot
    provide the same guarantee on its own.

    Compares the ENCODED byte length, not ``len(command)`` — the setting
    is named ``max_command_bytes`` and a multibyte UTF-8 string would
    otherwise slip well past the intended limit despite having fewer
    ``str`` characters than bytes.
    """
    actual_bytes = len(command.encode("utf-8"))
    if actual_bytes > max_bytes:
        raise ToolError(
            f"command is {actual_bytes} bytes, exceeding the "
            f"{max_bytes}-byte limit set by max_command_bytes (configure "
            "in [settings] of servers.toml, range 1024-1048576). Shorten "
            "the command or raise the limit."
        )


@mcp.tool()
@_mcp_tool
async def execute(
    server: str,
    command: str,
    timeout: int = 30,
    working_dir: str | None = None,
    force: bool = False,
    dry_run: bool = False,
) -> str:
    """Execute a shell command on a single SSH server.

    Args:
        server: Server name (e.g. 'web-prod-01'). Must match a configured server.
                Use list_servers to see available servers.
        command: Shell command to execute on the remote server (exactly as it
                would be typed at a bash prompt). Rejected if it exceeds
                ``max_command_bytes`` (default 65536 encoded UTF-8 bytes).
        timeout: Command timeout in **seconds**. Default 30. Not range-checked,
                and NOT authoritative: a ``timeout`` set on the server's entry
                in servers.toml overrides this argument outright, so a
                per-server 30 wins over a caller-supplied 600.
        working_dir: Absolute remote directory to cd into before running the
                command. Uses the server's ``default_dir`` from servers.toml
                if omitted, or the SSH login directory if neither is set.
        force: If True, bypass the dangerous-command detection patterns. Use
                only for audited bulk operations. The block list is ~25 regexes
                and is broader than "obviously destructive": besides rm -rf /,
                mkfs, dd-to-disk, chmod 777 /, redirects into /dev/sd* and
                /etc/{passwd,shadow,gshadow,sudoers}, find -delete / -exec rm,
                shred / wipefs / blkdiscard / sgdisk on /dev/, partition-table
                edits, and fork bombs, it also rejects ordinary interpreter
                wrappers — ``bash -c ...``, ``python3 -c ...`` (also perl/ruby
                ``-c``/``-e``), ``eval "..."``, and ``base64 -d | sh``. Harmless
                commands in those forms need ``force=True`` too. Default False.
        dry_run: If True, do NOT connect or execute. Return a preview describing
                what would run (server, command, working_dir, timeout, force).
                Dangerous-command detection still runs so rejection can be
                previewed. Useful for LLM plans that want to validate intent
                before committing. Default False.

    Returns:
        Formatted command execution result with stdout, stderr, and exit code.
        Long output is truncated at ``max_output_bytes`` (default 50 KiB) PER
        STREAM — stdout and stderr get independent budgets, so the combined
        worst case is 2x that setting. A truncated stream ends with
        ``[... output truncated at N bytes]``, and hitting the cap TERMINATES
        the remote process rather than letting it keep writing.
    """
    ssh = _get_ssh()
    _check_command_length(command, _get_registry().settings.max_command_bytes)
    result = await ssh.execute(server, command, timeout, working_dir, force, dry_run)
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
    dry_run: bool = False,
) -> str:
    """Execute a shell command on all servers in a group in parallel.

    Concurrency is capped by the ``max_parallel_hosts`` setting (default 10;
    configure in ``[settings]`` of servers.toml, range 1–100). The semaphore is
    PROCESS-WIDE, not per call: concurrent execute_on_group calls share the same
    slots and therefore serialise against each other for their share of them.

    Args:
        group: Group name (e.g. 'production', 'web'). Use list_groups to see
               available groups.
        command: Shell command to execute on every server in the group.
                Rejected if it exceeds ``max_command_bytes`` (default 65536
                encoded UTF-8 bytes).
        timeout: Per-server command timeout in **seconds**. Default 30. Not
                range-checked, and overridden per server by a ``timeout`` set
                on that server's entry in servers.toml.
                Each server has its own timer; slow servers do NOT extend the
                per-server limit for others.
        working_dir: Absolute remote directory to cd into on each server.
                Uses each server's ``default_dir`` if omitted.
        fail_fast: If True, cancel remaining tasks as soon as any server
                returns a non-zero exit code or errors. Default False —
                run all servers to completion and report each result.
        force: If True, bypass the dangerous-command detection patterns. Use
                only for audited bulk operations. The same broad block list
                described under ``execute`` applies here — including plain
                ``bash -c`` / ``python3 -c`` / ``eval`` wrappers. Default False.
        dry_run: If True, do NOT connect or execute anywhere. Return a
                per-server preview describing what would run. Dangerous-
                command detection still applies. Useful for previewing
                fleet-wide rollouts before committing. Default False.

    Returns:
        Formatted summary showing per-server results, success/failure counts,
        and aggregate exit status.
    """
    ssh = _get_ssh()
    _check_command_length(command, _get_registry().settings.max_command_bytes)
    results = await ssh.execute_on_group(
        group, command, timeout, working_dir, fail_fast, force, dry_run
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

    Files larger than 100 MiB are refused outright — use rsync or scp for those.

    Args:
        server: Server name (e.g. 'pro-dicentra').
        local_path: Path to the local file, RELATIVE to the configured
                ``transfer_root`` (see [settings] in servers.toml, or the
                ``SSH_MCP_TRANSFER_ROOT`` environment variable). Absolute
                paths, ``..``, ``.`` components and embedded NUL bytes are
                rejected, as is a symlink at ANY component of the path.
                Sub-directories are allowed (e.g. ``'reports/q1.csv'``),
                but every intermediate
                directory must already exist under ``transfer_root`` —
                upload_file does not create them. ``transfer_root`` itself must
                be a real directory owned by the running user with mode 0700,
                or every transfer fails.
        remote_path: Destination path on the remote server — normally absolute,
                though a relative path is not rejected, just resolved by the
                remote SFTP server against the SSH login directory. Rejected if
                it contains ``..`` anywhere (even inside an otherwise legitimate
                filename) or matches the sensitive-path denylist
                (``/etc/shadow``, ``/etc/passwd``, ``.ssh/*``,
                ``.aws/credentials``, ``.kube/config``, ``.netrc``, …). An
                existing REGULAR file at the destination is silently
                OVERWRITTEN — unlike download_file, upload does not no-clobber;
                an existing non-regular target (symlink, device, FIFO) is
                refused.

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
        remote_path: Path to the remote file — normally absolute, though a
                relative path is not rejected, just resolved by the remote SFTP
                server against the SSH login directory. Must be a regular file —
                symlinks, devices, FIFOs, and other non-regular remote
                files are refused. Rejected if it contains ``..`` anywhere or
                matches the same sensitive-path denylist upload_file enforces.
                Size is NOT capped here (upload's 100 MiB limit has no download
                counterpart) — an oversized transfer only logs a warning, after
                the bytes are already on disk.
        local_path: Destination path, RELATIVE to the configured
                ``transfer_root`` (see [settings] in servers.toml, or the
                ``SSH_MCP_TRANSFER_ROOT`` environment variable). Absolute
                paths, ``..``, ``.`` components and embedded NUL bytes are
                rejected, as is a symlink at any component of the path.
                Sub-directories are allowed,
                but every intermediate directory must already exist under
                ``transfer_root``. NO-CLOBBER: if a file already exists at
                the destination, the download fails rather than silently
                overwriting it — remove or rename the existing file first.
                A failed or cancelled download unlinks the partial file it
                created, so a retry is not blocked by its own leftovers.

    Returns:
        Confirmation message with file size.
    """
    ssh = _get_ssh()
    return await ssh.download(server, remote_path, local_path)


# Minimum acceptable length for a bearer token. 16 chars ≈ 80 bits of
# entropy if the source is random. Shorter values are rejected at startup
# as likely to be typos, placeholders, or human-chosen weak secrets.
_MIN_TOKEN_LENGTH: int = 16


def _build_http_app(
    token: str | None,
    *,
    stateless: bool,
    transport_security: TransportSecuritySettings,
) -> Any:
    """Return the Starlette ASGI app for streamable HTTP transport.

    Assembles a SINGLE outer Starlette app containing:

    1. The MCPServer streamable HTTP app mounted under ``/``
    2. A ``lifespan`` that starts MCPServer's session-manager task group
       via the PUBLIC ``MCPServer.session_manager`` property — without
       this every request returns HTTP 500 with ``RuntimeError('Task
       group is not initialized')``.
    3. On shutdown, drains the pooled SSH manager BEFORE exiting the
       inner lifespan so ``_ssh.close_all()`` can still dispatch
       traffic on a live event loop.
    4. If ``token`` is provided, a bearer-auth middleware is attached
       to THIS outer app (not a separate wrapper) so the middleware
       runs inside the same lifespan context as the MCPServer app.

    Earlier versions (v0.3.0) built three nested Starlette apps:
    bearer wrapper → shutdown-lifespan wrapper → MCPServer. Only the
    outermost lifespan ran, so the MCPServer task group was never
    initialized. This single-app approach fixes that regression.

    ``stateless`` and ``transport_security`` have no defaults on purpose:
    a bare ``None`` transport_security constructs a settings object with
    DNS-rebinding protection OFF (mcp/server/transport_security.py:48),
    so a default here would make that fail-open path reachable by
    omission. Note there is deliberately no ``host`` parameter: the SDK
    consults ``host`` only to auto-enable loopback protection when
    ``transport_security is None`` (mcp/server/lowlevel/server.py:735),
    which this signature forbids, so forwarding it had no effect.

    Returns a ``Starlette`` instance ready to hand to ``uvicorn.run``.
    """
    from contextlib import asynccontextmanager

    from starlette.applications import Starlette
    from starlette.routing import Mount

    inner_app = mcp.streamable_http_app(
        stateless_http=stateless,
        transport_security=transport_security,
    )

    # N4: this used to reach into `inner_app.router.lifespan_context` — a
    # PRIVATE Starlette attribute, not ours or the MCP SDK's to depend on
    # (Starlette itself went 0.52.1 -> 1.3.1 during this release cycle,
    # unconstrained by this project). `streamable_http_app()` above wires
    # its own inner Starlette app with `lifespan=lambda app:
    # self.session_manager.run()` (mcp/server/lowlevel/server.py:828) — calling
    # `lifespan_ctx(inner_app)` therefore did nothing but reach `.run()`
    # through a private indirection. `MCPServer.session_manager` is the
    # SDK-documented public accessor for the exact same object, and
    # `.run()` takes no arguments, so we call it directly from OUR outer
    # lifespan instead — Starlette only ever runs the outermost lifespan,
    # never a mounted sub-app's, which is why we must invoke this
    # ourselves rather than relying on the inner app's own wiring.
    #
    # The check below is a fast, loud, startup-time sanity signal that
    # `streamable_http_app()` did its documented job of populating the
    # session manager. R5 finding #8's original guard could not detect
    # the actual semantic break it was written for — a present, callable
    # `lifespan_context` attribute proves nothing about whether it
    # functionally starts the task group. The real verification of that
    # is the request-through tests in tests/test_http_transport.py, which
    # drive real requests through this app and assert the absence of the
    # "Task group is not initialized" failure signature.
    try:
        session_manager = mcp.session_manager
    except RuntimeError as exc:
        raise RuntimeError(
            "MCPServer's session manager was not initialized by "
            "streamable_http_app() — this used to also populate "
            "Starlette's private router.lifespan_context, which "
            "ssh-mcp no longer depends on. The MCP SDK may have changed "
            "its internal wiring (as of mcp 2.1.1 it lives in "
            "mcp/server/lowlevel/server.py); update the lifespan wiring "
            "in server.py._build_http_app or pin a known-good mcp."
        ) from exc

    @asynccontextmanager
    async def _lifespan(_app: Starlette) -> Any:
        # Step 1: start the MCPServer session manager's task group via the
        # public session_manager.run() API (see note above).
        async with session_manager.run():
            try:
                yield
            finally:
                # Step 2: drain SSH BEFORE exiting the inner lifespan
                # so close_all() can still dispatch on a live event loop.
                global _ssh
                if _ssh is not None:
                    logger.info("Draining SSH connections on HTTP shutdown")
                    try:
                        await _ssh.close_all()
                        logger.info("SSH connections drained cleanly")
                    except Exception as e:
                        logger.warning(
                            "Error draining SSH connections: %s",
                            e,
                            exc_info=True,
                        )

    app = Starlette(
        routes=[Mount("/", app=inner_app)],
        lifespan=_lifespan,
    )

    if token is not None:
        # Validate token before attaching so bad tokens fail fast at
        # ``_build_http_app`` call time, not on the first request.
        _assert_valid_bearer_token(token)
        _BearerAuth = _make_bearer_auth_middleware()
        app.add_middleware(_BearerAuth, expected=token)

    return app


def _assert_valid_bearer_token(token: str) -> None:
    """Raise ValueError if ``token`` cannot work as an HTTP bearer credential.

    Validates the token before installing the bearer middleware. Called by
    ``_build_http_app`` so bad tokens fail fast at app construction time,
    not on the first request. Applies to BOTH sources — the
    ``SSH_MCP_HTTP_TOKEN`` env var and ``SSH_MCP_HTTP_TOKEN_FILE`` — because
    both converge on the same ``token`` variable before this runs.

    Two rules:

    * At least ``_MIN_TOKEN_LENGTH`` characters. A short or empty secret
      guarding remote command execution is a security risk.
    * Printable ASCII with no interior whitespace. This is not pedantry: a
      validator demonstrated against the installed h11 that a token
      containing NUL or a newline raises ``LocalProtocolError: Illegal
      header value`` in the CLIENT, and that a non-ASCII token is Latin-1
      encoded by common clients while the middleware compares UTF-8 bytes —
      so the server would start happily with a secret that returns 401 to
      everyone, forever. Failing at startup turns a silently unusable
      deployment into an actionable error. The rule is deliberately looser
      than RFC 6750's ``b64token`` grammar, which would reject characters
      that do work today (``:``, ``!``) and break existing deployments.
    """
    if not token or len(token) < _MIN_TOKEN_LENGTH:
        raise ValueError(
            f"bearer token must be at least {_MIN_TOKEN_LENGTH} characters "
            f"(got {len(token)}) — a short or empty token is a security risk"
        )
    if not token.isascii() or not token.isprintable() or any(map(str.isspace, token)):
        raise ValueError(
            "bearer token must be printable ASCII with no whitespace — an "
            "HTTP header value cannot carry control characters, interior "
            "spaces or non-ASCII text, so such a token would return 401 to "
            "every client. Check for a stray newline, tab or non-ASCII "
            "character in SSH_MCP_HTTP_TOKEN / SSH_MCP_HTTP_TOKEN_FILE."
        )


def _make_bearer_auth_middleware() -> Any:
    """Return the ``_BearerAuth`` pure ASGI middleware class.

    Uses a raw ASGI middleware instead of Starlette's ``BaseHTTPMiddleware``
    to avoid known issues with body copying that breaks SSE streaming and
    memory leaks under concurrency (R5 audit finding).

    The middleware:
      * Requires ``Authorization: <scheme> <token>`` header on every request
        where ``<scheme>`` is ``Bearer`` (case-insensitive per RFC 7235 §2.1)
      * Uses ``hmac.compare_digest`` to prevent timing attacks on the secret
      * Returns 401 with ``WWW-Authenticate`` on missing/invalid credentials
      * Passes non-HTTP scopes (lifespan, websocket) through unchanged
    """
    import hmac
    import json

    async def _send_401(
        send: Any,
        body: dict[str, str],
        headers: list[tuple[bytes, bytes]] | None = None,
    ) -> None:
        encoded = json.dumps(body).encode()
        response_headers = list(headers or [(b"content-type", b"application/json")])
        response_headers.append((b"content-length", str(len(encoded)).encode()))
        await send(
            {
                "type": "http.response.start",
                "status": 401,
                "headers": response_headers,
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": encoded,
            }
        )

    class _BearerAuth:
        def __init__(self, app: Any, expected: str) -> None:
            self.app = app
            self._expected = expected

        async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
            if scope["type"] != "http":
                await self.app(scope, receive, send)
                return

            headers = dict(scope.get("headers", []))
            raw_auth = headers.get(b"authorization", b"")
            # N5: split and compare in BYTES space rather than decoding the
            # credential portion to str. The header used to be decoded
            # wholesale with "latin-1" (which never itself raises — every
            # byte 0x00-0xFF has a latin-1 codepoint) and then compared via
            # hmac.compare_digest(str, str). compare_digest restricts str
            # comparison to ASCII-only and raises TypeError on anything
            # else, so a non-ASCII token turned into an unhandled 500 from
            # inside auth middleware instead of a clean 401. Only the
            # "Bearer" scheme keyword — always ASCII — is decoded; the
            # token bytes are compared directly, which hmac.compare_digest
            # accepts unconditionally for bytes-like arguments.
            parts = raw_auth.split(maxsplit=1)
            if len(parts) != 2 or parts[0].decode("latin-1").lower() != "bearer":
                await _send_401(
                    send,
                    {"error": "missing bearer token"},
                    headers=[
                        (b"content-type", b"application/json"),
                        (b"www-authenticate", b'Bearer realm="ssh-mcp"'),
                    ],
                )
                return
            supplied = parts[1]
            expected = self._expected.encode("utf-8")
            if not hmac.compare_digest(supplied, expected):
                await _send_401(
                    send,
                    {"error": "invalid bearer token"},
                    headers=[
                        (b"content-type", b"application/json"),
                        (
                            b"www-authenticate",
                            b'Bearer realm="ssh-mcp", error="invalid_token"',
                        ),
                    ],
                )
                return
            await self.app(scope, receive, send)

    return _BearerAuth


def _build_transport_security(
    raw_allowed_hosts: str | None, host: str
) -> TransportSecuritySettings:
    """Build DNS-rebinding-protection settings, refusing wildcard hosts.

    ``raw_allowed_hosts`` is the unprocessed
    ``os.environ.get("SSH_MCP_HTTP_ALLOWED_HOSTS")`` value: ``None`` means
    unset, ``""`` means set-but-empty, and a whitespace-only string is a
    third, separately-refused case. This function does the stripping, so
    callers hand it the raw value.

    Pure: no globals read or written, so the refusal set is unit-testable.
    In v1 this mutated ``mcp.settings.transport_security``; v2 removed
    that field and takes the object on ``streamable_http_app()`` instead.
    """
    allowed_hosts_env = (raw_allowed_hosts or "").strip()

    base_hosts = ["127.0.0.1:*", "localhost:*", "[::1]:*"]
    extra_hosts: list[str] = []
    # Truthy covers exactly "neither None nor empty", the two values that
    # both mean "unset"; a non-empty value that strips to nothing is the
    # third, refused case.
    if raw_allowed_hosts and not allowed_hosts_env:
        # Explicitly set but whitespace-only after stripping. Distinct from
        # "unset" (which falls through to the localhost-only default below)
        # — a whitespace value almost always means a broken env-file
        # substitution, and silently treating it as "no extra hosts" would
        # mask that from the operator.
        raise RuntimeError(
            "SSH_MCP_HTTP_ALLOWED_HOSTS is set but contains only whitespace. "
            "Unset the variable to use the localhost-only default, or "
            "provide a concrete hostname (e.g. 'ssh-mcp.internal:*')."
        )
    if allowed_hosts_env:
        extra_hosts = [h.strip() for h in allowed_hosts_env.split(",") if h.strip()]
        # H4: reject wildcards — they silently disable DNS-rebinding
        # protection. An operator setting "*" almost certainly means
        # "match my specific hostname" and doesn't realize the security
        # implication. Fail loud instead of silently letting it through.
        #
        # Ordering trap (regression found on ci/fix-digest-verification):
        # an earlier implementation special-cased entries starting with
        # "*." as "always a permitted suffix wildcard, skip refusal" via a
        # `continue` evaluated before the `entry in {"*", "*:*", "*.*"}`
        # refusal was reached. "*.*" starts with "*." too, so that
        # `continue` fired first and let "*.*" — semantically identical to
        # the bare "*" this gate exists to block — through as PERMITTED.
        # Do not reintroduce a startswith("*.")-first shortcut.
        #
        # Suffix wildcards are now REFUSED too (panel finding 2026-09-06,
        # two independent validators plus a direct read of the installed
        # SDK). Until 0.7.0 this gate permitted "*.internal.example.com"
        # and three docs sites advertised it, but the SDK never
        # implemented suffix matching: mcp 2.1.1's
        # TransportSecurityMiddleware._validate_host
        # (mcp/server/transport_security.py:50-69) does an exact-set
        # lookup and then ONE trailing ":*" port-wildcard pass, and there
        # is no "*." handling anywhere in the SDK. A "*." entry was
        # therefore matched LITERALLY, so a real Host header such as
        # "api.internal.example.com" got a 421 and the operator had no
        # way to see why. Refusing at startup turns a silent
        # reject-everything into a loud, actionable error. Only a
        # trailing ":*" port wildcard is a real feature here.
        for entry in extra_hosts:
            remainder = entry[:-2] if entry.endswith(":*") else entry
            if not remainder or "*" in remainder or not remainder.strip("."):
                raise RuntimeError(
                    f"SSH_MCP_HTTP_ALLOWED_HOSTS entry {entry!r} contains a "
                    "wildcard the MCP SDK does not implement, so it would "
                    "match no request at all. Only a trailing ':*' port "
                    "wildcard is supported. List each concrete hostname "
                    "instead (e.g. 'api.internal.example.com:*')."
                )

    # Also add the actual bind host if it's not already covered.
    #
    # The `# nosec B104` is LOAD-BEARING despite what bandit says about it.
    # Bandit prints "nosec encountered (B104), but no failed test on file
    # server.py" three times per run, which reads exactly like a redundant
    # suppression -- and 0.7.0 briefly deleted it on that basis. CI went
    # red: bandit raises B104 (hardcoded_bind_all_interfaces) on the
    # "0.0.0.0" literal in this set and exits 1. The literal is a
    # comparison EXCLUDING 0.0.0.0 from the allow-list, i.e. the opposite
    # of binding to it, so the finding is a false positive and the
    # suppression is correct. Do not remove it; that misleading warning is
    # a bandit quirk, not a signal.
    if host not in {"127.0.0.1", "localhost", "::1", "0.0.0.0"}:  # nosec B104
        base_hosts.append(f"{host}:*")

    default_origins = [
        "http://127.0.0.1:*",
        "http://localhost:*",
        "http://[::1]:*",
    ]
    # v2's own field default is True (mcp/server/transport_security.py:26),
    # but we always pass this explicitly (D7) rather than relying on
    # either default: passing any transport_security object at all
    # suppresses the SDK's loopback-only auto-enable
    # (mcp/server/lowlevel/server.py:735), so the value has to be stated
    # here.
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[*base_hosts, *extra_hosts],
        allowed_origins=default_origins,
    )


# A bearer token is tens of bytes. The cap exists so a mistyped
# SSH_MCP_HTTP_TOKEN_FILE pointing at a log file or a device node is refused
# instead of being slurped into memory and then used as a secret. Kept as a
# module-level constant rather than a Settings field for the same reason as
# ssh.py's tunables: greppable and testable without widening the
# operator-facing config surface.
_MAX_TOKEN_FILE_BYTES = 65536


def _read_token_file(token_file: str) -> str:
    """Read the bearer token from a file, validating what we actually read.

    This guards a secret that authenticates an endpoint which executes shell
    commands, so the checks are deliberate rather than defensive boilerplate:

    * The descriptor is ``fstat``-ed and read, so every check applies to the
      SAME object that supplies the token. Stat-then-open would be a TOCTOU
      window on exactly the file an attacker would want to swap.
    * ``O_NONBLOCK`` means a fifo does not hang startup forever waiting for a
      writer. It is a no-op on a regular file, and deliberately NOT claimed
      as a liveness guarantee: a regular file on a slow or hostile FUSE
      mount can still block the read, which is a local denial of service by
      whoever controls that mount and the config pointing at it. Bounding
      that would need a reader thread plus a timeout, which is not worth the
      complexity for a startup-only path whose input is operator
      configuration rather than request data.
    * A non-regular file is REFUSED: no deployment legitimately points this at
      a directory, socket or device, so it is unambiguously misconfiguration.
    * An oversized file is REFUSED, both on the ``st_size`` snapshot and on
      the bytes actually read (see ``_MAX_TOKEN_FILE_BYTES``).
    * A group/other WRITABLE mode is REFUSED. Whoever can write the file
      chooses the token that authorises remote command execution, so this is
      an integrity hole rather than a disclosure one, and it costs nothing to
      refuse: neither Docker's ``0444`` nor Kubernetes' ``0644`` carries a
      group/other write bit.
    * A group/other READABLE mode only WARNS. It deliberately does not
      refuse: Docker Swarm mounts secrets ``0444`` and Kubernetes defaults to
      ``0644``, so refusing would break the two most common secret mounts
      outright. World-readable inside an isolated container image is a very
      different risk from world-readable on a shared host, and this code
      cannot reliably tell which it is in — so it reports the mode and leaves
      the judgement to the operator. An execute bit alone is silent: it
      discloses nothing about a regular file's contents.
    * An owner that is neither this process nor root only WARNS, for the same
      container reason — secret mounts are commonly root-owned and consumed
      unprivileged — but it is worth saying, because that user can rewrite
      the token at will. This also covers the hardlink-to-another-users-file
      case, where the inode's owner is the giveaway.

    Symlinks are FOLLOWED on purpose, which is the one place this diverges
    from ``paths.py::ensure_root``'s ``O_NOFOLLOW``. Kubernetes projects each
    secret key as a symlink (``key`` -> ``..data/key`` -> ``..<ts>/key``) so
    that updates are atomic; refusing symlinks here would reject every
    Kubernetes secret mount. The confinement argument that justifies
    ``O_NOFOLLOW`` for ``transfer_root`` does not transfer: there is no tree
    beneath this path to confine, and the ``fstat`` below still describes the
    real file the token came from.

    Raises:
        RuntimeError: on an unreadable, non-regular or oversized file.
    """
    try:
        # getattr, not os.O_NONBLOCK: the constant is POSIX-only and absent
        # on Windows, where a bare reference raises AttributeError before the
        # OSError handler below can turn it into an actionable message. 0.7.0
        # read this file with Path.read_text(), which worked on Windows, so a
        # hard reference would be a platform regression — and CI is
        # ubuntu-only, so nothing here would have caught it. Falling back to
        # 0 just means no O_NONBLOCK, which is exactly the pre-0.7.1
        # behaviour on the one platform that has no fifos to guard against.
        # NB: this is unlike the SFTP subsystem, which fails closed off
        # POSIX on purpose (paths.py::ensure_root) — the HTTP transport has
        # never been documented POSIX-only.
        fd = os.open(token_file, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    except OSError as e:
        raise RuntimeError(
            f"SSH_MCP_HTTP_TOKEN_FILE={token_file!r} could not be read: {e}"
        ) from e
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise RuntimeError(
                f"SSH_MCP_HTTP_TOKEN_FILE={token_file!r} is not a regular file "
                f"(mode {stat.filemode(st.st_mode)}). Point it at a file "
                "containing the token."
            )
        if st.st_size > _MAX_TOKEN_FILE_BYTES:
            raise RuntimeError(
                f"SSH_MCP_HTTP_TOKEN_FILE={token_file!r} is "
                f"{st.st_size} bytes, over the {_MAX_TOKEN_FILE_BYTES}-byte "
                "limit. A bearer token is tens of bytes — this is almost "
                "certainly the wrong path."
            )
        # Permission checks are POSIX-only. On Windows CPython SYNTHESISES
        # st_mode as S_IFREG|0o666 for any non-read-only file (0o444 when the
        # read-only attribute is set), so `& 0o022` would be true for every
        # ordinary file and this would refuse EVERY Windows token file while
        # telling the operator to run `chmod go-w`, which does not exist
        # there. Verified against `stat.S_IFREG | 0o666`. The mode bits carry
        # no ACL information on Windows, so there is nothing meaningful to
        # check rather than something to fake.
        posix_perms = os.name == "posix"
        # Group/other WRITE is refused, not warned. Panel finding: the
        # original single `& 0o077` test lumped three different things
        # together. A writable token file is an INTEGRITY hole, strictly
        # worse than disclosure — anyone who can write it chooses the secret
        # that authorises remote command execution, then waits for a
        # restart. Refusing costs nothing in the deployments this code
        # bends over backwards to support: Docker Swarm mounts secrets 0444
        # and Kubernetes defaults to 0644, neither of which carries a
        # group/other write bit.
        #
        # It is load-bearing rather than advisory, but it is a SNAPSHOT: a
        # successful O_RDONLY open proves only that THIS process may read,
        # and says nothing about whether others may mutate the inode, so
        # refusing here does stop a steady-state 0666 file from supplying the
        # secret. It is not a continuous immutability guarantee — the owner,
        # root, or a writer holding an fd opened while the file was still
        # writable can change the content afterwards.
        if posix_perms and st.st_mode & 0o022:
            raise RuntimeError(
                f"SSH_MCP_HTTP_TOKEN_FILE={token_file!r} is writable beyond "
                f"its owner (mode {oct(stat.S_IMODE(st.st_mode))}). Anyone "
                "who can write this file chooses the token that authorises "
                "remote command execution. Run: chmod go-w "
                f"{token_file!r}"
            )
        # READ access only warns — see the docstring for why this cannot be
        # fatal. Note this tests 0o044 rather than 0o077: an execute bit on
        # a regular file discloses nothing, so warning about it was noise.
        if posix_perms and st.st_mode & 0o044:
            logger.warning(
                "SSH_MCP_HTTP_TOKEN_FILE %r is readable beyond its owner "
                "(mode %s). This token authenticates remote command "
                "execution; prefer 0600. Container secret mounts are "
                "commonly 0444 (Docker) or 0644 (Kubernetes), which is "
                "usually acceptable inside an isolated image but not on a "
                "shared host.",
                token_file,
                oct(stat.S_IMODE(st.st_mode)),
            )
        # Ownership warns rather than refuses, for the same container reason:
        # Docker and Kubernetes secret mounts are commonly root-owned while
        # the process runs unprivileged, so `st_uid == geteuid()` would
        # reject them. But a file owned by some OTHER unprivileged user is
        # worth saying out loud: that user can rewrite it whenever they like.
        #
        # `os.geteuid` is POSIX-only, exactly like `os.O_NONBLOCK` above, and
        # a bare call would AttributeError on Windows for EVERY token file —
        # a validator caught this as the same class of bug the O_NONBLOCK
        # getattr already guards against. Windows has no uid to compare, so
        # the check is skipped there rather than faked.
        geteuid = getattr(os, "geteuid", None)
        if geteuid is not None and st.st_uid not in (geteuid(), 0):
            logger.warning(
                "SSH_MCP_HTTP_TOKEN_FILE %r is owned by uid %d, which is "
                "neither this process (uid %d) nor root. That user can "
                "replace the token at any time.",
                token_file,
                st.st_uid,
                geteuid(),
            )
        # Read BYTES, not text. `st_size` above is only a pre-read snapshot —
        # a regular file can grow between `fstat` and `read` — so the cap has
        # to bind on what was actually read. It must also bind on BYTES:
        # `TextIOWrapper.read(n)` counts decoded CHARACTERS, so reading
        # `n` from a text stream accepted 65,536 multi-byte characters =
        # 131,072 bytes and still passed, which a validator demonstrated with
        # a file of `é`. Decoding after the length check makes the limit mean
        # what README and CHANGELOG say it means.
        with os.fdopen(fd, "rb") as fh:
            fd = -1  # fdopen owns it now; do not double-close in `finally`
            raw = fh.read(_MAX_TOKEN_FILE_BYTES + 1)
        if len(raw) > _MAX_TOKEN_FILE_BYTES:
            raise RuntimeError(
                f"SSH_MCP_HTTP_TOKEN_FILE={token_file!r} exceeds the "
                f"{_MAX_TOKEN_FILE_BYTES}-byte limit while being read. "
                "A bearer token is tens of bytes — this is almost "
                "certainly the wrong path."
            )
        # utf-8-sig, not utf-8: a BOM is NOT whitespace, so `.strip()` leaves
        # it on the front of the token. Windows Notepad and PowerShell's
        # `Out-File` both write one by default, and the result was a token
        # that looked correct to the operator, counted the BOM toward the
        # 16-character minimum, and returned 401 to every client forever.
        # utf-8-sig is a superset here — it decodes BOM-less UTF-8 unchanged.
        return raw.decode("utf-8-sig").strip()
    except UnicodeDecodeError as e:
        # UnicodeDecodeError is a ValueError, NOT an OSError, so the handler
        # below does not catch it and it would escape as a raw traceback at
        # startup. Found by exercising a token file containing invalid UTF-8.
        # The old `Path.read_text()` raised the same thing, so this is not a
        # regression — but the docstring promises RuntimeError, and a binary
        # file is exactly the kind of wrong path an operator needs told.
        raise RuntimeError(
            f"SSH_MCP_HTTP_TOKEN_FILE={token_file!r} is not valid UTF-8 "
            f"({e.reason} at byte {e.start}). A bearer token must be text; "
            "this looks like a binary file."
        ) from e
    except OSError as e:
        raise RuntimeError(
            f"SSH_MCP_HTTP_TOKEN_FILE={token_file!r} could not be read: {e}"
        ) from e
    finally:
        if fd != -1:
            os.close(fd)


def _run_http() -> None:
    """Run ssh-mcp over MCP streamable HTTP transport.

    Configured via environment variables:

    * ``SSH_MCP_HTTP_HOST`` — bind address, default ``127.0.0.1``.
      Using any non-localhost value (``0.0.0.0``, a LAN IP, etc.) REQUIRES
      ``SSH_MCP_HTTP_TOKEN`` to be set, otherwise startup aborts.
    * ``SSH_MCP_HTTP_PORT`` — TCP port, default ``8000``.
    * ``SSH_MCP_HTTP_AUTH`` — authentication mode, default ``bearer``.
      Set to ``none`` to skip the bearer middleware entirely (typical
      when ssh-mcp sits behind a trusted reverse proxy that performs
      authentication itself). When ``none`` is combined with a
      non-localhost bind, ``SSH_MCP_HTTP_NETWORK_NO_AUTH=I_ACCEPT_RCE_RISK``
      is ALSO required — this is a deliberately verbose escape hatch.
    * ``SSH_MCP_HTTP_TOKEN`` — shared bearer secret (required when
      ``SSH_MCP_HTTP_AUTH=bearer`` and bind is non-localhost). When set,
      every request must carry ``Authorization: Bearer <token>`` or 401.
    * ``SSH_MCP_HTTP_TOKEN_FILE`` — path read for the bearer secret when
      ``SSH_MCP_HTTP_TOKEN`` is empty or unset (Docker/Compose secret
      mounts). An unreadable path aborts startup.
    * ``SSH_MCP_HTTP_NETWORK_NO_AUTH`` — magic-string opt-out for the
      ``auth=none`` + non-localhost combination. Must equal literal
      ``I_ACCEPT_RCE_RISK`` to take effect.
    * ``SSH_MCP_HTTP_STATELESS`` — if ``true``, MCPServer runs in stateless
      mode. Recommended for load-balanced or serverless deployments.
    * ``SSH_MCP_HTTP_ALLOWED_HOSTS`` — comma-separated extra Host headers
      for DNS-rebinding protection (in addition to localhost). Protection is
      always ON and cannot be disabled; bare wildcard entries (``*``, ``*:*``,
      ``*.*``) abort startup because they would silently defeat it. A
      leading ``*.`` suffix wildcard is ALSO refused as of 0.7.0: the MCP
      SDK never implemented suffix matching, so such an entry matched
      literally and rejected every real request. List concrete hostnames.
    * ``SSH_MCP_HTTP_KEEPALIVE_TIMEOUT`` / ``SSH_MCP_HTTP_LIMIT_CONCURRENCY``
      / ``SSH_MCP_HTTP_BACKLOG`` — uvicorn tuning knobs, see
      ``_parse_http_tuning`` for defaults and accepted ranges.
    """
    import uvicorn

    host = os.environ.get("SSH_MCP_HTTP_HOST", "127.0.0.1")
    raw_port = os.environ.get("SSH_MCP_HTTP_PORT", "8000")
    try:
        port = int(raw_port)
    except ValueError as exc:
        raise RuntimeError(
            f"SSH_MCP_HTTP_PORT={raw_port!r} is not a valid integer"
        ) from exc
    if not (1 <= port <= 65535):
        raise RuntimeError(
            f"SSH_MCP_HTTP_PORT={port} is out of range (must be 1-65535)"
        )
    # M4: strip whitespace so env-file tokens with a trailing newline work
    env_token_raw = os.environ.get("SSH_MCP_HTTP_TOKEN", "")
    raw_token = env_token_raw.strip()
    # P5: fall back to reading token from a file (e.g. Docker secret mount)
    token_file = os.environ.get("SSH_MCP_HTTP_TOKEN_FILE", "").strip()
    if not raw_token and token_file:
        raw_token = _read_token_file(token_file)
        if not raw_token:
            # "Configured but empty" is NOT the same as "not configured", and
            # collapsing the two silently disabled authentication: an empty
            # token file mapped to `token = None`, which on a loopback bind
            # means the endpoint serves with NO bearer middleware at all.
            # An operator who went to the trouble of mounting a secret file
            # is not asking for that. Panel finding 2026-09-06; it also
            # mirrors the treatment SSH_MCP_HTTP_ALLOWED_HOSTS has always
            # had, where set-but-whitespace is refused rather than silently
            # read as "no extra hosts".
            raise RuntimeError(
                f"SSH_MCP_HTTP_TOKEN_FILE={token_file!r} is empty or contains "
                "only whitespace. A configured token source that yields no "
                "token would silently disable authentication. Write a token "
                "to the file, unset the variable, or set "
                "SSH_MCP_HTTP_AUTH=none if unauthenticated is deliberate."
            )
    elif not raw_token and env_token_raw and not token_file:
        # Same rule for the env var: a non-empty value that strips to nothing
        # is a broken substitution (e.g. `SSH_MCP_HTTP_TOKEN="${SECRET}"`
        # with SECRET unset expanding to a space), not a request for
        # anonymous access. A literal "" is still treated as unset, matching
        # how every other SSH_MCP_HTTP_* variable behaves.
        raise RuntimeError(
            "SSH_MCP_HTTP_TOKEN is set but contains only whitespace. A "
            "configured token that strips to nothing would silently disable "
            "authentication. Set a real token, unset the variable, or set "
            "SSH_MCP_HTTP_AUTH=none if unauthenticated is deliberate."
        )
    token = raw_token or None
    stateless = (
        os.environ.get("SSH_MCP_HTTP_STATELESS", "false").strip().lower() == "true"
    )
    # Keep the raw (pre-strip) value around so we can tell "unset" apart
    # from "explicitly set to whitespace" below — os.environ.get(..., "")
    # collapses both to "", which would let a blank templated env var
    # (e.g. "${EXTRA_HOSTS:- }") silently fall back to the localhost-only
    # default instead of failing loud on what is almost always a config
    # generation mistake.
    _allowed_hosts_raw = os.environ.get("SSH_MCP_HTTP_ALLOWED_HOSTS")

    # Auth-mode dispatch. Default ``bearer`` preserves v0.3.1 behavior.
    # ``none`` disables the bearer middleware entirely — useful when a
    # reverse proxy handles authentication.
    auth_mode = os.environ.get("SSH_MCP_HTTP_AUTH", "bearer").strip().lower()
    if auth_mode not in {"bearer", "none"}:
        raise RuntimeError(
            f"Unknown SSH_MCP_HTTP_AUTH={auth_mode!r}. "
            "Valid values: 'bearer' (default), 'none'."
        )

    # Security gate: refuse to expose the server to non-localhost traffic
    # without a token. Localhost binds remain unauthenticated because they
    # match the historical stdio deployment model (single-user workstation).
    #
    # Green Team Round 1 finding H5: use ``ipaddress.ip_address().is_loopback``
    # so non-canonical forms (``::ffff:127.0.0.1``, ``0:0:0:0:0:0:0:1``,
    # entire 127.0.0.0/8 block) are correctly classified. Fall back to a
    # string match for hostnames that aren't valid IP literals.
    import ipaddress

    try:
        is_localhost = ipaddress.ip_address(host).is_loopback
    except ValueError:
        # Hostname (not an IP literal) — fall back to the known-safe names
        is_localhost = host.lower() in {"localhost"}

    if auth_mode == "bearer":
        if not is_localhost and token is None:
            raise RuntimeError(
                f"SSH_MCP_HTTP_TOKEN must be set when binding to {host!r}. "
                "Refusing to expose SSH command execution over the network "
                "without bearer-token authentication."
            )
    else:  # auth_mode == "none"
        # Force token to None so the wrapper doesn't attach the middleware
        # even if the operator left SSH_MCP_HTTP_TOKEN set by mistake.
        token = None
        if not is_localhost:
            # Require the long-form escape hatch for network binds.
            ack = os.environ.get("SSH_MCP_HTTP_NETWORK_NO_AUTH", "")
            if ack != "I_ACCEPT_RCE_RISK":
                raise RuntimeError(
                    f"SSH_MCP_HTTP_AUTH=none with host={host!r} is refused. "
                    "Binding an unauthenticated SSH command executor to a "
                    "non-localhost address is equivalent to granting a "
                    "remote root shell to anyone who can reach the port. "
                    "If you understand the risk and handle authentication "
                    "at a reverse proxy, set environment variable "
                    "SSH_MCP_HTTP_NETWORK_NO_AUTH=I_ACCEPT_RCE_RISK to "
                    "proceed."
                )

    # v2 removed the mcp.settings.host / .port / .stateless_http /
    # .transport_security fields entirely (assigning them now raises
    # ValueError); stateless is threaded through _build_http_app's
    # streamable_http_app() call instead, and host and port are only
    # ever needed by _build_transport_security's allow-list entry and
    # uvicorn.run() below. transport_security is built by the pure,
    # unit-testable _build_transport_security so no module global is
    # mutated.
    transport_security = _build_transport_security(_allowed_hosts_raw, host)

    effective_auth = "bearer" if token else "none"
    logger.info(
        "Starting ssh-mcp v%s (streamable-http) on %s:%s stateless=%s auth=%s",
        __version__,
        host,
        port,
        stateless,
        effective_auth,
    )
    if token is None:
        if is_localhost:
            logger.warning(
                "HTTP transport is running WITHOUT authentication on %s. "
                "Do NOT forward this port beyond the loopback interface.",
                host,
            )
        else:
            # Loud banner for operators who opted into the no-auth escape
            # hatch — they passed the long-form ack so they know, but the
            # log stream should still scream about it.
            logger.warning(
                "⚠️  ssh-mcp is serving UNAUTHENTICATED HTTP on %s:%s. "
                "You accepted SSH_MCP_HTTP_NETWORK_NO_AUTH=I_ACCEPT_RCE_RISK. "
                "Every request that reaches /mcp can execute shell commands "
                "on the configured remote servers. Terminate auth at your "
                "reverse proxy and NEVER expose this port to an untrusted "
                "network.",
                host,
                port,
            )

    app = _build_http_app(
        token, stateless=stateless, transport_security=transport_security
    )

    # Tuning knobs for uvicorn — see `_parse_http_tuning` for defaults
    # and rationale. These exist because the v0.4.0 default (uvicorn's
    # own ``timeout_keep_alive=5s``) accumulated enough concurrent
    # keepalive connections under n8n burst traffic to exhaust the
    # container's 1024 fd limit, crashing on ``socket.accept()``.
    keepalive, concurrency, backlog = _parse_http_tuning()
    logger.info(
        "HTTP tuning: timeout_keep_alive=%ss limit_concurrency=%s backlog=%s",
        keepalive,
        concurrency,
        backlog,
    )

    # Run the ASGI server. uvicorn's own access logs go to stdout by
    # default — route them to stderr to preserve the MCP convention that
    # protocol output and operational logs are on separate channels.
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_config=None,  # use the root logger we configured above
        timeout_keep_alive=keepalive,
        limit_concurrency=concurrency,
        backlog=backlog,
    )


def _parse_http_tuning() -> tuple[int, int, int]:
    """Parse the uvicorn tuning env vars with validation.

    Returns ``(timeout_keep_alive, limit_concurrency, backlog)``.

    Defaults are chosen to survive bursty keepalive traffic on a
    1024-fd container (typical Docker default) without tuning:

    * ``timeout_keep_alive=2`` (down from uvicorn's 5s default) —
      closes idle HTTP/1.1 connections fast so ephemeral clients
      like n8n don't pile up ESTABLISHED sockets.
    * ``limit_concurrency=256`` — rejects new requests with 503 once
      256 in-flight, preventing unbounded connection growth.
    * ``backlog=128`` — smaller listen backlog than uvicorn's 2048
      default so a SYN flood is capped earlier.

    Operators can override via ``SSH_MCP_HTTP_KEEPALIVE_TIMEOUT``,
    ``SSH_MCP_HTTP_LIMIT_CONCURRENCY``, and ``SSH_MCP_HTTP_BACKLOG``.

    Raises:
        RuntimeError: if any value is non-numeric or negative, or is zero for
            ``limit_concurrency`` or ``backlog`` — only
            ``SSH_MCP_HTTP_KEEPALIVE_TIMEOUT`` accepts 0.
    """

    def _parse_int(name: str, default: int, *, min_value: int) -> int:
        raw = os.environ.get(name)
        if raw is None or raw.strip() == "":
            return default
        try:
            value = int(raw)
        except ValueError as exc:
            raise RuntimeError(f"{name}={raw!r} is not a valid integer") from exc
        if value < min_value:
            raise RuntimeError(
                f"{name}={value} is below the minimum allowed value {min_value}"
            )
        return value

    keepalive = _parse_int("SSH_MCP_HTTP_KEEPALIVE_TIMEOUT", default=2, min_value=0)
    concurrency = _parse_int("SSH_MCP_HTTP_LIMIT_CONCURRENCY", default=256, min_value=1)
    backlog = _parse_int("SSH_MCP_HTTP_BACKLOG", default=128, min_value=1)
    return keepalive, concurrency, backlog


def main() -> None:
    """Entry point for console script (uvx ssh-mcp).

    Handles one CLI subcommand before anything else: ``ssh-mcp healthcheck``
    runs ``ssh_mcp.healthcheck.run()`` and exits 0 or 1 without opening a socket
    or starting a transport. This is what the Dockerfile HEALTHCHECK invokes.

    Otherwise dispatches on ``SSH_MCP_TRANSPORT``:

    * ``stdio`` (default) — classic MCP stdio subprocess transport,
      used by Claude Desktop / Claude Code via ``uvx ssh-mcp``.
    * ``http`` or ``streamable-http`` — MCP streamable HTTP transport on
      a TCP port. Requires ``SSH_MCP_HTTP_TOKEN`` for non-localhost binds.
      See ``_run_http`` for the full list of env vars.
    """
    # Dispatch subcommands BEFORE any expensive setup.
    # The ``healthcheck`` subcommand must NOT touch ``mcp.run`` or open sockets.
    if len(sys.argv) >= 2 and sys.argv[1] == "healthcheck":
        from ssh_mcp.healthcheck import run as run_healthcheck

        run_healthcheck()  # exits 0 or 1
        return  # unreachable but keeps mypy happy

    from ssh_mcp import __version__

    transport = os.environ.get("SSH_MCP_TRANSPORT", "stdio").strip().lower()

    if transport in ("http", "streamable-http"):
        try:
            config_path = _get_config_path()
            logger.info("Config will be loaded from %s on first tool call", config_path)
        except FileNotFoundError as e:
            logger.warning("No config file found yet: %s", e)
        _run_http()
        return

    if transport != "stdio":
        raise ValueError(
            f"Unknown SSH_MCP_TRANSPORT={transport!r}. "
            "Valid values: stdio, http, streamable-http."
        )

    logger.info(
        "Starting ssh-mcp v%s (stdio transport) - waiting for MCP client on stdin",
        __version__,
    )
    try:
        config_path = _get_config_path()
        logger.info("Config will be loaded from %s on first tool call", config_path)
    except FileNotFoundError as e:
        logger.warning("No config file found yet: %s", e)
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
