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


# R5 finding #3: atexit registration flag — prevents stacking multiple
# handlers if _init() is called more than once (e.g. test teardown + re-init).
_atexit_registered: bool = False


def _cleanup_connections() -> None:
    """Best-effort SSH cleanup on process exit (stdio transport only).

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
    except Exception as e:
        logger.warning("Error during connection cleanup: %s", e)


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
        except asyncio.CancelledError:
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
    dry_run: bool = False,
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
        dry_run: If True, do NOT connect or execute. Return a preview describing
                what would run (server, command, working_dir, timeout, force).
                Dangerous-command detection still runs so rejection can be
                previewed. Useful for LLM plans that want to validate intent
                before committing. Default False.

    Returns:
        Formatted command execution result with stdout, stderr, and exit code.
        Long output is truncated at ``max_output_bytes`` (default 50 KiB).
    """
    ssh = _get_ssh()
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
        dry_run: If True, do NOT connect or execute anywhere. Return a
                per-server preview describing what would run. Dangerous-
                command detection still applies. Useful for previewing
                fleet-wide rollouts before committing. Default False.

    Returns:
        Formatted summary showing per-server results, success/failure counts,
        and aggregate exit status.
    """
    ssh = _get_ssh()
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


# Minimum acceptable length for a bearer token. 16 chars ≈ 80 bits of
# entropy if the source is random. Shorter values are rejected at startup
# as likely to be typos, placeholders, or human-chosen weak secrets.
_MIN_TOKEN_LENGTH: int = 16


def _build_http_app(token: str | None) -> Any:
    """Return the Starlette ASGI app for streamable HTTP transport.

    Assembles a SINGLE outer Starlette app containing:

    1. The FastMCP streamable HTTP app mounted under ``/``
    2. A ``lifespan`` that chains the FastMCP session-manager lifespan
       so its internal task group is initialized — without this every
       request returns HTTP 500 with ``RuntimeError('Task group is
       not initialized')``.
    3. On shutdown, drains the pooled SSH manager BEFORE exiting the
       inner lifespan so ``_ssh.close_all()`` can still dispatch
       traffic on a live event loop.
    4. If ``token`` is provided, a bearer-auth middleware is attached
       to THIS outer app (not a separate wrapper) so the middleware
       runs inside the same lifespan context as the FastMCP app.

    Earlier versions (v0.3.0) built three nested Starlette apps:
    bearer wrapper → shutdown-lifespan wrapper → FastMCP. Only the
    outermost lifespan ran, so the FastMCP task group was never
    initialized. This single-app approach fixes that regression.

    Returns a ``Starlette`` instance ready to hand to ``uvicorn.run``.
    """
    from contextlib import asynccontextmanager

    from starlette.applications import Starlette
    from starlette.routing import Mount

    inner_app = mcp.streamable_http_app()

    # R5 finding #8: assert the FastMCP app exposes the lifespan we chain.
    # This is a private Starlette attribute — if the MCP SDK restructures
    # its app in a major version, we want a loud startup crash, not a
    # silent 500-on-every-request like the v0.3.0 incident.
    lifespan_ctx = getattr(getattr(inner_app, "router", None), "lifespan_context", None)
    if not callable(lifespan_ctx):
        raise RuntimeError(
            "FastMCP streamable_http_app() does not expose "
            "router.lifespan_context — the MCP SDK may have changed "
            "its internal structure. ssh-mcp requires this to chain "
            "the session-manager lifespan. Pin mcp[cli]<2.0.0 or "
            "update the lifespan wiring in server.py."
        )

    @asynccontextmanager
    async def _lifespan(_app: Starlette) -> Any:
        # Step 1: start the FastMCP session manager's task group via
        # its own lifespan context.
        async with lifespan_ctx(inner_app):
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
    """Raise ValueError if ``token`` is too short or empty.

    Validates token length before installing the bearer middleware.
    Called by ``_build_http_app`` so bad tokens fail fast at app
    construction time, not on the first request.
    """
    if not token or len(token) < _MIN_TOKEN_LENGTH:
        raise ValueError(
            f"bearer token must be at least {_MIN_TOKEN_LENGTH} characters "
            f"(got {len(token)}) — a short or empty token is a security risk"
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
            auth = headers.get(b"authorization", b"").decode("latin-1")
            parts = auth.split(maxsplit=1)
            if len(parts) != 2 or parts[0].lower() != "bearer":
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
            if not hmac.compare_digest(supplied, self._expected):
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
    * ``SSH_MCP_HTTP_NETWORK_NO_AUTH`` — magic-string opt-out for the
      ``auth=none`` + non-localhost combination. Must equal literal
      ``I_ACCEPT_RCE_RISK`` to take effect.
    * ``SSH_MCP_HTTP_STATELESS`` — if ``true``, FastMCP runs in stateless
      mode. Recommended for load-balanced or serverless deployments.
    * ``SSH_MCP_HTTP_ALLOWED_HOSTS`` — comma-separated extra Host headers
      for DNS-rebinding protection (in addition to localhost).
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
    raw_token = os.environ.get("SSH_MCP_HTTP_TOKEN", "").strip()
    # P5: fall back to reading token from a file (e.g. Docker secret mount)
    if not raw_token:
        token_file = os.environ.get("SSH_MCP_HTTP_TOKEN_FILE", "").strip()
        if token_file:
            try:
                raw_token = Path(token_file).read_text().strip()
            except (OSError, FileNotFoundError) as e:
                raise RuntimeError(
                    f"SSH_MCP_HTTP_TOKEN_FILE={token_file!r} could not be read: {e}"
                ) from e
    token = raw_token or None
    stateless = os.environ.get("SSH_MCP_HTTP_STATELESS", "false").lower() == "true"
    allowed_hosts_env = os.environ.get("SSH_MCP_HTTP_ALLOWED_HOSTS", "").strip()

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

    # Apply settings to the module-level FastMCP instance. The SDK reads
    # these fields at ``streamable_http_app()`` construction time.
    mcp.settings.host = host
    mcp.settings.port = port
    mcp.settings.stateless_http = stateless
    # P3: Always enable DNS rebinding protection, even without
    # SSH_MCP_HTTP_ALLOWED_HOSTS. The MCP SDK defaults to
    # enable_dns_rebinding_protection=False which is unsafe.
    from mcp.server.transport_security import TransportSecuritySettings

    base_hosts = ["127.0.0.1:*", "localhost:*", "[::1]:*"]
    extra_hosts: list[str] = []
    if allowed_hosts_env:
        extra_hosts = [h.strip() for h in allowed_hosts_env.split(",") if h.strip()]
        # H4: reject wildcards — they silently disable DNS-rebinding
        # protection. An operator setting "*" almost certainly means
        # "match my specific hostname" and doesn't realize the security
        # implication. Fail loud instead of silently letting it through.
        for entry in extra_hosts:
            bare = entry.replace(":*", "").replace("*", "")
            if not bare or entry in {"*", "*:*", "*.*"} or entry.startswith("*."):
                if entry.startswith("*."):
                    continue  # wildcard suffixes like *.internal.example.com are OK
                raise RuntimeError(
                    f"SSH_MCP_HTTP_ALLOWED_HOSTS wildcard entry {entry!r} "
                    "would disable DNS-rebinding protection. "
                    "Use a concrete hostname (e.g. 'ssh-mcp.internal:*') instead."
                )

    # Also add the actual bind host if it's not already covered
    if host not in {"127.0.0.1", "localhost", "::1", "0.0.0.0"}:  # nosec B104
        base_hosts.append(f"{host}:*")

    existing = mcp.settings.transport_security
    default_origins = [
        "http://127.0.0.1:*",
        "http://localhost:*",
        "http://[::1]:*",
    ]
    mcp.settings.transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[*base_hosts, *extra_hosts],
        allowed_origins=(
            list(existing.allowed_origins) if existing is not None else default_origins
        ),
    )

    from ssh_mcp import __version__

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

    app = _build_http_app(token)

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
        RuntimeError: if any value is non-numeric, negative, or (for
            ``limit_concurrency``) zero.
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

    Dispatches on ``SSH_MCP_TRANSPORT``:

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
