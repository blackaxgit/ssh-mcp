"""Liveness healthcheck for ssh-mcp Docker container.

Invoked as ``ssh-mcp healthcheck`` from the Dockerfile HEALTHCHECK
directive. Exits 0 if the server is healthy, 1 otherwise. Prints a
single diagnostic line to stderr on failure (never logs the token).

Auto-detects transport via ``SSH_MCP_TRANSPORT`` env var:
  * ``stdio`` (default): import check + config file parse
  * ``http`` / ``streamable-http``: MCP initialize POST handshake
  * any other value: also falls through to the stdio check. That is
    *laxer* than the server, which raises ``Unknown
    SSH_MCP_TRANSPORT=...`` and refuses to start (see
    ``server.py::main``) — so a container that cannot boot because of a
    typo'd transport (``htpp``) still passes this liveness gate.

HTTP mode reads the same env vars as the server: ``SSH_MCP_HTTP_PORT``
(default ``8000``), ``SSH_MCP_HTTP_AUTH`` (``none`` suppresses the
bearer token), ``SSH_MCP_HTTP_TOKEN`` and ``SSH_MCP_HTTP_TOKEN_FILE``.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import NoReturn

HEALTHCHECK_TIMEOUT = 3  # seconds


def _load_token() -> str | None:
    """Read bearer token from env or token file.

    Returns None if neither is set — and also if the token file is
    unreadable or blank, so unset and broken are indistinguishable to the
    caller. Note the asymmetry with ``server.py::_run_http``, which raises
    RuntimeError on an unreadable ``SSH_MCP_HTTP_TOKEN_FILE``: here a
    missing token only means the handshake goes out unauthenticated, and
    the resulting 401 still counts as alive.
    """
    raw = os.environ.get("SSH_MCP_HTTP_TOKEN", "").strip()
    if raw:
        return raw
    token_file = os.environ.get("SSH_MCP_HTTP_TOKEN_FILE", "").strip()
    if token_file:
        try:
            return Path(token_file).read_text().strip() or None
        except OSError:
            return None
    return None


def _check_stdio() -> tuple[bool, str]:
    """Verify the package imports and its resolved config actually parses.

    S15 (production incident risk): the previous version of this check only
    looked at ``SSH_MCP_CONFIG``, and only *if* it was both set and pointed
    at a file that already existed — otherwise it silently reported healthy
    off a bare ``import ssh_mcp``. But ``server.py::_get_config_path`` has a
    three-step fallback chain (``SSH_MCP_CONFIG`` env var ->
    ``$XDG_CONFIG_HOME/ssh-mcp/servers.toml``, falling back to
    ``~/.config/ssh-mcp/servers.toml`` only when ``XDG_CONFIG_HOME`` is
    unset -> package-relative dev config), so a probe that checks only the
    first step is checking a *different* path than the one the server
    actually uses to start up. That asymmetry let a
    container with no usable configuration anywhere in the real chain (e.g.
    ``SSH_MCP_CONFIG`` unset, or set to a typo'd path) still pass Docker's
    liveness gate, because the probe never got far enough to notice.
    "Configured" is therefore defined here as: the server's own resolver
    finds a config file, and that file parses into a valid ServerRegistry.
    We call ``server._get_config_path`` directly instead of re-implementing
    its fallback chain — a hand-rolled second copy would drift from the
    real one the next time either changes, reintroducing this exact bug.
    Measured cost of importing server.py (FastMCP + asyncssh + structlog)
    is ~0.3s. Nothing bounds this branch from the inside:
    HEALTHCHECK_TIMEOUT is only handed to ``urlopen`` in ``_check_http``,
    so the only limit here is the ``--timeout=5s`` the Dockerfile
    HEALTHCHECK directive enforces on the whole probe.

    Returns (ok, diagnostic).
    """
    try:
        import ssh_mcp  # noqa: F401
    except ImportError as e:
        return False, f"import failed: {e}"

    try:
        from ssh_mcp.server import _get_config_path
    except ImportError as e:
        return False, f"import failed: {e}"

    try:
        config_path = _get_config_path()
    except FileNotFoundError as e:
        # Nothing usable anywhere in the chain: the server itself would
        # refuse to start here (see _get_config_path's docstring for the
        # exact chain), so reporting healthy would be a lie the container
        # orchestrator would trust. A *typo'd* SSH_MCP_CONFIG does not land
        # here — step 1 returns that path verbatim with no existence check,
        # so it surfaces below as "config parse failed: FileNotFoundError".
        return False, f"no config resolved: {e}"

    try:
        from ssh_mcp.config import ServerRegistry

        ServerRegistry(config_path)
    except Exception as e:
        return False, f"config parse failed: {type(e).__name__}"

    return True, "stdio healthy"


def _check_http() -> tuple[bool, str]:
    """Send MCP initialize POST and verify the server responds.

    Returns (ok, diagnostic). Any non-5xx status is considered healthy
    (including 401 if auth is misconfigured — the server is clearly alive).
    """
    port = os.environ.get("SSH_MCP_HTTP_PORT", "8000")
    auth_mode = os.environ.get("SSH_MCP_HTTP_AUTH", "bearer").strip().lower()
    token = _load_token() if auth_mode != "none" else None

    # Two values below are implicit couplings to SDK defaults, not knobs:
    # "2025-03-26" is the MCP protocol revision this probe claims, and
    # ``/mcp`` is FastMCP's default streamable_http_path (server.py never
    # overrides it and mounts the app at "/"). If either default moves,
    # this probe must be updated in lockstep or it stops reaching the app.
    payload = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "ssh-mcp-healthcheck", "version": "1"},
            },
        }
    ).encode()

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    url = f"http://127.0.0.1:{port}/mcp"
    req = urllib.request.Request(url, data=payload, method="POST", headers=headers)  # noqa: S310

    try:
        # Scheme, host and path are hardcoded http://127.0.0.1/mcp — never
        # a file:// scheme and not user-controlled, which is what makes
        # B310 (permitted-schemes) moot. The port segment *is* env-derived
        # (SSH_MCP_HTTP_PORT) and is not validated here: no int(), no range
        # check — that validation lives in server.py::_run_http and runs in
        # the server process. A junk value only yields an unreachable URL
        # and an unhealthy verdict.
        with urllib.request.urlopen(req, timeout=HEALTHCHECK_TIMEOUT) as resp:  # nosec B310  # noqa: S310
            return True, f"http {resp.status}"
    except urllib.error.HTTPError as e:
        # Any non-5xx status means the server is alive but the request was rejected
        # (wrong auth, wrong protocol version, etc.) — still healthy.
        if e.code < 500:
            return True, f"http {e.code}"
        return False, f"http {e.code}"
    except urllib.error.URLError as e:
        return False, f"connect failed: {type(e.reason).__name__}"
    except Exception as e:
        return False, f"unexpected: {type(e).__name__}"


def run() -> NoReturn:
    """Entry point invoked by ``ssh-mcp healthcheck`` CLI."""
    transport = os.environ.get("SSH_MCP_TRANSPORT", "stdio").strip().lower()
    if transport in ("http", "streamable-http"):
        ok, diag = _check_http()
    else:
        ok, diag = _check_stdio()

    if not ok:
        print(f"ssh-mcp healthcheck: UNHEALTHY ({diag})", file=sys.stderr)
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    run()
