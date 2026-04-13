"""Liveness healthcheck for ssh-mcp Docker container.

Invoked as ``ssh-mcp healthcheck`` from the Dockerfile HEALTHCHECK
directive. Exits 0 if the server is healthy, 1 otherwise. Prints a
single diagnostic line to stderr on failure (never logs the token).

Auto-detects transport via ``SSH_MCP_TRANSPORT`` env var:
  * ``stdio`` (default): import check + config file parse
  * ``http`` / ``streamable-http``: MCP initialize POST handshake
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
    """Read bearer token from env or token file. Returns None if neither set."""
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
    """Verify the package imports and the config file parses.

    Returns (ok, diagnostic).
    """
    try:
        import ssh_mcp  # noqa: F401
    except ImportError as e:
        return False, f"import failed: {e}"
    # Try to resolve and parse config if present
    config_path = os.environ.get("SSH_MCP_CONFIG", "")
    if config_path and Path(config_path).exists():
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
        # URL is hardcoded http://127.0.0.1:<port>/mcp — not user-controlled
        # and not a file:// scheme. Port comes from the validated
        # SSH_MCP_HTTP_PORT env var, so B310 (permitted-schemes) doesn't apply.
        with urllib.request.urlopen(req, timeout=HEALTHCHECK_TIMEOUT) as resp:  # nosec B310  # noqa: S310
            return True, f"http {resp.status}"
    except urllib.error.HTTPError as e:
        # Any 4xx means the server is alive but the request was rejected
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
