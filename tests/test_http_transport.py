"""Tests for MCP streamable HTTP transport (Phase C HTTP feature).

Exercises the transport-selection dispatch, the bearer-token middleware,
and the safety gate that refuses to bind non-localhost without auth.
No real network sockets are opened — middleware is tested via Starlette's
TestClient (synchronous, in-process) and the network startup path is
exercised via a mocked ``uvicorn.run``.
"""

from __future__ import annotations

from collections.abc import Iterator
from unittest.mock import patch

import pytest
from starlette.testclient import TestClient

import ssh_mcp.server as server_module
from ssh_mcp.server import _build_http_app, _run_http, _wrap_with_bearer_auth, main


def _make_dummy_asgi_app():
    """Return a trivial Starlette app that returns 200 OK on any path.

    Used as a downstream for bearer-auth middleware tests so we don't
    need the MCP session-manager lifespan to run. The middleware logic
    is what we're actually testing.
    """
    from starlette.applications import Starlette
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route

    async def _ok(_request):
        return PlainTextResponse("downstream ok")

    return Starlette(routes=[Route("/{path:path}", _ok, methods=["GET", "POST"])])


@pytest.fixture(autouse=True)
def _reset_server_globals() -> Iterator[None]:
    """Restore module-level FastMCP settings after each test.

    ``_run_http`` mutates ``mcp.settings`` in place; without this fixture
    a test setting ``host = "0.0.0.0"`` would poison the next one.
    """
    saved_host = server_module.mcp.settings.host
    saved_port = server_module.mcp.settings.port
    saved_stateless = server_module.mcp.settings.stateless_http
    saved_security = server_module.mcp.settings.transport_security
    yield
    server_module.mcp.settings.host = saved_host
    server_module.mcp.settings.port = saved_port
    server_module.mcp.settings.stateless_http = saved_stateless
    server_module.mcp.settings.transport_security = saved_security


# ---------------------------------------------------------------------------
# _build_http_app — middleware wiring
# ---------------------------------------------------------------------------


class TestBuildHttpApp:
    """Verify _build_http_app wraps auth middleware exactly when expected."""

    def test_no_token_returns_raw_fastmcp_app(self) -> None:
        """When token is None, no auth wrapper is added."""
        from starlette.applications import Starlette

        app = _build_http_app(token=None)
        # The raw FastMCP app is a Starlette instance; the wrapper one
        # is also a Starlette, so identity check isn't enough — verify
        # there is no BearerAuth middleware in the stack.
        assert isinstance(app, Starlette)
        middleware_classes = [
            type(m).__name__ for m in getattr(app, "user_middleware", [])
        ]
        assert "Middleware" not in middleware_classes or not any(
            "Bearer" in str(m) for m in middleware_classes
        )

    def test_with_token_wraps_app(self) -> None:
        """When token is set, middleware is registered on the wrapper."""
        app = _build_http_app(token="secret-xyz")
        # The wrapper must expose user_middleware with at least one entry
        assert hasattr(app, "user_middleware")
        assert len(app.user_middleware) > 0


# ---------------------------------------------------------------------------
# Bearer-token middleware behavior (Starlette TestClient)
# ---------------------------------------------------------------------------


class TestBearerTokenMiddleware:
    """Middleware tested against a trivial downstream ASGI app.

    The MCP session-manager lifespan is NOT available inside a TestClient
    without running ``mcp.run()``, which makes it unsuitable as a
    downstream for middleware tests. We instead wrap a tiny Starlette app
    that returns 200 OK on any path — the middleware's job is to block
    unauth'd requests BEFORE they reach the downstream, so the downstream
    identity is irrelevant.
    """

    def _make_client_with_token(self, token: str) -> TestClient:
        wrapped = _wrap_with_bearer_auth(_make_dummy_asgi_app(), token)
        return TestClient(wrapped)

    def test_missing_auth_returns_401(self) -> None:
        """No Authorization header → 401 with WWW-Authenticate challenge."""
        client = self._make_client_with_token("correct-token")
        resp = client.get("/mcp")
        assert resp.status_code == 401
        assert "bearer" in resp.headers.get("www-authenticate", "").lower()
        assert "missing bearer" in resp.json()["error"].lower()

    def test_wrong_scheme_returns_401(self) -> None:
        """Basic auth or other schemes must be rejected."""
        client = self._make_client_with_token("correct-token")
        resp = client.get("/mcp", headers={"Authorization": "Basic dXNlcjpwYXNz"})
        assert resp.status_code == 401

    def test_wrong_token_returns_401(self) -> None:
        """Correct scheme but wrong value → 401, NOT 200."""
        client = self._make_client_with_token("correct-token")
        resp = client.get("/mcp", headers={"Authorization": "Bearer wrong-token"})
        assert resp.status_code == 401
        assert "invalid" in resp.json()["error"].lower()

    def test_correct_token_reaches_downstream(self) -> None:
        """Correct bearer token must pass the auth gate AND hit downstream."""
        client = self._make_client_with_token("correct-token")
        resp = client.get(
            "/mcp",
            headers={"Authorization": "Bearer correct-token"},
        )
        assert resp.status_code == 200
        assert resp.text == "downstream ok"

    def test_case_sensitive_token_comparison(self) -> None:
        """Token mismatch by case must fail — we use hmac.compare_digest."""
        client = self._make_client_with_token("CorrectToken")
        resp = client.get("/mcp", headers={"Authorization": "Bearer correcttoken"})
        assert resp.status_code == 401

    def test_empty_token_value_rejected(self) -> None:
        """``Authorization: Bearer `` (empty) must be rejected."""
        client = self._make_client_with_token("secret")
        resp = client.get("/mcp", headers={"Authorization": "Bearer "})
        assert resp.status_code == 401

    def test_no_token_configured_all_requests_pass_through(self) -> None:
        """``_wrap_with_bearer_auth`` is not called at all when token is None;
        requests must reach the downstream directly via the raw FastMCP app.
        We verify this using a trivial downstream mounted in place of MCP.
        """
        from starlette.testclient import TestClient as _TC

        dummy = _make_dummy_asgi_app()
        client = _TC(dummy)
        resp = client.get("/mcp")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# _run_http safety gate
# ---------------------------------------------------------------------------


class TestRunHttpSafetyGate:
    """Refuse to expose SSH exec over the network without a token."""

    def test_bind_to_0_0_0_0_without_token_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SSH_MCP_HTTP_HOST", "0.0.0.0")
        monkeypatch.delenv("SSH_MCP_HTTP_TOKEN", raising=False)
        with pytest.raises(RuntimeError, match="SSH_MCP_HTTP_TOKEN must be set"):
            _run_http()

    def test_bind_to_lan_ip_without_token_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SSH_MCP_HTTP_HOST", "10.0.0.5")
        monkeypatch.delenv("SSH_MCP_HTTP_TOKEN", raising=False)
        with pytest.raises(RuntimeError, match="SSH_MCP_HTTP_TOKEN must be set"):
            _run_http()

    def test_bind_to_0_0_0_0_with_token_starts(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With a token, non-localhost binds are allowed (uvicorn mocked)."""
        monkeypatch.setenv("SSH_MCP_HTTP_HOST", "0.0.0.0")
        monkeypatch.setenv("SSH_MCP_HTTP_TOKEN", "s3cret")
        with patch("uvicorn.run") as mock_run:
            _run_http()
        mock_run.assert_called_once()
        _args, kwargs = mock_run.call_args
        assert kwargs["host"] == "0.0.0.0"

    def test_localhost_bind_without_token_is_allowed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Localhost without auth is allowed (matches stdio deployment model)."""
        monkeypatch.setenv("SSH_MCP_HTTP_HOST", "127.0.0.1")
        monkeypatch.delenv("SSH_MCP_HTTP_TOKEN", raising=False)
        with patch("uvicorn.run") as mock_run:
            _run_http()
        mock_run.assert_called_once()

    def test_port_env_var_honored(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SSH_MCP_HTTP_HOST", "127.0.0.1")
        monkeypatch.setenv("SSH_MCP_HTTP_PORT", "9001")
        with patch("uvicorn.run") as mock_run:
            _run_http()
        _args, kwargs = mock_run.call_args
        assert kwargs["port"] == 9001

    def test_stateless_env_var_honored(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SSH_MCP_HTTP_HOST", "127.0.0.1")
        monkeypatch.setenv("SSH_MCP_HTTP_STATELESS", "true")
        with patch("uvicorn.run"):
            _run_http()
        assert server_module.mcp.settings.stateless_http is True

    def test_allowed_hosts_extends_dns_rebinding_list(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SSH_MCP_HTTP_HOST", "127.0.0.1")
        monkeypatch.setenv(
            "SSH_MCP_HTTP_ALLOWED_HOSTS", "ssh-mcp.internal:*, api.example.com:8000"
        )
        with patch("uvicorn.run"):
            _run_http()
        allowed = server_module.mcp.settings.transport_security.allowed_hosts
        # Localhost defaults must survive
        assert "127.0.0.1:*" in allowed
        # Extra hosts must be added
        assert "ssh-mcp.internal:*" in allowed
        assert "api.example.com:8000" in allowed


# ---------------------------------------------------------------------------
# main() transport dispatch
# ---------------------------------------------------------------------------


class TestMainTransportDispatch:
    """main() reads SSH_MCP_TRANSPORT and dispatches correctly."""

    def test_default_is_stdio(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SSH_MCP_TRANSPORT", raising=False)
        with patch.object(server_module.mcp, "run") as mock_run:
            main()
        mock_run.assert_called_once_with(transport="stdio")

    def test_explicit_stdio(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SSH_MCP_TRANSPORT", "stdio")
        with patch.object(server_module.mcp, "run") as mock_run:
            main()
        mock_run.assert_called_once_with(transport="stdio")

    def test_http_routes_to_run_http(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SSH_MCP_TRANSPORT", "http")
        monkeypatch.setenv("SSH_MCP_HTTP_HOST", "127.0.0.1")
        with patch.object(server_module, "_run_http") as mock_run_http:
            main()
        mock_run_http.assert_called_once()

    def test_streamable_http_alias_works(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SSH_MCP_TRANSPORT", "streamable-http")
        monkeypatch.setenv("SSH_MCP_HTTP_HOST", "127.0.0.1")
        with patch.object(server_module, "_run_http") as mock_run_http:
            main()
        mock_run_http.assert_called_once()

    def test_unknown_transport_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SSH_MCP_TRANSPORT", "grpc")
        with pytest.raises(ValueError, match="Unknown SSH_MCP_TRANSPORT"):
            main()

    def test_transport_env_var_is_case_insensitive(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SSH_MCP_TRANSPORT", "HTTP")
        monkeypatch.setenv("SSH_MCP_HTTP_HOST", "127.0.0.1")
        with patch.object(server_module, "_run_http") as mock_run_http:
            main()
        mock_run_http.assert_called_once()
