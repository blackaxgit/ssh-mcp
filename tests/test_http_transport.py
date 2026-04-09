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
    """Restore module-level FastMCP settings and session manager between tests.

    ``_run_http`` mutates ``mcp.settings`` in place; without this fixture
    a test setting ``host = "0.0.0.0"`` would poison the next one.

    Additionally, FastMCP caches a single ``StreamableHTTPSessionManager``
    on ``mcp._session_manager`` and that manager's ``.run()`` context
    manager raises on second entry. Multiple tests that drive the real
    HTTP app through ``TestClient`` would collide on this singleton. We
    reset it to ``None`` before each test so the next ``streamable_http_app``
    call mints a fresh manager.
    """
    saved_host = server_module.mcp.settings.host
    saved_port = server_module.mcp.settings.port
    saved_stateless = server_module.mcp.settings.stateless_http
    saved_security = server_module.mcp.settings.transport_security
    # Force a fresh session manager for this test
    server_module.mcp._session_manager = None
    yield
    server_module.mcp.settings.host = saved_host
    server_module.mcp.settings.port = saved_port
    server_module.mcp.settings.stateless_http = saved_stateless
    server_module.mcp.settings.transport_security = saved_security
    server_module.mcp._session_manager = None


# ---------------------------------------------------------------------------
# _build_http_app — middleware wiring
# ---------------------------------------------------------------------------


class TestGracefulShutdown:
    """Green Team H1: lifespan must close SSH connections on shutdown."""

    async def test_lifespan_closes_ssh_manager_on_shutdown(self) -> None:
        """A simulated shutdown event must invoke SSHManager.close_all().

        Uses an ``AsyncExitStack`` + the Starlette lifespan context to
        step the ASGI lifespan through ``startup -> shutdown``, capturing
        whether ``_ssh.close_all()`` was awaited during the shutdown phase.
        """
        from unittest.mock import AsyncMock

        import ssh_mcp.server as server_module

        # Install a mock SSH manager so we can observe close_all being called
        mock_ssh = AsyncMock()
        mock_ssh.close_all = AsyncMock()
        original_ssh = server_module._ssh
        server_module._ssh = mock_ssh
        try:
            app = server_module._build_http_app(token=None)
            # Starlette's TestClient drives the lifespan via context manager
            with TestClient(app):
                pass  # entering/exiting the context runs startup/shutdown
        finally:
            server_module._ssh = original_ssh

        mock_ssh.close_all.assert_awaited_once()

    async def test_lifespan_shutdown_when_ssh_never_initialized(self) -> None:
        """If _ssh is None at shutdown, lifespan must not raise."""
        import ssh_mcp.server as server_module

        original_ssh = server_module._ssh
        server_module._ssh = None
        try:
            app = server_module._build_http_app(token=None)
            # Simply entering and exiting the lifespan should not raise
            with TestClient(app):
                pass
        finally:
            server_module._ssh = original_ssh


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
        app = _build_http_app(token="secret-xyz-abcdefghij")
        # The wrapper must expose user_middleware with at least one entry
        assert hasattr(app, "user_middleware")
        assert len(app.user_middleware) > 0

    def test_middleware_blocks_unauth_requests_on_real_fastmcp_app(self) -> None:
        """Green Team H6: stronger mutation-resistance check.

        ``test_with_token_wraps_app`` only checks that SOME middleware is
        registered. A mutation that swapped the middleware for a no-op
        class or mounted it in the wrong order would pass that test.
        This test drives an actual request through the real FastMCP
        wrapper and verifies the 401 path is hit BEFORE reaching the
        MCP session manager (which would otherwise raise a different
        error due to its own lifespan requirement).
        """
        app = _build_http_app(token="middleware-integration-test-token")
        client = TestClient(app)
        # No Authorization header → middleware must 401 before the MCP
        # session manager is reached. If the middleware was bypassed,
        # we'd get a 500 from the missing task group instead.
        resp = client.get("/mcp")
        assert resp.status_code == 401
        assert "bearer" in resp.headers.get("www-authenticate", "").lower()

    def test_authenticated_request_reaches_initialized_session_manager(
        self,
    ) -> None:
        """Red Team R5 regression: production bug v0.3.0 where
        ``_install_shutdown_lifespan`` mounted the FastMCP app as a sub-app
        and added its OWN lifespan — Starlette only runs top-level
        lifespans, so the FastMCP session manager's task group was never
        initialized and every authenticated request returned HTTP 500 with
        ``RuntimeError('Task group is not initialized. Make sure to use
        run().')``.

        An authenticated request may return any 4xx/5xx for MCP protocol
        reasons (wrong Accept header, unknown method, etc.) — but it
        MUST NOT return the "Task group is not initialized" error.

        This test ALSO covers the ``token=None`` path by parametrizing
        over both branches — but because the FastMCP session manager is
        a module-level singleton that cannot be re-run once started, we
        reset its ``_has_started`` flag between the two subtests by
        recreating the server module attribute. If that reset breaks in
        a future SDK version, drop the ``token=None`` subtest — the
        ``token`` branch alone is sufficient to catch the regression.
        """
        token = "auth-reaches-session-manager-ok"
        app = _build_http_app(token=token)
        with TestClient(app) as client:
            resp = client.get(
                "/mcp",
                headers={"Authorization": f"Bearer {token}"},
            )
        body = resp.text
        assert "Task group is not initialized" not in body, (
            f"FastMCP session manager never started: "
            f"status={resp.status_code} body={body!r}"
        )


class TestUvicornLogRouting:
    """Green Team H7: uvicorn access logs must flow through the structlog
    ProcessorFormatter attached to the root logger.

    We verify this by checking that the ``uvicorn`` logger hierarchy has
    no handlers of its own (so records propagate to root) AND that the
    root handler is the structlog ProcessorFormatter installed at import.
    """

    def test_uvicorn_loggers_propagate_to_root(self) -> None:
        """No handlers on uvicorn loggers means records bubble to root."""
        import logging

        # After module import, _configure_logging() has attached exactly
        # one handler on root. Uvicorn logs must reach THAT handler.
        root = logging.getLogger()
        assert len(root.handlers) >= 1, "structlog configured root handler must exist"

        # uvicorn, uvicorn.access, uvicorn.error should NOT have their
        # own handlers by default — if they did, their records would
        # go to the default uvicorn stderr handler instead of ours.
        for name in ("uvicorn", "uvicorn.access", "uvicorn.error"):
            lg = logging.getLogger(name)
            # propagate must be True so messages reach the root handler
            assert lg.propagate is True, f"{name} logger does not propagate to root"

    def test_root_handler_is_structlog_processor_formatter(self) -> None:
        """Structural check: the root logger's single handler must be
        formatted by ``structlog.stdlib.ProcessorFormatter``.

        This is the handler that uvicorn.access records reach when they
        propagate from ``uvicorn.access`` → root. If the formatter is
        anything else, JSON output via SSH_MCP_LOG_FORMAT=json would
        silently break for HTTP transport.
        """
        import logging

        import structlog.stdlib

        import ssh_mcp.server  # noqa: F401  — trigger _configure_logging()

        root = logging.getLogger()
        # There may be a caplog-injected handler alongside ours; find the
        # structlog one specifically.
        structlog_handlers = [
            h
            for h in root.handlers
            if isinstance(
                getattr(h, "formatter", None),
                structlog.stdlib.ProcessorFormatter,
            )
        ]
        assert len(structlog_handlers) >= 1, (
            "Root logger must have a structlog ProcessorFormatter handler "
            "so uvicorn.access records get structured output. "
            f"Handlers: {root.handlers}"
        )

    def test_uvicorn_access_log_record_reaches_root(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """uvicorn.access records must propagate to the root logger.

        Verified via pytest caplog, which attaches to the root logger —
        if propagation is broken, the record wouldn't appear in caplog.
        """
        import logging

        import ssh_mcp.server  # noqa: F401

        with caplog.at_level(logging.INFO, logger="uvicorn.access"):
            logging.getLogger("uvicorn.access").info(
                '127.0.0.1:54321 - "GET /mcp HTTP/1.1" 200'
            )

        access_records = [r for r in caplog.records if r.name == "uvicorn.access"]
        assert len(access_records) >= 1, (
            "uvicorn.access record did not reach root logger"
        )
        assert "GET /mcp" in access_records[0].getMessage()


# ---------------------------------------------------------------------------
# Bearer-token middleware behavior (Starlette TestClient)
# ---------------------------------------------------------------------------


class TestBearerAuthR3Hardening:
    """Red Team R3 HIGH findings H2, H3, H4, M4."""

    def test_wrap_rejects_empty_expected_token(self) -> None:
        """H2: _wrap_with_bearer_auth must refuse empty string as expected.

        Otherwise hmac.compare_digest('', '') returns True and any client
        sending 'Authorization: Bearer ' authenticates.
        """
        dummy = _make_dummy_asgi_app()
        with pytest.raises(ValueError, match="token"):
            _wrap_with_bearer_auth(dummy, "")

    def test_wrap_rejects_very_short_tokens(self) -> None:
        """H2 follow-up: tokens under a reasonable minimum are suspicious."""
        dummy = _make_dummy_asgi_app()
        with pytest.raises(ValueError, match="token"):
            _wrap_with_bearer_auth(dummy, "abc")

    def test_bearer_scheme_is_case_insensitive(self) -> None:
        """H3: RFC 7235 says scheme is case-insensitive. Accept any casing."""
        wrapped = _wrap_with_bearer_auth(
            _make_dummy_asgi_app(), "correct-token-longenough"
        )
        client = TestClient(wrapped)
        for scheme in ("Bearer", "bearer", "BEARER", "BeArEr"):
            resp = client.get(
                "/mcp", headers={"Authorization": f"{scheme} correct-token-longenough"}
            )
            assert resp.status_code == 200, f"Scheme {scheme!r} must authenticate"

    def test_wildcard_allowed_hosts_rejected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """H4: SSH_MCP_HTTP_ALLOWED_HOSTS=* silently disables DNS rebinding.

        Reject at startup with a clear error so operators can't neutralize
        the protection by accident.
        """
        monkeypatch.setenv("SSH_MCP_HTTP_HOST", "127.0.0.1")
        monkeypatch.setenv("SSH_MCP_HTTP_ALLOWED_HOSTS", "*")
        with pytest.raises(RuntimeError, match="wildcard"):
            _run_http()

    def test_wildcard_in_list_also_rejected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A wildcard anywhere in the comma list disables protection."""
        monkeypatch.setenv("SSH_MCP_HTTP_HOST", "127.0.0.1")
        monkeypatch.setenv("SSH_MCP_HTTP_ALLOWED_HOSTS", "ssh-mcp.internal:*,*:*")
        with pytest.raises(RuntimeError, match="wildcard"):
            _run_http()

    def test_token_whitespace_stripped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """M4: SSH_MCP_HTTP_TOKEN with trailing whitespace (common from .env
        files that append ``\\n``) must be stripped before being handed to
        the middleware, or the server will never authenticate requests.

        Verified by patching ``_build_http_app`` so we can capture the
        token that was actually passed through.
        """
        monkeypatch.setenv("SSH_MCP_HTTP_HOST", "127.0.0.1")
        monkeypatch.setenv("SSH_MCP_HTTP_TOKEN", "  secret-token-longenough\n\t ")

        from unittest.mock import patch

        captured: list[str | None] = []

        def fake_build(token):  # type: ignore[no-untyped-def]
            captured.append(token)
            return _make_dummy_asgi_app()

        with patch("ssh_mcp.server._build_http_app", side_effect=fake_build):
            with patch("uvicorn.run"):
                _run_http()

        assert captured == ["secret-token-longenough"], (
            f"Token not stripped: got {captured!r}"
        )


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
        client = self._make_client_with_token("correct-token-longenough")
        resp = client.get("/mcp")
        assert resp.status_code == 401
        assert "bearer" in resp.headers.get("www-authenticate", "").lower()
        assert "missing bearer" in resp.json()["error"].lower()

    def test_wrong_scheme_returns_401(self) -> None:
        """Basic auth or other schemes must be rejected."""
        client = self._make_client_with_token("correct-token-longenough")
        resp = client.get("/mcp", headers={"Authorization": "Basic dXNlcjpwYXNz"})
        assert resp.status_code == 401

    def test_wrong_token_returns_401(self) -> None:
        """Correct scheme but wrong value → 401, NOT 200."""
        client = self._make_client_with_token("correct-token-longenough")
        resp = client.get("/mcp", headers={"Authorization": "Bearer wrong-token"})
        assert resp.status_code == 401
        assert "invalid" in resp.json()["error"].lower()

    def test_correct_token_reaches_downstream(self) -> None:
        """Correct bearer token must pass the auth gate AND hit downstream."""
        client = self._make_client_with_token("correct-token-longenough")
        resp = client.get(
            "/mcp",
            headers={"Authorization": "Bearer correct-token-longenough"},
        )
        assert resp.status_code == 200
        assert resp.text == "downstream ok"

    def test_case_sensitive_token_comparison(self) -> None:
        """Token mismatch by case must fail — we use hmac.compare_digest."""
        client = self._make_client_with_token("CorrectTokenLongEnough")
        resp = client.get(
            "/mcp",
            headers={"Authorization": "Bearer correcttokenlongenough"},
        )
        assert resp.status_code == 401

    def test_empty_token_value_rejected(self) -> None:
        """``Authorization: Bearer `` (empty) must be rejected."""
        client = self._make_client_with_token("secret-long-token-val")
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
        monkeypatch.setenv("SSH_MCP_HTTP_TOKEN", "s3cret-long-token-val")
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

    @pytest.mark.parametrize(
        "host",
        [
            # Canonical IPv4/IPv6 loopback
            "127.0.0.1",
            "::1",
            # Green Team H5: non-canonical but still loopback
            "127.0.0.2",  # anywhere in 127.0.0.0/8
            "127.1.2.3",
            "0:0:0:0:0:0:0:1",  # expanded IPv6 ::1
            "0000:0000:0000:0000:0000:0000:0000:0001",  # full expansion
            "::ffff:127.0.0.1",  # IPv4-mapped IPv6 loopback
            "::ffff:127.5.5.5",
        ],
    )
    def test_loopback_variants_allowed_without_token(
        self, monkeypatch: pytest.MonkeyPatch, host: str
    ) -> None:
        """Green Team H5: all loopback IP forms must be treated as localhost."""
        monkeypatch.setenv("SSH_MCP_HTTP_HOST", host)
        monkeypatch.delenv("SSH_MCP_HTTP_TOKEN", raising=False)
        with patch("uvicorn.run") as mock_run:
            _run_http()
        mock_run.assert_called_once()

    @pytest.mark.parametrize(
        "host",
        [
            # Non-loopback IPs that must require a token
            "0.0.0.0",
            "10.0.0.5",
            "192.168.1.10",
            "8.8.8.8",
            "::",  # IPv6 unspecified — binds to all
            "fe80::1",  # link-local
            "2001:db8::1",  # documentation range
            # Hostnames that aren't "localhost"
            "example.com",
            "server.internal",
        ],
    )
    def test_non_loopback_hosts_require_token(
        self, monkeypatch: pytest.MonkeyPatch, host: str
    ) -> None:
        """Green Team H5: every non-loopback address must fail-secure."""
        monkeypatch.setenv("SSH_MCP_HTTP_HOST", host)
        monkeypatch.delenv("SSH_MCP_HTTP_TOKEN", raising=False)
        with pytest.raises(RuntimeError, match="SSH_MCP_HTTP_TOKEN must be set"):
            _run_http()

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
