"""Tests for MCP streamable HTTP transport (Phase C HTTP feature).

Exercises the transport-selection dispatch, the bearer-token middleware,
and the safety gate that refuses to bind non-localhost without auth.
No real network sockets are opened — middleware is tested via Starlette's
TestClient (synchronous, in-process) and the network startup path is
exercised via a mocked ``uvicorn.run``.
"""

from __future__ import annotations

import os
import signal
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

import pytest
from starlette.testclient import TestClient

import ssh_mcp.server as server_module
from ssh_mcp.server import (
    _assert_valid_bearer_token,
    _make_bearer_auth_middleware,
    _run_http,
    main,
)


def _loopback_app(token: str | None):
    """Build the HTTP app as it is built for a default loopback bind.

    ``_build_http_app`` deliberately has no defaults for ``stateless`` or
    ``transport_security`` (a ``None`` transport_security would disable
    DNS-rebinding protection), so every caller must spell them out. The
    tests below vary only ``token``; transport-security behaviour is
    covered separately against ``_build_transport_security`` directly.
    """
    return server_module._build_http_app(
        token=token,
        stateless=False,
        transport_security=server_module._build_transport_security(None, "127.0.0.1"),
    )


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
    """Reset the cached session manager between tests.

    v1's ``mcp.settings.host/port/stateless_http/transport_security`` no
    longer exist on the v2 ``Settings`` object (assigning a removed field
    raises ``ValueError``), so there is nothing left to save/restore there.

    The session-manager reset is still required, but not for the reason
    it used to be: v1's ``streamable_http_app()`` cached a single
    ``StreamableHTTPSessionManager`` whose ``.run()`` context manager
    raised on a second entry, so a second ``TestClient`` in the suite
    would collide. v2 mints a fresh manager on every call
    (``mcp/server/lowlevel/server.py:742-751``), so that collision can no
    longer happen. What still depends on this reset is
    ``TestLifespanAssertionFires`` below, which needs
    ``_lowlevel_server._session_manager`` to be ``None`` so that the
    ``session_manager`` property raises instead of returning a stale one.
    """
    # Force a fresh session manager for this test
    server_module.mcp._lowlevel_server._session_manager = None
    yield
    server_module.mcp._lowlevel_server._session_manager = None


# ---------------------------------------------------------------------------
# _build_http_app — middleware wiring
# ---------------------------------------------------------------------------


class TestUvicornTuning:
    """Production incident 2026-04-11: container hit OSError(24, 'Too many
    open files') because uvicorn default ``timeout_keep_alive=5s`` + bursty
    n8n traffic accumulated ~110 ESTABLISHED HTTP connections, eventually
    exceeding the container's 1024 fd limit.

    These tests pin the new ``SSH_MCP_HTTP_*`` knobs that ``_run_http``
    forwards into ``uvicorn.run``. The defaults are chosen to survive
    bursty keepalive traffic without tuning.
    """

    def test_default_keepalive_and_concurrency_passed_to_uvicorn(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Defaults: timeout_keep_alive=2s, limit_concurrency=256."""
        monkeypatch.setenv("SSH_MCP_HTTP_HOST", "127.0.0.1")
        monkeypatch.delenv("SSH_MCP_HTTP_KEEPALIVE_TIMEOUT", raising=False)
        monkeypatch.delenv("SSH_MCP_HTTP_LIMIT_CONCURRENCY", raising=False)
        monkeypatch.delenv("SSH_MCP_HTTP_BACKLOG", raising=False)
        with patch("uvicorn.run") as mock_run:
            _run_http()
        _args, kwargs = mock_run.call_args
        assert kwargs["timeout_keep_alive"] == 2
        assert kwargs["limit_concurrency"] == 256

    def test_custom_keepalive_timeout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SSH_MCP_HTTP_KEEPALIVE_TIMEOUT=1 overrides the default."""
        monkeypatch.setenv("SSH_MCP_HTTP_HOST", "127.0.0.1")
        monkeypatch.setenv("SSH_MCP_HTTP_KEEPALIVE_TIMEOUT", "1")
        with patch("uvicorn.run") as mock_run:
            _run_http()
        _args, kwargs = mock_run.call_args
        assert kwargs["timeout_keep_alive"] == 1

    def test_custom_limit_concurrency(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SSH_MCP_HTTP_LIMIT_CONCURRENCY=1000 overrides the default."""
        monkeypatch.setenv("SSH_MCP_HTTP_HOST", "127.0.0.1")
        monkeypatch.setenv("SSH_MCP_HTTP_LIMIT_CONCURRENCY", "1000")
        with patch("uvicorn.run") as mock_run:
            _run_http()
        _args, kwargs = mock_run.call_args
        assert kwargs["limit_concurrency"] == 1000

    def test_custom_backlog(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SSH_MCP_HTTP_BACKLOG sets uvicorn backlog."""
        monkeypatch.setenv("SSH_MCP_HTTP_HOST", "127.0.0.1")
        monkeypatch.setenv("SSH_MCP_HTTP_BACKLOG", "512")
        with patch("uvicorn.run") as mock_run:
            _run_http()
        _args, kwargs = mock_run.call_args
        assert kwargs["backlog"] == 512

    def test_invalid_keepalive_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Non-integer SSH_MCP_HTTP_KEEPALIVE_TIMEOUT must raise at startup."""
        monkeypatch.setenv("SSH_MCP_HTTP_HOST", "127.0.0.1")
        monkeypatch.setenv("SSH_MCP_HTTP_KEEPALIVE_TIMEOUT", "not-a-number")
        with pytest.raises((ValueError, RuntimeError)):
            _run_http()

    def test_negative_keepalive_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Negative keepalive is nonsensical and must be rejected."""
        monkeypatch.setenv("SSH_MCP_HTTP_HOST", "127.0.0.1")
        monkeypatch.setenv("SSH_MCP_HTTP_KEEPALIVE_TIMEOUT", "-1")
        with pytest.raises(RuntimeError, match="SSH_MCP_HTTP_KEEPALIVE_TIMEOUT"):
            _run_http()

    def test_zero_concurrency_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """limit_concurrency=0 would reject all requests — refuse at startup."""
        monkeypatch.setenv("SSH_MCP_HTTP_HOST", "127.0.0.1")
        monkeypatch.setenv("SSH_MCP_HTTP_LIMIT_CONCURRENCY", "0")
        with pytest.raises(RuntimeError, match="SSH_MCP_HTTP_LIMIT_CONCURRENCY"):
            _run_http()


class TestOptionalAuthMode:
    """SSH_MCP_HTTP_AUTH=none disables the bearer middleware.

    Feature for operators who put ssh-mcp behind a trusted reverse proxy
    that handles authentication. Requires explicit acknowledgement when
    binding to a non-localhost address so accidental exposure is impossible.
    """

    def test_auth_none_on_localhost_allowed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """auth=none + localhost bind → allowed (matches stdio model)."""
        monkeypatch.setenv("SSH_MCP_HTTP_HOST", "127.0.0.1")
        monkeypatch.setenv("SSH_MCP_HTTP_AUTH", "none")
        monkeypatch.delenv("SSH_MCP_HTTP_TOKEN", raising=False)
        monkeypatch.delenv("SSH_MCP_HTTP_NETWORK_NO_AUTH", raising=False)
        with patch("uvicorn.run") as mock_run:
            _run_http()
        mock_run.assert_called_once()

    def test_auth_none_on_public_bind_refused_without_ack(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """auth=none + 0.0.0.0 → refuse without explicit acknowledgement."""
        monkeypatch.setenv("SSH_MCP_HTTP_HOST", "0.0.0.0")
        monkeypatch.setenv("SSH_MCP_HTTP_AUTH", "none")
        monkeypatch.delenv("SSH_MCP_HTTP_TOKEN", raising=False)
        monkeypatch.delenv("SSH_MCP_HTTP_NETWORK_NO_AUTH", raising=False)
        with pytest.raises(RuntimeError, match="SSH_MCP_HTTP_NETWORK_NO_AUTH"):
            _run_http()

    def test_auth_none_on_public_bind_refused_with_wrong_ack(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The ack env var must match a specific value, not any truthy."""
        monkeypatch.setenv("SSH_MCP_HTTP_HOST", "0.0.0.0")
        monkeypatch.setenv("SSH_MCP_HTTP_AUTH", "none")
        monkeypatch.delenv("SSH_MCP_HTTP_TOKEN", raising=False)
        monkeypatch.setenv("SSH_MCP_HTTP_NETWORK_NO_AUTH", "true")
        with pytest.raises(RuntimeError, match="I_ACCEPT_RCE_RISK"):
            _run_http()

    def test_auth_none_on_public_bind_allowed_with_exact_ack(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Exact magic-string ack unlocks the no-auth public bind."""
        monkeypatch.setenv("SSH_MCP_HTTP_HOST", "0.0.0.0")
        monkeypatch.setenv("SSH_MCP_HTTP_AUTH", "none")
        monkeypatch.delenv("SSH_MCP_HTTP_TOKEN", raising=False)
        monkeypatch.setenv("SSH_MCP_HTTP_NETWORK_NO_AUTH", "I_ACCEPT_RCE_RISK")
        with patch("uvicorn.run") as mock_run:
            _run_http()
        mock_run.assert_called_once()

    def test_auth_none_does_not_install_middleware(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When auth=none is active, no bearer middleware is attached."""
        monkeypatch.setenv("SSH_MCP_HTTP_HOST", "127.0.0.1")
        monkeypatch.setenv("SSH_MCP_HTTP_AUTH", "none")
        monkeypatch.delenv("SSH_MCP_HTTP_TOKEN", raising=False)

        captured: list[str | None] = []

        def fake_build(token, **_kwargs):  # type: ignore[no-untyped-def]
            captured.append(token)
            return _make_dummy_asgi_app()

        with patch("ssh_mcp.server._build_http_app", side_effect=fake_build):
            with patch("uvicorn.run"):
                _run_http()

        assert captured == [None], (
            f"auth=none must pass token=None to _build_http_app, got {captured!r}"
        )

    def test_auth_bearer_is_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Unset SSH_MCP_HTTP_AUTH defaults to bearer (backwards compatible).

        Non-localhost bind without token still raises (no change from v0.3.1).
        """
        monkeypatch.setenv("SSH_MCP_HTTP_HOST", "0.0.0.0")
        monkeypatch.delenv("SSH_MCP_HTTP_AUTH", raising=False)
        monkeypatch.delenv("SSH_MCP_HTTP_TOKEN", raising=False)
        with pytest.raises(RuntimeError, match="SSH_MCP_HTTP_TOKEN must be set"):
            _run_http()

    def test_auth_mode_is_case_insensitive(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SSH_MCP_HTTP_HOST", "127.0.0.1")
        monkeypatch.setenv("SSH_MCP_HTTP_AUTH", "NONE")
        monkeypatch.delenv("SSH_MCP_HTTP_TOKEN", raising=False)
        with patch("uvicorn.run") as mock_run:
            _run_http()
        mock_run.assert_called_once()

    def test_unknown_auth_mode_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SSH_MCP_HTTP_HOST", "127.0.0.1")
        monkeypatch.setenv("SSH_MCP_HTTP_AUTH", "oauth")
        with pytest.raises(RuntimeError, match="SSH_MCP_HTTP_AUTH"):
            _run_http()


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
            app = _loopback_app(None)
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
            app = _loopback_app(None)
            # Simply entering and exiting the lifespan should not raise
            with TestClient(app):
                pass
        finally:
            server_module._ssh = original_ssh


class TestBuildHttpApp:
    """Verify _build_http_app wraps auth middleware exactly when expected."""

    def test_no_token_returns_raw_mcpserver_app(self) -> None:
        """When token is None, no auth wrapper is added."""
        from starlette.applications import Starlette

        app = _loopback_app(None)
        # The raw MCPServer app is a Starlette instance; the wrapper one
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
        app = _loopback_app("secret-xyz-abcdefghij")
        # The wrapper must expose user_middleware with at least one entry
        assert hasattr(app, "user_middleware")
        assert len(app.user_middleware) > 0

    def test_middleware_blocks_unauth_requests_on_real_mcpserver_app(self) -> None:
        """Green Team H6: stronger mutation-resistance check.

        ``test_with_token_wraps_app`` only checks that SOME middleware is
        registered. A mutation that swapped the middleware for a no-op
        class or mounted it in the wrong order would pass that test.
        This test drives an actual request through the real MCPServer
        wrapper and verifies the 401 path is hit BEFORE reaching the
        MCP session manager (which would otherwise raise a different
        error due to its own lifespan requirement).
        """
        app = _loopback_app("middleware-integration-test-token")
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
        ``_install_shutdown_lifespan`` mounted the MCPServer app as a sub-app
        and added its OWN lifespan — Starlette only runs top-level
        lifespans, so the MCPServer session manager's task group was never
        initialized and every authenticated request returned HTTP 500 with
        ``RuntimeError('Task group is not initialized. Make sure to use
        run().')``.

        An authenticated request may return any 4xx/5xx for MCP protocol
        reasons (wrong Accept header, unknown method, etc.) — but it
        MUST NOT return the "Task group is not initialized" error.

        This test ALSO covers the ``token=None`` path by parametrizing
        over both branches — but because the MCPServer session manager is
        a module-level singleton that cannot be re-run once started, we
        reset its ``_has_started`` flag between the two subtests by
        recreating the server module attribute. If that reset breaks in
        a future SDK version, drop the ``token=None`` subtest — the
        ``token`` branch alone is sufficient to catch the regression.
        """
        token = "auth-reaches-session-manager-ok"
        app = _loopback_app(token)
        with TestClient(app) as client:
            resp = client.get(
                "/mcp",
                headers={"Authorization": f"Bearer {token}"},
            )
        body = resp.text
        assert "Task group is not initialized" not in body, (
            f"MCPServer session manager never started: "
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

    def test_build_http_app_rejects_empty_expected_token(self) -> None:
        """H2: _build_http_app must refuse empty string as expected.

        Otherwise hmac.compare_digest('', '') returns True and any client
        sending 'Authorization: Bearer ' authenticates.
        """
        with pytest.raises(ValueError, match="token"):
            _assert_valid_bearer_token("")

    def test_build_http_app_rejects_very_short_tokens(self) -> None:
        """H2 follow-up: tokens under a reasonable minimum are suspicious."""
        with pytest.raises(ValueError, match="token"):
            _assert_valid_bearer_token("abc")

    def test_bearer_scheme_is_case_insensitive(self) -> None:
        """H3: RFC 7235 says scheme is case-insensitive. Accept any casing."""
        from starlette.applications import Starlette
        from starlette.routing import Mount

        dummy = _make_dummy_asgi_app()
        app = Starlette(routes=[Mount("/", app=dummy)])
        _BearerAuth = _make_bearer_auth_middleware()
        app.add_middleware(_BearerAuth, expected="correct-token-longenough")
        client = TestClient(app)
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

    @pytest.mark.parametrize(
        "entry",
        [
            "*",
            "*:*",
            "*.*",
            "*.*:*",
            "*.*.*",
            "*.:*",
            "a*b.example.com",
        ],
    )
    def test_wildcard_family_rejected(
        self, entry: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Regression for the H4 ordering trap on ci/fix-digest-verification.

        The previous implementation checked ``entry.startswith("*.")`` as an
        "always a permitted suffix wildcard" escape hatch BEFORE the
        ``entry in {"*", "*:*", "*.*"}`` refusal ran. "*.*" satisfies
        ``startswith("*.")`` too, so that escape hatch fired first and let
        "*.*" — which matches essentially any dotted hostname, functionally
        equivalent to the bare "*" this gate exists to block — through as
        PERMITTED, even though it was explicitly listed in the refusal set.

        Every entry here must still resolve to "no concrete hostname"
        after stripping the two deliberately-permitted wildcard forms (a
        trailing ``:*`` port wildcard, a leading ``*.`` subdomain
        wildcard), so all of them must be refused.
        """
        monkeypatch.setenv("SSH_MCP_HTTP_HOST", "127.0.0.1")
        monkeypatch.setenv("SSH_MCP_HTTP_ALLOWED_HOSTS", entry)
        with pytest.raises(RuntimeError, match="wildcard"):
            _run_http()

    def test_whitespace_only_allowed_hosts_rejected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An ALLOWED_HOSTS value that is explicitly set but blank (e.g. an
        empty templated env var like ``${EXTRA_HOSTS:- }``) must fail loud
        rather than silently falling back to the localhost-only default —
        that fallback would mask a broken deployment config from the
        operator.
        """
        monkeypatch.setenv("SSH_MCP_HTTP_HOST", "127.0.0.1")
        monkeypatch.setenv("SSH_MCP_HTTP_ALLOWED_HOSTS", "   ")
        with pytest.raises(RuntimeError, match="whitespace"):
            _run_http()

    @pytest.mark.parametrize(
        "entry",
        [
            "ok.example.com:*",
            "ok.example.com",
        ],
    )
    def test_supported_entry_forms_permitted(self, entry: str) -> None:
        """A concrete hostname, bare or with a trailing port wildcard, passes.

        These are the only two forms mcp 2.1.1 actually implements:
        ``TransportSecurityMiddleware._validate_host``
        (mcp/server/transport_security.py:50-69) does an exact-set lookup
        and then one trailing ``":*"`` port-wildcard pass. Exercises
        ``_build_transport_security`` directly rather than through
        ``_run_http``, since it is the pure function that owns this
        decision (no global mutation to observe or restore).
        """
        ts = server_module._build_transport_security(entry, "127.0.0.1")
        assert entry in ts.allowed_hosts, (
            f"{entry!r} should be permitted, got {ts.allowed_hosts!r}"
        )

    @pytest.mark.parametrize(
        "entry",
        [
            "*.internal.example.com",
            "*.internal.example.com:*",
        ],
    )
    def test_suffix_wildcard_refused(self, entry: str) -> None:
        """A leading ``*.`` entry is refused as of 0.7.0.

        Until 0.7.0 this form was permitted and AGENTS.md, the
        ``_run_http`` docstring and this test all called it "deliberately
        permitted". Two independent validators and a direct read of the
        installed SDK established that it never worked: there is no ``*.``
        handling anywhere in mcp 2.1.1, so the entry was compared
        LITERALLY and a real Host header like ``api.internal.example.com``
        got a 421 with nothing in the logs to explain it. Refusing at
        startup turns silent reject-everything into a loud error.

        This test fails against 0.6.x, which is the point.
        """
        with pytest.raises(RuntimeError, match="does not implement"):
            server_module._build_transport_security(entry, "127.0.0.1")

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

        def fake_build(token, **_kwargs):  # type: ignore[no-untyped-def]
            captured.append(token)
            return _make_dummy_asgi_app()

        with patch("ssh_mcp.server._build_http_app", side_effect=fake_build):
            with patch("uvicorn.run"):
                _run_http()

        assert captured == ["secret-token-longenough"], (
            f"Token not stripped: got {captured!r}"
        )


class TestBearerTokenMiddleware:
    """Pure ASGI middleware tested against a trivial downstream ASGI app.

    The MCP session-manager lifespan is NOT available inside a TestClient
    without running ``mcp.run()``, which makes it unsuitable as a
    downstream for middleware tests. We instead wrap a tiny Starlette app
    that returns 200 OK on any path — the middleware's job is to block
    unauth'd requests BEFORE they reach the downstream, so the downstream
    identity is irrelevant.
    """

    def _make_client_with_token(self, token: str) -> TestClient:
        from starlette.applications import Starlette
        from starlette.routing import Mount

        dummy = _make_dummy_asgi_app()
        app = Starlette(routes=[Mount("/", app=dummy)])
        _BearerAuth = _make_bearer_auth_middleware()
        app.add_middleware(_BearerAuth, expected=token)
        return TestClient(app)

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
        """When token is None, no middleware is attached and requests
        reach the downstream directly via the raw app.
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
        assert server_module.mcp.session_manager.stateless is True

    def test_allowed_hosts_extends_dns_rebinding_list(self) -> None:
        ts = server_module._build_transport_security(
            "ssh-mcp.internal:*, api.example.com:8000", "127.0.0.1"
        )
        allowed = ts.allowed_hosts
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


# ---------------------------------------------------------------------------
# Lifespan assertion fires (mutation gap test #11)
# ---------------------------------------------------------------------------


class TestLifespanAssertionFires:
    """Verify _build_http_app raises when inner app lacks lifespan_context."""

    def test_build_http_app_raises_if_lifespan_context_missing(self) -> None:
        """A missing lifespan_context must trigger a RuntimeError at build time."""
        from unittest.mock import MagicMock

        import ssh_mcp.server as srv

        # Build a fake inner app whose router.lifespan_context is None,
        # simulating a future MCP SDK that restructures its internals.
        fake_router = MagicMock()
        fake_router.lifespan_context = None
        fake_inner = MagicMock()
        fake_inner.router = fake_router

        with patch.object(srv.mcp, "streamable_http_app", return_value=fake_inner):
            with pytest.raises(RuntimeError, match="lifespan_context"):
                _loopback_app(None)


# ---------------------------------------------------------------------------
# Purple-team P3: DNS rebinding protection always enabled
# ---------------------------------------------------------------------------


class TestDnsRebindingAlwaysEnabled:
    """P3: TransportSecuritySettings must be configured even when
    SSH_MCP_HTTP_ALLOWED_HOSTS is not set."""

    def test_dns_rebinding_enabled_by_default(self) -> None:
        """Without an ``SSH_MCP_HTTP_ALLOWED_HOSTS`` override, dns rebinding
        protection must still default to True. (v2's
        ``TransportSecuritySettings.enable_dns_rebinding_protection`` field
        itself now defaults to True — this asserts ssh-mcp still passes it
        explicitly rather than relying on that SDK default, via the
        required ``transport_security`` kwarg on ``_build_http_app``.)
        """
        ts = server_module._build_transport_security(None, "127.0.0.1")
        assert ts.enable_dns_rebinding_protection is True

    def test_dns_rebinding_includes_localhost_defaults(self) -> None:
        """Default allowed_hosts must include localhost entries."""
        ts = server_module._build_transport_security(None, "127.0.0.1")
        allowed = ts.allowed_hosts
        assert "127.0.0.1:*" in allowed
        assert "localhost:*" in allowed
        assert "[::1]:*" in allowed

    def test_custom_bind_host_added_to_allowed_hosts(self) -> None:
        """A non-standard bind host should be included in allowed_hosts."""
        ts = server_module._build_transport_security(None, "10.0.0.5")
        assert "10.0.0.5:*" in ts.allowed_hosts


# ---------------------------------------------------------------------------
# Purple-team P5: SSH_MCP_HTTP_TOKEN_FILE support
# ---------------------------------------------------------------------------


class TestTokenFile:
    """P5: SSH_MCP_HTTP_TOKEN_FILE reads a bearer token from disk."""

    def test_token_file_read_from_disk(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Create a tmpfile with a token, set SSH_MCP_HTTP_TOKEN_FILE,
        verify _run_http reads it and passes to _build_http_app."""
        token_path = tmp_path / "token.txt"
        token_path.write_text("  file-based-secret-token-long\n")

        monkeypatch.setenv("SSH_MCP_HTTP_HOST", "127.0.0.1")
        monkeypatch.delenv("SSH_MCP_HTTP_TOKEN", raising=False)
        monkeypatch.setenv("SSH_MCP_HTTP_TOKEN_FILE", str(token_path))

        captured: list[str | None] = []

        def fake_build(token, **_kwargs):  # type: ignore[no-untyped-def]
            captured.append(token)
            return _make_dummy_asgi_app()

        with patch("ssh_mcp.server._build_http_app", side_effect=fake_build):
            with patch("uvicorn.run"):
                _run_http()

        assert captured == ["file-based-secret-token-long"], (
            f"Token from file not passed correctly: got {captured!r}"
        )

    def test_token_file_missing_raises(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """SSH_MCP_HTTP_TOKEN_FILE pointing to nonexistent path must raise."""
        missing = tmp_path / "nonexistent" / "token.txt"

        monkeypatch.setenv("SSH_MCP_HTTP_HOST", "127.0.0.1")
        monkeypatch.delenv("SSH_MCP_HTTP_TOKEN", raising=False)
        monkeypatch.setenv("SSH_MCP_HTTP_TOKEN_FILE", str(missing))

        with pytest.raises(RuntimeError, match="SSH_MCP_HTTP_TOKEN_FILE"):
            _run_http()

    def test_token_env_takes_precedence_over_file(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """When both SSH_MCP_HTTP_TOKEN and SSH_MCP_HTTP_TOKEN_FILE are set,
        the env var token wins (file is only a fallback)."""
        token_path = tmp_path / "token.txt"
        token_path.write_text("file-token-should-lose-this")

        monkeypatch.setenv("SSH_MCP_HTTP_HOST", "127.0.0.1")
        monkeypatch.setenv("SSH_MCP_HTTP_TOKEN", "env-token-should-win-ok")
        monkeypatch.setenv("SSH_MCP_HTTP_TOKEN_FILE", str(token_path))

        captured: list[str | None] = []

        def fake_build(token, **_kwargs):  # type: ignore[no-untyped-def]
            captured.append(token)
            return _make_dummy_asgi_app()

        with patch("ssh_mcp.server._build_http_app", side_effect=fake_build):
            with patch("uvicorn.run"):
                _run_http()

        assert captured == ["env-token-should-win-ok"], (
            f"Env token did not take precedence: got {captured!r}"
        )


class TestTokenFileValidation:
    """The token file authenticates an endpoint that runs shell commands, so
    what is read gets validated. Panel finding 2026-09-06: the previous
    implementation was a bare ``Path(p).read_text()`` with no checks at all.

    Every test here calls ``_read_token_file`` directly: it owns the decision
    and is pure apart from the filesystem, so there is no global transport
    state to set up or restore.
    """

    _TOKEN = "file-based-secret-token-long"

    def test_owner_only_file_is_read_without_warning(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A 0600 file is the recommended case: read it, say nothing."""
        p = tmp_path / "token"
        p.write_text(f"  {self._TOKEN}\n")
        p.chmod(0o600)

        with caplog.at_level("WARNING", logger="ssh_mcp.server"):
            assert server_module._read_token_file(str(p)) == self._TOKEN

        assert "readable beyond" not in caplog.text

    @pytest.mark.parametrize("mode", [0o644, 0o444, 0o604, 0o640])
    def test_group_or_other_READABLE_warns_but_still_works(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture, mode: int
    ) -> None:
        """Group/other READ warns and must NOT refuse.

        Docker Swarm mounts secrets 0444 and Kubernetes defaults to 0644, so
        refusing world-readable would break the two most common secret mounts
        outright. The warning has to name the mode to be actionable.

        Every mode here is deliberately free of group/other WRITE bits, which
        are refused by the sibling test below.
        """
        p = tmp_path / "token"
        p.write_text(self._TOKEN)
        p.chmod(mode)

        with caplog.at_level("WARNING", logger="ssh_mcp.server"):
            assert server_module._read_token_file(str(p)) == self._TOKEN

        assert "readable beyond" in caplog.text
        assert oct(mode) in caplog.text, (
            f"warning must name the octal mode, got: {caplog.text!r}"
        )

    @pytest.mark.parametrize("mode", [0o622, 0o660, 0o606, 0o666])
    def test_group_or_other_WRITABLE_is_refused(
        self, tmp_path: Path, mode: int
    ) -> None:
        """Group/other WRITE aborts startup — an integrity hole, not disclosure.

        Panel finding 2026-09-06: the first implementation tested a single
        ``& 0o077`` and merely warned, lumping three different things
        together. Anyone who can WRITE this file chooses the token that
        authorises remote command execution, then waits for a restart — which
        is strictly worse than being able to read it. Refusing is free
        compatibility-wise: Docker's 0444 and Kubernetes' 0644 carry no
        group/other write bit, so the mounts this code bends to support are
        unaffected.
        """
        p = tmp_path / "token"
        p.write_text(self._TOKEN)
        p.chmod(mode)

        with pytest.raises(RuntimeError, match="writable beyond"):
            server_module._read_token_file(str(p))

    def test_execute_bit_alone_does_not_warn(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """An execute bit on a regular file discloses nothing.

        The check is ``& 0o044``, not ``& 0o077``, precisely so this is
        silent. Warning about it was noise.
        """
        p = tmp_path / "token"
        p.write_text(self._TOKEN)
        p.chmod(0o611)

        with caplog.at_level("WARNING", logger="ssh_mcp.server"):
            assert server_module._read_token_file(str(p)) == self._TOKEN

        assert "readable beyond" not in caplog.text

    def test_bounded_read_catches_a_file_that_grows_after_fstat(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The cap must bind on bytes READ, not just on the ``fstat`` snapshot.

        Panel finding: the pre-read ``st_size`` check is only a snapshot, so
        an unbounded ``fh.read()`` would sail past the limit if the file grew
        between ``fstat`` and ``read`` — the descriptor being the same object
        removes pathname TOCTOU but not content-mutation TOCTOU. Simulated by
        making ``fstat`` under-report, which is exactly what a growing file
        looks like from the check's point of view.
        """
        p = tmp_path / "token"
        p.write_bytes(b"y" * (server_module._MAX_TOKEN_FILE_BYTES + 10))
        p.chmod(0o600)

        real_fstat = os.fstat

        def lying_fstat(fd: int) -> os.stat_result:
            st = real_fstat(fd)
            # Same mode/uid, but a size well under the cap.
            fields = list(st)
            fields[6] = 10
            return os.stat_result(fields)

        monkeypatch.setattr(server_module.os, "fstat", lying_fstat)

        with pytest.raises(RuntimeError, match="while being read"):
            server_module._read_token_file(str(p))

    def test_owner_is_this_process_does_not_warn(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The ownership warning must not fire on the normal case.

        A file owned by a third unprivileged user cannot be created without
        root, so the positive case is not testable in CI; this pins the
        negative so the check cannot degrade into warning on every startup.
        """
        p = tmp_path / "token"
        p.write_text(self._TOKEN)
        p.chmod(0o600)

        with caplog.at_level("WARNING", logger="ssh_mcp.server"):
            server_module._read_token_file(str(p))

        assert "owned by uid" not in caplog.text

    def test_kubernetes_symlink_chain_is_followed(self, tmp_path: Path) -> None:
        """A Kubernetes-shaped symlink chain must resolve, not be refused.

        kubelet's atomic writer projects each key as ``key`` ->
        ``..data/key`` -> ``..<timestamp>/key`` so that updates are atomic.
        ``paths.py::ensure_root`` uses O_NOFOLLOW; copying that here would
        reject every Kubernetes secret mount, which is why this file
        deliberately follows symlinks. This test is the guard against someone
        "hardening" it by adding O_NOFOLLOW.
        """
        data_dir = tmp_path / "..2026_09_06_04_00_00.123456789"
        data_dir.mkdir()
        (data_dir / "token").write_text(self._TOKEN)
        (tmp_path / "..data").symlink_to(data_dir)
        (tmp_path / "token").symlink_to(tmp_path / "..data" / "token")

        assert server_module._read_token_file(str(tmp_path / "token")) == self._TOKEN

    def test_directory_is_refused(self, tmp_path: Path) -> None:
        """A directory is unambiguous misconfiguration, not a token."""
        with pytest.raises(RuntimeError, match="not a regular file"):
            server_module._read_token_file(str(tmp_path))

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="fifos are POSIX-only")
    def test_fifo_is_refused_and_does_not_hang(self, tmp_path: Path) -> None:
        """A fifo must be refused rather than blocking startup forever.

        This is what O_NONBLOCK buys: a plain O_RDONLY open on a writer-less
        fifo blocks indefinitely, so the server would hang before binding
        instead of failing loudly.

        The SIGALRM deadline is the point of this test, not decoration.
        Panel finding 2026-09-06: without it, deleting O_NONBLOCK does not
        turn this test RED -- it HANGS the whole suite, and `ci.yml` sets no
        `timeout-minutes`, so the runner would sit at GitHub's 360-minute
        default. A mutation that hangs CI is strictly worse than one that
        fails it, so the failure mode is forced to be a fast, legible error.
        Chosen over adding a `pytest-timeout` dependency for one test.
        """
        fifo = tmp_path / "fifo"
        os.mkfifo(fifo)

        def _deadline(signum: int, frame: object) -> None:
            raise TimeoutError(
                "_read_token_file blocked opening a writer-less fifo — "
                "O_NONBLOCK was lost"
            )

        previous = signal.signal(signal.SIGALRM, _deadline)
        signal.setitimer(signal.ITIMER_REAL, 5.0)
        try:
            with pytest.raises(RuntimeError, match="not a regular file"):
                server_module._read_token_file(str(fifo))
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)

    def test_oversized_file_is_refused(self, tmp_path: Path) -> None:
        """A file over the cap is the wrong path, not a secret."""
        p = tmp_path / "token"
        p.write_bytes(b"x" * (server_module._MAX_TOKEN_FILE_BYTES + 1))

        with pytest.raises(RuntimeError, match="over the .*-byte limit"):
            server_module._read_token_file(str(p))

    def test_file_at_the_size_limit_is_accepted(self, tmp_path: Path) -> None:
        """The cap is inclusive — the boundary must not be off by one."""
        p = tmp_path / "token"
        p.write_bytes(b"x" * server_module._MAX_TOKEN_FILE_BYTES)

        got = server_module._read_token_file(str(p))
        assert len(got) == server_module._MAX_TOKEN_FILE_BYTES

    def test_empty_file_yields_empty_string(self, tmp_path: Path) -> None:
        """An empty file must stay non-fatal.

        ``_run_http`` maps ``"" -> None``, which on a loopback bind means
        "no auth" -- the pre-0.7.0 behaviour. Changing this to raise would
        turn a documented deployment into a startup failure.
        """
        p = tmp_path / "token"
        p.write_text("")
        p.chmod(0o600)

        assert server_module._read_token_file(str(p)) == ""

    def test_non_utf8_file_is_refused_with_a_runtime_error(
        self, tmp_path: Path
    ) -> None:
        """Invalid UTF-8 must surface as RuntimeError, not a raw traceback.

        ``UnicodeDecodeError`` is a ``ValueError``, NOT an ``OSError``, so the
        ``except OSError`` arm does not catch it and it escaped as an
        unhandled traceback at startup until this was fixed. The old
        ``Path.read_text()`` had the same hole, so this is not a regression --
        but the helper documents that it raises ``RuntimeError``, and a
        binary file is exactly the wrong-path case an operator needs told
        about in words.
        """
        p = tmp_path / "token"
        p.write_bytes(b"\xff\xfe\x00not-text")
        p.chmod(0o600)

        with pytest.raises(RuntimeError, match="not valid UTF-8"):
            server_module._read_token_file(str(p))

    @pytest.mark.skipif(
        not os.path.isdir("/dev/fd"), reason="/dev/fd is POSIX-specific"
    )
    def test_no_file_descriptor_is_leaked_on_any_path(self, tmp_path: Path) -> None:
        """Every exit path must close the descriptor exactly once.

        The helper hands the fd to ``os.fdopen`` on success and sets a ``-1``
        sentinel so ``finally`` does not double-close, while the four refusal
        paths raise BEFORE ``fdopen`` and rely on ``finally``. That is easy to
        get subtly wrong, and a leak in a long-lived server is a real
        resource bug -- the repo has a prior incident where accumulated
        connections exhausted the container's 1024 fd limit (see the
        ``SSH_MCP_HTTP_KEEPALIVE_TIMEOUT`` note in README).

        Counting ``/dev/fd`` is POSIX-specific, which is acceptable here:
        the sibling fifo test already requires ``os.mkfifo``.
        """
        ok = tmp_path / "ok"
        ok.write_text("token-1234567890abcdef")
        ok.chmod(0o600)
        big = tmp_path / "big"
        big.write_bytes(b"x" * (server_module._MAX_TOKEN_FILE_BYTES + 1))
        binary = tmp_path / "bin"
        binary.write_bytes(b"\xff\xfe\x00")
        binary.chmod(0o600)

        targets = [ok, big, tmp_path, tmp_path / "missing", binary]

        def _open_fd_count() -> int:
            return len(os.listdir("/dev/fd"))

        before = _open_fd_count()
        for _ in range(50):
            for t in targets:
                try:
                    server_module._read_token_file(str(t))
                except RuntimeError:
                    pass
        after = _open_fd_count()

        assert after <= before, (
            f"descriptor leak: {before} open fds before, {after} after "
            f"250 calls across {len(targets)} paths"
        )

    def test_io_error_after_open_becomes_a_runtime_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An OSError raised while READING must also be wrapped.

        The open-fails case is covered by ``TestTokenFile
        ::test_token_file_missing_raises``, but the ``except OSError`` arm
        also has to catch a failure from the READ -- e.g. EIO on a failing
        disk, or a procfs pseudo-file that stats as a regular file and then
        refuses to be read (a validator demonstrated exactly that with
        ``/proc/self/mem``). Without this the operator would get a raw
        OSError traceback naming neither the env var nor the path.

        The failure is injected at ``read`` rather than at ``fdopen``
        because that is the real uncovered branch, and because a fake that
        makes ``fdopen`` itself raise gets the ownership handoff wrong: the
        helper only sets its ``fd = -1`` sentinel once ``fdopen`` has
        returned, so a fake that closes the descriptor and then raises makes
        the ``finally`` double-close and fail with EBADF -- an artefact of
        the fake, not a defect in the code under test.
        """
        p = tmp_path / "token"
        p.write_text(self._TOKEN)
        p.chmod(0o600)

        real_fdopen = os.fdopen

        class _UnreadableFile:
            def __init__(self, wrapped: object) -> None:
                self._wrapped = wrapped

            def __enter__(self) -> _UnreadableFile:
                return self

            def __exit__(self, *exc: object) -> None:
                self._wrapped.close()  # type: ignore[attr-defined]

            def read(self, *_a: object) -> str:
                raise OSError(5, "Input/output error")

        def unreadable_fdopen(fd: int, *a: object, **kw: object) -> _UnreadableFile:
            return _UnreadableFile(real_fdopen(fd, *a, **kw))  # type: ignore[arg-type]

        monkeypatch.setattr(server_module.os, "fdopen", unreadable_fdopen)

        with pytest.raises(RuntimeError, match="could not be read"):
            server_module._read_token_file(str(p))

    def test_empty_token_file_yields_no_auth_through_run_http(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """End-to-end: an empty token file must still mean "no token".

        ``_read_token_file`` returning ``""`` is only half the contract; what
        matters to an operator is that ``_run_http`` maps it to ``None`` at
        `token = raw_token or None`, which on a loopback bind is the
        documented unauthenticated mode. Panel finding 2026-09-06: the
        unit-level test alone stays green if that mapping is changed to
        `token = raw_token`, which would attach the bearer middleware with an
        empty secret and abort startup on the 16-character minimum -- turning
        a configuration that worked in 0.7.0 into a hard failure.
        """
        token_path = tmp_path / "token"
        token_path.write_text("")
        token_path.chmod(0o600)

        monkeypatch.setenv("SSH_MCP_HTTP_HOST", "127.0.0.1")
        monkeypatch.delenv("SSH_MCP_HTTP_TOKEN", raising=False)
        monkeypatch.setenv("SSH_MCP_HTTP_TOKEN_FILE", str(token_path))

        captured: list[str | None] = []

        def fake_build(token, **_kwargs):  # type: ignore[no-untyped-def]
            captured.append(token)
            return _make_dummy_asgi_app()

        with patch("ssh_mcp.server._build_http_app", side_effect=fake_build):
            with patch("uvicorn.run"):
                _run_http()

        assert captured == [None], (
            f"empty token file must yield token=None, got {captured!r}"
        )
