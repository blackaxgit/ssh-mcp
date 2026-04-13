"""Tests for ssh_mcp.healthcheck liveness probe."""

from __future__ import annotations

import urllib.error
from unittest.mock import MagicMock, patch

import pytest

from ssh_mcp import healthcheck


# ---------------------------------------------------------------------------
# stdio mode
# ---------------------------------------------------------------------------


def test_stdio_healthy_without_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """Package imports cleanly; no config path set -> healthy."""
    monkeypatch.delenv("SSH_MCP_CONFIG", raising=False)
    ok, diag = healthcheck._check_stdio()
    assert ok is True
    assert "healthy" in diag


def test_stdio_healthy_with_valid_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """Valid TOML config file parses cleanly."""
    config = tmp_path / "servers.toml"
    # Empty registry (no [servers.*] entries) is still valid TOML.
    config.write_text("# empty registry\n")
    monkeypatch.setenv("SSH_MCP_CONFIG", str(config))
    ok, diag = healthcheck._check_stdio()
    assert ok is True, f"expected healthy, got: {diag}"


def test_stdio_unhealthy_on_malformed_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """Malformed TOML -> unhealthy with diagnostic."""
    config = tmp_path / "servers.toml"
    config.write_text("this is [ not valid ::: toml")
    monkeypatch.setenv("SSH_MCP_CONFIG", str(config))
    ok, diag = healthcheck._check_stdio()
    assert ok is False
    assert "config parse failed" in diag


# ---------------------------------------------------------------------------
# http mode
# ---------------------------------------------------------------------------


def _mock_response(status: int = 200) -> MagicMock:
    """Build a context-manager mock that urlopen's ``with`` block returns."""
    resp = MagicMock()
    resp.status = status
    cm = MagicMock()
    cm.__enter__.return_value = resp
    cm.__exit__.return_value = False
    return cm


def test_http_healthy_200(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SSH_MCP_HTTP_PORT", "8000")
    monkeypatch.setenv("SSH_MCP_HTTP_AUTH", "none")
    with patch("urllib.request.urlopen", return_value=_mock_response(200)):
        ok, diag = healthcheck._check_http()
    assert ok is True
    assert diag == "http 200"


def test_http_401_still_healthy(monkeypatch: pytest.MonkeyPatch) -> None:
    """401 means the server is alive but rejected our creds -> still healthy."""
    monkeypatch.setenv("SSH_MCP_HTTP_PORT", "8000")
    monkeypatch.setenv("SSH_MCP_HTTP_AUTH", "none")
    err = urllib.error.HTTPError(
        url="http://127.0.0.1:8000/mcp",
        code=401,
        msg="Unauthorized",
        hdrs=None,  # type: ignore[arg-type]
        fp=None,
    )
    with patch("urllib.request.urlopen", side_effect=err):
        ok, diag = healthcheck._check_http()
    assert ok is True
    assert diag == "http 401"


def test_http_500_unhealthy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SSH_MCP_HTTP_PORT", "8000")
    monkeypatch.setenv("SSH_MCP_HTTP_AUTH", "none")
    err = urllib.error.HTTPError(
        url="http://127.0.0.1:8000/mcp",
        code=500,
        msg="Internal Server Error",
        hdrs=None,  # type: ignore[arg-type]
        fp=None,
    )
    with patch("urllib.request.urlopen", side_effect=err):
        ok, diag = healthcheck._check_http()
    assert ok is False
    assert diag == "http 500"


def test_http_connect_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SSH_MCP_HTTP_PORT", "8000")
    monkeypatch.setenv("SSH_MCP_HTTP_AUTH", "none")
    err = urllib.error.URLError(ConnectionRefusedError("nope"))
    with patch("urllib.request.urlopen", side_effect=err):
        ok, diag = healthcheck._check_http()
    assert ok is False
    assert "connect failed" in diag
    assert "ConnectionRefusedError" in diag


def test_http_auth_none_omits_authorization_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With SSH_MCP_HTTP_AUTH=none, no Authorization header should be sent."""
    monkeypatch.setenv("SSH_MCP_HTTP_PORT", "8000")
    monkeypatch.setenv("SSH_MCP_HTTP_AUTH", "none")
    # Even if a token is set, it must be ignored.
    monkeypatch.setenv("SSH_MCP_HTTP_TOKEN", "should-not-be-sent")
    captured = {}

    def fake_urlopen(req, timeout):  # type: ignore[no-untyped-def]
        captured["headers"] = dict(req.header_items())
        return _mock_response(200)

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        ok, _ = healthcheck._check_http()
    assert ok is True
    # urllib normalizes header capitalization to Title-Case
    assert not any(k.lower() == "authorization" for k in captured["headers"])


def test_http_token_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SSH_MCP_HTTP_PORT", "8000")
    monkeypatch.setenv("SSH_MCP_HTTP_AUTH", "bearer")
    monkeypatch.setenv("SSH_MCP_HTTP_TOKEN", "secret-from-env")
    monkeypatch.delenv("SSH_MCP_HTTP_TOKEN_FILE", raising=False)
    captured = {}

    def fake_urlopen(req, timeout):  # type: ignore[no-untyped-def]
        captured["headers"] = dict(req.header_items())
        return _mock_response(200)

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        healthcheck._check_http()

    auth_values = [
        v for k, v in captured["headers"].items() if k.lower() == "authorization"
    ]
    assert auth_values == ["Bearer secret-from-env"]


def test_http_token_from_file(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    """When env token is unset, fall back to SSH_MCP_HTTP_TOKEN_FILE."""
    token_file = tmp_path / "token"
    token_file.write_text("secret-from-file\n")
    monkeypatch.setenv("SSH_MCP_HTTP_PORT", "8000")
    monkeypatch.setenv("SSH_MCP_HTTP_AUTH", "bearer")
    monkeypatch.delenv("SSH_MCP_HTTP_TOKEN", raising=False)
    monkeypatch.setenv("SSH_MCP_HTTP_TOKEN_FILE", str(token_file))
    captured = {}

    def fake_urlopen(req, timeout):  # type: ignore[no-untyped-def]
        captured["headers"] = dict(req.header_items())
        return _mock_response(200)

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        healthcheck._check_http()

    auth_values = [
        v for k, v in captured["headers"].items() if k.lower() == "authorization"
    ]
    assert auth_values == ["Bearer secret-from-file"]


# ---------------------------------------------------------------------------
# run() entry point
# ---------------------------------------------------------------------------


def test_run_exits_0_on_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SSH_MCP_TRANSPORT", "stdio")
    monkeypatch.delenv("SSH_MCP_CONFIG", raising=False)
    with pytest.raises(SystemExit) as exc_info:
        healthcheck.run()
    assert exc_info.value.code == 0


def test_run_exits_1_on_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SSH_MCP_TRANSPORT", "http")
    monkeypatch.setenv("SSH_MCP_HTTP_PORT", "8000")
    monkeypatch.setenv("SSH_MCP_HTTP_AUTH", "none")
    err = urllib.error.URLError(ConnectionRefusedError("nope"))
    with patch("urllib.request.urlopen", side_effect=err):
        with pytest.raises(SystemExit) as exc_info:
            healthcheck.run()
    assert exc_info.value.code == 1


def test_run_http_transport_aliases(monkeypatch: pytest.MonkeyPatch) -> None:
    """Both ``http`` and ``streamable-http`` should go through _check_http."""
    monkeypatch.setenv("SSH_MCP_TRANSPORT", "streamable-http")
    monkeypatch.setenv("SSH_MCP_HTTP_AUTH", "none")
    with patch("ssh_mcp.healthcheck._check_http", return_value=(True, "http 200")) as m:
        with pytest.raises(SystemExit) as exc_info:
            healthcheck.run()
    m.assert_called_once()
    assert exc_info.value.code == 0
