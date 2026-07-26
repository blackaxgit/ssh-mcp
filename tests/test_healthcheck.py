"""Tests for ssh_mcp.healthcheck liveness probe."""

from __future__ import annotations

import urllib.error
from unittest.mock import MagicMock, patch

import pytest

from ssh_mcp import healthcheck


# ---------------------------------------------------------------------------
# stdio mode
# ---------------------------------------------------------------------------


def test_stdio_unhealthy_without_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """S15: no config resolvable anywhere in the server's fallback chain -> unhealthy.

    Previously this reported healthy off a bare ``import ssh_mcp`` — a probe
    that never actually checked whether the server could initialize. HOME is
    redirected to an empty tmp_path so this test doesn't accidentally pick up
    a real ``~/.config/ssh-mcp/servers.toml`` on the machine running the suite.
    """
    monkeypatch.delenv("SSH_MCP_CONFIG", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    ok, diag = healthcheck._check_stdio()
    assert ok is False
    assert "no config resolved" in diag


def test_stdio_unhealthy_config_path_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """S15: SSH_MCP_CONFIG set but pointing at a nonexistent file -> unhealthy.

    ``_get_config_path`` returns the env var path verbatim without checking
    existence (that's ServerRegistry's job), so this exercises the parse-time
    FileNotFoundError path rather than the resolution-time one.
    """
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("SSH_MCP_CONFIG", str(tmp_path / "does-not-exist.toml"))
    ok, diag = healthcheck._check_stdio()
    assert ok is False
    assert "config parse failed" in diag


def test_stdio_healthy_with_valid_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """Valid TOML config file parses cleanly."""
    monkeypatch.setenv("HOME", str(tmp_path))
    config = tmp_path / "servers.toml"
    # Empty registry (no [servers.*] entries) is still valid TOML.
    config.write_text("# empty registry\n")
    monkeypatch.setenv("SSH_MCP_CONFIG", str(config))
    ok, diag = healthcheck._check_stdio()
    assert ok is True, f"expected healthy, got: {diag}"


def test_stdio_healthy_via_xdg_fallback_without_env_var(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """S15: SSH_MCP_CONFIG unset but a valid XDG config exists -> healthy.

    Proves the probe now walks the *same* fallback chain as the server
    (server.py::_get_config_path step 2) instead of only ever looking at
    SSH_MCP_CONFIG — the asymmetry the finding was about.
    """
    monkeypatch.delenv("SSH_MCP_CONFIG", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    xdg_dir = tmp_path / ".config" / "ssh-mcp"
    xdg_dir.mkdir(parents=True)
    (xdg_dir / "servers.toml").write_text("# empty registry\n")
    ok, diag = healthcheck._check_stdio()
    assert ok is True, f"expected healthy, got: {diag}"


def test_stdio_unhealthy_on_malformed_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """Malformed TOML -> unhealthy with diagnostic."""
    monkeypatch.setenv("HOME", str(tmp_path))
    config = tmp_path / "servers.toml"
    config.write_text("this is [ not valid ::: toml")
    monkeypatch.setenv("SSH_MCP_CONFIG", str(config))
    ok, diag = healthcheck._check_stdio()
    assert ok is False
    assert "config parse failed" in diag


def test_stdio_token_never_logged_on_any_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The stdio diagnostic must never contain a configured HTTP token.

    stdio mode doesn't consult the token at all, but this guards against a
    future refactor accidentally threading it through, and confirms nothing
    is printed to stdout/stderr by _check_stdio itself (run() owns printing).
    """
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("SSH_MCP_HTTP_TOKEN", "super-secret-token-value")
    monkeypatch.delenv("SSH_MCP_CONFIG", raising=False)
    ok, diag = healthcheck._check_stdio()
    assert ok is False
    assert "super-secret-token-value" not in diag
    captured = capsys.readouterr()
    assert "super-secret-token-value" not in captured.out
    assert "super-secret-token-value" not in captured.err


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


def test_run_exits_0_on_success(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    """End-to-end: a resolvable, valid config -> exit 0.

    Uses an explicit SSH_MCP_CONFIG (rather than relying on ambient HOME) so
    this test is deterministic regardless of what's on the machine running
    the suite — see S15 test_stdio_unhealthy_without_config for the case
    this used to conflate with "healthy".
    """
    monkeypatch.setenv("SSH_MCP_TRANSPORT", "stdio")
    config = tmp_path / "servers.toml"
    config.write_text("# empty registry\n")
    monkeypatch.setenv("SSH_MCP_CONFIG", str(config))
    with pytest.raises(SystemExit) as exc_info:
        healthcheck.run()
    assert exc_info.value.code == 0


def test_run_exits_1_on_unresolvable_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """S15 end-to-end: no config anywhere in the fallback chain -> exit 1.

    This is the regression test for the finding itself: previously ``run()``
    would exit 0 here, meaning Docker's HEALTHCHECK reported a misconfigured
    container as live.
    """
    monkeypatch.setenv("SSH_MCP_TRANSPORT", "stdio")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("SSH_MCP_CONFIG", raising=False)
    with pytest.raises(SystemExit) as exc_info:
        healthcheck.run()
    assert exc_info.value.code == 1


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
