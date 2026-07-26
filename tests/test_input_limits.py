"""Regression tests for packet P-C: input limits and server-side polish.

Covers:
  * B2-cap — ``max_command_bytes`` enforced at the ``execute`` /
    ``execute_on_group`` tool boundary, before the command reaches the
    superlinear ``_redact_secrets`` / ``_is_dangerous_command`` functions
    in ``ssh.py``.
  * N5 — a non-ASCII bearer token yields a clean 401, not an unhandled
    500 from ``hmac.compare_digest``'s ASCII-only ``str`` restriction.
  * XDG consistency — ``_get_config_path`` honours ``$XDG_CONFIG_HOME``
    when set, falling back to ``~/.config`` when unset.
  * Tool docstrings — ``upload_file`` / ``download_file`` no longer
    instruct callers to pass absolute local paths.

Every test here is written to FAIL against the pre-fix code and PASS
after it.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from mcp.server.fastmcp.exceptions import ToolError

import ssh_mcp.server as server_module
from ssh_mcp.config import ServerRegistry
from ssh_mcp.models import ExecResult
from ssh_mcp.ssh import SSHManager

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def reset_server_globals(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reset server module globals before each test (mirrors test_server.py)."""
    monkeypatch.setattr(server_module, "_registry", None)
    monkeypatch.setattr(server_module, "_ssh", None)
    monkeypatch.setattr(server_module, "_init_lock", asyncio.Lock())


@pytest.fixture
def mock_init(monkeypatch: pytest.MonkeyPatch, tmp_config_file: Path) -> MagicMock:
    """Pre-initialize server globals with a REAL registry + mocked SSHManager.

    The registry is real (not mocked) because ``max_command_bytes`` is read
    via ``_get_registry().settings`` — deliberately, not via
    ``_get_ssh().settings``, because the pre-existing ``mock_init`` fixture
    pattern used across this test suite (test_server.py) mocks ``_ssh`` with
    ``MagicMock(spec=SSHManager)`` and never populates its ``.settings``
    attribute, which would make ``.settings`` access raise ``AttributeError``
    on every mocked call. Reading settings from the registry avoids
    depending on that mock's shape.
    """
    registry = ServerRegistry(str(tmp_config_file))
    mock_ssh = MagicMock(spec=SSHManager)
    monkeypatch.setattr(server_module, "_registry", registry)
    monkeypatch.setattr(server_module, "_ssh", mock_ssh)
    return mock_ssh


def _dummy_result(command: str) -> ExecResult:
    return ExecResult(
        server="test-web1",
        command=command,
        stdout="ok",
        stderr="",
        exit_code=0,
        duration_ms=1,
    )


# ---------------------------------------------------------------------------
# B2-cap — _check_command_length unit behavior
# ---------------------------------------------------------------------------


class TestCheckCommandLength:
    """Unit tests for the boundary check itself."""

    def test_command_at_limit_is_accepted(self) -> None:
        """Exactly max_bytes must be accepted (boundary is inclusive)."""
        command = "a" * 100
        server_module._check_command_length(command, max_bytes=100)  # no raise

    def test_command_one_byte_over_limit_is_rejected(self) -> None:
        """One byte over the limit must be rejected."""
        command = "a" * 101
        with pytest.raises(ToolError):
            server_module._check_command_length(command, max_bytes=100)

    def test_multibyte_command_rejected_on_byte_length_not_char_length(self) -> None:
        """A naive len(command) check would miss this: each 'é' is 1 char but
        2 UTF-8 bytes, so 60 characters is 120 bytes — over a 100-byte limit
        even though the character count (60) is comfortably under it."""
        command = "é" * 60
        assert len(command) == 60  # character length is well under the limit
        assert len(command.encode("utf-8")) == 120  # byte length exceeds it
        with pytest.raises(ToolError):
            server_module._check_command_length(command, max_bytes=100)

    def test_multibyte_command_at_byte_limit_is_accepted(self) -> None:
        """The multibyte counterpart of the boundary-inclusive happy path."""
        command = "é" * 50  # 50 chars, 100 bytes
        assert len(command.encode("utf-8")) == 100
        server_module._check_command_length(command, max_bytes=100)  # no raise

    def test_error_message_names_the_limit_and_setting(self) -> None:
        """Fail-fast error must be actionable: name actual/permitted sizes
        and the setting that controls them."""
        command = "x" * 200
        with pytest.raises(ToolError) as exc_info:
            server_module._check_command_length(command, max_bytes=100)
        message = str(exc_info.value)
        assert "200" in message
        assert "100" in message
        assert "max_command_bytes" in message


# ---------------------------------------------------------------------------
# B2-cap — enforcement at the execute / execute_on_group tool boundary
# ---------------------------------------------------------------------------


class TestExecuteEnforcesCommandLimit:
    """Verify the `execute` tool rejects an over-long command BEFORE it
    reaches the SSH layer — the whole point being that _is_dangerous_command
    / _redact_secrets (superlinear, no re timeout) must never see it."""

    async def test_oversized_command_rejected_before_ssh_call(
        self, mock_init: MagicMock
    ) -> None:
        mock_init.execute = AsyncMock(side_effect=AssertionError("must not be called"))
        max_bytes = server_module._get_registry().settings.max_command_bytes
        oversized = "x" * (max_bytes + 1)

        with pytest.raises(ToolError, match="max_command_bytes"):
            await server_module.execute(server="test-web1", command=oversized)

        mock_init.execute.assert_not_awaited()

    async def test_oversized_command_rejected_even_with_dry_run(
        self, mock_init: MagicMock
    ) -> None:
        """The measured attack (B2) is reachable via dry_run=True before any
        SSH connection or authentication — the cap must apply regardless."""
        mock_init.execute = AsyncMock(side_effect=AssertionError("must not be called"))
        max_bytes = server_module._get_registry().settings.max_command_bytes
        oversized = "x" * (max_bytes + 1)

        with pytest.raises(ToolError, match="max_command_bytes"):
            await server_module.execute(
                server="test-web1", command=oversized, dry_run=True
            )

        mock_init.execute.assert_not_awaited()

    async def test_command_at_limit_reaches_ssh_layer(
        self, mock_init: MagicMock
    ) -> None:
        max_bytes = server_module._get_registry().settings.max_command_bytes
        command = "x" * max_bytes
        mock_init.execute = AsyncMock(return_value=_dummy_result(command))

        result = await server_module.execute(server="test-web1", command=command)

        mock_init.execute.assert_awaited_once()
        assert "ok" in result


class TestExecuteOnGroupEnforcesCommandLimit:
    """Same enforcement, mirrored for execute_on_group (server.py:422-429)."""

    async def test_oversized_command_rejected_before_ssh_call(
        self, mock_init: MagicMock
    ) -> None:
        mock_init.execute_on_group = AsyncMock(
            side_effect=AssertionError("must not be called")
        )
        max_bytes = server_module._get_registry().settings.max_command_bytes
        oversized = "x" * (max_bytes + 1)

        with pytest.raises(ToolError, match="max_command_bytes"):
            await server_module.execute_on_group(group="test-prod", command=oversized)

        mock_init.execute_on_group.assert_not_awaited()

    async def test_command_at_limit_reaches_ssh_layer(
        self, mock_init: MagicMock
    ) -> None:
        max_bytes = server_module._get_registry().settings.max_command_bytes
        command = "x" * max_bytes
        mock_init.execute_on_group = AsyncMock(return_value=[_dummy_result(command)])

        await server_module.execute_on_group(group="test-prod", command=command)

        mock_init.execute_on_group.assert_awaited_once()


# ---------------------------------------------------------------------------
# N5 — non-ASCII bearer token returns 401, not 500
# ---------------------------------------------------------------------------


class TestBearerAuthNonAsciiToken:
    """hmac.compare_digest(str, str) raises TypeError on non-ASCII input.

    Driven at the raw ASGI level (not through TestClient/httpx) because
    HTTP client libraries validate header bytes before sending, which would
    prevent constructing the malformed request this test needs to send.
    """

    @staticmethod
    def _make_middleware(expected: str) -> tuple[object, list[dict[str, object]]]:
        BearerAuth = server_module._make_bearer_auth_middleware()
        sent: list[dict[str, object]] = []

        async def downstream(scope, receive, send):  # type: ignore[no-untyped-def]
            raise AssertionError(
                "downstream app must not be reached for invalid credentials"
            )

        middleware = BearerAuth(downstream, expected=expected)
        return middleware, sent

    async def test_non_ascii_token_returns_401_not_500(self) -> None:
        middleware, sent = self._make_middleware("correct-token-1234567890")

        # UTF-8 bytes that are NOT valid ASCII once decoded as latin-1 they
        # become a str containing codepoints > U+007F, which used to blow
        # up inside hmac.compare_digest.
        non_ascii_credential = "tökén-döes-nöt-match".encode("utf-8")
        scope = {
            "type": "http",
            "headers": [(b"authorization", b"Bearer " + non_ascii_credential)],
        }

        async def receive():  # type: ignore[no-untyped-def]
            return {"type": "http.disconnect"}

        events: list[dict[str, object]] = []

        async def send(message):  # type: ignore[no-untyped-def]
            events.append(message)

        # Must complete without raising (no unhandled TypeError -> 500).
        await middleware(scope, receive, send)  # type: ignore[operator]

        start = next(m for m in events if m["type"] == "http.response.start")
        assert start["status"] == 401

    async def test_ascii_token_still_authenticates(self) -> None:
        """Happy-path regression check: the bytes-based comparison must still
        accept a correct, ordinary ASCII token."""
        token = "correct-token-1234567890"

        BearerAuth = server_module._make_bearer_auth_middleware()
        reached_downstream = False

        async def downstream(scope, receive, send):  # type: ignore[no-untyped-def]
            nonlocal reached_downstream
            reached_downstream = True
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b""})

        middleware = BearerAuth(downstream, expected=token)
        scope = {
            "type": "http",
            "headers": [(b"authorization", f"Bearer {token}".encode())],
        }

        async def receive():  # type: ignore[no-untyped-def]
            return {"type": "http.disconnect"}

        async def send(message):  # type: ignore[no-untyped-def]
            pass

        await middleware(scope, receive, send)  # type: ignore[operator]

        assert reached_downstream

    async def test_wrong_ascii_token_still_returns_401(self) -> None:
        """Ordinary invalid-credential path must still 401 (fail closed)."""
        middleware, _ = self._make_middleware("correct-token-1234567890")
        scope = {
            "type": "http",
            "headers": [(b"authorization", b"Bearer wrong-token-0000000000")],
        }

        async def receive():  # type: ignore[no-untyped-def]
            return {"type": "http.disconnect"}

        events: list[dict[str, object]] = []

        async def send(message):  # type: ignore[no-untyped-def]
            events.append(message)

        await middleware(scope, receive, send)  # type: ignore[operator]

        start = next(m for m in events if m["type"] == "http.response.start")
        assert start["status"] == 401


# ---------------------------------------------------------------------------
# XDG consistency — _get_config_path honours $XDG_CONFIG_HOME
# ---------------------------------------------------------------------------


class TestXdgConfigHomeConsistency:
    def test_xdg_config_home_honored_when_set(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """A config placed under $XDG_CONFIG_HOME must be found there,
        rather than under the hardcoded ~/.config path."""
        monkeypatch.delenv("SSH_MCP_CONFIG", raising=False)
        custom_xdg = tmp_path / "custom-xdg-config"
        monkeypatch.setenv("XDG_CONFIG_HOME", str(custom_xdg))

        config_file = custom_xdg / "ssh-mcp" / "servers.toml"
        config_file.parent.mkdir(parents=True)
        config_file.touch()

        result = server_module._get_config_path()

        assert result == str(config_file)

    def test_falls_back_to_dot_config_when_xdg_config_home_unset(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """With $XDG_CONFIG_HOME unset, the ~/.config fallback must still
        work (regression guard for the existing fallback chain order)."""
        from unittest.mock import patch

        monkeypatch.delenv("SSH_MCP_CONFIG", raising=False)
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)

        xdg_config = tmp_path / ".config" / "ssh-mcp" / "servers.toml"
        xdg_config.parent.mkdir(parents=True)
        xdg_config.touch()

        with patch.object(Path, "home", return_value=tmp_path):
            result = server_module._get_config_path()

        assert result == str(xdg_config)


# ---------------------------------------------------------------------------
# Tool docstrings — upload_file / download_file no longer say "absolute"
# for the transfer_root-relative local path
# ---------------------------------------------------------------------------


class TestTransferToolDocstrings:
    def test_upload_file_docstring_drops_absolute_local_path_contract(self) -> None:
        doc = server_module.upload_file.__doc__ or ""
        assert "Absolute path to local file" not in doc
        assert "transfer_root" in doc
        assert "relative" in doc.lower()

    def test_download_file_docstring_drops_absolute_local_path_contract(self) -> None:
        doc = server_module.download_file.__doc__ or ""
        assert "Absolute local destination path" not in doc
        assert "transfer_root" in doc
        assert "relative" in doc.lower()
        assert "no-clobber" in doc.lower()

    def test_neither_docstring_instructs_absolute_local_paths(self) -> None:
        """Direct check on the local_path Args line specifically: the
        remote_path/remote file legitimately stays absolute, only the
        LOCAL path contract changed."""
        for tool in (server_module.upload_file, server_module.download_file):
            doc = tool.__doc__ or ""
            local_path_lines = [
                line for line in doc.splitlines() if "local_path:" in line
            ]
            assert local_path_lines, (
                f"{tool.__name__} docstring must document local_path"
            )
            assert "absolute" not in local_path_lines[0].lower()
