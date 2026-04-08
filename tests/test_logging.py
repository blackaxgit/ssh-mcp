"""Tests for structured logging configuration in ssh_mcp.server._configure_logging."""

from __future__ import annotations

import importlib
import json
import logging

import pytest


def _reload_server_module() -> None:
    """Reload ssh_mcp.server so module-level _configure_logging() re-runs."""
    import ssh_mcp.server

    importlib.reload(ssh_mcp.server)


class TestConfigureLogging:
    """_configure_logging wires stderr handler with chosen renderer."""

    def test_console_format_default(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Default (no env var) emits human-readable console output."""
        monkeypatch.delenv("SSH_MCP_LOG_FORMAT", raising=False)
        _reload_server_module()

        logger = logging.getLogger("ssh_mcp.test")
        logger.info("hello world")

        err = capsys.readouterr().err
        # Console renderer should NOT produce JSON; must contain the message text.
        assert "hello world" in err
        assert not err.strip().startswith("{"), (
            "Console output must not be JSON-formatted"
        )

    def test_json_format_when_env_set(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """SSH_MCP_LOG_FORMAT=json emits parseable JSON lines."""
        monkeypatch.setenv("SSH_MCP_LOG_FORMAT", "json")
        _reload_server_module()

        logger = logging.getLogger("ssh_mcp.test")
        logger.info("json event", extra={"server": "web1"})

        err = capsys.readouterr().err
        # Find the JSON line containing our event
        lines = [ln for ln in err.strip().splitlines() if ln.strip().startswith("{")]
        assert lines, f"No JSON lines in stderr: {err!r}"

        # Parse and assert structure
        event = None
        for line in lines:
            parsed = json.loads(line)
            if parsed.get("event") == "json event":
                event = parsed
                break
        assert event is not None, f"Event not found in: {lines}"

        # Every log line must carry these structured fields
        assert "timestamp" in event
        assert event.get("level") == "info"

    def test_json_timestamp_is_iso(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """JSON timestamps must be ISO-8601 UTC (sortable, tz-aware)."""
        monkeypatch.setenv("SSH_MCP_LOG_FORMAT", "json")
        _reload_server_module()

        logger = logging.getLogger("ssh_mcp.test")
        logger.info("ts check")

        err = capsys.readouterr().err
        for line in err.strip().splitlines():
            if not line.strip().startswith("{"):
                continue
            parsed = json.loads(line)
            if parsed.get("event") != "ts check":
                continue
            ts = parsed["timestamp"]
            # ISO-8601 with T separator and tz suffix
            assert "T" in ts
            # structlog TimeStamper with utc=True adds "+00:00" or "Z"
            assert ts.endswith("Z") or ts.endswith("+00:00")
            return
        pytest.fail("Did not find 'ts check' log line")

    def test_reconfigure_does_not_duplicate_handlers(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Calling _configure_logging twice must not add a second handler."""
        from ssh_mcp.server import _configure_logging

        monkeypatch.delenv("SSH_MCP_LOG_FORMAT", raising=False)
        _configure_logging()
        handlers_after_first = len(logging.getLogger().handlers)

        _configure_logging()
        handlers_after_second = len(logging.getLogger().handlers)

        assert handlers_after_first == 1
        assert handlers_after_second == 1, (
            "Reconfiguration must clear handlers to avoid duplicate log lines"
        )

    def test_unknown_format_falls_back_to_console(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Invalid SSH_MCP_LOG_FORMAT values silently fall back to console.

        Operators who set an unexpected value should get readable logs, not
        a crash. JSON is only used when the value is exactly 'json'.
        """
        monkeypatch.setenv("SSH_MCP_LOG_FORMAT", "yaml")
        _reload_server_module()

        logger = logging.getLogger("ssh_mcp.test")
        logger.info("fallback check")

        err = capsys.readouterr().err
        assert "fallback check" in err
        assert not err.strip().startswith("{")
