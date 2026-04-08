"""Tests for OpenTelemetry instrumentation (C1).

Uses ``InMemorySpanExporter`` from the OTel SDK so every assertion runs
fully offline. A module-scoped fixture installs a ``TracerProvider`` with
the in-memory exporter exactly once, then each test clears it between
invocations.
"""

from __future__ import annotations

from collections.abc import Iterator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)

from ssh_mcp.models import Settings
from ssh_mcp.ssh import SSHManager

_exporter: InMemorySpanExporter = InMemorySpanExporter()


@pytest.fixture(scope="module", autouse=True)
def _install_tracer_provider() -> Iterator[None]:
    """Install an SDK TracerProvider with in-memory exporter for the module.

    The NoOp provider installed at import time is replaced here so the
    spans produced by ssh_mcp code are actually recorded. After the module
    finishes, we leave the SDK provider in place — other test modules are
    isolated by Hypothesis/pytest fixtures and don't assert on tracing.
    """
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(_exporter))
    trace.set_tracer_provider(provider)
    yield


@pytest.fixture(autouse=True)
def _clear_spans() -> Iterator[None]:
    """Reset the recorded spans between tests for isolation."""
    _exporter.clear()
    yield
    _exporter.clear()


def _make_registry():
    import tempfile

    from ssh_mcp.config import ServerRegistry

    config_content = """
[settings]
command_timeout = 30

[groups]
test = { description = "Test group" }

[servers.test-host]
description = "Test server"
groups = ["test"]
"""
    tmp = tempfile.NamedTemporaryFile(suffix=".toml", mode="w", delete=False)
    tmp.write(config_content)
    tmp.flush()
    tmp.close()
    return ServerRegistry(tmp.name)


class TestSSHExecuteTracing:
    """`SSHManager.execute` creates a span with expected attributes."""

    async def test_span_created_on_dangerous_command_block(self) -> None:
        """Blocked commands must still produce a span with error status."""
        # Need a fresh tracer after provider swap — the module-level tracer
        # cached at import time points to the old NoOp provider. Patch it.
        import ssh_mcp.ssh as ssh_module

        with patch.object(
            ssh_module, "_ssh_tracer", trace.get_tracer("ssh_mcp.ssh")
        ):
            manager = SSHManager(_make_registry(), Settings())
            result = await manager.execute("test-host", "rm -rf /", timeout=30)

        # The call should be blocked, not actually execute anything
        assert result.error is not None
        assert "Blocked" in result.error

        spans = _exporter.get_finished_spans()
        assert len(spans) == 1
        span = spans[0]
        assert span.name == "ssh.execute"
        assert span.attributes["ssh.host"] == "test-host"
        assert span.attributes["ssh.command_length"] == len("rm -rf /")
        assert span.attributes["ssh.force"] is False
        # Blocked result should have ERROR status via set_status in wrapper
        from opentelemetry.trace.status import StatusCode

        assert span.status.status_code == StatusCode.ERROR
        assert "Blocked" in span.attributes.get("ssh.error", "")

    async def test_command_length_does_not_leak_raw_command(self) -> None:
        """Spans must NOT include the raw command text — only its length.

        Privacy guarantee: operators may ingest traces into third-party
        backends where secrets in command strings would be exposed.
        """
        import ssh_mcp.ssh as ssh_module

        secret_cmd = "echo 'password=hunter2' > /tmp/out"
        with patch.object(
            ssh_module, "_ssh_tracer", trace.get_tracer("ssh_mcp.ssh")
        ):
            manager = SSHManager(_make_registry(), Settings())
            # Mock _get_connection to avoid real SSH; the call will still
            # enter the span creation path.
            with patch.object(
                manager,
                "_get_connection",
                AsyncMock(side_effect=OSError("no net")),
            ):
                await manager.execute("test-host", secret_cmd)

        spans = _exporter.get_finished_spans()
        assert len(spans) == 1
        span = spans[0]
        # The raw command must NOT appear in any attribute
        for key, value in span.attributes.items():
            assert "hunter2" not in str(value), (
                f"Secret leaked via attribute {key}={value}"
            )
            assert "password=" not in str(value), (
                f"Secret leaked via attribute {key}={value}"
            )
        # But the length IS recorded
        assert span.attributes["ssh.command_length"] == len(secret_cmd)


class TestNoOpWhenTracerUnavailable:
    """Graceful degradation when opentelemetry-api is not installed."""

    async def test_execute_works_when_tracer_is_none(self) -> None:
        """Monkey-patching ``_ssh_tracer`` to None must not break execute."""
        import ssh_mcp.ssh as ssh_module

        with patch.object(ssh_module, "_ssh_tracer", None):
            manager = SSHManager(_make_registry(), Settings())
            # Dangerous-command path returns early without needing a real
            # connection — ideal for the no-op smoke test.
            result = await manager.execute("test-host", "rm -rf /")
            assert "Blocked" in (result.error or "")

        # No spans should be recorded because the wrapper skipped the
        # tracer path entirely.
        assert not _exporter.get_finished_spans()
