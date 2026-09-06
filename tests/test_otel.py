"""Tests for OpenTelemetry instrumentation (C1).

Uses ``InMemorySpanExporter`` from the OTel SDK so every assertion runs
fully offline. A module-scoped fixture installs a ``TracerProvider`` with
the in-memory exporter exactly once, then each test clears it between
invocations.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from hypothesis import given
from hypothesis import strategies as st
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

        with patch.object(ssh_module, "_ssh_tracer", trace.get_tracer("ssh_mcp.ssh")):
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
        with patch.object(ssh_module, "_ssh_tracer", trace.get_tracer("ssh_mcp.ssh")):
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


class TestOTelCommandPrivacyFuzz:
    """Green Team H4: Hypothesis fuzz test for command-content privacy.

    The substring-based check above only catches two literal tokens —
    a mutation that accidentally added a ``span.set_attribute("ssh.cmd",
    command)`` line would pass the above test for any command not
    containing ``hunter2`` or ``password=``. This property-based test
    generates arbitrary command strings and verifies that NONE of the
    characters in the command appear in any span attribute value.
    """

    @given(
        st.text(
            alphabet=st.characters(
                # Printable ASCII including symbols, plus a handful of
                # common Unicode control characters. Excludes null and
                # other bytes that would break asyncssh regardless.
                min_codepoint=0x21,
                max_codepoint=0x7E,
            ),
            min_size=16,
            max_size=100,
        )
    )
    def test_no_command_characters_in_spans(self, secret: str) -> None:
        """Property: a secret long enough to be unique must NEVER appear
        verbatim in any span attribute value.

        Generating secrets of length ≥16 with printable ASCII makes them
        statistically impossible to occur as substrings of the hardcoded
        attribute names or status strings — so any match is a real leak.
        """
        import asyncio

        import ssh_mcp.ssh as ssh_module

        _exporter.clear()

        with patch.object(ssh_module, "_ssh_tracer", trace.get_tracer("ssh_mcp.ssh")):
            manager = SSHManager(_make_registry(), Settings())
            with patch.object(
                manager,
                "_get_connection",
                AsyncMock(side_effect=OSError("no net")),
            ):
                asyncio.run(manager.execute("test-host", secret))

        spans = _exporter.get_finished_spans()
        assert len(spans) >= 1
        for span in spans:
            for key, value in span.attributes.items():
                assert secret not in str(value), (
                    f"Command leaked: secret={secret!r} in attribute {key}={value!r}"
                )


class TestSFTPTracing:
    """Green Team H2: SFTP upload/download must produce OTel spans.

    Previously only ``execute`` was wrapped. Lack of SFTP spans meant
    operators couldn't see file transfers in their trace backend and
    distributed trace correlation broke for any tool call that combined
    exec + upload/download.
    """

    async def test_upload_creates_span_on_failure(self, tmp_path: Path) -> None:
        """A failing upload still produces a span with error status.

        B1: local_path is now transfer_root-RELATIVE, not an absolute
        ``tmp_path`` string — an absolute path is rejected by
        ``validate_relative`` (PathConfinementError) BEFORE
        ``_get_connection`` is ever reached, which would exercise a
        different failure than the one this test targets (a connection
        failure surfacing as RuntimeError). A relative name lets the
        mocked ``_get_connection`` OSError be the thing that actually
        fires.
        """
        import ssh_mcp.ssh as ssh_module
        from opentelemetry.trace.status import StatusCode

        local_path = "payload.txt"

        with patch.object(ssh_module, "_ssh_tracer", trace.get_tracer("ssh_mcp.ssh")):
            settings = Settings(transfer_root=str(tmp_path / "transfers"))
            manager = SSHManager(_make_registry(), settings)
            with patch.object(
                manager,
                "_get_connection",
                AsyncMock(side_effect=OSError("no net")),
            ):
                from contextlib import suppress

                with suppress(Exception):
                    await manager.upload("test-host", local_path, "/tmp/target.txt")

        spans = [s for s in _exporter.get_finished_spans() if s.name == "ssh.upload"]
        assert len(spans) == 1, "Exactly one ssh.upload span expected"
        span = spans[0]
        assert span.attributes["ssh.host"] == "test-host"
        assert span.attributes["ssh.local_path_length"] == len(local_path)
        assert span.attributes["ssh.remote_path_length"] == len("/tmp/target.txt")
        # Inner _upload_impl catches OSError and re-raises as RuntimeError,
        # so the outer span sees the wrapped exception class.
        assert span.attributes.get("ssh.error_type") == "RuntimeError"
        assert span.status.status_code == StatusCode.ERROR

    async def test_download_creates_span_on_failure(self, tmp_path: Path) -> None:
        """A failing download still produces a span with error status."""
        import ssh_mcp.ssh as ssh_module
        from opentelemetry.trace.status import StatusCode

        local_path = "downloaded.txt"

        with patch.object(ssh_module, "_ssh_tracer", trace.get_tracer("ssh_mcp.ssh")):
            settings = Settings(transfer_root=str(tmp_path / "transfers"))
            manager = SSHManager(_make_registry(), settings)
            with patch.object(
                manager,
                "_get_connection",
                AsyncMock(side_effect=OSError("no net")),
            ):
                from contextlib import suppress

                with suppress(Exception):
                    await manager.download("test-host", "/tmp/source.txt", local_path)

        spans = [s for s in _exporter.get_finished_spans() if s.name == "ssh.download"]
        assert len(spans) == 1
        span = spans[0]
        assert span.attributes["ssh.host"] == "test-host"
        assert span.status.status_code == StatusCode.ERROR

    async def test_sftp_spans_not_created_when_tracer_none(
        self, tmp_path: Path
    ) -> None:
        """Soft-import fallback: no tracer → no spans, but upload still runs.

        Defect 7 (panel iteration 2, all three reviewers): this test used
        to pass ``upload()`` an ABSOLUTE local path (``str(local)``),
        which ``validate_relative`` (B1 confinement) rejects immediately
        with a ``ValueError`` — the ``suppress(Exception)`` hid that, so
        "upload still runs" was never actually exercised. The assertion
        below passed regardless, for a reason unrelated to what the test
        claims to prove: ``_ssh_tracer is None`` makes ``upload()`` skip
        the ``with start_as_current_span(...)`` block BEFORE
        ``_upload_impl`` is even called, so no span is created no matter
        what (or how early) ``_upload_impl`` raises. A transfer_root
        relative path lets the call proceed past validation into
        ``_get_connection`` (mocked to fail) instead, so the no-op-tracer
        assertion is now proven against a call that actually did real
        work.
        """
        import ssh_mcp.ssh as ssh_module
        from contextlib import suppress

        settings = Settings(transfer_root=str(tmp_path / "transfers"))

        with patch.object(ssh_module, "_ssh_tracer", None):
            manager = SSHManager(_make_registry(), settings)
            with patch.object(
                manager,
                "_get_connection",
                AsyncMock(side_effect=OSError("no net")),
            ):
                with suppress(Exception):
                    await manager.upload("test-host", "payload.txt", "/tmp/target.txt")

        # No SFTP spans should exist
        sftp_spans = [
            s
            for s in _exporter.get_finished_spans()
            if s.name in ("ssh.upload", "ssh.download")
        ]
        assert sftp_spans == []


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


# Credential-shaped command used as a canary: `--password=` is matched by
# `_long_flag_is_credential` in `ssh_mcp/ssh.py`, so if a future coupling
# ever let a raw command reach the SDK's own span through some path other
# than the one audited below, this string would surface the leak.
SECRET_CMD = "mysql --password=hunter2 -e 'select 1'"


class TestSDKMiddlewareSpanPrivacy:
    """D6/T6: the SDK's own OpenTelemetry middleware must never leak a command.

    D6 (`docs/plans/2026-09-05-modernize-mcp-v2.md`) leaves `mcp` v2's
    on-by-default `OpenTelemetryMiddleware` (`mcp/server/_otel.py`) enabled
    because its audited attribute set is `mcp.method.name`,
    `mcp.protocol.version`, `jsonrpc.request.id`, `gen_ai.operation.name`,
    and `gen_ai.tool.name` -- never tool arguments. But the error path is
    NOT attribute-only: an exception escaping the handler reaches
    `span.record_exception(e)` (an event) and `span.set_status(ERROR,
    str(e))` (the status description), so a scan limited to
    `span.attributes` is blind to exactly the path that could leak. These
    tests are the regression guard that makes that a safe decision instead
    of an assumption, and assertion 1 below is deliberately load-bearing:
    without it, a run producing zero SDK ``SERVER`` spans would pass
    vacuously.
    """

    async def test_sdk_middleware_span_carries_no_command(
        self, tmp_config_file: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A successful `execute` call's SDK span carries no command text."""
        from mcp.client import Client
        from opentelemetry.trace import SpanKind

        import ssh_mcp.server as server_module
        from ssh_mcp.config import ServerRegistry
        from ssh_mcp.models import ExecResult

        monkeypatch.setenv("SSH_MCP_CONFIG", str(tmp_config_file))
        fake_ssh = MagicMock(spec=SSHManager)
        fake_ssh.execute = AsyncMock(
            return_value=ExecResult(
                server="web1",
                command=SECRET_CMD,
                stdout="ok",
                stderr="",
                exit_code=0,
                duration_ms=1,
            )
        )
        monkeypatch.setattr(server_module, "_ssh", fake_ssh)
        monkeypatch.setattr(
            server_module, "_registry", ServerRegistry(str(tmp_config_file))
        )

        async with Client(server_module.mcp) as client:
            await client.call_tool("execute", {"server": "web1", "command": SECRET_CMD})

        spans = _exporter.get_finished_spans()
        server_spans = [s for s in spans if s.kind is SpanKind.SERVER]
        # Assertion 1 -- anti-vacuity guard. Confirmed by tracing the source
        # (`mcp/server/runner.py`: `serve_one` -> `ServerRunner._on_request`
        # -> `_compose_server_middleware`) that the default in-process
        # `mode="auto"` path for an `MCPServer` DOES run
        # `Server.middleware`, so this passes without `mode="legacy"`. If a
        # future SDK release changes that routing and this lookup starts
        # raising `StopIteration`, retry with
        # `Client(server_module.mcp, mode="legacy")` -- do not delete this
        # assertion to make the test pass.
        call = next(s for s in server_spans if s.name == "tools/call execute")
        assert call.attributes is not None
        assert call.attributes["gen_ai.tool.name"] == "execute"

        # Assertion 2 -- attributes AND events AND status description, not
        # attributes alone: the error path (exercised in the sibling test
        # below) writes to events and the status description, not
        # attributes, so a scan of attributes only would never see it.
        haystack = [str(v) for v in call.attributes.values()]
        haystack += [str(event.attributes) for event in call.events]
        haystack.append(str(call.status.description or ""))
        assert not any(SECRET_CMD in h for h in haystack)

    async def test_sdk_middleware_span_no_exception_event_on_tool_error(
        self,
    ) -> None:
        """A `ToolError` must not reach the span as an event or status text.

        `mcp/server/mcpserver/server.py:426-441` converts a `ToolError` to
        `CallToolResult(is_error=True)` INSIDE the tool-call handler, before
        `OpenTelemetryMiddleware` ever sees an exception -- so the
        middleware's `except Exception` branch (which would call
        `record_exception`/`set_status(ERROR, str(e))`) never fires for it.
        The middleware's own `tools/call` post-check instead sets only
        `error.type="tool_error"` and a bare `set_status(ERROR)` with no
        description. Registered on a throwaway `MCPServer`, never the
        module-level `mcp` shared by every other test in this file.
        """
        from mcp.client import Client
        from mcp.server.mcpserver import MCPServer
        from mcp.server.mcpserver.exceptions import ToolError
        from opentelemetry.trace import SpanKind

        credential_url = "https://u:p@bastion.example.com/x"
        throwaway: MCPServer = MCPServer("otel-privacy-probe")

        @throwaway.tool()
        async def fail(command: str) -> str:
            raise ToolError(f"fail {credential_url}: {command}")

        async with Client(throwaway) as client:
            await client.call_tool("fail", {"command": SECRET_CMD})

        spans = _exporter.get_finished_spans()
        server_spans = [s for s in spans if s.kind is SpanKind.SERVER]
        call = next(s for s in server_spans if s.name == "tools/call fail")
        assert call.attributes is not None
        assert call.attributes.get("error.type") == "tool_error"

        assert call.events == ()
        assert not call.status.description

        # Belt-and-suspenders: even if a future SDK release stops leaving
        # these empty, neither the credential nor the command may surface
        # via any channel on this span.
        haystack = [str(v) for v in call.attributes.values()]
        haystack += [str(event.attributes) for event in call.events]
        haystack.append(str(call.status.description or ""))
        assert not any(credential_url in h for h in haystack)
        assert not any(SECRET_CMD in h for h in haystack)
