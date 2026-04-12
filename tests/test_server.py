"""Unit tests for SSH MCP server module.

Tests cover configuration resolution, lazy initialization, MCP tool functions,
and connection cleanup. All SSH operations are mocked to avoid real connections.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import asyncssh
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
    """Reset server module globals before each test."""
    monkeypatch.setattr(server_module, "_registry", None)
    monkeypatch.setattr(server_module, "_ssh", None)
    # _init_lock is now a module-level Lock (never None); replace with a fresh
    # one so each test starts with an uncontended lock.
    monkeypatch.setattr(server_module, "_init_lock", asyncio.Lock())


@pytest.fixture
def mock_init(monkeypatch: pytest.MonkeyPatch, tmp_config_file: Path) -> MagicMock:
    """Pre-initialize server globals with test fixtures.

    Returns:
        MagicMock wrapping SSHManager for assertion checks.
    """
    registry = ServerRegistry(str(tmp_config_file))
    mock_ssh = MagicMock(spec=SSHManager)
    monkeypatch.setattr(server_module, "_registry", registry)
    monkeypatch.setattr(server_module, "_ssh", mock_ssh)
    return mock_ssh


# ---------------------------------------------------------------------------
# _get_config_path
# ---------------------------------------------------------------------------


class TestGetConfigPath:
    """Tests for _get_config_path() fallback chain."""

    def test_env_var_takes_priority(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Test SSH_MCP_CONFIG environment variable is used first."""
        config = tmp_path / "env_config.toml"
        config.touch()
        monkeypatch.setenv("SSH_MCP_CONFIG", str(config))

        result = server_module._get_config_path()

        assert result == str(config)

    def test_env_var_expands_tilde(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test SSH_MCP_CONFIG expands ~ in path."""
        monkeypatch.setenv("SSH_MCP_CONFIG", "~/my_config.toml")

        result = server_module._get_config_path()

        assert "~" not in result
        assert result.endswith("my_config.toml")

    def test_xdg_path_used_when_no_env_var(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Test XDG config path is used when env var is absent."""
        monkeypatch.delenv("SSH_MCP_CONFIG", raising=False)

        xdg_config = tmp_path / ".config" / "ssh-mcp" / "servers.toml"
        xdg_config.parent.mkdir(parents=True)
        xdg_config.touch()

        with patch.object(Path, "home", return_value=tmp_path):
            result = server_module._get_config_path()

        assert result == str(xdg_config)

    def test_dev_path_fallback(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Test development path fallback when XDG path is absent."""
        monkeypatch.delenv("SSH_MCP_CONFIG", raising=False)

        # Ensure XDG path does not exist by pointing home to empty tmp dir
        with patch.object(Path, "home", return_value=tmp_path):
            # Create a fake dev config relative to __file__
            dev_config = (
                Path(server_module.__file__).parent.parent.parent
                / "config"
                / "servers.toml"
            )
            if dev_config.exists():
                result = server_module._get_config_path()
                assert result == str(dev_config)
            else:
                # Dev config does not exist either — should raise
                with pytest.raises(FileNotFoundError):
                    server_module._get_config_path()

    def test_raises_when_no_config_exists(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Test FileNotFoundError when no config exists anywhere."""
        monkeypatch.delenv("SSH_MCP_CONFIG", raising=False)

        # Point home to empty tmp dir and dev config to nonexistent path
        with (
            patch.object(Path, "home", return_value=tmp_path),
            patch.object(
                Path,
                "exists",
                return_value=False,
            ),
        ):
            with pytest.raises(
                FileNotFoundError, match="SSH MCP configuration not found"
            ):
                server_module._get_config_path()


# ---------------------------------------------------------------------------
# _init
# ---------------------------------------------------------------------------


class TestInit:
    """Tests for _init() lazy initialization."""

    async def test_successful_initialization(
        self, monkeypatch: pytest.MonkeyPatch, tmp_config_file: Path
    ) -> None:
        """Test _init creates registry and ssh manager."""
        monkeypatch.setenv("SSH_MCP_CONFIG", str(tmp_config_file))

        await server_module._init()

        assert server_module._registry is not None
        assert server_module._ssh is not None
        assert isinstance(server_module._registry, ServerRegistry)
        assert isinstance(server_module._ssh, SSHManager)

    async def test_idempotent_double_call(
        self, monkeypatch: pytest.MonkeyPatch, tmp_config_file: Path
    ) -> None:
        """Test calling _init twice does not re-initialize."""
        monkeypatch.setenv("SSH_MCP_CONFIG", str(tmp_config_file))

        await server_module._init()
        first_registry = server_module._registry
        first_ssh = server_module._ssh

        await server_module._init()

        assert server_module._registry is first_registry
        assert server_module._ssh is first_ssh

    async def test_concurrent_calls_initialize_exactly_once(
        self, monkeypatch: pytest.MonkeyPatch, tmp_config_file: Path
    ) -> None:
        """Test concurrent _init calls only initialize registry once (lock works)."""
        monkeypatch.setenv("SSH_MCP_CONFIG", str(tmp_config_file))

        with patch(
            "ssh_mcp.server.ServerRegistry", wraps=ServerRegistry
        ) as mock_registry_cls:
            await asyncio.gather(
                server_module._init(),
                server_module._init(),
                server_module._init(),
            )

        # ServerRegistry.__init__ must be called exactly once regardless of
        # how many concurrent callers raced to _init().
        assert mock_registry_cls.call_count == 1
        assert server_module._registry is not None
        assert server_module._ssh is not None


# ---------------------------------------------------------------------------
# list_servers
# ---------------------------------------------------------------------------


class TestListServers:
    """Tests for list_servers MCP tool."""

    async def test_returns_all_servers(self, mock_init: MagicMock) -> None:
        """Test list_servers returns formatted table with all servers."""
        result = await server_module.list_servers()

        assert "test-web1" in result
        assert "test-web2" in result
        assert "test-db1" in result

    async def test_group_filter(self, mock_init: MagicMock) -> None:
        """Test list_servers filters by group name."""
        result = await server_module.list_servers(group="test-prod")

        assert "test-web1" in result
        assert "test-web2" in result
        assert "test-db1" not in result

    async def test_invalid_group_returns_error(self, mock_init: MagicMock) -> None:
        """Test list_servers returns error string for unknown group."""
        result = await server_module.list_servers(group="nonexistent")

        assert "Error" in result

    async def test_empty_group_returns_message(self, mock_init: MagicMock) -> None:
        """Test list_servers returns message for group with no servers."""
        # test-dev has test-db1, but let's use a group with no servers
        # by temporarily removing servers from the registry
        registry: ServerRegistry = server_module._registry  # type: ignore[assignment]
        registry._servers.clear()

        result = await server_module.list_servers(group="test-prod")

        assert "No servers found" in result


# ---------------------------------------------------------------------------
# list_groups
# ---------------------------------------------------------------------------


class TestListGroups:
    """Tests for list_groups MCP tool."""

    async def test_returns_formatted_groups(self, mock_init: MagicMock) -> None:
        """Test list_groups returns formatted table with groups and counts."""
        result = await server_module.list_groups()

        assert "test-prod" in result
        assert "test-dev" in result


# ---------------------------------------------------------------------------
# execute
# ---------------------------------------------------------------------------


class TestExecute:
    """Tests for execute MCP tool."""

    async def test_delegates_to_ssh_manager(self, mock_init: MagicMock) -> None:
        """Test execute delegates to _ssh.execute() with correct args."""
        expected_result = ExecResult(
            server="test-web1",
            command="uptime",
            stdout="up 10 days",
            stderr="",
            exit_code=0,
            duration_ms=100,
        )
        mock_init.execute = AsyncMock(return_value=expected_result)

        result = await server_module.execute(
            server="test-web1",
            command="uptime",
            timeout=15,
            working_dir="/tmp",
            force=True,
        )

        mock_init.execute.assert_awaited_once_with(
            "test-web1", "uptime", 15, "/tmp", True, False
        )
        assert "uptime" in result or "up 10 days" in result

    async def test_formats_result(self, mock_init: MagicMock) -> None:
        """Test execute formats result with format_exec_result."""
        expected_result = ExecResult(
            server="test-web1",
            command="ls",
            stdout="file.txt",
            stderr="",
            exit_code=0,
            duration_ms=50,
        )
        mock_init.execute = AsyncMock(return_value=expected_result)

        result = await server_module.execute(server="test-web1", command="ls")

        assert "file.txt" in result

    async def test_exception_raises_tool_error(self, mock_init: MagicMock) -> None:
        """Test execute raises ToolError on unexpected exception."""
        mock_init.execute = AsyncMock(side_effect=RuntimeError("Connection failed"))

        with pytest.raises(ToolError, match="Connection failed"):
            await server_module.execute(server="test-web1", command="uptime")

    async def test_tool_error_passthrough(self, mock_init: MagicMock) -> None:
        """Test execute re-raises ToolError without wrapping."""
        mock_init.execute = AsyncMock(side_effect=ToolError("Original error"))

        with pytest.raises(ToolError, match="Original error"):
            await server_module.execute(server="test-web1", command="uptime")


# ---------------------------------------------------------------------------
# execute_on_group
# ---------------------------------------------------------------------------


class TestExecuteOnGroup:
    """Tests for execute_on_group MCP tool."""

    async def test_delegates_to_ssh_manager(self, mock_init: MagicMock) -> None:
        """Test execute_on_group delegates with correct args including force."""
        results = [
            ExecResult(
                server="test-web1",
                command="uptime",
                stdout="up 5 days",
                stderr="",
                exit_code=0,
                duration_ms=100,
            ),
        ]
        mock_init.execute_on_group = AsyncMock(return_value=results)

        await server_module.execute_on_group(
            group="test-prod",
            command="uptime",
            timeout=20,
            working_dir="/var",
            fail_fast=True,
            force=True,
        )

        mock_init.execute_on_group.assert_awaited_once_with(
            "test-prod", "uptime", 20, "/var", True, True, False
        )

    async def test_exception_raises_tool_error(self, mock_init: MagicMock) -> None:
        """Test execute_on_group raises ToolError on exception."""
        mock_init.execute_on_group = AsyncMock(
            side_effect=RuntimeError("Group not found")
        )

        with pytest.raises(ToolError, match="Group not found"):
            await server_module.execute_on_group(group="test-prod", command="uptime")

    async def test_tool_error_passthrough(self, mock_init: MagicMock) -> None:
        """Test execute_on_group re-raises ToolError without wrapping."""
        mock_init.execute_on_group = AsyncMock(
            side_effect=ToolError("Dangerous command")
        )

        with pytest.raises(ToolError, match="Dangerous command"):
            await server_module.execute_on_group(group="test-prod", command="rm -rf /")


# ---------------------------------------------------------------------------
# upload_file
# ---------------------------------------------------------------------------


class TestUploadFile:
    """Tests for upload_file MCP tool."""

    async def test_delegates_to_ssh_manager(self, mock_init: MagicMock) -> None:
        """Test upload_file delegates to _ssh.upload() with correct args."""
        mock_init.upload = AsyncMock(return_value="Uploaded 1024 bytes")

        result = await server_module.upload_file(
            server="test-web1",
            local_path="/tmp/file.txt",
            remote_path="/home/user/file.txt",
        )

        mock_init.upload.assert_awaited_once_with(
            "test-web1", "/tmp/file.txt", "/home/user/file.txt"
        )
        assert "1024" in result

    async def test_exception_raises_tool_error(self, mock_init: MagicMock) -> None:
        """Test upload_file raises ToolError on exception."""
        mock_init.upload = AsyncMock(side_effect=OSError("File not found"))

        with pytest.raises(ToolError, match="File not found"):
            await server_module.upload_file(
                server="test-web1",
                local_path="/tmp/missing.txt",
                remote_path="/home/user/missing.txt",
            )

    async def test_tool_error_passthrough(self, mock_init: MagicMock) -> None:
        """Test upload_file re-raises ToolError without wrapping."""
        mock_init.upload = AsyncMock(side_effect=ToolError("Sensitive path"))

        with pytest.raises(ToolError, match="Sensitive path"):
            await server_module.upload_file(
                server="test-web1",
                local_path="/tmp/file.txt",
                remote_path="/etc/shadow",
            )


# ---------------------------------------------------------------------------
# download_file
# ---------------------------------------------------------------------------


class TestDownloadFile:
    """Tests for download_file MCP tool."""

    async def test_delegates_to_ssh_manager(self, mock_init: MagicMock) -> None:
        """Test download_file delegates to _ssh.download() with correct args."""
        mock_init.download = AsyncMock(return_value="Downloaded 2048 bytes")

        result = await server_module.download_file(
            server="test-web1",
            remote_path="/home/user/data.csv",
            local_path="/tmp/data.csv",
        )

        mock_init.download.assert_awaited_once_with(
            "test-web1", "/home/user/data.csv", "/tmp/data.csv"
        )
        assert "2048" in result

    async def test_exception_raises_tool_error(self, mock_init: MagicMock) -> None:
        """Test download_file raises ToolError on exception."""
        mock_init.download = AsyncMock(side_effect=OSError("Permission denied"))

        with pytest.raises(ToolError, match="Permission denied"):
            await server_module.download_file(
                server="test-web1",
                remote_path="/root/secret.txt",
                local_path="/tmp/secret.txt",
            )

    async def test_tool_error_passthrough(self, mock_init: MagicMock) -> None:
        """Test download_file re-raises ToolError without wrapping."""
        mock_init.download = AsyncMock(side_effect=ToolError("Sensitive path"))

        with pytest.raises(ToolError, match="Sensitive path"):
            await server_module.download_file(
                server="test-web1",
                remote_path="/etc/shadow",
                local_path="/tmp/shadow",
            )


# ---------------------------------------------------------------------------
# _cleanup_connections
# ---------------------------------------------------------------------------


class TestCleanupConnections:
    """Tests for _cleanup_connections() atexit handler."""

    def test_noop_when_ssh_is_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test cleanup does nothing when _ssh is not set."""
        monkeypatch.setattr(server_module, "_ssh", None)

        # Should not raise
        server_module._cleanup_connections()

    def test_calls_close_all_via_asyncio_run(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """R5: cleanup uses asyncio.run() directly (dead create_task branch removed)."""
        mock_ssh = MagicMock(spec=SSHManager)
        mock_ssh.close_all = AsyncMock()
        monkeypatch.setattr(server_module, "_ssh", mock_ssh)

        with patch("asyncio.run") as mock_run:
            server_module._cleanup_connections()

        mock_run.assert_called_once()

    def test_handles_cleanup_error_gracefully(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test cleanup logs warning on close_all exception — does not crash."""
        mock_ssh = MagicMock(spec=SSHManager)
        mock_ssh.close_all = AsyncMock()
        monkeypatch.setattr(server_module, "_ssh", mock_ssh)

        with patch("asyncio.run", side_effect=Exception("cleanup failed")):
            # Should not raise — error is logged
            server_module._cleanup_connections()


# ---------------------------------------------------------------------------
# R5 #17: _execute_impl error taxonomy
# ---------------------------------------------------------------------------


class TestExecErrorTaxonomy:
    """R5 #17: verify every exception type caught by _execute_impl returns ExecResult."""

    def _make_manager(self, tmp_path: Path) -> SSHManager:
        """Build an SSHManager backed by a real ServerRegistry from a tmpfile."""
        config_content = """\
[servers.test-srv]
description = "Disposable test server"
groups = []
"""
        config_file = tmp_path / "taxonomy.toml"
        config_file.write_text(config_content)

        from ssh_mcp.config import ServerRegistry
        from ssh_mcp.models import Settings

        registry = ServerRegistry(str(config_file))
        return SSHManager(registry, Settings())

    @pytest.mark.parametrize(
        "exc_class,exc_args",
        [
            pytest.param(
                asyncssh.DisconnectError,
                (1, "connection lost"),
                id="DisconnectError",
            ),
            pytest.param(
                asyncssh.PermissionDenied,
                ("auth denied",),
                id="PermissionDenied",
            ),
            pytest.param(
                OSError,
                ("network unreachable",),
                id="OSError",
            ),
        ],
    )
    async def test_ssh_exceptions_return_exec_result_with_error(
        self, tmp_path: Path, exc_class: type, exc_args: tuple[object, ...]
    ) -> None:
        """Each SSH-layer exception must produce ExecResult with error, not raise."""
        manager = self._make_manager(tmp_path)

        mock_conn = AsyncMock()
        mock_conn.run = AsyncMock(side_effect=exc_class(*exc_args))

        with patch.object(manager, "_get_connection", return_value=mock_conn):
            result = await manager.execute("test-srv", "whoami")

        assert isinstance(result, ExecResult)
        assert result.exit_code is None
        assert result.error is not None
        assert len(result.error) > 0

    async def test_timeout_error_returns_exec_result_with_error(
        self, tmp_path: Path
    ) -> None:
        """asyncio.TimeoutError (inner try) must produce ExecResult with error."""
        manager = self._make_manager(tmp_path)

        mock_conn = AsyncMock()
        mock_conn.run = AsyncMock(side_effect=asyncio.TimeoutError())

        with patch.object(manager, "_get_connection", return_value=mock_conn):
            result = await manager.execute("test-srv", "sleep 9999")

        assert isinstance(result, ExecResult)
        assert result.exit_code is None
        assert result.error is not None
        assert "timeout" in result.error.lower()


# ---------------------------------------------------------------------------
# R5 #18: MCP tool function signature stability
# ---------------------------------------------------------------------------


class TestToolSignatureStability:
    """R5 #18: verify MCP tool function signatures are stable.

    If a parameter is added, removed, or reordered, existing positional-arg
    mock assertions in the test suite would silently pass while production
    behaviour changes.  These tests lock down the public contract.
    """

    def test_execute_signature(self) -> None:
        import inspect

        sig = inspect.signature(server_module.execute)
        params = list(sig.parameters.keys())
        assert params == [
            "server",
            "command",
            "timeout",
            "working_dir",
            "force",
            "dry_run",
        ]

    def test_execute_on_group_signature(self) -> None:
        import inspect

        sig = inspect.signature(server_module.execute_on_group)
        params = list(sig.parameters.keys())
        assert params == [
            "group",
            "command",
            "timeout",
            "working_dir",
            "fail_fast",
            "force",
            "dry_run",
        ]

    def test_upload_file_signature(self) -> None:
        import inspect

        sig = inspect.signature(server_module.upload_file)
        params = list(sig.parameters.keys())
        assert params == ["server", "local_path", "remote_path"]

    def test_download_file_signature(self) -> None:
        import inspect

        sig = inspect.signature(server_module.download_file)
        params = list(sig.parameters.keys())
        assert params == ["server", "remote_path", "local_path"]

    def test_list_servers_signature(self) -> None:
        import inspect

        sig = inspect.signature(server_module.list_servers)
        params = list(sig.parameters.keys())
        assert params == ["group"]

    def test_list_groups_signature(self) -> None:
        import inspect

        sig = inspect.signature(server_module.list_groups)
        params = list(sig.parameters.keys())
        assert params == []
