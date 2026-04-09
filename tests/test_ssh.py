"""Unit tests for SSH MCP security-critical functions in ssh.py.

Tests cover dangerous command detection, path validation, and SSHManager
initialization. All tests run without real SSH connections.
"""

from __future__ import annotations

import asyncio

import pytest
from hypothesis import given
from hypothesis import strategies as st

from ssh_mcp.config import ServerRegistry
from ssh_mcp.models import Settings
from ssh_mcp.ssh import (
    SSHManager,
    _DANGEROUS_PATTERNS,
    _SENSITIVE_PATHS,
    _is_dangerous_command,
    _make_connection_id,
    _validate_local_path,
    _validate_remote_path,
)


# ---------------------------------------------------------------------------
# Dangerous command detection
# ---------------------------------------------------------------------------


class TestIsDangerousCommand:
    """Tests for _is_dangerous_command using _DANGEROUS_PATTERNS."""

    # --- Commands that MUST be blocked ---

    @pytest.mark.parametrize(
        "command",
        [
            # rm -rf /  variants
            "rm -rf /",
            "rm  -rf  /",
            "rm -rf /home",
            "rm -rf /var/log",
            "sudo rm -rf /",
            "rm -rf /tmp/../etc",
            # mkfs variants
            "mkfs.ext4 /dev/sda",
            "mkfs.xfs /dev/sdb1",
            "mkfs /dev/sda",
            "sudo mkfs.vfat /dev/sdc",
            # dd if= variants
            "dd if=/dev/zero of=/dev/sda",
            "dd if=/dev/urandom of=/disk bs=1M",
            "dd if=/dev/sda of=/dev/sdb",
            # redirect to /dev/sd*
            "> /dev/sda",
            "cat /dev/zero > /dev/sdb",
            "echo bad > /dev/sdc",
            # chmod 777 /  variants
            "chmod 777 /",
            "chmod 777 /etc",
            "sudo chmod 777 /var",
            # fork bomb
            ":(){ :|:& };:",
            ":(){ :|:& };: ",
        ],
        ids=lambda c: c[:40].replace(" ", "_"),
    )
    def test_blocks_dangerous_command(self, command: str) -> None:
        """_is_dangerous_command returns True for commands that match patterns."""
        assert _is_dangerous_command(command) is True

    # --- Commands that MUST NOT be blocked ---

    @pytest.mark.parametrize(
        "command",
        [
            "ls -la",
            "cat /var/log/syslog",
            "df -h",
            "ps aux",
            "uptime",
            "whoami",
            "echo hello",
            "pwd",
            "find /tmp -name '*.log'",
            "grep -r error /var/log/app",
            "tail -f /var/log/nginx/access.log",
            "systemctl status nginx",
            # rm -rf targeting a relative path (no leading /) is safe
            "rm -rf mydir",
            "rm -rf ./cache",
            # chmod with numeric mode but no / prefix is safe
            "chmod 777 mydir",
            "chmod 777 ./scripts",
            "cat /etc/hostname",
            "date",
            "env",
        ],
        ids=lambda c: c[:40].replace(" ", "_"),
    )
    def test_allows_safe_command(self, command: str) -> None:
        """_is_dangerous_command returns False for safe commands."""
        assert _is_dangerous_command(command) is False

    def test_empty_string_is_safe(self) -> None:
        """An empty command string is not dangerous."""
        assert _is_dangerous_command("") is False

    def test_rm_rf_without_slash_is_safe(self) -> None:
        """rm -rf without any leading / is not dangerous."""
        assert _is_dangerous_command("rm -rf mydir") is False

    def test_rm_rf_relative_path_is_safe(self) -> None:
        """rm -rf on a relative path (no /) is safe."""
        assert _is_dangerous_command("rm -rf ./builddir") is False

    def test_rm_rf_absolute_path_is_dangerous(self) -> None:
        """rm -rf on any absolute path (with /) is dangerous per the pattern."""
        # Pattern is rm\s+-rf\s+/ — matches any absolute path
        assert _is_dangerous_command("rm -rf /tmp/builddir") is True

    def test_chmod_777_any_absolute_path_is_dangerous(self) -> None:
        """chmod 777 on any absolute path (with /) is dangerous per the pattern."""
        # Pattern is chmod\s+777\s+/ — matches any path beginning with /
        assert _is_dangerous_command("chmod 777 /home/user/public") is True

    def test_chmod_777_relative_path_is_safe(self) -> None:
        """chmod 777 on a relative path (no leading /) is safe."""
        assert _is_dangerous_command("chmod 777 mydir") is False

    def test_mkfs_in_path_name_is_dangerous(self) -> None:
        """mkfs anywhere in the command string triggers the pattern."""
        # The pattern is a simple substring match on 'mkfs'
        assert _is_dangerous_command("sudo mkfs.btrfs /dev/sde") is True

    def test_dd_if_requires_equals(self) -> None:
        """dd without 'if=' is not matched by the dangerous pattern."""
        assert _is_dangerous_command("dd bs=512 count=100") is False

    def test_pipes_do_not_suppress_dangerous_detection(self) -> None:
        """Dangerous command embedded in a pipeline is still detected."""
        assert _is_dangerous_command("echo test | rm -rf /") is True

    def test_semicolon_separated_dangerous_command(self) -> None:
        """Dangerous command after a semicolon is still detected."""
        assert _is_dangerous_command("ls -la; rm -rf /") is True

    # --- Null-byte and control-character injection bypass attempts ---

    def test_null_byte_between_rm_and_flag_is_still_dangerous(self) -> None:
        """Null byte injected between 'rm' and '-rf' must not bypass detection."""
        # Without sanitization "rm\x00-rf /" would not match r"rm\s+-rf\s+/"
        # because \x00 is not \s. Sanitization strips it before matching.
        assert _is_dangerous_command("rm\x00-rf /") is True

    def test_null_byte_before_mkfs_device_is_still_dangerous(self) -> None:
        """Null byte between mkfs and device path must not bypass detection."""
        assert _is_dangerous_command("mkfs\x00/dev/sda") is True

    def test_embedded_newline_in_rm_rf_is_still_dangerous(self) -> None:
        """Embedded newline splitting 'rm -rf /' must not bypass detection."""
        assert _is_dangerous_command("rm -rf\n/") is True

    def test_carriage_return_in_rm_rf_is_still_dangerous(self) -> None:
        """Carriage return splitting token must not bypass detection."""
        assert _is_dangerous_command("rm\r-rf /") is True

    def test_multiple_control_chars_do_not_bypass_detection(self) -> None:
        """Multiple interspersed control chars must not bypass detection."""
        assert _is_dangerous_command("rm\x01\x02-rf\x03 /") is True

    def test_null_byte_only_command_is_safe(self) -> None:
        """A command consisting only of null bytes produces an empty string — safe."""
        assert _is_dangerous_command("\x00\x00\x00") is False

    def test_control_chars_around_safe_command_remain_safe(self) -> None:
        """Control chars around a safe command do not make it dangerous."""
        assert _is_dangerous_command("\x01ls\x02 -la\x03") is False


# ---------------------------------------------------------------------------
# _DANGEROUS_PATTERNS coverage: each pattern tested individually
# ---------------------------------------------------------------------------


class TestDangerousPatternsDirectly:
    """Ensure every compiled pattern in _DANGEROUS_PATTERNS fires correctly."""

    def test_pattern_count(self) -> None:
        """Sanity check: the expected number of patterns are present."""
        assert len(_DANGEROUS_PATTERNS) == 6

    def test_rm_rf_slash_pattern(self) -> None:
        assert _DANGEROUS_PATTERNS[0].search("rm -rf /") is not None
        assert _DANGEROUS_PATTERNS[0].search("rm -rf /tmp") is not None
        assert _DANGEROUS_PATTERNS[0].search("rm -rf mydir") is None

    def test_mkfs_pattern(self) -> None:
        assert _DANGEROUS_PATTERNS[1].search("mkfs.ext4 /dev/sda") is not None
        assert _DANGEROUS_PATTERNS[1].search("mkfs") is not None
        assert (
            _DANGEROUS_PATTERNS[1].search("ls mkfs_backup") is not None
        )  # substring match

    def test_dd_if_pattern(self) -> None:
        assert _DANGEROUS_PATTERNS[2].search("dd if=/dev/zero of=/dev/sda") is not None
        assert (
            _DANGEROUS_PATTERNS[2].search("dd if=input.bin of=output.bin") is not None
        )
        assert _DANGEROUS_PATTERNS[2].search("dd bs=512 count=1") is None

    def test_redirect_dev_sd_pattern(self) -> None:
        assert _DANGEROUS_PATTERNS[3].search("> /dev/sda") is not None
        assert _DANGEROUS_PATTERNS[3].search("echo x > /dev/sdb") is not None
        assert _DANGEROUS_PATTERNS[3].search("echo x > /dev/null") is None

    def test_chmod_777_slash_pattern(self) -> None:
        # Pattern matches chmod 777 followed by any / prefix — all absolute paths
        assert _DANGEROUS_PATTERNS[4].search("chmod 777 /") is not None
        assert _DANGEROUS_PATTERNS[4].search("chmod 777 /etc") is not None
        assert _DANGEROUS_PATTERNS[4].search("chmod 777 /home/user") is not None
        assert _DANGEROUS_PATTERNS[4].search("chmod 777 /tmp/mydir") is not None
        # Relative paths (no /) are safe
        assert _DANGEROUS_PATTERNS[4].search("chmod 777 mydir") is None
        assert _DANGEROUS_PATTERNS[4].search("chmod 777 ./scripts") is None

    def test_fork_bomb_pattern(self) -> None:
        # Pattern uses \s* (zero-or-more), so spaces are optional
        assert _DANGEROUS_PATTERNS[5].search(":(){ :|:& };:") is not None
        assert (
            _DANGEROUS_PATTERNS[5].search(":(){ :|:&};:") is not None
        )  # no trailing space also matches
        # Pattern requires the exact structure; unrelated strings do not match
        assert _DANGEROUS_PATTERNS[5].search("echo hello") is None
        assert _DANGEROUS_PATTERNS[5].search("ls -la") is None


# ---------------------------------------------------------------------------
# Path validation
# ---------------------------------------------------------------------------


class TestValidateRemotePath:
    """Tests for _validate_remote_path."""

    # --- Paths that MUST be blocked ---

    @pytest.mark.parametrize(
        "path",
        [
            # Parent directory traversal
            "/var/log/../etc/shadow",
            "../../etc/passwd",
            "/home/user/../../etc/shadow",
            "/tmp/../tmp/../etc/shadow",
            # Sensitive files (exact paths)
            "/etc/shadow",
            "/etc/passwd",
            "/root/.ssh/authorized_keys",
            "/home/user/.ssh/authorized_keys",
            "/home/user/.ssh/id_rsa",
            "/home/user/.ssh/id_ed25519",
            "/home/user/.ssh/id_ecdsa",
            "/home/user/.ssh/id_dsa",
            # Case insensitive variants
            "/etc/SHADOW",
            "/ETC/passwd",
            "/home/user/.SSH/id_rsa",
        ],
        ids=lambda p: p.replace("/", "_").replace(".", "_")[:50],
    )
    def test_blocks_sensitive_path(self, path: str) -> None:
        """_validate_remote_path raises ValueError for sensitive or traversal paths."""
        with pytest.raises(ValueError):
            _validate_remote_path(path)

    # --- Paths that MUST be allowed ---

    @pytest.mark.parametrize(
        "path",
        [
            "/var/log/app.log",
            "/home/user/file.txt",
            "/tmp/data",
            "/opt/app/config.yaml",
            "/srv/www/index.html",
            "/etc/nginx/nginx.conf",
            # NOTE: /var/lib/mysql/ is deliberately NOT in this list — Red Team
            # R3 added it to _SENSITIVE_PATHS because direct filesystem access
            # to database data files can exfiltrate tables/secrets.
            "/usr/local/bin/script.sh",
            "/backups/2026-01-01/dump.sql",
            "/home/user/.ssh/id_ed25519.pub",  # public keys are legitimate
        ],
        ids=lambda p: p.replace("/", "_")[:50],
    )
    def test_allows_normal_path(self, path: str) -> None:
        """_validate_remote_path does not raise for normal paths."""
        _validate_remote_path(path)  # Should not raise

    def test_traversal_raises_value_error_with_message(self) -> None:
        """ValueError message mentions traversal for .. paths."""
        with pytest.raises(ValueError, match="traversal"):
            _validate_remote_path("/var/log/../etc/shadow")

    def test_sensitive_path_raises_value_error_with_message(self) -> None:
        """ValueError message mentions sensitive path when blocked."""
        with pytest.raises(ValueError, match="sensitive"):
            _validate_remote_path("/etc/shadow")

    def test_double_dot_anywhere_in_path_is_blocked(self) -> None:
        """A '..' segment anywhere in the path triggers the traversal guard."""
        with pytest.raises(ValueError):
            _validate_remote_path("/valid/path/with/../traversal/attempt")

    def test_dotdot_in_filename_is_blocked(self) -> None:
        """A filename containing '..' is blocked even if not a traversal."""
        with pytest.raises(ValueError):
            _validate_remote_path("/tmp/my..file")

    def test_sensitive_paths_list_coverage(self) -> None:
        """Every entry in _SENSITIVE_PATHS triggers a ValueError.

        Directory-style entries (ending with ``/``) are tested by appending
        a child filename. File-style absolute entries are tested as-is.
        Relative entries (``.ssh/id_rsa``) are prepended with a home dir.
        Windows ``\\...`` entries are covered separately since substring
        matching on backslashes is awkward inside test strings.
        """
        for sensitive in _SENSITIVE_PATHS:
            if sensitive.startswith("\\"):
                continue  # Windows entries — covered by TestExpandedSensitiveAllowlist
            if sensitive.endswith("/"):
                # Directory — test with a file inside
                path = sensitive + "secret.txt"
            elif sensitive.startswith("/"):
                # Absolute file — test as-is
                path = sensitive
            else:
                # Relative — prepend a home
                path = f"/home/user/{sensitive}"
            with pytest.raises(ValueError, match="sensitive"):
                _validate_remote_path(path)


# ---------------------------------------------------------------------------
# SSHManager initialization (no real SSH connections)
# ---------------------------------------------------------------------------


class TestSSHManagerInit:
    """Tests for SSHManager initialization and configuration storage."""

    def _make_registry(self) -> ServerRegistry:
        """Return a minimal ServerRegistry backed by a real config file."""
        import tempfile

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

    def test_registry_stored_on_init(self, sample_settings: Settings) -> None:
        """SSHManager stores the registry reference passed at construction."""
        registry = self._make_registry()
        manager = SSHManager(registry, sample_settings)
        assert manager.registry is registry

    def test_settings_stored_on_init(self, sample_settings: Settings) -> None:
        """SSHManager stores the settings reference passed at construction."""
        registry = self._make_registry()
        manager = SSHManager(registry, sample_settings)
        assert manager.settings is sample_settings

    def test_connection_pool_starts_empty(self, sample_settings: Settings) -> None:
        """The internal connection pool dict is empty on init."""
        registry = self._make_registry()
        manager = SSHManager(registry, sample_settings)
        assert manager._connections == {}

    def test_last_used_starts_empty(self, sample_settings: Settings) -> None:
        """The last-used tracking dict is empty on init."""
        registry = self._make_registry()
        manager = SSHManager(registry, sample_settings)
        assert manager._last_used == {}

    def test_locks_start_empty(self, sample_settings: Settings) -> None:
        """The per-server locks dict is empty on init."""
        registry = self._make_registry()
        manager = SSHManager(registry, sample_settings)
        assert manager._locks == {}

    def test_custom_settings_reflected(self) -> None:
        """SSHManager correctly stores non-default Settings values."""
        custom_settings = Settings(
            command_timeout=120,
            max_output_bytes=102400,
            connection_idle_timeout=600,
            known_hosts=True,
        )
        registry = self._make_registry()
        manager = SSHManager(registry, custom_settings)

        assert manager.settings.command_timeout == 120
        assert manager.settings.max_output_bytes == 102400
        assert manager.settings.connection_idle_timeout == 600
        assert manager.settings.known_hosts is True

    def test_audit_logger_configured(self, sample_settings: Settings) -> None:
        """SSHManager sets up the audit logger under ssh_mcp.audit."""
        import logging

        registry = self._make_registry()
        manager = SSHManager(registry, sample_settings)

        assert manager._audit is logging.getLogger("ssh_mcp.audit")

    def test_eviction_not_started_without_event_loop(
        self, sample_settings: Settings
    ) -> None:
        """SSHManager defers eviction start when no event loop is running."""
        registry = self._make_registry()
        manager = SSHManager(registry, sample_settings)
        # Eviction is deferred — _running should be False
        assert manager._running is False
        assert manager._eviction_task is None

    async def test_group_execution_semaphore_uses_max_parallel_hosts(self) -> None:
        """execute_on_group's concurrency semaphore reflects Settings.max_parallel_hosts.

        Guards against regressing the hardcoded ``Semaphore(10)``. We inject a
        custom ``max_parallel_hosts`` and assert the semaphore built inside
        ``execute_on_group`` has the matching bound by patching
        ``asyncio.Semaphore`` and capturing its first positional argument.
        """
        from unittest.mock import patch

        settings = Settings(max_parallel_hosts=7)
        registry = self._make_registry()
        manager = SSHManager(registry, settings)

        captured: list[int] = []
        real_semaphore = asyncio.Semaphore

        def capturing_semaphore(value: int) -> asyncio.Semaphore:
            captured.append(value)
            return real_semaphore(value)

        with patch("ssh_mcp.ssh.asyncio.Semaphore", side_effect=capturing_semaphore):
            # Group has 1 test-host, so only 1 execute will be attempted;
            # the real execute will fail (no SSH), but by then the Semaphore
            # is already constructed.
            try:
                await manager.execute_on_group("test", "true")
            except Exception:
                pass

        assert captured, "Semaphore was never constructed in execute_on_group"
        assert captured[0] == 7


# ---------------------------------------------------------------------------
# _validate_local_path
# ---------------------------------------------------------------------------


class TestValidateLocalPath:
    """Tests for _validate_local_path — blocks sensitive local files."""

    @pytest.mark.parametrize(
        "path",
        [
            "/home/user/../etc/shadow",
            "../../etc/passwd",
            "/etc/shadow",
            "/etc/passwd",
            "/home/user/.ssh/authorized_keys",
            "/home/user/.ssh/id_rsa",
            "/home/user/.ssh/id_ed25519",
        ],
        ids=lambda p: p.replace("/", "_").replace(".", "_")[:50],
    )
    def test_blocks_sensitive_local_path(self, path: str) -> None:
        with pytest.raises(ValueError):
            _validate_local_path(path)

    @pytest.mark.parametrize(
        "path",
        [
            "/var/log/app.log",
            "/home/user/file.txt",
            "/tmp/data",
            "/opt/app/config.yaml",
        ],
        ids=lambda p: p.replace("/", "_")[:50],
    )
    def test_allows_normal_local_path(self, path: str) -> None:
        _validate_local_path(path)  # Should not raise

    def test_sensitive_local_paths_list_coverage(self) -> None:
        for sensitive in _SENSITIVE_PATHS:
            if sensitive.startswith("\\"):
                continue
            if sensitive.endswith("/"):
                path = sensitive + "secret.txt"
            elif sensitive.startswith("/"):
                path = sensitive
            else:
                path = f"/home/user/{sensitive}"
            with pytest.raises(ValueError):
                _validate_local_path(path)


# ---------------------------------------------------------------------------
# Red-team hardening: path normalization + expanded allowlist (RT-Fix 1)
# ---------------------------------------------------------------------------


class TestPathNormalizationBypasses:
    """Paths that resolve to sensitive files must be blocked after normalization.

    Red Team R3 finding C1: ``/etc//shadow`` and ``/etc/./shadow`` are both
    valid Unix paths that resolve to ``/etc/shadow``, but the naive substring
    check in the original implementation missed them.
    """

    @pytest.mark.parametrize(
        "path",
        [
            "/etc//shadow",
            "/etc/./shadow",
            "/etc/././shadow",
            "/etc//./shadow",
            "//etc/shadow",
            "/etc///shadow",
            "/./etc/shadow",
            "/./etc/./shadow",
        ],
    )
    def test_double_slash_bypass_blocked(self, path: str) -> None:
        """Double-slash and dot-slash obfuscations of /etc/shadow must fail."""
        with pytest.raises(ValueError):
            _validate_remote_path(path)

    @pytest.mark.parametrize(
        "path",
        [
            "/etc//shadow",
            "/etc/./shadow",
        ],
    )
    def test_double_slash_bypass_blocked_local(self, path: str) -> None:
        """Same protection for local SFTP paths."""
        with pytest.raises(ValueError):
            _validate_local_path(path)


class TestExpandedSensitiveAllowlist:
    """Cloud credentials, k8s secrets, proc memory, Windows paths all blocked.

    Red Team R3 finding C2: the original allowlist only covered classic Unix
    system files and SSH keys. Modern infrastructure hosts cloud tokens and
    k8s kubeconfigs that are equally sensitive.
    """

    @pytest.mark.parametrize(
        "path",
        [
            # Cloud credentials
            "/home/user/.aws/credentials",
            "/home/user/.aws/config",
            "/home/user/.azure/accessTokens.json",
            "/home/user/.config/gcloud/credentials.db",
            # Kubernetes
            "/home/user/.kube/config",
            "/var/lib/kubelet/pki/kubelet-client.key",
            "/etc/kubernetes/admin.conf",
            # Shell credential caches
            "/home/user/.netrc",
            "/home/user/.pgpass",
            "/home/user/.git-credentials",
            "/home/user/.docker/config.json",
            # Process memory / kernel
            "/proc/self/mem",
            "/proc/self/environ",
            "/proc/1234/environ",
            "/proc/kcore",
            # Database data files
            "/var/lib/mysql/mysql/user.MYD",
            "/var/lib/postgresql/16/main/base/1/",
            # Additional Unix secrets
            "/etc/sudoers",
            "/etc/gshadow",
        ],
    )
    def test_sensitive_path_blocked(self, path: str) -> None:
        with pytest.raises(ValueError):
            _validate_remote_path(path)

    def test_ssh_pub_key_allowed(self) -> None:
        """.pub keys are NOT secret — allow SFTP upload/download of public keys.

        Red Team R3 finding H5: the previous substring match blocked
        ``id_ed25519.pub`` because it contains the substring ``id_ed25519``.
        This broke legitimate public-key distribution via SFTP.
        """
        _validate_remote_path("/home/user/.ssh/id_ed25519.pub")
        _validate_remote_path("/home/user/.ssh/id_rsa.pub")
        _validate_remote_path("/home/user/.ssh/id_ecdsa.pub")
        _validate_remote_path("/home/user/.ssh/id_dsa.pub")
        _validate_local_path("/tmp/deploy_key.pub")


# ---------------------------------------------------------------------------
# force=True bypass
# ---------------------------------------------------------------------------


class TestDangerousCommandForceBypass:
    """Tests for force=True bypassing dangerous command detection."""

    def test_dangerous_command_blocked_without_force(self) -> None:
        assert _is_dangerous_command("rm -rf /") is True

    def test_force_parameter_exists_in_execute_signature(self) -> None:
        """Verify force parameter exists in SSHManager.execute signature."""
        import inspect

        sig = inspect.signature(SSHManager.execute)
        assert "force" in sig.parameters


# ---------------------------------------------------------------------------
# dry_run parameter (C3)
# ---------------------------------------------------------------------------


class TestDryRun:
    """Tests for dry_run=True preview behavior."""

    def _make_registry(self) -> ServerRegistry:
        import tempfile

        config_content = """
[settings]
command_timeout = 30

[groups]
test = { description = "Test group" }

[servers.test-host]
description = "Test server"
groups = ["test"]
default_dir = "/srv/app"
"""
        tmp = tempfile.NamedTemporaryFile(suffix=".toml", mode="w", delete=False)
        tmp.write(config_content)
        tmp.flush()
        tmp.close()
        return ServerRegistry(tmp.name)

    async def test_dry_run_does_not_call_get_connection(self) -> None:
        """dry_run=True must skip connection setup entirely."""
        from unittest.mock import AsyncMock, patch

        manager = SSHManager(self._make_registry(), Settings())

        with patch.object(
            manager,
            "_get_connection",
            AsyncMock(side_effect=AssertionError("must not connect in dry_run")),
        ):
            result = await manager.execute("test-host", "uptime", dry_run=True)

        assert result.exit_code == 0
        assert result.error is None
        assert "[DRY RUN]" in result.stdout
        assert "uptime" in result.stdout
        assert "test-host" in result.stdout

    async def test_dry_run_includes_default_dir_from_config(self) -> None:
        """The preview must show the server's default_dir when no override."""
        from unittest.mock import AsyncMock, patch

        manager = SSHManager(self._make_registry(), Settings())
        with patch.object(
            manager,
            "_get_connection",
            AsyncMock(side_effect=AssertionError("must not connect in dry_run")),
        ):
            result = await manager.execute("test-host", "uptime", dry_run=True)

        assert "/srv/app" in result.stdout

    async def test_dry_run_working_dir_override_wins(self) -> None:
        """An explicit working_dir override must appear in the preview."""
        from unittest.mock import AsyncMock, patch

        manager = SSHManager(self._make_registry(), Settings())
        with patch.object(
            manager,
            "_get_connection",
            AsyncMock(side_effect=AssertionError("must not connect in dry_run")),
        ):
            result = await manager.execute(
                "test-host",
                "ls",
                working_dir="/custom/path",
                dry_run=True,
            )

        assert "/custom/path" in result.stdout
        assert "/srv/app" not in result.stdout

    async def test_dry_run_still_blocks_dangerous_commands(self) -> None:
        """Dangerous commands must be rejected even in dry_run mode.

        This is the whole point of dry_run: preview what would happen,
        including rejection. Skipping the dangerous-command check would
        defeat the use case of previewing a plan before committing.
        """
        manager = SSHManager(self._make_registry(), Settings())
        result = await manager.execute("test-host", "rm -rf /", dry_run=True)

        assert result.error is not None
        assert "Blocked" in result.error
        assert "[DRY RUN]" not in result.stdout

    async def test_dry_run_with_force_bypasses_dangerous_check(self) -> None:
        """dry_run + force should preview a dangerous command without blocking."""
        from unittest.mock import AsyncMock, patch

        manager = SSHManager(self._make_registry(), Settings())
        with patch.object(
            manager,
            "_get_connection",
            AsyncMock(side_effect=AssertionError("must not connect in dry_run")),
        ):
            result = await manager.execute(
                "test-host",
                "rm -rf /",
                force=True,
                dry_run=True,
            )

        assert result.error is None
        assert "[DRY RUN]" in result.stdout
        assert "rm -rf /" in result.stdout

    async def test_dry_run_group_produces_result_per_server(self) -> None:
        """execute_on_group dry_run must produce a preview for every server."""
        from unittest.mock import AsyncMock, patch

        manager = SSHManager(self._make_registry(), Settings())
        with patch.object(
            manager,
            "_get_connection",
            AsyncMock(side_effect=AssertionError("must not connect in dry_run")),
        ):
            results = await manager.execute_on_group("test", "uptime", dry_run=True)

        assert len(results) == 1  # test group has 1 server
        assert all(r.exit_code == 0 for r in results)
        assert all("[DRY RUN]" in r.stdout for r in results)


# ---------------------------------------------------------------------------
# connection_id generation + SFTP audit lifecycle (B2)
# ---------------------------------------------------------------------------


class TestConnectionIdGeneration:
    """_make_connection_id produces grep-friendly unique identifiers."""

    def test_connection_id_starts_with_server_name(self) -> None:
        cid = _make_connection_id("web1")
        assert cid.startswith("web1-")

    def test_connection_id_contains_pid(self) -> None:
        import os

        cid = _make_connection_id("web1")
        assert f"-{os.getpid()}-" in cid

    def test_connection_ids_are_unique(self) -> None:
        """Two calls must produce distinct ids even for the same server."""
        ids = {_make_connection_id("web1") for _ in range(100)}
        assert len(ids) == 100


class TestSFTPAuditLogging:
    """SFTP upload/download emit start/complete/failed audit logs."""

    def _make_registry(self) -> ServerRegistry:
        import tempfile

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

    async def test_upload_emits_start_and_complete_audit_logs(
        self,
        tmp_path,
        caplog: pytest.LogCaptureFixture,
        sample_settings: Settings,
    ) -> None:
        """upload() must emit sftp.upload.start AND sftp.upload.complete."""
        from unittest.mock import AsyncMock, MagicMock, patch

        local = tmp_path / "payload.txt"
        local.write_bytes(b"hello sftp")

        manager = SSHManager(self._make_registry(), sample_settings)
        # Seed the pool so _get_connection returns our mock without touching
        # real network or asyncssh.connect().
        mock_sftp = MagicMock()
        mock_sftp.put = AsyncMock(return_value=None)

        sftp_ctx = MagicMock()
        sftp_ctx.__aenter__ = AsyncMock(return_value=mock_sftp)
        sftp_ctx.__aexit__ = AsyncMock(return_value=None)

        mock_conn = MagicMock()
        mock_conn.is_closed = MagicMock(return_value=False)
        mock_conn.start_sftp_client = MagicMock(return_value=sftp_ctx)

        with patch.object(
            manager, "_get_connection", AsyncMock(return_value=mock_conn)
        ):
            # Pre-seed the connection_id so audit log can reference it
            manager._connection_ids["test-host"] = "test-host-1-abcd1234"

            with caplog.at_level("INFO", logger="ssh_mcp.audit"):
                await manager.upload("test-host", str(local), "/tmp/target.txt")

        messages = [r.message for r in caplog.records]
        assert any("sftp.upload.start" in m for m in messages), (
            f"No start log in: {messages}"
        )
        assert any("sftp.upload.complete" in m for m in messages), (
            f"No complete log in: {messages}"
        )

    async def test_upload_failure_emits_failed_audit_log(
        self,
        tmp_path,
        caplog: pytest.LogCaptureFixture,
        sample_settings: Settings,
    ) -> None:
        """Upload failure must emit sftp.upload.failed with error type."""
        from unittest.mock import AsyncMock, MagicMock, patch

        local = tmp_path / "payload.txt"
        local.write_bytes(b"data")

        manager = SSHManager(self._make_registry(), sample_settings)

        # start_sftp_client raises to simulate failure
        mock_conn = MagicMock()
        mock_conn.is_closed = MagicMock(return_value=False)
        mock_conn.start_sftp_client = MagicMock(side_effect=OSError("no route"))

        with patch.object(
            manager, "_get_connection", AsyncMock(return_value=mock_conn)
        ):
            manager._connection_ids["test-host"] = "test-host-1-deadbeef"
            with caplog.at_level("WARNING", logger="ssh_mcp.audit"):
                with pytest.raises(RuntimeError, match="Upload failed"):
                    await manager.upload("test-host", str(local), "/tmp/target.txt")

        messages = [r.message for r in caplog.records]
        assert any("sftp.upload.failed" in m for m in messages), (
            f"No failed log in: {messages}"
        )
        # Error type should be included so operators can triage quickly
        assert any("OSError" in m for m in messages)

    async def test_download_emits_start_and_complete_audit_logs(
        self,
        tmp_path,
        caplog: pytest.LogCaptureFixture,
        sample_settings: Settings,
    ) -> None:
        """download() must emit sftp.download.start AND sftp.download.complete."""
        from unittest.mock import AsyncMock, MagicMock, patch

        local = tmp_path / "downloaded.txt"
        # Pre-create so Path(local_path).stat() works after mocked get()
        local.write_bytes(b"some data")

        manager = SSHManager(self._make_registry(), sample_settings)
        mock_sftp = MagicMock()
        mock_sftp.get = AsyncMock(return_value=None)

        sftp_ctx = MagicMock()
        sftp_ctx.__aenter__ = AsyncMock(return_value=mock_sftp)
        sftp_ctx.__aexit__ = AsyncMock(return_value=None)

        mock_conn = MagicMock()
        mock_conn.is_closed = MagicMock(return_value=False)
        mock_conn.start_sftp_client = MagicMock(return_value=sftp_ctx)

        with patch.object(
            manager, "_get_connection", AsyncMock(return_value=mock_conn)
        ):
            manager._connection_ids["test-host"] = "test-host-1-cafef00d"
            with caplog.at_level("INFO", logger="ssh_mcp.audit"):
                await manager.download("test-host", "/tmp/source.txt", str(local))

        messages = [r.message for r in caplog.records]
        assert any("sftp.download.start" in m for m in messages)
        assert any("sftp.download.complete" in m for m in messages)

    def test_connection_ids_cleared_on_close_all(
        self, sample_settings: Settings
    ) -> None:
        """close_all() must clear the connection_ids dict."""
        manager = SSHManager(self._make_registry(), sample_settings)
        manager._connection_ids["test-host"] = "test-host-1-abcd"

        asyncio.run(manager.close_all())

        assert manager._connection_ids == {}


# ---------------------------------------------------------------------------
# Property-based fuzz tests for _is_dangerous_command (B3)
#
# These tests use Hypothesis to explore the input space beyond the
# hand-curated parametrize cases. They catch regressions where:
#   * a regex change accidentally makes rm -rf / slip past the filter
#   * a regex change starts rejecting benign commands that happen to
#     contain "dd" or "chmod" substrings in non-destructive positions
#   * control-character sanitization leaves exploitable gaps
# ---------------------------------------------------------------------------


class TestDangerousCommandProperties:
    """Property-based tests using Hypothesis to fuzz ``_is_dangerous_command``."""

    @given(
        st.text(
            alphabet=st.characters(min_codepoint=0, max_codepoint=255),
            max_size=200,
        )
    )
    def test_never_crashes_on_arbitrary_byte_input(self, payload: str) -> None:
        """Property: the function returns bool for ANY input, never raises.

        Guards against regex regressions (catastrophic backtracking,
        encoding errors) that would crash the whole tool call instead of
        returning a safe "not dangerous" verdict.
        """
        result = _is_dangerous_command(payload)
        assert isinstance(result, bool)

    @given(st.from_regex(r"rm\s+-rf\s+/.*", fullmatch=False))
    def test_rm_rf_root_always_caught(self, payload: str) -> None:
        """Property: any string containing ``rm -rf /`` is rejected."""
        assert _is_dangerous_command(payload) is True

    @given(st.from_regex(r"mkfs\.\w+", fullmatch=False))
    def test_mkfs_always_caught(self, payload: str) -> None:
        """Property: any string matching ``mkfs.<fstype>`` is rejected."""
        assert _is_dangerous_command(payload) is True

    @given(st.from_regex(r"dd\s+if=/dev/\w+", fullmatch=False))
    def test_dd_with_device_input_always_caught(self, payload: str) -> None:
        """Property: ``dd if=/dev/*`` patterns are rejected."""
        assert _is_dangerous_command(payload) is True

    @given(
        st.text(
            alphabet=st.characters(
                whitelist_categories=("Lu", "Ll", "Nd"),
                whitelist_characters=" -./_",
            ),
            min_size=1,
            max_size=80,
        ).filter(
            lambda s: (
                not any(
                    token in s.lower()
                    for token in (
                        "rm -rf /",
                        "rm  -rf  /",
                        "mkfs",
                        "dd if=",
                        "/dev/sd",
                        "chmod 777 /",
                    )
                )
            )
        )
    )
    def test_safe_looking_text_not_flagged(self, payload: str) -> None:
        """Property: letters+digits+path-safe chars without dangerous tokens pass.

        Narrower than "any text" to avoid false positives from generated
        substrings accidentally matching a dangerous regex — the filter
        excludes any payload containing a known dangerous substring.
        """
        assert _is_dangerous_command(payload) is False

    @given(
        st.sampled_from(
            ["rm -rf /", "mkfs.ext4 /dev/sda", "dd if=/dev/zero of=/dev/sdb"]
        ),
        st.integers(min_value=1, max_value=10),
    )
    def test_control_char_injection_never_bypasses(self, cmd: str, n_ctrl: int) -> None:
        """Property: injecting control chars into a known-bad command must NOT bypass.

        Red Team R2 fix: null bytes and other ASCII control characters are
        normalized to spaces before regex matching. This property verifies
        the normalization across every dangerous token and every possible
        control character insertion point.
        """
        # Insert control chars at a couple of positions in the command.
        # Pick positions deterministically from n_ctrl so Hypothesis
        # shrinking produces meaningful counterexamples on failure.
        for i in range(n_ctrl):
            pos = i % len(cmd)
            cmd = cmd[:pos] + chr(i % 32) + cmd[pos:]
        assert _is_dangerous_command(cmd) is True, f"bypass found: {cmd!r}"
